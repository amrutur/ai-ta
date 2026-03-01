"""
Tests for the RAG (Retrieval-Augmented Generation) pipeline.

Tests cover:
- PDF text extraction
- Text chunking
- build_course_index endpoint (via API)
- retrieve_context integration
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from starlette.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixture: FastAPI TestClient
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    with patch("api_server.load_course_info_from_db", new_callable=AsyncMock, return_value={}):
        with patch("api_server.load_notebooks_from_db", new_callable=AsyncMock, return_value={}):
            from api_server import app
            with TestClient(app, raise_server_exceptions=False) as c:
                yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auth_header(email="instructor@test.com", name="Test User"):
    """Build an Authorization header with a valid JWT."""
    from auth import create_jwt_token
    token = create_jwt_token(
        {"id": "123", "email": email, "name": name},
        secret_key="test-secret-key-for-unit-tests",
    )
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Unit tests for rag module internals
# ---------------------------------------------------------------------------

class TestChunking:

    def test_chunk_text_basic(self):
        from rag import _chunk_text
        text = "A" * 2500
        chunks = _chunk_text(text, chunk_size=1000, overlap=200)
        assert len(chunks) >= 3
        # Each chunk should be at most 1000 characters
        for c in chunks:
            assert len(c) <= 1000

    def test_chunk_text_small_input(self):
        from rag import _chunk_text
        chunks = _chunk_text("Hello world", chunk_size=1000, overlap=200)
        assert len(chunks) == 1
        assert chunks[0] == "Hello world"

    def test_chunk_text_empty(self):
        from rag import _chunk_text
        chunks = _chunk_text("", chunk_size=1000, overlap=200)
        assert chunks == []

    def test_chunk_text_whitespace_only(self):
        from rag import _chunk_text
        chunks = _chunk_text("   \n\n  ", chunk_size=1000, overlap=200)
        assert chunks == []

    def test_chunk_overlap(self):
        """Adjacent chunks should share overlapping content."""
        from rag import _chunk_text
        text = "".join([str(i % 10) for i in range(3000)])
        chunks = _chunk_text(text, chunk_size=1000, overlap=200)
        # The end of chunk 0 should overlap with the start of chunk 1
        assert chunks[0][-200:] == chunks[1][:200]


class TestExtractText:

    def test_extract_text_from_pdf(self):
        """Should extract text from a simple PDF."""
        from rag import _extract_text_from_pdf
        # Create a minimal PDF with reportlab-free approach using pypdf
        # We'll use a real minimal PDF binary
        from pypdf import PdfWriter
        import io

        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        buf = io.BytesIO()
        writer.write(buf)
        pdf_bytes = buf.getvalue()

        # A blank page should return empty or whitespace-only text
        text = _extract_text_from_pdf(pdf_bytes)
        assert isinstance(text, str)

    def test_extract_text_from_invalid_pdf(self):
        """Invalid PDF bytes should raise an error."""
        from rag import _extract_text_from_pdf
        with pytest.raises(Exception):
            _extract_text_from_pdf(b"not a pdf file")


# ---------------------------------------------------------------------------
# API endpoint tests for /build_course_index
# ---------------------------------------------------------------------------

class TestBuildCourseIndexEndpoint:

    def _setup_course(self, instructor_email="instructor@test.com"):
        from api_server import courses
        from database import make_course_handle
        course_handle = make_course_handle("mit", "2025", "6.001")
        courses[course_handle] = {
            "instructor_gmail": instructor_email,
            "course_name": "Intro to CS",
            "folder_name": "test-bucket/mit-2025-6-001/",
        }
        return course_handle

    def _cleanup_course(self, course_handle):
        from api_server import courses
        if course_handle in courses:
            del courses[course_handle]

    def test_requires_auth(self, client):
        resp = client.post(
            "/build_course_index",
            json={"course_id": "6.001", "term_id": "2025", "institution_id": "mit"},
        )
        assert resp.status_code == 401

    def test_rejects_non_instructor(self, client):
        course_handle = self._setup_course(instructor_email="real-instructor@test.com")
        try:
            resp = client.post(
                "/build_course_index",
                json={"course_id": "6.001", "term_id": "2025", "institution_id": "mit"},
                headers=_auth_header(email="student@test.com"),
            )
            assert resp.status_code == 403
        finally:
            self._cleanup_course(course_handle)

    def test_returns_success_on_valid_request(self, client):
        course_handle = self._setup_course()
        try:
            with patch("api_server.build_course_index", new_callable=AsyncMock) as mock_build:
                mock_build.return_value = {
                    "status": "success",
                    "files_processed": 2,
                    "chunks_created": 15,
                }
                resp = client.post(
                    "/build_course_index",
                    json={"course_id": "6.001", "term_id": "2025", "institution_id": "mit"},
                    headers=_auth_header(email="instructor@test.com"),
                )

            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "success"
            assert data["files_processed"] == 2
            assert data["chunks_created"] == 15
            mock_build.assert_called_once_with(course_handle, "test-bucket/mit-2025-6-001/")
        finally:
            self._cleanup_course(course_handle)

    def test_handles_build_failure(self, client):
        course_handle = self._setup_course()
        try:
            with patch("api_server.build_course_index", new_callable=AsyncMock,
                       side_effect=Exception("GCS connection error")):
                resp = client.post(
                    "/build_course_index",
                    json={"course_id": "6.001", "term_id": "2025", "institution_id": "mit"},
                    headers=_auth_header(email="instructor@test.com"),
                )

            assert resp.status_code == 500
            assert "failed" in resp.json()["detail"].lower()
        finally:
            self._cleanup_course(course_handle)

    def test_missing_fields_returns_400(self, client):
        resp = client.post(
            "/build_course_index",
            json={"course_id": "6.001"},
            headers=_auth_header(email="instructor@test.com"),
        )
        assert resp.status_code == 422  # Pydantic validation error


# ---------------------------------------------------------------------------
# Tests for RAG context retrieval integration
# ---------------------------------------------------------------------------

class TestRetrieveContext:

    def _setup_db_mock(self, subcollection_mock):
        """Set up config.db to return a proper synchronous chain for collection/document calls."""
        import config
        mock_doc_ref = MagicMock()
        mock_doc_ref.collection.return_value = subcollection_mock

        mock_collection_ref = MagicMock()
        mock_collection_ref.document.return_value = mock_doc_ref

        config.db.collection = MagicMock(return_value=mock_collection_ref)

    @pytest.mark.asyncio
    async def test_retrieve_returns_formatted_chunks(self):
        """retrieve_context should return formatted text from Firestore vector search."""
        from rag import retrieve_context

        # Mock the embedding function
        with patch("rag._embed_texts") as mock_embed:
            mock_embed.return_value = [[0.1] * 768]

            # Mock Firestore vector search
            mock_doc1 = MagicMock()
            mock_doc1.to_dict.return_value = {
                "source_file": "lecture1.pdf",
                "text": "Neural networks are computational models.",
            }
            mock_doc2 = MagicMock()
            mock_doc2.to_dict.return_value = {
                "source_file": "lecture2.pdf",
                "text": "Backpropagation is a training algorithm.",
            }

            # Create an async iterator for stream()
            async def mock_stream():
                for doc in [mock_doc1, mock_doc2]:
                    yield doc

            mock_query = MagicMock()
            mock_query.stream = mock_stream

            mock_subcollection = MagicMock()
            mock_subcollection.find_nearest.return_value = mock_query

            self._setup_db_mock(mock_subcollection)

            result = await retrieve_context("mit-2025-6001", "What are neural networks?")

            assert "lecture1.pdf" in result
            assert "Neural networks are computational models." in result
            assert "lecture2.pdf" in result
            assert "---" in result  # separator between chunks

    @pytest.mark.asyncio
    async def test_retrieve_returns_empty_on_no_results(self):
        """retrieve_context should return empty string when no chunks match."""
        from rag import retrieve_context

        with patch("rag._embed_texts") as mock_embed:
            mock_embed.return_value = [[0.1] * 768]

            async def mock_stream():
                return
                yield  # make it an async generator

            mock_query = MagicMock()
            mock_query.stream = mock_stream

            mock_subcollection = MagicMock()
            mock_subcollection.find_nearest.return_value = mock_query

            self._setup_db_mock(mock_subcollection)

            result = await retrieve_context("mit-2025-6001", "irrelevant query")
            assert result == ""

    @pytest.mark.asyncio
    async def test_retrieve_handles_error_gracefully(self):
        """retrieve_context should return empty string on error, not raise."""
        from rag import retrieve_context

        with patch("rag._embed_texts") as mock_embed:
            mock_embed.return_value = [[0.1] * 768]

            mock_subcollection = MagicMock()
            mock_subcollection.find_nearest.side_effect = Exception("Vector index not found")

            self._setup_db_mock(mock_subcollection)

            result = await retrieve_context("mit-2025-6001", "test query")
            assert result == ""
