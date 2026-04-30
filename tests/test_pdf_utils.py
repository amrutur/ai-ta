"""Tests for pdf_utils — PDF text extraction, name slug helpers, and student matching."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pdf_utils import (
    PLACEHOLDER_EMAIL_DOMAIN,
    extract_authors_with_gemini,
    extract_first_pages_text,
    is_placeholder_student_id,
    make_placeholder_student_id,
    match_author_to_student,
    slugify_name,
)


class TestSlugifyName:
    def test_basic(self):
        assert slugify_name("Jane Doe") == "jane-doe"

    def test_strips_punctuation(self):
        assert slugify_name("J. R. R. Tolkien") == "j-r-r-tolkien"

    def test_collapses_whitespace(self):
        assert slugify_name("  Alice    Bob  ") == "alice-bob"

    def test_empty_falls_back_to_unknown(self):
        assert slugify_name("") == "unknown"
        assert slugify_name("   ") == "unknown"
        assert slugify_name("###") == "unknown"


class TestPlaceholderId:
    def test_format(self):
        sid = make_placeholder_student_id("Jane Doe")
        assert sid == f"jane-doe@{PLACEHOLDER_EMAIL_DOMAIN}"

    def test_round_trip(self):
        sid = make_placeholder_student_id("Anyone At All")
        assert is_placeholder_student_id(sid)

    def test_real_email_is_not_placeholder(self):
        assert not is_placeholder_student_id("alice@iisc.ac.in")
        assert not is_placeholder_student_id("")


class TestExtractFirstPagesText:
    def test_returns_empty_on_invalid_pdf(self):
        # garbage bytes — pypdf should raise; we should swallow and return ""
        assert extract_first_pages_text(b"not a real pdf") == ""

    @patch("pdf_utils.PdfReader")
    def test_concatenates_first_n_pages(self, mock_reader_cls):
        # Build mock pages that return text via .extract_text()
        page1 = MagicMock()
        page1.extract_text.return_value = "Page one"
        page2 = MagicMock()
        page2.extract_text.return_value = "Page two"
        page3 = MagicMock()
        page3.extract_text.return_value = "Page three"
        page4 = MagicMock()
        page4.extract_text.return_value = "Page four"

        reader = MagicMock()
        reader.pages = [page1, page2, page3, page4]
        mock_reader_cls.return_value = reader

        out = extract_first_pages_text(b"%PDF-fake", max_pages=2)
        assert "Page one" in out
        assert "Page two" in out
        assert "Page three" not in out

    @patch("pdf_utils.PdfReader")
    def test_skips_pages_that_raise(self, mock_reader_cls):
        good = MagicMock()
        good.extract_text.return_value = "Good page"
        bad = MagicMock()
        bad.extract_text.side_effect = RuntimeError("nope")

        reader = MagicMock()
        reader.pages = [bad, good]
        mock_reader_cls.return_value = reader

        out = extract_first_pages_text(b"%PDF-fake", max_pages=5)
        assert "Good page" in out


class TestMatchAuthorToStudent:
    def test_exact_match(self):
        directory = {
            "alice@iisc.ac.in": "Alice Smith",
            "bob@iisc.ac.in": "Bob Jones",
        }
        assert match_author_to_student("Alice Smith", directory) == "alice@iisc.ac.in"

    def test_minor_typo_still_matches(self):
        directory = {"alice@iisc.ac.in": "Alice Smith"}
        # "Alic Smith" should still hit threshold
        assert match_author_to_student("Alic Smith", directory) == "alice@iisc.ac.in"

    def test_no_match_returns_none(self):
        directory = {"alice@iisc.ac.in": "Alice Smith"}
        assert match_author_to_student("Zachariah Quux", directory) is None

    def test_empty_directory(self):
        assert match_author_to_student("Any Name", {}) is None

    def test_empty_name(self):
        directory = {"alice@iisc.ac.in": "Alice Smith"}
        assert match_author_to_student("", directory) is None

    def test_skips_entries_with_blank_names(self):
        directory = {
            "noname@iisc.ac.in": "",
            "alice@iisc.ac.in": "Alice Smith",
        }
        assert match_author_to_student("Alice Smith", directory) == "alice@iisc.ac.in"


class TestExtractAuthorsWithGemini:
    @pytest.mark.asyncio
    async def test_empty_text_returns_empty(self):
        assert await extract_authors_with_gemini("") == []
        assert await extract_authors_with_gemini("   \n\n  ") == []

    @pytest.mark.asyncio
    @patch("vertexai.generative_models.GenerativeModel")
    async def test_parses_structured_output(self, mock_model_cls):
        instance = MagicMock()
        response = MagicMock()
        response.text = '{"authors": ["Alice Smith", "Bob Jones"]}'
        instance.generate_content = MagicMock(return_value=response)
        mock_model_cls.return_value = instance

        result = await extract_authors_with_gemini("Title page text...")
        assert result == ["Alice Smith", "Bob Jones"]

    @pytest.mark.asyncio
    @patch("vertexai.generative_models.GenerativeModel")
    async def test_strips_blank_authors(self, mock_model_cls):
        instance = MagicMock()
        response = MagicMock()
        response.text = '{"authors": ["Alice", "", "  ", "Bob"]}'
        instance.generate_content = MagicMock(return_value=response)
        mock_model_cls.return_value = instance

        assert await extract_authors_with_gemini("Some text") == ["Alice", "Bob"]

    @pytest.mark.asyncio
    @patch("vertexai.generative_models.GenerativeModel")
    async def test_swallows_llm_errors(self, mock_model_cls):
        instance = MagicMock()
        instance.generate_content = MagicMock(side_effect=RuntimeError("boom"))
        mock_model_cls.return_value = instance

        # Don't crash the ingest — return empty list and let caller create a placeholder.
        assert await extract_authors_with_gemini("Some text") == []

    @pytest.mark.asyncio
    @patch("vertexai.generative_models.GenerativeModel")
    async def test_swallows_invalid_json(self, mock_model_cls):
        instance = MagicMock()
        response = MagicMock()
        response.text = "not json at all"
        instance.generate_content = MagicMock(return_value=response)
        mock_model_cls.return_value = instance

        assert await extract_authors_with_gemini("Some text") == []


# Make AsyncMock unused-import warning go away if linter complains
_ = AsyncMock
