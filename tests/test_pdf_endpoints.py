"""Endpoint-level tests for the PDF-assignment flow.

Focus is on request validation, auth, and orchestration paths. The deep
multimodal scoring path is exercised via mocks rather than a real model
call.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from auth import create_jwt_token


@pytest.fixture(scope="module")
def client():
    with patch("api_server.load_course_info_from_db", new_callable=AsyncMock, return_value={}):
        with patch("api_server.load_notebooks_from_db", new_callable=AsyncMock, return_value={}):
            from api_server import app
            with TestClient(app, raise_server_exceptions=False) as c:
                yield c


def _instructor_header(email="instructor@test.com"):
    token = create_jwt_token(
        {"id": "1", "email": email, "name": "Instructor"},
        secret_key="test-secret-key-for-unit-tests",
    )
    return {"Authorization": f"Bearer {token}"}


def _setup_pdf_course(course_id="cp260", nb_id="lab1", instructor="instructor@test.com"):
    """Insert a course + PDF rubric into the in-memory cache; return course_handle."""
    from api_server import courses
    from database import make_course_handle

    ch = make_course_handle("iisc", "2025-26", course_id)
    courses[ch] = {
        "instructor_gmail": instructor,
        "isactive_tutor": True,
        nb_id: {
            "assignment_type": "pdf",
            "max_marks": 50.0,
            "problem_statement": "Build a TCP server",
            "rubric_text": "Correctness 30, code quality 20",
            "sample_graded_response": "",
            "isactive_eval": True,
        },
    }
    return ch


def _setup_notebook_course(course_id="cp260", nb_id="hw1", instructor="instructor@test.com"):
    from api_server import courses
    from database import make_course_handle

    ch = make_course_handle("iisc", "2025-26", course_id)
    courses[ch] = {
        "instructor_gmail": instructor,
        "isactive_tutor": True,
        nb_id: {"assignment_type": "notebook", "max_marks": 100.0, "isactive_eval": True},
    }
    return ch


def _teardown(course_handle):
    from api_server import courses
    courses.pop(course_handle, None)


# ---------------------------------------------------------------------------
# /upload_rubric in PDF mode
# ---------------------------------------------------------------------------


class TestUploadRubricFile:
    def test_requires_auth(self, client):
        resp = client.post(
            "/upload_rubric_file",
            data={"notebook_id": "lab1", "max_marks": "50.0",
                  "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                  "assignment_type": "pdf"},
            files={"file": ("rubric.pdf", b"%PDF-fake", "application/pdf")},
        )
        assert resp.status_code == 401

    def test_pdf_rubric_uploaded_to_gcs(self, client):
        from api_server import courses
        from database import make_course_handle

        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            with patch("api_server.upload_blob", return_value="gs://b/path/lab1.pdf") as mock_upload, \
                 patch("api_server.save_pdf_rubric", new_callable=AsyncMock) as mock_save:
                resp = client.post(
                    "/upload_rubric_file",
                    data={"notebook_id": "lab1", "max_marks": "50.0",
                          "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                          "assignment_type": "pdf"},
                    files={"file": ("rubric.pdf", b"%PDF-fake-content", "application/pdf")},
                    headers={"Authorization": _instructor_header()["Authorization"]},
                )
            assert resp.status_code == 200
            mock_upload.assert_called_once()
            args = mock_upload.call_args.args
            # destination_path should put the rubric under <course>/rubrics/<notebook>.pdf
            assert args[1] == f"{ch}/rubrics/lab1.pdf"
            mock_save.assert_awaited_once()
            # The cache reflects the new rubric
            assert courses[ch]["lab1"]["assignment_type"] == "pdf"
            assert courses[ch]["lab1"]["rubric_pdf_uri"] == "gs://b/path/lab1.pdf"
        finally:
            courses.pop(ch, None)

    def test_rejects_non_pdf_content_type(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            resp = client.post(
                "/upload_rubric_file",
                data={"notebook_id": "lab1", "max_marks": "50.0",
                      "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                      "assignment_type": "pdf"},
                files={"file": ("rubric.txt", b"hello", "text/plain")},
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
            assert "PDF" in resp.text
        finally:
            courses.pop(ch, None)

    def test_notebook_assignment_type_returns_400(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            resp = client.post(
                "/upload_rubric_file",
                data={"notebook_id": "hw1", "max_marks": "100.0",
                      "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                      "assignment_type": "notebook"},
                files={"file": ("rubric.ipynb", b"{}", "application/x-ipynb+json")},
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
            assert "upload_rubric_link" in resp.text or "Drive" in resp.text
        finally:
            courses.pop(ch, None)


class TestUploadRubricLink:
    def test_requires_auth(self, client):
        resp = client.post(
            "/upload_rubric_link",
            json={"notebook_id": "lab1", "max_marks": 50.0,
                  "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                  "assignment_type": "pdf",
                  "drive_share_link": "https://drive.google.com/file/d/X/view"},
        )
        assert resp.status_code == 401

    def test_pdf_via_drive_link_uploaded_to_gcs(self, client):
        from api_server import courses
        from database import make_course_handle

        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            with patch("api_server.download_file_bytes_sa", return_value=b"%PDF-rubric"), \
                 patch("api_server.upload_blob", return_value="gs://b/path/lab1.pdf") as mock_upload, \
                 patch("api_server.save_pdf_rubric", new_callable=AsyncMock) as mock_save:
                resp = client.post(
                    "/upload_rubric_link",
                    json={"notebook_id": "lab1", "max_marks": 50.0,
                          "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                          "assignment_type": "pdf",
                          "drive_share_link": "https://drive.google.com/file/d/RUBRIC_ID/view"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            mock_upload.assert_called_once()
            mock_save.assert_awaited_once()
            assert courses[ch]["lab1"]["rubric_pdf_uri"] == "gs://b/path/lab1.pdf"
        finally:
            courses.pop(ch, None)

    def test_drive_download_failure_502(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            with patch("api_server.download_file_bytes_sa", return_value=None):
                resp = client.post(
                    "/upload_rubric_link",
                    json={"notebook_id": "lab1", "max_marks": 50.0,
                          "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                          "assignment_type": "pdf",
                          "drive_share_link": "https://drive.google.com/file/d/X/view"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 502
            assert "shared" in resp.text.lower()
        finally:
            courses.pop(ch, None)

    def test_notebook_returns_501_with_pointer_to_colab_client(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            resp = client.post(
                "/upload_rubric_link",
                json={"notebook_id": "hw1", "max_marks": 100.0,
                      "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                      "assignment_type": "notebook",
                      "drive_share_link": "https://colab.research.google.com/drive/X"},
                headers=_instructor_header(),
            )
            assert resp.status_code == 501
            assert "Colab" in resp.text or "ta.upload_rubric" in resp.text
        finally:
            courses.pop(ch, None)

    def test_bad_link_400(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            resp = client.post(
                "/upload_rubric_link",
                json={"notebook_id": "lab1", "max_marks": 50.0,
                      "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                      "assignment_type": "pdf",
                      "drive_share_link": "https://example.com/not-a-drive-link"},
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
        finally:
            courses.pop(ch, None)


class TestUploadPdfRubric:
    def test_pdf_rubric_succeeds(self, client):
        from api_server import courses
        from database import make_course_handle

        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            with patch("api_server.save_pdf_rubric", new_callable=AsyncMock):
                resp = client.post(
                    "/upload_rubric",
                    json={
                        "notebook_id": "lab1", "max_marks": 50.0,
                        "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                        "assignment_type": "pdf",
                        "problem_statement": "Build a TCP server",
                        "rubric_text": "Correctness 30, quality 20",
                        "sample_graded_response": "Sample text",
                    },
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            assert courses[ch]["lab1"]["assignment_type"] == "pdf"
            assert courses[ch]["lab1"]["problem_statement"] == "Build a TCP server"
        finally:
            _teardown(ch)

    def test_pdf_rubric_missing_required_field_400(self, client):
        from api_server import courses
        from database import make_course_handle

        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            resp = client.post(
                "/upload_rubric",
                json={
                    "notebook_id": "lab1", "max_marks": 50.0,
                    "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                    "assignment_type": "pdf",
                    # missing problem_statement and rubric_text
                },
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
            assert "problem_statement" in resp.text
        finally:
            _teardown(ch)


# ---------------------------------------------------------------------------
# /ingest_pdf_submissions
# ---------------------------------------------------------------------------


class TestIngestPdfSubmissions:
    def test_requires_auth(self, client):
        resp = client.post(
            "/ingest_pdf_submissions",
            json={
                "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                "notebook_id": "lab1",
                "drive_folder_url": "https://drive.google.com/drive/folders/X",
            },
        )
        assert resp.status_code == 401

    def test_course_not_found(self, client):
        resp = client.post(
            "/ingest_pdf_submissions",
            json={
                "institution_id": "iisc", "term_id": "2025-26", "course_id": "missing",
                "notebook_id": "lab1",
                "drive_folder_url": "https://drive.google.com/drive/folders/X",
            },
            headers=_instructor_header(),
        )
        assert resp.status_code == 404

    def test_rejects_non_pdf_assignment(self, client):
        ch = _setup_notebook_course(course_id="cp261", nb_id="hw1")
        try:
            resp = client.post(
                "/ingest_pdf_submissions",
                json={
                    "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp261",
                    "notebook_id": "hw1",
                    "drive_folder_url": "https://drive.google.com/drive/folders/X",
                },
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
            assert "PDF" in resp.text
        finally:
            _teardown(ch)

    def test_bad_drive_url(self, client):
        ch = _setup_pdf_course()
        try:
            resp = client.post(
                "/ingest_pdf_submissions",
                json={
                    "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                    "notebook_id": "lab1",
                    "drive_folder_url": "https://example.com/not-a-drive-link",
                },
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
        finally:
            _teardown(ch)

    def test_happy_path_skips_unchanged_and_ingests_new(self, client):
        ch = _setup_pdf_course()
        try:
            files = [
                {"id": "FID_A", "name": "alice_lab.pdf", "modifiedTime": "T1", "size": "1000"},
                {"id": "FID_B", "name": "bob_lab.pdf", "modifiedTime": "T2", "size": "2000"},
            ]

            with patch("api_server.list_pdfs_in_folder_sa", return_value=files), \
                 patch("api_server.download_file_bytes_sa", return_value=b"%PDF-fake"), \
                 patch("api_server.upload_blob", return_value="gs://b/path"), \
                 patch("api_server.extract_first_pages_text", return_value="cover text"), \
                 patch("api_server.extract_authors_with_gemini", new_callable=AsyncMock, return_value=["Alice"]), \
                 patch("api_server.get_student_directory", new_callable=AsyncMock, return_value={"alice@iisc.ac.in": "Alice"}), \
                 patch("api_server.match_author_to_student", return_value="alice@iisc.ac.in"), \
                 patch("api_server.add_placeholder_student", new_callable=AsyncMock), \
                 patch("api_server.upsert_pdf_submission", new_callable=AsyncMock), \
                 patch("api_server.get_pdf_submission", new_callable=AsyncMock,
                       side_effect=[None,  # FID_A — not yet ingested
                                    {"drive_modified_time": "T2"}]):  # FID_B — same modified_time → skip
                resp = client.post(
                    "/ingest_pdf_submissions",
                    json={
                        "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                        "notebook_id": "lab1",
                        "drive_folder_url": "https://drive.google.com/drive/folders/X",
                    },
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["ingested"]) == 1
            assert data["ingested"][0]["drive_file_id"] == "FID_A"
            assert data["ingested"][0]["student_ids"] == ["alice@iisc.ac.in"]
            assert len(data["skipped"]) == 1
            assert data["skipped"][0]["drive_file_id"] == "FID_B"
        finally:
            _teardown(ch)

    def test_oversize_file_recorded_as_failed(self, client):
        ch = _setup_pdf_course()
        try:
            huge = 60 * 1024 * 1024  # exceeds MAX_PDF_SIZE_BYTES (50 MB)
            files = [{"id": "FID_X", "name": "huge.pdf", "modifiedTime": "T", "size": str(huge)}]

            with patch("api_server.list_pdfs_in_folder_sa", return_value=files):
                resp = client.post(
                    "/ingest_pdf_submissions",
                    json={
                        "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                        "notebook_id": "lab1",
                        "drive_folder_url": "https://drive.google.com/drive/folders/X",
                    },
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["failed"]) == 1
            assert "too large" in data["failed"][0]["error"].lower()
        finally:
            _teardown(ch)


# ---------------------------------------------------------------------------
# /grade_pdf_assignment
# ---------------------------------------------------------------------------


class TestGradePdfAssignment:
    def test_requires_auth(self, client):
        resp = client.post(
            "/grade_pdf_assignment",
            json={
                "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                "notebook_id": "lab1",
            },
        )
        assert resp.status_code == 401

    def test_rejects_non_pdf_assignment(self, client):
        ch = _setup_notebook_course(course_id="cp262", nb_id="hw1")
        try:
            resp = client.post(
                "/grade_pdf_assignment",
                json={
                    "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp262",
                    "notebook_id": "hw1",
                },
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
        finally:
            _teardown(ch)

    def test_no_submissions_404(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.list_pdf_submissions", new_callable=AsyncMock, return_value=[]):
                resp = client.post(
                    "/grade_pdf_assignment",
                    json={
                        "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                        "notebook_id": "lab1",
                    },
                    headers=_instructor_header(),
                )
            assert resp.status_code == 404
        finally:
            _teardown(ch)


# ---------------------------------------------------------------------------
# /regrade_pdf_submission
# ---------------------------------------------------------------------------


class TestDownloadMarks:
    def test_requires_auth(self, client):
        resp = client.get(
            "/download_marks",
            params={"institution_id": "iisc", "term_id": "2025-26",
                    "course_id": "cp260", "notebook_id": "lab1"},
        )
        assert resp.status_code == 401

    def test_csv_for_all_students(self, client):
        ch = _setup_pdf_course()
        try:
            marks = [
                {"student_id": "alice@iisc.ac.in", "total_marks": 42.0},
                {"student_id": "bob@iisc.ac.in", "total_marks": -1},   # submitted, ungraded
                {"student_id": "carol@iisc.ac.in", "total_marks": None}, # never submitted
            ]
            with patch("api_server.get_marks_list", new_callable=AsyncMock,
                       return_value=(50.0, marks)), \
                 patch("api_server.get_student_directory", new_callable=AsyncMock,
                       return_value={"alice@iisc.ac.in": "Alice Smith",
                                     "bob@iisc.ac.in": "Bob Jones",
                                     "carol@iisc.ac.in": "Carol Lee"}):
                resp = client.get(
                    "/download_marks",
                    params={"institution_id": "iisc", "term_id": "2025-26",
                            "course_id": "cp260", "notebook_id": "lab1"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/csv")
            assert 'attachment' in resp.headers["content-disposition"]
            body = resp.text
            assert "student_id,name,total_marks,max_marks" in body
            assert "alice@iisc.ac.in,Alice Smith,42.0,50.0" in body
            assert "bob@iisc.ac.in,Bob Jones,not_graded,50.0" in body
            assert "carol@iisc.ac.in,Carol Lee,,50.0" in body
        finally:
            _teardown(ch)

    def test_csv_for_one_student(self, client):
        ch = _setup_pdf_course()
        try:
            marks = [
                {"student_id": "alice@iisc.ac.in", "total_marks": 42.0},
                {"student_id": "bob@iisc.ac.in", "total_marks": 30.0},
            ]
            with patch("api_server.get_marks_list", new_callable=AsyncMock,
                       return_value=(50.0, marks)), \
                 patch("api_server.get_student_directory", new_callable=AsyncMock,
                       return_value={"alice@iisc.ac.in": "Alice", "bob@iisc.ac.in": "Bob"}):
                resp = client.get(
                    "/download_marks",
                    params={"institution_id": "iisc", "term_id": "2025-26",
                            "course_id": "cp260", "notebook_id": "lab1",
                            "student_id": "alice@iisc.ac.in"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            body = resp.text
            assert "alice@iisc.ac.in" in body
            assert "bob@iisc.ac.in" not in body
        finally:
            _teardown(ch)


class TestDownloadGraderResponse:
    def test_requires_auth(self, client):
        resp = client.get(
            "/download_grader_response",
            params={"institution_id": "iisc", "term_id": "2025-26",
                    "course_id": "cp260", "notebook_id": "lab1"},
        )
        assert resp.status_code == 401

    def test_json_keyed_by_student(self, client):
        ch = _setup_pdf_course()
        try:
            student_list = ["alice@iisc.ac.in", "bob@iisc.ac.in"]

            async def fake_fetch(db, course_handle, notebook_id, student_id):
                if student_id == "alice@iisc.ac.in":
                    return {
                        "student_id": "alice@iisc.ac.in",
                        "total_marks": 42.0,
                        "max_marks": 50.0,
                        "feedback": {"overall": {"marks": 42.0, "response": "good"}},
                    }
                return None  # bob has no graded response yet

            with patch("api_server.get_student_list", new_callable=AsyncMock,
                       return_value=student_list), \
                 patch("api_server.fetch_grader_response", side_effect=fake_fetch), \
                 patch("api_server.get_student_directory", new_callable=AsyncMock,
                       return_value={"alice@iisc.ac.in": "Alice", "bob@iisc.ac.in": "Bob"}):
                resp = client.get(
                    "/download_grader_response",
                    params={"institution_id": "iisc", "term_id": "2025-26",
                            "course_id": "cp260", "notebook_id": "lab1"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("application/json")
            assert "attachment" in resp.headers["content-disposition"]
            data = resp.json()
            assert "alice@iisc.ac.in" in data
            assert data["alice@iisc.ac.in"]["name"] == "Alice"
            assert data["alice@iisc.ac.in"]["total_marks"] == 42.0
            assert data["alice@iisc.ac.in"]["grader_response"]["overall"]["marks"] == 42.0
            # Bob had no feedback — should be omitted from the dict.
            assert "bob@iisc.ac.in" not in data
        finally:
            _teardown(ch)


class TestGradeAssignmentDispatch:
    def test_requires_auth(self, client):
        resp = client.post(
            "/grade_assignment",
            json={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                  "notebook_id": "lab1"},
        )
        assert resp.status_code == 401

    def test_pdf_assignment_dispatches_to_pdf_path(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.grade_pdf_assignment", new_callable=AsyncMock) as mock_pdf, \
                 patch("api_server.grade_notebook", new_callable=AsyncMock) as mock_nb:
                mock_pdf.return_value = MagicMock()  # any return; dispatch is what we test
                resp = client.post(
                    "/grade_assignment",
                    json={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                          "notebook_id": "lab1", "do_regrade": True},
                    headers=_instructor_header(),
                )
            mock_pdf.assert_awaited_once()
            mock_nb.assert_not_awaited()
            # The PDF body forwarded is a GradePdfAssignmentRequest
            forwarded = mock_pdf.call_args.args[0]
            assert forwarded.notebook_id == "lab1"
            assert forwarded.do_regrade is True
        finally:
            _teardown(ch)

    def test_notebook_assignment_dispatches_to_notebook_path(self, client):
        ch = _setup_notebook_course(course_id="cp260", nb_id="hw1")
        try:
            with patch("api_server.grade_pdf_assignment", new_callable=AsyncMock) as mock_pdf, \
                 patch("api_server.grade_notebook", new_callable=AsyncMock) as mock_nb:
                mock_nb.return_value = MagicMock()
                resp = client.post(
                    "/grade_assignment",
                    json={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                          "notebook_id": "hw1", "student_id": "alice@x.com", "do_regrade": False},
                    headers=_instructor_header(),
                )
            mock_pdf.assert_not_awaited()
            mock_nb.assert_awaited_once()
            forwarded = mock_nb.call_args.args[0]
            assert forwarded.notebook_id == "hw1"
            assert forwarded.student_id == "alice@x.com"
        finally:
            _teardown(ch)

    def test_legacy_rubric_without_assignment_type_treated_as_notebook(self, client):
        # Old courses pre-date the assignment_type discriminator. They should
        # still grade via the notebook path.
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "legacy")
        courses[ch] = {
            "instructor_gmail": "instructor@test.com",
            "hw1": {"max_marks": 100.0},  # no assignment_type
        }
        try:
            with patch("api_server.grade_pdf_assignment", new_callable=AsyncMock) as mock_pdf, \
                 patch("api_server.grade_notebook", new_callable=AsyncMock) as mock_nb:
                client.post(
                    "/grade_assignment",
                    json={"institution_id": "iisc", "term_id": "2025-26", "course_id": "legacy",
                          "notebook_id": "hw1"},
                    headers=_instructor_header(),
                )
            mock_pdf.assert_not_awaited()
            mock_nb.assert_awaited_once()
        finally:
            courses.pop(ch, None)

    def test_missing_rubric_404(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}  # no notebook
        try:
            resp = client.post(
                "/grade_assignment",
                json={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                      "notebook_id": "lab_does_not_exist"},
                headers=_instructor_header(),
            )
            assert resp.status_code == 404
        finally:
            courses.pop(ch, None)


class TestRegradePdfSubmission:
    def test_requires_auth(self, client):
        resp = client.post(
            "/regrade_pdf_submission",
            json={
                "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                "notebook_id": "lab1", "student_id": "alice@iisc.ac.in",
            },
        )
        assert resp.status_code == 401

    def test_no_mirror_doc_404(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.get_student_pdf_mirror", new_callable=AsyncMock, return_value=None):
                resp = client.post(
                    "/regrade_pdf_submission",
                    json={
                        "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                        "notebook_id": "lab1", "student_id": "alice@iisc.ac.in",
                    },
                    headers=_instructor_header(),
                )
            assert resp.status_code == 404
        finally:
            _teardown(ch)

    def test_mirror_without_drive_file_id_404(self, client):
        ch = _setup_pdf_course()
        try:
            with patch(
                "api_server.get_student_pdf_mirror",
                new_callable=AsyncMock,
                return_value={"assignment_type": "pdf"},  # no drive_file_id
            ):
                resp = client.post(
                    "/regrade_pdf_submission",
                    json={
                        "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                        "notebook_id": "lab1", "student_id": "alice@iisc.ac.in",
                    },
                    headers=_instructor_header(),
                )
            assert resp.status_code == 404
            assert "drive_file_id" in resp.text
        finally:
            _teardown(ch)
