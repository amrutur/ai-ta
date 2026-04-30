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
            # The cache reflects the new rubric in the 2D schema.
            assert courses[ch]["lab1"]["assignment_type"] == "report"
            assert courses[ch]["lab1"]["submission_type"] == "pdf"
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
            # Error message should point Colab/q&a users at the right path.
            assert "Colab" in resp.text or "q&a" in resp.text or "ta.upload_rubric" in resp.text
        finally:
            courses.pop(ch, None)


class TestUploadPdfSubmission:
    def _form(self, **extra):
        d = {"institution_id": "iisc", "term_id": "2025-26",
             "course_id": "cp260", "notebook_id": "lab1",
             "student_ids": "alice@iisc.ac.in, bob@iisc.ac.in"}
        d.update(extra)
        return d

    def _pdf(self, content=b"%PDF-fake-content"):
        return ("submission.pdf", content, "application/pdf")

    def test_requires_auth(self, client):
        resp = client.post(
            "/upload_pdf_submission",
            data=self._form(),
            files={"file": self._pdf()},
        )
        assert resp.status_code == 401

    def test_no_rubric_404(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}  # no rubric
        try:
            resp = client.post(
                "/upload_pdf_submission",
                data=self._form(),
                files={"file": self._pdf()},
                headers=_instructor_header(),
            )
            assert resp.status_code == 404
        finally:
            courses.pop(ch, None)

    def test_wrong_rubric_type_400(self, client):
        ch = _setup_notebook_course(course_id="cp260", nb_id="lab1")
        try:
            resp = client.post(
                "/upload_pdf_submission",
                data=self._form(),
                files={"file": self._pdf()},
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
            assert "PDF" in resp.text
        finally:
            _teardown(ch)

    def test_non_pdf_content_type_400(self, client):
        ch = _setup_pdf_course()
        try:
            resp = client.post(
                "/upload_pdf_submission",
                data=self._form(),
                files={"file": ("notpdf.txt", b"hello", "text/plain")},
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
        finally:
            _teardown(ch)

    def test_empty_file_400(self, client):
        ch = _setup_pdf_course()
        try:
            resp = client.post(
                "/upload_pdf_submission",
                data=self._form(),
                files={"file": self._pdf(content=b"")},
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
        finally:
            _teardown(ch)

    def test_invalid_email_400(self, client):
        ch = _setup_pdf_course()
        try:
            resp = client.post(
                "/upload_pdf_submission",
                data=self._form(student_ids="alice, not-an-email"),
                files={"file": self._pdf()},
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
        finally:
            _teardown(ch)

    def test_happy_path_creates_tracking_and_mirrors(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.upload_blob", return_value="gs://b/path/manual-X.pdf") as mock_upload, \
                 patch("api_server.get_student_directory", new_callable=AsyncMock,
                       return_value={"alice@iisc.ac.in": "Alice"}), \
                 patch("api_server.upsert_student", new_callable=AsyncMock) as mock_upsert_stu, \
                 patch("api_server.upsert_pdf_submission", new_callable=AsyncMock) as mock_upsert_pdf:
                resp = client.post(
                    "/upload_pdf_submission",
                    data=self._form(),
                    files={"file": self._pdf()},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data["student_ids"] == ["alice@iisc.ac.in", "bob@iisc.ac.in"]
            # bob auto-enrolled (not in roster); alice already there
            assert data["auto_added_students"] == ["bob@iisc.ac.in"]
            assert data["drive_file_id"].startswith("manual-")
            assert data["filename"] == "submission.pdf"
            mock_upload.assert_called_once()
            mock_upsert_stu.assert_awaited_once()  # only bob
            mock_upsert_pdf.assert_awaited_once()
            # Tracking-doc payload: extracted_authors=[] because we didn't
            # run extraction on this manual upload.
            kw = mock_upsert_pdf.call_args.kwargs
            assert kw["extracted_authors"] == []
            assert kw["student_ids"] == ["alice@iisc.ac.in", "bob@iisc.ac.in"]
        finally:
            _teardown(ch)

    def test_idempotent_same_pdf_same_drive_file_id(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.upload_blob", return_value="gs://b/p.pdf"), \
                 patch("api_server.get_student_directory", new_callable=AsyncMock,
                       return_value={}), \
                 patch("api_server.upsert_student", new_callable=AsyncMock), \
                 patch("api_server.upsert_pdf_submission", new_callable=AsyncMock):
                content = b"%PDF-1.4 idempotent test content"
                r1 = client.post(
                    "/upload_pdf_submission",
                    data=self._form(),
                    files={"file": ("a.pdf", content, "application/pdf")},
                    headers=_instructor_header(),
                )
                r2 = client.post(
                    "/upload_pdf_submission",
                    data=self._form(),
                    files={"file": ("a.pdf", content, "application/pdf")},
                    headers=_instructor_header(),
                )
            assert r1.status_code == 200 and r2.status_code == 200
            # Same content → same SHA → same drive_file_id, so the second
            # upload overwrites the same tracking doc rather than creating
            # a duplicate.
            assert r1.json()["drive_file_id"] == r2.json()["drive_file_id"]
        finally:
            _teardown(ch)

    def test_dedupes_email_list(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.upload_blob", return_value="gs://b/p.pdf"), \
                 patch("api_server.get_student_directory", new_callable=AsyncMock,
                       return_value={"alice@iisc.ac.in": "Alice"}), \
                 patch("api_server.upsert_student", new_callable=AsyncMock), \
                 patch("api_server.upsert_pdf_submission", new_callable=AsyncMock):
                resp = client.post(
                    "/upload_pdf_submission",
                    # email mentioned twice with different cases → one entry
                    data=self._form(student_ids="alice@iisc.ac.in, ALICE@IISC.AC.IN"),
                    files={"file": self._pdf()},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            assert resp.json()["student_ids"] == ["alice@iisc.ac.in"]
        finally:
            _teardown(ch)


class TestDebugPdfAuthors:
    def test_requires_auth(self, client):
        resp = client.post(
            "/debug_pdf_authors",
            json={"institution_id": "iisc", "term_id": "2025-26",
                  "course_id": "cp260",
                  "drive_url": "https://drive.google.com/file/d/F/view"},
        )
        assert resp.status_code == 401

    def test_drive_download_failure_surfaces_sa_email(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.download_file_bytes_sa", return_value=None):
                resp = client.post(
                    "/debug_pdf_authors",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260",
                          "drive_url": "https://drive.google.com/file/d/FILE_ID/view"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data['ok'] is False
            assert "service account" in (data.get('hint') or '').lower()
            assert data['drive_file_id'] == "FILE_ID"
        finally:
            _teardown(ch)

    def test_image_only_pdf_hint(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.download_file_bytes_sa", return_value=b"%PDF-fake"), \
                 patch("api_server.extract_first_pages_text", return_value=""), \
                 patch("api_server.extract_authors_with_gemini",
                       new_callable=AsyncMock,
                       return_value=([], {"model": "gemini-2.5-flash",
                                          "prompt_chars": 0,
                                          "llm_raw_response": None,
                                          "parsed": None,
                                          "error": "no text extracted (PDF may be image-only / scanned)"})), \
                 patch("api_server.get_student_directory", new_callable=AsyncMock,
                       return_value={}):
                resp = client.post(
                    "/debug_pdf_authors",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260",
                          "drive_url": "https://drive.google.com/file/d/FILE_ID/view"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data['ok'] is True
            assert data['text_extracted_chars'] == 0
            assert "scanned" in data['hint']
            assert data['extracted_authors'] == []
        finally:
            _teardown(ch)

    def test_authors_with_partial_roster_match(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.download_file_bytes_sa", return_value=b"%PDF-fake"), \
                 patch("api_server.extract_first_pages_text",
                       return_value="Title page\nBy Alice Smith and Bob Jones"), \
                 patch("api_server.extract_authors_with_gemini",
                       new_callable=AsyncMock,
                       return_value=(["Alice Smith", "Bob Jones"],
                                     {"model": "gemini-2.5-flash",
                                      "prompt_chars": 200,
                                      "llm_raw_response": '{"authors":["Alice Smith","Bob Jones"]}',
                                      "parsed": {"authors": ["Alice Smith", "Bob Jones"]},
                                      "error": None})), \
                 patch("api_server.get_student_directory", new_callable=AsyncMock,
                       return_value={"alice@iisc.ac.in": "Alice Smith"}):  # Bob NOT enrolled
                resp = client.post(
                    "/debug_pdf_authors",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260",
                          "drive_url": "https://drive.google.com/file/d/FILE_ID/view"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data['ok'] is True
            assert data['extracted_authors'] == ["Alice Smith", "Bob Jones"]
            matches = {m['extracted_name']: m for m in data['roster_matches']}
            assert matches["Alice Smith"]['matched_email'] == "alice@iisc.ac.in"
            assert matches["Alice Smith"]['would_create_placeholder'] is False
            assert matches["Bob Jones"]['matched_email'] is None
            assert matches["Bob Jones"]['would_create_placeholder'] is True
            assert "roster" in (data['hint'] or '').lower()
            assert data['llm_debug']['parsed']['authors'] == ["Alice Smith", "Bob Jones"]
        finally:
            _teardown(ch)


class TestReassignPdfSubmission:
    def test_requires_auth(self, client):
        resp = client.post(
            "/reassign_pdf_submission",
            json={"institution_id": "iisc", "term_id": "2025-26",
                  "course_id": "cp260", "notebook_id": "lab1",
                  "drive_file_id": "F", "student_ids": ["a@x.com"]},
        )
        assert resp.status_code == 401

    def test_unknown_drive_file_404(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.get_pdf_submission", new_callable=AsyncMock,
                       return_value=None):
                resp = client.post(
                    "/reassign_pdf_submission",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260", "notebook_id": "lab1",
                          "drive_file_id": "MISSING",
                          "student_ids": ["alice@x.com"]},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 404
        finally:
            _teardown(ch)

    def test_invalid_email_400(self, client):
        ch = _setup_pdf_course()
        try:
            resp = client.post(
                "/reassign_pdf_submission",
                json={"institution_id": "iisc", "term_id": "2025-26",
                      "course_id": "cp260", "notebook_id": "lab1",
                      "drive_file_id": "F", "student_ids": ["not-an-email"]},
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
        finally:
            _teardown(ch)

    def test_happy_path_moves_grade_off_placeholder(self, client):
        ch = _setup_pdf_course()
        try:
            tracking = {
                "drive_file_id": "F",
                "drive_modified_time": "T1",
                "gcs_uri": "gs://b/F.pdf",
                "original_filename": "lab2.pdf",
                "extracted_authors": [],
                "student_ids": ["unknown-lab2@pending.local"],
                "graded_at": "2026-04-30T00:00:00Z",
                "total_marks": 42.0,
                "max_marks": 50.0,
                "grader_response": {"overall": {"marks": 42.0, "response": "good"}},
            }

            patches = [
                patch("api_server.get_pdf_submission", new_callable=AsyncMock,
                      return_value=tracking),
                patch("api_server.get_student_directory", new_callable=AsyncMock,
                      return_value={"alice@iisc.ac.in": "Alice"}),  # Bob not enrolled yet
                patch("api_server.upsert_student", new_callable=AsyncMock),
                patch("api_server.delete_student_pdf_mirror", new_callable=AsyncMock,
                      return_value=True),
                patch("api_server.upsert_pdf_submission", new_callable=AsyncMock),
                patch("api_server.update_pdf_submission_grade", new_callable=AsyncMock),
            ]
            with patches[0] as _, patches[1] as _, \
                 patches[2] as mock_upsert_stu, \
                 patches[3] as mock_del, \
                 patches[4] as mock_ups, \
                 patches[5] as mock_upd:
                resp = client.post(
                    "/reassign_pdf_submission",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260", "notebook_id": "lab1",
                          "drive_file_id": "F",
                          "student_ids": ["alice@iisc.ac.in", "bob@iisc.ac.in"]},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data['old_student_ids'] == ["unknown-lab2@pending.local"]
            assert data['new_student_ids'] == ["alice@iisc.ac.in", "bob@iisc.ac.in"]
            # Bob auto-added (not in roster); Alice was already enrolled.
            assert data['auto_added_students'] == ["bob@iisc.ac.in"]
            assert data['cleared_placeholders'] == ["unknown-lab2@pending.local"]
            mock_upsert_stu.assert_awaited_once()  # only Bob
            mock_del.assert_awaited_once()         # delete the placeholder mirror
            mock_ups.assert_awaited_once()         # rewrite tracking + new mirrors
            mock_upd.assert_awaited_once()         # carry the grade onto new mirrors
            grade_kwargs = mock_upd.call_args.kwargs
            assert grade_kwargs['student_ids'] == ["alice@iisc.ac.in", "bob@iisc.ac.in"]
            assert grade_kwargs['total_marks'] == 42.0
        finally:
            _teardown(ch)

    def test_skips_grade_carry_when_not_yet_graded(self, client):
        # If the tracking doc has no graded_at, reassignment doesn't write a
        # grade — preserves "not graded yet" state.
        ch = _setup_pdf_course()
        try:
            tracking = {
                "drive_file_id": "F",
                "drive_modified_time": "T",
                "gcs_uri": "gs://b/F.pdf",
                "original_filename": "lab2.pdf",
                "extracted_authors": [],
                "student_ids": ["unknown@pending.local"],
                # no graded_at
            }
            with patch("api_server.get_pdf_submission", new_callable=AsyncMock,
                       return_value=tracking), \
                 patch("api_server.get_student_directory", new_callable=AsyncMock,
                       return_value={"alice@iisc.ac.in": "Alice"}), \
                 patch("api_server.upsert_student", new_callable=AsyncMock), \
                 patch("api_server.delete_student_pdf_mirror", new_callable=AsyncMock,
                       return_value=True), \
                 patch("api_server.upsert_pdf_submission", new_callable=AsyncMock), \
                 patch("api_server.update_pdf_submission_grade",
                       new_callable=AsyncMock) as mock_upd:
                resp = client.post(
                    "/reassign_pdf_submission",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260", "notebook_id": "lab1",
                          "drive_file_id": "F",
                          "student_ids": ["alice@iisc.ac.in"]},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            mock_upd.assert_not_awaited()  # no grade to carry
        finally:
            _teardown(ch)


class TestDebugDriveAccess:
    def test_requires_auth(self, client):
        resp = client.post(
            "/debug_drive_access",
            json={"institution_id": "iisc", "term_id": "2025-26",
                  "course_id": "cp260",
                  "drive_url": "https://drive.google.com/drive/folders/X"},
        )
        assert resp.status_code == 401

    def test_folder_access_success(self, client):
        ch = _setup_pdf_course()
        try:
            files = [
                {"id": "a", "name": "alice.pdf", "modifiedTime": "T1", "size": "100"},
                {"id": "b", "name": "bob.pdf", "modifiedTime": "T2", "size": "200"},
            ]
            with patch("api_server.list_pdfs_in_folder_sa", return_value=files):
                resp = client.post(
                    "/debug_drive_access",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260",
                          "drive_url": "https://drive.google.com/drive/folders/FOLDER_ID"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data['ok'] is True
            assert data['kind'] == "folder"
            assert data['drive_id'] == "FOLDER_ID"
            assert data['items_found'] == 2
            assert "alice.pdf" in data['sample_names']
        finally:
            _teardown(ch)

    def test_folder_access_403_returns_diagnostic(self, client):
        from googleapiclient.errors import HttpError
        ch = _setup_pdf_course()
        try:
            resp_obj = MagicMock(); resp_obj.status = 403; resp_obj.reason = 'Forbidden'
            err = HttpError(resp_obj, b'{}')
            err.error_details = [{"reason": "insufficientFilePermissions"}]
            with patch("api_server.list_pdfs_in_folder_sa", side_effect=err):
                resp = client.post(
                    "/debug_drive_access",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260",
                          "drive_url": "https://drive.google.com/drive/folders/FOLDER_ID"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data['ok'] is False
            assert data['error_status'] == 403
            assert data['error_reason'] == "insufficientFilePermissions"
            assert data['hint'] is not None
            assert data['sa_email']  # SA email surfaced for sharing
        finally:
            _teardown(ch)

    def test_file_url_routes_to_metadata_get(self, client):
        ch = _setup_pdf_course()
        try:
            with patch("api_server.list_pdfs_in_folder_sa") as mock_list, \
                 patch("drive_utils._build_drive_service") as mock_build:
                # File URL → folder_id None → file branch
                svc = MagicMock()
                meta = {"id": "FILE_ID", "name": "rubric.pdf",
                        "mimeType": "application/pdf", "modifiedTime": "T",
                        "size": "12345"}
                svc.files.return_value.get.return_value.execute.return_value = meta
                mock_build.return_value = svc

                resp = client.post(
                    "/debug_drive_access",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260",
                          "drive_url": "https://drive.google.com/file/d/FILE_ID/view"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data['kind'] == "file"
            assert data['ok'] is True
            assert data['file_metadata']['name'] == "rubric.pdf"
            mock_list.assert_not_called()
        finally:
            _teardown(ch)

    def test_unparseable_url_400(self, client):
        ch = _setup_pdf_course()
        try:
            resp = client.post(
                "/debug_drive_access",
                json={"institution_id": "iisc", "term_id": "2025-26",
                      "course_id": "cp260",
                      "drive_url": "https://example.com/not-a-drive-link"},
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
        finally:
            _teardown(ch)


class TestIngestErrorReporting:
    def test_403_from_drive_surfaces_underlying_reason(self, client):
        from googleapiclient.errors import HttpError
        ch = _setup_pdf_course()
        try:
            resp_obj = MagicMock(); resp_obj.status = 403; resp_obj.reason = 'Forbidden'
            err = HttpError(resp_obj, b'{}')
            err.error_details = [{"reason": "insufficientFilePermissions"}]
            with patch("api_server.list_pdfs_in_folder_sa", side_effect=err):
                resp = client.post(
                    "/ingest_pdf_submissions",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260", "notebook_id": "lab1",
                          "drive_folder_url": "https://drive.google.com/drive/folders/X"},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 502
            # Caller should now see the actual status, reason, and SA email.
            text = resp.text
            assert "403" in text
            assert "insufficientFilePermissions" in text
        finally:
            _teardown(ch)


class TestUploadStudentRoster:
    def _csv(self, text: str):
        return ("roster.csv", text.encode("utf-8"), "text/csv")

    def test_requires_auth(self, client):
        resp = client.post(
            "/upload_student_roster",
            data={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260"},
            files={"file": self._csv("name,email\nAlice,alice@x.com\n")},
        )
        assert resp.status_code == 401

    def test_happy_path_adds_and_updates(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            async def fake_upsert(db, course_handle, email, name, roll_no=None):
                # Simulate: alice is added, bob is updated
                return "added" if email.startswith("alice") else "updated"

            with patch("api_server.upsert_student", side_effect=fake_upsert), \
                 patch("api_server.list_placeholder_students", new_callable=AsyncMock,
                       return_value={}):
                resp = client.post(
                    "/upload_student_roster",
                    data={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260"},
                    files={"file": self._csv("name,email\nAlice,alice@x.com\nBob,bob@x.com\n")},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data["added"] == ["alice@x.com"]
            assert data["updated"] == ["bob@x.com"]
            assert data["skipped"] == []
            assert data["matching_placeholders"] == []
        finally:
            courses.pop(ch, None)

    def test_reports_csv_row_errors(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            async def fake_upsert(db, course_handle, email, name, roll_no=None):
                return "added"
            csv_text = "name,email\nAlice,not-an-email\nBob,bob@x.com\n"
            with patch("api_server.upsert_student", side_effect=fake_upsert), \
                 patch("api_server.list_placeholder_students", new_callable=AsyncMock,
                       return_value={}):
                resp = client.post(
                    "/upload_student_roster",
                    data={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260"},
                    files={"file": self._csv(csv_text)},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data["added"] == ["bob@x.com"]
            assert len(data["skipped"]) == 1
            assert "invalid email" in data["skipped"][0]["reason"]
        finally:
            courses.pop(ch, None)

    def test_detects_placeholder_matches(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            async def fake_upsert(db, course_handle, email, name, roll_no=None):
                return "added"
            placeholders = {
                "jane-doe@pending.local": {"name": "Jane Doe"},
                "carol@pending.local":    {"name": "Carol Lee"},
            }
            with patch("api_server.upsert_student", side_effect=fake_upsert), \
                 patch("api_server.list_placeholder_students", new_callable=AsyncMock,
                       return_value=placeholders):
                resp = client.post(
                    "/upload_student_roster",
                    data={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260"},
                    files={"file": self._csv("name,email\nJane Doe,jane@x.com\nDavid,david@x.com\n")},
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            # Jane matches the roster; Carol doesn't.
            ids = [m["placeholder_student_id"] for m in data["matching_placeholders"]]
            assert "jane-doe@pending.local" in ids
            assert "carol@pending.local" not in ids
            jane = next(m for m in data["matching_placeholders"] if m["placeholder_student_id"] == "jane-doe@pending.local")
            assert jane["matched_email"] == "jane@x.com"
        finally:
            courses.pop(ch, None)

    def test_empty_file_400(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            resp = client.post(
                "/upload_student_roster",
                data={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260"},
                files={"file": self._csv("")},
                headers=_instructor_header(),
            )
            assert resp.status_code == 400
        finally:
            courses.pop(ch, None)

    def test_missing_required_columns(self, client):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            with patch("api_server.list_placeholder_students", new_callable=AsyncMock,
                       return_value={}):
                resp = client.post(
                    "/upload_student_roster",
                    data={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260"},
                    files={"file": self._csv("name,roll_no\nAlice,42\n")},  # no email column
                    headers=_instructor_header(),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data["added"] == []
            # The header-level error surfaces in skipped.
            assert len(data["skipped"]) == 1
            assert "name" in data["skipped"][0]["reason"]
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
            # Legacy "pdf" value gets mapped to (report, pdf) on write.
            assert courses[ch]["lab1"]["assignment_type"] == "report"
            assert courses[ch]["lab1"]["submission_type"] == "pdf"
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

    def test_qa_pdf_returns_501_pointer_to_future_features(self, client):
        # New 2D combo: q&a rubric over PDF submission. Not implemented yet.
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {
            "instructor_gmail": "instructor@test.com",
            "lab1": {
                "assignment_type": "q&a",
                "submission_type": "pdf",
                "max_marks": 50.0,
            },
        }
        try:
            resp = client.post(
                "/grade_assignment",
                json={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                      "notebook_id": "lab1"},
                headers=_instructor_header(),
            )
            assert resp.status_code == 501
            assert "future_features" in resp.text or "not yet implemented" in resp.text
        finally:
            courses.pop(ch, None)

    def test_explicit_2d_report_pdf_dispatches_to_pdf_path(self, client):
        # New schema: explicit assignment_type+submission_type pair.
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {
            "instructor_gmail": "instructor@test.com",
            "lab1": {
                "assignment_type": "report",
                "submission_type": "pdf",
                "max_marks": 50.0,
            },
        }
        try:
            with patch("api_server.grade_pdf_assignment", new_callable=AsyncMock) as mock_pdf:
                mock_pdf.return_value = MagicMock()
                client.post(
                    "/grade_assignment",
                    json={"institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
                          "notebook_id": "lab1"},
                    headers=_instructor_header(),
                )
            mock_pdf.assert_awaited_once()
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
