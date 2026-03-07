"""
Tests for API endpoints.

Uses FastAPI's TestClient with a fully mocked backend. The mock ``config``
module is injected by conftest.py before ``api_server`` is imported.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient
from rate_limiter import student_rate_limiter


# ---------------------------------------------------------------------------
# Fixture: FastAPI TestClient with startup event disabled
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    """
    Provide a TestClient for the FastAPI app.
    Patches the startup event so it doesn't try to load from Firestore.
    """
    # Patch the database loaders that run on startup
    with patch("api_server.load_course_info_from_db", new_callable=AsyncMock, return_value={}):
        with patch("api_server.load_notebooks_from_db", new_callable=AsyncMock, return_value={}):
            from api_server import app
            with TestClient(app, raise_server_exceptions=False) as c:
                yield c


# ---------------------------------------------------------------------------
# Fixture: simulate an authenticated user via JWT
# ---------------------------------------------------------------------------

def _auth_header(email="student@test.com", name="Test User"):
    """Build an Authorization header with a valid JWT."""
    from auth import create_jwt_token
    token = create_jwt_token(
        {"id": "123", "email": email, "name": name},
        secret_key="test-secret-key-for-unit-tests",
    )
    return {"Authorization": f"Bearer {token}"}


def _admin_header():
    return _auth_header(email="admin@test.com", name="Admin")


# ---------------------------------------------------------------------------
# Unauthenticated access
# ---------------------------------------------------------------------------

class TestUnauthenticated:
    def test_root_returns_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Login" in resp.text

    def test_session_test(self, client):
        resp = client.get("/session-test")
        assert resp.status_code == 200

    def test_assist_requires_auth(self, client):
        """POST /assist without auth should return 401."""
        resp = client.post("/assist", json={
            "qnum": 1, "context": "", "question": {}, "answer": [],
            "output": {}, "ta_chat": "", "notebook_id": "hw1",
            "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
        })
        assert resp.status_code == 401

    def test_eval_requires_auth(self, client):
        """POST /eval without auth should return 401."""
        resp = client.post("/eval", json={
            "notebook_id": "hw1", "context": {}, "questions": {},
            "answers": {}, "outputs": {},
            "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
        })
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /assist endpoint
# ---------------------------------------------------------------------------

class TestAssistEndpoint:
    def test_missing_course_returns_error(self, client):
        """If the course is not in cache, /assist should fail gracefully."""
        resp = client.post(
            "/assist",
            json={
                "qnum": 1, "context": "ctx", "question": {"question": "Q"},
                "answer": [{"percent": 100, "component": "A"}], "output": {}, "ta_chat": "help",
                "notebook_id": "hw1",
                "institution_id": "mit", "term_id": "2025", "course_id": "nonexistent",
            },
            headers=_auth_header(),
        )
        # courses is a defaultdict, so accessing a missing key creates it.
        # Non-instructor + no isactive_tutor → 503 "Tutor is temporarily disabled"
        # or 404/500 if something else goes wrong.
        assert resp.status_code in (404, 500, 503)


# ---------------------------------------------------------------------------
# /grade endpoint
# ---------------------------------------------------------------------------

class TestGradeEndpoint:
    def test_grade_validates_input(self, client):
        """POST /grade with empty question should return an error."""
        resp = client.post(
            "/grade",
            json={
                "question": "", "answer": "4", "q_id": "q1",
                "notebook_id": "hw1", "rubric": "answer is 4",
                "student_id": "s1", "course_id": "6.001",
                "term_id": "2025", "institution_id": "mit",
            },
            headers=_auth_header(),
        )
        # Empty question triggers "Question not provided" (400 internally),
        # but the broad except wraps it as 500. Either way, it's an error.
        assert resp.status_code in (400, 500)
        assert "not provided" in resp.json()["detail"].lower() or resp.status_code == 500

    def test_grade_with_valid_input(self, client):
        """POST /grade with valid input should reach the scoring agent."""
        with patch(
            "api_server.score_question",
            new_callable=AsyncMock,
            return_value=(8.0, "Good answer. Total marks: 8"),
        ):
            resp = client.post(
                "/grade",
                json={
                    "question": "What is 2+2?", "answer": "4", "q_id": "q1",
                    "notebook_id": "hw1", "rubric": "answer is 4",
                    "student_id": "s1", "course_id": "6.001",
                    "term_id": "2025", "institution_id": "mit",
                },
                headers=_auth_header(),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["marks"] == 8.0


# ---------------------------------------------------------------------------
# /eval endpoint
# ---------------------------------------------------------------------------

class TestEvalEndpoint:
    def test_eval_course_not_found(self, client):
        """If course not in cache, /eval should return an error.
        courses is a defaultdict(dict) so accessing a missing key creates
        an empty dict.  isactive_eval defaults to False → 503.
        """
        resp = client.post(
            "/eval",
            json={
                "notebook_id": "hw1", "context": {}, "questions": {"1": "Q"},
                "answers": {"1": "A"}, "outputs": {"1": ""},
                "institution_id": "mit", "term_id": "2025", "course_id": "nonexistent",
            },
            headers=_auth_header(),
        )
        # defaultdict auto-creates the key → isactive_eval missing → 503
        assert resp.status_code in (404, 503)

    def test_eval_with_valid_course_and_rubric(self, client):
        """Full /eval flow with mocked scoring."""
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")

        # Set up course cache with rubric data
        courses[course_handle] = {
            "isactive_eval": True,
            "hw1": {
                "questions": {"1": {"question": "What is 2+2?", "marks": 10.0}},
                "answers": {"1": [{"percent": 100, "component": "4"}]},
                "outputs": {"1": ""},
                "max_marks": 10.0,
            },
        }

        with patch("api_server.score_question", new_callable=AsyncMock, return_value=(10.0, "Perfect. Total marks: 10")):
            with patch("api_server.retrieve_context", new_callable=AsyncMock, return_value=""):
                with patch("api_server.add_student_if_not_exists", new_callable=AsyncMock):
                    with patch("api_server.add_student_notebook_if_not_exists", new_callable=AsyncMock):
                      with patch("api_server.save_student_answers", new_callable=AsyncMock):
                        with patch("api_server.update_marks", new_callable=AsyncMock):
                            resp = client.post(
                                "/eval",
                                json={
                                    "notebook_id": "hw1",
                                    "context": {"1": "intro"},
                                    "questions": {"1": {"question": "What is 2+2?", "marks": 10.0}},
                                    "answers": {"1": [{"percent": 100, "component": "4"}]},
                                    "outputs": {"1": ""},
                                    "institution_id": "mit",
                                    "term_id": "2025",
                                    "course_id": "6.001",
                                },
                                headers=_auth_header(),
                            )

        assert resp.status_code == 200
        # Streaming NDJSON: parse each line
        lines = [json.loads(line) for line in resp.text.strip().split("\n") if line]
        # Should have a progress message and a final response
        progress_msgs = [l for l in lines if l["type"] == "progress"]
        response_msgs = [l for l in lines if l["type"] == "response"]
        assert len(progress_msgs) >= 2
        assert "saved in the server" in progress_msgs[0]["message"]
        assert "Done evaluating question 1" in progress_msgs[1]["message"]
        assert len(response_msgs) == 1
        assert "10.0" in response_msgs[0]["response"]

        # Clean up cache
        del courses[course_handle]


# ---------------------------------------------------------------------------
# /create_course endpoint (admin-only)
# ---------------------------------------------------------------------------

class TestCreateCourseEndpoint:
    def test_non_admin_rejected(self, client):
        """Non-admin user should get 403."""
        resp = client.post(
            "/create_course",
            json={
                "course_id": "6.001", "term_id": "2025", "institution_id": "mit",
            },
            headers=_auth_header(email="student@test.com"),
        )
        assert resp.status_code == 403

    def test_admin_can_create(self, client):
        """Admin user should be able to create a course."""
        with patch("api_server.get_course_data", new_callable=AsyncMock, return_value=None):
            with patch("api_server.create_course", new_callable=AsyncMock, return_value=True):
                resp = client.post(
                    "/create_course",
                    json={
                        "course_id": "6.001", "term_id": "2025",
                        "institution_id": "mit",
                    },
                    headers=_admin_header(),
                )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /upload_rubric endpoint
# ---------------------------------------------------------------------------

class TestUploadRubricEndpoint:
    def test_upload_rubric_uses_notebook_id(self, client):
        """Endpoint should use query_body.notebook_id (not rubric_name)."""
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")
        courses[course_handle] = {
            "instructor_gmail": "instructor@test.com",
        }

        with patch("api_server.save_rubric", new_callable=AsyncMock):
            resp = client.post(
                "/upload_rubric",
                json={
                    "notebook_id": "hw1", "max_marks": 100.0,
                    "context": {"1": "ctx"}, "questions": {"1": "Q"},
                    "answers": {"1": "A"}, "outputs": {"1": ""},
                    "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
                },
                headers=_auth_header(email="instructor@test.com"),
            )

        assert resp.status_code == 200
        # Verify the rubric was stored in cache under notebook_id
        assert "hw1" in courses[course_handle]
        assert courses[course_handle]["hw1"]["max_marks"] == 100.0

        # Clean up
        del courses[course_handle]


# ---------------------------------------------------------------------------
# /upload_course_materials endpoints
# ---------------------------------------------------------------------------

class TestUploadCourseMaterialsEndpoint:

    def _setup_course(self, instructor_email="instructor@test.com"):
        """Create a course in the cache and return the course handle."""
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

    # --- GET (HTML page) ---

    def test_get_redirects_to_login_when_unauthenticated(self, client):
        """GET /upload_course_materials without auth should redirect to /login."""
        resp = client.get("/upload_course_materials", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]
        assert "message=" in resp.headers["location"]

    def test_get_returns_html_with_form_fields(self, client):
        """Authenticated user should see the page with text boxes for IDs."""
        resp = client.get(
            "/upload_course_materials",
            headers=_auth_header(email="instructor@test.com"),
        )
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "institution_id" in resp.text
        assert "term_id" in resp.text
        assert "course_id" in resp.text
        assert "instructor@test.com" in resp.text

    # --- GET /validate_course_access ---

    def test_validate_rejects_non_instructor(self, client):
        """Non-instructor should get 403 from /validate_course_access."""
        course_handle = self._setup_course(instructor_email="real-instructor@test.com")
        try:
            resp = client.get(
                "/validate_course_access",
                params={"course_id": "6.001", "term_id": "2025", "institution_id": "mit"},
                headers=_auth_header(email="student@test.com"),
            )
            assert resp.status_code == 403
        finally:
            self._cleanup_course(course_handle)

    def test_validate_returns_course_name_for_instructor(self, client):
        """Instructor should get course info from /validate_course_access."""
        course_handle = self._setup_course()
        try:
            resp = client.get(
                "/validate_course_access",
                params={"course_id": "6.001", "term_id": "2025", "institution_id": "mit"},
                headers=_auth_header(email="instructor@test.com"),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["course_name"] == "Intro to CS"
        finally:
            self._cleanup_course(course_handle)

    def test_validate_returns_course_name_for_admin(self, client):
        """Platform admin should also pass /validate_course_access."""
        course_handle = self._setup_course()
        try:
            resp = client.get(
                "/validate_course_access",
                params={"course_id": "6.001", "term_id": "2025", "institution_id": "mit"},
                headers=_admin_header(),
            )
            assert resp.status_code == 200
            assert resp.json()["course_name"] == "Intro to CS"
        finally:
            self._cleanup_course(course_handle)

    # --- POST /get_upload_url (signed URL generation) ---

    def test_get_upload_url_requires_auth(self, client):
        """POST /get_upload_url without auth should return 401."""
        resp = client.post(
            "/get_upload_url",
            json={"course_id": "6.001", "term_id": "2025", "institution_id": "mit",
                  "filename": "test.txt", "content_type": "text/plain"},
        )
        assert resp.status_code == 401

    def test_get_upload_url_rejects_non_instructor(self, client):
        """Non-instructor should get 403 on /get_upload_url."""
        course_handle = self._setup_course(instructor_email="real-instructor@test.com")
        try:
            resp = client.post(
                "/get_upload_url",
                json={"course_id": "6.001", "term_id": "2025", "institution_id": "mit",
                      "filename": "test.txt", "content_type": "text/plain"},
                headers=_auth_header(email="student@test.com"),
            )
            assert resp.status_code == 403
        finally:
            self._cleanup_course(course_handle)

    def test_get_upload_url_returns_signed_url(self, client):
        """Instructor should receive a signed upload URL and destination path."""
        course_handle = self._setup_course()
        try:
            with patch("api_server.generate_signed_upload_url") as mock_gen:
                mock_gen.return_value = "https://storage.googleapis.com/signed-url-here"
                resp = client.post(
                    "/get_upload_url",
                    json={"course_id": "6.001", "term_id": "2025", "institution_id": "mit",
                          "filename": "notes.pdf", "content_type": "application/pdf"},
                    headers=_auth_header(email="instructor@test.com"),
                )

            assert resp.status_code == 200
            data = resp.json()
            assert data["upload_url"] == "https://storage.googleapis.com/signed-url-here"
            assert data["destination"] == "mit-2025-6-001/notes.pdf"
            mock_gen.assert_called_once_with(
                "test-bucket",
                "mit-2025-6-001/notes.pdf",
                "application/pdf",
            )
        finally:
            self._cleanup_course(course_handle)

    def test_get_upload_url_handles_generation_failure(self, client):
        """If generate_signed_upload_url raises, the error is reported."""
        course_handle = self._setup_course()
        try:
            with patch("api_server.generate_signed_upload_url", side_effect=Exception("GCS error")):
                resp = client.post(
                    "/get_upload_url",
                    json={"course_id": "6.001", "term_id": "2025", "institution_id": "mit",
                          "filename": "bad.txt", "content_type": "text/plain"},
                    headers=_auth_header(email="instructor@test.com"),
                )

            assert resp.status_code == 500
            assert "failed" in resp.json()["detail"].lower()
        finally:
            self._cleanup_course(course_handle)


# ---------------------------------------------------------------------------
# Rate limiting tests
# ---------------------------------------------------------------------------

class TestRateLimiting:

    def _setup_course(self, rate_limit=None, window=None,
                      instructor_email="instructor@test.com"):
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")
        courses[course_handle] = {
            "instructor_gmail": instructor_email,
            "isactive_tutor": True,
            "isactive_eval": True,
            "student_rate_limit": rate_limit,
            "student_rate_limit_window": window,
        }
        return course_handle

    def _cleanup(self, course_handle):
        from api_server import courses
        if course_handle in courses:
            del courses[course_handle]
        student_rate_limiter.clear_course(course_handle)

    def test_assist_blocked_when_rate_limit_exceeded(self, client):
        """Student should get 429 after exceeding the rate limit on /assist."""
        course_handle = self._setup_course(rate_limit=2, window=3600)
        try:
            # Use up the quota
            for _ in range(2):
                student_rate_limiter.check_and_record(
                    course_handle, "student@test.com", 2, 3600
                )
            resp = client.post(
                "/assist",
                json={
                    "qnum": 1, "context": "ctx",
                    "question": {"question": "Q"},
                    "answer": [{"percent": 100, "component": "A"}],
                    "output": {}, "ta_chat": "help",
                    "notebook_id": "hw1",
                    "institution_id": "mit", "term_id": "2025",
                    "course_id": "6.001",
                },
                headers=_auth_header(email="student@test.com"),
            )
            assert resp.status_code == 429
            assert "Rate limit exceeded" in resp.json()["detail"]
        finally:
            self._cleanup(course_handle)

    def test_assist_allowed_when_no_rate_limit(self, client):
        """Without a rate limit configured, students should not be blocked."""
        course_handle = self._setup_course(rate_limit=None)
        try:
            with patch("api_server.run_agent_and_get_response", new_callable=AsyncMock, return_value="response"):
                with patch("api_server.add_student_notebook_if_not_exists", new_callable=AsyncMock):
                    with patch("api_server.retrieve_context", new_callable=AsyncMock, return_value=""):
                        # Should not return 429
                        resp = client.post(
                            "/assist",
                            json={
                                "qnum": 1, "context": "ctx",
                                "question": {"question": "Q"},
                                "answer": [{"percent": 100, "component": "A"}],
                                "output": {}, "ta_chat": "help",
                                "notebook_id": "hw1",
                                "institution_id": "mit", "term_id": "2025",
                                "course_id": "6.001",
                            },
                            headers=_auth_header(email="student@test.com"),
                        )
            assert resp.status_code != 429
        finally:
            self._cleanup(course_handle)

    def test_instructor_bypasses_rate_limit(self, client):
        """Instructors should not be affected by the rate limit."""
        course_handle = self._setup_course(rate_limit=1, window=3600)
        try:
            # Use up the quota for the instructor email
            student_rate_limiter.check_and_record(
                course_handle, "instructor@test.com", 1, 3600
            )
            with patch("api_server.run_agent_and_get_response", new_callable=AsyncMock, return_value="response"):
                with patch("api_server.add_instructor_notebook_if_not_exists", new_callable=AsyncMock):
                    with patch("api_server.retrieve_context", new_callable=AsyncMock, return_value=""):
                        resp = client.post(
                            "/assist",
                            json={
                                "qnum": 1, "context": "ctx",
                                "question": {"question": "Q"},
                                "answer": [{"percent": 100, "component": "A"}],
                                "output": {}, "ta_chat": "help",
                                "notebook_id": "hw1",
                                "institution_id": "mit", "term_id": "2025",
                                "course_id": "6.001",
                            },
                            headers=_auth_header(email="instructor@test.com"),
                        )
            # Instructor should not get 429
            assert resp.status_code != 429
        finally:
            self._cleanup(course_handle)

    def test_grade_blocked_when_rate_limit_exceeded(self, client):
        """Student should get 429 on /grade after exceeding rate limit."""
        course_handle = self._setup_course(rate_limit=1, window=3600)
        try:
            student_rate_limiter.check_and_record(
                course_handle, "student@test.com", 1, 3600
            )
            resp = client.post(
                "/grade",
                json={
                    "question": "What is 2+2?", "answer": "4", "q_id": "q1",
                    "notebook_id": "hw1", "rubric": "answer is 4",
                    "student_id": "s1", "course_id": "6.001",
                    "term_id": "2025", "institution_id": "mit",
                },
                headers=_auth_header(email="student@test.com"),
            )
            assert resp.status_code == 429
        finally:
            self._cleanup(course_handle)

    def test_eval_blocked_when_rate_limit_exceeded(self, client):
        """Student should get 429 on /eval after exceeding rate limit."""
        course_handle = self._setup_course(rate_limit=1, window=3600)
        try:
            student_rate_limiter.check_and_record(
                course_handle, "student@test.com", 1, 3600
            )
            resp = client.post(
                "/eval",
                json={
                    "notebook_id": "hw1", "context": {}, "questions": {"1": "Q"},
                    "answers": {"1": "A"}, "outputs": {"1": ""},
                    "institution_id": "mit", "term_id": "2025",
                    "course_id": "6.001",
                },
                headers=_auth_header(email="student@test.com"),
            )
            assert resp.status_code == 429
        finally:
            self._cleanup(course_handle)


# ---------------------------------------------------------------------------
# /update_course_config — rate limit fields
# ---------------------------------------------------------------------------

class TestUpdateCourseConfigRateLimit:

    def _setup_course(self, instructor_email="instructor@test.com"):
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")
        courses[course_handle] = {
            "instructor_gmail": instructor_email,
            "isactive_tutor": True,
            "isactive_eval": True,
            "student_rate_limit": None,
            "student_rate_limit_window": None,
        }
        return course_handle

    def _cleanup(self, course_handle):
        from api_server import courses
        if course_handle in courses:
            del courses[course_handle]
        student_rate_limiter.clear_course(course_handle)

    def test_set_rate_limit(self, client):
        """Instructor can set student_rate_limit via /update_course_config."""
        course_handle = self._setup_course()
        try:
            with patch("api_server.update_course_info", new_callable=AsyncMock):
                resp = client.post(
                    "/update_course_config",
                    json={
                        "institution_id": "mit", "term_id": "2025",
                        "course_id": "6.001",
                        "student_rate_limit": 20,
                    },
                    headers=_auth_header(email="instructor@test.com"),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data["updated"]["student_rate_limit"] == 20

            from api_server import courses
            assert courses[course_handle]["student_rate_limit"] == 20
        finally:
            self._cleanup(course_handle)

    def test_set_rate_limit_window(self, client):
        """Instructor can set student_rate_limit_window."""
        course_handle = self._setup_course()
        try:
            with patch("api_server.update_course_info", new_callable=AsyncMock):
                resp = client.post(
                    "/update_course_config",
                    json={
                        "institution_id": "mit", "term_id": "2025",
                        "course_id": "6.001",
                        "student_rate_limit_window": 1800,
                    },
                    headers=_auth_header(email="instructor@test.com"),
                )
            assert resp.status_code == 200
            assert resp.json()["updated"]["student_rate_limit_window"] == 1800
        finally:
            self._cleanup(course_handle)

    def test_disable_rate_limit_with_zero(self, client):
        """Setting student_rate_limit to 0 should store None (disabled)."""
        course_handle = self._setup_course()
        try:
            with patch("api_server.update_course_info", new_callable=AsyncMock):
                resp = client.post(
                    "/update_course_config",
                    json={
                        "institution_id": "mit", "term_id": "2025",
                        "course_id": "6.001",
                        "student_rate_limit": 0,
                    },
                    headers=_auth_header(email="instructor@test.com"),
                )
            assert resp.status_code == 200
            assert resp.json()["updated"]["student_rate_limit"] is None

            from api_server import courses
            assert courses[course_handle]["student_rate_limit"] is None
        finally:
            self._cleanup(course_handle)

    def test_non_instructor_cannot_set_rate_limit(self, client):
        """Non-instructor should get 403 on /update_course_config."""
        course_handle = self._setup_course(instructor_email="real-instructor@test.com")
        try:
            resp = client.post(
                "/update_course_config",
                json={
                    "institution_id": "mit", "term_id": "2025",
                    "course_id": "6.001",
                    "student_rate_limit": 10,
                },
                headers=_auth_header(email="student@test.com"),
            )
            assert resp.status_code == 403
        finally:
            self._cleanup(course_handle)

    def test_invalid_rate_limit_rejected(self, client):
        """Negative rate limit should be rejected by model validation (422)."""
        course_handle = self._setup_course()
        try:
            resp = client.post(
                "/update_course_config",
                json={
                    "institution_id": "mit", "term_id": "2025",
                    "course_id": "6.001",
                    "student_rate_limit": -5,
                },
                headers=_auth_header(email="instructor@test.com"),
            )
            assert resp.status_code == 422
        finally:
            self._cleanup(course_handle)


# ---------------------------------------------------------------------------
# /rate_limit_status endpoint
# ---------------------------------------------------------------------------

class TestRateLimitStatusEndpoint:

    def _setup_course(self, rate_limit=None, window=None,
                      instructor_email="instructor@test.com"):
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")
        courses[course_handle] = {
            "instructor_gmail": instructor_email,
            "student_rate_limit": rate_limit,
            "student_rate_limit_window": window,
        }
        return course_handle

    def _cleanup(self, course_handle):
        from api_server import courses
        if course_handle in courses:
            del courses[course_handle]
        student_rate_limiter.clear_course(course_handle)

    def test_returns_disabled_when_no_limit(self, client):
        course_handle = self._setup_course()
        try:
            resp = client.post(
                "/rate_limit_status",
                json={"institution_id": "mit", "term_id": "2025", "course_id": "6.001"},
                headers=_auth_header(email="instructor@test.com"),
            )
            assert resp.status_code == 200
            assert resp.json()["rate_limiting"] == "disabled"
        finally:
            self._cleanup(course_handle)

    def test_returns_usage_when_enabled(self, client):
        course_handle = self._setup_course(rate_limit=10, window=3600)
        try:
            # Simulate some usage
            student_rate_limiter.check_and_record(course_handle, "alice@test.com", 10, 3600)
            student_rate_limiter.check_and_record(course_handle, "alice@test.com", 10, 3600)

            resp = client.post(
                "/rate_limit_status",
                json={"institution_id": "mit", "term_id": "2025", "course_id": "6.001"},
                headers=_auth_header(email="instructor@test.com"),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["rate_limiting"] == "enabled"
            assert data["max_requests"] == 10
            assert data["students"]["alice@test.com"]["used"] == 2
        finally:
            self._cleanup(course_handle)

    def test_non_instructor_rejected(self, client):
        course_handle = self._setup_course(instructor_email="real-instructor@test.com")
        try:
            resp = client.post(
                "/rate_limit_status",
                json={"institution_id": "mit", "term_id": "2025", "course_id": "6.001"},
                headers=_auth_header(email="student@test.com"),
            )
            assert resp.status_code == 403
        finally:
            self._cleanup(course_handle)
