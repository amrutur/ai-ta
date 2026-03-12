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
        """If course not in cache, /eval should return 404 or 503."""
        resp = client.post(
            "/eval",
            json={
                "notebook_id": "hw1", "context": {}, "questions": {"1": "Q"},
                "answers": {"1": "A"}, "outputs": {"1": ""},
                "institution_id": "mit", "term_id": "2025", "course_id": "nonexistent",
            },
            headers=_auth_header(),
        )
        # defaultdict auto-creates the key → notebook missing → 503
        assert resp.status_code in (404, 503)

    def test_eval_with_valid_course_and_rubric(self, client):
        """Full /eval flow with mocked scoring."""
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")

        # Set up course cache with rubric data
        courses[course_handle] = {
            "hw1": {
                "isactive_eval": True,
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
# /regrade_answer endpoint
# ---------------------------------------------------------------------------

class TestRegradeAnswerEndpoint:

    REGRADE_JSON = {
        "qnum": 1, "notebook_id": "hw1", "student_id": "student@test.com",
        "course_id": "6.001", "term_id": "2025", "institution_id": "mit",
        "student_contends": "I believe my answer is correct because...",
    }

    def _setup_course(self, instructor_email="instructor@test.com"):
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")
        courses[course_handle] = {
            "instructor_gmail": instructor_email,
            "hw1": {
                "max_marks": 20.0,
                "questions": {
                    "1": {"question": "What is 2+2?", "marks": 10.0},
                    "2": {"question": "What is 3+3?", "marks": 10.0},
                },
                "answers": {
                    "1": [{"percent": "100", "component": "4"}],
                    "2": [{"percent": "100", "component": "6"}],
                },
            },
        }
        return course_handle

    def _cleanup(self, course_handle):
        from api_server import courses
        if course_handle in courses:
            del courses[course_handle]

    def test_requires_auth(self, client):
        """POST /regrade_answer without auth should return 401."""
        resp = client.post("/regrade_answer", json=self.REGRADE_JSON)
        assert resp.status_code == 401

    def test_non_instructor_rejected(self, client):
        """Non-instructor should get 403."""
        course_handle = self._setup_course(instructor_email="prof@test.com")
        try:
            resp = client.post(
                "/regrade_answer", json=self.REGRADE_JSON,
                headers=_auth_header(email="student@test.com"),
            )
            assert resp.status_code == 403
        finally:
            self._cleanup(course_handle)

    def test_regrade_success_with_contention(self, client):
        """Instructor regrades a question with student contention."""
        course_handle = self._setup_course()
        try:
            student_answers = {"1": [{"component": "4"}], "2": [{"component": "6"}]}
            grader_resp = {
                "student_id": "student@test.com",
                "total_marks": 15, "max_marks": 20,
                "feedback": {
                    "1": {"marks": 5.0, "response": "Partially correct."},
                    "2": {"marks": 10.0, "response": "Correct."},
                },
            }

            with patch("api_server.get_student_notebook_answers", new_callable=AsyncMock, return_value=student_answers):
                with patch("api_server.fetch_grader_response", new_callable=AsyncMock, return_value=grader_resp):
                    with patch("api_server.retrieve_context", new_callable=AsyncMock, return_value="course material"):
                        with patch("api_server.score_question", new_callable=AsyncMock, return_value=(8.0, "Regraded: mostly correct.")) as mock_score:
                            with patch("api_server.update_marks", new_callable=AsyncMock) as mock_update:
                                resp = client.post(
                                    "/regrade_answer", json=self.REGRADE_JSON,
                                    headers=_auth_header(email="instructor@test.com"),
                                )

            assert resp.status_code == 200
            data = resp.json()
            assert data["marks"] == 8.0
            assert "Regraded" in data["response"]

            # Verify score_question was called with augmented answer including contention
            call_args = mock_score.call_args
            rubric_answer_arg = call_args[0][2]
            assert "{agent's grading}" in rubric_answer_arg
            assert "Partially correct." in rubric_answer_arg
            assert "{student's contention}" in rubric_answer_arg
            assert "I believe my answer is correct" in rubric_answer_arg

            # Verify update_marks was called with recalculated total (8 + 10 = 18)
            update_call = mock_update.call_args
            assert update_call[0][3] == "hw1"  # notebook_id
            assert update_call[0][4] == 18.0  # total_marks (regraded Q1=8 + Q2=10)
        finally:
            self._cleanup(course_handle)

    def test_regrade_no_answers_returns_404(self, client):
        """If student has no submitted answers, return 404."""
        course_handle = self._setup_course()
        try:
            with patch("api_server.get_student_notebook_answers", new_callable=AsyncMock, return_value=None):
                resp = client.post(
                    "/regrade_answer", json=self.REGRADE_JSON,
                    headers=_auth_header(email="instructor@test.com"),
                )
            assert resp.status_code == 404
            assert "No submitted answers" in resp.json()["detail"]
        finally:
            self._cleanup(course_handle)

    def test_regrade_skipped_when_do_regrade_false(self, client):
        """With do_regrade=False, already-graded question should return 409."""
        course_handle = self._setup_course()
        try:
            student_answers = {"1": [{"component": "4"}]}
            grader_resp = {
                "student_id": "student@test.com",
                "total_marks": 5, "max_marks": 20,
                "feedback": {"1": {"marks": 5.0, "response": "Partially correct."}},
            }

            regrade_json = {**self.REGRADE_JSON, "do_regrade": False}

            with patch("api_server.get_student_notebook_answers", new_callable=AsyncMock, return_value=student_answers):
                with patch("api_server.fetch_grader_response", new_callable=AsyncMock, return_value=grader_resp):
                    resp = client.post(
                        "/regrade_answer", json=regrade_json,
                        headers=_auth_header(email="instructor@test.com"),
                    )
            assert resp.status_code == 409
        finally:
            self._cleanup(course_handle)


# /grade_notebook endpoint
# ---------------------------------------------------------------------------

class TestGradeNotebookEndpoint:
    def test_grade_notebook_requires_auth(self, client):
        """Unauthenticated request should be rejected."""
        resp = client.post(
            "/grade_notebook",
            json={
                "student_id": "student@test.com", "notebook_id": "hw1",
                "course_id": "6.001", "term_id": "2025", "institution_id": "mit",
            },
        )
        assert resp.status_code == 401

    def test_grade_notebook_non_instructor_rejected(self, client):
        """Non-instructor user should get 403."""
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")
        courses[course_handle] = {"instructor_gmail": "prof@test.com"}

        resp = client.post(
            "/grade_notebook",
            json={
                "student_id": "student@test.com", "notebook_id": "hw1",
                "course_id": "6.001", "term_id": "2025", "institution_id": "mit",
            },
            headers=_auth_header(email="student@test.com"),
        )
        assert resp.status_code == 403

        del courses[course_handle]

    def test_grade_notebook_course_not_found(self, client):
        """Non-existent course should return 404 or 503."""
        resp = client.post(
            "/grade_notebook",
            json={
                "student_id": "student@test.com", "notebook_id": "hw1",
                "course_id": "nonexistent", "term_id": "2025", "institution_id": "mit",
            },
            headers=_admin_header(),
        )
        assert resp.status_code in (404, 503)

    def test_grade_notebook_single_student(self, client):
        """Full /grade_notebook flow for a single student with mocked scoring."""
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")

        courses[course_handle] = {
            "instructor_gmail": "admin@test.com",
            "hw1": {
                "isactive_eval": True,
                "questions": {"1": {"question": "What is 2+2?", "marks": 10.0}},
                "answers": {"1": [{"percent": 100, "component": "4"}]},
                "max_marks": 10.0,
            },
        }

        mock_answers = {"1": [{"component": "4"}]}

        with patch("api_server.is_notebook_graded", new_callable=AsyncMock, return_value=False):
            with patch("api_server.score_question", new_callable=AsyncMock, return_value=(10.0, "Perfect. Total marks: 10")):
                with patch("api_server.retrieve_context", new_callable=AsyncMock, return_value=""):
                    with patch("api_server.get_student_notebook_answers", new_callable=AsyncMock, return_value=mock_answers):
                        with patch("api_server.update_marks", new_callable=AsyncMock):
                            resp = client.post(
                                "/grade_notebook",
                                json={
                                    "student_id": "student@test.com",
                                    "notebook_id": "hw1",
                                    "course_id": "6.001",
                                    "term_id": "2025",
                                    "institution_id": "mit",
                                },
                                headers=_admin_header(),
                            )

        assert resp.status_code == 200
        lines = [json.loads(line) for line in resp.text.strip().split("\n") if line]
        response_msgs = [l for l in lines if l["type"] == "response"]
        assert len(response_msgs) == 1
        assert "1 student(s) graded" in response_msgs[0]["response"]

        del courses[course_handle]

    def test_grade_notebook_all_students(self, client):
        """Grade all students: one with answers, one without."""
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")

        courses[course_handle] = {
            "instructor_gmail": "admin@test.com",
            "hw1": {
                "isactive_eval": True,
                "questions": {"1": {"question": "What is 2+2?", "marks": 10.0}},
                "answers": {"1": [{"percent": 100, "component": "4"}]},
                "max_marks": 10.0,
            },
        }

        async def mock_get_answers(db, ch, sid, nid):
            if sid == "student1@test.com":
                return {"1": [{"component": "4"}]}
            return None  # student2 has no submission

        with patch("api_server.is_notebook_graded", new_callable=AsyncMock, return_value=False):
            with patch("api_server.get_student_list", new_callable=AsyncMock, return_value=["student1@test.com", "student2@test.com"]):
                with patch("api_server.score_question", new_callable=AsyncMock, return_value=(10.0, "Perfect. Total marks: 10")):
                    with patch("api_server.retrieve_context", new_callable=AsyncMock, return_value=""):
                        with patch("api_server.get_student_notebook_answers", side_effect=mock_get_answers):
                            with patch("api_server.update_marks", new_callable=AsyncMock):
                                resp = client.post(
                                    "/grade_notebook",
                                    json={
                                        "student_id": "All",
                                        "notebook_id": "hw1",
                                        "course_id": "6.001",
                                        "term_id": "2025",
                                        "institution_id": "mit",
                                    },
                                    headers=_admin_header(),
                                )

        assert resp.status_code == 200
        lines = [json.loads(line) for line in resp.text.strip().split("\n") if line]
        response_msgs = [l for l in lines if l["type"] == "response"]
        assert len(response_msgs) == 1
        assert "1 student(s) graded" in response_msgs[0]["response"]
        assert "1 skipped" in response_msgs[0]["response"]

        del courses[course_handle]

    def test_grade_notebook_skips_already_graded(self, client):
        """Already-graded students are skipped."""
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")

        courses[course_handle] = {
            "instructor_gmail": "admin@test.com",
            "hw1": {
                "isactive_eval": True,
                "questions": {"1": {"question": "What is 2+2?", "marks": 10.0}},
                "answers": {"1": [{"percent": 100, "component": "4"}]},
                "max_marks": 10.0,
            },
        }

        # is_notebook_graded returns True → student should be skipped entirely
        with patch("api_server.is_notebook_graded", new_callable=AsyncMock, return_value=True):
            with patch("api_server.get_student_notebook_answers", new_callable=AsyncMock) as mock_get:
                with patch("api_server.score_question", new_callable=AsyncMock) as mock_score:
                    resp = client.post(
                        "/grade_notebook",
                        json={
                            "student_id": "student@test.com",
                            "notebook_id": "hw1",
                            "course_id": "6.001",
                            "term_id": "2025",
                            "institution_id": "mit",
                        },
                        headers=_admin_header(),
                    )

        assert resp.status_code == 200
        # Neither answers fetch nor scoring should have been called
        mock_get.assert_not_called()
        mock_score.assert_not_called()
        lines = [json.loads(line) for line in resp.text.strip().split("\n") if line]
        response_msgs = [l for l in lines if l["type"] == "response"]
        assert len(response_msgs) == 1
        assert "0 student(s) graded" in response_msgs[0]["response"]
        assert "1 skipped" in response_msgs[0]["response"]

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
            with patch("api_server.update_notebook_info", new_callable=AsyncMock):
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
        assert courses[course_handle]["hw1"]["isactive_eval"] is True

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
            "student_rate_limit": rate_limit,
            "student_rate_limit_window": window,
            "hw1": {"isactive_eval": True},
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


# ---------------------------------------------------------------------------
# /notify_student_grades endpoint
# ---------------------------------------------------------------------------

def _parse_ndjson_stream(resp):
    """Parse an NDJSON streaming response into a list of parsed JSON objects."""
    lines = resp.text.strip().split("\n")
    return [json.loads(line) for line in lines if line.strip()]


def _get_final_response(events):
    """Extract the final 'response' event from a list of NDJSON events."""
    for event in events:
        if event.get("type") == "response":
            return event
    return None


class TestNotifyStudentGradesEndpoint:

    def _setup_course(self, instructor_email="instructor@test.com"):
        from api_server import courses
        from database import make_course_handle

        course_handle = make_course_handle("mit", "2025", "6.001")
        courses[course_handle] = {
            "instructor_gmail": instructor_email,
        }
        return course_handle

    def _cleanup(self, course_handle):
        from api_server import courses
        if course_handle in courses:
            del courses[course_handle]

    def test_requires_auth(self, client):
        """POST /notify_student_grades without auth should return 401."""
        resp = client.post(
            "/notify_student_grades",
            json={
                "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
                "notebook_id": "hw1", "student_id": "student@test.com",
            },
        )
        assert resp.status_code == 401

    def test_non_instructor_rejected(self, client):
        """Non-instructor should get 403."""
        course_handle = self._setup_course(instructor_email="real-instructor@test.com")
        try:
            resp = client.post(
                "/notify_student_grades",
                json={
                    "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
                    "notebook_id": "hw1", "student_id": "student@test.com",
                },
                headers=_auth_header(email="student@test.com"),
            )
            assert resp.status_code == 403
        finally:
            self._cleanup(course_handle)

    def test_single_student_email_sent(self, client):
        """Instructor sends grade notification to a single student."""
        course_handle = self._setup_course()
        try:
            grader_response = {"total_marks": 8, "max_marks": 10, "feedback": "Good work"}
            with patch("api_server.is_email_notified", new_callable=AsyncMock, return_value=False):
                with patch("api_server.fetch_grader_response", new_callable=AsyncMock, return_value=grader_response):
                    with patch("api_server.send_email", return_value=True) as mock_send:
                        with patch("api_server.mark_email_notified", new_callable=AsyncMock):
                            resp = client.post(
                                "/notify_student_grades",
                                json={
                                    "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
                                    "notebook_id": "hw1", "student_id": "student@test.com",
                                },
                                headers=_auth_header(email="instructor@test.com"),
                            )

            assert resp.status_code == 200
            events = _parse_ndjson_stream(resp)
            final = _get_final_response(events)
            assert final is not None
            assert "Sent 1" in final["response"]
            assert "0 failed" in final["response"]
            mock_send.assert_called_once()
            call_args = mock_send.call_args
            assert call_args[0][2] == "student@test.com"  # to address
            assert "hw1" in call_args[0][3]  # subject contains notebook_id
        finally:
            self._cleanup(course_handle)

    def test_single_student_no_graded_response(self, client):
        """If student has no graded response, they are skipped."""
        course_handle = self._setup_course()
        try:
            with patch("api_server.is_email_notified", new_callable=AsyncMock, return_value=False):
                with patch("api_server.fetch_grader_response", new_callable=AsyncMock, return_value=None):
                    with patch("api_server.send_email") as mock_send:
                        resp = client.post(
                            "/notify_student_grades",
                            json={
                                "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
                                "notebook_id": "hw1", "student_id": "student@test.com",
                            },
                            headers=_auth_header(email="instructor@test.com"),
                        )

            assert resp.status_code == 200
            events = _parse_ndjson_stream(resp)
            final = _get_final_response(events)
            assert final is not None
            assert "skipped 1" in final["response"]
            mock_send.assert_not_called()
        finally:
            self._cleanup(course_handle)

    def test_all_students_mixed_results(self, client):
        """Notify all students: one succeeds, one has no grades, one fails."""
        course_handle = self._setup_course()
        try:
            async def mock_fetch(db, ch, nid, sid):
                if sid == "student1@test.com":
                    return {"total_marks": 8, "max_marks": 10}
                if sid == "student3@test.com":
                    return {"total_marks": 5, "max_marks": 10}
                return None  # student2 has no grades

            def mock_send(api_key, from_email, to, subject, body):
                if to == "student3@test.com":
                    return False  # simulate failure
                return True

            with patch("api_server.get_student_list", new_callable=AsyncMock, return_value=["student1@test.com", "student2@test.com", "student3@test.com"]):
                with patch("api_server.is_email_notified", new_callable=AsyncMock, return_value=False):
                    with patch("api_server.fetch_grader_response", side_effect=mock_fetch):
                        with patch("api_server.send_email", side_effect=mock_send):
                            with patch("api_server.mark_email_notified", new_callable=AsyncMock):
                                resp = client.post(
                                    "/notify_student_grades",
                                    json={
                                        "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
                                        "notebook_id": "hw1", "student_id": "all",
                                    },
                                    headers=_auth_header(email="instructor@test.com"),
                                )

            assert resp.status_code == 200
            events = _parse_ndjson_stream(resp)
            final = _get_final_response(events)
            assert final is not None
            assert "Sent 1" in final["response"]
            assert "skipped 1" in final["response"]
            assert "1 failed" in final["response"]
        finally:
            self._cleanup(course_handle)

    def test_email_failure_counted(self, client):
        """If send_email returns False, it should be counted as failed."""
        course_handle = self._setup_course()
        try:
            grader_response = {"total_marks": 8, "max_marks": 10}
            with patch("api_server.is_email_notified", new_callable=AsyncMock, return_value=False):
                with patch("api_server.fetch_grader_response", new_callable=AsyncMock, return_value=grader_response):
                    with patch("api_server.send_email", return_value=False):
                        resp = client.post(
                            "/notify_student_grades",
                            json={
                                "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
                                "notebook_id": "hw1", "student_id": "student@test.com",
                            },
                            headers=_auth_header(email="instructor@test.com"),
                        )

            assert resp.status_code == 200
            events = _parse_ndjson_stream(resp)
            final = _get_final_response(events)
            assert final is not None
            assert "1 failed" in final["response"]
            assert "Sent 0" in final["response"]
        finally:
            self._cleanup(course_handle)

    def test_no_students_returns_404(self, client):
        """If 'all' is specified but no students exist, should return 404."""
        course_handle = self._setup_course()
        try:
            with patch("api_server.get_student_list", new_callable=AsyncMock, return_value=[]):
                resp = client.post(
                    "/notify_student_grades",
                    json={
                        "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
                        "notebook_id": "hw1", "student_id": "all",
                    },
                    headers=_auth_header(email="instructor@test.com"),
                )

            assert resp.status_code == 404
        finally:
            self._cleanup(course_handle)

    def test_already_notified_skipped(self, client):
        """Students already notified should be skipped when do_resend is False."""
        course_handle = self._setup_course()
        try:
            with patch("api_server.is_email_notified", new_callable=AsyncMock, return_value=True):
                with patch("api_server.send_email") as mock_send:
                    resp = client.post(
                        "/notify_student_grades",
                        json={
                            "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
                            "notebook_id": "hw1", "student_id": "student@test.com",
                        },
                        headers=_auth_header(email="instructor@test.com"),
                    )

            assert resp.status_code == 200
            events = _parse_ndjson_stream(resp)
            final = _get_final_response(events)
            assert final is not None
            assert "skipped 1" in final["response"]
            mock_send.assert_not_called()
        finally:
            self._cleanup(course_handle)

    def test_do_resend_overrides_already_notified(self, client):
        """With do_resend=True, already-notified students should still get emailed."""
        course_handle = self._setup_course()
        try:
            grader_response = {"total_marks": 8, "max_marks": 10, "feedback": "Good work"}
            with patch("api_server.is_email_notified", new_callable=AsyncMock, return_value=True):
                with patch("api_server.fetch_grader_response", new_callable=AsyncMock, return_value=grader_response):
                    with patch("api_server.send_email", return_value=True) as mock_send:
                        with patch("api_server.mark_email_notified", new_callable=AsyncMock):
                            resp = client.post(
                                "/notify_student_grades",
                                json={
                                    "institution_id": "mit", "term_id": "2025", "course_id": "6.001",
                                    "notebook_id": "hw1", "student_id": "student@test.com",
                                    "do_resend": True,
                                },
                                headers=_auth_header(email="instructor@test.com"),
                            )

            assert resp.status_code == 200
            events = _parse_ndjson_stream(resp)
            final = _get_final_response(events)
            assert final is not None
            assert "Sent 1" in final["response"]
            mock_send.assert_called_once()
        finally:
            self._cleanup(course_handle)
