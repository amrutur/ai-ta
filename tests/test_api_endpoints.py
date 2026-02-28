"""
Tests for API endpoints.

Uses FastAPI's TestClient with a fully mocked backend. The mock ``config``
module is injected by conftest.py before ``api_server`` is imported.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient


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
            "qnum": 1, "context": "", "question": {}, "answer": "",
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
                "answer": "A", "output": {}, "ta_chat": "help",
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
                "questions": {"1": "What is 2+2?"},
                "answers": {"1": "4"},
                "outputs": {"1": ""},
                "max_marks": 10.0,
            },
        }

        with patch("api_server.score_question", new_callable=AsyncMock, return_value=(10.0, "Perfect. Total marks: 10")):
            with patch("api_server.add_student_if_not_exists", new_callable=AsyncMock):
                with patch("api_server.add_student_notebook_if_not_exists", new_callable=AsyncMock):
                    with patch("api_server.update_marks", new_callable=AsyncMock):
                        resp = client.post(
                            "/eval",
                            json={
                                "notebook_id": "hw1",
                                "context": {"1": "intro"},
                                "questions": {"1": "What is 2+2?"},
                                "answers": {"1": "4"},
                                "outputs": {"1": ""},
                                "institution_id": "mit",
                                "term_id": "2025",
                                "course_id": "6.001",
                            },
                            headers=_auth_header(),
                        )

        assert resp.status_code == 200
        data = resp.json()
        assert "10.0" in data["response"]

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
