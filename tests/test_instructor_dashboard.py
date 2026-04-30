"""Tests for instructor-dashboard plumbing: TA-aware authorization and /my_courses."""

from unittest.mock import AsyncMock, patch

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


def _auth_header(email: str):
    token = create_jwt_token(
        {"id": "1", "email": email, "name": "Tester"},
        secret_key="test-secret-key-for-unit-tests",
    )
    return {"Authorization": f"Bearer {token}"}


def _seed_courses(*entries: dict) -> list[str]:
    """Insert each entry into the in-memory courses cache; return their handles."""
    from api_server import courses
    handles = []
    for e in entries:
        ch = e['course_handle']
        courses[ch] = {k: v for k, v in e.items() if k != 'course_handle'}
        handles.append(ch)
    return handles


def _clear_courses(handles: list[str]):
    from api_server import courses
    for h in handles:
        courses.pop(h, None)


# ---------------------------------------------------------------------------
# is_authorized — TA email accepted alongside instructor
# ---------------------------------------------------------------------------


class TestIsAuthorized:
    def test_instructor_authorized(self):
        from api_server import is_authorized, courses
        courses['ch'] = {'instructor_gmail': 'prof@iisc.ac.in'}
        try:
            assert is_authorized('prof@iisc.ac.in', 'ch')
            assert is_authorized('PROF@IISC.AC.IN', 'ch')  # case-insensitive
        finally:
            courses.pop('ch', None)

    def test_ta_authorized(self):
        from api_server import is_authorized, courses
        courses['ch'] = {'instructor_gmail': 'prof@iisc.ac.in', 'ta_gmail': 'ta@iisc.ac.in'}
        try:
            assert is_authorized('ta@iisc.ac.in', 'ch')
        finally:
            courses.pop('ch', None)

    def test_ta_email_field(self):
        from api_server import is_authorized, courses
        courses['ch'] = {'ta_email': 'ta@inst.edu'}
        try:
            assert is_authorized('ta@inst.edu', 'ch')
        finally:
            courses.pop('ch', None)

    def test_unrelated_user_not_authorized(self):
        from api_server import is_authorized, courses
        courses['ch'] = {'instructor_gmail': 'prof@iisc.ac.in'}
        try:
            assert not is_authorized('rando@example.com', 'ch')
        finally:
            courses.pop('ch', None)

    def test_admin_always_authorized(self):
        from api_server import is_authorized, courses
        courses['ch'] = {}  # No instructor at all
        try:
            assert is_authorized('admin@test.com', 'ch')  # admin_email in conftest
        finally:
            courses.pop('ch', None)

    def test_empty_email(self):
        from api_server import is_authorized
        assert not is_authorized('', 'ch')


# ---------------------------------------------------------------------------
# /my_courses — filters by role
# ---------------------------------------------------------------------------


class TestMyCourses:
    def test_requires_auth(self, client):
        resp = client.get("/my_courses")
        assert resp.status_code == 401

    def test_admin_sees_all(self, client):
        handles = _seed_courses(
            {"course_handle": "ch_a", "institution_id": "iisc", "term_id": "2025-26",
             "course_id": "cp260", "instructor_gmail": "prof@x.com"},
            {"course_handle": "ch_b", "institution_id": "iit", "term_id": "2025-26",
             "course_id": "cs101", "instructor_gmail": "other@y.com"},
        )
        try:
            resp = client.get("/my_courses", headers=_auth_header("admin@test.com"))
            assert resp.status_code == 200
            data = resp.json()
            handles_returned = [c['course_handle'] for c in data['courses']]
            assert "ch_a" in handles_returned and "ch_b" in handles_returned
            # Admin role tag
            for c in data['courses']:
                assert c['role'] == "admin"
        finally:
            _clear_courses(handles)

    def test_instructor_only_their_courses(self, client):
        handles = _seed_courses(
            {"course_handle": "ch_mine", "institution_id": "iisc", "term_id": "2025-26",
             "course_id": "cp260", "instructor_gmail": "prof@x.com"},
            {"course_handle": "ch_theirs", "institution_id": "iit", "term_id": "2025-26",
             "course_id": "cs101", "instructor_gmail": "other@y.com"},
        )
        try:
            resp = client.get("/my_courses", headers=_auth_header("prof@x.com"))
            assert resp.status_code == 200
            handles_returned = [c['course_handle'] for c in resp.json()['courses']]
            assert handles_returned == ["ch_mine"]
            assert resp.json()['courses'][0]['role'] == "instructor"
        finally:
            _clear_courses(handles)

    def test_ta_sees_their_courses_with_ta_role(self, client):
        handles = _seed_courses(
            {"course_handle": "ch_ta", "institution_id": "iisc", "term_id": "2025-26",
             "course_id": "cp260", "instructor_gmail": "prof@x.com",
             "ta_gmail": "ta@x.com"},
        )
        try:
            resp = client.get("/my_courses", headers=_auth_header("ta@x.com"))
            assert resp.status_code == 200
            data = resp.json()
            assert len(data['courses']) == 1
            assert data['courses'][0]['role'] == "ta"
        finally:
            _clear_courses(handles)

    def test_unrelated_user_sees_empty(self, client):
        handles = _seed_courses(
            {"course_handle": "ch_x", "instructor_gmail": "prof@x.com"},
        )
        try:
            resp = client.get("/my_courses", headers=_auth_header("rando@example.com"))
            assert resp.status_code == 200
            assert resp.json() == {"courses": []}
        finally:
            _clear_courses(handles)

    def test_results_sorted(self, client):
        handles = _seed_courses(
            {"course_handle": "ch_b", "institution_id": "iisc", "term_id": "2025-26",
             "course_id": "z", "instructor_gmail": "prof@x.com"},
            {"course_handle": "ch_a", "institution_id": "iisc", "term_id": "2025-26",
             "course_id": "a", "instructor_gmail": "prof@x.com"},
        )
        try:
            resp = client.get("/my_courses", headers=_auth_header("prof@x.com"))
            ids = [c['course_id'] for c in resp.json()['courses']]
            assert ids == ["a", "z"]
        finally:
            _clear_courses(handles)


# ---------------------------------------------------------------------------
# Dashboard at /, admin moved to /admin
# ---------------------------------------------------------------------------


class TestRouting:
    def test_root_redirects_to_login_when_unauthenticated(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login?next=/"

    def test_root_serves_dashboard_when_authenticated(self, client):
        resp = client.get("/", headers=_auth_header("prof@x.com"))
        assert resp.status_code == 200
        # Sentinel strings present in the dashboard HTML
        assert "AI-TA Instructor Dashboard" in resp.text
        assert "/my_courses" in resp.text  # the page calls this endpoint client-side
        assert "course-select" in resp.text

    def test_admin_login_page_at_admin(self, client):
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "Admin Login" in resp.text
        # Should clearly point instructors to the dashboard
        assert "dashboard" in resp.text.lower()

    def test_login_accepts_safe_next_param(self, client):
        # /login starts the OAuth flow but should accept a safe ?next= for
        # post-login redirection. We don't follow through to OAuth here; we
        # just verify the handler accepts the param and returns a 200 HTML
        # redirect page (the existing behavior).
        resp = client.get("/login?next=/", follow_redirects=False)
        assert resp.status_code == 200
        assert "Redirecting to Google" in resp.text


# ---------------------------------------------------------------------------
# Dashboard service registry — smoke test that the major endpoints are wired up
# ---------------------------------------------------------------------------


class TestDashboardServiceRegistry:
    """Sanity-check that the dashboard HTML offers buttons for the
    instructor-facing endpoints. The dashboard is a single-page app, so the
    JS service registry sits inside the HTML; we just check for the URLs."""

    def test_includes_pdf_endpoints(self, client):
        resp = client.get("/", headers=_auth_header("admin@test.com"))
        assert resp.status_code == 200
        for url in [
            "/upload_rubric_file",
            "/upload_rubric_link",
            "/ingest_pdf_submissions",
            "/grade_pdf_assignment",
            "/regrade_pdf_submission",
        ]:
            assert url in resp.text, f"Dashboard should expose {url}"

    def test_includes_grade_management_endpoints(self, client):
        resp = client.get("/", headers=_auth_header("admin@test.com"))
        for url in [
            "/fetch_marks_list",
            "/fetch_grader_response",
            "/notify_student_grades",
            "/grade_notebook",
            "/regrade_answer",
        ]:
            assert url in resp.text

    def test_includes_course_config_endpoints(self, client):
        resp = client.get("/", headers=_auth_header("admin@test.com"))
        for url in [
            "/enable_tutor",
            "/disable_tutor",
            "/update_course_config",
            "/rate_limit_status",
            "/build_course_index",
            "/list_course_files",
        ]:
            assert url in resp.text

    def test_calls_my_courses_for_picker(self, client):
        resp = client.get("/", headers=_auth_header("admin@test.com"))
        assert "/my_courses" in resp.text
        assert "course-select" in resp.text

    def test_includes_course_materials_link(self, client):
        # Course materials use the existing drag-drop page; the dashboard
        # surfaces it as a link so instructors can find it.
        resp = client.get("/", headers=_auth_header("admin@test.com"))
        assert "/upload_course_materials" in resp.text
        # Section header
        assert "Course materials" in resp.text

    def test_uses_colab_assignments_label(self, client):
        # User-visible rename: "Notebook assignments" → "Colab assignments".
        resp = client.get("/", headers=_auth_header("admin@test.com"))
        assert "Colab assignments" in resp.text
