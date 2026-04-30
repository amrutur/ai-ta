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
            "/regrade_pdf_submission",
        ]:
            assert url in resp.text, f"Dashboard should expose {url}"

    def test_includes_unified_grade_endpoint(self, client):
        # The dashboard uses one /grade_assignment button that dispatches by
        # assignment_type server-side, instead of separate PDF / Colab buttons.
        resp = client.get("/", headers=_auth_header("admin@test.com"))
        assert "/grade_assignment" in resp.text

    def test_includes_grade_management_endpoints(self, client):
        resp = client.get("/", headers=_auth_header("admin@test.com"))
        for url in [
            "/fetch_marks_list",
            "/fetch_grader_response",
            "/notify_student_grades",
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

    def test_includes_roster_upload(self, client):
        resp = client.get("/", headers=_auth_header("admin@test.com"))
        assert "/upload_student_roster" in resp.text
        assert "Course roster" in resp.text


# ---------------------------------------------------------------------------
# Rubric type normalization (assignment_type × submission_type)
# ---------------------------------------------------------------------------


class TestNormalizeRubricTypes:
    def test_legacy_pdf_value(self):
        from api_server import _normalize_rubric_types
        assert _normalize_rubric_types({"assignment_type": "pdf"}) == ("report", "pdf")

    def test_legacy_notebook_value(self):
        from api_server import _normalize_rubric_types
        assert _normalize_rubric_types({"assignment_type": "notebook"}) == ("q&a", "colab")

    def test_missing_defaults_to_qa_colab(self):
        from api_server import _normalize_rubric_types
        # Pre-discriminator rubrics had no assignment_type at all; treat as
        # q&a + colab since that was the original (and only) flow.
        assert _normalize_rubric_types({"max_marks": 100.0}) == ("q&a", "colab")

    def test_new_2d_pair_passthrough(self):
        from api_server import _normalize_rubric_types
        assert _normalize_rubric_types({
            "assignment_type": "q&a", "submission_type": "pdf",
        }) == ("q&a", "pdf")
        assert _normalize_rubric_types({
            "assignment_type": "report", "submission_type": "pdf",
        }) == ("report", "pdf")

    def test_invalid_combo_falls_back_to_safe_default(self):
        from api_server import _normalize_rubric_types
        # Garbage values should not crash — fall back to q&a+colab.
        assert _normalize_rubric_types({
            "assignment_type": "weird", "submission_type": "alien",
        }) == ("q&a", "colab")

    def test_helpers_use_normalized_form(self):
        from api_server import _is_pdf_rubric, _is_report_pdf_rubric
        # Legacy "pdf" rubric → report+pdf.
        assert _is_pdf_rubric({"assignment_type": "pdf"})
        assert _is_report_pdf_rubric({"assignment_type": "pdf"})
        # New q&a+pdf rubric → pdf submission, but NOT a report+pdf.
        assert _is_pdf_rubric({"assignment_type": "q&a", "submission_type": "pdf"})
        assert not _is_report_pdf_rubric({"assignment_type": "q&a", "submission_type": "pdf"})
        # q&a+colab → neither.
        assert not _is_pdf_rubric({"assignment_type": "q&a", "submission_type": "colab"})


# ---------------------------------------------------------------------------
# Format-string prompts: <<course_name>> / <<course_topics>>
# ---------------------------------------------------------------------------


class TestFormatPrompt:
    def test_substitutes_both_placeholders(self):
        import agent
        rendered = agent.format_prompt(
            "Assistant for <<course_name>> on <<course_topics>>.",
            course_name="Embedded Systems",
            course_topics="microcontrollers and FPGAs",
        )
        assert rendered == "Assistant for Embedded Systems on microcontrollers and FPGAs."

    def test_falls_back_when_course_topics_blank(self):
        import agent
        rendered = agent.format_prompt(
            "On <<course_topics>>.",
            course_name="X",
            course_topics="",
        )
        # Falls back to a readable default rather than leaving an empty noun phrase.
        assert "<<course_topics>>" not in rendered
        assert agent.DEFAULT_COURSE_TOPICS_FALLBACK in rendered

    def test_leaves_other_curly_braces_untouched(self):
        import agent
        # Existing prompts use {Relevant course material:} as content markers;
        # plain str.format would crash on them. Replace-based formatter doesn't.
        template = "Look for {Relevant course material:} in <<course_name>>."
        rendered = agent.format_prompt(template, course_name="C", course_topics="T")
        assert "{Relevant course material:}" in rendered
        assert "in C." in rendered

    def test_create_agent_uses_formatted_default(self):
        import agent
        # Default agent for "instructor" should have placeholders replaced.
        ag = agent.create_agent(
            "instructor", course_name="Sample Course",
            course_topics="signals and systems",
            course_handle="ch-test-default",
        )
        # The exact attribute name on Agent depends on ADK; just check the
        # resulting instruction string contains our substitutions.
        instr = getattr(ag, 'instruction', None) or getattr(ag, '_instruction', '')
        assert "<<course_name>>" not in str(instr)
        assert "Sample Course" in str(instr)


# ---------------------------------------------------------------------------
# /course_prompt and /update_course_prompt
# ---------------------------------------------------------------------------


class TestCoursePromptEndpoints:
    def _setup(self, *, instructor="instructor@test.com", overrides=None):
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        data = {
            "instructor_gmail": instructor,
            "course_name": "CP260 Embedded Systems",
            "course_topics": "microcontrollers, FPGAs, hardware/software co-design",
        }
        if overrides:
            data.update(overrides)
        courses[ch] = data
        return ch

    def _teardown(self, ch):
        from api_server import courses
        courses.pop(ch, None)

    def test_view_default_prompt_when_no_override(self, client):
        ch = self._setup()
        try:
            resp = client.get(
                "/course_prompt",
                params={"institution_id": "iisc", "term_id": "2025-26",
                        "course_id": "cp260", "agent_type": "instructor"},
                headers=_auth_header("instructor@test.com"),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data['agent_type'] == "instructor"
            assert data['is_default'] is True
            assert data['course_name'] == "CP260 Embedded Systems"
            # Default template still has the unresolved placeholders.
            assert "<<course_name>>" in data['default_template']
            # The 'prompt' field returns the same template (no override).
            assert "<<course_name>>" in data['prompt']
        finally:
            self._teardown(ch)

    def test_view_returns_override_when_set(self, client):
        ch = self._setup(overrides={
            "instructor_assist_prompt": "Custom override for <<course_name>>.",
        })
        try:
            resp = client.get(
                "/course_prompt",
                params={"institution_id": "iisc", "term_id": "2025-26",
                        "course_id": "cp260", "agent_type": "instructor"},
                headers=_auth_header("instructor@test.com"),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data['is_default'] is False
            assert data['prompt'].startswith("Custom override")

        finally:
            self._teardown(ch)

    def test_view_unknown_agent_type_400(self, client):
        ch = self._setup()
        try:
            resp = client.get(
                "/course_prompt",
                params={"institution_id": "iisc", "term_id": "2025-26",
                        "course_id": "cp260", "agent_type": "scoring"},  # legacy alias not exposed
                headers=_auth_header("instructor@test.com"),
            )
            assert resp.status_code == 400
        finally:
            self._teardown(ch)

    def test_update_sets_override_and_invalidates_runners(self, client):
        from unittest.mock import patch as _patch
        ch = self._setup()
        try:
            with _patch("api_server.update_course_info", new_callable=AsyncMock) as mock_upd, \
                 _patch("api_server.config.invalidate_course_runners") as mock_inv:
                resp = client.post(
                    "/update_course_prompt",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260", "agent_type": "scoring_report",
                          "prompt": "My report grading rubric"},
                    headers=_auth_header("instructor@test.com"),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data == {"agent_type": "scoring_report", "is_now_default": False}
            mock_upd.assert_awaited_once()
            mock_inv.assert_called_once_with(ch)
            # Cache reflects new override.
            from api_server import courses
            assert courses[ch]["scoring_report_prompt"] == "My report grading rubric"
        finally:
            self._teardown(ch)

    def test_update_with_empty_prompt_clears_override(self, client):
        from unittest.mock import patch as _patch
        ch = self._setup(overrides={"student_assist_prompt": "Old override"})
        try:
            with _patch("api_server.update_course_info", new_callable=AsyncMock), \
                 _patch("api_server.config.invalidate_course_runners"):
                resp = client.post(
                    "/update_course_prompt",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260", "agent_type": "student",
                          "prompt": ""},
                    headers=_auth_header("instructor@test.com"),
                )
            assert resp.status_code == 200
            assert resp.json()["is_now_default"] is True
            from api_server import courses
            assert courses[ch].get("student_assist_prompt") in (None, "")
        finally:
            self._teardown(ch)

    def test_update_unauthorized_user_403(self, client):
        ch = self._setup()
        try:
            resp = client.post(
                "/update_course_prompt",
                json={"institution_id": "iisc", "term_id": "2025-26",
                      "course_id": "cp260", "agent_type": "instructor",
                      "prompt": "trying to hijack"},
                headers=_auth_header("rando@example.com"),
            )
            assert resp.status_code == 403
        finally:
            self._teardown(ch)

    def test_invalid_agent_type_rejected_at_model_layer(self, client):
        ch = self._setup()
        try:
            resp = client.post(
                "/update_course_prompt",
                json={"institution_id": "iisc", "term_id": "2025-26",
                      "course_id": "cp260", "agent_type": "rogue",
                      "prompt": "x"},
                headers=_auth_header("instructor@test.com"),
            )
            # Pydantic validator on the model rejects unknown agent_type.
            assert resp.status_code == 422
        finally:
            self._teardown(ch)


class TestUpdateCourseConfigCourseMetadata:
    def test_course_name_and_topics_invalidate_runners(self, client):
        from unittest.mock import patch as _patch
        from api_server import courses
        from database import make_course_handle
        ch = make_course_handle("iisc", "2025-26", "cp260")
        courses[ch] = {"instructor_gmail": "instructor@test.com"}
        try:
            with _patch("api_server.update_course_info", new_callable=AsyncMock), \
                 _patch("api_server.config.invalidate_course_runners") as mock_inv:
                resp = client.post(
                    "/update_course_config",
                    json={"institution_id": "iisc", "term_id": "2025-26",
                          "course_id": "cp260",
                          "course_name": "CP260", "course_topics": "MCUs and FPGAs"},
                    headers=_auth_header("instructor@test.com"),
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data["updated"]["course_name"] == "CP260"
            assert data["updated"]["course_topics"] == "MCUs and FPGAs"
            mock_inv.assert_called_once_with(ch)
            assert courses[ch]["course_name"] == "CP260"
        finally:
            courses.pop(ch, None)
