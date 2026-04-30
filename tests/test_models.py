"""
Tests for Pydantic request/response models.

These tests verify that model field names match what the API endpoints
expect, catching the class of bugs where endpoint code references a
field that doesn't exist on the model (e.g. ``query_body.user_email``
on a model that has no ``user_email`` field).
"""

import pytest
from pydantic import ValidationError

from models import (
    AddRubricRequest,
    AddRubricResponse,
    AssistRequest,
    AssistResponse,
    CreateCourseRequest,
    CreateCourseResponse,
    EvalRequest,
    EvalResponse,
    FetchGradedRequest,
    FetchGradedResponse,
    FetchMarksListRequest,
    FetchMarksListResponse,
    GradePdfAssignmentRequest,
    GradeRequest,
    GradeResponse,
    IngestPdfSubmissionsRequest,
    IngestPdfSubmissionsResponse,
    NotifyGradedRequest,
    NotifyGradedResponse,
    RegisterStudentRequest,
    RegisterStudentResponse,
    RegradePdfSubmissionRequest,
    RegradePdfSubmissionResponse,
    TutorInteractionRequest,
    TutorInteractionResponse,
    UpdateCourseConfigRequest,
)


# ---------------------------------------------------------------------------
# AssistRequest / AssistResponse
# ---------------------------------------------------------------------------

class TestAssistRequest:
    def test_valid(self):
        req = AssistRequest(
            qnum=1,
            context="some context",
            question={"question": "What is 2+2?"},
            answer=[{"percent": 100, "component": "4"}],
            output={"stdout": "4"},
            ta_chat="Is this correct?",
            notebook_id="hw1",
            institution_id="mit",
            term_id="2025-spring",
            course_id="6.001",
        )
        assert req.qnum == 1
        assert req.notebook_id == "hw1"

    def test_missing_required_field(self):
        with pytest.raises(ValidationError):
            AssistRequest(qnum=1)  # missing many required fields


# ---------------------------------------------------------------------------
# GradeRequest / GradeResponse
# ---------------------------------------------------------------------------

class TestGradeRequest:
    def test_valid(self):
        req = GradeRequest(
            question="What is 2+2?",
            answer="4",
            q_id="q1",
            notebook_id="hw1",
            rubric="The answer is 4",
            student_id="student@test.com",
            course_id="6.001",
            term_id="2025-spring",
            institution_id="mit",
        )
        assert req.student_id == "student@test.com"
        assert req.rubric == "The answer is 4"

    def test_has_no_user_email_field(self):
        """GradeRequest should NOT have user_email — endpoints must not reference it."""
        assert "user_email" not in GradeRequest.model_fields

    def test_has_no_user_name_field(self):
        """GradeRequest should NOT have user_name — endpoints must not reference it."""
        assert "user_name" not in GradeRequest.model_fields

    def test_has_student_id(self):
        assert "student_id" in GradeRequest.model_fields


class TestGradeResponse:
    def test_valid(self):
        resp = GradeResponse(response="Good job", marks=4.0)
        assert resp.marks == 4.0


# ---------------------------------------------------------------------------
# EvalRequest / EvalResponse
# ---------------------------------------------------------------------------

class TestEvalRequest:
    def test_valid(self):
        req = EvalRequest(
            notebook_id="hw1",
            context={"1": "topic intro"},
            questions={"1": "What is 2+2?"},
            answers={"1": "4"},
            outputs={"1": ""},
            institution_id="mit",
            term_id="2025-spring",
            course_id="6.001",
        )
        assert req.notebook_id == "hw1"
        assert req.answers == {"1": "4"}

    def test_has_no_old_fields(self):
        """EvalRequest was redesigned — old fields must not exist."""
        old_fields = ["user_name", "user_email", "answer_notebook", "rubric_link", "answer_hash"]
        for field in old_fields:
            assert field not in EvalRequest.model_fields, f"EvalRequest should not have '{field}'"

    def test_has_required_new_fields(self):
        required = ["notebook_id", "context", "questions", "answers", "outputs",
                     "institution_id", "term_id", "course_id"]
        for field in required:
            assert field in EvalRequest.model_fields, f"EvalRequest missing '{field}'"


class TestEvalResponse:
    def test_valid(self):
        resp = EvalResponse(response="Done")
        assert resp.response == "Done"

    def test_has_no_marks_field(self):
        """EvalResponse no longer carries marks — only a text response."""
        assert "marks" not in EvalResponse.model_fields


# ---------------------------------------------------------------------------
# AddRubricRequest / AddRubricResponse
# ---------------------------------------------------------------------------

class TestAddRubricRequest:
    def test_valid(self):
        req = AddRubricRequest(
            notebook_id="hw1",
            max_marks=100.0,
            context={"1": "intro"},
            questions={"1": "Q1"},
            answers={"1": "A1"},
            outputs={"1": ""},
            institution_id="mit",
            term_id="2025-spring",
            course_id="6.001",
        )
        assert req.max_marks == 100.0
        # Default assignment_type stays "notebook" so existing clients are unaffected.
        assert req.assignment_type == "notebook"

    def test_has_outputs(self):
        """outputs field must exist (was missing in an earlier version)."""
        assert "outputs" in AddRubricRequest.model_fields

    def test_pdf_mode_omits_notebook_fields(self):
        req = AddRubricRequest(
            notebook_id="lab1",
            max_marks=50.0,
            institution_id="iisc",
            term_id="2025-26",
            course_id="cp260",
            assignment_type="pdf",
            problem_statement="Build a TCP server",
            rubric_text="Correctness 30, code quality 20",
            sample_graded_response="Sample graded text",
        )
        assert req.assignment_type == "pdf"
        assert req.problem_statement == "Build a TCP server"
        assert req.context is None
        assert req.questions is None


# ---------------------------------------------------------------------------
# IngestPdfSubmissionsRequest / GradePdfAssignmentRequest / RegradePdfSubmissionRequest
# ---------------------------------------------------------------------------


class TestPdfModeRequests:
    def test_ingest(self):
        req = IngestPdfSubmissionsRequest(
            institution_id="iisc", term_id="2025-26", course_id="cp260",
            notebook_id="lab1",
            drive_folder_url="https://drive.google.com/drive/folders/ABC",
        )
        assert req.drive_folder_url.endswith("/folders/ABC")

    def test_ingest_response_default_lists_empty(self):
        resp = IngestPdfSubmissionsResponse()
        assert resp.ingested == [] and resp.skipped == [] and resp.failed == []

    def test_grade_pdf_assignment(self):
        req = GradePdfAssignmentRequest(
            institution_id="iisc", term_id="2025-26", course_id="cp260",
            notebook_id="lab1",
        )
        assert req.do_regrade is False

    def test_regrade_pdf_submission(self):
        req = RegradePdfSubmissionRequest(
            institution_id="iisc", term_id="2025-26", course_id="cp260",
            notebook_id="lab1",
            student_id="alice@iisc.ac.in",
        )
        assert req.do_regrade is True
        assert req.student_contends == ""

    def test_regrade_pdf_submission_response(self):
        resp = RegradePdfSubmissionResponse(response="Re-evaluated", marks=42.0)
        assert resp.marks == 42.0


# ---------------------------------------------------------------------------
# Other models — basic instantiation
# ---------------------------------------------------------------------------

class TestOtherModels:
    def test_register_student(self):
        req = RegisterStudentRequest(
            student_id="s1", student_name="Alice",
            course_id="6.001", term_id="2025", institution_id="mit",
        )
        assert req.student_id == "s1"

    def test_fetch_graded_request(self):
        req = FetchGradedRequest(
            notebook_id="hw1", student_id="s1",
            institution_id="mit", term_id="2025", course_id="6.001",
        )
        assert req.student_id == "s1"

    def test_fetch_marks_list_request(self):
        req = FetchMarksListRequest(
            institution_id="mit", term_id="2025",
            course_id="6.001", notebook_id="hw1",
        )
        assert req.notebook_id == "hw1"

    def test_create_course_request(self):
        req = CreateCourseRequest(
            course_id="6.001", term_id="2025", institution_id="mit",
        )
        assert req.course_id == "6.001"

    def test_tutor_interaction_request(self):
        req = TutorInteractionRequest(
            course_id="6.001", term_id="2025", institution_id="mit",
        )
        assert req.course_id == "6.001"


# ---------------------------------------------------------------------------
# UpdateCourseConfigRequest — rate limit fields
# ---------------------------------------------------------------------------

class TestUpdateCourseConfigRequest:
    def test_valid_with_rate_limit_fields(self):
        req = UpdateCourseConfigRequest(
            institution_id="mit", term_id="2025", course_id="6.001",
            student_rate_limit=20,
            student_rate_limit_window=3600,
        )
        assert req.student_rate_limit == 20
        assert req.student_rate_limit_window == 3600

    def test_rate_limit_fields_optional(self):
        req = UpdateCourseConfigRequest(
            institution_id="mit", term_id="2025", course_id="6.001",
        )
        assert req.student_rate_limit is None
        assert req.student_rate_limit_window is None

    def test_rate_limit_zero_disables(self):
        req = UpdateCourseConfigRequest(
            institution_id="mit", term_id="2025", course_id="6.001",
            student_rate_limit=0,
        )
        assert req.student_rate_limit == 0

    def test_rate_limit_negative_rejected(self):
        with pytest.raises(ValidationError):
            UpdateCourseConfigRequest(
                institution_id="mit", term_id="2025", course_id="6.001",
                student_rate_limit=-1,
            )

    def test_rate_limit_above_max_rejected(self):
        with pytest.raises(ValidationError):
            UpdateCourseConfigRequest(
                institution_id="mit", term_id="2025", course_id="6.001",
                student_rate_limit=1001,
            )

    def test_window_below_min_rejected(self):
        with pytest.raises(ValidationError):
            UpdateCourseConfigRequest(
                institution_id="mit", term_id="2025", course_id="6.001",
                student_rate_limit_window=30,
            )

    def test_window_above_max_rejected(self):
        with pytest.raises(ValidationError):
            UpdateCourseConfigRequest(
                institution_id="mit", term_id="2025", course_id="6.001",
                student_rate_limit_window=100000,
            )

    def test_window_boundary_values(self):
        req_min = UpdateCourseConfigRequest(
            institution_id="mit", term_id="2025", course_id="6.001",
            student_rate_limit_window=60,
        )
        assert req_min.student_rate_limit_window == 60
        req_max = UpdateCourseConfigRequest(
            institution_id="mit", term_id="2025", course_id="6.001",
            student_rate_limit_window=86400,
        )
        assert req_max.student_rate_limit_window == 86400
