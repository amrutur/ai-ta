"""
Pydantic request/response models for the API endpoints.
"""

from datetime import datetime
from pydantic import BaseModel, AnyUrl, EmailStr, field_validator
from typing import Dict, Any, List, Optional


class QueryRequest(BaseModel):
    query: str
    course_id: str
    notebook_id: str
    q_name: str
    rubric_link: AnyUrl | None = None
    user_name: str | None = None
    user_email: str | None = None

class QueryResponse(BaseModel):
    response: str

class AssistRequest(BaseModel):
    qnum: int
    context: str
    question: Dict[str,Any]
    answer: List[Dict[str, Any]]
    output: Dict[str,Any]
    ta_chat: str
    notebook_id: str
    institution_id: str
    term_id: str
    course_id: str

class AssistResponse(BaseModel):
    response: str

class RegisterStudentRequest(BaseModel):
    student_id: str
    student_name: str
    student_email: EmailStr | None = None
    course_id: str
    term_id: str
    institution_id: str

class RegisterStudentResponse(BaseModel):
    response: str

class GradeRequest(BaseModel):
    question: str
    answer: str
    q_id: str
    notebook_id: str 
    rubric: str
    student_id: str
    course_id: str
    term_id: str
    institution_id: str

class GradeResponse(BaseModel):
    response: str
    marks: float

class EvalRequest(BaseModel):
    notebook_id: str
    context: Dict[str,Any]
    questions: Dict[str,Any]
    answers: Dict[str,Any]    
    outputs: Dict[str,Any]
    institution_id: str
    term_id: str
    course_id: str

class EvalResponse(BaseModel):
    response: str

class FetchGradedRequest(BaseModel):
    notebook_id: str
    student_id: str
    institution_id: str
    term_id: str
    course_id: str

class FetchGradedResponse(BaseModel):
    grader_response: Dict[str, Any] | None = None

class FetchMarksListRequest(BaseModel):
    institution_id: str
    term_id: str
    course_id: str
    notebook_id: str

class FetchMarksListResponse(BaseModel):
    max_marks: float | None = None
    marks_list: List[Dict[str, Any]] | None = None


class NotifyGradedRequest(BaseModel):
    institution_id: str
    term_id: str
    course_id: str
    notebook_id: str
    student_id: str
    do_resend: bool = False

class NotifyGradedResponse(BaseModel):
    response: str


class CreateCourseRequest(BaseModel):
    """Body for POST /create_course.

    The agent prompts (``instructor_assist_prompt`` etc.) are no longer
    accepted at create time — they're long, multi-paragraph, and impractical
    to paste into a single JSON request. Use POST /update_course_prompt
    after creation if you need to override a default. The course_name and
    course_topics fields are filled into the prompts'
    ``<<course_name>>`` / ``<<course_topics>>`` placeholders at agent
    creation time.
    """
    course_id: str
    term_id: str
    institution_id: str
    course_name: str | None = None
    course_topics: str | None = None
    instructor_email: EmailStr|None = None
    instructor_gmail: EmailStr|None = None
    instructor_name: str | None = None
    start_date: datetime |  None = None
    end_date: datetime | None = None
    ta_name: str | None = None
    ta_email: EmailStr | None = None
    ta_gmail: EmailStr | None = None
    ai_model: str | None = None

class CreateCourseResponse(BaseModel):
    response: str

class TutorInteractionRequest(BaseModel):
    course_id: str
    term_id: str
    institution_id: str

class EvalToggleRequest(BaseModel):
    notebook_id: str
    course_id: str
    term_id: str
    institution_id: str

class TutorInteractionResponse(BaseModel):
    response: str

class ListResponse(BaseModel):
    listname: list[str]

class AddRubricRequest(BaseModel):
    """Add or replace a rubric for an assignment.

    The rubric carries two orthogonal flags:

    - ``assignment_type``: ``"q&a"`` (per-question scoring) or ``"report"``
      (holistic scoring). For backward compatibility the legacy values
      ``"notebook"`` and ``"pdf"`` are also accepted and mapped:
      ``"notebook"`` → ``"q&a"`` + ``submission_type="colab"``; ``"pdf"`` →
      ``"report"`` + ``submission_type="pdf"``.
    - ``submission_type``: ``"colab"`` or ``"pdf"`` — the format students
      submit in. Defaults are inferred from the assignment_type when
      omitted (q&a→colab, report→pdf).
    """
    notebook_id: str
    max_marks: float
    institution_id: str
    term_id: str
    course_id: str
    # q&a / Colab rubric body (optional so report rubrics can omit them).
    context: Dict[str, Any] | None = None
    questions: Dict[str, Any] | None = None
    answers: Dict[str, Any] | None = None
    outputs: Dict[str, Any] | None = None
    # report / PDF rubric body (optional so q&a rubrics can omit them).
    problem_statement: str | None = None
    rubric_text: str | None = None
    sample_graded_response: str | None = None
    # Discriminators. Default keeps existing clients working: notebook → q&a+colab.
    assignment_type: str = "q&a"
    submission_type: str | None = None

class AddRubricResponse(BaseModel):
    response: str


class IngestPdfSubmissionsRequest(BaseModel):
    institution_id: str
    term_id: str
    course_id: str
    notebook_id: str
    drive_folder_url: str

class IngestedPdfRecord(BaseModel):
    drive_file_id: str
    filename: str
    authors: List[str]
    student_ids: List[str]
    placeholder_student_ids: List[str]
    gcs_uri: str

class SkippedPdfRecord(BaseModel):
    drive_file_id: str
    filename: str
    reason: str

class FailedPdfRecord(BaseModel):
    drive_file_id: str | None = None
    filename: str | None = None
    error: str

class IngestPdfSubmissionsResponse(BaseModel):
    ingested: List[IngestedPdfRecord] = []
    skipped: List[SkippedPdfRecord] = []
    failed: List[FailedPdfRecord] = []


class GradePdfAssignmentRequest(BaseModel):
    institution_id: str
    term_id: str
    course_id: str
    notebook_id: str
    do_regrade: bool = False


class RosterRowError(BaseModel):
    row_number: int
    raw: Dict[str, Any]
    reason: str

class PlaceholderRosterMatch(BaseModel):
    placeholder_student_id: str
    placeholder_name: str
    matched_email: str
    matched_name: str

class UploadStudentRosterResponse(BaseModel):
    added: List[str] = []
    updated: List[str] = []
    skipped: List[RosterRowError] = []
    # Placeholders (@pending.local) whose names fuzzy-match a roster entry.
    # Detection only — no auto-merge in this version.
    matching_placeholders: List[PlaceholderRosterMatch] = []


class GradeAssignmentRequest(BaseModel):
    """Unified grade-an-assignment request.

    Server dispatches to the PDF or Colab path based on assignment_type
    on the rubric doc. ``student_id`` is only used by the Colab path
    (PDF mode grades every ingested submission).
    """
    institution_id: str
    term_id: str
    course_id: str
    notebook_id: str
    student_id: str = "All"
    do_regrade: bool = False


class RegradePdfSubmissionRequest(BaseModel):
    institution_id: str
    term_id: str
    course_id: str
    notebook_id: str
    student_id: str
    do_regrade: bool = True
    student_contends: str = ""

class RegradePdfSubmissionResponse(BaseModel):
    response: str
    marks: float

class GradeNotebookRequest(BaseModel):
    student_id: str  # specific student email or "All" to grade all students
    notebook_id: str
    course_id: str
    term_id: str
    institution_id: str
    do_regrade: bool = False

class RegradeAnswerRequest(BaseModel):
    qnum: int
    notebook_id: str
    student_id: str
    course_id: str
    term_id: str
    institution_id: str
    do_regrade: bool = True
    student_contends: str = ""

class RegradeAnswerResponse(BaseModel):
    response: str
    marks: float

class BuildCourseIndexRequest(BaseModel):
    course_id: str
    term_id: str
    institution_id: str

class BuildCourseIndexResponse(BaseModel):
    status: str
    files_processed: int
    chunks_created: int
    message: str | None = None

class UpdateCourseConfigRequest(BaseModel):
    institution_id: str
    term_id: str
    course_id: str
    model: Optional[str] = None
    isactive_tutor: Optional[bool] = None
    student_rate_limit: Optional[int] = None
    student_rate_limit_window: Optional[int] = None
    # Filled into the agents' <<course_name>> / <<course_topics>> placeholders.
    # Updating either invalidates the runner cache so the change is picked up
    # without restarting the server.
    course_name: Optional[str] = None
    course_topics: Optional[str] = None

    @field_validator('student_rate_limit')
    @classmethod
    def validate_student_rate_limit(cls, v):
        if v is not None and v < 0:
            raise ValueError('student_rate_limit must be >= 0 (0 to disable)')
        if v is not None and v > 1000:
            raise ValueError('student_rate_limit must be <= 1000')
        return v

    @field_validator('student_rate_limit_window')
    @classmethod
    def validate_student_rate_limit_window(cls, v):
        if v is not None and (v < 60 or v > 86400):
            raise ValueError('student_rate_limit_window must be between 60 and 86400 seconds')
        return v

class UpdateCourseConfigResponse(BaseModel):
    updated: Dict[str, Any]


class UpdateCoursePromptRequest(BaseModel):
    """Set or clear a per-course prompt override for one agent.

    ``agent_type`` must be one of ``"instructor"``, ``"student"``,
    ``"scoring_qa"``, ``"scoring_report"``. An empty / null ``prompt``
    clears the override, restoring the default template from agent.py.
    """
    institution_id: str
    term_id: str
    course_id: str
    agent_type: str
    prompt: str | None = None

    @field_validator('agent_type')
    @classmethod
    def validate_agent_type(cls, v):
        allowed = {"instructor", "student", "scoring_qa", "scoring_report"}
        if v not in allowed:
            raise ValueError(f"agent_type must be one of {sorted(allowed)}; got {v!r}")
        return v


class UpdateCoursePromptResponse(BaseModel):
    agent_type: str
    is_now_default: bool


class CoursePromptResponse(BaseModel):
    """Returned by GET /course_prompt.

    ``prompt`` is the *effective* prompt the agent will use right now —
    the override if one is set, otherwise the default template formatted
    with the course's ``course_name`` and ``course_topics``. ``is_default``
    is True iff there is no override. ``default_template`` is the raw
    template (with the unresolved ``<<course_name>>`` /
    ``<<course_topics>>`` placeholders) — useful for the dashboard's
    "reset to default" button.
    """
    agent_type: str
    prompt: str
    is_default: bool
    default_template: str
    course_name: str
    course_topics: str

class UpdateGlobalConfigRequest(BaseModel):
    semaphore_limit: Optional[int] = None

    @field_validator('semaphore_limit')
    @classmethod
    def validate_semaphore_limit(cls, v):
        if v is not None and (v < 1 or v > 100):
            raise ValueError('semaphore_limit must be between 1 and 100')
        return v

class UpdateGlobalConfigResponse(BaseModel):
    updated: Dict[str, Any]

class ListCourseFilesRequest(BaseModel):
    course_id: str
    term_id: str
    institution_id: str

class ListCourseFilesResponse(BaseModel):
    files: List[Dict[str, Any]]

