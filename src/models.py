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

class NotifyGradedResponse(BaseModel):
    response: str


class CreateCourseRequest(BaseModel):
    course_id: str
    term_id: str
    institution_id: str
    course_name: str | None = None
    instructor_email: EmailStr|None = None
    instructor_gmail: EmailStr|None = None
    instructor_name: str | None = None
    start_date: datetime |  None = None
    end_date: datetime | None = None
    ta_name: str | None = None
    ta_email: EmailStr | None = None
    ta_gmail: EmailStr | None = None

class CreateCourseResponse(BaseModel):
    response: str

class TutorInteractionRequest(BaseModel):
    course_id: str
    term_id: str
    institution_id: str

class TutorInteractionResponse(BaseModel):
    response: str

class ListResponse(BaseModel):
    listname: list[str]

class AddRubricRequest(BaseModel):
    notebook_id: str
    max_marks: float
    context: Dict[str,Any]
    questions: Dict[str,Any]
    answers: Dict[str, Any]
    outputs: Dict[str,Any]
    institution_id: str
    term_id: str
    course_id: str
 
class AddRubricResponse(BaseModel):
    response: str

class GradeNotebookRequest(BaseModel):
    student_id: str  # specific student email or "All" to grade all students
    notebook_id: str
    course_id: str
    term_id: str
    institution_id: str

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
    isactive_eval: Optional[bool] = None
    isactive_tutor: Optional[bool] = None
    student_rate_limit: Optional[int] = None
    student_rate_limit_window: Optional[int] = None

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

