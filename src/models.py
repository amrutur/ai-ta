"""
Pydantic request/response models for the API endpoints.
"""

from datetime import datetime
from pydantic import BaseModel, AnyUrl, EmailStr
from typing import Dict, Any


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
    answer: str
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
    marks_list: Dict[str, Any] | None = None


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
    answers: Dict[str,Any]
    outputs: Dict[str,Any]  
    institution_id: str
    term_id: str
    course_id: str
 
class AddRubricResponse(BaseModel):
    response: str

class BuildCourseIndexRequest(BaseModel):
    course_id: str
    term_id: str
    institution_id: str

class BuildCourseIndexResponse(BaseModel):
    status: str
    files_processed: int
    chunks_created: int
    message: str | None = None

