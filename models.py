"""
Pydantic request/response models for the API endpoints.
"""

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
    query: str
    q_id: str
    rubric_link: AnyUrl | None = None
    user_name: str | None = None
    user_email: str | None = None

class AssistResponse(BaseModel):
    response: str

class GradeRequest(BaseModel):
    question: str
    answer: str
    rubric: str
    course_id: str | None = None
    notebook_id: str | None = None
    q_id: str | None = None
    user_name: str | None = None
    user_email: str | None = None

class GradeResponse(BaseModel):
    response: str
    marks: float

class EvalRequest(BaseModel):
    course_id: str
    user_name: str
    user_email: str
    notebook_id: str
    answer_notebook: Dict[str, Any]
    answer_hash: str
    rubric_link: AnyUrl

class EvalResponse(BaseModel):
    response: str
    marks: float

class FetchGradedRequest(BaseModel):
    notebook_id: str
    user_email: EmailStr

class FetchGradedResponse(BaseModel):
    grader_response: Dict[str, Any] | None = None

class NotifyGradedRequest(BaseModel):
    notebook_id: str
    user_email: EmailStr | None = None

class NotifyGradedResponse(BaseModel):
    response: str

class FetchStudentListRequest(BaseModel):
    course_id: str | None = None
    notebook_id: str | None = None

class FetchStudentListResponse(BaseModel):
    response: Dict[str, Any] | None = None
