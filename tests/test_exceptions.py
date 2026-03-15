"""
Tests for custom exception classes in exceptions.py and aita_exceptions.py.
"""

from exceptions import AITAError, CourseNotFoundError, StudentNotEnrolledError
from aita_exceptions import (
    AITAError as AITAError2,
    CourseNotFoundError as CourseNotFoundError2,
    NotebookNotFoundError,
    StudentNotEnrolledError as StudentNotEnrolledError2,
)


class TestExceptions:
    def test_aita_error_is_base_exception(self):
        err = AITAError("something went wrong")
        assert isinstance(err, Exception)
        assert str(err) == "something went wrong"

    def test_course_not_found_stores_course_id(self):
        err = CourseNotFoundError("CS101")
        assert err.course_id == "CS101"
        assert "CS101" in str(err)
        assert isinstance(err, AITAError)

    def test_student_not_enrolled(self):
        err = StudentNotEnrolledError("student@test.com", "CS101")
        assert "student@test.com" in str(err)
        assert "CS101" in str(err)
        assert isinstance(err, AITAError)


class TestAitaExceptions:
    def test_notebook_not_found(self):
        err = NotebookNotFoundError("nb1", "student@test.com", "CS101")
        assert "nb1" in str(err)
        assert "student@test.com" in str(err)
        assert "CS101" in str(err)
        assert isinstance(err, AITAError2)

    def test_course_not_found_message(self):
        err = CourseNotFoundError2("PHYS200")
        assert err.message == "Course with ID 'PHYS200' was not found in the 'courses' collection in the database."

    def test_exception_hierarchy(self):
        assert issubclass(CourseNotFoundError2, AITAError2)
        assert issubclass(StudentNotEnrolledError2, AITAError2)
        assert issubclass(NotebookNotFoundError, AITAError2)
        assert issubclass(AITAError2, Exception)
