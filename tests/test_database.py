"""
Tests for database functions.

Each function under test receives a mock Firestore ``db`` client,
so no real GCP calls are made.

Firestore's async client uses SYNC calls for .collection() / .document()
and ASYNC calls for .get() / .set() / .stream().  The mocks here mirror
that: MagicMock for sync parts, AsyncMock only for the async operations.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from database import (
    make_course_handle,
    add_student_if_not_exists,
    add_instructor_notebook_if_not_exists,
    save_rubric,
    update_marks,
    upload_student_notebook,
    load_course_info_from_db,
    load_notebooks_from_db,
)


# ---------------------------------------------------------------------------
# make_course_handle  (pure function — no mocking needed)
# ---------------------------------------------------------------------------

class TestMakeCourseHandle:
    def test_basic(self):
        result = make_course_handle("MIT", "2025-Spring", "6.001")
        assert result == "mit2025-spring6001"

    def test_spaces_replaced(self):
        result = make_course_handle("UC Berkeley", "Fall 2025", "CS 61A")
        assert " " not in result
        assert result == "uc-berkeleyfall-2025cs-61a"

    def test_special_chars_stripped(self):
        result = make_course_handle("MIT!", "2025/Spring", "6.001#A")
        assert "#" not in result
        assert "!" not in result

    def test_consistent(self):
        """Same inputs should always produce the same handle."""
        a = make_course_handle("inst", "term", "course")
        b = make_course_handle("inst", "term", "course")
        assert a == b


# ---------------------------------------------------------------------------
# Helper: build a mock Firestore DB with configurable document chains
#
# Firestore pattern:  db.collection('x').document('y')   → sync
#                     ref.get() / ref.set() / ref.stream()→ async
# ---------------------------------------------------------------------------

def _make_mock_db(course_exists=True, student_exists=False, notebook_exists=False):
    """Build a mock Firestore client with a predictable chain of returns.

    Uses MagicMock for sync operations (.collection, .document) and
    AsyncMock only for async operations (.get, .set).
    """
    # Course document snapshot
    course_doc = MagicMock()
    course_doc.exists = course_exists
    course_doc.to_dict.return_value = {"course_name": "Test"}
    course_doc.reference = MagicMock()
    course_doc.reference.set = AsyncMock()

    # Course reference  (courses/{handle})
    course_ref = MagicMock()
    course_ref.get = AsyncMock(return_value=course_doc)
    course_ref.set = AsyncMock()

    # Student document snapshot
    student_doc = MagicMock()
    student_doc.exists = student_exists
    student_doc.to_dict.return_value = {"name": "Alice"}

    # Student reference  (courses/{handle}/Students/{id})
    student_ref = MagicMock()
    student_ref.get = AsyncMock(return_value=student_doc)
    student_ref.set = AsyncMock()

    # Notebook document snapshot
    notebook_doc = MagicMock()
    notebook_doc.exists = notebook_exists

    # Notebook reference
    notebook_ref = MagicMock()
    notebook_ref.get = AsyncMock(return_value=notebook_doc)
    notebook_ref.set = AsyncMock()

    # Wire up the chain (all sync calls)
    student_ref.collection.return_value.document.return_value = notebook_ref
    course_ref.collection.return_value.document.return_value = student_ref

    # db.collection('courses').document(handle)  → course_ref
    db = MagicMock()
    db.collection.return_value.document.return_value = course_ref

    return db


# ---------------------------------------------------------------------------
# add_student_if_not_exists
# ---------------------------------------------------------------------------

class TestAddStudentIfNotExists:
    async def test_adds_new_student(self):
        db = _make_mock_db(course_exists=True, student_exists=False)
        await add_student_if_not_exists(db, "test-course", "student1", "Alice")
        # Student ref's set() should have been called
        student_ref = db.collection.return_value.document.return_value.collection.return_value.document.return_value
        student_ref.set.assert_called_once()

    async def test_skips_existing_student(self):
        db = _make_mock_db(course_exists=True, student_exists=True)
        await add_student_if_not_exists(db, "test-course", "student1", "Alice")
        student_ref = db.collection.return_value.document.return_value.collection.return_value.document.return_value
        student_ref.set.assert_not_called()

    async def test_raises_on_missing_course(self):
        db = _make_mock_db(course_exists=False)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await add_student_if_not_exists(db, "no-course", "s1", "Bob")
        assert exc_info.value.status_code == 404

    async def test_signature_has_four_params(self):
        """Verify the function accepts exactly (db, course_handle, student_id, student_name)."""
        import inspect
        sig = inspect.signature(add_student_if_not_exists)
        params = list(sig.parameters.keys())
        assert params == ["db", "course_handle", "student_id", "student_name"]


# ---------------------------------------------------------------------------
# add_instructor_notebook_if_not_exists
# ---------------------------------------------------------------------------

class TestAddInstructorNotebook:
    async def test_creates_notebook_doc(self):
        db = _make_mock_db(course_exists=True, student_exists=False)
        # In this function, the "student_ref" position in the chain is actually
        # the notebook_ref (course_ref.collection('Notebooks').document(notebook_id))
        notebook_ref = db.collection.return_value.document.return_value.collection.return_value.document.return_value
        await add_instructor_notebook_if_not_exists(db, "test-course", "hw1")
        notebook_ref.set.assert_called_once()


# ---------------------------------------------------------------------------
# save_rubric
# ---------------------------------------------------------------------------

class TestSaveRubric:
    async def test_calls_set(self):
        db = MagicMock()
        rubric_ref = MagicMock()
        rubric_ref.set = AsyncMock()
        db.collection.return_value.document.return_value.collection.return_value.document.return_value = rubric_ref

        await save_rubric(
            db, "test-course", "hw1",
            max_marks=100.0,
            context={"1": "intro"},
            questions={"1": "Q1"},
            answers={"1": "A1"},
            outputs={"1": ""},
        )
        rubric_ref.set.assert_called_once()
        call_data = rubric_ref.set.call_args[0][0]
        assert call_data["max_marks"] == 100.0
        assert "outputs" in call_data

    async def test_signature_includes_outputs(self):
        """outputs parameter must exist (was added after initial implementation)."""
        import inspect
        sig = inspect.signature(save_rubric)
        assert "outputs" in sig.parameters


# ---------------------------------------------------------------------------
# update_marks
# ---------------------------------------------------------------------------

class TestUpdateMarks:
    async def test_signature_has_correct_params(self):
        """Verify update_marks accepts (db, course_id, student_id, notebook_id, ...)."""
        import inspect
        sig = inspect.signature(update_marks)
        params = list(sig.parameters.keys())
        assert params == [
            "db", "course_id", "student_id", "notebook_id",
            "total_marks", "max_marks", "grader_response",
        ]


# ---------------------------------------------------------------------------
# upload_student_notebook
# ---------------------------------------------------------------------------

class TestUploadStudentNotebook:
    async def test_signature(self):
        import inspect
        sig = inspect.signature(upload_student_notebook)
        params = list(sig.parameters.keys())
        assert params == [
            "db", "course_handle", "student_id", "student_name",
            "notebook_id", "answer_notebook", "answer_hash",
        ]


# ---------------------------------------------------------------------------
# load_course_info_from_db
# ---------------------------------------------------------------------------

class TestLoadCourseInfoFromDb:
    async def test_returns_dict(self):
        db = MagicMock()

        mock_doc = MagicMock()
        mock_doc.id = "test-course"
        mock_doc.to_dict.return_value = {"course_name": "Test"}

        async def _stream():
            yield mock_doc

        db.collection.return_value.stream = _stream

        result = await load_course_info_from_db(db)
        assert isinstance(result, dict)
        assert "test-course" in result
        assert result["test-course"]["course_name"] == "Test"


# ---------------------------------------------------------------------------
# load_notebooks_from_db
# ---------------------------------------------------------------------------

class TestLoadNotebooksFromDb:
    async def test_returns_dict(self):
        db = MagicMock()

        mock_nb = MagicMock()
        mock_nb.id = "hw1"
        mock_nb.to_dict.return_value = {
            "max_marks": 100.0,
            "questions": {},
            "answers": {},
            "outputs": {},
            "last_updated": "some-timestamp",
        }

        async def _stream():
            yield mock_nb

        db.collection.return_value.document.return_value.collection.return_value.stream = _stream

        result = await load_notebooks_from_db(db, "test-course")
        assert "hw1" in result
        # last_updated should be stripped from cache
        assert "last_updated" not in result["hw1"]
