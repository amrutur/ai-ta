"""Tests for PDF-assignment helpers in database.py.

Firestore async client: ``.collection()``/``.document()`` are sync, while
``.get()``/``.set()``/``.stream()`` are async — so we use MagicMock for the
chain and AsyncMock only for the async leaves (matching test_database.py).
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from database import (
    PDF_SUBMISSIONS_SUBCOLLECTION,
    add_placeholder_student,
    get_pdf_submission,
    get_student_directory,
    get_student_pdf_mirror,
    list_pdf_submissions,
    list_placeholder_students,
    save_pdf_rubric,
    update_pdf_submission_grade,
    upsert_pdf_submission,
    upsert_student,
)


def _make_db_with_doc(doc_set=None, doc_get=None, doc_id=None):
    """Build a generic Firestore-shaped mock that resolves any chain of
    ``.collection().document().collection().document()`` calls to a single
    leaf doc reference whose async methods are wired to the supplied mocks.

    Returns ``(db, leaf_ref)`` so the caller can inspect ``leaf_ref.set``
    / ``leaf_ref.get`` calls.
    """
    leaf = MagicMock()
    leaf.set = doc_set or AsyncMock()
    leaf.get = doc_get or AsyncMock()
    if doc_id is not None:
        leaf.id = doc_id

    # collection().document() resolves to a node that itself has .collection
    # and .document callable — same shape as leaf so chains terminate at leaf.
    node = MagicMock()
    node.set = leaf.set
    node.get = leaf.get
    node.collection.return_value = MagicMock()
    node.collection.return_value.document.return_value = leaf
    # Allow arbitrary depth: leaf.collection().document() → leaf again
    leaf.collection.return_value = MagicMock()
    leaf.collection.return_value.document.return_value = leaf
    leaf.collection.return_value.stream = MagicMock()

    db = MagicMock()
    db.collection.return_value = MagicMock()
    db.collection.return_value.document.return_value = node
    return db, leaf, node


# ---------------------------------------------------------------------------
# save_pdf_rubric
# ---------------------------------------------------------------------------


class TestSavePdfRubric:
    @pytest.mark.asyncio
    async def test_writes_pdf_assignment_type_and_fields(self):
        db, leaf, _ = _make_db_with_doc()

        await save_pdf_rubric(
            db, "iisc-2025-cp260", "lab1",
            max_marks=50.0,
            problem_statement="Build a TCP server",
            rubric_text="Correctness 30, code quality 20",
            sample_graded_response="Graded sample text",
        )

        leaf.set.assert_awaited_once()
        payload = leaf.set.call_args.args[0]
        assert payload['assignment_type'] == 'pdf'
        assert payload['max_marks'] == 50.0
        assert payload['problem_statement'] == "Build a TCP server"
        assert payload['rubric_text'] == "Correctness 30, code quality 20"
        assert payload['sample_graded_response'] == "Graded sample text"
        assert payload['isactive_eval'] is True

    @pytest.mark.asyncio
    async def test_blank_sample_graded_response_normalized(self):
        db, leaf, _ = _make_db_with_doc()
        await save_pdf_rubric(
            db, "ch", "nb", 50.0,
            problem_statement="x", rubric_text="y", sample_graded_response=None,
        )
        payload = leaf.set.call_args.args[0]
        assert payload['sample_graded_response'] == ""

    @pytest.mark.asyncio
    async def test_rubric_pdf_uri_persisted(self):
        db, leaf, _ = _make_db_with_doc()
        await save_pdf_rubric(
            db, "ch", "nb", 50.0,
            rubric_pdf_uri="gs://bucket/ch/rubrics/nb.pdf",
        )
        payload = leaf.set.call_args.args[0]
        assert payload['rubric_pdf_uri'] == "gs://bucket/ch/rubrics/nb.pdf"
        # When the rubric is a PDF, text fields default to empty strings
        # (the model gets the PDF as a Part, so text is just a fallback).
        assert payload['problem_statement'] == ""
        assert payload['rubric_text'] == ""


# ---------------------------------------------------------------------------
# get_pdf_submission
# ---------------------------------------------------------------------------


class TestGetPdfSubmission:
    @pytest.mark.asyncio
    async def test_returns_dict_when_exists(self):
        snap = MagicMock()
        snap.exists = True
        snap.to_dict.return_value = {"drive_file_id": "X", "gcs_uri": "gs://..."}
        db, leaf, _ = _make_db_with_doc(doc_get=AsyncMock(return_value=snap))

        result = await get_pdf_submission(db, "ch", "nb", "X")
        assert result == {"drive_file_id": "X", "gcs_uri": "gs://..."}

    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self):
        snap = MagicMock(); snap.exists = False
        db, leaf, _ = _make_db_with_doc(doc_get=AsyncMock(return_value=snap))
        assert await get_pdf_submission(db, "ch", "nb", "X") is None


# ---------------------------------------------------------------------------
# list_pdf_submissions
# ---------------------------------------------------------------------------


class TestListPdfSubmissions:
    @pytest.mark.asyncio
    async def test_returns_all_docs_with_id(self):
        d1 = MagicMock(); d1.id = "fid_a"; d1.to_dict.return_value = {"gcs_uri": "gs://a"}
        d2 = MagicMock(); d2.id = "fid_b"; d2.to_dict.return_value = {"gcs_uri": "gs://b"}

        async def gen():
            for d in (d1, d2):
                yield d

        db, _, _ = _make_db_with_doc()
        # Walk the chain to the deepest collection() and stub stream.
        # courses → ch → Notebooks → nb → pdf_submissions.stream()
        nb_node = db.collection.return_value.document.return_value  # courses/ch
        notebooks_coll = nb_node.collection.return_value           # Notebooks
        nb_doc = notebooks_coll.document.return_value              # Notebooks/nb
        pdfs_coll = nb_doc.collection.return_value                 # pdf_submissions
        pdfs_coll.stream = MagicMock(return_value=gen())

        results = await list_pdf_submissions(db, "ch", "nb")
        assert len(results) == 2
        assert {r['drive_file_id'] for r in results} == {"fid_a", "fid_b"}


# ---------------------------------------------------------------------------
# upsert_pdf_submission
# ---------------------------------------------------------------------------


class TestUpsertPdfSubmission:
    @pytest.mark.asyncio
    async def test_writes_tracking_doc_and_mirror_docs(self):
        # Tracking-doc ref:
        #   courses → ch → Notebooks → nb → pdf_submissions → drive_id
        # Mirror docs:
        #   courses → ch → Students → sid → Notebooks → nb
        # Both chains start with `db.collection.return_value.document.return_value`
        # (i.e. courses/ch). We capture every `.set` call across the chain.

        all_set_calls = []

        def make_set():
            mock = AsyncMock(side_effect=lambda payload, **kw: all_set_calls.append(payload))
            return mock

        # We rebuild the shared chain so any .set anywhere shares one recorder.
        leaf_set = make_set()

        # courses/ch
        courses_doc = MagicMock(); courses_doc.set = leaf_set
        # courses/ch/Notebooks/nb (used by tracking write at depth +2)
        nb_doc = MagicMock(); nb_doc.set = leaf_set
        # tracking pdf_submissions/drive_id
        pdf_doc = MagicMock(); pdf_doc.set = leaf_set
        # courses/ch/Students/sid
        student_doc = MagicMock(); student_doc.set = leaf_set
        # courses/ch/Students/sid/Notebooks/nb
        mirror_doc = MagicMock(); mirror_doc.set = leaf_set

        # Wire chain
        notebooks_coll = MagicMock()
        notebooks_coll.document.return_value = nb_doc
        nb_doc.collection.return_value = MagicMock()
        nb_doc.collection.return_value.document.return_value = pdf_doc

        students_coll = MagicMock()
        students_coll.document.return_value = student_doc
        student_doc.collection.return_value = MagicMock()
        student_doc.collection.return_value.document.return_value = mirror_doc

        # First .collection on the course doc returns Notebooks for the tracking write
        # AND Students for the mirror write — use side_effect to differentiate by name.
        def courses_doc_collection(name):
            return notebooks_coll if name == 'Notebooks' else students_coll
        courses_doc.collection = MagicMock(side_effect=courses_doc_collection)

        db = MagicMock()
        db.collection.return_value = MagicMock()
        db.collection.return_value.document.return_value = courses_doc

        await upsert_pdf_submission(
            db, "ch", "nb",
            drive_file_id="DRIVE_ID",
            drive_modified_time="2026-04-30T10:00:00Z",
            gcs_uri="gs://bucket/ch/submissions/nb/DRIVE_ID.pdf",
            original_filename="alice_bob_lab1.pdf",
            extracted_authors=["Alice Smith", "Bob Jones"],
            student_ids=["alice@iisc.ac.in", "bob@iisc.ac.in"],
        )

        # 1 tracking + 2 mirrors = 3 .set calls
        assert len(all_set_calls) == 3

        tracking_payload = all_set_calls[0]
        assert tracking_payload['drive_file_id'] == "DRIVE_ID"
        assert tracking_payload['drive_modified_time'] == "2026-04-30T10:00:00Z"
        assert tracking_payload['extracted_authors'] == ["Alice Smith", "Bob Jones"]
        assert tracking_payload['student_ids'] == ["alice@iisc.ac.in", "bob@iisc.ac.in"]

        mirror_alice = all_set_calls[1]
        assert mirror_alice['assignment_type'] == 'pdf'
        assert mirror_alice['drive_file_id'] == "DRIVE_ID"
        assert mirror_alice['gcs_uri'].startswith("gs://")
        assert mirror_alice['co_authors'] == ["bob@iisc.ac.in"]

        mirror_bob = all_set_calls[2]
        assert mirror_bob['co_authors'] == ["alice@iisc.ac.in"]


# ---------------------------------------------------------------------------
# update_pdf_submission_grade
# ---------------------------------------------------------------------------


class TestUpdatePdfSubmissionGrade:
    @pytest.mark.asyncio
    async def test_writes_grade_to_tracking_and_mirror_docs(self):
        all_set_calls = []
        leaf_set = AsyncMock(side_effect=lambda payload, **kw: all_set_calls.append(payload))

        # Same shared-leaf trick as upsert test.
        courses_doc = MagicMock(); courses_doc.set = leaf_set
        nb_doc = MagicMock(); nb_doc.set = leaf_set
        pdf_doc = MagicMock(); pdf_doc.set = leaf_set
        student_doc = MagicMock(); student_doc.set = leaf_set
        mirror_doc = MagicMock(); mirror_doc.set = leaf_set

        notebooks_coll = MagicMock()
        notebooks_coll.document.return_value = nb_doc
        nb_doc.collection.return_value = MagicMock()
        nb_doc.collection.return_value.document.return_value = pdf_doc

        students_coll = MagicMock()
        students_coll.document.return_value = student_doc
        student_doc.collection.return_value = MagicMock()
        student_doc.collection.return_value.document.return_value = mirror_doc

        courses_doc.collection = MagicMock(
            side_effect=lambda name: notebooks_coll if name == 'Notebooks' else students_coll,
        )

        db = MagicMock()
        db.collection.return_value = MagicMock()
        db.collection.return_value.document.return_value = courses_doc

        await update_pdf_submission_grade(
            db, "ch", "nb",
            drive_file_id="DRIVE_ID",
            student_ids=["a@x.com", "b@x.com"],
            total_marks=42.0,
            max_marks=50.0,
            grader_response={"overall": {"marks": 42.0, "response": "good"}},
        )

        # 1 tracking + 2 mirrors = 3 set calls
        assert len(all_set_calls) == 3
        for payload in all_set_calls:
            assert payload['total_marks'] == 42.0
            assert payload['max_marks'] == 50.0
            assert payload['grader_response']['overall']['marks'] == 42.0


# ---------------------------------------------------------------------------
# add_placeholder_student
# ---------------------------------------------------------------------------


class TestAddPlaceholderStudent:
    @pytest.mark.asyncio
    async def test_creates_when_missing(self):
        course_snap = MagicMock(); course_snap.exists = True
        student_snap = MagicMock(); student_snap.exists = False

        course_doc = MagicMock()
        course_doc.get = AsyncMock(return_value=course_snap)

        student_doc = MagicMock()
        student_doc.get = AsyncMock(return_value=student_snap)
        student_doc.set = AsyncMock()

        students_coll = MagicMock()
        students_coll.document.return_value = student_doc
        course_doc.collection.return_value = students_coll

        db = MagicMock()
        db.collection.return_value.document.return_value = course_doc

        await add_placeholder_student(db, "ch", "jane@pending.local", "Jane Doe", "DRIVE_ID")

        student_doc.set.assert_awaited_once()
        payload = student_doc.set.call_args.args[0]
        assert payload['name'] == "Jane Doe"
        assert payload['pending_review'] is True
        assert payload['initialized'] is False
        assert payload['created_from_drive_file_id'] == "DRIVE_ID"

    @pytest.mark.asyncio
    async def test_no_op_if_exists(self):
        course_snap = MagicMock(); course_snap.exists = True
        student_snap = MagicMock(); student_snap.exists = True

        course_doc = MagicMock()
        course_doc.get = AsyncMock(return_value=course_snap)
        student_doc = MagicMock()
        student_doc.get = AsyncMock(return_value=student_snap)
        student_doc.set = AsyncMock()

        students_coll = MagicMock()
        students_coll.document.return_value = student_doc
        course_doc.collection.return_value = students_coll

        db = MagicMock()
        db.collection.return_value.document.return_value = course_doc

        await add_placeholder_student(db, "ch", "jane@pending.local", "Jane Doe", "DRIVE_ID")
        student_doc.set.assert_not_called()


# ---------------------------------------------------------------------------
# get_student_directory
# ---------------------------------------------------------------------------


class TestGetStudentDirectory:
    @pytest.mark.asyncio
    async def test_returns_id_to_name_map(self):
        d1 = MagicMock(); d1.id = "alice@iisc.ac.in"; d1.to_dict.return_value = {"name": "Alice"}
        d2 = MagicMock(); d2.id = "bob@iisc.ac.in"; d2.to_dict.return_value = {"name": "Bob"}
        d3 = MagicMock(); d3.id = "noname@iisc.ac.in"; d3.to_dict.return_value = {}

        async def gen():
            for d in (d1, d2, d3):
                yield d

        students_coll = MagicMock()
        students_coll.stream = MagicMock(return_value=gen())

        course_doc = MagicMock()
        course_doc.collection.return_value = students_coll

        db = MagicMock()
        db.collection.return_value.document.return_value = course_doc

        result = await get_student_directory(db, "ch")
        assert result == {
            "alice@iisc.ac.in": "Alice",
            "bob@iisc.ac.in": "Bob",
            "noname@iisc.ac.in": "",
        }


class TestGetStudentPdfMirror:
    @pytest.mark.asyncio
    async def test_returns_dict_when_exists(self):
        snap = MagicMock(); snap.exists = True
        snap.to_dict.return_value = {"drive_file_id": "X"}
        db, _, _ = _make_db_with_doc(doc_get=AsyncMock(return_value=snap))
        result = await get_student_pdf_mirror(db, "ch", "alice@x.com", "nb")
        assert result == {"drive_file_id": "X"}

    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self):
        snap = MagicMock(); snap.exists = False
        db, _, _ = _make_db_with_doc(doc_get=AsyncMock(return_value=snap))
        assert await get_student_pdf_mirror(db, "ch", "alice@x.com", "nb") is None


class TestUpsertStudent:
    @pytest.mark.asyncio
    async def test_added_when_new(self):
        course_snap = MagicMock(); course_snap.exists = True
        student_snap = MagicMock(); student_snap.exists = False

        course_doc = MagicMock()
        course_doc.get = AsyncMock(return_value=course_snap)
        student_doc = MagicMock()
        student_doc.get = AsyncMock(return_value=student_snap)
        student_doc.set = AsyncMock()

        students_coll = MagicMock()
        students_coll.document.return_value = student_doc
        course_doc.collection.return_value = students_coll

        db = MagicMock()
        db.collection.return_value.document.return_value = course_doc

        result = await upsert_student(db, "ch", "alice@x.com", "Alice Smith", roll_no="42")
        assert result == "added"
        student_doc.set.assert_awaited_once()
        payload = student_doc.set.call_args.args[0]
        assert payload['name'] == "Alice Smith"
        assert payload['initialized'] is True
        assert payload['roll_no'] == "42"

    @pytest.mark.asyncio
    async def test_updated_when_exists_uses_merge(self):
        course_snap = MagicMock(); course_snap.exists = True
        student_snap = MagicMock(); student_snap.exists = True

        course_doc = MagicMock()
        course_doc.get = AsyncMock(return_value=course_snap)
        student_doc = MagicMock()
        student_doc.get = AsyncMock(return_value=student_snap)
        student_doc.set = AsyncMock()

        students_coll = MagicMock()
        students_coll.document.return_value = student_doc
        course_doc.collection.return_value = students_coll

        db = MagicMock()
        db.collection.return_value.document.return_value = course_doc

        result = await upsert_student(db, "ch", "alice@x.com", "Alice Smith")
        assert result == "updated"
        # Existing student → merge=True so we don't clobber created_at, etc.
        kwargs = student_doc.set.call_args.kwargs
        assert kwargs.get('merge') is True

    @pytest.mark.asyncio
    async def test_omits_roll_no_when_blank(self):
        course_snap = MagicMock(); course_snap.exists = True
        student_snap = MagicMock(); student_snap.exists = False
        course_doc = MagicMock()
        course_doc.get = AsyncMock(return_value=course_snap)
        student_doc = MagicMock()
        student_doc.get = AsyncMock(return_value=student_snap)
        student_doc.set = AsyncMock()
        students_coll = MagicMock()
        students_coll.document.return_value = student_doc
        course_doc.collection.return_value = students_coll
        db = MagicMock()
        db.collection.return_value.document.return_value = course_doc

        await upsert_student(db, "ch", "alice@x.com", "Alice", roll_no=None)
        payload = student_doc.set.call_args.args[0]
        assert 'roll_no' not in payload


class TestListPlaceholderStudents:
    @pytest.mark.asyncio
    async def test_filters_to_pending_local_only(self):
        d1 = MagicMock(); d1.id = "alice@iisc.ac.in"; d1.to_dict.return_value = {"name": "Alice"}
        d2 = MagicMock(); d2.id = "jane-doe@pending.local"; d2.to_dict.return_value = {"name": "Jane Doe"}
        d3 = MagicMock(); d3.id = "j-r-r-tolkien@pending.local"; d3.to_dict.return_value = {"name": "J. R. R. Tolkien"}

        async def gen():
            for d in (d1, d2, d3):
                yield d

        students_coll = MagicMock()
        students_coll.stream = MagicMock(return_value=gen())
        course_doc = MagicMock()
        course_doc.collection.return_value = students_coll
        db = MagicMock()
        db.collection.return_value.document.return_value = course_doc

        result = await list_placeholder_students(db, "ch")
        assert set(result.keys()) == {"jane-doe@pending.local", "j-r-r-tolkien@pending.local"}
        assert result["jane-doe@pending.local"]["name"] == "Jane Doe"


def test_subcollection_constant():
    """If this name changes, ingest + grading must change in lockstep."""
    assert PDF_SUBMISSIONS_SUBCOLLECTION == "pdf_submissions"
