# Future Features

A running list of features intentionally deferred from the current
codebase. Each entry sketches the scope, the reason it's deferred, and a
rough implementation note so future work can pick up cleanly.

## 1. Q&A grading over PDF submissions

**Status:** schema supports it; grading path not yet implemented.

**Today's combinations**

| `assignment_type` | `submission_type` | Status |
|---|---|---|
| `q&a` | `colab` | Implemented (per-question scoring of notebook cells). |
| `report` | `pdf` | Implemented (multimodal holistic scoring of a PDF). |
| `q&a` | `pdf` | **Deferred** — see below. |
| `report` | `colab` | Out of scope (no realistic use case). |

**What it means**

A Q&A assignment whose answers are submitted as a single PDF rather than
as a Colab notebook. The rubric format is unchanged from the existing
Colab-q&a flow (one component-decomposed answer per question, with marks
per component); only the submission format changes.

**Why deferred**

The existing q&a grading loop ([`evaluate`][evaluate], [`score_question`][score_question])
splits the student's submission into per-question answers by parsing
notebook cells with `**Q<n>**` markers. PDFs don't carry that structure,
so the agent has to find each question's answer inside the PDF itself.

**Implementation sketch**

- Add a new helper `score_qa_pdf_question` in `agent_service.py` that
  takes `(rubric_question, rubric_components, pdf_gcs_uri)` and runs the
  scoring agent with the PDF attached as a multimodal `Part` plus a
  prompt instructing the agent to find that question's answer in the PDF
  before grading.
- New dispatcher case in `/grade_assignment`: when the rubric is
  `(assignment_type='q&a', submission_type='pdf')`, iterate questions and
  call the new helper, accumulating marks the same way as q&a + colab.
- Reuse `/ingest_pdf_submissions` as-is for PDF intake (it doesn't depend
  on assignment_type).
- Per-student grader_response uses the same `{qnum_str: {marks, response}}`
  shape as q&a + colab — so `/fetch_grader_response`, `/regrade_answer`,
  `/notify_student_grades`, and the marks/grader-response downloads all
  work unchanged.

**Cost estimate:** moderate. One new scoring helper, one new dispatch
case, no new rubric format. A few hours of implementation + tests.

[evaluate]: ../src/agent_service.py
[score_question]: ../src/agent_service.py

## 2. OCR for handwritten / scanned PDFs

**Status:** not implemented.

**What it means**

Some Q&A assignments are submitted as **scanned handwritten work** (e.g.
math derivations, hand-drawn circuits). Today's PDF flow assumes the PDF
contains machine-readable text: author extraction (Gemini call on the
first few pages of `pypdf`-extracted text) won't pull author names off a
scan, and the multimodal scoring agent — while capable of reading
handwriting — may struggle with low-quality scans, dense math
notation, or schematics drawn freehand.

**Implementation sketch**

- Detect scanned PDFs at ingest: if `pypdf` extracts < some threshold of
  characters per page across the first few pages, treat the PDF as a
  scan.
- Run OCR (Vertex AI Document AI, or Tesseract for local dev) to extract
  text. Use the OCR text for author extraction; **also** keep passing the
  raw PDF as a multimodal `Part` to the scoring agent so it sees the
  original handwriting / diagrams alongside the OCR'd text.
- Store an `ocr_extracted_text` field on the per-PDF tracking doc so we
  don't re-run OCR on regrade.
- Surface an `ocr_used: true` flag in the ingest response so the
  instructor knows which submissions went through OCR (useful for
  spot-checking quality).

**Edge cases to think about**

- Math notation: even good OCR garbles equations. The multimodal model
  will likely outperform OCR text for math-heavy answers — keep both
  signals.
- Author names on a scanned cover page: depending on neatness, fuzzy
  matching against the roster may need a lower threshold or a hybrid
  approach (e.g. fall back to "instructor confirms" UI if low confidence).
- Cost: Document AI is paid per page. Worth a per-course budget setting.

**Cost estimate:** moderate. New OCR module, ingest changes, a couple of
new fields on the tracking doc. Most of the complexity is in tuning
thresholds and handling edge cases (math, low-quality scans).

## 3. Server-side notebook (.ipynb) rubric cell parsing

**Status:** not implemented; instructors use the Colab client's
`ta.upload_rubric()` for notebook rubrics. `/upload_rubric_link` with
`assignment_type='notebook'` (legacy term for `q&a + colab`) returns 501
pointing to the Colab client.

**Why deferred**

The Colab client already does this parsing well, and it's tightly
coupled to the `**Q<n>**` / `##Ans` / `#<pct>%` cell-markup convention.
Re-implementing it server-side is duplicative unless we want
non-Colab-using instructors to be able to author rubrics in a different
tool.

**When to implement**

If users start asking to upload notebooks rendered from VS Code / Jupyter
without going through Colab.

## 4. Auto-merge of @pending.local placeholders into roster matches

**Status:** detection only. `/upload_student_roster` reports placeholder
records whose names fuzzy-match a roster entry, but doesn't merge them.

**What "merge" means**

When a placeholder `Students/{slug}@pending.local` matches a real
roster entry `Students/{email}`:

- Move the placeholder's `Notebooks/*` mirror docs to the real student.
- Update `pdf_submissions/{drive_file_id}.student_ids` arrays to swap
  the placeholder ID for the real email.
- Update `co_authors` lists on every related mirror doc.
- Delete the placeholder record.

**Why deferred**

Each merge touches at least three Firestore documents and needs to be
done atomically (otherwise a student's marks can disappear or get
duplicated). Given that the detection flow already tells the instructor
exactly which placeholders are recoverable, doing the merge by hand in
Firestore is feasible for v1.

**Implementation sketch**

- New `POST /merge_placeholder_student` endpoint accepting
  `(placeholder_id, real_email)`.
- Wrap the moves in a Firestore batched write where possible.
- Surface a "Merge into ..." button next to each detected match in the
  roster upload result panel on the dashboard.

## 5. Cleanup endpoint for orphaned PDF submissions

**Status:** not implemented.

If an instructor deletes / replaces PDFs in the Drive folder, the
corresponding `pdf_submissions/{drive_file_id}` tracking docs and the
GCS-stored PDFs aren't automatically cleaned up. A small admin endpoint
that lists / prunes orphaned tracking docs (e.g. those whose Drive file
no longer exists) would be useful for long-running courses.

---

If you pick up any of these, please update this doc with a status change
or a link to the implementing PR.
