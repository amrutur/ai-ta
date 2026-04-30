# AI Teaching Assistant Platform

An AI-powered teaching and grading assistant for graduate courses. The system provides automated feedback, grading, and personalized tutoring for students working on assignments in Google Colab notebooks.

## Overview

This repository contains the **server-side API** for the AI teaching assistant and grading system. It works in conjunction with the [colab_grading_client](https://github.com/amrutur/colab_grading_client) Python package, which provides client-side functions for students to interact with the grading assistant directly from their Google Colab notebooks.

### System Architecture

```
┌─────────────────────────┐
│  Google Colab Notebook  │  ← Student / Instructor workspace
│  (colab_grading_client) │
└───────────┬─────────────┘
            │ HTTP/JSON (JWT auth)
            ↓
┌─────────────────────────┐
│  FastAPI Server         │  ← This repository
│  (src/api_server.py)    │
└───┬───────┬─────────┬───┘
    │       │         │
    ↓       ↓         ↓
┌───────┐ ┌────────┐ ┌─────────────┐
│Gemini │ │Firestr │ │Google Cloud │
│2.5 Pro│ │Database│ │Storage (GCS)│
└───────┘ └────────┘ └─────────────┘
```

### Firestore Database Schema

```
firestore/
├── courses/ (collection)
│   └── {course_handle}/ (document, e.g. "iisc-2025-26-e1-254")
│       ├── course_name, course_number, academic_year, institution
│       ├── course_id, term_id, institution_id
│       ├── instructor_email, instructor_gmail, instructor_name
│       ├── ta_name, ta_email, ta_gmail (optional)
│       ├── start_date, end_date, created_at, last_updated
│       ├── folder_name (GCS path)
│       ├── isactive_tutor (feature flag — tutoring toggle)
│       ├── student_rate_limit, student_rate_limit_window (per-student rate limiting)
│       ├── ai_model, instructor_assist_prompt, student_assist_prompt, scoring_assist_prompt (course-specific AI config)
│       │
│       ├── Notebooks/ (subcollection — rubrics & instructor content)
│       │   └── {notebook_id}/
│       │       ├── assignment_type ("q&a" | "report") — rubric shape
│       │       ├── submission_type ("colab" | "pdf") — submission format
│       │       │     (legacy assignment_type values "notebook" / "pdf" are
│       │       │      auto-mapped on read: "notebook"→q&a+colab, "pdf"→report+pdf)
│       │       ├── max_marks, isactive_eval
│       │       ├── (q&a) context, questions, answers, outputs
│       │       ├── (report) problem_statement, rubric_text, sample_graded_response,
│       │       │            rubric_pdf_uri (gs:// path, optional)
│       │       ├── rag_chunks/ (subcollection — vector embeddings)
│       │       │   └── {auto-id}/ (source_file, chunk_index, text, embedding)
│       │       └── pdf_submissions/ (subcollection — per-PDF tracking, when submission_type=pdf)
│       │           └── {drive_file_id}/
│       │               ├── drive_modified_time, gcs_uri, original_filename
│       │               ├── extracted_authors, student_ids, ingested_at
│       │               ├── total_marks, max_marks, grader_response, graded_at
│       │
│       └── Students/ (subcollection)
│           └── {student_email}/
│               ├── name, initialized, created_at
│               ├── (placeholder records from PDF ingest) pending_review,
│               │   created_from_drive_file_id
│               └── Notebooks/ (subcollection — submissions & grades)
│                   └── {notebook_id}/
│                       ├── (notebook mode) answer_notebook, answer_hash, submitted_at
│                       ├── (pdf mode) assignment_type, drive_file_id, gcs_uri,
│                       │   co_authors, original_filename, submitted_at
│                       ├── total_marks, max_marks, graded_at
│                       ├── grader_response, graded_json
│                       ├── email_notified_at
│
│       ├── student_sessions/ (subcollection — student-agent conversation history)
│       │   └── {app_name}/users/{user_email}/sessions/{session_id}/events/...
│       │
│       └── instructor_sessions/ (subcollection — instructor-agent conversation history)
│           └── {app_name}/users/{user_email}/sessions/{session_id}/events/...
```

## Key Features

### For Students
- **Interactive Tutoring**: Get AI-powered feedback and hints on assignment questions
- **Guided Learning**: Progressive hints grounded in course materials and rubrics
- **Automated Grading**: Submit notebooks for automated evaluation with detailed feedback
- **Google OAuth Authentication**: Secure login using Google accounts

### For Instructors
- **Instructor AI Assistant**: Verify content, create questions, review rubrics, and get suggestions
- **Rubric Management**: Upload scoring rubrics to guide the AI grading agent (notebook or PDF mode)
- **PDF Assignments**: Ingest student-submitted PDF reports from a shared Drive folder, grade them holistically via Gemini multimodal (figures/tables/plots are visible to the model), and regrade with optional student contention. See [PDF Assignment Mode](#pdf-assignment-mode) below.
- **Course Materials Upload**: Drag-and-drop browser interface for uploading PDFs to GCS
- **RAG Index Building**: Build vector search indices over uploaded course materials
- **Tutor & Eval Controls**: Dynamically enable/disable the tutoring endpoint per course and evaluation per notebook
- **Per-Student Rate Limiting**: Configurable sliding-window rate limits per course to manage AI model usage
- **Batch Grading**: Evaluate multiple student submissions via `/grade_notebook` (supports regrading with `do_regrade`)
- **Per-Question Regrading**: Regrade individual questions with optional student contention via `/regrade_answer`
- **Course File Management**: List uploaded course files in GCS via `/list_course_files`
- **Course-Specific AI Configuration**: Configure AI model and custom prompts per course via Firestore
- **Email Notifications**: Notify students when grades are ready via Gmail SMTP
- **Grade Management**: View student marks lists and detailed grading feedback

### Technical Features
- **Google ADK Integration**: Built on Google's Agent Development Kit (ADK v1.26.0)
- **Three Specialized AI Agents**:
  - **Instructor Assistant Agent**: Helps instructors with content review, question creation, and rubric design
  - **Student Tutor Agent**: Provides interactive tutoring and feedback to students
  - **Scoring Agent**: Evaluates submissions against rubrics with component-based scoring
- **RAG Pipeline**: Retrieval-Augmented Generation using Vertex AI embeddings (`text-embedding-004`) and Firestore vector search for grounding responses in course materials
- **Custom Firestore Session Service**: Async session persistence with app-level and user-level state, event subcollections, isolated per course
- **Course-Specific AI Configuration**: Per-course AI model selection and custom agent prompts stored in Firestore
- **Dual Authentication**: OAuth 2.0 sessions (browser) and JWT tokens (API/Colab clients)
- **Per-Student Rate Limiting**: In-memory sliding-window rate limiter configurable per course, with instructor bypass and live config updates
- **GCS Signed URL Uploads**: Direct browser-to-GCS uploads via signed URLs (bypasses Cloud Run size limits)
- **Gmail SMTP Integration**: Email delivery for grade notifications
- **Cloud Run Deployment**: Scalable, serverless deployment on Google Cloud

## Prerequisites

### For Development
- Python 3.11+
- Google Cloud Project with enabled APIs:
  - Firestore
  - Secret Manager
  - Cloud Storage
  - Vertex AI
  - Cloud Run (for production)
- OAuth 2.0 credentials
- Gmail app password stored as `EMAIL_KEY` in Secret Manager (for email notifications)

### For Students
- Google Colab account
- Installation of `colab_grading_client` package

## Installation

### Server Setup (This Repository)

1. **Clone the repository**
   ```bash
   git clone https://github.com/amrutur/ai-ta.git
   cd ai-ta
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**

   Copy `.env.example` to `.env` and fill in the values:
   ```bash
   cp .env.example .env
   ```

   See [Configuration](#configuration) for details on each variable.

4. **Configure Google Cloud Secrets**

   Store sensitive credentials in Secret Manager:
   - OAuth client ID and secret
   - Session signing key
   - Firestore service account private key and key ID
   - Gmail app password (`EMAIL_KEY`) for email notifications (optional)
   - Gemini API key (optional — uses Vertex AI service account auth if not set)

5. **Run the development server**
   ```bash
   python src/api_server.py
   ```

   The server will start at `http://localhost:8080`

### Client Setup (For Students)

Students install the client package in their Colab notebooks:

```python
!pip install colab-grading-client
```

## Usage

### For Students (in Google Colab)

1. **Setup** — In the first code cell, configure the server URL, course details, and import the client:
   ```python
   AI_TA_URL = "https://ai-ta-326056429620.asia-south1.run.app/"
   course_id = "cp260"
   notebook_id = "HW3"
   institution_id = "IISc"
   term_id = "2025-26"

   !pip install colab-grading-client
   import colab_grading_client as ta
   ```

2. **Login** — Authenticate with Google in the next code cell:
   ```python
   session = ta.authenticate(AI_TA_URL)
   ```

3. **Question cells** — Each question is a **text cell** that starts with:
   ```
   **Q<qnum>: <marks> **
   ```
   For example: `**Q1: 10 **`

4. **Answer cells** — The answer cell (code or text) follows the question and starts with:
   ```
   ##Ans
   ```

5. **Chat cells** — After the answer cell, add a **text cell** for chatting with the TA:
   ```
   **Chat with TA**
   <your questions for the TA>
   ```

6. **Get TA help** — After the chat cell, add a **code cell** to invoke the teaching assistant:
   ```python
   ta.show_teaching_assist_button(session, AI_TA_URL, <qnum>, notebook_id, institution_id, term_id, course_id)
   ```

### For Instructors

1. **Login to the system**

   Navigate to `https://your-server-url.run.app/` — this is the **instructor dashboard**: a single-page UI with a course picker and buttons for every instructor service (rubric upload, PDF ingest/grade/regrade, batch notebook grading, marks list, grader response, email notifications, course config, rate-limit status, RAG rebuild). All the forms hit the same JSON / multipart endpoints documented below.

   Platform admins use `/admin` to access `/docs`. Colab clients still get a JWT via `/login` → `/get_auth_token`.

   Access is gated by your email matching one of `instructor_email`, `instructor_gmail`, `ta_email`, or `ta_gmail` on the course document. TAs have full instructor scope in this version.

2. **Upload course materials**

   Navigate to `https://your-server-url.run.app/upload_course_materials` to access the drag-and-drop upload interface for PDF course materials.

3. **Build the RAG index**

   After uploading materials, build the vector search index so the AI agents can reference them:
   ```
   POST /build_course_index
   { "course_id": "...", "term_id": "...", "institution_id": "..." }
   ```

4. **Upload a rubric**

   Use the `/upload_rubric` endpoint to save question rubrics (questions, answers, marks, context) for a notebook. See below and examples folder for more info on developing colab notebooks as homeworks or quizzes

5. **Enable tutoring and evaluation**
   ```
   POST /enable_tutor   — allow students to use /assist
   POST /enable_eval    — allow students to submit for grading via /eval
   ```

6. **Configure per-student rate limiting** (optional)

   Limit how many AI requests each student can make per time window:
   ```
   POST /update_course_config
   {
     "institution_id": "...", "term_id": "...", "course_id": "...",
     "student_rate_limit": 20,
     "student_rate_limit_window": 3600
   }
   ```
   - `student_rate_limit`: Max AI requests per student per window (set to `0` to disable)
   - `student_rate_limit_window`: Window size in seconds (60–86400, default: 3600)
   - Instructors and admins are not affected by rate limits
   - One `/eval` submission counts as one request regardless of question count
   - Monitor usage with `POST /rate_limit_status`

7. **View student grades**
   ```python
   # In a Colab notebook with instructor credentials
   import colab_grading_client as cgc
   grades = cgc.fetch_marks_list(...)
   ```

8. **Send grade notifications**
   ```python
   cgc.notify_student_grades(...)
   ```

9. **Developing homework/quiz colab notebooks**

Set the AI-TA-URL variable to point to your AI-TA server.

Set the course_id, term_id, institution_id to be appropriate strings so that it can uniquely identify this course in your institution. The default values are for IISc.

Each question cell starts with the line:

star star Qnum: marks star star

which indicates the question number and the marks for this question

The question text will usually be a single question cell.

After the question cell, have one text cell with the line

hash hash Ans (see example below)

This can be followed by one or more answer cells - which can be code or text cells.

If the cell with the answer tag gets deleted, the client will be unable to get hold of the answer cells to send to the grader.

While you are developing your quiz notebook, you can follow the answer cell with a text cell starting with the line

star star Chat with TA

and include your dialogue for the TA to get their inputs. (for example, check this question and answer)

Following that will be the cell to make a call to the TA with the line, ta.show_teaching_assist_button. The second parameter to this function is the question number - which you need to change to match with the question number.

For homework notebooks, you can have multiple cells either in the beginning or in between question-answer cells - which can serve to provide additional context/learning material. These
are for the students to study and understand and could be used to help with the for follow on questions. The context is used auto-regressively by the tutor to provide guidance to the student on any question. i.e. the context from the beginning of the notebook uptill the question is used. The tutor also uses its own background knowledge as well as any RAG material.

**IMPORTANT NOTE TO INSTRUCTORS**

1. Once you are done developing the notebook, you can upload this notebook as a rubric using the ta.upload_rubric function (in the second to last cell of this notebook)

2. Make a copy of this notebook and in the copy

a) remove the appropriate answer content (for example pieces of code, where you want the student to provide answers), or text pieces or entire text in the answer cells where you want the stdt to provide answers.

b) If you are releasing this as a homework, you can keep the chat with TA cell  as it will help the student to interact with the TA and arrive at an answer.

c) for a notebook as a homework, you can choose to not allocate any marks to a question - in which case it will default to 10 marks.

d) you can choose to allocate marks to various answer components by following the format below (each component is preceded with a hash percentage-value% for that component.)

e) if you are releasing as a quiz, you can delete the chat with ta cells.

f) delete the cell with the ta.upload_rubric

g) keep the cell with ta.submit_eval_button.

h) you can delete this preamble for the student.

3. share the link of the copied/edited quiz/homework notebook with the students. they need to make their own copy and work on that.

4. authentication: the system relies on Single sign on authentication - either with gmail or your institutional email system - provided they offer a SSO service which google can connect to.


### PDF Assignment Mode

For courses where students submit PDF reports (e.g. lab write-ups, project reports) instead of working in Colab notebooks, the platform supports a PDF-assignment grading flow that reuses the same course/student/grade data model.

> **Rubric type model.** Each rubric carries two orthogonal flags:
>
> - `assignment_type`: `"q&a"` (per-question scoring with component-decomposed rubric answers) or `"report"` (holistic scoring of a report/lab against a single rubric body).
> - `submission_type`: `"colab"` (notebook cells parsed for per-question answers) or `"pdf"` (a single PDF report passed to the agent as a multimodal Part).
>
> The supported combinations today: `q&a + colab` (the original notebook flow) and `report + pdf` (this section). The `q&a + pdf` combination is captured in [docs/future_features.md](./docs/future_features.md). Legacy `assignment_type` values `"notebook"` and `"pdf"` are still accepted on writes and auto-mapped to the new pair on reads.

**1. Upload a PDF rubric** — `POST /upload_rubric` with `assignment_type: "pdf"`. The PDF rubric is holistic (one rubric per entire report), not per-question:

```json
{
  "institution_id": "iisc",
  "term_id": "2025-26",
  "course_id": "cp260",
  "notebook_id": "lab1",
  "max_marks": 50.0,
  "assignment_type": "pdf",
  "problem_statement": "Build a single-threaded TCP echo server in C and demonstrate it handling N clients...",
  "rubric_text": "Correctness 30 marks (10 for protocol handling, 10 for concurrency, 10 for error paths). Code quality 10 marks. Report writeup 10 marks.",
  "sample_graded_response": "Optional: paste a previously-graded response here as a one-shot example for the scoring agent."
}
```

**2. Share the Drive folder with the service account** — Students submit their PDFs (e.g. via Google Form file uploads or by dropping files into a shared Drive folder). The instructor takes the resulting Drive folder, right-clicks → Share, and grants **Viewer** access to the platform service account email (the `client_email` in your service-account JSON / `SERVICE_ACCOUNT_EMAIL` env var).

**3. Ingest** — `POST /ingest_pdf_submissions`:

```json
{
  "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
  "notebook_id": "lab1",
  "drive_folder_url": "https://drive.google.com/drive/folders/<FOLDER_ID>"
}
```

For each PDF in the folder the server:
- Skips files that are already ingested with the same `modifiedTime` (idempotent re-runs).
- Downloads the PDF, uploads it to GCS at `{bucket}/{course_handle}/submissions/{notebook_id}/{drive_file_id}.pdf`.
- Extracts author names from the cover page via Gemini and fuzzy-matches them against enrolled students.
- For unmatched names, creates a placeholder student record at `Students/{slug}@pending.local` with `pending_review: true`. The instructor can clean these up later (e.g. merge or delete in Firestore).
- Joint submissions (multiple authors on one PDF) get one mirror record per author, all linked to the same `drive_file_id` and `co_authors` list.

The response is `{ingested: [...], skipped: [...], failed: [...]}` so the instructor can spot any oversize / inaccessible files.

**4. Grade** — `POST /grade_pdf_assignment` streams ndjson progress while running the scoring agent on every ingested PDF concurrently:

```json
{ "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
  "notebook_id": "lab1", "do_regrade": false }
```

The scoring agent receives the PDF as a multimodal Vertex AI input (via `gs://` URI), so figures, tables, and plots are considered alongside the rubric, problem statement, sample response, and RAG-retrieved course material. The grade is written to the per-PDF tracking doc and to every co-author's mirror doc — so `/fetch_marks_list`, `/fetch_grader_response`, and `/notify_student_grades` work unchanged.

Idempotency: submissions with `graded_at >= drive_modified_time` are skipped unless `do_regrade=true`.

**5. Regrade individual submissions** — `POST /regrade_pdf_submission` for cases where a student contests their grade:

```json
{ "institution_id": "iisc", "term_id": "2025-26", "course_id": "cp260",
  "notebook_id": "lab1", "student_id": "alice@iisc.ac.in",
  "do_regrade": true,
  "student_contends": "I implemented retry logic on lines 80-95 — please re-check section 3 of my report."
}
```

The previous response and the contention text are appended to the prompt; the audit trail is preserved in the new `grader_response`.

**Limits & notes**
- Maximum PDF size during ingest is 50 MB. Larger files are reported in `failed` rather than silently truncated.
- OneDrive folders are not currently supported — only Google Drive folders shared with the service account.
- The PDF rubric is holistic. If you need per-question grading on a PDF report, structure your `rubric_text` as enumerated criteria; the agent will reason about each criterion.


## API Endpoints

API endpoints can be tested by connecting to `https://AI_tutor_server_url/docs`

### Authentication

The API supports two authentication methods:

1. **Session-based (Browser/OAuth)**: For web browsers — initiate via `/login`
2. **JWT Token-based**: For API clients like Colab notebooks — obtain via `/get_auth_token` or `/colab_auth`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login` | GET | Initiate Google OAuth login flow |
| `/callback` | GET | OAuth callback handler |
| `/get_auth_token` | GET | Get JWT token after OAuth login (browser session required) |
| `/colab_auth` | POST | Authenticate Colab notebook via Google access token |
| `/whoami` | GET | Return current user info |
| `/logout` | GET | Clear user session |

### Student Endpoints

| Endpoint | Method | Request Model | Description |
|----------|--------|---------------|-------------|
| `/assist` | POST | `AssistRequest` | Get AI tutor feedback on a question (requires tutor enabled) |
| `/grade` | POST | `GradeRequest` | Grade a single question-answer; returns marks and feedback |
| `/eval` | POST | `EvalRequest` | Evaluate an entire notebook submission (requires eval enabled) |

### Instructor Endpoints (Requires Instructor Authentication)

| Endpoint | Method | Request Model | Description |
|----------|--------|---------------|-------------|
| `/enable_tutor` | POST | `TutorInteractionRequest` | Enable the `/assist` endpoint for students |
| `/disable_tutor` | POST | `TutorInteractionRequest` | Disable the `/assist` endpoint for students |
| `/enable_eval` | POST | `TutorInteractionRequest` | Enable the `/eval` endpoint for students |
| `/disable_eval` | POST | `TutorInteractionRequest` | Disable the `/eval` endpoint |
| `/upload_rubric` | POST | `AddRubricRequest` | Upload rubric (questions, answers, marks, context) |
| `/fetch_marks_list` | POST | `FetchMarksListRequest` | Fetch all student marks for a notebook |
| `/fetch_grader_response` | POST | `FetchGradedRequest` | Fetch grading feedback for a specific student |
| `/grade_notebook` | POST | `GradeNotebookRequest` | Batch-grade a notebook for one or all students (supports `do_regrade`) |
| `/regrade_answer` | POST | `RegradeAnswerRequest` | Regrade a single question with optional student contention |
| `/notify_student_grades` | POST | `NotifyGradedRequest` | Send grade notification email to a student |
| `/list_course_files` | POST | `ListCourseFilesRequest` | List files in a course's GCS storage folder |
| `/upload_course_materials` | GET | — | Drag-and-drop file upload page for course PDFs |
| `/validate_course_access` | GET | Query params | Validate instructor access to a course |
| `/get_upload_url` | POST | JSON body | Generate signed GCS URL for direct browser upload |
| `/upload_file` | POST | FormData | Upload a file directly to GCS (avoids CORS issues with signed URLs) |
| `/build_course_index` | POST | `BuildCourseIndexRequest` | Build RAG vector index for course PDF materials |
| `/update_course_config` | POST | `UpdateCourseConfigRequest` | Update course config (model, tutor/eval toggle, rate limits) |
| `/rate_limit_status` | POST | `TutorInteractionRequest` | View per-student rate limit usage for a course |
| `/ingest_pdf_submissions` | POST | `IngestPdfSubmissionsRequest` | Ingest PDF reports from a shared Drive folder for a PDF assignment |
| `/grade_pdf_assignment` | POST | `GradePdfAssignmentRequest` | Stream-grade every ingested PDF submission for a notebook |
| `/regrade_pdf_submission` | POST | `RegradePdfSubmissionRequest` | Regrade a single student's PDF submission, optionally with contention |
| `/upload_rubric_file` | POST | multipart | Upload a rubric file directly (PDF for PDF assignments) |
| `/upload_rubric_link` | POST | JSON | Upload a rubric from a Drive share link (PDF mode) |
| `/my_courses` | GET | — | List the courses the current user can manage (instructor / TA / admin) |

### Admin Endpoints (Requires Admin Authentication)

| Endpoint | Method | Request Model | Description |
|----------|--------|---------------|-------------|
| `/create_course` | POST | `CreateCourseRequest` | Create a new course on the platform |
| `/update_global_config` | POST | `UpdateGlobalConfigRequest` | Update global server config (e.g., concurrency semaphore limit) |

### Diagnostics

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check / admin login page |
| `/session-test` | GET | Test session configuration (development) |

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | Yes | Google Cloud project ID |
| `PRODUCTION` | Yes | `0` for development, `1` for production |
| `ADMIN_EMAIL` | Yes | Platform administrator email |
| `FIRESTORE_DATABASE_ID` | Yes | Firestore database name |
| `SERVICE_ACCOUNT_EMAIL` | Yes | Service account email |
| `FIRESTORE_CLIENT_ID` | Yes | Service account client ID |
| `OAUTH_CLIENT_ID_KEY_NAME` | Yes | Secret Manager key name for OAuth client ID |
| `OAUTH_CLIENT_SECRET_KEY_NAME` | Yes | Secret Manager key name for OAuth client secret |
| `SIGNING_SECRET_KEY_NAME` | Yes | Secret Manager key name for session signing key |
| `FIRESTORE_PRIVATE_KEY_ID_KEY_NAME` | Yes | Secret Manager key name for Firestore key ID |
| `FIRESTORE_PRIVATE_KEY_KEY_NAME` | Yes | Secret Manager key name for Firestore private key |
| `OAUTH_REDIRECT_URI` | No | Custom OAuth redirect URI (for ngrok / Cloud Run) |
| `FROM_EMAIL` | No | Gmail address used to send notifications (disables email if unset) |
| `GEMINI_API_KEY_NAME` | No | Secret Manager key for Gemini API (uses Vertex AI if unset) |
| `BUCKET_NAME` | No | GCS bucket name (defaults to `{project_id}-bucket`) |
| `REGION` | No | GCP region for Vertex AI |

### Google Cloud Secrets

Secrets are stored in Secret Manager and accessed by the server at startup:

| Secret | Purpose |
|--------|---------|
| OAuth client ID | OAuth 2.0 client credentials |
| OAuth client secret | OAuth 2.0 client credentials |
| Signing secret key | JWT / session signing |
| Firestore private key ID | Service account authentication |
| Firestore private key | Service account authentication |
| `EMAIL_KEY` | Gmail app password for SMTP email delivery (optional) |
| Gemini API key | Direct Gemini API access (optional) |

See [GMAIL_SETUP.md](./GMAIL_SETUP.md) for email configuration details.

## Deployment

### Docker Build

```bash
# Build the image
docker build -t ai-ta .

# Test locally
docker run -p 8080:8080 \
  -e GOOGLE_CLOUD_PROJECT=your-project \
  -e PRODUCTION=0 \
  ai-ta
```

### Google Cloud Run

For detailed deployment instructions, see [DEPLOYMENT.md](./DEPLOYMENT.md).

Quick deployment:

```bash
# Set project
export PROJECT_ID=your-project-id
export SERVICE_NAME=your-service-name
export REGION=asia-south1

# Build and deploy
gcloud builds submit --tag gcr.io/$PROJECT_ID/$SERVICE_NAME

gcloud run deploy $SERVICE_NAME \
  --image gcr.io/$PROJECT_ID/$SERVICE_NAME \
  --region $REGION \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars PRODUCTION=1,GOOGLE_CLOUD_PROJECT=$PROJECT_ID
```

## Development

### Project Structure

```
ai-ta/
├── src/
│   ├── api_server.py        # FastAPI app — routes, middleware, request handling
│   ├── config.py            # Configuration, secrets, and service initialization
│   ├── models.py            # Pydantic request/response models
│   ├── auth.py              # OAuth helpers, JWT creation/verification
│   ├── database.py          # Firestore CRUD (courses, students, rubrics, grades, PDF submissions)
│   ├── firestore_service.py # Custom async Firestore session service for ADK
│   ├── agent.py             # AI agent definitions (instructor, tutor, scoring)
│   ├── agent_service.py     # Agent orchestration and scoring logic (notebook + PDF)
│   ├── rate_limiter.py       # Per-student sliding-window rate limiter
│   ├── rag.py               # RAG pipeline (PDF chunking, embedding, retrieval)
│   ├── drive_utils.py       # Google Drive helpers (file + folder access via service account)
│   ├── pdf_utils.py         # PDF text extraction, author detection, fuzzy student matching
│   ├── storage_utils.py     # GCS upload and signed URL utilities
│   ├── email_service.py     # Gmail SMTP email service
│   ├── aita_exceptions.py   # Custom exception classes
│   └── exceptions.py        # Base exception hierarchy
├── tests/
│   ├── conftest.py              # Pytest configuration and shared fixtures
│   ├── test_api_endpoints.py    # API integration tests
│   ├── test_agent_service.py    # Agent execution tests
│   ├── test_auth.py             # Auth logic tests
│   ├── test_database.py         # Database operations tests
│   ├── test_drive_utils.py      # Google Drive utility tests (file + folder access)
│   ├── test_email_service.py    # Email service tests
│   ├── test_exceptions.py       # Exception tests
│   ├── test_firestore_service.py # Session service tests
│   ├── test_models.py           # Pydantic model tests
│   ├── test_pdf_database.py     # PDF-assignment database helper tests
│   ├── test_pdf_endpoints.py    # PDF-assignment endpoint tests (ingest/grade/regrade)
│   ├── test_pdf_utils.py        # PDF text + author extraction + student matching tests
│   ├── test_rag.py              # RAG pipeline tests
│   ├── test_rate_limiter.py     # Rate limiter tests
│   └── test_storage_utils.py    # GCS utility tests
├── requirements.txt
├── Dockerfile
├── Makefile
├── .env.example             # Environment variables template
├── DEPLOYMENT.md            # Cloud Run deployment guide
├── GMAIL_SETUP.md           # Email configuration guide
└── README.md
```

### AI Agents

The system uses three specialized agents built with Google ADK. The AI model defaults to `gemini-2.5-pro` but can be configured per course via Firestore (using the `ai_model` field in the course document). Custom agent prompts can also be set per course.

1. **Instructor Assistant Agent** (`instructor_assist_agent`)
   - Model: `gemini-2.5-pro` (configurable per course)
   - Purpose: Assists instructors with content review, question creation, rubric checking, and rubric answer generation

2. **Student Tutor Agent** (`ai_tutor_agent`)
   - Model: `gemini-2.5-pro` (configurable per course)
   - Purpose: Interactive tutoring — evaluates student answers against rubrics and course materials, provides feedback and hints

3. **Scoring Agent** (`ai_scoring_agent`)
   - Model: `gemini-2.5-pro` (configurable per course)
   - Purpose: Automated grading — component-based scoring with partial credit, matches student answers against rubric components

### RAG Pipeline

The system includes a Retrieval-Augmented Generation pipeline for grounding agent responses in course materials:

- **Embedding model**: `text-embedding-004` (Vertex AI)
- **Chunk size**: 1000 characters with 200-character overlap
- **Storage**: Firestore native `Vector` type in `rag_chunks` subcollection
- **Retrieval**: Cosine similarity search via Firestore `find_nearest()`
- **Integration**: Retrieved context is injected into `/assist` and `/eval` agent prompts

### Testing & Code Quality

The project uses `pytest` for testing and `ruff` for linting and formatting. Dev dependencies are in `requirements-dev.txt`.

```bash
# Install dev dependencies
make install

# Run the full test suite
make test

# Lint source and test files
make lint

# Auto-format source and test files
make format

# Remove Python cache files
make clean
```

Tests are located in the `tests/` directory and cover API endpoints, agent orchestration, authentication, database operations, RAG pipeline, rate limiting, and more. Configuration is in `pyproject.toml`.

### Local Development with ngrok

For testing OAuth on a public URL:

```bash
# Start ngrok
ngrok http 8080

# Set environment variable
export OAUTH_REDIRECT_URI=https://your-subdomain.ngrok-free.app/callback

# Run server
python src/api_server.py
```

### Logging

Logs are written to:
- Console (stdout) — INFO level and above
- `app.log` file — DEBUG level and above

## Related Repositories

- **Client Package**: [colab_grading_client](https://github.com/amrutur/colab_grading_client) — Python package for students and instructors to use in Colab notebooks

## Documentation

- [Deployment Guide](./DEPLOYMENT.md) — Cloud Run deployment instructions
- [Gmail SMTP Setup](./GMAIL_SETUP.md) — Email notification configuration

## Contributing

This is an educational project. For issues or questions, please contact the project maintainer.

## License

See [LICENSE](./LICENSE) file for details.

## Acknowledgments

Built with significant assistance from Claude's Sonnet 4.6 for code development and Google's Gemini AI for general info and leveraging:
- Google Agent Development Kit (ADK)
- Google Generative AI (Gemini 2.5 Pro)
- FastAPI
- Google Cloud Platform (Firestore, Cloud Storage, Vertex AI, Cloud Run)

---

**Project**: AI Teaching Assistant (ai-ta)
**Institution**: Graduate-level courses
**Maintained by**: Bharadwaj Amrutur (amrutur@gmail.com)
