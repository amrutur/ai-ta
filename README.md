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
│       ├── isactive_tutor, isactive_eval (feature flags)
│       ├── student_rate_limit, student_rate_limit_window (per-student rate limiting)
│       │
│       ├── Notebooks/ (subcollection — rubrics & instructor content)
│       │   └── {notebook_id}/
│       │       ├── max_marks, context, questions, answers, outputs
│       │       └── rag_chunks/ (subcollection — vector embeddings)
│       │           └── {auto-id}/ (source_file, chunk_index, text, embedding)
│       │
│       └── Students/ (subcollection)
│           └── {student_email}/
│               ├── name, initialized, created_at
│               └── Notebooks/ (subcollection — submissions & grades)
│                   └── {notebook_id}/
│                       ├── answer_notebook, answer_hash, submitted_at
│                       ├── total_marks, max_marks, graded_at
│                       ├── grader_response, graded_json
│
├── student_sessions/ (collection — student-agent conversation history)
│   └── {app_name}/users/{user_email}/sessions/{session_id}/events/...
│
└── instructor_sessions/ (collection — instructor-agent conversation history)
    └── {app_name}/users/{user_email}/sessions/{session_id}/events/...
```

## Key Features

### For Students
- **Interactive Tutoring**: Get AI-powered feedback and hints on assignment questions
- **Guided Learning**: Progressive hints grounded in course materials and rubrics
- **Automated Grading**: Submit notebooks for automated evaluation with detailed feedback
- **Google OAuth Authentication**: Secure login using Google accounts

### For Instructors
- **Instructor AI Assistant**: Verify content, create questions, review rubrics, and get suggestions
- **Rubric Management**: Upload scoring rubrics to guide the AI grading agent
- **Course Materials Upload**: Drag-and-drop browser interface for uploading PDFs to GCS
- **RAG Index Building**: Build vector search indices over uploaded course materials
- **Tutor & Eval Controls**: Dynamically enable/disable the tutoring and evaluation endpoints per course
- **Per-Student Rate Limiting**: Configurable sliding-window rate limits per course to manage AI model usage
- **Batch Grading**: Evaluate multiple student submissions
- **Email Notifications**: Notify students when grades are ready via SendGrid
- **Grade Management**: View student marks lists and detailed grading feedback

### Technical Features
- **Google ADK Integration**: Built on Google's Agent Development Kit (ADK v1.26.0)
- **Three Specialized AI Agents**:
  - **Instructor Assistant Agent**: Helps instructors with content review, question creation, and rubric design
  - **Student Tutor Agent**: Provides interactive tutoring and feedback to students
  - **Scoring Agent**: Evaluates submissions against rubrics with component-based scoring
- **RAG Pipeline**: Retrieval-Augmented Generation using Vertex AI embeddings (`text-embedding-004`) and Firestore vector search for grounding responses in course materials
- **Custom Firestore Session Service**: Async session persistence with app-level and user-level state, event subcollections
- **Dual Authentication**: OAuth 2.0 sessions (browser) and JWT tokens (API/Colab clients)
- **Per-Student Rate Limiting**: In-memory sliding-window rate limiter configurable per course, with instructor bypass and live config updates
- **GCS Signed URL Uploads**: Direct browser-to-GCS uploads via signed URLs (bypasses Cloud Run size limits)
- **SendGrid Integration**: Email delivery for grade notifications
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
- SendGrid API key (for email notifications)

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
   - SendGrid API key (optional)
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

   Navigate to `https://your-server-url.run.app/login`

2. **Upload course materials**

   Navigate to `https://your-server-url.run.app/upload_course_materials` to access the drag-and-drop upload interface for PDF course materials.

3. **Build the RAG index**

   After uploading materials, build the vector search index so the AI agents can reference them:
   ```
   POST /build_course_index
   { "course_id": "...", "term_id": "...", "institution_id": "..." }
   ```

4. **Upload a rubric**

   Use the `/upload_rubric` endpoint to save question rubrics (questions, answers, marks, context) for a notebook.

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
| `/notify_student_grades` | POST | `NotifyGradedRequest` | Send grade notification email to a student |
| `/upload_course_materials` | GET | — | Drag-and-drop file upload page for course PDFs |
| `/validate_course_access` | GET | Query params | Validate instructor access to a course |
| `/get_upload_url` | POST | JSON body | Generate signed GCS URL for direct browser upload |
| `/build_course_index` | POST | `BuildCourseIndexRequest` | Build RAG vector index for course PDF materials |
| `/update_course_config` | POST | `UpdateCourseConfigRequest` | Update course config (model, tutor/eval toggle, rate limits) |
| `/rate_limit_status` | POST | `TutorInteractionRequest` | View per-student rate limit usage for a course |

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
| `SENDGRID_FROM_EMAIL` | No | Sender email for notifications (disables email if unset) |
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
| `sendgrid-api-key` | SendGrid email delivery (optional) |
| Gemini API key | Direct Gemini API access (optional) |

See [SENDGRID_SETUP.md](./SENDGRID_SETUP.md) for email configuration details.

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
│   ├── database.py          # Firestore CRUD (courses, students, rubrics, grades)
│   ├── firestore_service.py # Custom async Firestore session service for ADK
│   ├── agent.py             # AI agent definitions (instructor, tutor, scoring)
│   ├── agent_service.py     # Agent orchestration and scoring logic
│   ├── rate_limiter.py       # Per-student sliding-window rate limiter
│   ├── rag.py               # RAG pipeline (PDF chunking, embedding, retrieval)
│   ├── drive_utils.py       # Google Drive / Colab notebook utilities
│   ├── storage_utils.py     # GCS upload and signed URL utilities
│   ├── email_service.py     # SendGrid email service
│   └── aita_exceptions.py   # Custom exception classes
├── tests/
│   ├── conftest.py          # Pytest configuration and shared fixtures
│   ├── test_api_endpoints.py
│   ├── test_database.py
│   ├── test_agent_service.py
│   ├── test_models.py
│   ├── test_rag.py
│   └── test_rate_limiter.py
├── requirements.txt
├── Dockerfile
├── Makefile
├── .env.example             # Environment variables template
├── DEPLOYMENT.md            # Cloud Run deployment guide
├── SENDGRID_SETUP.md        # Email configuration guide
└── README.md
```

### AI Agents

The system uses three specialized agents built with Google ADK:

1. **Instructor Assistant Agent** (`instructor_assist_agent`)
   - Model: `gemini-2.5-pro`
   - Purpose: Assists instructors with content review, question creation, rubric checking, and rubric answer generation

2. **Student Tutor Agent** (`ai_tutor_agent`)
   - Model: `gemini-2.5-pro`
   - Purpose: Interactive tutoring — evaluates student answers against rubrics and course materials, provides feedback and hints

3. **Scoring Agent** (`ai_scoring_agent`)
   - Model: `gemini-2.5-pro`
   - Purpose: Automated grading — component-based scoring with partial credit, matches student answers against rubric components

### RAG Pipeline

The system includes a Retrieval-Augmented Generation pipeline for grounding agent responses in course materials:

- **Embedding model**: `text-embedding-004` (Vertex AI)
- **Chunk size**: 1000 characters with 200-character overlap
- **Storage**: Firestore native `Vector` type in `rag_chunks` subcollection
- **Retrieval**: Cosine similarity search via Firestore `find_nearest()`
- **Integration**: Retrieved context is injected into `/assist` and `/eval` agent prompts

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
- [SendGrid Setup](./SENDGRID_SETUP.md) — Email notification configuration

## Contributing

This is an educational project. For issues or questions, please contact the project maintainer.

## License

See [LICENSE](./LICENSE) file for details.

## Acknowledgments

Built with significant assistance from Google's Gemini AI and leveraging:
- Google Agent Development Kit (ADK)
- Google Generative AI (Gemini 2.5 Pro)
- FastAPI
- SendGrid
- Google Cloud Platform (Firestore, Cloud Storage, Vertex AI, Cloud Run)

---

**Project**: AI Teaching Assistant (ai-ta)
**Institution**: Graduate-level courses
**Maintained by**: Bharadwaj Amrutur (amrutur@gmail.com)
