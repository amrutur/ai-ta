# AI Teaching Assistant Platform

An AI-powered teaching and grading assistant for graduate courses.The system provides automated feedback, grading, and personalized tutoring for students working on assignments in Google Colab notebooks.

## Overview

This repository contains the **server-side API** for the AI treaching  assistant and grading system. It works in conjunction with the [colab_grading_client](https://github.com/amrutur/colab_grading_client) Python package, which provides client-side functions for students to interact with the grading assistant directly from their Google Colab notebooks.

### System Architecture

```
┌─────────────────────────┐
│  Google Colab Notebook  │  ← Student workspace
│  (colab_grading_client) │
└───────────┬─────────────┘
            │ HTTP/JSON
            ↓
┌─────────────────────────┐
│  FastAPI Server         │  ← This repository
│  (api_server.py)        │
└───────────┬─────────────┘
            │
    ┌───────┴────────┐
    ↓                ↓
┌─────────┐    ┌──────────┐
│ Gemini  │    │Firestore │
│  AI     │    │ Database │
└─────────┘    └──────────┘
```

## Key Features

### For Students
- **Interactive Help**: Get instant feedback and hints on assignment questions
- **Guided Learning**: AI provides progressive hints without revealing answers immediately (3-attempt rule)
- **Automated Grading**: Submit notebooks for automated evaluation with detailed feedback
- **Google OAuth Authentication**: Secure login using institutional Google accounts

### For Instructors
- **Rubric-Based Grading**: Upload scoring rubrics to guide the AI grading agent
- **Batch Grading**: Evaluate multiple student submissions efficiently
- **Email Notifications**: Automatically notify students when grades are ready
- **Grade Management**: View and export grades for all students
- **Component-Based Scoring**: Flexible rubric system with partial credit support

### Technical Features
- **Google ADK Integration**: Built on Google's Agent Development Kit (ADK)
- **Dual AI Agents**:
  - **Teaching Agent**: Provides interactive help and hints
  - **Scoring Agent**: Evaluates submissions against rubrics
- **Firestore Logging**: All interactions logged for analysis and auditing
- **SendGrid Integration**: Reliable email delivery for grade notifications
- **Google Drive Integration**: Access student notebooks and rubric files
- **Cloud Run Deployment**: Scalable, serverless deployment on Google Cloud

## Prerequisites

### For Development
- Python 3.8+
- Google Cloud Project with enabled APIs:
  - Firestore
  - Secret Manager
  - Cloud Run (for production)
  - Drive API
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

   Create a `.env` file (or set environment variables):
   ```bash
   GOOGLE_CLOUD_PROJECT=your-project-id
   PRODUCTION=0  # Set to 1 for production
   INSTRUCTOR_EMAILS=instructor1@example.com,instructor2@example.com
   OAUTH_REDIRECT_URI=http://localhost:8080/callback  # Or your ngrok URL
   SENDGRID_FROM_EMAIL=noreply@yourdomain.com
   SERVICE_ACCOUNT_EMAIL=your-service-account@project.iam.gserviceaccount.com
   FIRESTORE_DATABASE_ID=your-firestore-db
   ```

4. **Configure Google Cloud Secrets**

   Store sensitive credentials in Secret Manager:
   - `oauth_client_config`: OAuth 2.0 client configuration JSON
   - `signing_secret_key`: Session signing key
   - `service_account_key`: Service account credentials JSON
   - `sendgrid-api-key`: SendGrid API key

5. **Run the development server**
   ```bash
   python api_server.py
   ```

   The server will start at `http://localhost:8080`

### Client Setup (For Students)

Students install the client package in their Colab notebooks:

```python
!pip install git+https://github.com/amrutur/colab_grading_client.git
```

## Usage

### For Students (in Google Colab)

1. **Install and import the client**
   ```python
   !pip install git+https://github.com/amrutur/colab_grading_client.git
   import colab_grading_client as cgc

   # Set the grader server URL
   cgc.GRADER_URL = "https://your-server-url.run.app"
   ```

2. **Login**
   ```python
   cgc.show_login_button()
   ```

3. **Get help on a question**
   ```python
   # Mark your question cell with **Q1** at the start
   # Write your answer in the next cell
   cgc.show_teaching_assist_button(question_number=1)
   ```

4. **Submit notebook for grading**
   ```python
   cgc.show_submit_eval_button()
   ```

### For Instructors

1. **Login to the system**

   Navigate to `https://your-server-url.run.app/login`

2. **Upload a rubric**

   Share a Google Doc with your service account containing:
   ```
   The assignment question is: [Question text]

   The scoring rubric is:
   (10 marks): Correct identification of eigenvalues
   (5 marks): Proper matrix decomposition
   (5 marks): Clear explanation of methodology
   ```

3. **View student grades**
   ```python
   # In a Colab notebook with instructor credentials
   import colab_grading_client as cgc

   grades = cgc.fetch_student_list(
       assignment_name="Assignment1",
       course_name="CP220"
   )
   ```

4. **Send grade notifications**
   ```python
   cgc.notify_student_grades(
       assignment_name="Assignment1",
       course_name="CP220"
   )
   ```

## API Endpoints

API endpoints can be tested by connecting to `https://AI_tutor_server_url/docs`

### Authentication

The API supports two authentication methods:

1. **Session-based (Browser/OAuth)**: For web browsers
2. **JWT Token-based**: For API clients like Colab notebooks

#### Endpoints
- `GET /login` - Initiate OAuth login flow
- `GET /callback` - OAuth callback handler
- `GET /get_auth_token` - Get JWT token after OAuth login (for API clients)
  - Returns: `{"token": "jwt_token_string", "token_type": "Bearer", "expires_in": 86400}`
  - Usage: Include in subsequent API calls as `Authorization: Bearer <token>`
- `GET /logout` - Clear user session

#### Using JWT Authentication from Colab

```python
import requests

# Step 1: User completes OAuth in browser
# Direct user to: https://your-server-url.run.app/login

# Step 2: After login, get JWT token (in same browser session)
response = requests.get("https://your-server-url.run.app/get_auth_token")
token = response.json()["token"]

# Step 3: Use token in API requests
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(
    "https://your-server-url.run.app/some_endpoint",
    json={...},
    headers=headers
)
```

### Student Operations
- `POST /assist` - Get teaching assistance for a question
  ```json
  {
    "question_number": 1,
    "question_text": "...",
    "answer_text": "...",
    "user_email": "student@example.com"
  }
  ```

### Instructor Operations (Requires Instructor Authentication)
- `POST /enable_eval` - Enable the evaluation endpoint for student submissions
- `POST /disable_eval` - Disable the evaluation endpoint (prevents new submissions)
- `POST /enable_tutor` - Enable the tutoring/assist endpoint for students
- `POST /disable_tutor` - Disable the tutoring/assist endpoint
- `POST /eval` - Submit notebook for grading (must be enabled first)
  ```json
  {
    "notebook_json": {...},
    "assignment_name": "Assignment1",
    "course_name": "CP220",
    "submission_hash": "md5_hash"
  }
  ```
- `POST /fetch_grader_response` - Retrieve grading results for a student
  ```json
  {
    "notebook_id": "Assignment1",
    "user_email": "student@example.com"
  }
  ```
- `POST /fetch_student_list` - Get all student grades for a course/assignment
- `POST /notify_student_grades` - Send email notifications to students with their grades

### Diagnostics
- `GET /` - Health check
- `GET /session-test` - Test session configuration (development)

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | Yes | Google Cloud project ID |
| `PRODUCTION` | Yes | `0` for development, `1` for production |
| `INSTRUCTOR_EMAILS` | Yes | Comma-separated list of instructor emails |
| `OAUTH_REDIRECT_URI` | No | OAuth redirect URI (for ngrok development) |
| `SENDGRID_FROM_EMAIL` | Yes | Sender email for notifications |
| `SERVICE_ACCOUNT_EMAIL` | Yes | Service account email |
| `FIRESTORE_DATABASE_ID` | Yes | Firestore database name |

### Google Cloud Secrets

Secrets are stored in Secret Manager and accessed by the server:

- **oauth_client_config**: OAuth 2.0 credentials
- **signing_secret_key**: Session encryption key
- **service_account_key**: Service account JSON key
- **sendgrid-api-key**: SendGrid API key

See [SENDGRID_SETUP.md](./SENDGRID_SETUP.md) for email configuration details.

## Deployment

### Docker Build

```bash
# Build the image
docker build -t cp220-grader-api .

# Test locally
docker run -p 8080:8080 \
  -e GOOGLE_CLOUD_PROJECT=your-project \
  -e PRODUCTION=0 \
  cp220-grader-api
```

### Google Cloud Run

For detailed deployment instructions, see [DEPLOYMENT.md](./DEPLOYMENT.md).

Quick deployment:

```bash
# Set project
export PROJECT_ID=your-project-id
export REGION=asia-south1

# Build and deploy
gcloud builds submit --tag gcr.io/$PROJECT_ID/cp220-grader-api

gcloud run deploy cp220-grader-api \
  --image gcr.io/$PROJECT_ID/cp220-grader-api \
  --region $REGION \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars PRODUCTION=1,GOOGLE_CLOUD_PROJECT=$PROJECT_ID
```

## Development

### Project Structure

```
cp220-2025-grader/
├── api_server.py          # Main FastAPI server
├── agent.py               # AI agent definitions (teaching & scoring)
├── requirements.txt       # Python dependencies
├── Dockerfile             # Container definition
├── .dockerignore          # Docker build exclusions
├── DEPLOYMENT.md          # Deployment guide
├── SENDGRID_SETUP.md      # Email configuration guide
└── README.md              # This file
```

### AI Agents

The system uses two specialized agents built with Google ADK:

1. **Teaching Agent** (`cp220_2025_grader_agent`)
   - Model: `gemini-2.0-flash`
   - Purpose: Interactive tutoring and feedback
   - Behavior: Provides progressive hints, reveals answers after 3 attempts

2. **Scoring Agent** (`cp220_2025_scoring_agent`)
   - Model: `gemini-2.0-flash`
   - Purpose: Automated grading with rubrics
   - Behavior: Component-based scoring with partial credit

### Local Development with ngrok

For testing OAuth on a public URL:

```bash
# Start ngrok
ngrok http 8080

# Set environment variable
export OAUTH_REDIRECT_URI=https://your-subdomain.ngrok-free.app/callback

# Run server
python api_server.py
```

### Logging

Logs are written to:
- Console (INFO level and above)
- `app.log` file (DEBUG level and above)

## Related Repositories

- **Client Package**: [colab_grading_client](https://github.com/amrutur/colab_grading_client) - Python package for students to use in Colab notebooks

## Documentation

- [Deployment Guide](./DEPLOYMENT.md) - Complete Cloud Run deployment instructions
- [SendGrid Setup](./SENDGRID_SETUP.md) - Email notification configuration
- [Gmail Setup](./GMAIL_SETUP.md) - Alternative email configuration (deprecated)

## Contributing

This is an educational project for CP220 course. For issues or questions, please contact the course instructor.

## License

See [LICENSE](./LICENSE) file for details.

## Acknowledgments

Built with significant assistance from Google's Gemini AI and leveraging:
- Google Agent Development Kit (ADK)
- Google Generative AI (Gemini)
- FastAPI
- SendGrid
- Google Cloud Platform

---

**Course**: CP220 - Linear Algebra and Probability for Robotics
**Institution**: Graduate-level course
**Maintained by**: Bharadwaj Amrutur (amrutur@gmail.com)
