#api_server.py
'''
An api server to access the AI agent for grading answers submitted via
Google Colab Notebook cell.

The Colab users need to be authenticated via Google's Oauth2 service

The instructor can optionally provide a rubric file to help assist
the AI agent in grading and providing hints for answers, as well as provide
marks. The rubric file has to be shared with a service account

It logs the interactions in a Firsestore NoSQl database

Required environment parameters:
GOOGLE_CLOUD_PROECT (should be set to be the project id for the application google cloud)
PRODUCTION (should be set to 0 for local testing and 1 for production)
ADMIN_EMAIL (platform administrator email addresses)
OAUTH_REDIRECT_URI (optional, for development with ngrok - e.g., https://yoursubdomain.ngrok-free.app/callback)
FROM_EMAIL (Gmail address to send notification emails from; requires EMAIL_KEY in Secret Manager)

In addition a google service account is needed to access the firestore database as
well as the rubric (the rubric file has to be shared with the service account)

All the secrets are accessed from the api_server's owner's secret manager on google.

Written with lots of help from google's gemini !

'''

import os
import asyncio
import logging
import traceback
import json
import uuid
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File, Form
from fastapi.responses import  HTMLResponse, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
import uvicorn
import requests as http_requests

from google_auth_oauthlib.flow import Flow
from google.genai import types

import config
from agent_service import run_agent_and_get_response, score_question, score_pdf_submission, evaluate, update_semaphore_limit, get_semaphore_limit, truncate_text, truncate_prompt, MAX_OUTPUT_CHARS, MAX_TOTAL_PROMPT_CHARS

from models import (
    QueryRequest, QueryResponse,
    AssistRequest, AssistResponse,
    GradeRequest, GradeResponse,
    EvalRequest, EvalResponse,
    FetchGradedRequest, FetchGradedResponse,
    NotifyGradedRequest, NotifyGradedResponse,
    TutorInteractionRequest, TutorInteractionResponse, EvalToggleRequest,
    CreateCourseRequest, CreateCourseResponse,
    FetchMarksListRequest, FetchMarksListResponse,
    AddRubricRequest, AddRubricResponse,
    GradeNotebookRequest,
    RegradeAnswerRequest, RegradeAnswerResponse,
    BuildCourseIndexRequest, BuildCourseIndexResponse,
    UpdateCourseConfigRequest, UpdateCourseConfigResponse,
    UpdateGlobalConfigRequest, UpdateGlobalConfigResponse,
    ListCourseFilesRequest, ListCourseFilesResponse,
    IngestPdfSubmissionsRequest, IngestPdfSubmissionsResponse,
    IngestedPdfRecord, SkippedPdfRecord, FailedPdfRecord,
    GradePdfAssignmentRequest,
    RegradePdfSubmissionRequest, RegradePdfSubmissionResponse,
)
from auth import (
    create_jwt_token,
    get_current_user,
    get_admin_user,
)
from database import (
    get_student_list,
    add_student_if_not_exists,
    add_instructor_notebook_if_not_exists,
    add_student_notebook_if_not_exists,
    upload_student_notebook,
    update_course_info,
    update_notebook_info,
    update_marks,
    save_student_answers,
    get_student_notebook_answers,
    is_notebook_graded,
    is_email_notified,
    mark_email_notified,
    fetch_grader_response,
    create_course,
    make_course_handle,
    save_rubric,
    save_pdf_rubric,
    get_marks_list,
    get_course_data,
    load_course_info_from_db,
    load_notebooks_from_db,
    load_default_values,
    add_placeholder_student,
    get_student_directory,
    get_student_pdf_mirror,
    get_pdf_submission,
    list_pdf_submissions,
    update_pdf_submission_grade,
    upsert_pdf_submission,
)
from drive_utils import (
    download_file_bytes_sa,
    extract_folder_id_from_link,
    get_file_id_from_share_link,
    list_pdfs_in_folder_sa,
    load_notebook_from_google_drive_sa,
)
from pdf_utils import (
    extract_authors_with_gemini,
    extract_first_pages_text,
    make_placeholder_student_id,
    match_author_to_student,
)
from email_service import send_email
from storage_utils import upload_blob, generate_signed_upload_url, list_blobs
from rag import build_course_index, retrieve_context
import agent
from rate_limiter import student_rate_limiter
import datetime
from collections import defaultdict

DEFAULT_RATE_LIMIT_WINDOW = 3600  # 1 hour

# --- FastAPI Application ---
app = FastAPI(title="AI-TA Agent API")

#---Course Data Cache---
courses=defaultdict(dict) #cache for course data to avoid fetching from db repeatedly

origins = [
    "http://localhost",
    "http://localhost:8080",
    "*",
    # You can also use "*" to allow all origins
]

#app.add_middleware(
#    CORSMiddleware,
#    allow_origins=["*"],  # Allows all origins
#    allow_credentials=True,
#    allow_methods=["*"],
#    allow_headers=["*"],
#)


# Add the session middleware with proper cookie settings for OAuth flow
# The secret_key is used to sign the session cookie for security.

# Determine if we're using HTTPS (production or ngrok)
using_https = config.is_production or os.environ.get('OAUTH_REDIRECT_URI', '').startswith('https://')

# Configure session middleware with settings optimized for Cloud Run
app.add_middleware(
    SessionMiddleware,
    secret_key=config.signing_secret_key,
    session_cookie="session",
    max_age=3600,  # 1 hour
    same_site="lax" if config.is_production else "lax",  # "lax" works for OAuth redirects in production
    https_only=using_https,  # True for production/ngrok (HTTPS), False for localhost (HTTP)
    path="/"  # Ensure cookie is valid for all paths
)

if config.is_production:
    logging.info("Session cookies configured for Cloud Run production (HTTPS, same_site=lax)")
elif using_https:
    logging.info("Session cookies configured for HTTPS development (ngrok)")
else:
    logging.info("Session cookies configured for HTTP development (localhost)")


# ==================== Startup Event ====================

@app.on_event("startup")
async def load_courses_cache():
    """Load all courses from Firestore into the in-memory cache on startup."""
    try:
        # Load platform-wide default values (prompts, model) from courses/default_values
        default_values = await load_default_values(config.db)

        all_courses = await load_course_info_from_db(config.db)
        for course_handle, course_data in all_courses.items():
            if course_handle == 'default_values':
                continue  # skip the defaults document itself
            courses[course_handle] = course_data
            courses[course_handle].setdefault('isactive_tutor', True)
            courses[course_handle].setdefault('student_rate_limit', None)
            courses[course_handle].setdefault('student_rate_limit_window', None)

            # Populate per-course prompts/model: use course-level if set, else defaults
            for key in ('ai_model', 'instructor_assist_prompt',
                        'student_assist_prompt', 'scoring_assist_prompt'):
                courses[course_handle].setdefault(key, default_values.get(key))

            # Load rubric notebooks for this course into the cache
            notebooks = await load_notebooks_from_db(config.db, course_handle)
            for notebook_id, notebook_data in notebooks.items():
                courses[course_handle][notebook_id] = notebook_data
            if notebooks:
                logging.info(f"  Course '{course_handle}': loaded {len(notebooks)} rubric notebook(s)")
        logging.info(f"Loaded {len(all_courses)} courses into cache on startup")
    except Exception as e:
        logging.error(f"Failed to load courses cache on startup: {e}")
        traceback.print_exc()


# ==================== Authentication Endpoints ====================

@app.get("/login", tags=["Authentication"])
async def login(request: Request):
    """
    Redirects the user to the Google OAuth consent screen to initiate login.

    Accepts an optional ``?next=<path>`` query param. After successful auth
    the OAuth callback redirects there (used by the dashboard to bring users
    back to ``/`` after login).
    """
    next_param = request.query_params.get('next')
    if next_param and next_param.startswith('/') and not next_param.startswith('//'):
        # Only allow same-origin redirects to avoid open-redirect.
        request.session['redirect_after_login'] = next_param
    flow = Flow.from_client_config(
        client_config=config.client_config,
        scopes=config.SCOPES,
        redirect_uri=config.client_config['web']['redirect_uris'][config.REDIRECT_URI_INDEX]
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    # Store the state and PKCE code_verifier in the session for the callback.
    request.session['state'] = state
    request.session['code_verifier'] = flow.code_verifier

    # Use HTML redirect to ensure session cookie is set before redirect
    # Direct RedirectResponse can sometimes redirect before session middleware sets the cookie
    html_content = f"""
    <html>
        <head>
            <title>Redirecting to Google...</title>
            <meta http-equiv="refresh" content="0;url={authorization_url}">
        </head>
        <body>
            <p>Redirecting to Google for authentication...</p>
            <p>If you are not redirected automatically, <a href="{authorization_url}">click here</a>.</p>
        </body>
    </html>
    """

    return HTMLResponse(content=html_content, status_code=200)

@app.get("/callback", tags=["Authentication"])
async def oauth_callback(request: Request):
    """
    Handles the callback from Google after user consent.
    Exchanges the authorization code for credentials and creates a user session.
    """
    state = request.session.get('state')
    query_state = request.query_params.get('state')

    if not state:
        raise HTTPException(
            status_code=400,
            detail="No state found in session. Session cookies may not be working. Please try logging in again."
        )

    if state != query_state:
        raise HTTPException(status_code=400, detail="State mismatch, possible CSRF attack.")


    # Create flow WITHOUT scopes for the callback.  Scopes were already sent
    # to Google in /login; re-specifying them here causes oauthlib to compare
    # requested vs granted scopes and raise a Warning (via `raise`, not
    # warnings.warn) that aborts fetch_token before the access token is set.
    # Passing scopes=None skips that comparison entirely.
    flow = Flow.from_client_config(
        client_config=config.client_config,
        scopes=None,
        redirect_uri=config.client_config['web']['redirect_uris'][config.REDIRECT_URI_INDEX]
        )

    # Reconstruct the authorization response URL with HTTPS
    # Cloud Run terminates HTTPS at the load balancer, so request.url shows HTTP
    # But OAuth requires HTTPS, so we need to reconstruct with the correct protocol
    authorization_response = str(request.url)

    # Check if running behind a proxy (Cloud Run) and fix the protocol
    forwarded_proto = request.headers.get('X-Forwarded-Proto', '')
    if forwarded_proto == 'https' and authorization_response.startswith('http://'):
        authorization_response = authorization_response.replace('http://', 'https://', 1)
    # Restore the PKCE code_verifier so oauthlib can complete the exchange.
    # fetch_token is a synchronous HTTP call; run it in a thread so we don't
    # block the async event loop.
    code_verifier = request.session.get('code_verifier')
    try:
        await asyncio.to_thread(
            flow.fetch_token,
            authorization_response=authorization_response,
            code_verifier=code_verifier,
        )
    except Exception as e:
        logging.error(f"OAuth token exchange failed: {e}")
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to complete OAuth authentication: {str(e)}"
        )

    # Log which scopes were actually granted vs requested
    granted = flow.oauth2session.token.get('scope', []) if flow.oauth2session.token else []
    if granted:
        logging.info(f"OAuth scopes granted: {granted}")
        missing = set(config.SCOPES) - set(granted)
        if missing:
            logging.warning(f"OAuth scopes NOT granted (may need consent screen config): {missing}")

    try:
        flow_creds = flow.credentials
    except ValueError as e:
        logging.error(f"No access token after fetch_token: {e}")
        raise HTTPException(
            status_code=500,
            detail="OAuth token exchange completed but no access token was received. Check client ID/secret configuration."
        )
    # Use credentials to fetch user info, but don't store the full OAuth
    # credentials in the session cookie — they are large (token, refresh_token,
    # client_secret, etc.) and can push the cookie past the browser's 4KB limit,
    # causing "Failed to Load Session" on refresh.

    # Fetch user info directly instead of using the discovery client.
    # build('oauth2', 'v2', ...) downloads a discovery document on every call,
    # adding several seconds of synchronous blocking latency.
    try:
        userinfo_resp = await asyncio.to_thread(
            http_requests.get,
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {flow_creds.token}"},
            timeout=10,
        )
        userinfo_resp.raise_for_status()
        request.session['user'] = userinfo_resp.json()
    except Exception as e:
        logging.error(f"Failed to retrieve user info from Google: {e}")
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve user info from Google: {str(e)}"
        )

    user_id = request.session['user']['id']
    user_name = request.session['user']['name']
    user_email = request.session['user'].get('email', '')

    # If this login was initiated from /admin_login, verify admin authorization
    if request.session.pop('admin_login', False):
        if user_email.lower() != config.admin_email:
            logging.warning(f"Unauthorized admin login attempt by {user_email}")
            request.session.clear()
            html_content = """
            <html>
                <head><title>Access Denied</title></head>
                <body>
                    <h1>Access Denied</h1>
                    <p>You are not authorized to login as a platform administrator.</p>
                    <p>Contact the platform owner if you believe this is an error.</p>
                    <a href="/">Try again</a>
                </body>
            </html>
            """
            return HTMLResponse(content=html_content, status_code=403)
        else:
            logging.info(f"Admin user '{user_name}' ({user_email}) successfully authenticated.")
            return RedirectResponse(url="/docs", status_code=302)
    else:
        # Honor a `next` URL set on /login (used by the dashboard so that
        # unauthenticated visitors who hit / land back on / after auth).
        next_url = request.session.pop('redirect_after_login', None)
        if next_url:
            return RedirectResponse(url=next_url, status_code=302)
        # Otherwise default to the JWT token page (Colab clients rely on this).
        return RedirectResponse(url="/get_auth_token", status_code=302)

@app.get("/get_auth_token", tags=["Authentication"], response_class=HTMLResponse)
async def get_auth_token(request: Request):
    """
    Generate a JWT token for authenticated user.
    User must be logged in via OAuth first (session-based).
    This token can then be used for API authentication from Colab notebooks.

    Returns:
        HTML page with the JWT token for easy copying into Colab.
    """
    if 'user' not in request.session:
        raise HTTPException(
            status_code=401,
            detail="User not authenticated. Please login first at /login"
        )

    user_data = request.session['user']

    # Generate JWT token
    token = create_jwt_token(user_data, config.signing_secret_key, expires_hours=24)
    user_name = user_data.get('name', '')
    user_email = user_data.get('email', '')

    html_content = f"""
    <html>
        <head><title>AI TA - Auth Token</title></head>
        <body style="font-family: sans-serif; max-width: 700px; margin: 40px auto; padding: 0 20px;">
            <h1>Welcome, {user_name}!</h1>
            <p>You are logged in as <strong>{user_email}</strong>.</p>
            <p>Paste the following token into your Colab notebook when prompted:</p>
            <div style="position: relative;">
                <textarea id="token" readonly rows="4" style="width: 100%; font-family: monospace; font-size: 13px; padding: 10px; word-break: break-all;">{token}</textarea>
                <button onclick="navigator.clipboard.writeText(document.getElementById('token').value); this.textContent='Copied!'; setTimeout(()=>this.textContent='Copy Token', 2000)"
                    style="margin-top: 8px; padding: 8px 20px; font-size: 14px; cursor: pointer;">Copy Token</button>
            </div>
            <p style="color: #666; font-size: 13px; margin-top: 20px;">This token expires in 24 hours. Visit this page again to get a new one.</p>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)

@app.get("/whoami", tags=["Authentication"])
async def whoami(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns the currently authenticated user's info.
    Accepts both session cookies (browser) and Bearer JWT tokens (API clients).
    Useful for verifying a token is valid from Colab notebooks.
    """
    return {
        "id": current_user.get("id"),
        "email": current_user.get("email"),
        "name": current_user.get("name"),
    }

@app.post("/colab_auth", tags=["Authentication"])
async def colab_auth(request: Request):
    """
    Authenticate a Colab notebook user via their Google access token.

    Accepts a Google access token (from google.colab.auth.authenticate_user()),
    verifies it with Google's userinfo API, registers the student under the
    given course, and returns a JWT for the app.

    Request body:
        {"google_token": "<access_token_from_colab>", "course_id": "<course_id>" (optional)}

    Returns:
        JSON with JWT token and user info
    """
    body = await request.json()
    google_token = body.get("google_token")
    course_id = body.get("course_id")
    if not google_token:
        raise HTTPException(status_code=400, detail="Missing google_token in request body")

    # Verify the token with Google's userinfo API
    try:
        resp = http_requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {google_token}"},
            timeout=10,
        )
        if resp.status_code != 200:
            logging.error(f"Google userinfo API returned {resp.status_code}: {resp.text}")
            raise HTTPException(
                status_code=401,
                detail="Invalid Google token. Please re-authenticate in Colab."
            )
        user_data = resp.json()
    except http_requests.RequestException as e:
        logging.error(f"Failed to verify Google token: {e}")
        raise HTTPException(status_code=502, detail="Failed to verify Google token with Google")

    user_id = user_data.get("id", "")
    user_gmail = user_data.get("email", "")
    user_name = user_data.get("name", "")

    if not user_gmail:
        raise HTTPException(status_code=401, detail="Could not retrieve email from Google token")

    logging.info(f"Colab auth: verified user {user_name} ({user_gmail}) for course {course_id}")

    # Add student to the course's Students subcollection if not already present
    if course_id:
        try:
            await add_student_if_not_exists(config.db, course_id, user_gmail, user_name)
        except Exception as e:
            logging.error(f"Firestore error during colab_auth student creation: {e}")

    # Generate JWT token
    token = create_jwt_token(user_data, config.signing_secret_key, expires_hours=24)

    return {
        "token": token,
        "token_type": "Bearer",
        "expires_in": 24 * 3600,
        "user": {
            "id": user_id,
            "gmail": user_gmail,
            "name": user_name,
        }
    }



@app.get("/logout", tags=["Authentication"])
async def logout(request: Request):
    """
    Logs the user out by clearing their session.
    """
    request.session.clear()
    html_content = "You have been logged out. <a href='/'>Login again</a>"
    return HTMLResponse(content=html_content)


# ==================== Student-Facing Endpoints ====================

@app.post("/assist")
async def assist(query_body: AssistRequest, request: Request):

    '''
    Call the AI Tutor agent to get assistance for a question.
    For a student: it can be used to get hints for a question, or to check if the answer is correct without giving away the marks.
    For a TA/Instructor: It can be used to get suggestions for the question, grading an answer, or to check if the answer is correct along with the suggested marks.

    Returns a streaming response with newline-delimited JSON lines:
      {"type": "progress", "message": "..."}   – progress updates
      {"type": "response", "response": "..."}   – final AI response
      {"type": "error", "detail": "..."}         – on failure
    '''

    user = get_current_user(request)
    user_gmail = user.get('email')
    user_name = user.get('name')

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    is_instructor = is_authorized(user_gmail, course_handle)

    # Check if tutor is disabled by instructor
    if not is_instructor and not courses[course_handle].get('isactive_tutor', False):
        raise HTTPException(status_code=503, detail="Tutor is temporarily disabled")

    # Per-student rate limit (skipped for instructors)
    if not is_instructor:
        check_student_rate_limit(user_gmail, course_handle)

    async def _generate():
        """Async generator that yields newline-delimited JSON progress/response lines."""
        try:
            parts = []
            context = query_body.context
            question = query_body.question.get("question", "")
            ta_chat = query_body.ta_chat
            # Format answer components: [{percent, component}, ...] → readable string
#            answer = " ".join(
#                f"[{a.get('percent', '')}%] {a.get('component', '')}"
#                for a in query_body.answer
#            ) if query_body.answer else ""
            answer = " ".join(
                f"{a.get('component', '')}"
                for a in query_body.answer
            ) if query_body.answer else ""

            output = query_body.output
            qnum = query_body.qnum
            notebook_id = query_body.notebook_id
            session_id = f"{course_handle}_{notebook_id}"
            initial_state = {'course_handle': course_handle}

            # --- Ensure DB records and session exist (+ RAG retrieval) concurrently ---

            async def _ensure_session_and_db():
                if is_instructor:
                    await add_instructor_notebook_if_not_exists(config.db, course_handle, notebook_id)
                    session_svc = config.get_session_service("instructor", course_handle)
                    existing = await session_svc.get_session(
                        app_name="ai_ta",
                        user_id=user_gmail, session_id=session_id,
                    )
                    if not existing:
                        await session_svc.create_session(
                            app_name="ai_ta",
                            user_id=user_gmail, session_id=session_id,
                            state=initial_state,
                        )
                else:
                    await add_student_notebook_if_not_exists(config.db, course_handle, user_gmail, user_name, notebook_id)
                    session_svc = config.get_session_service("student", course_handle)
                    existing = await session_svc.get_session(
                        app_name="ai_ta",
                        user_id=user_gmail, session_id=session_id,
                    )
                    if not existing:
                        await session_svc.create_session(
                            app_name="ai_ta",
                            user_id=user_gmail, session_id=session_id,
                            state=initial_state,
                        )

            async def _retrieve_rag():
                rag_query = " ".join(filter(None, [str(question), str(ta_chat)]))
                if rag_query.strip():
                    return await retrieve_context(course_handle, rag_query)
                return ""

            # Run DB/session setup and RAG retrieval concurrently
            _, rag_material = await asyncio.gather(
                _ensure_session_and_db(),
                _retrieve_rag(),
            )

            # --- Build the prompt parts ---

            if is_instructor:
                # Provide full context so the agent can give instructor-level suggestions
                if context:
                    parts.append(types.Part.from_text(text="{The topic content is:} " + truncate_text(str(context))))
                if question:
                    parts.append(types.Part.from_text(text="{The question is:} " + truncate_text(str(question))))
                if ta_chat:
                    parts.append(types.Part.from_text(text="{The instructor asks:} " + truncate_text(str(ta_chat))))
                if answer:
                    parts.append(types.Part.from_text(text="{The instructor's answer is} " + truncate_text(str(answer))))
                if output:
                    parts.append(types.Part.from_text(text="{The instructor's code output is} " + truncate_text(json.dumps(output), MAX_OUTPUT_CHARS)))
                runner = config.get_runner("instructor", courses, course_handle)
            else:
                # Student path — use cached rubric data without revealing the answer
                if notebook_id not in courses[course_handle]:
                    yield json.dumps({"type": "error", "detail": "Rubric notebook data not found for this course and notebook. Please ask the instructor to add the rubric first."}) + "\n"
                    return

                context = courses[course_handle][notebook_id]['context'].get(str(qnum))
                question = courses[course_handle][notebook_id]['questions'].get(str(qnum))
                if question is None:
                    yield json.dumps({"type": "error", "detail": "Question not found in rubric for this course and notebook."}) + "\n"
                    return
                rubric_answer = courses[course_handle][notebook_id]['answers'].get(str(qnum))
                rubric_output = courses[course_handle][notebook_id].get('outputs', {}).get(str(qnum))

                if context is not None:
                    parts.append(types.Part.from_text(text="{The context is:} " + truncate_text(str(context))))
                parts.append(types.Part.from_text(text="{The question is:} " + truncate_text(str(question))))
                parts.append(types.Part.from_text(text="{The student's answer is} " + truncate_text(str(answer))))
                if output:
                    parts.append(types.Part.from_text(text="{The student's code output is} " + truncate_text(json.dumps(output), MAX_OUTPUT_CHARS)))
                parts.append(types.Part.from_text(text="{The student asks:} " + truncate_text(str(ta_chat))))
                if rubric_answer is not None:
                    parts.append(types.Part.from_text(text="{The rubric is} " + truncate_text(str(rubric_answer))))
                if rubric_output is not None:
                    parts.append(types.Part.from_text(text="{The rubric code output is} " + truncate_text(str(rubric_output), MAX_OUTPUT_CHARS)))
                runner = config.get_runner("student", courses, course_handle)

            # Prepend RAG material if available
            if rag_material:
                parts.insert(0, types.Part.from_text(
                    text="{Relevant course material:} " + truncate_text(rag_material)
                ))

            # Final safety net: ensure total prompt size is within limits
            total_chars = sum(len(p.text or "") for p in parts)
            if total_chars > MAX_TOTAL_PROMPT_CHARS:
                logging.warning("Total prompt size %d chars exceeds limit %d. Truncating largest parts.", total_chars, MAX_TOTAL_PROMPT_CHARS)
                # Truncate the largest parts proportionally
                ratio = MAX_TOTAL_PROMPT_CHARS / total_chars
                for idx, p in enumerate(parts):
                    if p.text and len(p.text) > 10000:
                        parts[idx] = types.Part.from_text(text=truncate_text(p.text, int(len(p.text) * ratio)))

            content = types.Content(role="user", parts=parts)

            yield json.dumps({"type": "progress", "message": "Formed the prompt and asking the Tutor now..."}) + "\n"

            # --- Call the agent with heartbeat to prevent client read-timeout ---
            agent_task = asyncio.create_task(
                run_agent_and_get_response(session_id, user_gmail, content, runner)
            )
            while not agent_task.done():
                done, _ = await asyncio.wait({agent_task}, timeout=15)
                if not done:
                    yield json.dumps({"type": "heartbeat"}) + "\n"
            response_text = agent_task.result()

            if not response_text:
                yield json.dumps({"type": "error", "detail": "Failed to generate response"}) + "\n"
                return

            yield json.dumps({"type": "response", "response": response_text}) + "\n"

        except HTTPException as e:
            yield json.dumps({"type": "error", "detail": e.detail}) + "\n"
        except Exception as e:
            logging.error("An exception occurred during query processing: %s", e)
            traceback.print_exc()
            yield json.dumps({"type": "error", "detail": f"An internal error occurred: {e}"}) + "\n"

    return StreamingResponse(_generate(), media_type="application/x-ndjson")


@app.post("/grade", response_model=GradeResponse)
async def grade(query_body: GradeRequest, request: Request):

    '''Grade a single question-answer'''
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)
    runner = config.get_runner("scoring", courses, course_handle)

    if ('user' in request.session) : #user is logged and authenticated
        user_id = request.session['user']['id']
        user_email = request.session['user'].get('email')
    else:
        user_id = query_body.student_id
        # Try to get email from JWT token for rate limiting
        try:
            jwt_user = get_current_user(request)
            user_email = jwt_user.get('email')
        except Exception:
            user_email = None

    # Per-student rate limit (only for authenticated non-instructors)
    if user_email and not is_authorized(user_email, course_handle):
        check_student_rate_limit(user_email, course_handle)

    try:
        if not query_body.question:
            raise HTTPException(status_code=400, detail="Question not provided")

        question = query_body.question + "."
        answer = query_body.answer + "." if query_body.answer else "No answer."
        rubric = query_body.rubric if query_body.rubric else "No rubric"

        marks, response_text = await score_question(question, answer, rubric, runner, config.get_session_service("scoring", course_handle), user_id)

        return GradeResponse(
            response=response_text,
            marks=marks
        )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during query processing: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/regrade_answer", response_model=RegradeAnswerResponse)
async def regrade_answer(query_body: RegradeAnswerRequest, request: Request):
    '''Regrade a specific question for a student, optionally incorporating the student's contention.

    Fetches the student's answer, rubric, and the previous grader response from the database,
    then re-scores the question with the contention context included.
    Only accessible to instructors/admins.
    '''

    user = get_current_user(request)
    user_gmail = user.get('email', '').lower()

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    if course_handle not in courses:
        raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found.")

    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="Only instructors can use the regrade_answer endpoint.")

    notebook_id = query_body.notebook_id
    student_id = query_body.student_id
    qnum_str = str(query_body.qnum)

    # Validate rubric data exists
    if notebook_id not in courses[course_handle]:
        raise HTTPException(status_code=404, detail=f"Rubric notebook data not found for notebook '{notebook_id}' in course '{course_handle}'. Please add the rubric first.")

    rubric_data = courses[course_handle].get(notebook_id)
    rubric_questions = rubric_data.get('questions', {})
    rubric_answers = rubric_data.get('answers', {})
    max_marks_total = rubric_data.get('max_marks', 0.0)

    rubric_question_data = rubric_questions.get(qnum_str, {})
    rubric_question = rubric_question_data.get('question', '')
    if not rubric_question:
        raise HTTPException(status_code=404, detail=f"No rubric question found for Q{qnum_str}.")

    rubric_question_marks = rubric_question_data.get('marks', 10.0)
    rubric_answer = rubric_answers.get(qnum_str, '')
    rubric_answer_str = truncate_text(" ".join(
        f"({float(a.get('percent'))/100.0*rubric_question_marks}) {a.get('component', '')}"
        for a in rubric_answer
    ))

    try:
        # Fetch student's answers and existing grader response
        answers = await get_student_notebook_answers(config.db, course_handle, student_id, notebook_id)
        if not answers:
            raise HTTPException(status_code=404, detail=f"No submitted answers found for student '{student_id}' notebook '{notebook_id}'.")

        student_answer = answers.get(qnum_str)
        student_answer_str = truncate_text(" ".join(
            f"{a.get('component', '')}"
            for a in student_answer
        )) if student_answer else "No answer."

        # Fetch existing grader response for context
        grader_response = await fetch_grader_response(config.db, course_handle, notebook_id, student_id)

        # Check if already graded — skip unless do_regrade is True
        if not query_body.do_regrade and grader_response:
            existing_feedback = grader_response.get('feedback', {})
            existing_q = existing_feedback.get(qnum_str)
            if existing_q:
                raise HTTPException(status_code=409, detail=f"Q{qnum_str} already graded for student '{student_id}'. Set do_regrade=true to regrade.")

        # Build the augmented rubric answer with previous grading + student contention
        augmented_answer = rubric_answer_str
        if grader_response:
            existing_feedback = grader_response.get('feedback', {})
            prev_q_response = existing_feedback.get(qnum_str, {})
            if prev_q_response:
                prev_response_text = prev_q_response.get('response', '')
                augmented_answer += f"\n\n{{agent's grading}}\n{prev_response_text}"

        if query_body.student_contends:
            augmented_answer += f"\n\n{{student's contention}}\n{query_body.student_contends}"

        # RAG retrieval + scoring
        runner = config.get_runner("scoring", courses, course_handle)

        rag_material = await retrieve_context(course_handle, rubric_question)
        marks, response_text = await score_question(
            rubric_question, student_answer_str, augmented_answer,
            runner, config.get_session_service("scoring", course_handle), student_id,
            course_material=rag_material
        )
        logging.info(f"Regraded Q{qnum_str} for {student_id}: {marks} marks")

        # Update the grader_response for this question in the DB
        existing_graded = {}
        if grader_response and grader_response.get('feedback'):
            existing_graded = {k: v for k, v in grader_response['feedback'].items()}

        # Preserve the full history: new response first, then old marks/response
        prev_q = existing_graded.get(qnum_str, {})
        prev_marks = prev_q.get('marks', 0.0)
        prev_response = prev_q.get('response', '')
        combined_response = f"{{regraded response}}\n{response_text}"
        if query_body.student_contends:
            combined_response += f"\n\n{{student's contention}}\n{query_body.student_contends}"
        combined_response += f"\n\n[previous marks]={prev_marks}\n[previous response]={prev_response}"

        existing_graded[qnum_str] = {'marks': marks, 'response': combined_response}

        # Recalculate total marks across all questions
        total_marks = sum(q.get('marks', 0.0) for q in existing_graded.values())

        await update_marks(config.db, course_handle, student_id, notebook_id, total_marks, max_marks_total, existing_graded)

        return RegradeAnswerResponse(
            response=response_text,
            marks=marks
        )

    except HTTPException:
        raise
    except Exception as e:
        logging.error("An exception occurred during regrade_answer: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/eval")
async def eval_submission(query_body: EvalRequest, request: Request):
    '''Evaluate the submitted notebook by grading all questions using the scoring agent.

    The client sends pre-parsed questions, answers, and outputs from the student's notebook.
    The rubric (expected answers) is loaded from the server-side course cache.
    Each question is scored individually using the scoring agent.

    Returns a streaming response with newline-delimited JSON lines:
      {"type": "progress", "message": "..."}   – per-question progress
      {"type": "response", "response": "..."}   – final summary
      {"type": "error", "detail": "..."}         – on failure
    '''

    user = get_current_user(request)
    user_gmail = user.get('email')
    user_name = user.get('name')

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    if course_handle not in courses:
        raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found.")

    notebook_id = query_body.notebook_id

    # Check if eval is enabled for this specific notebook
    notebook_data = courses[course_handle].get(notebook_id)
    if not notebook_data or not notebook_data.get('isactive_eval', False):
        raise HTTPException(status_code=503, detail=f"The evaluation API endpoint is currently inactive for notebook '{notebook_id}'.")

    # Per-student rate limit (skipped for instructors)
    if not is_authorized(user_gmail, course_handle):
        check_student_rate_limit(user_gmail, course_handle)

    runner = config.get_runner("scoring", courses, course_handle)

    async def _generate():
        try:
            if notebook_id not in courses[course_handle]:
                yield json.dumps({"type": "error", "detail": "Rubric notebook data not found for this course and notebook. Please ask the instructor to add the rubric first."}) + "\n"
                return

            # Get rubric from the course cache
            rubric_data = courses[course_handle].get(notebook_id)
            if not rubric_data:
                yield json.dumps({"type": "error", "detail": f"Rubric data not found for notebook '{notebook_id}' in course '{course_handle}'."}) + "\n"
                return

            rubric_questions = rubric_data.get('questions', {})
            rubric_answers = rubric_data.get('answers', {})
            max_marks_total = rubric_data.get('max_marks', 0.0)

            # Ensure student record exists (run both DB calls concurrently)
            await asyncio.gather(
                add_student_if_not_exists(config.db, course_handle, user_gmail, user_name),
                add_student_notebook_if_not_exists(config.db, course_handle, user_gmail, user_name, notebook_id),
            )

            # Store student answers in the notebook document
            await save_student_answers(config.db, course_handle, user_gmail, notebook_id, query_body.answers)

            yield json.dumps({"type": "progress", "message": "Your notebook has been saved in the server and has also been queued for evaluation. Once the evaluation is complete, the graded notebook will be sent via email."}) + "\n"

            # --- Build per-question grading tasks ---

            async def _grade_one(qnum_str, student_answer):
                """Grade a single question: RAG retrieval + scoring agent call."""
                rubric_question = rubric_questions.get(qnum_str, '').get('question', '')
                rubric_question_marks = rubric_questions.get(qnum_str).get('marks', 10.0)
                rubric_answer = rubric_answers.get(qnum_str, '')
                rubric_answer_str = truncate_text(" ".join(
                    f"({float(a.get('percent'))/100.0*rubric_question_marks}) {a.get('component', '')}"
                    for a in rubric_answer
                ))
                logging.info(f"Grading Q{qnum_str}: rubric question='{rubric_question}', rubric answer='{rubric_answer_str}'")
                student_answer_str = truncate_text(" ".join(
                    f"{a.get('component', '')}"
                    for a in student_answer
                )) if student_answer else ""

                if not rubric_question:
                    logging.error(f"No rubric question found for Q{qnum_str}. Skipping.")
                    raise HTTPException(status_code=404, detail=f"Rubric question not found for question number '{qnum_str}' in notebook '{notebook_id}'.")

                # RAG retrieval + scoring run concurrently across questions
                rag_material = await retrieve_context(course_handle, rubric_question)
                marks, response_text = await score_question(
                    rubric_question, str(student_answer_str), str(rubric_answer_str),
                    runner, config.get_session_service("scoring", course_handle), user_gmail,
                    course_material=rag_material
                )
                logging.info(f"Graded Q{qnum_str}: {marks} marks")
                return qnum_str, marks, response_text

            # Launch all questions concurrently as tasks
            tasks = [
                asyncio.create_task(_grade_one(qnum_str, student_answer))
                for qnum_str, student_answer in query_body.answers.items()
            ]
            graded = {}
            total_marks = 0.0
            num_questions = len(tasks)
            pending_tasks = set(tasks)
            while pending_tasks:
                # Wait up to 15s for any task to complete; send heartbeat if none do
                done, pending_tasks = await asyncio.wait(pending_tasks, timeout=15, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    yield json.dumps({"type": "heartbeat"}) + "\n"
                    continue
                for finished in done:
                    qnum_str, marks, response_text = finished.result()
                    total_marks += marks
                    graded[qnum_str] = {'marks': marks, 'response': response_text}
                    yield json.dumps({"type": "progress", "message": f"Done evaluating question {qnum_str}"}) + "\n"

            logging.info(f"{user_name}: Evaluation completed. Total Marks: {total_marks}/{max_marks_total} for {num_questions} questions.")

            # Store marks in database
            await update_marks(config.db, course_handle, user_gmail, notebook_id, total_marks, max_marks_total, graded)

            yield json.dumps({"type": "response", "response": f"{user_name}: Evaluation completed. Total Marks: {total_marks}/{max_marks_total} for {num_questions} questions."}) + "\n"

        except Exception as e:
            logging.error("An exception occurred during evaluation: %s", e)
            traceback.print_exc()
            yield json.dumps({"type": "error", "detail": f"An internal error occurred: {e}"}) + "\n"

    return StreamingResponse(_generate(), media_type="application/x-ndjson")


@app.post("/grade_notebook")
async def grade_notebook(query_body: GradeNotebookRequest, request: Request):
    '''Grade a student's (or all students') submitted notebook from the database.

    Reads the student's previously submitted answers from Firestore, grades them
    against the rubric stored in the course cache, and streams progress back.

    If student_id is "All", grades every student enrolled in the course who has
    submitted answers for the given notebook.

    Returns a streaming response with newline-delimited JSON lines:
      {"type": "progress", "message": "..."}   - per-question / per-student progress
      {"type": "response", "response": "..."}   - final summary
      {"type": "error", "detail": "..."}         - on failure
    '''

    user = get_current_user(request)
    user_gmail = user.get('email')

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    if course_handle not in courses:
        raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found.")

    # Only instructors / admins may use this endpoint
    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="Only instructors can use the grade_notebook endpoint.")

    runner = config.get_runner("scoring", courses, course_handle)
    notebook_id = query_body.notebook_id

    # Validate rubric data exists for the notebook
    if notebook_id not in courses[course_handle]:
        raise HTTPException(status_code=404, detail=f"Rubric notebook data not found for notebook '{notebook_id}' in course '{course_handle}'. Please add the rubric first.")

    rubric_data = courses[course_handle].get(notebook_id)
    rubric_questions = rubric_data.get('questions', {})
    rubric_answers = rubric_data.get('answers', {})
    max_marks_total = rubric_data.get('max_marks', 0.0)

    # Build list of students to grade
    if query_body.student_id.lower() == "all":
        student_ids = await get_student_list(config.db, course_handle)
    else:
        student_ids = [query_body.student_id]

    async def _grade_one_question(qnum_str, student_answer, student_id):
        """Grade a single question for a student: RAG retrieval + scoring agent call."""
        rubric_question = rubric_questions.get(qnum_str, {}).get('question', '')
        rubric_question_marks = rubric_questions.get(qnum_str, {}).get('marks', 10.0)
        rubric_answer = rubric_answers.get(qnum_str, '')
        rubric_answer_str = " ".join(
            f"({float(a.get('percent'))/100.0*rubric_question_marks}) {a.get('component', '')}"
            for a in rubric_answer
        )
        student_answer_str = " ".join(
            f"{a.get('component', '')}"
            for a in student_answer
        ) if student_answer else ""

        if not rubric_question:
            logging.error(f"No rubric question found for Q{qnum_str}. Skipping.")
            return qnum_str, 0.0, f"No rubric question found for Q{qnum_str}."

        try:
            rag_material = await retrieve_context(course_handle, rubric_question)
            marks, response_text = await score_question(
                rubric_question, str(student_answer_str), str(rubric_answer_str),
                runner, config.get_session_service("scoring", course_handle), student_id,
                course_material=rag_material
            )
            logging.info(f"Graded Q{qnum_str} for {student_id}: {marks} marks")
            return qnum_str, marks, response_text
        except Exception as e:
            logging.error(f"Error grading Q{qnum_str} for {student_id}: {e}")
            return qnum_str, 0.0, f"Error grading question: {e}"

    async def _grade_one_student(student_id):
        """Grade all questions for a single student. Returns (student_id, total_marks, graded_dict) or None if skipped."""
        # Skip students whose notebooks are already graded (unless regrading)
        if not query_body.do_regrade and await is_notebook_graded(config.db, course_handle, student_id, notebook_id):
            logging.info(f"Student '{student_id}' notebook '{notebook_id}' already graded. Skipping.")
            return None

        answers = await get_student_notebook_answers(config.db, course_handle, student_id, notebook_id)
        if not answers:
            logging.info(f"No submitted answers for student '{student_id}' notebook '{notebook_id}'. Skipping.")
            return None

        tasks = [
            asyncio.create_task(_grade_one_question(qnum_str, student_answer, student_id))
            for qnum_str, student_answer in answers.items()
        ]

        graded = {}
        total_marks = 0.0
        try:
            for finished in asyncio.as_completed(tasks):
                qnum_str, marks, response_text = await finished
                total_marks += marks
                graded[qnum_str] = {'marks': marks, 'response': response_text}
        except Exception:
            # Cancel remaining tasks and suppress their exceptions
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        # Store marks in database
        await update_marks(config.db, course_handle, student_id, notebook_id, total_marks, max_marks_total, graded)

        return student_id, total_marks, graded

    # Launch grading tasks *before* entering the streaming generator so they
    # are not tied to the response lifecycle.  Each task writes its results to
    # the DB independently, so even if the HTTP stream is torn down (e.g. the
    # server starts shutting down) the grading work will run to completion.
    student_tasks = [
        asyncio.create_task(_grade_one_student(sid))
        for sid in student_ids
    ]

    async def _generate():
        try:
            yield json.dumps({"type": "progress", "message": f"Starting grading for {len(student_ids)} student(s), notebook '{notebook_id}'."}) + "\n"

            graded_count = 0
            skipped_count = 0
            results_summary = []
            pending_tasks = set(student_tasks)

            while pending_tasks:
                done, pending_tasks = await asyncio.wait(pending_tasks, timeout=15, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    yield json.dumps({"type": "heartbeat"}) + "\n"
                    continue
                for finished in done:
                    try:
                        result = finished.result()
                    except Exception as e:
                        logging.error(f"Error grading a student: {e}")
                        yield json.dumps({"type": "progress", "message": f"Error grading a student: {e}"}) + "\n"
                        continue

                    if result is None:
                        skipped_count += 1
                        yield json.dumps({"type": "progress", "message": f"Skipped a student (already graded or no submitted answers). Progress: {graded_count + skipped_count}/{len(student_ids)}"}) + "\n"
                    else:
                        student_id, total_marks, _ = result
                        graded_count += 1
                        results_summary.append({"student_id": student_id, "total_marks": total_marks, "max_marks": max_marks_total})
                        yield json.dumps({"type": "progress", "message": f"Graded {student_id}: {total_marks}/{max_marks_total}. Progress: {graded_count + skipped_count}/{len(student_ids)}"}) + "\n"

            summary = f"Grading complete. {graded_count} student(s) graded, {skipped_count} skipped (already graded or no submission)."
            logging.info(summary)
            yield json.dumps({"type": "response", "response": summary, "results": results_summary}) + "\n"

        except asyncio.CancelledError:
            # Stream was torn down (client disconnect or server shutdown).
            # The grading tasks are independent top-level tasks and will
            # continue running; just log and exit the generator cleanly.
            logging.warning("grade_notebook stream cancelled; grading tasks will continue in the background.")
            return

        except Exception as e:
            logging.error("An exception occurred during grade_notebook: %s", e)
            traceback.print_exc()
            yield json.dumps({"type": "error", "detail": f"An internal error occurred: {e}"}) + "\n"

    return StreamingResponse(_generate(), media_type="application/x-ndjson")


# ==================== Utility Endpoints ====================

@app.get("/", tags=["Instructor Dashboard"], response_class=HTMLResponse)
async def instructor_dashboard(request: Request):
    """Instructor / TA dashboard.

    If the visitor is logged in (session or JWT), serve the dashboard HTML.
    The page calls /my_courses to populate the course picker and renders a
    grid of buttons that open per-endpoint forms.

    If not logged in, redirect to /login with ``?next=/`` so the user lands
    back here after OAuth.
    """
    try:
        get_current_user(request)
    except HTTPException:
        return RedirectResponse(url="/login?next=/", status_code=302)

    return HTMLResponse(content=_render_dashboard_html(), status_code=200)


@app.get("/admin", tags=["Authentication"], response_class=HTMLResponse)
async def admin_login_page(request: Request):
    """Admin login page (formerly served at /).

    Sets ``admin_login=True`` so the OAuth callback verifies admin access.
    Lands on /docs after successful admin auth.
    """
    request.session['admin_login'] = True
    html_content = """
    <html>
        <head>
            <title>Admin Login — AI Teaching Assistant Platform</title>
        </head>
        <body>
            <h1>Admin Login</h1>
            <p>Platform administrators sign in here to access /docs and admin endpoints.
               Instructors and TAs can use the <a href="/">dashboard</a> directly.</p>
            <form action="/login" method="get">
                <button type="submit" style="padding: 10px 20px; font-size: 16px; cursor: pointer;">Login with Google (Admin)</button>
            </form>
            <br><br>
            <p style="font-size: 12px; color: #666;">
                Having login issues? Check <a href="/session-test">session test</a>
            </p>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)


def _render_dashboard_html() -> str:
    """Return the static instructor-dashboard HTML.

    Single-page app: course picker at top, sections of buttons below. Each
    button toggles an inline form. Forms POST JSON to existing endpoints
    (session cookie carries auth). Streaming endpoints render ndjson
    progress into an inline output panel.
    """
    return DASHBOARD_HTML


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AI-TA Instructor Dashboard</title>
<style>
:root {
  --bg: #f6f7f9;
  --panel: #ffffff;
  --border: #d8dde3;
  --text: #1f2328;
  --muted: #57606a;
  --accent: #0969da;
  --accent-hover: #0860c2;
  --success: #1a7f37;
  --error: #cf222e;
  --warn: #9a6700;
}
* { box-sizing: border-box; }
body {
  margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg); color: var(--text); font-size: 14px;
}
header {
  background: var(--panel); border-bottom: 1px solid var(--border);
  padding: 12px 24px; display: flex; align-items: center; gap: 24px;
  position: sticky; top: 0; z-index: 10;
}
header h1 { font-size: 18px; margin: 0; }
header .spacer { flex: 1; }
header .user { color: var(--muted); font-size: 13px; }
main { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
.course-picker {
  background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px; margin-bottom: 20px;
}
.course-picker label { display: block; font-weight: 600; margin-bottom: 6px; }
.course-picker select { width: 100%; padding: 8px; border-radius: 6px; border: 1px solid var(--border); font-size: 14px; }
.course-picker .hint { color: var(--muted); font-size: 12px; margin-top: 6px; }
.section {
  background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px; margin-bottom: 16px;
}
.section h2 { font-size: 15px; margin: 0 0 10px 0; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
.button-row { display: flex; flex-wrap: wrap; gap: 8px; }
.svc-btn {
  background: var(--panel); border: 1px solid var(--border); color: var(--text);
  padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px;
}
.svc-btn:hover { border-color: var(--accent); color: var(--accent); }
.svc-btn.active { background: var(--accent); color: white; border-color: var(--accent); }
.svc-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.form-panel {
  display: none; margin-top: 12px; padding: 14px;
  background: #f6f8fa; border: 1px solid var(--border); border-radius: 6px;
}
.form-panel.open { display: block; }
.form-panel label { display: block; margin: 8px 0 4px; font-weight: 600; font-size: 13px; }
.form-panel input[type=text], .form-panel input[type=number], .form-panel select, .form-panel textarea {
  width: 100%; padding: 7px 9px; border: 1px solid var(--border); border-radius: 5px;
  font-size: 13px; font-family: inherit;
}
.form-panel textarea { min-height: 80px; resize: vertical; font-family: ui-monospace, monospace; }
.form-panel .row { display: flex; gap: 12px; }
.form-panel .row > div { flex: 1; }
.form-panel button[type=submit] {
  background: var(--accent); color: white; border: none; padding: 8px 16px;
  border-radius: 5px; cursor: pointer; font-size: 13px; margin-top: 12px;
}
.form-panel button[type=submit]:hover { background: var(--accent-hover); }
.form-panel button[type=submit]:disabled { opacity: 0.5; cursor: progress; }
.output {
  margin-top: 12px; padding: 10px; background: #ffffff; border: 1px solid var(--border);
  border-radius: 5px; font-family: ui-monospace, monospace; font-size: 12px;
  max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-word;
}
.output:empty { display: none; }
.output .ok { color: var(--success); }
.output .err { color: var(--error); }
.output .warn { color: var(--warn); }
.empty {
  text-align: center; color: var(--muted); padding: 40px 20px;
}
.empty a { color: var(--accent); }
.empty code { background: #eef0f3; padding: 2px 6px; border-radius: 3px; }
</style>
</head>
<body>
<header>
  <h1>AI-TA Instructor Dashboard</h1>
  <div class="spacer"></div>
  <span class="user" id="user-info"></span>
  <a href="/logout" style="color: var(--muted); font-size: 13px;">Sign out</a>
</header>

<main>
  <div class="course-picker">
    <label for="course-select">Course</label>
    <select id="course-select">
      <option value="">Loading…</option>
    </select>
    <div class="hint" id="course-hint">Select a course to enable the actions below.</div>
  </div>

  <div id="dashboard-body">
    <div class="empty">
      Forms will appear here once a course is selected.
      <br><br>
      Don't see your course? Make sure your email is set as
      <code>instructor_email</code>, <code>instructor_gmail</code>,
      <code>ta_email</code>, or <code>ta_gmail</code> on the course document
      in Firestore.
    </div>
  </div>
</main>

<script>
const state = { course: null, courses: [] };

async function loadUser() {
  try {
    const r = await fetch('/whoami');
    if (r.ok) {
      const u = await r.json();
      document.getElementById('user-info').textContent = `${u.name || u.email}`;
    }
  } catch {}
}

async function loadCourses() {
  const sel = document.getElementById('course-select');
  const hint = document.getElementById('course-hint');
  try {
    const r = await fetch('/my_courses');
    if (!r.ok) {
      sel.innerHTML = '<option value="">Not authenticated</option>';
      return;
    }
    const data = await r.json();
    state.courses = data.courses;
    if (data.courses.length === 0) {
      sel.innerHTML = '<option value="">No courses found</option>';
      hint.textContent = 'You are not listed as instructor or TA on any course.';
      return;
    }
    sel.innerHTML = '<option value="">— select a course —</option>';
    for (const c of data.courses) {
      const label = `${c.course_id || '?'} (${c.term_id || '?'}, ${c.institution_id || '?'}) [${c.role}]`;
      sel.innerHTML += `<option value="${c.course_handle}">${label}</option>`;
    }
  } catch (e) {
    sel.innerHTML = '<option value="">Error</option>';
    hint.textContent = 'Failed to load courses: ' + e.message;
  }
}

document.getElementById('course-select').addEventListener('change', (e) => {
  const handle = e.target.value;
  state.course = state.courses.find(c => c.course_handle === handle) || null;
  renderDashboard();
});

function renderDashboard() {
  const body = document.getElementById('dashboard-body');
  if (!state.course) {
    body.innerHTML = '<div class="empty">Forms will appear here once a course is selected.</div>';
    return;
  }
  // Forms are wired up in a follow-up commit; this is the skeleton placeholder.
  body.innerHTML = `
    <div class="section">
      <h2>Selected course</h2>
      <p><strong>${state.course.course_id || '?'}</strong>
         — ${state.course.term_id || '?'} @ ${state.course.institution_id || '?'}
         (role: ${state.course.role})</p>
      <p style="color: var(--muted); font-size: 12px;">
        Service buttons (rubric upload, ingest, grade, regrade, marks, etc.)
        will be wired up in subsequent commits.
      </p>
    </div>
  `;
}

loadUser();
loadCourses();
</script>
</body>
</html>
"""

@app.get("/session-test")
async def session_test(request: Request):
    """
    Diagnostic endpoint to test if sessions are working properly.
    Useful for debugging OAuth state mismatch issues.
    """
    # Try to get an existing test value
    test_value = request.session.get('test_value', None)

    # Set a new test value
    import time
    new_value = f"test_{int(time.time())}"
    request.session['test_value'] = new_value

    return {
        "message": "Session test endpoint",
        "previous_test_value": test_value,
        "new_test_value": new_value,
        "session_keys": list(request.session.keys()),
        "cookies_received": list(request.cookies.keys()),
        "instructions": "Refresh this page. If 'previous_test_value' matches the previous 'new_test_value', sessions are working."
    }


# ==================== Instructor-or-admin-Only Endpoints ====================
def is_authorized(user_gmail: str, course_handle: str) -> bool:
    """Check if the user is an instructor or TA for the course, or a platform admin.

    For this version TAs have the same authorization scope as instructors.
    """
    if not user_gmail:
        return False
    user_lower = user_gmail.lower()

    # Platform admin is always authorized
    if user_lower == config.admin_email:
        return True

    # Check all instructor / TA email fields on the course
    course_data = courses.get(course_handle, {})
    for field in ('instructor_gmail', 'instructor_email', 'created_by',
                  'ta_gmail', 'ta_email'):
        value = course_data.get(field)
        if value and user_lower == value.lower():
            return True

    return False


def _course_role(user_email: str, course_data: dict) -> str | None:
    """Return 'admin', 'instructor', 'ta', or None for the user's role on a course."""
    if not user_email:
        return None
    user_lower = user_email.lower()
    if user_lower == config.admin_email:
        return "admin"

    instructor_fields = ('instructor_gmail', 'instructor_email', 'created_by')
    ta_fields = ('ta_gmail', 'ta_email')

    for field in instructor_fields:
        value = course_data.get(field)
        if value and user_lower == value.lower():
            return "instructor"
    for field in ta_fields:
        value = course_data.get(field)
        if value and user_lower == value.lower():
            return "ta"
    return None


@app.get("/my_courses")
async def my_courses(request: Request):
    """List courses the current user can manage (instructor, TA, or admin).

    Used by the instructor dashboard to populate the course picker so every
    subsequent form is scoped to a course the user is authorized for.

    Admins see every course in the cache. Instructors and TAs see only the
    courses where their email matches one of the role fields.
    """
    user = get_current_user(request)
    user_email = (user.get('email') or '').lower()
    is_admin = user_email == config.admin_email

    out = []
    for course_handle, course_data in courses.items():
        if is_admin:
            role = "admin"
        else:
            role = _course_role(user_email, course_data)
            if role is None:
                continue
        out.append({
            "course_handle": course_handle,
            "institution_id": course_data.get('institution_id'),
            "term_id": course_data.get('term_id'),
            "course_id": course_data.get('course_id'),
            "course_name": course_data.get('course_name'),
            "instructor_name": course_data.get('instructor_name'),
            "role": role,
        })
    out.sort(key=lambda c: (c.get('institution_id') or '', c.get('term_id') or '',
                            c.get('course_id') or ''))
    return {"courses": out}


def check_student_rate_limit(user_email: str, course_handle: str) -> None:
    """Raise HTTP 429 if the student has exceeded their rate limit for this course."""
    course_data = courses.get(course_handle, {})
    max_requests = course_data.get('student_rate_limit')
    if max_requests is None:
        return  # Rate limiting not configured

    window = course_data.get('student_rate_limit_window') or DEFAULT_RATE_LIMIT_WINDOW

    if not student_rate_limiter.check_and_record(course_handle, user_email, max_requests, window):
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. You are allowed {max_requests} AI requests "
                   f"per {window // 60} minute(s) for this course. Please try again later."
        )


@app.post("/disable_tutor")
async def disable_tutor(
    query_body: TutorInteractionRequest,
    request: Request
):
    '''
    Disable the tutor (assist endpoint).
    This endpoint is only accessible to instructors.
    '''

    user = get_current_user(request)

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    try:
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin")
        courses[course_handle]['isactive_tutor'] = False
        await update_course_info(config.db, course_handle, 'isactive_tutor', False)
        logging.info(f"Instructor {user.get('email')} has disabled the tutor")
        return {"message": "Tutor has been disabled successfully"}
    except Exception as e:
        logging.error("An exception occurred during disable_tutor: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/enable_tutor")
async def enable_tutor(
    query_body: TutorInteractionRequest,
    request: Request
    ):
    '''
    Enable the tutor (assist endpoint).
    This endpoint is only accessible to instructors.
    '''
    user = get_current_user(request)

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    try:
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin")
        courses[course_handle]['isactive_tutor'] = True
        await update_course_info(config.db, course_handle, 'isactive_tutor', True)
        logging.info(f"Instructor {user_gmail} has enabled the tutor")
        return {"message": "Tutor has been enabled successfully"}
    except Exception as e:
        logging.error("An exception occurred during enable_tutor: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/disable_eval")
async def disable_eval(
    query_body: EvalToggleRequest,
    request: Request
):
    '''
    Disable the eval endpoint for a specific notebook.
    This endpoint is only accessible to instructors.
    '''
    user = get_current_user(request)

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)
    notebook_id = query_body.notebook_id

    try:
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle):
            raise HTTPException(status_code=403, detail="User is not an instructor for this course nor a platform admin")
        if course_handle not in courses or notebook_id not in courses[course_handle]:
            raise HTTPException(status_code=404, detail=f"Notebook '{notebook_id}' not found in course '{course_handle}'.")
        courses[course_handle][notebook_id]['isactive_eval'] = False
        await update_notebook_info(config.db, course_handle, notebook_id, 'isactive_eval', False)
        logging.info(f"Instructor {user_gmail} has disabled eval for notebook '{notebook_id}' in course '{course_handle}'")
        return {"message": f"Eval has been disabled for notebook '{notebook_id}'."}
    except HTTPException:
        raise
    except Exception as e:
        logging.error("An exception occurred during disable_eval: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/enable_eval")
async def enable_eval(
    query_body: EvalToggleRequest,
    request: Request
):
    '''
    Enable the eval endpoint for a specific notebook.
    This endpoint is only accessible to instructors.
    '''
    user = get_current_user(request)

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)
    notebook_id = query_body.notebook_id

    try:
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle):
            raise HTTPException(status_code=403, detail="User is not an instructor for this course nor a platform admin")
        if course_handle not in courses or notebook_id not in courses[course_handle]:
            raise HTTPException(status_code=404, detail=f"Notebook '{notebook_id}' not found in course '{course_handle}'.")
        courses[course_handle][notebook_id]['isactive_eval'] = True
        await update_notebook_info(config.db, course_handle, notebook_id, 'isactive_eval', True)
        logging.info(f"Instructor {user_gmail} has enabled eval for notebook '{notebook_id}' in course '{course_handle}'")
        return {"message": f"Eval has been enabled for notebook '{notebook_id}'."}
    except HTTPException:
        raise
    except Exception as e:
        logging.error("An exception occurred during enable_eval: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/update_course_config", response_model=UpdateCourseConfigResponse)
async def update_course_config(
    query_body: UpdateCourseConfigRequest,
    request: Request
):
    '''Update per-course configuration (model, isactive_tutor, student_rate_limit, student_rate_limit_window).
    Only accessible to instructors or platform admins.'''
    user = get_current_user(request)
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    user_gmail = user.get('email', '').lower()
    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="User is not an instructor for this course nor a platform admin")

    if course_handle not in courses:
        raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found.")

    updated = {}
    try:
        if query_body.model is not None:
            courses[course_handle]['model'] = query_body.model
            await update_course_info(config.db, course_handle, 'model', query_body.model)
            updated['model'] = query_body.model

        if query_body.isactive_tutor is not None:
            courses[course_handle]['isactive_tutor'] = query_body.isactive_tutor
            await update_course_info(config.db, course_handle, 'isactive_tutor', query_body.isactive_tutor)
            updated['isactive_tutor'] = query_body.isactive_tutor

        if query_body.student_rate_limit is not None:
            # 0 means disabled (store as None)
            val = query_body.student_rate_limit if query_body.student_rate_limit > 0 else None
            courses[course_handle]['student_rate_limit'] = val
            await update_course_info(config.db, course_handle, 'student_rate_limit', val)
            updated['student_rate_limit'] = val
            student_rate_limiter.clear_course(course_handle)

        if query_body.student_rate_limit_window is not None:
            courses[course_handle]['student_rate_limit_window'] = query_body.student_rate_limit_window
            await update_course_info(config.db, course_handle, 'student_rate_limit_window', query_body.student_rate_limit_window)
            updated['student_rate_limit_window'] = query_body.student_rate_limit_window
            student_rate_limiter.clear_course(course_handle)

        if not updated:
            raise HTTPException(status_code=400, detail="No configuration fields provided to update.")

        logging.info(f"User {user_gmail} updated course config for '{course_handle}': {updated}")
        return UpdateCourseConfigResponse(updated=updated)

    except HTTPException:
        raise
    except Exception as e:
        logging.error("Error updating course config: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/rate_limit_status")
async def rate_limit_status(query_body: TutorInteractionRequest, request: Request):
    '''Get per-student rate limit usage for a course. Instructor-only.'''
    user = get_current_user(request)
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    user_gmail = user.get('email', '').lower()
    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="Instructor access required")

    course_data = courses.get(course_handle, {})
    max_req = course_data.get('student_rate_limit')
    window = course_data.get('student_rate_limit_window') or DEFAULT_RATE_LIMIT_WINDOW

    if max_req is None:
        return {"rate_limiting": "disabled", "course": course_handle}

    usage = student_rate_limiter.get_course_usage(course_handle, max_req, window)
    return {
        "rate_limiting": "enabled",
        "max_requests": max_req,
        "window_seconds": window,
        "students": usage,
    }


@app.post("/update_global_config", response_model=UpdateGlobalConfigResponse)
async def update_global_config(
    query_body: UpdateGlobalConfigRequest,
    request: Request
):
    '''Update global server configuration (semaphore_limit).
    Only accessible to platform admins.'''
    user = get_admin_user(request)

    updated = {}
    try:
        if query_body.semaphore_limit is not None:
            update_semaphore_limit(query_body.semaphore_limit)
            updated['semaphore_limit'] = query_body.semaphore_limit

        if not updated:
            raise HTTPException(status_code=400, detail="No configuration fields provided to update.")

        logging.info(f"Admin {user.get('email')} updated global config: {updated}")
        return UpdateGlobalConfigResponse(updated=updated)

    except HTTPException:
        raise
    except Exception as e:
        logging.error("Error updating global config: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/fetch_marks_list", response_model=FetchMarksListResponse)
async def fetch_marks_list_api(
    query_body: FetchMarksListRequest,
    request: Request
):
    '''
    Fetch the list of students and marks.
    This endpoint is only accessible to instructors.
    '''
    user = get_current_user(request)
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    logging.info(f"{user.get('email')} is fetching student list")

    try:
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin")

        max_marks, marks_list = await get_marks_list(config.db, course_handle, notebook_id=query_body.notebook_id)
        logging.info(f"Found {len(marks_list)} students in course {course_handle}")

        return FetchMarksListResponse(
            max_marks=max_marks,
            marks_list=marks_list
        )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during fetch_marks_list_api: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/fetch_grader_response", response_model=FetchGradedResponse)
async def fetch_grader_response_api(
    query_body: FetchGradedRequest,
    request: Request
):
    '''
    Fetch the graded response for a student from the database.
    Instructors can fetch any student's grades.
    '''

    user = get_current_user(request)
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)


    try:

        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin")

        if not query_body.notebook_id:
            raise HTTPException(status_code=400, detail="notebook_id not provided")

        if not query_body.user_email:
            raise HTTPException(status_code=400, detail="user_email not provided")

        student_id = query_body.student_id

        grader_response = await fetch_grader_response(config.db, course_handle, query_body.notebook_id, student_id)
        if not grader_response:
            raise HTTPException(status_code=404, detail="No graded response found for the given student and notebook")

        return FetchGradedResponse(
            grader_response=grader_response
        )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during fetch_grader_response_api: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/notify_student_grades")
async def notify_student_grades_api(
    query_body: NotifyGradedRequest,
    request: Request
):
    '''Fetch the graded response for a student from the database and send email notification.

    If student_id is "All", sends email to all students who have graded submissions for the notebook.
    Otherwise sends to the specific student.

    Emails are sent as background tasks so the work continues even if the client disconnects.
    Each successful send is recorded in Firestore (email_notified_at). On retry, students
    who were already notified are skipped unless do_resend is True.

    Returns a streaming response with newline-delimited JSON lines:
      {"type": "progress", "message": "..."}   - per-student progress
      {"type": "response", "response": "..."}   - final summary
      {"type": "error", "detail": "..."}         - on failure
    '''

    user = get_current_user(request)
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    user_gmail = user.get('email', '').lower()
    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="User is not an instructor for this course nor a platform admin")

    notebook_id = query_body.notebook_id
    do_resend = query_body.do_resend

    # Build list of students to notify
    if query_body.student_id.lower() == "all":
        student_ids = await get_student_list(config.db, course_handle)
    else:
        student_ids = [query_body.student_id]

    if not student_ids:
        raise HTTPException(status_code=404, detail="No students found to notify.")

    async def _notify_one_student(student_id):
        """Send grade email to a single student. Returns (student_id, status_string)."""
        # Check if already notified (unless resending)
        if not do_resend and await is_email_notified(config.db, course_handle, student_id, notebook_id):
            logging.info(f"Student '{student_id}' already notified for notebook '{notebook_id}'. Skipping.")
            return student_id, "already_notified"

        grader_response = await fetch_grader_response(config.db, course_handle, notebook_id, student_id)
        if not grader_response:
            logging.warning(f"No graded response found for student_id={student_id} and notebook_id={notebook_id}. Skipping.")
            return student_id, "no_grades"

        total_marks = grader_response.get('total_marks', 0)
        max_marks = grader_response.get('max_marks', 0)
        subject = f"Graded Response for your submission {notebook_id}"
        msg_body = f"Hello {student_id},\n\n Your marks in {notebook_id} is {total_marks} out of {max_marks}. \n\nDetailed feedback for your submission"
        msg_body += json.dumps(grader_response, indent=4)
        msg_body += "\n\nBest regards,\nYour fiendly AI-TA"

        logging.info(f"Instructor {user_gmail} is sending email to {student_id} with subject '{subject}'")

        email_sent = send_email(config._mail_api_key, config._from_email, student_id, subject, msg_body)

        if email_sent:
            await mark_email_notified(config.db, course_handle, student_id, notebook_id)
            return student_id, "sent"
        else:
            logging.error(f"Failed to send email to {student_id}")
            return student_id, "failed"

    # Launch email tasks *before* entering the streaming generator so they
    # are not tied to the response lifecycle.  Each task persists its result
    # to Firestore independently, so even if the HTTP stream is torn down
    # the email work will run to completion.
    is_bulk = len(student_ids) > 1

    if is_bulk:
        # For bulk sends, stagger tasks with delays to avoid Gmail SMTP rate limits
        async def _notify_with_delay(student_id, delay):
            if delay > 0:
                await asyncio.sleep(delay)
            return await _notify_one_student(student_id)

        student_tasks = [
            asyncio.create_task(_notify_with_delay(sid, i * 10))
            for i, sid in enumerate(student_ids)
        ]
    else:
        student_tasks = [
            asyncio.create_task(_notify_one_student(sid))
            for sid in student_ids
        ]

    async def _generate():
        try:
            yield json.dumps({"type": "progress", "message": f"Starting email notifications for {len(student_ids)} student(s), notebook '{notebook_id}'."}) + "\n"

            sent_count = 0
            skipped_count = 0
            failed_count = 0
            pending_tasks = set(student_tasks)

            while pending_tasks:
                done, pending_tasks = await asyncio.wait(pending_tasks, timeout=15, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    yield json.dumps({"type": "heartbeat"}) + "\n"
                    continue
                for finished in done:
                    try:
                        student_id, status = finished.result()
                    except Exception as e:
                        logging.error(f"Error notifying a student: {e}")
                        failed_count += 1
                        yield json.dumps({"type": "progress", "message": f"Error notifying a student: {e}"}) + "\n"
                        continue

                    if status == "sent":
                        sent_count += 1
                        yield json.dumps({"type": "progress", "message": f"Email sent to {student_id}. Progress: {sent_count + skipped_count + failed_count}/{len(student_ids)}"}) + "\n"
                    elif status in ("no_grades", "already_notified"):
                        skipped_count += 1
                        reason = "already notified" if status == "already_notified" else "no graded response"
                        yield json.dumps({"type": "progress", "message": f"Skipped {student_id} ({reason}). Progress: {sent_count + skipped_count + failed_count}/{len(student_ids)}"}) + "\n"
                    else:
                        failed_count += 1
                        yield json.dumps({"type": "progress", "message": f"Failed to send email to {student_id}. Progress: {sent_count + skipped_count + failed_count}/{len(student_ids)}"}) + "\n"

            summary = f"Sent {sent_count} email(s), skipped {skipped_count} (no graded response or already notified), {failed_count} failed."
            logging.info(summary)
            yield json.dumps({"type": "response", "response": summary}) + "\n"

        except asyncio.CancelledError:
            # Stream was torn down (client disconnect or server shutdown).
            # The email tasks are independent top-level tasks and will
            # continue running; just log and exit the generator cleanly.
            logging.warning("notify_student_grades stream cancelled; email tasks will continue in the background.")
            return

        except Exception as e:
            logging.error("An exception occurred during notify_student_grades: %s", e)
            traceback.print_exc()
            yield json.dumps({"type": "error", "detail": f"An internal error occurred: {e}"}) + "\n"

    return StreamingResponse(_generate(), media_type="application/x-ndjson")


@app.post("/upload_rubric", response_model=AddRubricResponse)
async def upload_rubric_api(
    query_body: AddRubricRequest,
    request: Request
):
    '''
    Add a rubric to a course.
    This endpoint is only accessible to course instructor/platform administrators.
    The questions cells, the answer cells and the context cells
    (everything other than the question and aswer cells)
    The context is auto-regressive (context for each question is all cells
    from beginnig till the question cell)

    These are stored in the databse as well as cached.
    '''

    user = get_current_user(request)
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)
    try:
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin. Is not allowed to upload rubric")

        if query_body.assignment_type == "pdf":
            if not query_body.problem_statement or not query_body.rubric_text:
                raise HTTPException(
                    status_code=400,
                    detail="PDF rubric requires both 'problem_statement' and 'rubric_text'."
                )
            courses[course_handle][query_body.notebook_id] = {
                'assignment_type': 'pdf',
                'max_marks': query_body.max_marks,
                'problem_statement': query_body.problem_statement,
                'rubric_text': query_body.rubric_text,
                'sample_graded_response': query_body.sample_graded_response or '',
                'isactive_eval': True,
            }
            await save_pdf_rubric(
                config.db, course_handle, query_body.notebook_id,
                query_body.max_marks, query_body.problem_statement,
                query_body.rubric_text, query_body.sample_graded_response,
            )
        else:
            if query_body.context is None or query_body.questions is None or query_body.answers is None or query_body.outputs is None:
                raise HTTPException(
                    status_code=400,
                    detail="Notebook rubric requires 'context', 'questions', 'answers', and 'outputs'."
                )
            courses[course_handle][query_body.notebook_id] = {
                'context': query_body.context,
                'questions': query_body.questions,
                'max_marks': query_body.max_marks,
                'answers': query_body.answers,
                'outputs': query_body.outputs,
                'isactive_eval': True,
            }
            await save_rubric(
                config.db, course_handle, query_body.notebook_id,
                query_body.max_marks, query_body.context, query_body.questions,
                query_body.answers, query_body.outputs,
            )
            await update_notebook_info(config.db, course_handle, query_body.notebook_id, 'isactive_eval', True)

        return AddRubricResponse(
            response=f"Successfully added rubric '{query_body.notebook_id}' to course '{course_handle}'"
        )
    except HTTPException:
        raise
    except Exception as e:
        logging.error("An exception occurred during add_rubric_api: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


MAX_RUBRIC_PDF_SIZE_BYTES = 20 * 1024 * 1024


@app.post("/upload_rubric_file", response_model=AddRubricResponse)
async def upload_rubric_file(
    request: Request,
    notebook_id: str = Form(...),
    max_marks: float = Form(...),
    institution_id: str = Form(...),
    term_id: str = Form(...),
    course_id: str = Form(...),
    assignment_type: str = Form("pdf"),
    file: UploadFile = File(...),
):
    """Upload a rubric file directly (PDF for PDF assignments).

    For ``assignment_type="pdf"``: the PDF is stored at
    ``gs://{bucket}/{course}/rubrics/{notebook_id}.pdf`` and referenced via
    ``rubric_pdf_uri`` on the rubric doc. The scoring agent receives this
    PDF as a multimodal Part alongside each student submission, so figures,
    tables, and worked examples in the rubric are visible to the model.

    For ``assignment_type="notebook"``: not yet supported via file upload —
    use /upload_rubric_link to point at a Drive-hosted rubric notebook
    (added in a follow-up commit).

    Only accessible to instructors / TAs / admins for the named course.
    """
    user = get_current_user(request)
    user_gmail = user.get('email', '').lower()
    course_handle = make_course_handle(institution_id, term_id, course_id)

    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="Only instructors/TAs can upload rubrics for this course.")

    if assignment_type != "pdf":
        raise HTTPException(
            status_code=400,
            detail="File upload currently supports assignment_type='pdf'. "
                   "For notebook rubrics, use /upload_rubric_link with a Drive share link.",
        )

    if (file.content_type or '') not in ('application/pdf', 'application/x-pdf'):
        raise HTTPException(status_code=400, detail=f"Expected a PDF file (got content_type={file.content_type!r}).")

    pdf_bytes = await file.read()
    if not pdf_bytes:
        raise HTTPException(status_code=400, detail="Empty file.")
    if len(pdf_bytes) > MAX_RUBRIC_PDF_SIZE_BYTES:
        raise HTTPException(status_code=413, detail=f"Rubric PDF too large ({len(pdf_bytes)} bytes; max {MAX_RUBRIC_PDF_SIZE_BYTES}).")

    destination_path = f"{course_handle}/rubrics/{notebook_id}.pdf"
    try:
        rubric_pdf_uri = await asyncio.to_thread(
            upload_blob, config.bucket_name, destination_path, pdf_bytes, "application/pdf",
        )
    except Exception as e:
        logging.error(f"Failed to upload rubric PDF to GCS: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to upload rubric to GCS: {e}")

    await save_pdf_rubric(
        config.db, course_handle, notebook_id, max_marks,
        rubric_pdf_uri=rubric_pdf_uri,
    )

    # Update the in-memory cache so subsequent grading calls see the new rubric.
    courses[course_handle][notebook_id] = {
        'assignment_type': 'pdf',
        'max_marks': max_marks,
        'problem_statement': '',
        'rubric_text': '',
        'sample_graded_response': '',
        'rubric_pdf_uri': rubric_pdf_uri,
        'isactive_eval': True,
    }

    logging.info(
        f"Instructor {user_gmail} uploaded PDF rubric for {course_handle}/{notebook_id} → {rubric_pdf_uri}"
    )
    return AddRubricResponse(
        response=f"Rubric '{notebook_id}' uploaded for course '{course_handle}' (rubric_pdf_uri={rubric_pdf_uri}).",
    )


@app.post("/upload_rubric_link", response_model=AddRubricResponse)
async def upload_rubric_link(request: Request):
    """Upload a rubric by share link (Google Drive) instead of file upload.

    Body (JSON): ``{notebook_id, max_marks, institution_id, term_id,
    course_id, assignment_type, drive_share_link}``.

    For ``assignment_type="pdf"``: we download the rubric from Drive (the
    file must be shared with the platform service account), copy it to
    ``gs://{bucket}/{course}/rubrics/{notebook_id}.pdf``, and set
    ``rubric_pdf_uri`` on the rubric doc — same end state as
    /upload_rubric_file.

    For ``assignment_type="notebook"``: this endpoint currently returns a
    501 with guidance to use the Colab client's ``ta.upload_rubric()``,
    which handles the cell parsing client-side. Server-side .ipynb cell
    parsing is not yet implemented here.
    """
    body = await request.json()

    required = ["notebook_id", "max_marks", "institution_id", "term_id",
                "course_id", "drive_share_link"]
    for f in required:
        if body.get(f) in (None, ""):
            raise HTTPException(status_code=400, detail=f"Missing required field: {f}")

    assignment_type = body.get("assignment_type", "pdf")
    user = get_current_user(request)
    user_gmail = user.get('email', '').lower()
    course_handle = make_course_handle(body["institution_id"], body["term_id"], body["course_id"])

    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="Only instructors/TAs can upload rubrics for this course.")

    if assignment_type == "notebook":
        raise HTTPException(
            status_code=501,
            detail=(
                "Notebook rubric upload via link is not yet implemented server-side. "
                "Please use the Colab client's ta.upload_rubric() function — it parses "
                "the rubric notebook cells locally and posts the structured data to "
                "/upload_rubric."
            ),
        )

    if assignment_type != "pdf":
        raise HTTPException(status_code=400, detail=f"Unsupported assignment_type: {assignment_type!r}")

    file_id = get_file_id_from_share_link(body["drive_share_link"])
    if not file_id:
        raise HTTPException(status_code=400, detail="Could not parse Drive file ID from the supplied link.")

    pdf_bytes = await asyncio.to_thread(download_file_bytes_sa, config.firestore_cred_dict, file_id)
    if pdf_bytes is None:
        raise HTTPException(
            status_code=502,
            detail=(
                "Failed to download rubric from Drive. Ensure the file is shared "
                f"with the service account ({config.firestore_cred_dict.get('client_email')})."
            ),
        )
    if len(pdf_bytes) > MAX_RUBRIC_PDF_SIZE_BYTES:
        raise HTTPException(status_code=413, detail=f"Rubric PDF too large ({len(pdf_bytes)} bytes; max {MAX_RUBRIC_PDF_SIZE_BYTES}).")

    notebook_id = body["notebook_id"]
    max_marks = float(body["max_marks"])
    destination_path = f"{course_handle}/rubrics/{notebook_id}.pdf"
    try:
        rubric_pdf_uri = await asyncio.to_thread(
            upload_blob, config.bucket_name, destination_path, pdf_bytes, "application/pdf",
        )
    except Exception as e:
        logging.error(f"Failed to upload rubric PDF to GCS: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to copy rubric to GCS: {e}")

    await save_pdf_rubric(
        config.db, course_handle, notebook_id, max_marks,
        rubric_pdf_uri=rubric_pdf_uri,
    )
    courses[course_handle][notebook_id] = {
        'assignment_type': 'pdf',
        'max_marks': max_marks,
        'problem_statement': '',
        'rubric_text': '',
        'sample_graded_response': '',
        'rubric_pdf_uri': rubric_pdf_uri,
        'isactive_eval': True,
    }

    logging.info(
        f"Instructor {user_gmail} uploaded PDF rubric via Drive link for "
        f"{course_handle}/{notebook_id} → {rubric_pdf_uri}"
    )
    return AddRubricResponse(
        response=f"Rubric '{notebook_id}' uploaded for course '{course_handle}' from Drive link.",
    )


# ==================== PDF Assignment Endpoints ====================

# Hard cap on PDF size during ingest. Larger PDFs probably indicate scanned
# documents or content we can't reasonably feed to the model; fail loudly
# rather than silently degrade the grade.
MAX_PDF_SIZE_BYTES = 50 * 1024 * 1024


async def _resolve_pdf_authors(
    course_handle: str,
    drive_file_id: str,
    pdf_bytes: bytes,
    filename: str,
) -> tuple[list[str], list[str], list[str]]:
    """Run author extraction and resolve names to enrolled-student IDs.

    Returns ``(extracted_authors, student_ids, placeholder_ids)``. If the LLM
    returns no authors, falls back to a single placeholder named after the
    filename so the PDF still gets a submission record (instructor can fix
    the attribution later).
    """
    cover_text = await asyncio.to_thread(extract_first_pages_text, pdf_bytes)
    extracted = await extract_authors_with_gemini(cover_text)

    if not extracted:
        # Use the filename stem as the placeholder display name so the
        # instructor can spot it in the Students subcollection.
        stem = filename.rsplit('.', 1)[0] if filename else f"unknown-{drive_file_id[:8]}"
        sid = make_placeholder_student_id(stem)
        await add_placeholder_student(config.db, course_handle, sid, stem, drive_file_id)
        return [], [sid], [sid]

    student_directory = await get_student_directory(config.db, course_handle)

    student_ids: list[str] = []
    placeholders: list[str] = []
    for name in extracted:
        matched = match_author_to_student(name, student_directory)
        if matched:
            student_ids.append(matched)
        else:
            sid = make_placeholder_student_id(name)
            await add_placeholder_student(config.db, course_handle, sid, name, drive_file_id)
            student_ids.append(sid)
            placeholders.append(sid)

    # De-duplicate while preserving order.
    seen: set[str] = set()
    deduped = [s for s in student_ids if not (s in seen or seen.add(s))]
    return extracted, deduped, placeholders


@app.post("/ingest_pdf_submissions", response_model=IngestPdfSubmissionsResponse)
async def ingest_pdf_submissions(query_body: IngestPdfSubmissionsRequest, request: Request):
    """Ingest PDF assignments from a shared Google Drive folder.

    The Drive folder must be shared (read access) with the platform service
    account. For each PDF in the folder we:
      1. Skip if a submission with the same drive_file_id + drive_modified_time
         already exists (idempotent re-runs).
      2. Download the PDF, upload it to GCS, extract authors via Gemini, and
         resolve each name to an enrolled student or a placeholder record.
      3. Write a per-PDF tracking doc plus per-student mirror docs.

    Only accessible to instructors / platform admins. Returns a structured
    summary of ingested / skipped / failed files; grading is a separate step
    via /grade_pdf_assignment.
    """
    user = get_current_user(request)
    user_gmail = user.get('email', '').lower()
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    if course_handle not in courses:
        raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found.")
    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="Only instructors can ingest PDF submissions.")

    rubric = courses[course_handle].get(query_body.notebook_id)
    if not rubric:
        raise HTTPException(status_code=404, detail=f"Notebook '{query_body.notebook_id}' has no rubric — upload a PDF rubric first.")
    if rubric.get('assignment_type') != 'pdf':
        raise HTTPException(status_code=400, detail=f"Notebook '{query_body.notebook_id}' is not configured for PDF assignments.")

    folder_id = extract_folder_id_from_link(query_body.drive_folder_url)
    if not folder_id:
        raise HTTPException(status_code=400, detail="Could not parse Drive folder ID from the supplied URL.")

    try:
        files = await asyncio.to_thread(list_pdfs_in_folder_sa, config.firestore_cred_dict, folder_id)
    except Exception as e:
        logging.error(f"Failed to list Drive folder {folder_id}: {e}")
        raise HTTPException(status_code=502, detail=f"Could not list folder. Ensure the folder is shared with the service account ({config.firestore_cred_dict.get('client_email')}).")

    response = IngestPdfSubmissionsResponse()

    for f in files:
        drive_file_id = f.get('id')
        filename = f.get('name', 'unknown.pdf')
        modified_time = f.get('modifiedTime', '')
        size_str = f.get('size') or '0'

        try:
            try:
                size_bytes = int(size_str)
            except (TypeError, ValueError):
                size_bytes = 0
            if size_bytes > MAX_PDF_SIZE_BYTES:
                response.failed.append(FailedPdfRecord(
                    drive_file_id=drive_file_id, filename=filename,
                    error=f"File too large ({size_bytes} bytes; max {MAX_PDF_SIZE_BYTES}).",
                ))
                continue

            existing = await get_pdf_submission(config.db, course_handle, query_body.notebook_id, drive_file_id)
            if existing and existing.get('drive_modified_time') == modified_time:
                response.skipped.append(SkippedPdfRecord(
                    drive_file_id=drive_file_id, filename=filename,
                    reason="Already ingested at this modified_time.",
                ))
                continue

            pdf_bytes = await asyncio.to_thread(download_file_bytes_sa, config.firestore_cred_dict, drive_file_id)
            if pdf_bytes is None:
                response.failed.append(FailedPdfRecord(
                    drive_file_id=drive_file_id, filename=filename,
                    error="Drive download failed (see server logs).",
                ))
                continue

            destination_path = f"{course_handle}/submissions/{query_body.notebook_id}/{drive_file_id}.pdf"
            gcs_uri = await asyncio.to_thread(
                upload_blob, config.bucket_name, destination_path, pdf_bytes, "application/pdf",
            )

            extracted, student_ids, placeholders = await _resolve_pdf_authors(
                course_handle, drive_file_id, pdf_bytes, filename,
            )

            await upsert_pdf_submission(
                config.db, course_handle, query_body.notebook_id,
                drive_file_id=drive_file_id,
                drive_modified_time=modified_time,
                gcs_uri=gcs_uri,
                original_filename=filename,
                extracted_authors=extracted,
                student_ids=student_ids,
            )

            response.ingested.append(IngestedPdfRecord(
                drive_file_id=drive_file_id,
                filename=filename,
                authors=extracted,
                student_ids=student_ids,
                placeholder_student_ids=placeholders,
                gcs_uri=gcs_uri,
            ))
            logging.info(
                f"Ingested PDF '{filename}' (drive_file_id={drive_file_id}) for "
                f"{len(student_ids)} student(s), {len(placeholders)} placeholder(s)."
            )

        except Exception as e:
            logging.error(f"Failed to ingest PDF '{filename}': {e}")
            traceback.print_exc()
            response.failed.append(FailedPdfRecord(
                drive_file_id=drive_file_id, filename=filename, error=str(e),
            ))

    logging.info(
        f"PDF ingest for {course_handle}/{query_body.notebook_id}: "
        f"{len(response.ingested)} ingested, {len(response.skipped)} skipped, "
        f"{len(response.failed)} failed."
    )
    return response


@app.post("/grade_pdf_assignment")
async def grade_pdf_assignment(query_body: GradePdfAssignmentRequest, request: Request):
    """Grade every ingested PDF submission for a notebook.

    For each per-PDF tracking doc:
      - Skip if already graded (graded_at >= drive_modified_time) unless do_regrade.
      - Run the scoring agent with the PDF (via gs:// URI) plus rubric/sample/RAG.
      - Write the grade to the tracking doc and to every co-author's mirror doc.

    Streams ndjson progress lines, mirroring /grade_notebook.
    Only accessible to instructors / platform admins.
    """
    user = get_current_user(request)
    user_gmail = user.get('email', '').lower()
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    if course_handle not in courses:
        raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found.")
    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="Only instructors can grade PDF assignments.")

    rubric = courses[course_handle].get(query_body.notebook_id)
    if not rubric:
        raise HTTPException(status_code=404, detail=f"Notebook '{query_body.notebook_id}' has no rubric.")
    if rubric.get('assignment_type') != 'pdf':
        raise HTTPException(status_code=400, detail=f"Notebook '{query_body.notebook_id}' is not a PDF assignment.")

    problem_statement = rubric.get('problem_statement', '')
    rubric_text = rubric.get('rubric_text', '')
    sample_graded_response = rubric.get('sample_graded_response', '') or ''
    rubric_pdf_uri = rubric.get('rubric_pdf_uri')
    max_marks_total = rubric.get('max_marks', 0.0)

    submissions = await list_pdf_submissions(config.db, course_handle, query_body.notebook_id)
    if not submissions:
        raise HTTPException(status_code=404, detail=f"No PDF submissions ingested for notebook '{query_body.notebook_id}'.")

    runner = config.get_runner("scoring", courses, course_handle)
    rag_material = await retrieve_context(course_handle, problem_statement) if problem_statement else ""

    async def _grade_one(sub: dict):
        drive_file_id = sub.get('drive_file_id')
        gcs_uri = sub.get('gcs_uri')
        student_ids = sub.get('student_ids') or []
        modified_time = sub.get('drive_modified_time') or ''
        graded_at = sub.get('graded_at')

        if not query_body.do_regrade and graded_at is not None and modified_time and \
           str(graded_at) >= modified_time:
            return drive_file_id, "skipped", None, None

        # Use the first student as the session/user_id so retries dedupe naturally.
        user_id = student_ids[0] if student_ids else f"unknown-{drive_file_id}"

        try:
            marks, response_text = await score_pdf_submission(
                problem_statement, rubric_text, sample_graded_response,
                gcs_uri, runner,
                config.get_session_service("scoring", course_handle),
                user_id, course_material=rag_material,
                rubric_pdf_uri=rubric_pdf_uri,
            )
        except Exception as e:
            logging.error(f"Failed scoring PDF {drive_file_id}: {e}")
            return drive_file_id, "failed", None, str(e)

        grader_response = {"overall": {"marks": marks, "response": response_text}}
        await update_pdf_submission_grade(
            config.db, course_handle, query_body.notebook_id,
            drive_file_id=drive_file_id,
            student_ids=student_ids,
            total_marks=marks,
            max_marks=max_marks_total,
            grader_response=grader_response,
        )
        return drive_file_id, "graded", marks, None

    tasks = [asyncio.create_task(_grade_one(s)) for s in submissions]

    async def _generate():
        try:
            yield json.dumps({"type": "progress", "message": f"Grading {len(submissions)} PDF submission(s) for '{query_body.notebook_id}'."}) + "\n"

            graded = skipped = failed = 0
            results = []
            pending = set(tasks)
            while pending:
                done, pending = await asyncio.wait(pending, timeout=15, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    yield json.dumps({"type": "heartbeat"}) + "\n"
                    continue
                for t in done:
                    try:
                        drive_file_id, status, marks, err = t.result()
                    except Exception as e:
                        failed += 1
                        yield json.dumps({"type": "progress", "message": f"Task error: {e}"}) + "\n"
                        continue
                    if status == "graded":
                        graded += 1
                        results.append({"drive_file_id": drive_file_id, "marks": marks, "max_marks": max_marks_total})
                        yield json.dumps({"type": "progress", "message": f"Graded {drive_file_id}: {marks}/{max_marks_total}"}) + "\n"
                    elif status == "skipped":
                        skipped += 1
                        yield json.dumps({"type": "progress", "message": f"Skipped {drive_file_id} (already graded)."}) + "\n"
                    else:
                        failed += 1
                        yield json.dumps({"type": "progress", "message": f"Failed {drive_file_id}: {err}"}) + "\n"

            summary = f"PDF grading done. {graded} graded, {skipped} skipped, {failed} failed."
            logging.info(summary)
            yield json.dumps({"type": "response", "response": summary, "results": results}) + "\n"

        except asyncio.CancelledError:
            logging.warning("grade_pdf_assignment stream cancelled; tasks continue in background.")
            return
        except Exception as e:
            logging.error("Error in grade_pdf_assignment stream: %s", e)
            traceback.print_exc()
            yield json.dumps({"type": "error", "detail": f"An internal error occurred: {e}"}) + "\n"

    return StreamingResponse(_generate(), media_type="application/x-ndjson")


@app.post("/regrade_pdf_submission", response_model=RegradePdfSubmissionResponse)
async def regrade_pdf_submission(query_body: RegradePdfSubmissionRequest, request: Request):
    """Regrade a single student's PDF submission, optionally with student contention.

    Looks up the student's mirror doc to get the drive_file_id, then re-runs the
    scoring agent with the previous response and contention text appended to the
    prompt. Writes the new grade to the tracking doc + every co-author's mirror.
    Only accessible to instructors / platform admins.
    """
    user = get_current_user(request)
    user_gmail = user.get('email', '').lower()
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    if course_handle not in courses:
        raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found.")
    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="Only instructors can regrade PDF submissions.")

    rubric = courses[course_handle].get(query_body.notebook_id)
    if not rubric or rubric.get('assignment_type') != 'pdf':
        raise HTTPException(status_code=404, detail=f"Notebook '{query_body.notebook_id}' is not a PDF assignment.")

    # Pull the student's mirror doc to discover drive_file_id + co-authors.
    mirror = await get_student_pdf_mirror(
        config.db, course_handle, query_body.student_id, query_body.notebook_id,
    )
    if mirror is None:
        raise HTTPException(status_code=404, detail=f"No PDF submission for student '{query_body.student_id}' on notebook '{query_body.notebook_id}'.")
    drive_file_id = mirror.get('drive_file_id')
    if not drive_file_id:
        raise HTTPException(status_code=404, detail="Student record has no drive_file_id — was this PDF ever ingested?")

    tracking = await get_pdf_submission(config.db, course_handle, query_body.notebook_id, drive_file_id)
    if not tracking:
        raise HTTPException(status_code=404, detail="Per-PDF tracking record missing.")

    if not query_body.do_regrade and tracking.get('graded_at') is not None:
        raise HTTPException(status_code=409, detail="Already graded. Set do_regrade=true to re-grade.")

    problem_statement = rubric.get('problem_statement', '')
    rubric_text = rubric.get('rubric_text', '')
    sample_graded_response = rubric.get('sample_graded_response', '') or ''
    rubric_pdf_uri = rubric.get('rubric_pdf_uri')
    max_marks_total = rubric.get('max_marks', 0.0)
    gcs_uri = tracking.get('gcs_uri')
    student_ids = tracking.get('student_ids') or [query_body.student_id]

    previous_grading = ""
    prev = tracking.get('grader_response', {}) or {}
    overall = prev.get('overall', {}) if isinstance(prev, dict) else {}
    if overall.get('response'):
        previous_grading = overall['response']

    runner = config.get_runner("scoring", courses, course_handle)
    rag_material = await retrieve_context(course_handle, problem_statement) if problem_statement else ""

    marks, response_text = await score_pdf_submission(
        problem_statement, rubric_text, sample_graded_response,
        gcs_uri, runner,
        config.get_session_service("scoring", course_handle),
        query_body.student_id, course_material=rag_material,
        student_contention=query_body.student_contends,
        previous_grading=previous_grading,
        rubric_pdf_uri=rubric_pdf_uri,
    )

    # Stash the new and previous response so the audit trail is preserved.
    combined_response = f"{{regraded response}}\n{response_text}"
    if query_body.student_contends:
        combined_response += f"\n\n{{student's contention}}\n{query_body.student_contends}"
    if previous_grading:
        prev_marks = overall.get('marks', 0.0)
        combined_response += f"\n\n[previous marks]={prev_marks}\n[previous response]={previous_grading}"

    grader_response = {"overall": {"marks": marks, "response": combined_response}}
    await update_pdf_submission_grade(
        config.db, course_handle, query_body.notebook_id,
        drive_file_id=drive_file_id,
        student_ids=student_ids,
        total_marks=marks,
        max_marks=max_marks_total,
        grader_response=grader_response,
    )

    return RegradePdfSubmissionResponse(response=response_text, marks=marks)

# ==================== Course Materials Upload ====================

@app.get("/upload_course_materials", response_class=HTMLResponse)
async def upload_course_materials_page(request: Request):
    '''
    Serve a drag-and-drop file upload page for course materials.
    Redirects to /login if the user is not authenticated.
    The page includes text boxes for institution_id, term_id, course_id
    and validates authorization before showing the upload area.
    '''
    # Check authentication — redirect to login instead of 401 for browser users
    try:
        user = get_current_user(request)
        user_email = user.get('email', '')
    except HTTPException:
        return RedirectResponse(url="/login?message=Please+login+first+to+upload+course+materials", status_code=302)

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Upload Course Materials</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #f5f5f5; }}
            h1 {{ color: #333; }}
            .user-info {{ background: #e8f4fd; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px; color: #1a5276; }}
            .form-group {{ margin-bottom: 16px; }}
            .form-group label {{ display: block; font-weight: bold; margin-bottom: 6px; color: #333; }}
            .form-group input {{
                width: 100%; padding: 10px 12px; border: 1px solid #ccc; border-radius: 6px;
                font-size: 15px; box-sizing: border-box;
            }}
            .form-group input:focus {{ border-color: #2196F3; outline: none; box-shadow: 0 0 0 2px rgba(33,150,243,0.2); }}
            #load-course-btn {{
                padding: 12px 32px; background: #2196F3; color: #fff;
                border: none; border-radius: 6px; font-size: 16px; cursor: pointer;
            }}
            #load-course-btn:hover {{ background: #1976D2; }}
            #load-course-btn:disabled {{ background: #aaa; cursor: not-allowed; }}
            .course-info {{ background: #e8f4fd; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px; color: #1a5276; display: none; }}
            .drop-zone {{
                border: 3px dashed #aaa; border-radius: 12px; padding: 60px 20px;
                text-align: center; background: #fff; cursor: pointer;
                transition: border-color 0.3s, background 0.3s; display: none;
            }}
            .drop-zone.dragover {{ border-color: #2196F3; background: #e3f2fd; }}
            .drop-zone p {{ font-size: 18px; color: #666; margin: 0 0 10px; }}
            .drop-zone small {{ color: #999; }}
            #file-input {{ display: none; }}
            #file-list {{ margin-top: 20px; }}
            .file-item {{
                background: #fff; padding: 10px 16px; margin: 6px 0; border-radius: 6px;
                display: flex; justify-content: space-between; align-items: center;
                border: 1px solid #ddd;
            }}
            .file-item .name {{ font-weight: bold; color: #333; }}
            .file-item .size {{ color: #888; font-size: 13px; }}
            .file-item .remove {{ color: #e74c3c; cursor: pointer; font-weight: bold; border: none; background: none; font-size: 18px; }}
            #upload-btn {{
                margin-top: 20px; padding: 12px 32px; background: #4CAF50; color: #fff;
                border: none; border-radius: 6px; font-size: 16px; cursor: pointer;
                display: none;
            }}
            #upload-btn:hover {{ background: #388E3C; }}
            #upload-btn:disabled {{ background: #aaa; cursor: not-allowed; }}
            #status {{ margin-top: 16px; padding: 12px 16px; border-radius: 6px; display: none; }}
            #status.success {{ display: block; background: #d4edda; color: #155724; }}
            #status.error {{ display: block; background: #f8d7da; color: #721c24; }}
            #status.progress {{ display: block; background: #fff3cd; color: #856404; }}
            #course-form {{ background: #fff; padding: 24px; border-radius: 8px; border: 1px solid #ddd; margin-bottom: 24px; }}
        </style>
    </head>
    <body>
        <h1>Upload Course Materials</h1>
        <div class="user-info">Logged in as: <strong>{user_email}</strong></div>

        <div id="course-form">
            <div class="form-group">
                <label for="institution_id">Institution ID</label>
                <input type="text" id="institution_id" placeholder="e.g. iisc">
            </div>
            <div class="form-group">
                <label for="term_id">Term ID</label>
                <input type="text" id="term_id" placeholder="e.g. 2025">
            </div>
            <div class="form-group">
                <label for="course_id">Course ID</label>
                <input type="text" id="course_id" placeholder="e.g. E0-228">
            </div>
            <button id="load-course-btn">Load Course</button>
        </div>

        <div class="course-info" id="course-info"></div>

        <div class="drop-zone" id="drop-zone">
            <p>Drag &amp; drop files here</p>
            <small>or click to browse</small>
        </div>
        <input type="file" id="file-input" multiple>

        <div id="file-list"></div>
        <button id="upload-btn">Upload Files</button>
        <div id="status"></div>

        <script>
            const loadBtn = document.getElementById('load-course-btn');
            const courseInfo = document.getElementById('course-info');
            const courseForm = document.getElementById('course-form');
            const dropZone = document.getElementById('drop-zone');
            const fileInput = document.getElementById('file-input');
            const fileList = document.getElementById('file-list');
            const uploadBtn = document.getElementById('upload-btn');
            const status = document.getElementById('status');
            let selectedFiles = [];
            let courseId = '', termId = '', institutionId = '';

            loadBtn.addEventListener('click', async () => {{
                institutionId = document.getElementById('institution_id').value.trim();
                termId = document.getElementById('term_id').value.trim();
                courseId = document.getElementById('course_id').value.trim();

                if (!institutionId || !termId || !courseId) {{
                    status.className = 'error';
                    status.textContent = 'Please fill in all three fields.';
                    status.style.display = 'block';
                    return;
                }}

                status.className = 'progress';
                status.textContent = 'Validating course access...';
                status.style.display = 'block';
                loadBtn.disabled = true;

                try {{
                    const resp = await fetch(
                        '/validate_course_access?institution_id=' + encodeURIComponent(institutionId)
                        + '&term_id=' + encodeURIComponent(termId)
                        + '&course_id=' + encodeURIComponent(courseId),
                        {{ credentials: 'same-origin' }}
                    );
                    if (!resp.ok) {{
                        let detail = 'Server error (HTTP ' + resp.status + ')';
                        try {{ const d = await resp.json(); detail = d.detail || detail; }} catch(e) {{}}
                        status.className = 'error';
                        status.textContent = detail;
                    }} else {{
                        const data = await resp.json();
                        courseInfo.innerHTML = '<strong>Course:</strong> ' + data.course_name
                            + ' (' + courseId + ')<br><strong>Term:</strong> ' + termId
                            + ' &nbsp; <strong>Institution:</strong> ' + institutionId;
                        courseInfo.style.display = 'block';
                        dropZone.style.display = 'block';
                        courseForm.style.display = 'none';
                        status.style.display = 'none';
                    }}
                }} catch (err) {{
                    status.className = 'error';
                    status.textContent = 'Network error: ' + err.message;
                }}
                loadBtn.disabled = false;
            }});

            dropZone.addEventListener('click', () => fileInput.click());

            dropZone.addEventListener('dragover', (e) => {{
                e.preventDefault();
                dropZone.classList.add('dragover');
            }});

            dropZone.addEventListener('dragleave', () => {{
                dropZone.classList.remove('dragover');
            }});

            dropZone.addEventListener('drop', (e) => {{
                e.preventDefault();
                dropZone.classList.remove('dragover');
                addFiles(e.dataTransfer.files);
            }});

            fileInput.addEventListener('change', () => {{
                addFiles(fileInput.files);
                fileInput.value = '';
            }});

            function addFiles(files) {{
                for (const f of files) {{
                    if (!selectedFiles.some(s => s.name === f.name && s.size === f.size)) {{
                        selectedFiles.push(f);
                    }}
                }}
                renderFileList();
            }}

            function removeFile(index) {{
                selectedFiles.splice(index, 1);
                renderFileList();
            }}

            function formatSize(bytes) {{
                if (bytes < 1024) return bytes + ' B';
                if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
                return (bytes / 1048576).toFixed(1) + ' MB';
            }}

            function renderFileList() {{
                fileList.innerHTML = '';
                selectedFiles.forEach((f, i) => {{
                    const div = document.createElement('div');
                    div.className = 'file-item';
                    div.innerHTML = '<span class="name">' + f.name + '</span>'
                        + '<span class="size">' + formatSize(f.size) + '</span>'
                        + '<button class="remove" onclick="removeFile(' + i + ')">&times;</button>';
                    fileList.appendChild(div);
                }});
                uploadBtn.style.display = selectedFiles.length > 0 ? 'inline-block' : 'none';
                status.className = '';
                status.style.display = 'none';
            }}

            uploadBtn.addEventListener('click', async () => {{
                if (selectedFiles.length === 0) return;
                uploadBtn.disabled = true;
                const total = selectedFiles.length;
                let uploaded = 0;
                const errors = [];

                for (let i = 0; i < total; i++) {{
                    const f = selectedFiles[i];
                    status.className = 'progress';
                    status.textContent = 'Uploading file ' + (i + 1) + ' of ' + total + ': ' + f.name + '...';
                    status.style.display = 'block';

                    try {{
                        // Upload file directly through the server to GCS
                        const formData = new FormData();
                        formData.append('file', f);
                        formData.append('course_id', courseId);
                        formData.append('term_id', termId);
                        formData.append('institution_id', institutionId);

                        const uploadResp = await fetch('/upload_file', {{
                            method: 'POST',
                            body: formData,
                            credentials: 'same-origin'
                        }});
                        if (!uploadResp.ok) {{
                            let detail = 'HTTP ' + uploadResp.status;
                            try {{ const d = await uploadResp.json(); detail = d.detail || detail; }} catch(e) {{}}
                            errors.push(f.name + ': ' + detail);
                        }} else {{
                            uploaded++;
                        }}
                    }} catch (err) {{
                        errors.push(f.name + ': ' + err.message);
                    }}
                }}

                if (errors.length === 0) {{
                    status.className = 'success';
                    status.textContent = 'Successfully uploaded ' + uploaded + ' file(s).';
                    selectedFiles = [];
                    renderFileList();
                }} else if (uploaded > 0) {{
                    status.className = 'error';
                    status.textContent = 'Uploaded ' + uploaded + ' of ' + total + '. Failed: ' + errors.join('; ');
                }} else {{
                    status.className = 'error';
                    status.textContent = 'All uploads failed: ' + errors.join('; ');
                }}
                uploadBtn.disabled = false;
            }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)


@app.get("/validate_course_access")
async def validate_course_access(
    institution_id: str,
    term_id: str,
    course_id: str,
    request: Request
):
    '''
    Validate that the authenticated user has instructor/admin access to the course.
    Called by the upload page JS before showing the drag-and-drop area.
    '''
    user = get_current_user(request)
    course_handle = make_course_handle(institution_id, term_id, course_id)

    user_gmail = user.get('email', '').lower()
    if not is_authorized(user_gmail, course_handle):
        raise HTTPException(status_code=403, detail="You are not an instructor for this course nor a platform admin")

    if course_handle not in courses:
        raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found")

    course_name = courses[course_handle].get('course_name', course_id)
    return {"course_name": course_name, "course_handle": course_handle}


@app.post("/get_upload_url")
async def get_upload_url(request: Request):
    '''
    Generate a signed GCS upload URL so the browser can PUT a file
    directly to Cloud Storage, bypassing the Cloud Run 32 MB body limit.

    Request JSON body:
        {
            "course_id": "...",
            "term_id": "...",
            "institution_id": "...",
            "filename": "notes.pdf",
            "content_type": "application/pdf"
        }

    Returns:
        {"upload_url": "<signed URL>", "destination": "<object path>"}
    '''
    try:
        user = get_current_user(request)
        body = await request.json()

        course_id = body.get('course_id', '')
        term_id = body.get('term_id', '')
        institution_id = body.get('institution_id', '')
        filename = body.get('filename', '')
        content_type = body.get('content_type', 'application/octet-stream')

        if not all([course_id, term_id, institution_id, filename]):
            raise HTTPException(status_code=400, detail="Missing required fields")

        course_handle = make_course_handle(institution_id, term_id, course_id)

        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle):
            raise HTTPException(status_code=403, detail="User is not an instructor for this course nor a platform admin")

        if course_handle not in courses:
            raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found")

        folder_name = courses[course_handle].get('folder_name', '')
        if not folder_name:
            raise HTTPException(status_code=500, detail="Course folder not configured")

        parts = folder_name.split('/', 1)
        bucket_name = parts[0]
        prefix = parts[1] if len(parts) > 1 else ''
        destination = f"{prefix}{filename}"

        signed_url = generate_signed_upload_url(bucket_name, destination, content_type)
        logging.info(f"Instructor {user_gmail} requested upload URL for '{filename}' in course {course_handle}")

        return {"upload_url": signed_url, "destination": destination}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Unexpected error in get_upload_url: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to generate upload URL: {str(e)}")


@app.post("/upload_file")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    course_id: str = Form(...),
    term_id: str = Form(...),
    institution_id: str = Form(...)
):
    '''
    Upload a file directly through the server to GCS.
    This avoids CORS issues with signed URLs by proxying the upload.
    '''
    try:
        user = get_current_user(request)

        if not all([course_id, term_id, institution_id, file.filename]):
            raise HTTPException(status_code=400, detail="Missing required fields")

        course_handle = make_course_handle(institution_id, term_id, course_id)

        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle):
            raise HTTPException(status_code=403, detail="User is not an instructor for this course nor a platform admin")

        if course_handle not in courses:
            raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found")

        folder_name = courses[course_handle].get('folder_name', '')
        if not folder_name:
            raise HTTPException(status_code=500, detail="Course folder not configured")

        parts = folder_name.split('/', 1)
        bucket_name = parts[0]
        prefix = parts[1] if len(parts) > 1 else ''
        destination = f"{prefix}{file.filename}"

        file_data = await file.read()
        content_type = file.content_type or 'application/octet-stream'

        from storage_utils import upload_blob
        upload_blob(bucket_name, destination, file_data, content_type)

        logging.info(f"Instructor {user_gmail} uploaded '{file.filename}' to course {course_handle}")
        return {"status": "success", "filename": file.filename, "destination": destination}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Unexpected error in upload_file: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {str(e)}")


@app.post("/list_course_files", response_model=ListCourseFilesResponse)
async def list_course_files_api(query_body: ListCourseFilesRequest, request: Request):
    '''
    List all files in the GCS folder for a course.
    Only accessible to course instructors or platform admins.
    '''
    try:
        user = get_current_user(request)

        course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle):
            raise HTTPException(status_code=403, detail="User is not an instructor for this course nor a platform admin")

        if course_handle not in courses:
            raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found")

        folder_name = courses[course_handle].get('folder_name', '')
        if not folder_name:
            raise HTTPException(status_code=500, detail="Course folder not configured")

        parts = folder_name.split('/', 1)
        bucket_name = parts[0]
        prefix = parts[1] if len(parts) > 1 else ''

        files = await list_blobs(bucket_name, prefix)
        logging.info(f"Instructor {user_gmail} listed {len(files)} files for course {course_handle}")

        return ListCourseFilesResponse(files=files)

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Unexpected error in list_course_files: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to list course files: {str(e)}")


@app.post("/build_course_index", response_model=BuildCourseIndexResponse)
async def build_course_index_api(query_body: BuildCourseIndexRequest, request: Request):
    '''
    Build the RAG vector index for a course by processing all PDFs in its
    GCS folder. Only accessible to course instructors or platform admins.
    '''
    try:
        user = get_current_user(request)

        course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle):
            raise HTTPException(status_code=403, detail="User is not an instructor for this course nor a platform admin")

        if course_handle not in courses:
            raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found")

        folder_name = courses[course_handle].get('folder_name', '')
        if not folder_name:
            raise HTTPException(status_code=500, detail="Course folder not configured")

        logging.info(f"Instructor {user_gmail} triggered RAG index build for course {course_handle}")
        result = await build_course_index(course_handle, folder_name)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Unexpected error in build_course_index: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to build course index: {str(e)}")


# ==================== Admin Endpoints ====================

@app.post("/create_course", response_model=CreateCourseResponse)
async def create_course_api(
    query_body: CreateCourseRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_admin_user)
):
    '''Create a new course in the platform.
    This endpoint is only accessible to platform administrators.'''
    try:

        course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

        course_data = await get_course_data(config.db, course_handle)
        if course_data is not None:
            logging.info(f"Course '{course_handle}' already exists. No new course created.")
            return CreateCourseResponse(
                response=f"Course '{course_handle}' already exists. No new course created."
            )
        
        #course doesnt exist: Create one.
        courses[course_handle] = {
            'course_id': query_body.course_id,
            'term_id': query_body.term_id,
            'institution_id': query_body.institution_id
        }


        if query_body.course_name :
            courses[course_handle]['course_name'] = query_body.course_name
        else:
            courses[course_handle]['course_name'] = None

        if query_body.instructor_gmail :
            courses[course_handle]['instructor_gmail'] = query_body.instructor_gmail
        else:
            courses[course_handle]['instructor_gmail'] = None

        if query_body.instructor_email :
            courses[course_handle]['instructor_email'] = query_body.instructor_email
        else:   
            courses[course_handle]['instructor_email'] = None

        if query_body.instructor_name :
            courses[course_handle]['instructor_name'] = query_body.instructor_name
        else:   
            courses[course_handle]['instructor_name'] = None

        if query_body.start_date :
            courses[course_handle]['start_date'] = query_body.start_date
        else:
            courses[course_handle]['start_date'] = None
        
        if query_body.end_date :
            courses[course_handle]['end_date'] = query_body.end_date
        else:            
            courses[course_handle]['end_date'] = None
        
        courses[course_handle]['folder_name'] = config.bucket_name+"/"+course_handle+"/"
        courses[course_handle]['created_by'] = current_user.get('email')
        courses[course_handle]['created_at'] = datetime.datetime.utcnow()

        courses[course_handle]['isactive_tutor']= True

        # Load platform default values to fall back on for prompts/model
        default_values = await load_default_values(config.db)

        # AI model and prompts: use supplied values, else fall back to defaults
        courses[course_handle]['ai_model'] = (
            query_body.ai_model or default_values.get('ai_model')
        )
        courses[course_handle]['instructor_assist_prompt'] = (
            query_body.instructor_assist_prompt or default_values.get('instructor_assist_prompt')
        )
        courses[course_handle]['student_assist_prompt'] = (
            query_body.student_assist_prompt or default_values.get('student_assist_prompt')
        )
        courses[course_handle]['scoring_assist_prompt'] = (
            query_body.scoring_assist_prompt or default_values.get('scoring_assist_prompt')
        )

        if await create_course(config.db, courses[course_handle]):
            logging.info(f"Admin {current_user.get('email')} created course {query_body.course_name} ({courses[course_handle]['course_id']})")

            return CreateCourseResponse(
                response=f"Course {courses[course_handle]['institution_id']}/{courses[course_handle]['term_id']}/{courses[course_handle]['course_id']} created successfully."
            )
        else:
            raise HTTPException(status_code=422, detail=f"Could not create course '{courses[course_handle]['course_id']}' for institution '{courses[course_handle]['institution_id']}' and term '{courses[course_handle]['term_id']}'.")
        
    except Exception as e:
        logging.error("An exception occurred during create_course_api: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=f"An internal error occurred: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    #uvicorn.run(app, host="127.0.0.1", port=port)
    uvicorn.run(app, host="0.0.0.0", port=port, timeout_graceful_shutdown=300) #allow access from any IP address; 5-min grace for background grading tasks
