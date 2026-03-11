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
from agent_service import run_agent_and_get_response, score_question, evaluate, update_semaphore_limit, get_semaphore_limit

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
    BuildCourseIndexRequest, BuildCourseIndexResponse,
    UpdateCourseConfigRequest, UpdateCourseConfigResponse,
    UpdateGlobalConfigRequest, UpdateGlobalConfigResponse
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
    get_marks_list,
    get_course_data,
    load_course_info_from_db,
    load_notebooks_from_db
)
from drive_utils import load_notebook_from_google_drive_sa
from email_service import send_email
from storage_utils import upload_blob, generate_signed_upload_url
from rag import build_course_index, retrieve_context
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
        all_courses = await load_course_info_from_db(config.db)
        for course_handle, course_data in all_courses.items():
            courses[course_handle] = course_data
            courses[course_handle].setdefault('isactive_tutor', True)
            courses[course_handle].setdefault('student_rate_limit', None)
            courses[course_handle].setdefault('student_rate_limit_window', None)
            # model defaults to None (uses agent.DEFAULT_MODEL via the runner factory)
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
    """
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
        #either an instructor or student loggin in via colab
        #redirect them to get the JWT token for API access
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
                    existing = await config.instructor_session_service.get_session(
                        app_name=config.runner_instructor.app_name,
                        user_id=user_gmail, session_id=session_id,
                    )
                    if not existing:
                        await config.instructor_session_service.create_session(
                            app_name=config.runner_instructor.app_name,
                            user_id=user_gmail, session_id=session_id,
                            state=initial_state,
                        )
                else:
                    await add_student_notebook_if_not_exists(config.db, course_handle, user_gmail, user_name, notebook_id)
                    existing = await config.student_session_service.get_session(
                        app_name=config.runner_student.app_name,
                        user_id=user_gmail, session_id=session_id,
                    )
                    if not existing:
                        await config.student_session_service.create_session(
                            app_name=config.runner_student.app_name,
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
                    parts.append(types.Part.from_text(text="{The topic content is:} " + str(context)))
                if question:
                    parts.append(types.Part.from_text(text="{The question is:} " + str(question)))
                if ta_chat:
                    parts.append(types.Part.from_text(text="{The instructor asks:} " + str(ta_chat)))
                if answer:
                    parts.append(types.Part.from_text(text="{The instructor's answer is} " + str(answer)))
                if output:
                    parts.append(types.Part.from_text(text="{The instructor's code output is} " + json.dumps(output)))
                course_model = courses[course_handle].get('model')
                runner = config.get_runner("instructor", course_model) if course_model else config.runner_instructor
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
                    parts.append(types.Part.from_text(text="{The context is:} " + str(context)))
                parts.append(types.Part.from_text(text="{The question is:} " + str(question)))
                parts.append(types.Part.from_text(text="{The student's answer is} " + str(answer)))
                if output:
                    parts.append(types.Part.from_text(text="{The student's code output is} " + json.dumps(output)))
                parts.append(types.Part.from_text(text="{The student asks:} " + str(ta_chat)))
                if rubric_answer is not None:
                    parts.append(types.Part.from_text(text="{The rubric is} " + str(rubric_answer)))
                if rubric_output is not None:
                    parts.append(types.Part.from_text(text="{The rubric code output is} " + str(rubric_output)))
                course_model = courses[course_handle].get('model')
                runner = config.get_runner("student", course_model) if course_model else config.runner_student

            # Prepend RAG material if available
            if rag_material:
                parts.insert(0, types.Part.from_text(
                    text="{Relevant course material:} " + rag_material
                ))

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
    course_model = courses[course_handle].get('model') if course_handle in courses else None
    runner = config.get_runner("scoring", course_model) if course_model else config.runner_scoring

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

        marks, response_text = await score_question(question, answer, rubric, runner, config.instructor_session_service, user_id)

        return GradeResponse(
            response=response_text,
            marks=marks
        )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during query processing: %s", e)
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

    course_model = courses[course_handle].get('model')
    runner = config.get_runner("scoring", course_model) if course_model else config.runner_scoring

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
                rubric_answer_str = " ".join(
                    f"({float(a.get('percent'))/100.0*rubric_question_marks}) {a.get('component', '')}"
                    for a in rubric_answer
                )
                logging.info(f"Grading Q{qnum_str}: rubric question='{rubric_question}', rubric answer='{rubric_answer_str}'")
                student_answer_str = " ".join(
                    f"{a.get('component', '')}"
                    for a in student_answer
                ) if student_answer else ""

                if not rubric_question:
                    logging.error(f"No rubric question found for Q{qnum_str}. Skipping.")
                    raise HTTPException(status_code=404, detail=f"Rubric question not found for question number '{qnum_str}' in notebook '{notebook_id}'.")

                # RAG retrieval + scoring run concurrently across questions
                rag_material = await retrieve_context(course_handle, rubric_question)
                marks, response_text = await score_question(
                    rubric_question, str(student_answer_str), str(rubric_answer_str),
                    runner, config.instructor_session_service, user_gmail,
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

    course_model = courses[course_handle].get('model')
    runner = config.get_runner("scoring", course_model) if course_model else config.runner_scoring
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
                runner, config.instructor_session_service, student_id,
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

@app.get("/", tags=["Authentication"], response_class=HTMLResponse)
async def admin_login_page(request: Request):
    """
    Serves the admin login page. Sets a session flag so the OAuth callback
    can verify the user is a platform administrator.
    """
    request.session['admin_login'] = True
    html_content = """
    <html>
        <head>
            <title>Login to AI Teach Assistant Platform</title>
        </head>
        <body>
            <h1>Welcome to AI Teaching Assistant Platform</h1>
            <p>Please log in to configure/adminster the platform.</p>
            <form action="/login" method="get">
                <button type="submit" style="padding: 10px 20px; font-size: 16px; cursor: pointer;">Login with Google</button>
            </form>
            <br><br>
            <p style="font-size: 12px; color: #666;">
                Having login issues? Check <a href="/session-test">session test</a>
            </p>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)

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
    """Check if the user is an instructor for the course or a platform admin."""
    if not user_gmail:
        return False
    user_lower = user_gmail.lower()

    # Platform admin is always authorized
    if user_lower == config.admin_email:
        return True

    # Check all instructor-related email fields on the course
    course_data = courses.get(course_handle, {})
    for field in ('instructor_gmail', 'instructor_email', 'created_by'):
        value = course_data.get(field)
        if value and user_lower == value.lower():
            return True

    return False


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
        user = get_current_user(request)
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin. Is not allowed to upload rubric")

        #Save the in the cache
        courses[course_handle][query_body.notebook_id]={'context':query_body.context,
                                             'questions':query_body.questions,
                                             'max_marks': query_body.max_marks,
                                             'answers':query_body.answers,
                                             'outputs':query_body.outputs,
                                             'isactive_eval': True}

        #now save the rubric in the databse as well
        await save_rubric(config.db, course_handle, query_body.notebook_id, query_body.max_marks, query_body.context, query_body.questions, query_body.answers, query_body.outputs)
        await update_notebook_info(config.db, course_handle, query_body.notebook_id, 'isactive_eval', True)

        return AddRubricResponse(
            response=f"Successfully added rubric '{query_body.notebook_id}' to course '{course_handle}'"
        )
    except Exception as e:
        logging.error("An exception occurred during add_rubric_api: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")

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
                        // Step 1: Get a signed upload URL from our server
                        const urlResp = await fetch('/get_upload_url', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{
                                course_id: courseId,
                                term_id: termId,
                                institution_id: institutionId,
                                filename: f.name,
                                content_type: f.type || 'application/octet-stream'
                            }}),
                            credentials: 'same-origin'
                        }});
                        if (!urlResp.ok) {{
                            let detail = 'HTTP ' + urlResp.status;
                            try {{ const d = await urlResp.json(); detail = d.detail || detail; }} catch(e) {{}}
                            errors.push(f.name + ': ' + detail);
                            continue;
                        }}
                        const {{ upload_url }} = await urlResp.json();

                        // Step 2: PUT the file directly to GCS using the signed URL
                        const putResp = await fetch(upload_url, {{
                            method: 'PUT',
                            headers: {{'Content-Type': f.type || 'application/octet-stream'}},
                            body: f
                        }});
                        if (!putResp.ok) {{
                            errors.push(f.name + ': GCS upload failed (HTTP ' + putResp.status + ')');
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
