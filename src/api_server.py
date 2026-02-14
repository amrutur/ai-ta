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
ADMIN_EMAILS (comma-separated list of platform administrator email addresses)
OAUTH_REDIRECT_URI (optional, for development with ngrok - e.g., https://yoursubdomain.ngrok-free.app/callback)
SENDGRID_FROM_EMAIL (email address to send emails from)

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

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
import uvicorn
import requests as http_requests

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.genai import types

import config
from models import (
    QueryRequest, QueryResponse,
    AssistRequest, AssistResponse,
    GradeRequest, GradeResponse,
    EvalRequest, EvalResponse,
    FetchGradedRequest, FetchGradedResponse,
    NotifyGradedRequest, NotifyGradedResponse,
    TutorInteractionRequest, TutorInteractionResponse,
    CreateCourseRequest, CreateCourseResponse,
)
from auth import (
    credentials_to_dict,
    create_jwt_token,
    get_current_user,
    get_instructor_user,
    get_admin_user,
)
from database import (
    get_student_list,
    get_user_list,
    add_user_if_not_exists,
    add_answer_notebook,
    update_course_info,
    update_marks,
    fetch_grader_response,
    create_course,
    is_instructor_for_any_course,
    make_course_handle
)
from drive_utils import load_notebook_from_google_drive_sa
from agent_service import run_agent_and_get_response, score_question, evaluate
from email_service import send_email
import datetime
from collections import defaultdict

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


# ==================== Authentication Endpoints ====================

@app.get("/login", tags=["Authentication"])
async def login(request: Request):
    """
    Redirects the user to the Google OAuth consent screen to initiate login.
    """
    logging.info(f"Login request received from: {request.client.host if request.client else 'unknown'}")
    logging.info(f"Login request URL: {request.url}")
    logging.debug(f"Login request headers: {dict(request.headers)}")
    logging.debug(f"Login existing cookies: {request.cookies}")

    flow = Flow.from_client_config(
        client_config=config.client_config,
        scopes=config.SCOPES,
        redirect_uri=config.client_config['web']['redirect_uris'][config.REDIRECT_URI_INDEX]
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    # Store the state in the user's session to verify it in the callback, preventing CSRF.
    request.session['state'] = state
    logging.info(f"Login: Generated and stored state in session: {state[:10]}...")
    logging.info(f"Login: Using redirect URI: {config.client_config['web']['redirect_uris'][config.REDIRECT_URI_INDEX]}")
    logging.debug(f"Login: Session data after storing state: {dict(request.session)}")

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

    logging.info(f"Login: Redirecting to Google OAuth via HTML redirect: {authorization_url[:80]}...")
    return HTMLResponse(content=html_content, status_code=200)

@app.get("/callback", tags=["Authentication"])
async def oauth_callback(request: Request):
    """
    Handles the callback from Google after user consent.
    Exchanges the authorization code for credentials and creates a user session.
    """
    logging.info(f"Callback request received from: {request.client.host if request.client else 'unknown'}")
    logging.info(f"Callback request URL: {request.url}")
    logging.debug(f"Callback request headers: {dict(request.headers)}")
    logging.info(f"Callback cookies received: {list(request.cookies.keys())}")

    state = request.session.get('state')
    query_state = request.query_params.get('state')

    logging.info(f"Callback: Session state: {state[:10] if state else 'None'}...")
    logging.info(f"Callback: Query state: {query_state[:10] if query_state else 'None'}...")
    logging.debug(f"Callback: Full session data: {dict(request.session)}")
    logging.debug(f"Callback: Full cookies: {request.cookies}")

    if not state:
        logging.error("Callback: No state found in session. Session may not be persisting.")
        logging.error(f"Callback: Available session keys: {list(request.session.keys())}")
        logging.error(f"Callback: Cookies present: {list(request.cookies.keys())}")
        raise HTTPException(
            status_code=400,
            detail="No state found in session. Session cookies may not be working. Please try logging in again."
        )

    if state != query_state:
        logging.error(f"Callback: State mismatch. Session: {state}, Query: {query_state}")
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
        logging.info(f"Callback: Corrected authorization_response from HTTP to HTTPS (X-Forwarded-Proto: https)")

    logging.info(f"Callback: Using authorization_response: {authorization_response[:100]}...")

    try:
        flow.fetch_token(authorization_response=authorization_response)
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

    try:
        userinfo_service = build('oauth2', 'v2', credentials=flow_creds)
        request.session['user'] = userinfo_service.userinfo().get().execute()
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
        if user_email.lower() not in [email.lower() for email in config.ADMIN_EMAILS]:
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

    try:
        user_list = get_user_list(config.db)

        if user_id not in user_list:
            logging.info(f"User '{user_name}' ({user_id}) not in database. Adding now.")
            user_ref = config.db.collection(u'users').document(user_id)
            user_ref.set({
                u'name': user_name,
                u'email': user_email
            })
    except Exception as e:
        logging.error(f"Firestore error during user lookup/creation: {e}")
        traceback.print_exc()
        # Don't block login for database errors - user is already authenticated

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

@app.post("/colab_auth", tags=["Authentication"])
async def colab_auth(request: Request):
    """
    Authenticate a Colab notebook user via their Google access token.

    Accepts a Google access token (from google.colab.auth.authenticate_user()),
    verifies it with Google's userinfo API, registers the student under the
    given course, and returns a JWT for the app.

    Request body:
        {"google_token": "<access_token_from_colab>", "course_id": "<course_id>"}

    Returns:
        JSON with JWT token and user info
    """
    body = await request.json()
    google_token = body.get("google_token")
    course_id = body.get("course_id")
    if not google_token:
        raise HTTPException(status_code=400, detail="Missing google_token in request body")
    if not course_id:
        raise HTTPException(status_code=400, detail="Missing course_id in request body")

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
    try:
        add_user_if_not_exists(config.db, course_id, user_gmail, user_name)
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

@app.post("/assist", response_model=AssistResponse)
async def assist(query_body: AssistRequest, request: Request):

    ''' Call the AI Tutor agent to get assistance for a question.'''

    student = get_current_user(request)

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)


    # Check if tutor is disabled by instructor
    if not courses[course_handle].isactive_tutor:
        raise HTTPException(status_code=503, detail="Tutor is temporarily disabled")

    runner = config.runner_assist

    student_gmail = student.get('email')

    try:
        # Use a consistent session ID for the agent conversation

        if 'agent_session_id' in request.session:
            session_id = request.session.get('agent_session_id')
        else:
            session_id = str(uuid.uuid4())
            request.session['agent_session_id'] = session_id
            await config.session_service.create_session(
                    app_name=runner.app_name,
                    user_id=student_gmail,
                    session_id=session_id
                )

        rubric = ''
        qnum = query_body.qnum
        if query_body.rubric_link:
            # Read rubric notebook using the application's service account, not the logged-in user's credentials. First check the cache
            rubric_json = courses[course_handle].get(query_body.rubric_link, {})
            if rubric_json is None:

                rubric = await asyncio.to_thread(
                load_notebook_from_google_drive_sa, config.firestore_cred_dict, str(query_body.rubric_link)
                if rubric is None:
                raise HTTPException(
                    status_code=404, detail=f"Rubric notebook '{query_body.rubric_link}' not found. Ensure it is shared with the service account: {config.firestore_cred_dict.get('client_email')}"
                )
                try:
                    # .ipynb files are JSON, so we can return them as JSON
                    rubric_json = json.loads(notebook_content)
                except json.JSONDecodeError:
                    # Or return as plain text if it's not valid JSON for some reason
                    return HTMLResponse(content=f"<pre>Could not parse rubric notebook as JSON. Raw content:\n\n{notebook_content}</pre>")
            )
            rubric =  "{The rubric is} " + ''.join(rubric_json['cells'][qnum+1]['source'])

        # Create a message from the query
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=query_body.query+rubric)]
        )

        # Attempt to get the response using the current session ID
        response_text = await run_agent_and_get_response(session_id, user_id, content, runner)

        if not response_text:
            raise HTTPException(status_code=500, detail="Failed to generate response")

        return AssistResponse(
            response=response_text
            )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during query processing: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/query", response_model=QueryResponse)
async def process_query(query_body: QueryRequest, request: Request):

    # Check if tutor is disabled by instructor
    if not config.isactive_tutor:
        raise HTTPException(status_code=503, detail="Tutor is temporarily disabled")

    runner = config.runner_assist

    try:
        # Use a consistent session ID for the agent conversation
        session_id = request.session.get('agent_session_id', str(uuid.uuid4()))
        request.session['agent_session_id'] = session_id

        user_id = query_body.user_email if query_body.user_email else "anonymous_user"
        user_name = query_body.user_name if query_body.user_name else "Anonymous User"

        # Create a message from the query
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=query_body.query)]
        )

        logging.info(f"User {user_name}, has asked for checking for question {query_body.q_name} in course {query_body.course_id} and notebook={query_body.notebook_id}")

        if query_body.rubric_link:
            # Read rubric notebook using the application's service account, not the logged-in user's credentials.
            notebook_content = await asyncio.to_thread(
                load_notebook_from_google_drive_sa, config.firestore_cred_dict, str(query_body.rubric_link)
            )
            if notebook_content is None:
                raise HTTPException(
                    status_code=404, detail=f"Rubric notebook '{query_body.rubric_link}' not found. Ensure it is shared with the service account: {config.firestore_cred_dict.get('client_email')}"
                )

            try:
                # .ipynb files are JSON, so we can return them as JSON
                notebook_json = json.loads(notebook_content)
            except json.JSONDecodeError:
                # Or return as plain text if it's not valid JSON for some reason
                return HTMLResponse(content=f"<pre>Could not parse notebook as JSON. Raw content:\n\n{notebook_content}</pre>")


        try:
            # Attempt to get the response using the current session ID
            response_text = await run_agent_and_get_response(session_id, user_id, content, runner)
        except ValueError as e:
            # This error indicates the session ID in the cookie is stale or invalid.
            if "Session not found" in str(e):
                print(f"Stale session ID '{session_id}' detected. Creating and retrying with a new session.")
                # Create a new session ID
                new_session_id = str(uuid.uuid4())
                # Explicitly create the new session in the database before using it.
                await config.session_service.create_session(
                    app_name=runner.app_name,
                    user_id=user_id,
                    session_id=new_session_id
                )
                request.session['agent_session_id'] = new_session_id
                response_text = await run_agent_and_get_response(new_session_id, user_id, content, runner)
            else:
                # Re-raise any other ValueError that is not a session not found error.
                raise

        if not response_text:
            raise HTTPException(status_code=500, detail="Failed to generate response")

        return QueryResponse(
            response=response_text
            )

    except KeyError:
        raise HTTPException(status_code=401, detail="Invalid session data. Please login again.")
    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during query processing: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/grade", response_model=GradeResponse)
async def grade(query_body: GradeRequest, request: Request):

    '''Grade a single question-answer'''
    runner = config.runner_score

    if ('user' in request.session) : #user is logged and authenticated
        user_id = request.session['user']['id']
    else:
        user_id = query_body.user_email if query_body.user_email else "anonymous_user"

    user_name = query_body.user_name if query_body.user_name else "Anonymous User"

    try:
        # Use a consistent session ID for the agent conversation

        if 'agent_session_id' in request.session:
            session_id = request.session.get('agent_session_id')
        else:
            session_id = str(uuid.uuid4())
            request.session['agent_session_id'] = session_id
            await config.session_service.create_session(
                    app_name=runner.app_name,
                    user_id=user_id,
                    session_id=session_id
                )

        if not query_body.question:
            raise HTTPException(status_code=400, detail="Question not provided")

        question = query_body.question + "."
        answer = query_body.answer + "." if query_body.answer else "No answer."
        rubric = query_body.rubric if query_body.rubric else "No rubric"

        marks, response_text = await score_question(question, answer, rubric, runner, config.session_service, user_id)

        return GradeResponse(
            response=response_text,
            marks=marks
        )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during query processing: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/eval", response_model=EvalResponse)
async def eval_submission(query_body: EvalRequest, request: Request):
    '''Evaluate the submitted notebook by grading all questions using the scoring agent'''

    # Check if eval API is enabled by instructor
    if not config.isactive_eval:
        raise HTTPException(status_code=503, detail="The evaluation API endpoint is currently inactive")

    runner = config.runner_score

    try:

        if not query_body.user_name or not query_body.user_email or not query_body.answer_notebook or not query_body.rubric_link or not query_body.answer_hash:
            raise HTTPException(status_code=400, detail="Incomplete request. Please provide user_name, user_email, answer_notebook, asnwer_hash and rubric_link")

        user_email = query_body.user_email
        user_name = query_body.user_name

        answer_json = query_body.answer_notebook
        answer_hash = query_body.answer_hash
        rubric_link = query_body.rubric_link

        #extract the cells from the notebook
        if ('ipynb' in answer_json): #remove one hierarchy if present
            answer_json = answer_json['ipynb']

        answer_cells = answer_json['cells'] if 'cells' in answer_json else []
        logging.debug(f"Number of answer cells: {len(answer_cells)}")
        if len(answer_cells) == 0:
            logging.debug(f"answer_json={answer_json}")
        #extract google validated name, and id.
        #This is stored in the metadata of the execution info for any code  cell of the notebook
        google_user_name = None
        google_user_id = None
        for i in range(len(answer_cells)):
            cell = answer_cells[i]
            if (cell.get('cell_type') == 'code' and
                'metadata' in cell and
                'executionInfo' in cell.get('metadata', {}) and
                cell['metadata']['executionInfo'].get('status') == 'ok'):
                    google_user_name = cell['metadata']['executionInfo']['user']['displayName']
                    google_user_id = cell['metadata']['executionInfo']['user']['userId']
                    break

        if not google_user_name:
            google_user_name = "Unknown"
            google_user_id = "Unknown"
            logging.warning("Warning: Could not extract google user name and id from notebook metadata.Need to run at least one code cell")

        logging.info(f"google_user_name={google_user_name}, google_user_id={google_user_id}")

        add_user_if_not_exists(config.db, query_body.course_id, google_user_id, user_name, user_email, google_user_name)

        add_answer_notebook(config.db, google_user_id, query_body.notebook_id, query_body.answer_notebook, answer_hash)

        # Read rubric notebook using the application's service account, not the logged-in user's credentials.
        logging.info(f"rubric link is {query_body.rubric_link}")
        rubric_content = await asyncio.to_thread(
            load_notebook_from_google_drive_sa, config.firestore_cred_dict, str(rubric_link)
        )
        if rubric_content is None:
            raise HTTPException(
                status_code=404, detail=f"{user_name} ({user_email}) Rubric notebook '{rubric_link}' not found. Ensure it is shared with the service account: {config.firestore_cred_dict.get('client_email')}"
            )
        try:
            # .ipynb files are JSON, so we can return them as JSON
            rubric_json = json.loads(rubric_content)
        except json.JSONDecodeError:
            # Or return as plain text if it's not valid JSON for some reason
            return HTMLResponse(content=f"<pre>Could not parse notebook as JSON. Raw content:\n</pre>")

        try:
            total_marks, max_marks, num_questions, graded = await evaluate(answer_json, rubric_json, runner, config.session_service, google_user_id)

            logging.info(f"{google_user_name}: Evaluation completed. Total Marks: {total_marks}/{max_marks} for {num_questions} questions.")

            update_marks(config.db, google_user_id, query_body.notebook_id, total_marks, max_marks, graded)

            return EvalResponse(
                response=google_user_name + ": You have successfully submitted notebook for evaluation. Graded answer will be sent to your email.",
                marks=0.0
            )
        except Exception as e:
            # By logging the exception with its traceback, you can see the root cause in your server logs.
            logging.error("An exception occurred during query processing: %s", e)
            traceback.print_exc()

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during query processing: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


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
    instructor_gmail = courses.get(course_handle, {}).get('instructor_gmail', '').lower()
    if user_gmail.lower() not in [instructor_gmail, config.admin_email]:
        logging.warning(f"Unauthorized access attempt by {user_gmail} for course {course_handle}. Instructor: {instructor_gmail}, Admin: {config.admin_email}")
        return False
    return True

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
    query_body: TutorInteractionRequest,
    request: Request
):
    '''
    Disable the eval endpoint.
    This endpoint is only accessible to instructors.
    '''
    user = get_current_user(request)

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    try:
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin")
        courses[course_handle]['isactive_eval'] = False
        await update_course_info(config.db, course_handle, 'isactive_eval', False)
        logging.info(f"Instructor {user_gmail} has disabled the eval API")
        return {"message": "Eval API has been disabled successfully"}
    except Exception as e:
        logging.error("An exception occurred during disable_eval: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/enable_eval")
async def enable_eval(
    query_body: TutorInteractionRequest,
    request: Request
):
    '''
    Enable the eval endpoint.
    This endpoint is only accessible to instructors.
    '''
    user = get_current_user(request)

    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    try:
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin")
        courses[course_handle]['isactive_eval'] = True
        await update_course_info(config.db, course_handle, 'isactive_eval', True)
        logging.info(f"Instructor {user_gmail} has enabled the eval API")
        return {"message": "Eval API has been enabled successfully"}
    except Exception as e:
        logging.error("An exception occurred during enable_eval: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/fetch_student_list")
async def fetch_student_list_api(
    query_body: TutorInteractionRequest,
    request: Request
):
    '''
    Fetch the list of students from the database.
    Returns a dictionary of user_id to name and email.
    This endpoint is only accessible to instructors.
    '''
    user = get_current_user(request)
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    logging.info(f"Instructor {current_user.get('email')} is fetching student list")

    try:
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin")

        student_list = await get_student_list(config.db, course_handle)
        logging.info(f"Found {len(student_list)} students in course {course_handle}")

        return TutorInteractionResponseResponse(
            response=student_list
        )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during fetch_student_list_api: %s", e)
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

        grader_response = fetch_grader_response(config.db, course_handle, query_body.notebook_id, student_id)
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


@app.post("/notify_student_grades", response_model=NotifyGradedResponse)
async def notify_student_grades_api(
    query_body: NotifyGradedRequest,
    request: Request
):
    '''Fetch the graded response for a student from the database and send email notification.
    If user_email is provided, sends email to that specific student.
    If user_email is None, sends email to all students who have graded submissions for the notebook.
    This endpoint is only accessible to instructors.'''

    user = get_current_user(request)
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)

    try:

        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin")

            
        student_id = query_body.student_id

        grader_response = fetch_grader_response(config.db, course_handle, query_body.notebook_id, query_body.student_id)
        if not grader_response:
            logging.warning(f"No graded response found for student_id={student_id} and notebook_id={query_body.notebook_id}")
            raise HTTPException(status_code=404, detail="No graded response found")

        total_marks = grader_response.get('total_marks', 0)
        max_marks = grader_response.get('max_marks', 0)
        subject = f"Graded Response for your submission {query_body.notebook_id}"
        msg_body = f"Hello {user_name},\n\n Your marks in {query_body.notebook_id} is {total_marks} out of {max_marks}. \n\nDetailed feedback for your submission"

        msg_body += json.dumps(grader_response, indent=4)

        msg_body += "\n\nBest regards,\nYour fiendly AI-TA"

        logging.info(f"Instructor {user_gmail} is sending email to {student_id} with subject '{subject}'")

        email_sent = send_email(config.sendgrid_client, config.sendgrid_from_email, student_id, subject, msg_body)

        if email_sent:
            return NotifyGradedResponse(
                response=f"Successfully sent email to {user_email} with graded response."
            )
        else:
            raise HTTPException(
                status_code=500,
                detail="Failed to send email. Please check server logs and ensure email service is properly configured."
            )
    
    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during notify_student_grades_api: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/upload_rubric", response_model=AddRubricResponse)
async def upload_rubric_api(
    query_body: AddRubricRequest,
    request: Request
):
    '''
    Add a rubric to a course.
    This endpoint is only accessible to platform administrators.
    The questions cells, the answer cells and the context cells
    (everything other than the question and aswer cells)
    The context is auto-regressive (context for each question is all cells
    from beginnig till the question cell)

    These are stored in the databse as well as cached.
    '''

    user = get_current_user(request)
    course_handle = make_course_handle(query_body.institution_id, query_body.term_id, query_body.course_id)
    rubric_notebook = query_body.rubric_notebook
    try:
        user = get_current_user(request)
        user_gmail = user.get('email', '').lower()
        if not is_authorized(user_gmail, course_handle) :
            raise HTTPException(status_code=403, detail="User is not an instructor  for this course nor a platform admin")

        #extract the cells from the notebook
        if ('ipynb' in rubric_notebook): #remove one hierarchy if present
            rubric_notebook = rubric_notebook['ipynb']

        rubric_cells = rubric_notebook['cells'] if 'cells' in rubric_notebook else []
        logging.debug(f"Number of rubric cells: {len(rubric_cells)}")
        if len(rubric_cells) == 0:
            logging.debug(f"rubric_notebook={rubric_notebook}")
            raise HTTPException(status_code=400, detail="No cells found in the rubric notebook")

        # Parse and Save the rubric to the database and in the cache
        courses[course_handle][notebook_id]= parse_and_save_rubric(config.db, course_handle, query_body, rubric_cells)

        return AddRubricResponse(
            response=f"Successfully added rubric '{query_body.rubric_name}' to course '{course_handle}'"
        )
    except Exception as e:
        logging.error("An exception occurred during add_rubric_api: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")

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

        course_doc = does_course_exist(config.db, course_handle)
        if course_doc:
            courses[course_handle] = course_doc.to_dict()
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
        courses[course_handle]['isactive_eval']= False

        if create_course(config.db, courses[course_handle]):
            logging.info(f"Admin {current_user.get('email')} created course '{query_body.course_name}' ({courses[course_handle]['course_id']})")

            return CreateCourseResponse(
                response=f"Course '{courses[course_handle]['institution_id']}'/'{courses[course_handle]['term_id']}'/'{courses[course_handle]['course_id']}') created successfully."
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
    uvicorn.run(app, host="0.0.0.0", port=port) #allow access from any IP address
