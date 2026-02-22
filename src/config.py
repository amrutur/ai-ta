"""
Configuration, secrets management, and service initialization.

Loads environment variables and secrets from Google Secret Manager,
initializes Firebase/Firestore, SendGrid, and the AI agent runners.

All initialized services are exposed as module-level variables for
import by other modules.
"""

import os
import sys
import logging
import traceback
import urllib.parse

from google.cloud import secretmanager
from dotenv import load_dotenv

import firebase_admin
from firebase_admin import credentials, firestore

from google.adk import Runner
from google.adk.sessions import DatabaseSessionService

from sendgrid import SendGridAPIClient

from fastapi import HTTPException


import agent


# --- Logging Configuration ---

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s] - %(message)s')

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('app.log', mode='a')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG)

root_logger = logging.getLogger()
root_logger.addHandler(console_handler)
root_logger.addHandler(file_handler)
root_logger.setLevel(logging.DEBUG)

logging.getLogger("starlette").setLevel(logging.INFO)
logging.getLogger("google_adk").setLevel(logging.DEBUG)
logging.getLogger("aiosqlite").setLevel(logging.INFO)
logging.getLogger("google.adk").setLevel(logging.DEBUG)
logging.getLogger("google.adk.runner").setLevel(logging.DEBUG)
logging.getLogger("google.adk.agents").setLevel(logging.DEBUG)


# --- Feature Flags ---
# Controlled via /enable_tutor, /disable_tutor, /enable_eval, /disable_eval endpoints

#set to true to enable assist api
isactive_tutor = True

#set to true to enable eval api
isactive_eval = False


# --- Admin Emails ---

admin_email = os.environ.get('ADMIN_EMAIL', '').lower()

if not admin_email:
    logging.error("No admin email configured. Set ADMIN_EMAIL environment variable.")
    raise HTTPException(status_code=500, detail="Server configuration error: No admin email  configured.")

# --- OAuth Scopes ---

SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"
]


# --- Secrets ---

def access_secret_payload(project_id: str, secret_id: str, version_id: str = "latest") -> str:
    """
    Access the payload for the given secret version from google secret manager
    and return it.
    """
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = client.access_secret_version(request={"name": name})
        payload = response.payload.data.decode("UTF-8")
        return payload
    except Exception as e:
        logging.error(f"Error accessing secret: {e}")
        raise HTTPException(status_code=500, detail=f"Error accessing secret '{secret_id}': {e}")

# --- Helper functions for loading ---
def get_required_env(var_name):
    value = os.environ.get(var_name)
    if not value:
        logging.error(f"Error: Required environment variable '{var_name}' is not set.")
        sys.exit(1)
    return value


def get_required_secret(project_id:str, key_name_env_var:str):
    secret_name = get_required_env(key_name_env_var)
    payload = access_secret_payload(project_id, secret_name)
    if not payload:
        logging.error(f"Error: Could not retrieve secret '{secret_name}' from Secret Manager for project '{project_id}'.")
        sys.exit(1)
    return payload

def load_app_config():
    """Loads all configuration from environment variables and Secret Manager, then initializes services."""
    load_dotenv(interpolate=True)


    project_id = get_required_env("GOOGLE_CLOUD_PROJECT")

    # --- Load all required values ---
    is_production = os.environ.get('PRODUCTION', '0') == '1'
    database_id = get_required_env('FIRESTORE_DATABASE_ID')
    oauth_client_id = get_required_secret(project_id,'OAUTH_CLIENT_ID_KEY_NAME')
    oauth_client_secret = get_required_secret(project_id,'OAUTH_CLIENT_SECRET_KEY_NAME')
    signing_secret_key = get_required_secret(project_id, 'SIGNING_SECRET_KEY_NAME')
    firestore_key_id = get_required_secret(project_id, 'FIRESTORE_PRIVATE_KEY_ID_KEY_NAME')
    firestore_key_raw = get_required_secret(project_id,'FIRESTORE_PRIVATE_KEY_KEY_NAME')
    # Gemini API key is optional — not needed when using Vertex AI with a service account
    gemini_api_key_name = os.environ.get('GEMINI_API_KEY_NAME', '')
    sendgrid_from_email = os.environ.get('SENDGRID_FROM_EMAIL', '')    
    sendgrid_api_key = ''
    if not sendgrid_from_email:
        logging.warning("SENDGRID_FROM_EMAIL environment variable not set. Email notifications will not work.")
    else:
        # Get SendGrid API key from Secret Manager
        sendgrid_api_key = access_secret_payload(project_id, 'sendgrid-api-key')
    bucket_name = os.environ.get('BUCKET_NAME',project_id+ '-bucket')    
    gemini_api_key = None
    if gemini_api_key_name:
        gemini_api_key = access_secret_payload(project_id, gemini_api_key_name)
        if not gemini_api_key:
            logging.warning(f"Could not retrieve Gemini API key from secret '{gemini_api_key_name}'. "
                            "Falling back to Vertex AI service account auth.")
    

    # Get OAuth redirect URI from environment (for development with ngrok)
    # If not set, use default based on production flag
    oauth_redirect_uri = os.environ.get('OAUTH_REDIRECT_URI', '')

    # --- Configure services ---
    if not is_production:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        logging.info("Running in development mode. Insecure OAUTH callback enabled.")
        if oauth_redirect_uri:
            logging.info(f"Using custom OAuth redirect URI: {oauth_redirect_uri}")

    # --- Construct configuration dictionaries ---
    firestore_key = firestore_key_raw.replace('\\n', '\n')
    service_account_email = get_required_env("SERVICE_ACCOUNT_EMAIL")
    firestore_client_id = get_required_env("FIRESTORE_CLIENT_ID")

    # URL-encode the service account email for the cert URL
    encoded_sa_email = urllib.parse.quote(service_account_email, safe='')

    firestore_cred_dict = {
        "type": "service_account",
        "project_id": project_id,
        "private_key_id": firestore_key_id,
        "private_key": firestore_key,
        "client_email": service_account_email,
        "client_id": firestore_client_id,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/{encoded_sa_email}",
        "universe_domain": "googleapis.com"
    }

    # Build redirect URIs list
    default_redirect_uris = [
        "http://localhost:8080/callback",
    ]

    # Add custom redirect URI from environment if provided (e.g., Cloud Run URL or ngrok URL)
    if oauth_redirect_uri:
        default_redirect_uris.append(oauth_redirect_uri)

    client_config = {
        "web": {
            "client_id": oauth_client_id,
            "project_id": project_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": oauth_client_secret,
            "redirect_uris": default_redirect_uris,
        }
    }

    # Determine the correct redirect URI based on production status and environment
    if oauth_redirect_uri:
        redirect_uri_index = 1  # Use custom redirect URI (Cloud Run URL, ngrok, etc.)
    else:
        redirect_uri_index = 0  # Use localhost

    selected_redirect_uri = default_redirect_uris[redirect_uri_index]
    logging.info(f"OAuth Configuration:")
    logging.info(f"  Production mode: {is_production}")
    logging.info(f"  Selected redirect URI: {selected_redirect_uri}")
    logging.info(f"  Available redirect URIs: {default_redirect_uris}")

    return {
        "project_id": project_id,
        "database_id": database_id,
        "signing_secret_key": signing_secret_key,
        "firestore_cred_dict": firestore_cred_dict,
        "client_config": client_config,
        "redirect_uri_index": redirect_uri_index,
        "gemini_api_key": gemini_api_key,
        "sendgrid_api_key": sendgrid_api_key,
        "bucket_name": bucket_name,
        "is_production": is_production,
        "sendgrid_from_email": sendgrid_from_email
    }


# --- Application Startup ---

_config = load_app_config()

# Initialize Firebase Admin with loaded credentials
try:
    cred = credentials.Certificate(_config["firestore_cred_dict"])
    app = firebase_admin.initialize_app(cred)
    # firebase_admin.firestore has no async_client() helper, so construct
    # the AsyncClient directly using the app's service-account credentials.
    db = firestore.AsyncClient(
        credentials=app.credential.get_credential(),
        project=_config["project_id"],
        database=_config["database_id"],
    )
except Exception as e:
    print(f"Fatal Error: Could not initialize Firebase/Firestore. {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)

# Initialize SendGrid email service
_sendgrid_from_email = _config.get('send_grid_from_email')
_sendgrid_api_key = _config.get('sendgrid_api_key')

if _sendgrid_api_key and _sendgrid_from_email:
    try:
        sendgrid_client = SendGridAPIClient(_sendgrid_api_key)
        logging.info(f"SendGrid email service initialized, sending as: {_sendgrid_from_email}")
    except Exception as e:
        logging.error(f"Failed to initialize SendGrid service: {e}")
        sendgrid_client = None
else:
    if not _sendgrid_api_key:
        logging.warning("SendGrid API key not found in Secret Manager (sendgrid-api-key). Email notifications will not work.")
    if not _sendgrid_from_email:
        logging.warning("SENDGRID_FROM_EMAIL not configured. Email notifications will not work.")
        logging.warning("Set SENDGRID_FROM_EMAIL environment variable to enable email notifications.")
    sendgrid_client = None

client_config = _config["client_config"]
signing_secret_key = _config["signing_secret_key"]
REDIRECT_URI_INDEX = _config["redirect_uri_index"]
firestore_cred_dict = _config["firestore_cred_dict"]
is_production = _config["is_production"]
bucket_name = _config["bucket_name"]

# Set Gemini API key if provided; otherwise Vertex AI uses service account auth
if _config.get("gemini_api_key"):
    os.environ['GOOGLE_API_KEY'] = str(_config["gemini_api_key"])

# Create a database session service
# Use aiosqlite for async support (required for Cloud Run deployment)
session_service = DatabaseSessionService(
    db_url="sqlite+aiosqlite:///agent_sessions.db"
)

# Create runners — one per agent, since Runner.run_async() does not
# support overriding the agent at call time.
runner_instructor = Runner(
    app_name="ai_ta",
    agent=agent.instructor_assist_agent,
    session_service=session_service
)
runner_student = Runner(
    app_name="ai_ta",
    agent=agent.student_assist_agent,
    session_service=session_service
)
runner_scoring = Runner(
    app_name="ai_ta",
    agent=agent.scoring_assist_agent,
    session_service=session_service
)   