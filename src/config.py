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

from google.cloud import secretmanager
from dotenv import load_dotenv

import firebase_admin
from firebase_admin import credentials, firestore

from google.adk import Runner
from google.adk.sessions import DatabaseSessionService

from sendgrid import SendGridAPIClient


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

enable_assist = False
active_eval_api = False


# --- Admin Emails ---

admin_emails_env = os.environ.get('ADMIN_EMAILS', '')
ADMIN_EMAILS = [email.strip() for email in admin_emails_env.split(',') if email.strip()]

if not ADMIN_EMAILS:
    logging.warning("No admin emails configured. Set ADMIN_EMAILS environment variable with comma-separated email addresses.")


# --- Instructor Emails ---

instructor_emails_env = os.environ.get('INSTRUCTOR_EMAILS', '')
INSTRUCTOR_EMAILS = [email.strip() for email in instructor_emails_env.split(',') if email.strip()]

if not INSTRUCTOR_EMAILS:
    logging.warning("No instructor emails configured. Set INSTRUCTOR_EMAILS environment variable with comma-separated email addresses.")


# --- OAuth Scopes ---

SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
    "https://www.googleapis.com/auth/drive.readonly",  # Add scope to read Google Drive files
    'https://www.googleapis.com/auth/gmail.send', #send email
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
        print(f"Error accessing secret: {e}", file=sys.stderr)
        return None


def load_app_config():
    """Loads all configuration from environment variables and Secret Manager, then initializes services."""
    load_dotenv(interpolate=True)

    # --- Helper functions for loading ---
    def get_required_env(var_name):
        value = os.environ.get(var_name)
        if not value:
            print(f"Error: Required environment variable '{var_name}' is not set.", file=sys.stderr)
            sys.exit(1)
        return value

    project_id = get_required_env("GOOGLE_CLOUD_PROJECT")

    def get_required_secret(key_name_env_var):
        secret_name = get_required_env(key_name_env_var)
        payload = access_secret_payload(project_id, secret_name)
        if not payload:
            print(f"Error: Could not retrieve secret '{secret_name}' from Secret Manager for project '{project_id}'.", file=sys.stderr)
            sys.exit(1)
        return payload

    # --- Load all required values ---
    is_production = os.environ.get('PRODUCTION', '0') == '1'
    database_id = get_required_env('FIRESTORE_DATABASE_ID')
    oauth_client_id = get_required_secret('OAUTH_CLIENT_ID_KEY_NAME')
    oauth_client_secret = get_required_secret('OAUTH_CLIENT_SECRET_KEY_NAME')
    signing_secret_key = get_required_secret('SIGNING_SECRET_KEY_NAME')
    firestore_key_id = get_required_secret('FIRESTORE_PRIVATE_KEY_ID_KEY_NAME')
    firestore_key_raw = get_required_secret('FIRESTORE_PRIVATE_KEY_KEY_NAME')
    gemini_api_key = get_required_secret('GEMINI_API_KEY_NAME')

    # Get SendGrid API key from Secret Manager
    sendgrid_api_key = access_secret_payload(project_id, 'sendgrid-api-key')
    if not sendgrid_api_key:
        print("Warning: SendGrid API key not found. Email notifications will be disabled.", file=sys.stderr)

    # Get OAuth redirect URI from environment (for development with ngrok)
    # If not set, use default based on production flag
    oauth_redirect_uri = os.environ.get('OAUTH_REDIRECT_URI', '')

    # --- Configure services ---
    if not is_production:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        print("Running in development mode. Insecure OAUTH callback enabled.")
        if oauth_redirect_uri:
            print(f"Using custom OAuth redirect URI: {oauth_redirect_uri}")

    # --- Construct configuration dictionaries ---
    firestore_key = firestore_key_raw.replace('\\n', '\n')
    firestore_cred_dict = {
        "type": "service_account",
        "project_id": project_id,
        "private_key_id": firestore_key_id,
        "private_key": firestore_key,
        "client_email": "cp220-firestore@cp220-grading-assistant.iam.gserviceaccount.com",
        "client_id": "101156988112383641306",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/cp220-firestore%40cp220-grading-assistant.iam.gserviceaccount.com",
        "universe_domain": "googleapis.com"
    }

    # Build redirect URIs list
    default_redirect_uris = [
        "http://localhost:8080/callback",
        "https://cp220-grader-api-622756405105.asia-south1.run.app/callback",
    ]

    # Add custom redirect URI from environment if provided (e.g., ngrok URL)
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
    if is_production:
        redirect_uri_index = 1  # Use Cloud Run URL
    elif oauth_redirect_uri:
        redirect_uri_index = 2  # Use custom redirect URI (e.g., ngrok)
    else:
        redirect_uri_index = 0  # Use localhost

    selected_redirect_uri = default_redirect_uris[redirect_uri_index]
    print(f"OAuth Configuration:")
    print(f"  Production mode: {is_production}")
    print(f"  Selected redirect URI: {selected_redirect_uri}")
    print(f"  Available redirect URIs: {default_redirect_uris}")

    return {
        "project_id": project_id,
        "database_id": database_id,
        "signing_secret_key": signing_secret_key,
        "firestore_cred_dict": firestore_cred_dict,
        "client_config": client_config,
        "redirect_uri_index": redirect_uri_index,
        "gemini_api_key": gemini_api_key,
        "sendgrid_api_key": sendgrid_api_key,
        "is_production": is_production
    }


# --- Application Startup ---

_config = load_app_config()

# Initialize Firebase Admin with loaded credentials
try:
    cred = credentials.Certificate(_config["firestore_cred_dict"])
    firebase_admin.initialize_app(cred)
    db = firestore.client(database_id=_config["database_id"])
except Exception as e:
    print(f"Fatal Error: Could not initialize Firebase/Firestore. {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)

# Initialize SendGrid email service
sendgrid_from_email = os.environ.get('SENDGRID_FROM_EMAIL', '')
_sendgrid_api_key = _config.get('sendgrid_api_key')

if _sendgrid_api_key and sendgrid_from_email:
    try:
        sendgrid_client = SendGridAPIClient(_sendgrid_api_key)
        logging.info(f"SendGrid email service initialized, sending as: {sendgrid_from_email}")
    except Exception as e:
        logging.error(f"Failed to initialize SendGrid service: {e}")
        sendgrid_client = None
else:
    if not _sendgrid_api_key:
        logging.warning("SendGrid API key not found in Secret Manager (sendgrid-api-key). Email notifications will not work.")
    if not sendgrid_from_email:
        logging.warning("SENDGRID_FROM_EMAIL not configured. Email notifications will not work.")
        logging.warning("Set SENDGRID_FROM_EMAIL environment variable to enable email notifications.")
    sendgrid_client = None

client_config = _config["client_config"]
signing_secret_key = _config["signing_secret_key"]
REDIRECT_URI_INDEX = _config["redirect_uri_index"]
firestore_cred_dict = _config["firestore_cred_dict"]
is_production = _config["is_production"]

os.environ['GOOGLE_API_KEY'] = str(_config["gemini_api_key"])

# Import agents (must be after GOOGLE_API_KEY is set)
import agent
root_agent = agent.root_agent
scoring_agent = agent.scoring_agent

# Create a database session service
# Use aiosqlite for async support (required for Cloud Run deployment)
session_service = DatabaseSessionService(
    db_url="sqlite+aiosqlite:///agent_sessions.db"
)

# Create runners with the agents
runner_assist = Runner(
    app_name="CP220_2025_Grader_Agent_API",
    agent=root_agent,
    session_service=session_service
)
runner_score = Runner(
    app_name="CP220_2025_Scoring_Agent_API",
    agent=scoring_agent,
    session_service=session_service
)
