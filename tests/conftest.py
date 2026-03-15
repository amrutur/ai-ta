"""
Shared test fixtures and configuration.

Injects a mock ``config`` module into ``sys.modules`` BEFORE any application
code is imported, so that ``api_server.py`` (which does ``import config`` at
module level) uses the mock instead of connecting to GCP services.
"""

import sys
import os
from unittest.mock import MagicMock, AsyncMock

import pytest

# ---------------------------------------------------------------------------
# 1. Add src/ to the Python path so tests can import application modules.
# ---------------------------------------------------------------------------
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# ---------------------------------------------------------------------------
# 2. Build and inject a mock ``config`` module.
#    config.py normally runs GCP calls (Secret Manager, Firebase init) at
#    import time.  We replace the entire module with a MagicMock whose
#    attributes are set to realistic test values.
# ---------------------------------------------------------------------------
_mock_config = MagicMock()

# Scalar / simple attributes consumed at module-level by api_server.py
_mock_config.signing_secret_key = "test-secret-key-for-unit-tests"
_mock_config.admin_email = "admin@test.com"
_mock_config.is_production = False
_mock_config.isactive_eval = True
_mock_config.isactive_tutor = True
_mock_config.bucket_name = "test-bucket"
_mock_config._mail_api_key = None
_mock_config._from_email = None
_mock_config.REDIRECT_URI_INDEX = 0
_mock_config.SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
]
_mock_config.client_config = {
    "web": {
        "client_id": "test-client-id",
        "project_id": "test-project",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_secret": "test-client-secret",
        "redirect_uris": ["http://localhost:8080/callback"],
    }
}
_mock_config.firestore_cred_dict = {
    "type": "service_account",
    "project_id": "test-project",
    "client_email": "test@test-project.iam.gserviceaccount.com",
}

# Firestore async client mock
_mock_config.db = AsyncMock()

# ADK Runner mocks
_mock_config.runner_instructor = MagicMock()
_mock_config.runner_instructor.app_name = "ai_ta"
_mock_config.runner_student = MagicMock()
_mock_config.runner_student.app_name = "ai_ta"
_mock_config.runner_scoring = MagicMock()
_mock_config.runner_scoring.app_name = "ai_ta"

# Session service factory mock — returns a fresh AsyncMock per call
_mock_config.get_session_service = MagicMock(side_effect=lambda *args, **kwargs: AsyncMock())

# Inject BEFORE anything tries to ``import config``
sys.modules["config"] = _mock_config

# ---------------------------------------------------------------------------
# 2b. Inject mock ``firestore_service`` module.
#     The real module imports google.cloud.firestore_v1.AsyncClient and
#     google.adk.sessions internals.  For tests we only need the class name
#     so that ``from firestore_service import FirestoreSessionService``
#     resolves.  We use a simple mock class.
# ---------------------------------------------------------------------------
_mock_firestore_service = MagicMock()
_mock_firestore_service.FirestoreSessionService = MagicMock
sys.modules["firestore_service"] = _mock_firestore_service


# ---------------------------------------------------------------------------
# 3. Common fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    """Fresh AsyncMock Firestore client for database function tests."""
    db = AsyncMock()

    # Default: document exists with sample data
    mock_doc = AsyncMock()
    mock_doc.exists = True
    mock_doc.id = "test-doc"
    mock_doc.to_dict.return_value = {"course_name": "Test Course"}
    mock_doc.reference = AsyncMock()
    db.collection.return_value.document.return_value.get.return_value = mock_doc

    return db


@pytest.fixture
def mock_runner():
    """Mock ADK Runner."""
    runner = MagicMock()
    runner.app_name = "ai_ta"
    return runner


@pytest.fixture
def mock_session_service():
    """Mock FirestoreSessionService."""
    return AsyncMock()
