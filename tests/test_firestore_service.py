"""
Tests for the FirestoreSessionService — custom Firestore-backed session service for ADK.
"""

import copy
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from google.adk.sessions import Session, State
from google.adk.sessions.base_session_service import GetSessionConfig
from google.adk.events import Event
from google.cloud.firestore_v1.async_client import AsyncClient

# We need to un-mock firestore_service for these tests since we're testing it directly
import importlib
import sys


# Import the real module — conftest injects a mock, so reload from source
@pytest.fixture(autouse=True)
def _real_firestore_service():
    """Temporarily restore the real firestore_service module for this test file."""
    # Remove the mock
    mock_mod = sys.modules.pop("firestore_service", None)
    # Import the real one
    import firestore_service as real_mod
    importlib.reload(real_mod)
    yield real_mod
    # Restore the mock after tests
    if mock_mod is not None:
        sys.modules["firestore_service"] = mock_mod


@pytest.fixture
def async_db():
    """Create a mock async Firestore client with proper chaining."""
    db = AsyncMock(spec=AsyncClient)
    return db


@pytest.fixture
def service(_real_firestore_service, async_db):
    """Create a FirestoreSessionService with a mock DB."""
    return _real_firestore_service.FirestoreSessionService(db=async_db, collection="test_sessions")


def _mock_doc(exists=True, data=None):
    doc = MagicMock()
    doc.exists = exists
    doc.to_dict.return_value = data or {}
    doc.id = str(uuid.uuid4())
    doc.reference = AsyncMock()
    return doc


class TestSessionRefHelpers:
    def test_session_ref_path(self, service, async_db):
        """_session_ref should chain through collection/document properly."""
        ref = service._session_ref("app1", "user1", "sess1")
        async_db.collection.assert_called_with("test_sessions")

    def test_events_collection(self, service, async_db):
        """_events_collection should return subcollection of session ref."""
        ref = service._events_collection("app1", "user1", "sess1")
        # Just verify it doesn't error and returns something
        assert ref is not None

    def test_app_state_ref(self, service, async_db):
        """_app_state_ref should navigate to _meta/app_state."""
        ref = service._app_state_ref("app1")
        assert ref is not None

    def test_user_state_ref(self, service, async_db):
        """_user_state_ref should navigate to users/{user_id}/_meta/user_state."""
        ref = service._user_state_ref("app1", "user1")
        assert ref is not None


class TestMergeState:
    def test_merges_app_and_user_state(self, service):
        """_merge_state should prefix keys with app: and user: prefixes."""
        session = Session(
            app_name="app1", user_id="u1", id="s1",
            state={"local_key": "val"},
            last_update_time=time.time(),
        )
        app_state = {"setting": "dark"}
        user_state = {"pref": "large"}

        result = service._merge_state(session, app_state, user_state)

        assert result.state[State.APP_PREFIX + "setting"] == "dark"
        assert result.state[State.USER_PREFIX + "pref"] == "large"
        assert result.state["local_key"] == "val"

    def test_empty_states(self, service):
        """Merging empty dicts should not alter session state."""
        session = Session(
            app_name="a", user_id="u", id="s",
            state={"key": "value"},
            last_update_time=0.0,
        )
        result = service._merge_state(session, {}, {})
        assert result.state == {"key": "value"}


class TestGetSetAppState:
    async def test_get_app_state_existing(self, service):
        """Should return stored state dict when doc exists."""
        doc = _mock_doc(exists=True, data={"state": {"theme": "dark"}})
        mock_ref = AsyncMock()
        mock_ref.get = AsyncMock(return_value=doc)

        with patch.object(service, "_app_state_ref", return_value=mock_ref):
            result = await service._get_app_state("app1")
        assert result == {"theme": "dark"}

    async def test_get_app_state_missing(self, service):
        """Should return empty dict when doc doesn't exist."""
        doc = _mock_doc(exists=False)
        mock_ref = AsyncMock()
        mock_ref.get = AsyncMock(return_value=doc)

        with patch.object(service, "_app_state_ref", return_value=mock_ref):
            result = await service._get_app_state("app1")
        assert result == {}


class TestCreateSession:
    async def test_creates_new_session(self, service):
        """create_session should store a new session and return it."""
        not_exists_doc = _mock_doc(exists=False)
        empty_state_doc = _mock_doc(exists=False)

        mock_session_ref = AsyncMock()
        mock_session_ref.get = AsyncMock(return_value=not_exists_doc)
        mock_session_ref.set = AsyncMock()

        with patch.object(service, "_session_ref", return_value=mock_session_ref), \
             patch.object(service, "_get_app_state", new_callable=AsyncMock, return_value={}), \
             patch.object(service, "_get_user_state", new_callable=AsyncMock, return_value={}):
            session = await service.create_session(
                app_name="app1", user_id="user1", session_id="sess1",
                state={"key": "val"},
            )

        assert session.app_name == "app1"
        assert session.user_id == "user1"
        assert session.id == "sess1"

    async def test_auto_generates_session_id(self, service):
        """If session_id is None, a UUID should be generated."""
        not_exists_doc = _mock_doc(exists=False)

        mock_session_ref = AsyncMock()
        mock_session_ref.get = AsyncMock(return_value=not_exists_doc)
        mock_session_ref.set = AsyncMock()

        with patch.object(service, "_session_ref", return_value=mock_session_ref), \
             patch.object(service, "_get_app_state", new_callable=AsyncMock, return_value={}), \
             patch.object(service, "_get_user_state", new_callable=AsyncMock, return_value={}):
            session = await service.create_session(
                app_name="app1", user_id="user1",
            )

        assert session.id is not None
        uuid.UUID(session.id)  # Will raise if not valid UUID


class TestDeleteSession:
    async def test_deletes_events_and_session(self, service, async_db):
        """delete_session should delete all events then the session doc."""
        # Mock events subcollection stream
        event_doc = AsyncMock()
        event_doc.reference = AsyncMock()

        async def mock_stream():
            yield event_doc

        events_ref = MagicMock()
        events_ref.stream = mock_stream

        session_ref = AsyncMock()

        with patch.object(service, "_events_collection", return_value=events_ref), \
             patch.object(service, "_session_ref", return_value=session_ref):
            await service.delete_session(app_name="a", user_id="u", session_id="s")

        event_doc.reference.delete.assert_awaited_once()
        session_ref.delete.assert_awaited_once()
