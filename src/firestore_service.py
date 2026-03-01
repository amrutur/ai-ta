"""
Custom Firestore-backed session service for Google ADK.

Replaces the ADK's built-in FirestoreSessionService (not available in all
ADK versions) with a direct implementation using the async Firestore client.

Sessions are stored in Firestore with configurable collection paths via
a template string (e.g. "sessions/{app_name}/{user_id}/{session_id}").

Each session document stores metadata (app_name, user_id, state,
last_update_time) and events are stored as sub-documents in an "events"
subcollection for scalability.
"""

import copy
import logging
import time
import uuid
from typing import Any, Optional

from google.cloud.firestore_v1.async_client import AsyncClient

from google.adk.events import Event
from google.adk.sessions import BaseSessionService, Session, State, _session_util
from google.adk.sessions.base_session_service import GetSessionConfig, ListSessionsResponse

logger = logging.getLogger(__name__)


class FirestoreSessionService(BaseSessionService):
    """Firestore-backed session service compatible with Google ADK Runner.

    Args:
        db: An async Firestore client instance.
        collection: The root Firestore collection for storing sessions.
            Defaults to "agent_sessions".
    """

    def __init__(self, db: AsyncClient, collection: str = "agent_sessions"):
        self.db = db
        self.collection = collection

    # ---- internal helpers ----

    def _session_ref(self, app_name: str, user_id: str, session_id: str):
        """Return a document reference for a session."""
        return (
            self.db.collection(self.collection)
            .document(app_name)
            .collection("users")
            .document(user_id)
            .collection("sessions")
            .document(session_id)
        )

    def _events_collection(self, app_name: str, user_id: str, session_id: str):
        """Return the events subcollection reference for a session."""
        return self._session_ref(app_name, user_id, session_id).collection("events")

    def _app_state_ref(self, app_name: str):
        """Return a document reference for app-level state."""
        return (
            self.db.collection(self.collection)
            .document(app_name)
            .collection("_meta")
            .document("app_state")
        )

    def _user_state_ref(self, app_name: str, user_id: str):
        """Return a document reference for user-level state."""
        return (
            self.db.collection(self.collection)
            .document(app_name)
            .collection("users")
            .document(user_id)
            .collection("_meta")
            .document("user_state")
        )

    async def _get_app_state(self, app_name: str) -> dict[str, Any]:
        doc = await self._app_state_ref(app_name).get()
        if doc.exists:
            return doc.to_dict().get("state", {})
        return {}

    async def _set_app_state(self, app_name: str, delta: dict[str, Any]):
        ref = self._app_state_ref(app_name)
        doc = await ref.get()
        current = doc.to_dict().get("state", {}) if doc.exists else {}
        current.update(delta)
        await ref.set({"state": current}, merge=True)

    async def _get_user_state(self, app_name: str, user_id: str) -> dict[str, Any]:
        doc = await self._user_state_ref(app_name, user_id).get()
        if doc.exists:
            return doc.to_dict().get("state", {})
        return {}

    async def _set_user_state(self, app_name: str, user_id: str, delta: dict[str, Any]):
        ref = self._user_state_ref(app_name, user_id)
        doc = await ref.get()
        current = doc.to_dict().get("state", {}) if doc.exists else {}
        current.update(delta)
        await ref.set({"state": current}, merge=True)

    def _merge_state(self, session: Session, app_state: dict, user_state: dict) -> Session:
        """Merge app-level and user-level state into the session state."""
        for key, value in app_state.items():
            session.state[State.APP_PREFIX + key] = value
        for key, value in user_state.items():
            session.state[State.USER_PREFIX + key] = value
        return session

    # ---- BaseSessionService interface ----

    async def create_session(
        self,
        *,
        app_name: str,
        user_id: str,
        state: Optional[dict[str, Any]] = None,
        session_id: Optional[str] = None,
    ) -> Session:
        session_id = (
            session_id.strip()
            if session_id and session_id.strip()
            else str(uuid.uuid4())
        )

        # Check for duplicate
        existing = await self._session_ref(app_name, user_id, session_id).get()
        if existing.exists:
            logger.warning("Session %s already exists for user %s, returning existing.", session_id, user_id)
            return await self.get_session(app_name=app_name, user_id=user_id, session_id=session_id)

        # Separate state into app/user/session scopes
        state_deltas = _session_util.extract_state_delta(state or {})
        app_state_delta = state_deltas["app"]
        user_state_delta = state_deltas["user"]
        session_state = state_deltas["session"]

        # Persist app/user state if present
        if app_state_delta:
            await self._set_app_state(app_name, app_state_delta)
        if user_state_delta:
            await self._set_user_state(app_name, user_id, user_state_delta)

        now = time.time()
        session = Session(
            app_name=app_name,
            user_id=user_id,
            id=session_id,
            state=session_state or {},
            last_update_time=now,
        )

        # Store session document (without events — those go in subcollection)
        ref = self._session_ref(app_name, user_id, session_id)
        logger.info("Writing session to Firestore path: %s (collection=%s)", ref.path, self.collection)
        await ref.set({
            "app_name": app_name,
            "user_id": user_id,
            "state": session_state or {},
            "last_update_time": now,
        })

        logger.info("Created session %s for user %s in app %s", session_id, user_id, app_name)

        # Return session with merged state
        copied = copy.deepcopy(session)
        app_state = await self._get_app_state(app_name)
        user_state = await self._get_user_state(app_name, user_id)
        return self._merge_state(copied, app_state, user_state)

    async def get_session(
        self,
        *,
        app_name: str,
        user_id: str,
        session_id: str,
        config: Optional[GetSessionConfig] = None,
    ) -> Optional[Session]:
        doc = await self._session_ref(app_name, user_id, session_id).get()
        if not doc.exists:
            return None

        data = doc.to_dict()

        # Load events from subcollection, ordered by timestamp
        events = []
        events_ref = self._events_collection(app_name, user_id, session_id)
        async for event_doc in events_ref.order_by("timestamp").stream():
            event_data = event_doc.to_dict()
            try:
                event = Event.model_validate(event_data)
                events.append(event)
            except Exception as e:
                logger.warning("Failed to deserialize event %s: %s", event_doc.id, e)

        session = Session(
            app_name=app_name,
            user_id=user_id,
            id=session_id,
            state=data.get("state", {}),
            events=events,
            last_update_time=data.get("last_update_time", 0.0),
        )

        # Apply GetSessionConfig filters
        if config:
            if config.num_recent_events:
                session.events = session.events[-config.num_recent_events:]
            if config.after_timestamp:
                session.events = [
                    e for e in session.events if e.timestamp >= config.after_timestamp
                ]

        # Merge app/user state
        app_state = await self._get_app_state(app_name)
        user_state = await self._get_user_state(app_name, user_id)
        return self._merge_state(session, app_state, user_state)

    async def list_sessions(
        self, *, app_name: str, user_id: Optional[str] = None,
    ) -> ListSessionsResponse:
        sessions = []

        if user_id:
            # List sessions for a specific user
            sessions_ref = (
                self.db.collection(self.collection)
                .document(app_name)
                .collection("users")
                .document(user_id)
                .collection("sessions")
            )
            async for doc in sessions_ref.stream():
                data = doc.to_dict()
                session = Session(
                    app_name=app_name,
                    user_id=user_id,
                    id=doc.id,
                    state=data.get("state", {}),
                    events=[],  # list_sessions doesn't include events
                    last_update_time=data.get("last_update_time", 0.0),
                )
                sessions.append(session)
        else:
            # List all users' sessions — enumerate user documents
            users_ref = (
                self.db.collection(self.collection)
                .document(app_name)
                .collection("users")
            )
            async for user_doc in users_ref.stream():
                uid = user_doc.id
                sessions_ref = (
                    self.db.collection(self.collection)
                    .document(app_name)
                    .collection("users")
                    .document(uid)
                    .collection("sessions")
                )
                async for doc in sessions_ref.stream():
                    data = doc.to_dict()
                    session = Session(
                        app_name=app_name,
                        user_id=uid,
                        id=doc.id,
                        state=data.get("state", {}),
                        events=[],
                        last_update_time=data.get("last_update_time", 0.0),
                    )
                    sessions.append(session)

        return ListSessionsResponse(sessions=sessions)

    async def delete_session(
        self, *, app_name: str, user_id: str, session_id: str,
    ) -> None:
        session_ref = self._session_ref(app_name, user_id, session_id)

        # Delete all events in the subcollection first
        events_ref = self._events_collection(app_name, user_id, session_id)
        async for event_doc in events_ref.stream():
            await event_doc.reference.delete()

        # Delete the session document
        await session_ref.delete()
        logger.info("Deleted session %s for user %s in app %s", session_id, user_id, app_name)

    async def append_event(self, session: Session, event: Event) -> Event:
        """Append an event to the session — called by ADK Runner after each turn."""
        if event.partial:
            return event

        # Let the base class update the in-memory session object
        event = self._trim_temp_delta_state(event)
        self._update_session_state(session, event)
        session.events.append(event)
        session.last_update_time = event.timestamp

        app_name = session.app_name
        user_id = session.user_id
        session_id = session.id

        # Serialize event to Firestore
        event_data = event.model_dump(mode="json", by_alias=True, exclude_none=True)
        events_ref = self._events_collection(app_name, user_id, session_id)
        logger.debug("Appending event %s to %s (collection=%s)", event.id, events_ref.parent.path, self.collection)
        await events_ref.document(event.id).set(event_data)

        # Update session document (state + last_update_time)
        session_state = {
            k: v for k, v in session.state.items()
            if not k.startswith(State.APP_PREFIX)
            and not k.startswith(State.USER_PREFIX)
            and not k.startswith(State.TEMP_PREFIX)
        }
        await self._session_ref(app_name, user_id, session_id).set({
            "app_name": app_name,
            "user_id": user_id,
            "state": session_state,
            "last_update_time": session.last_update_time,
        })

        # Persist app/user state deltas if present
        if event.actions and event.actions.state_delta:
            state_deltas = _session_util.extract_state_delta(event.actions.state_delta)
            if state_deltas["app"]:
                await self._set_app_state(app_name, state_deltas["app"])
            if state_deltas["user"]:
                await self._set_user_state(app_name, user_id, state_deltas["user"])

        return event
