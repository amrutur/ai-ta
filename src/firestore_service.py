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
import json
import logging
import sys
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

    Sessions are stored as sub-collections under the course document so that
    each course has its own isolated session data::

        courses/{course_handle}/{collection}/{app_name}/users/{user_id}/sessions/{session_id}

    Args:
        db: An async Firestore client instance.
        collection: The session collection name (e.g. "student_sessions",
            "instructor_sessions").  Defaults to "agent_sessions".
        course_handle: The course identifier whose document in the ``courses``
            collection serves as the parent for all session data.
    """

    # Default cap on events loaded per session.  Keeps the conversation
    # history sent to the LLM within token limits (each event can carry a
    # large prompt + response).  Only the most recent events are kept.
    DEFAULT_MAX_EVENTS = 10

    # Maximum total size (in bytes) for the serialized events loaded in
    # get_session.  If the events exceed this, the oldest events are dropped
    # until the total fits.  1 MB by default.
    MAX_SESSION_EVENTS_BYTES = 1 * 1024 * 1024

    # Prefixes that identify non-interaction context parts (RAG, rubric,
    # question context, etc.).  These are stripped from events before
    # persisting so that only the student–agent dialogue is captured.
    _CONTEXT_PREFIXES = (
        "{Relevant course material:}",
        "{The context is:}",
        "{The topic content is:}",
        "{The question is:}",
        "{The student's answer is}",
        "{The student's code output is}",
        "{The rubric is}",
        "{The rubric code output is}",
        "{The instructor's answer is}",
        "{The instructor's code output is}",
    )

    def __init__(self, db: AsyncClient, collection: str = "agent_sessions",
                 course_handle: str = "", max_events: int | None = None):
        self.db = db
        self.collection = collection
        self.course_handle = course_handle
        self.max_events = max_events if max_events is not None else self.DEFAULT_MAX_EVENTS

    # ---- internal helpers ----

    def _course_root(self):
        """Return the collection reference scoped under the course document."""
        return (
            self.db.collection("courses")
            .document(self.course_handle)
            .collection(self.collection)
        )

    def _session_ref(self, app_name: str, user_id: str, session_id: str):
        """Return a document reference for a session."""
        return (
            self._course_root()
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
            self._course_root()
            .document(app_name)
            .collection("_meta")
            .document("app_state")
        )

    def _user_state_ref(self, app_name: str, user_id: str):
        """Return a document reference for user-level state."""
        return (
            self._course_root()
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
        await self._session_ref(app_name, user_id, session_id).set({
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

        # Load events from subcollection, ordered by timestamp.
        # To prevent unbounded conversation history from exceeding LLM token
        # limits, only the most recent `self.max_events` events are loaded
        # (unless the caller passes a GetSessionConfig that further narrows).
        events = []
        events_ref = self._events_collection(app_name, user_id, session_id)
        query = events_ref.order_by("timestamp")
        effective_limit = self.max_events
        if config and config.num_recent_events:
            effective_limit = config.num_recent_events
        if effective_limit and effective_limit > 0:
            query = query.limit_to_last(effective_limit)
        async for event_doc in query.stream():
            event_data = event_doc.to_dict()
            try:
                event = Event.model_validate(event_data)
                events.append(event)
            except Exception as e:
                logger.warning("Failed to deserialize event %s: %s", event_doc.id, e)

        # --- Size guard: drop oldest events until total size is within limit ---
        total_bytes = sum(sys.getsizeof(json.dumps(e.model_dump(mode="json", exclude_none=True))) for e in events)
        if total_bytes > self.MAX_SESSION_EVENTS_BYTES:
            logger.warning(
                "Session %s events total %d bytes (limit %d). Truncating oldest events.",
                session_id, total_bytes, self.MAX_SESSION_EVENTS_BYTES,
            )
            while events and total_bytes > self.MAX_SESSION_EVENTS_BYTES:
                removed = events.pop(0)
                total_bytes -= sys.getsizeof(json.dumps(removed.model_dump(mode="json", exclude_none=True)))

        session = Session(
            app_name=app_name,
            user_id=user_id,
            id=session_id,
            state=data.get("state", {}),
            events=events,
            last_update_time=data.get("last_update_time", 0.0),
        )

        # Apply remaining GetSessionConfig filters (num_recent_events is
        # already handled at the query level above).
        if config and config.after_timestamp:
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
                self._course_root()
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
                self._course_root()
                .document(app_name)
                .collection("users")
            )
            async for user_doc in users_ref.stream():
                uid = user_doc.id
                sessions_ref = (
                    self._course_root()
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

        # Strip non-interaction context parts (RAG, rubric, question text,
        # etc.) so only the student–agent dialogue is persisted.
        event_data = event.model_dump(mode="json", by_alias=True, exclude_none=True)
        if event_data.get("content") and event_data["content"].get("parts"):
            event_data["content"]["parts"] = [
                part for part in event_data["content"]["parts"]
                if not (
                    isinstance(part.get("text"), str)
                    and any(part["text"].startswith(prefix) for prefix in self._CONTEXT_PREFIXES)
                )
            ]

        # Serialize event to Firestore
        events_ref = self._events_collection(app_name, user_id, session_id)
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
