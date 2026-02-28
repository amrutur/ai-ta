from google.adk.sessions import BaseSessionService, Session
from google.cloud import firestore

from typing_extensions import Any, override


class CustomFirestoreSessionService(BaseSessionService):
    def __init__(self, project_id, database_id="(default)", collection_template="sessions"):
        self.db = firestore.AsyncClient(project=project_id, database=database_id)
        self.template = collection_template

    @overrride
    async def create_session(self, 
                             *,
                             app_name:str, 
                             user_id:str, 
                             session_id:str, 
                             state:dict[str, Any]
                             ) -> Session:
        # Implementation to create a session in Firestore
        course_handle = state['course_handle']
        is_instructor = state.get('is_instructor', False)
        if is_instructor:
            #is an instructor session, save in main course document.
            doc_ref = self.db.collection(course_handle).collection('Notebooks').document(session_id)
            if not doc_ref.get().exists:
                 session_data = {
                    "user_id": user_id,
                    "app_name": app_name,
                    "state": state,
                    "created_at": firestore.SERVER_TIMESTAMP
                }
            await doc_ref.set(session_data)
            return Session(
                app_name=app_name,
                user_id=user_id,
                id=session_id,
                state=state,
                events=[],
                last_update_time=session_data["created_at"],
            )
        else:
            #is a student session, save in subcollection under the course document.
            doc_ref = self.db.collection('courses').document(course_handle).collection('Students').document(user_id).collection('Notebooks').document(session_id)
            if not doc_ref.get().exists:
                session_data = {
                    "user_id": user_id,
                    "app_name": app_name,
                    "state": state,
                    "created_at": firestore.SERVER_TIMESTAMP
                }
                await doc_ref.set(session_data)
            return Session(
                app_name=app_name,
                user_id=user_id,
                id=session_id,
                state=state,
                events=[],
                last_update_time=session_data["created_at"],
            )
    

    async def get_session(self, 
                          *,
                          app_name:str, 
                          user_id:str, 
                          session_id:str
                          ) -> Session | None:
        # Implementation to fetch from Firestore
        doc_ref = self.db.collection("sessions").document(session_id)
        doc = await doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
            return Session(id=session_id, user_id=user_id, state=data.get("state", {}))
        return None

    async def append_event(self, session, event):
        # Implementation to save events
        await self.db.collection("events").add({
            "session_id": session.id,
            "content": event.content,
            "timestamp": firestore.SERVER_TIMESTAMP
        })
