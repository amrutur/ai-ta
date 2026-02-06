"""
Firestore database operations.

All functions accept a Firestore `db` client as their first parameter
to keep them decoupled from global state and easy to test.
"""

import logging
import json
import re
from firebase_admin import firestore


def get_user_list(db):
    '''Return the list of user IDs in the Firestore database.'''
    users_ref = db.collection('users')
    docs = users_ref.select([]).stream()
    user_list = []

    for doc in docs:
        user_list.append(doc.id)

    return user_list

def add_user_if_not_exists(db, google_user_id, user_name, user_email, google_user_name):
    '''Add the user to the Firestore database if not already present.'''
    user_list = get_user_list(db)

    if google_user_id not in user_list:
        logging.info(f"User '{user_name}' ({google_user_id}) not in database. Adding now.")
        user_ref = db.collection(u'users').document(google_user_id)
        user_ref.set({
            u'name': user_name,
            u'email': user_email,
            u'google_user_name': google_user_name
        })

def add_answer_notebook(db, google_user_id, notebook_id, answer_notebook, answer_hash):
    '''Add the answer notebook to the Firestore database.'''
    try:
        answer_ref = db.collection(u'users').document(google_user_id).collection(u'notebooks').document(notebook_id)
        answer_ref.set({
            u'answer_notebook': answer_notebook,
            u'answer_hash': answer_hash,
            u'submitted_at': firestore.SERVER_TIMESTAMP
        })
    except Exception as e:
        logging.error(f"Error adding answer notebook to Firestore: {e}")

def update_marks(db, google_user_id, notebook_id, total_marks, max_marks, graded):
    '''Update the marks for the answer notebook of google_user_id in the Firestore database.'''
    try:
        answer_ref = db.collection(u'users').document(google_user_id).collection(u'notebooks').document(notebook_id)
        answer_ref.set({
            u'total_marks': total_marks,
            u'max_marks': max_marks,
            u'graded_at': firestore.SERVER_TIMESTAMP
        }, merge=True)
        # Convert graded dict keys to strings for Firestore compatibility
        # Firestore requires string keys in maps, but graded has integer keys (question numbers)
        graded_with_string_keys = {str(k): v for k, v in graded.items()}
        # Also update the graded details (using graded_json for dict/object type)
        answer_ref.set({
            u'graded_json': graded_with_string_keys
        }, merge=True)
    except Exception as e:
        logging.error(f"Error updating marks in Firestore: {e}")

def fetch_grader_response(db, notebook_id: str = None, user_email: str = None):
    '''
    Get the graded answer for the student user_email for notebook_id in the Firestore database.
    '''
    logging.debug(f"Fetching grader response for email: {user_email} and notebook_id: {notebook_id}")

    try:
        user_list = get_user_list(db)
        grader_response = {}

        if notebook_id is None:
            logging.error(f"notebook_id is None")
            return None
        for user_id in user_list:
            answer_ref = db.collection(u'users').document(user_id).collection(u'notebooks').document(notebook_id)
            userinfo_ref = db.collection(u'users').document(user_id)
            logging.debug(f"Fetched userinfo_ref for {user_email}")
            userinfo_doc = userinfo_ref.get()
            logging.debug(f"Fetched userinfo_doc for {userinfo_doc.get('name')} with {userinfo_doc.get('email')} ")
            answer_doc = answer_ref.get()
            logging.debug(f"Checking user: {userinfo_doc.get('name')} with {userinfo_doc.get('email')} ")
            if re.match(f"{user_email}", userinfo_doc.get('email'), re.IGNORECASE) is None:
                logging.debug(f"No match for email {user_email} and {userinfo_doc.get('email')}")
                continue
            logging.debug(f"Found matching user: {userinfo_doc.get('name')} with {userinfo_doc.get('email')} ")

            user_name = userinfo_doc.get('name')
            logging.debug(f"Fetching graded response for user: {user_name} and notebook_id: {notebook_id}")
            response_json = answer_doc.to_dict()

            # Try to get graded_json (new format), fall back to graded (old format) for backward compatibility
            graded_data = response_json.get('graded_json')
            if graded_data is None:
                # Backward compatibility: try old 'graded' field (JSON string)
                graded_string = response_json.get('graded')
                if graded_string:
                    graded_data = json.loads(graded_string)

            logging.debug(f"user:{user_name} : total marks: {response_json.get('total_marks')} Response json: {graded_data}")

            grader_response = {'user_name': user_name, 'total_marks': response_json.get('total_marks'), 'max_marks': response_json.get('max_marks')}

            grader_response['feedback'] = graded_data
            logging.debug(f"For  matching user, response is: {grader_response}")
            break
        return grader_response
    except Exception as e:
        logging.error(f"Error in fetch_grader_response: {e}")
