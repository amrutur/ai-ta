"""
Firestore database operations.

All functions accept a Firestore `db` client as their first parameter
to keep them decoupled from global state and easy to test.
"""

import logging
import json
import re
from firebase_admin import firestore
from google.api_core import exceptions as google_exceptions
from fastapi import HTTPException
from aita_exceptions import CourseNotFoundError, StudentNotEnrolledError, NotebookNotFoundError
from typing import Any

def make_course_handle(institution_id: str, term_id: str, course_id: str) -> str:
    '''Derive a GCS folder name from institution, academic year, and course id.

    Concatenates the three values with hyphens, lowercased, with spaces and
    special characters replaced to produce a valid folder name.
    ''' 
    raw = f"{institution_id}/{term_id}/{course_id}"
    # Lowercase, replace spaces/underscores with hyphens, strip non-alphanumeric except hyphens
    name = raw.lower()
    name = re.sub(r'[\s_]+', '-', name)
    name = re.sub(r'[^a-z0-9\-]', '', name)
    # Collapse multiple hyphens and strip leading/trailing hyphens
    name = re.sub(r'-+', '-', name).strip('-')
    return name

async def load_default_values(db) -> dict:
    '''Load default values from the courses/default_values document.

    Returns:
        Dictionary with keys like ai_model, instructor_assist_prompt, etc.
        Returns empty dict if the document does not exist.
    '''
    try:
        doc_ref = db.collection(u'courses').document('default_values')
        doc = await doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
            logging.info(f"Loaded default_values from Firestore: {list(data.keys())}")
            return data
        else:
            logging.warning("courses/default_values document not found in Firestore")
            return {}
    except Exception as e:
        logging.error(f"Failed to load default_values from Firestore: {e}")
        return {}

async def load_course_info_from_db(db) -> dict:
    '''Load all course documents from Firestore and return them as a dict.

    Returns:
        Dictionary mapping course_handle -> course_data dict
    '''
    all_courses = {}
    try:
        courses_ref = db.collection(u'courses')
        docs = courses_ref.stream()
        async for doc in docs:
            all_courses[doc.id] = doc.to_dict()
        logging.info(f"Loaded {len(all_courses)} courses from Firestore")
    except Exception as e:
        logging.error(f"Failed to load courses from Firestore: {e}")
        raise
    return all_courses

async def update_course_info(db, course_handle:str, keyname: str, value: Any):
    ''' Update course document's key to value in the Firestore database.
    '''
    try:
        course = await db.collection(u'courses').document(course_handle).get()
        if not course.exists:
            raise CourseNotFoundError(course_handle)  
        await course.reference.set({keyname: value, 'last_updated': firestore.SERVER_TIMESTAMP}, merge=True)      

    except google_exceptions.NotFound:
        logging.error("Firestore collection 'courses' not found.")
        raise HTTPException(status_code=500, detail="Database access error.")
    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions for ai-ta-486602.")
        raise HTTPException(status_code=500, detail="Database access denied.")        
    except google_exceptions.GoogleAPICallError as e:
        # Catch-all for other network/API issues (timeouts, 500s from Google)
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")
    except Exception as e:
        logging.error(f"An unexpected error occurred in update_course_info: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while accessing the database.")

async def load_notebooks_from_db(db, course_handle: str) -> dict:
    '''Load all notebook (rubric) documents from a course's Notebooks subcollection.

    Returns:
        Dictionary mapping notebook_id -> notebook_data dict
    '''
    notebooks = {}
    try:
        notebooks_ref = db.collection(u'courses').document(course_handle).collection(u'Notebooks')
        async for doc in notebooks_ref.stream():
            doc_data = doc.to_dict()
            # Exclude internal fields that aren't needed in the cache
            doc_data.pop('last_updated', None)
            notebooks[doc.id] = doc_data
    except Exception as e:
        logging.error(f"Failed to load notebooks for course '{course_handle}': {e}")
    return notebooks

async def save_rubric(db, course_handle:str, notebook_id:str, max_marks: float, context:dict, questions:dict, answers:dict, outputs:dict):
    ''' Save the notebook's rubric information to the Firestore database under Notebooks
        subcollection for this course.

        Holds the context, questions, and answers for the rubric notebook, which will be used by the grading agent when grading student submissions. Also saves the max_marks for the notebook, which is used to calculate the final grade percentage for the submission.
    '''
    try:
        rubric_ref = db.collection(u'courses').document(course_handle).collection(u'Notebooks').document(notebook_id)
        await rubric_ref.set({
            u'max_marks': max_marks,
            u'context': context,
            u'questions': questions,
            u'answers': answers,
            u'outputs': outputs,
            u'last_updated': firestore.SERVER_TIMESTAMP
        })
    except google_exceptions.NotFound:
        logging.error("Firestore collection 'courses' not found.")
        raise HTTPException(status_code=500, detail="Database access error.")
    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions for ai-ta-486602.")
        raise HTTPException(status_code=500, detail="Database access denied.")        
    except google_exceptions.GoogleAPICallError as e:
        # Catch-all for other network/API issues (timeouts, 500s from Google)
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")
    except Exception as e:
        logging.error(f"An unexpected error occurred in save_rubric: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while saving the rubric.")

async def update_notebook_info(db, course_handle: str, notebook_id: str, keyname: str, value: Any):
    '''Update a field on a notebook document in Firestore.

    Path: courses/{course_handle}/Notebooks/{notebook_id}
    '''
    try:
        notebook_ref = (db.collection(u'courses').document(course_handle)
                        .collection(u'Notebooks').document(notebook_id))
        notebook_doc = await notebook_ref.get()
        if not notebook_doc.exists:
            raise NotebookNotFoundError(notebook_id, "unknown", course_handle)
        await notebook_ref.set({keyname: value, 'last_updated': firestore.SERVER_TIMESTAMP}, merge=True)
    except (NotebookNotFoundError, CourseNotFoundError):
        raise
    except google_exceptions.NotFound:
        logging.error("Firestore collection 'courses' not found.")
        raise HTTPException(status_code=500, detail="Database access error.")
    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions.")
        raise HTTPException(status_code=500, detail="Database access denied.")
    except google_exceptions.GoogleAPICallError as e:
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")
    except Exception as e:
        logging.error(f"An unexpected error occurred in update_notebook_info: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while updating the notebook.")

async def get_student_list(db, course_handle: str):
    '''Return the list of student gmails for the course_id in the Firestore database.'''
    try:
        courses_ref = db.collection(u'courses').document(course_handle)
        course_doc = await courses_ref.get()
        if not course_doc.exists:
            raise CourseNotFoundError(course_handle)
        students_ref = courses_ref.collection(u'Students')
        student_list = []
        async for doc in students_ref.select([]).stream():
            student_list.append(doc.id)

    except google_exceptions.NotFound:
        logging.error("Firestore collection 'courses' not found.")
        raise HTTPException(status_code=500, detail="Database access error.")
    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions for ai-ta-486602.")
        raise HTTPException(status_code=500, detail="Database access denied.")        
    except google_exceptions.GoogleAPICallError as e:
        # Catch-all for other network/API issues (timeouts, 500s from Google)
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")
    except CourseNotFoundError as e:
        # Catching your own custom exception raised inside the try block
        logging.info(f"User requested non-existent course: {course_handle}")
        raise HTTPException(status_code=404, detail=e.message)
    except Exception as e:
        logging.error(f"An unexpected error occurred in get_student_list: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while accessing the database.")

    return student_list

async def get_marks_list(db, course_handle: str,  notebook_id: str):
    '''Return the list of student marks for the course_id in the Firestore database.

    Path: courses/{course_handle}/Students/{student_id}/Notebooks/{notebook_id}

    Returns:
        Tuple of (max_marks, marks_list) where marks_list is a list of dicts
        with student_id and total_marks. total_marks is -1 if not graded yet,
        or None if the notebook doesn't exist for that student.
    '''
    try:
        courses_ref = db.collection(u'courses').document(course_handle)
        course_doc = await courses_ref.get()
        if not course_doc.exists:
            raise CourseNotFoundError(course_handle)
        students_ref = courses_ref.collection(u'Students')
        marks_list = []
        max_marks = None
        async for doc in students_ref.select([]).stream():
            student_id = doc.id
            notebook_ref = students_ref.document(student_id).collection(u'Notebooks')
            notebook = await notebook_ref.document(notebook_id).get()
            marks_info = {'student_id': student_id}
            if notebook.exists:
                notebook_dict = notebook.to_dict()
                max_marks = notebook_dict.get('max_marks', max_marks)
                if 'graded_at' in notebook_dict:
                    marks_info['total_marks'] = notebook_dict.get('total_marks', None)
                else:
                    logging.warning(f"Notebook '{notebook_id}' for student '{student_id}' in course '{course_handle}' exists but has not been graded yet.")
                    marks_info['total_marks'] = -1
            else:
                logging.warning(f"Notebook '{notebook_id}' not found for student '{student_id}' in course '{course_handle}'.")
                marks_info['total_marks'] = None
            marks_list.append(marks_info)

    except google_exceptions.NotFound:
        logging.error("Firestore collection 'courses' not found.")
        raise HTTPException(status_code=500, detail="Database access error.")
    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions for ai-ta-486602.")
        raise HTTPException(status_code=500, detail="Database access denied.")        
    except google_exceptions.GoogleAPICallError as e:
        # Catch-all for other network/API issues (timeouts, 500s from Google)
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")
    except CourseNotFoundError as e:
        # Catching your own custom exception raised inside the try block
        logging.info(f"User requested non-existent course: {course_handle}")
        raise HTTPException(status_code=404, detail=e.message)
    except Exception as e:
        logging.error(f"An unexpected error occurred in get_marks_list: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while accessing the database.")

    return max_marks, marks_list


async def add_student_if_not_exists(db, course_handle, student_id, student_name):
    '''Add the student to the course's Students subcollection if not already present.

    Path: courses/{course_handle}/Students/{student_id}
    '''
    try:
        course_ref = db.collection(u'courses').document(course_handle)
        course_doc = await course_ref.get()
        if not course_doc.exists:
            logging.error(f"Course:'{course_handle}' not found when trying to add student '{student_id}'.")
            raise CourseNotFoundError(course_handle)       
        student_ref = course_ref.collection(u'Students').document(student_id)
        student_doc = await student_ref.get()
        if not student_doc.exists:
            logging.info(f"Student '{student_id}' not in course {course_handle}. Adding now.")
            await student_ref.set({
                u'name': student_name,
                "initialized": True,
                "created_at": firestore.SERVER_TIMESTAMP
                })
    except google_exceptions.NotFound:
        # Note: In Firestore, .get() on a non-existent ID usually returns
        # a 'doc.exists=False' snapshot rather than raising this error.
        # But this is useful for missing Collections or wrong Database IDs.
        logging.error(f"Firestore collection/resource not found.")
        raise

    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions for ai-ta-486602.")
        raise HTTPException(status_code=500, detail="Database access denied.")

    except google_exceptions.GoogleAPICallError as e:
        # Catch-all for other network/API issues (timeouts, 500s from Google)
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")

    except CourseNotFoundError as e:
        # Catching your own custom exception raised inside the try block
        logging.info(f"User requested non-existent course: {course_handle}")
        raise HTTPException(status_code=404, detail=e.message)
    except Exception as e:
        logging.error(f"An unexpected error occurred in add_user_if_not_exists: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while accessing the database.")

async def add_instructor_notebook_if_not_exists(db, course_handle, notebook_id):
    '''Add the instructor interactions to the course's notebook subcollection if not already present.

    Path: courses/{course_handle}/Notebooks/{notebook_id}
    '''
    try:
        course_ref = db.collection(u'courses').document(course_handle)
        course_doc = await course_ref.get()
        if not course_doc.exists:
            logging.error(f"Course:'{course_handle}' not found when trying to add Notebook '{notebook_id}'.")
            raise CourseNotFoundError(course_handle)       
        notebook_ref = course_ref.collection(u'Notebooks').document(notebook_id)
        notebook_doc = await notebook_ref.get()
        if not notebook_doc.exists:
            logging.info(f"Notebook '{notebook_id}' not in course {course_handle}. Adding now.")
            await notebook_ref.set({
                "initialized": True,
                "created_at": firestore.SERVER_TIMESTAMP
                })
    except google_exceptions.NotFound:
        # Note: In Firestore, .get() on a non-existent ID usually returns
        # a 'doc.exists=False' snapshot rather than raising this error.
        # But this is useful for missing Collections or wrong Database IDs.
        logging.error(f"Firestore collection/resource not found.")
        raise

    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions for ai-ta-486602.")
        raise HTTPException(status_code=500, detail="Database access denied.")

    except google_exceptions.GoogleAPICallError as e:
        # Catch-all for other network/API issues (timeouts, 500s from Google)
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")

    except CourseNotFoundError as e:
        # Catching your own custom exception raised inside the try block
        logging.info(f"User requested non-existent course: {course_handle}")
        raise HTTPException(status_code=404, detail=e.message)
    except Exception as e:
        logging.error(f"An unexpected error occurred in add_user_if_not_exists: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while accessing the database.")

async def add_student_notebook_if_not_exists(db, course_handle, student_id, student_name, notebook_id):
    '''Add the student interactions to the student's notebook subcollection if not already present.

    Path: courses/{course_handle}/Students/{student_id}/Notebooks/{notebook_id}
    '''
    try:
        course_ref = db.collection(u'courses').document(course_handle)
        course_doc = await course_ref.get()
        if not course_doc.exists:
            logging.error(f"Course:'{course_handle}' not found when trying to add Notebook '{notebook_id}'.")
            raise CourseNotFoundError(course_handle)       
        student_ref = course_ref.collection(u'Students').document(student_id)
        student_doc = await student_ref.get()
        if not student_doc.exists:
            logging.info(f"Student '{student_id}' not in course {course_handle}. Adding now.")
            await student_ref.set({
                u'name': student_name,
                "initialized": True,
                "created_at": firestore.SERVER_TIMESTAMP
                })
        notebook_ref = student_ref.collection(u'Notebooks').document(notebook_id)
        notebook_doc = await notebook_ref.get()
        if not notebook_doc.exists:
            logging.info(f"Notebook '{notebook_id}' not in course {course_handle}/{student_id}. Adding now.")
            await notebook_ref.set({
                "initialized": True,
                "created_at": firestore.SERVER_TIMESTAMP
                })

    except google_exceptions.NotFound:
        # Note: In Firestore, .get() on a non-existent ID usually returns
        # a 'doc.exists=False' snapshot rather than raising this error.
        # But this is useful for missing Collections or wrong Database IDs.
        logging.error(f"Firestore collection/resource not found.")
        raise

    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions for ai-ta-486602.")
        raise HTTPException(status_code=500, detail="Database access denied.")

    except google_exceptions.GoogleAPICallError as e:
        # Catch-all for other network/API issues (timeouts, 500s from Google)
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")

    except CourseNotFoundError as e:
        # Catching your own custom exception raised inside the try block
        logging.info(f"User requested non-existent course: {course_handle}")
        raise HTTPException(status_code=404, detail=e.message)
    except Exception as e:
        logging.error(f"An unexpected error occurred in add_user_if_not_exists: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while accessing the database.")  

async def upload_student_notebook(db, course_handle, student_id, student_name, notebook_id, answer_notebook, answer_hash):
    '''Add the answer notebook to the student's record.'''
    try:
        course_ref = db.collection(u'courses').document(course_handle)
        course_doc = await course_ref.get()
        if not course_doc.exists:
            logging.error(f"Course with handle '{course_handle}' not found when trying to upload student answer book '{student_id}:{notebook_id}'.")
            raise CourseNotFoundError(course_handle)       
        student_ref = course_ref.collection(u'Students').document(student_id)
        student_doc = await student_ref.get()
        if not student_doc.exists:
            logging.info(f"Student '{student_id}' not in course {course_handle}. Adding now.")
            await student_ref.set({
                u'name': student_name,
                "initialized": True,
                "created_at": firestore.SERVER_TIMESTAMP
                })
        notebook_ref = student_ref.collection(u'Notebooks').document(notebook_id)
        notebook_doc = await notebook_ref.get()
        if notebook_doc.exists:
            logging.warning(f"Notebook with ID '{notebook_id}' already exists for student '{student_id}' in course '{course_handle}'. Overwriting the existing notebook.")

        await notebook_ref.set({
            u'answer_notebook': answer_notebook,
            u'answer_hash': answer_hash,
            u'submitted_at': firestore.SERVER_TIMESTAMP
        })
    except google_exceptions.NotFound:
        # Note: In Firestore, .get() on a non-existent ID usually returns 
        # a 'doc.exists=False' snapshot rather than raising this error.
        # But this is useful for missing Collections or wrong Database IDs.
        logging.error(f"Firestore collection/resource not found.")
        raise
        
    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions for ai-ta-486602.")
        raise HTTPException(status_code=500, detail="Database access denied.")
        
    except google_exceptions.GoogleAPICallError as e:
        # Catch-all for other network/API issues (timeouts, 500s from Google)
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")

    except CourseNotFoundError as e:
        # Catching your own custom exception raised inside the try block
        logging.info(f"User requested non-existent course: {course_handle}")
        raise HTTPException(status_code=404, detail=str(e))
    except StudentNotEnrolledError as e:
        logging.info(f"User '{student_id}' tried to submit notebook for course '{course_handle}' they are not enrolled in.")
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logging.error(f"Error in upload_student_notebook: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error while adding answer notebook.")

async def get_student_notebook_answers(db, course_handle, student_id, notebook_id):
    '''Fetch the student's submitted answers from their notebook document.

    Path: courses/{course_handle}/Students/{student_id}/Notebooks/{notebook_id}

    Returns:
        The answers dict if found, or None if the student/notebook doesn't exist
        or has no answers field.
    '''
    try:
        notebook_ref = (db.collection(u'courses').document(course_handle)
                        .collection(u'Students').document(student_id)
                        .collection(u'Notebooks').document(notebook_id))
        notebook_doc = await notebook_ref.get()
        if not notebook_doc.exists:
            return None
        doc_data = notebook_doc.to_dict()
        return doc_data.get('answers', None)
    except Exception as e:
        logging.error(f"Error fetching student answers for {student_id}/{notebook_id}: {e}")
        return None

async def is_notebook_graded(db, course_handle, student_id, notebook_id):
    '''Check if a student's notebook has already been graded.

    Path: courses/{course_handle}/Students/{student_id}/Notebooks/{notebook_id}

    Returns:
        True if the notebook document exists and has a 'graded_at' field set, False otherwise.
    '''
    try:
        notebook_ref = (db.collection(u'courses').document(course_handle)
                        .collection(u'Students').document(student_id)
                        .collection(u'Notebooks').document(notebook_id))
        notebook_doc = await notebook_ref.get()
        if not notebook_doc.exists:
            return False
        doc_data = notebook_doc.to_dict()
        return doc_data.get('graded_at') is not None
    except Exception as e:
        logging.error(f"Error checking graded status for {student_id}/{notebook_id}: {e}")
        return False

async def is_email_notified(db, course_handle, student_id, notebook_id):
    '''Check if a grade notification email has already been sent for this student/notebook.

    Path: courses/{course_handle}/Students/{student_id}/Notebooks/{notebook_id}

    Returns:
        True if the notebook document has an 'email_notified_at' field set, False otherwise.
    '''
    try:
        notebook_ref = (db.collection(u'courses').document(course_handle)
                        .collection(u'Students').document(student_id)
                        .collection(u'Notebooks').document(notebook_id))
        notebook_doc = await notebook_ref.get()
        if not notebook_doc.exists:
            return False
        doc_data = notebook_doc.to_dict()
        return doc_data.get('email_notified_at') is not None
    except Exception as e:
        logging.error(f"Error checking email notification status for {student_id}/{notebook_id}: {e}")
        return False


async def mark_email_notified(db, course_handle, student_id, notebook_id):
    '''Record that a grade notification email was sent for this student/notebook.

    Path: courses/{course_handle}/Students/{student_id}/Notebooks/{notebook_id}
    Sets the 'email_notified_at' field to the server timestamp.
    '''
    try:
        notebook_ref = (db.collection(u'courses').document(course_handle)
                        .collection(u'Students').document(student_id)
                        .collection(u'Notebooks').document(notebook_id))
        await notebook_ref.set({
            u'email_notified_at': firestore.SERVER_TIMESTAMP,
        }, merge=True)
    except Exception as e:
        logging.error(f"Error marking email notified for {student_id}/{notebook_id}: {e}")


async def save_student_answers(db, course_handle, student_id, notebook_id, answers):
    '''Save the student's answers to their notebook document.

    Path: courses/{course_handle}/Students/{student_id}/Notebooks/{notebook_id}
    '''
    try:
        notebook_ref = (db.collection(u'courses').document(course_handle)
                        .collection(u'Students').document(student_id)
                        .collection(u'Notebooks').document(notebook_id))
        await notebook_ref.update({u'answers': answers})
    except Exception as e:
        logging.error(f"Error saving student answers for {student_id}/{notebook_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to save student answers.")

async def update_marks(db, course_id, student_id, notebook_id, total_marks, max_marks, grader_response):
    '''Update the marks for the answer notebook of student_id in the database.'''
    try:
        course_ref = db.collection(u'courses').document(course_id)
        course_doc = await course_ref.get()
        if not course_doc.exists:
            logging.error(f"Course with ID '{course_id}' not found when trying to add user '{student_id}'.")
            raise CourseNotFoundError(course_id)       
        student_ref = course_ref.collection(u'Students').document(student_id)
        student_doc = await student_ref.get()
        if not student_doc.exists:
            logging.error(f"Student '{student_id}' not in course {course_id}.")
            raise StudentNotEnrolledError(student_id, course_id)
        notebook_ref = student_ref.collection(u'Notebooks').document(notebook_id)
        notebook_doc = await notebook_ref.get()
        if not notebook_doc.exists:
            logging.error(f"Notebook with ID '{notebook_id}' not found for student '{student_id}' in course '{course_id}'.")
            raise NotebookNotFoundError(notebook_id, student_id, course_id)    
        await notebook_ref.set({
            u'total_marks': total_marks,
            u'max_marks': max_marks,
            u'graded_at': firestore.SERVER_TIMESTAMP,
        }, merge=True)
        # Convert grader_response dict keys to strings for Firestore compatibility
        # Firestore requires string keys in maps, but grader_response has integer keys (question numbers)
        grader_response_with_string_keys = {str(k): v for k, v in grader_response.items()}
        # Also update the grader_response details (using grader_response for dict/object type)
        await notebook_ref.set({
            u'grader_response': grader_response_with_string_keys
        }, merge=True)
    except google_exceptions.NotFound:
        # Note: In Firestore, .get() on a non-existent ID usually returns 
        # a 'doc.exists=False' snapshot rather than raising this error.
        # But this is useful for missing Collections or wrong Database IDs.
        logging.error(f"Firestore collection/resource not found.")
        raise
        
    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions for ai-ta-486602.")
        raise HTTPException(status_code=500, detail="Database access denied.")
        
    except google_exceptions.GoogleAPICallError as e:
        # Catch-all for other network/API issues (timeouts, 500s from Google)
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")

    except CourseNotFoundError as e:
        # Catching your own custom exception raised inside the try block
        logging.info(f"User requested non-existent course: {course_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except StudentNotEnrolledError as e:
        logging.info(f"User '{student_id}' tried to submit notebook for course '{course_id}' they are not enrolled in.")
        raise HTTPException(status_code=403, detail=str(e)) 
    except NotebookNotFoundError as e:
        logging.info(f"User '{student_id}' tried to update marks for notebook '{notebook_id}' that does not exist.")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logging.error(f"Error in  update_marks: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error while updating marks.")

async def get_course_data(db, course_handle: str) -> dict:
    '''Check if a course exists in the Firestore database.
    Args:
        db: Firestore client
        course_handle: The unique handle for the course (institution_id/term_id/course_id)
    Returns:
        The course document if it exists, None otherwise.
    '''
    try:
        course_ref = db.collection(u'courses').document(course_handle)
        course_doc = await course_ref.get()
        if course_doc.exists:
            return course_doc.to_dict()            
        else:
            logging.info(f"Course with handle '{course_handle}' not found.")
            return None  
    except Exception as e:
        logging.error(f"Error checking if course exists: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while checking if the course exists.")

async def create_course(db, course_data: dict) -> bool:
    '''Create a new course in the Firestore database.
    Args:
        db: Firestore client
        course_data: Dictionary with course fields (course_name, course_number,
            academic_year, institution, instructor_email, instructor_gmail,
            instructor_name, start_date, end_date, and optional ta_name,
            ta_email, ta_gmail)

    Returns:
        True if course was created successfully (or already exists), False otherwise.
    '''
    course_handle = make_course_handle(
        course_data['institution_id'],
        course_data['term_id'],
        course_data['course_id'],
    )

    try: 
        course_ref = db.collection(u'courses').document(course_handle)
        course_doc = await course_ref.get()
        if not course_doc.exists:
            await course_ref.set(course_data)
            logging.info(f"Created course {course_data['course_id']} with handle: {course_handle}")
        else:
            logging.warning(f"Course with handle '{course_handle}' already exists. Skipping creation.")
        return True

    except google_exceptions.GoogleAPICallError as e:
        logging.error(f"Failed to create course in Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")
    except Exception as e:
        logging.error(f"An unexpected error occurred while creating course: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while creating the course.")
    
    return False


# ===========================================================================
# PDF-assignment helpers
#
# PDF submissions live in two places to keep things idempotent and to let the
# existing fetch/notify/marks endpoints work unchanged:
#
#   1. Canonical per-PDF tracking doc (one per Drive file):
#        courses/{ch}/Notebooks/{nb}/pdf_submissions/{drive_file_id}
#      Holds drive metadata, GCS path, resolved student_ids, and the grade.
#
#   2. Per-student mirror doc (one per author of each PDF):
#        courses/{ch}/Students/{sid}/Notebooks/{nb}
#      Mirrors the grade so /fetch_marks_list, /fetch_grader_response, and
#      /notify_student_grades work with no changes.
# ===========================================================================

PDF_SUBMISSIONS_SUBCOLLECTION = "pdf_submissions"


async def save_pdf_rubric(
    db,
    course_handle: str,
    notebook_id: str,
    max_marks: float,
    problem_statement: str = "",
    rubric_text: str = "",
    sample_graded_response: str | None = None,
    rubric_pdf_uri: str | None = None,
):
    """Save a PDF-assignment rubric under courses/{ch}/Notebooks/{nb}.

    Either the text fields (problem_statement + rubric_text) or
    ``rubric_pdf_uri`` (a ``gs://`` path to a rubric PDF on GCS) must be
    provided. When ``rubric_pdf_uri`` is set the scoring agent receives the
    rubric PDF as a multimodal Part alongside each student submission, so
    figures, tables, and worked examples in the rubric are visible to the
    model. The text fields remain useful as a fallback or supplement.

    Sets ``assignment_type='pdf'`` so the cache + endpoints can branch on it.
    Always enables eval — instructor toggles it off via /disable_eval if needed.
    """
    try:
        rubric_ref = (db.collection('courses').document(course_handle)
                      .collection('Notebooks').document(notebook_id))
        payload = {
            'assignment_type': 'pdf',
            'max_marks': max_marks,
            'problem_statement': problem_statement or '',
            'rubric_text': rubric_text or '',
            'sample_graded_response': sample_graded_response or '',
            'isactive_eval': True,
            'last_updated': firestore.SERVER_TIMESTAMP,
        }
        if rubric_pdf_uri is not None:
            payload['rubric_pdf_uri'] = rubric_pdf_uri
        await rubric_ref.set(payload, merge=True)
    except google_exceptions.PermissionDenied:
        logging.error("Service account permission denied while saving PDF rubric.")
        raise HTTPException(status_code=500, detail="Database access denied.")
    except google_exceptions.GoogleAPICallError as e:
        logging.error(f"Firestore error saving PDF rubric: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")
    except Exception as e:
        logging.error(f"Unexpected error saving PDF rubric: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while saving the rubric.")


def _pdf_submission_ref(db, course_handle: str, notebook_id: str, drive_file_id: str):
    return (db.collection('courses').document(course_handle)
            .collection('Notebooks').document(notebook_id)
            .collection(PDF_SUBMISSIONS_SUBCOLLECTION).document(drive_file_id))


async def get_pdf_submission(db, course_handle: str, notebook_id: str, drive_file_id: str) -> dict | None:
    """Return the per-PDF tracking doc, or None if not present."""
    try:
        doc = await _pdf_submission_ref(db, course_handle, notebook_id, drive_file_id).get()
        return doc.to_dict() if doc.exists else None
    except Exception as e:
        logging.error(f"Error fetching pdf_submission {drive_file_id}: {e}")
        return None


async def list_pdf_submissions(db, course_handle: str, notebook_id: str) -> list[dict]:
    """Return all per-PDF tracking docs for a notebook."""
    out = []
    try:
        ref = (db.collection('courses').document(course_handle)
               .collection('Notebooks').document(notebook_id)
               .collection(PDF_SUBMISSIONS_SUBCOLLECTION))
        async for doc in ref.stream():
            data = doc.to_dict() or {}
            data['drive_file_id'] = doc.id
            out.append(data)
    except Exception as e:
        logging.error(f"Error listing pdf_submissions for {course_handle}/{notebook_id}: {e}")
    return out


async def upsert_pdf_submission(
    db,
    course_handle: str,
    notebook_id: str,
    drive_file_id: str,
    drive_modified_time: str,
    gcs_uri: str,
    original_filename: str,
    extracted_authors: list[str],
    student_ids: list[str],
):
    """Write the per-PDF tracking doc and seed mirror docs for every author.

    Mirror docs hold ``assignment_type='pdf'``, ``drive_file_id``, ``gcs_uri``,
    and the co-author list — everything else (marks, grader_response, graded_at)
    is filled in later by the grading flow. Existing graded_at on a mirror doc
    is preserved across re-ingest of an unchanged PDF.
    """
    try:
        ref = _pdf_submission_ref(db, course_handle, notebook_id, drive_file_id)
        await ref.set({
            'drive_file_id': drive_file_id,
            'drive_modified_time': drive_modified_time,
            'gcs_uri': gcs_uri,
            'original_filename': original_filename,
            'extracted_authors': extracted_authors,
            'student_ids': student_ids,
            'ingested_at': firestore.SERVER_TIMESTAMP,
        }, merge=True)

        # Seed per-student mirror docs.
        for sid in student_ids:
            mirror_ref = (db.collection('courses').document(course_handle)
                          .collection('Students').document(sid)
                          .collection('Notebooks').document(notebook_id))
            await mirror_ref.set({
                'assignment_type': 'pdf',
                'drive_file_id': drive_file_id,
                'gcs_uri': gcs_uri,
                'original_filename': original_filename,
                'co_authors': [s for s in student_ids if s != sid],
                'submitted_at': firestore.SERVER_TIMESTAMP,
            }, merge=True)
    except google_exceptions.PermissionDenied:
        raise HTTPException(status_code=500, detail="Database access denied.")
    except google_exceptions.GoogleAPICallError as e:
        logging.error(f"Firestore error during upsert_pdf_submission: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")
    except Exception as e:
        logging.error(f"Unexpected error in upsert_pdf_submission: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while saving the PDF submission.")


async def update_pdf_submission_grade(
    db,
    course_handle: str,
    notebook_id: str,
    drive_file_id: str,
    student_ids: list[str],
    total_marks: float,
    max_marks: float,
    grader_response: dict,
):
    """Write grade to the per-PDF tracking doc + all per-student mirror docs.

    ``grader_response`` is a dict (typically ``{"overall": {"marks": .., "response": ..}}``)
    so it lines up with the per-question-keyed dict used for notebook grading
    and ``/fetch_grader_response`` keeps working with no client changes.
    """
    try:
        ref = _pdf_submission_ref(db, course_handle, notebook_id, drive_file_id)
        await ref.set({
            'total_marks': total_marks,
            'max_marks': max_marks,
            'grader_response': grader_response,
            'graded_at': firestore.SERVER_TIMESTAMP,
        }, merge=True)

        for sid in student_ids:
            mirror_ref = (db.collection('courses').document(course_handle)
                          .collection('Students').document(sid)
                          .collection('Notebooks').document(notebook_id))
            await mirror_ref.set({
                'total_marks': total_marks,
                'max_marks': max_marks,
                'grader_response': grader_response,
                'graded_at': firestore.SERVER_TIMESTAMP,
            }, merge=True)
    except Exception as e:
        logging.error(f"Error in update_pdf_submission_grade: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error while updating PDF marks.")


async def add_placeholder_student(db, course_handle: str, student_id: str, name: str, drive_file_id: str):
    """Create a placeholder student record for an unmatched PDF author.

    Marked with ``pending_review=True`` and ``initialized=False`` so the
    instructor can spot and merge/clean up these records later.
    """
    try:
        course_ref = db.collection('courses').document(course_handle)
        course_doc = await course_ref.get()
        if not course_doc.exists:
            raise CourseNotFoundError(course_handle)
        student_ref = course_ref.collection('Students').document(student_id)
        student_doc = await student_ref.get()
        if student_doc.exists:
            return  # already present — no-op
        await student_ref.set({
            'name': name,
            'initialized': False,
            'pending_review': True,
            'created_from_drive_file_id': drive_file_id,
            'created_at': firestore.SERVER_TIMESTAMP,
        })
    except CourseNotFoundError:
        raise HTTPException(status_code=404, detail=f"Course '{course_handle}' not found.")
    except Exception as e:
        logging.error(f"Error creating placeholder student '{student_id}': {e}")
        raise HTTPException(status_code=500, detail="Failed to create placeholder student.")


async def get_student_pdf_mirror(
    db, course_handle: str, student_id: str, notebook_id: str,
) -> dict | None:
    """Return the per-student PDF submission mirror doc, or None if missing."""
    try:
        ref = (db.collection('courses').document(course_handle)
               .collection('Students').document(student_id)
               .collection('Notebooks').document(notebook_id))
        doc = await ref.get()
        return doc.to_dict() if doc.exists else None
    except Exception as e:
        logging.error(f"Error fetching mirror doc for {student_id}/{notebook_id}: {e}")
        return None


async def get_student_directory(db, course_handle: str) -> dict[str, str]:
    """Return ``{student_id: name}`` for every enrolled student in the course.

    Used by the PDF ingest flow to fuzzy-match extracted author names to
    existing students.
    """
    out: dict[str, str] = {}
    try:
        students_ref = (db.collection('courses').document(course_handle)
                        .collection('Students'))
        async for doc in students_ref.stream():
            data = doc.to_dict() or {}
            out[doc.id] = data.get('name', '') or ''
    except Exception as e:
        logging.error(f"Error fetching student directory for {course_handle}: {e}")
    return out


async def fetch_grader_response(db, course_handle:str, notebook_id: str = None, student_id: str = None)-> dict:
    '''
    Get the graded answer for the student_id for notebook_id in the Firestore database.
    '''
    try:
        course_ref = db.collection(u'courses').document(course_handle)
        course_doc = await course_ref.get()
        if not course_doc.exists:
            logging.error(f"Course with handle '{course_handle}' not found when trying to fetch grader response.")
            raise CourseNotFoundError(course_handle)    

        grader_response = {}    

        if notebook_id is None:
            logging.error(f"notebook_id is None")
            return None
        
        student_ref = course_ref.collection(u'Students').document(student_id)
        student_doc = await student_ref.get()

        if not student_doc.exists:
            logging.warning(f"Student '{student_id}' not found in course {course_handle} when trying to fetch grader response.")
            raise StudentNotEnrolledError(student_id, course_handle)
    
        answer_ref = student_ref.collection(u'Notebooks').document(notebook_id)
        answer_doc = await answer_ref.get()
        if not answer_doc.exists:
            logging.warning(f"Notebook '{notebook_id}' for student '{student_id}' in course '{course_handle}' not found.")
            raise NotebookNotFoundError(notebook_id, student_id, course_handle)

        answer_dict = answer_doc.to_dict()

        graded_json = answer_dict.get('grader_response', None)

        if graded_json is None:
            logging.warning(f"Graded response for notebook '{notebook_id}' for student '{student_id}' in course '{course_handle}' not found. This may be because the notebook has not been graded yet, or because the grading data is in an older format. Returning None for this student's response.")
            return None

        logging.debug(f"student_id: {student_id} : total marks: {answer_dict.get('total_marks')} Response json: {graded_json}")

        grader_response = {'student_id': student_id, 'total_marks': answer_dict.get('total_marks'), 'max_marks': answer_dict.get('max_marks')}
        grader_response['feedback'] = graded_json

        return grader_response
    except google_exceptions.NotFound:
        # Note: In Firestore, .get() on a non-existent ID usually returns 
        # a 'doc.exists=False' snapshot rather than raising this error.
        # But this is useful for missing Collections or wrong Database IDs.
        logging.error(f"Firestore collection/resource not found.")
        raise
        
    except google_exceptions.PermissionDenied:
        logging.error("Check your Service Account permissions for ai-ta-486602.")
        raise HTTPException(status_code=500, detail="Database access denied.")
        
    except google_exceptions.GoogleAPICallError as e:
        # Catch-all for other network/API issues (timeouts, 500s from Google)
        logging.error(f"A network error occurred with Firestore: {e}")
        raise HTTPException(status_code=503, detail="Database temporarily unavailable.")

    except CourseNotFoundError as e:
        # Catching your own custom exception raised inside the try block
        logging.info(f"User requested non-existent course: {course_handle}")
        raise HTTPException(status_code=404, detail=str(e))
    except StudentNotEnrolledError as e:
        logging.info(f"User '{student_id}' tried to submit notebook for course '{course_handle}' they are not enrolled in.")
        raise HTTPException(status_code=403, detail=str(e)) 
    except NotebookNotFoundError as e:
        logging.info(f"User '{student_id}' tried to update marks for notebook '{notebook_id}' that does not exist.")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logging.error(f"Error in  update_marks: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error while updating marks.")