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
        logging.error(f"An unexpected error occurred in add_user_if_not_exists: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while accessing the database.")

async def save_rubric(db, course_handle:str, notebook_id:str, max_marks: float, context:dict, questions:dict, answers:dict):
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
        logging.error(f"An unexpected error occurred in add_user_if_not_exists: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while accessing the database.")

    return student_list

async def get_marks_list(db, course_handle: str,  notebook_id: str):
    '''Return the list of student marks for the course_id in the Firestore database.'''
    try:
        courses_ref = db.collection(u'courses').document(course_handle)
        course_doc = await courses_ref.get()
        if not course_doc.exists:
            raise CourseNotFoundError(course_handle)
        students_ref = courses_ref.collection(u'Students')
        marks_list = []
        async for doc in students_ref.select([]).stream():
            notebook_ref = students_ref.document(doc.id).collection(u'notebooks')
            notebook = await notebook_ref.document(notebook_id).get()
            marks_info = {'student_id': doc.id}
            if notebook.exists:
                notebook_dict = notebook.to_dict()
                max_marks = notebook_dict.get('max_marks', None)
                if 'graded_at' in notebook_dict:   
                    #notebook has been graded, so we can return the total marks (even if zero)             
                    marks_info['total_marks'] = notebook_dict.get('total_marks', None)
                else:
                    marks_info['total_marks'] = -1 # Indicate not graded yet with -1
            else:
                marks_info['total_marks'] = 0 # Indicate no submission with None
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
        logging.error(f"An unexpected error occurred in add_user_if_not_exists: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while accessing the database.")

    return max_marks, marks_list



async def add_student_if_not_exists(db, course_id, student_id, student_name):
    '''Add the student to the course's Students subcollection if not already present.

    Path: courses/{course_id}/Students/{student_id}
    '''
    try:
        course_ref = db.collection(u'courses').document(course_id)
        course_doc = await course_ref.get()
        if not course_doc.exists:
            logging.error(f"Course with ID '{course_id}' not found when trying to add student '{student_id}'.")
            raise CourseNotFoundError(course_id)       
        student_ref = course_ref.collection(u'Students').document(student_id)
        student_doc = await student_ref.get()
        if not student_doc.exists:
            logging.info(f"Student '{student_id}' not in course {course_id}. Adding now.")
            await student_ref.set({
                u'name': student_name,
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
        logging.info(f"User requested non-existent course: {course_id}")
        raise HTTPException(status_code=404, detail=e.message)
    except Exception as e:
        logging.error(f"An unexpected error occurred in add_user_if_not_exists: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while accessing the database.")
    
async def add_answer_notebook(db, course_id, student_id, student_name, notebook_id, answer_notebook, answer_hash):
    '''Add the answer notebook to the student's record.'''
    try:
        course_ref = db.collection(u'courses').document(course_id)
        course_doc = await course_ref.get()
        if not course_doc.exists:
            logging.error(f"Course with ID '{course_id}' not found when trying to add student '{student_id}'.")
            raise CourseNotFoundError(course_id)       
        student_ref = course_ref.collection(u'Students').document(student_id)
        student_doc = await student_ref.get()
        if not student_doc.exists:
            logging.info(f"Student '{student_id}' not in course {course_id}. Adding now.")
            await student_ref.set({
                u'name': student_name,
                })
        notebook_ref = student_ref.collection(u'notebooks').document(notebook_id)
        notebook_doc = await notebook_ref.get()
        if notebook_doc.exists:
            logging.warning(f"Notebook with ID '{notebook_id}' already exists for student '{student_id}' in course '{course_id}'. Overwriting the existing notebook.")

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
        logging.info(f"User requested non-existent course: {course_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except StudentNotEnrolledError as e:
        logging.info(f"User '{student_id}' tried to submit notebook for course '{course_id}' they are not enrolled in.")
        raise HTTPException(status_code=403, detail=str(e)) 
    except Exception as e:
        logging.error(f"Error in  add_answer_notebook: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error while adding answer notebook.")

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
        notebook_ref = student_ref.collection(u'notebooks').document(notebook_id)
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
            logging.warning(f"Notebook{notebook_id} for student '{student_id}' in course '{course_handle}' not found. Creating one to give zero marks")

        answer_doc = answer_doc.to_dict()

        graded_json = answer_doc.get('graded_json', None)

        if graded_json is None:
            logging.warning(f"Graded response for notebook '{notebook_id}' for student '{student_id}' in course '{course_handle}' not found. This may be because the notebook has not been graded yet, or because the grading data is in an older format. Returning None for this student's response.")
            return None

        logging.debug(f"student_id: {student_id} : total marks: {answer_doc.get('total_marks')} Response json: {graded_json}")

        grader_response = {'student_id': student_id, 'total_marks': answer_doc.get('total_marks'), 'max_marks': answer_doc.get('max_marks')}
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