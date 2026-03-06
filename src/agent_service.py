"""
Agent orchestration and scoring logic.

Provides functions to run AI agents, score individual questions,
and evaluate entire notebook submissions.
"""

import sys
import logging
import traceback
import re
import uuid
import asyncio


from fastapi import HTTPException
from google.adk import Runner
from firestore_service import FirestoreSessionService
from google.genai import types

# Limit concurrent Gemini API calls to avoid rate-limit errors
DEFAULT_SEMAPHORE_LIMIT = 5
_gemini_semaphore = asyncio.Semaphore(DEFAULT_SEMAPHORE_LIMIT)
_semaphore_limit = DEFAULT_SEMAPHORE_LIMIT

def get_semaphore_limit() -> int:
    """Return the current semaphore limit."""
    return _semaphore_limit

def update_semaphore_limit(new_limit: int):
    """Replace the global semaphore with a new limit.

    In-flight requests on the old semaphore finish naturally;
    new requests use the new one.
    """
    global _gemini_semaphore, _semaphore_limit
    _semaphore_limit = new_limit
    _gemini_semaphore = asyncio.Semaphore(new_limit)
    logging.info(f"Gemini API semaphore limit updated to {new_limit}")

async def run_agent_and_get_response(current_session_id: str, user_id: str, content: types.Content, runner: Runner) -> str:
    """Helper to run the agent and aggregate the response text from the stream."""
    async with _gemini_semaphore:
        response_stream = runner.run_async(
            user_id=user_id,
            session_id=current_session_id,
            new_message=content,
        )

        text = ""
        async for event in response_stream:
            if event.content and event.content.parts:
                for part in event.content.parts:
                    text += part.text
            if event.is_final_response():
                break

        return text


async def score_question(question: str, answer: str, rubric: str, runner: Runner, session_service: FirestoreSessionService, user_id: str, course_material: str = "") -> tuple[float, str]:
    '''
    Score a single question-answer with the rubric using the scoring agent.

    Args:
        question: The question asked
        answer: The student's answer
        rubric: The rubric to be used for grading
        runner: The runner with the scoring agent
        session_service: The session service for creating agent sessions
        user_id: The user ID of the student
        course_material: Optional relevant course material from RAG retrieval

    Returns:
        Tuple of (marks, response_text)
    '''

    try:
        # Create a new session to avoid any context carryover
        session_id = str(uuid.uuid4())
        await session_service.create_session(
            app_name=runner.app_name,
            user_id=user_id,
            session_id=session_id
        )

        question = "{The assignment question is:}" + question + "."
        answer = "{The student's answer is: }" + answer + "."
        rubric = "{The scoring rubric is:}" + rubric + "."

        # Create the prompt content
        full_prompt = ""
        if course_material:
            full_prompt += "{Relevant course material:}" + course_material + " "
        full_prompt += question + rubric + answer
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=full_prompt)]
        )

        # Log the full prompt being sent to the scoring agent
        logging.debug(f"Sending prompt to scoring agent for user {user_id}:")
        logging.debug(f"Full prompt content: {full_prompt}")

        # Attempt to get the response using the current session ID
        response_text = await run_agent_and_get_response(session_id, user_id, content, runner)

    except Exception as e:
        logging.error(f"Error in score_question: {e}")
        raise HTTPException(status_code=500, detail=f"An internal error occurred while scoring: {e}")

    if not response_text:
        raise HTTPException(status_code=500, detail="Agent failed to generate response")

    # Extract the marks from the response text
    marks = 0.0
    marks_pattern = r"total\s+marks\D+(\d+\.?\d*)"
    marks_match = re.search(marks_pattern, response_text, re.IGNORECASE)
    if marks_match:
        marks = float(marks_match.group(1))
    else:
        raise HTTPException(status_code=500, detail="Agent failed to extract marks")

    return marks, response_text

async def get_rubric_answers(rubric_cells:list) -> dict:
    '''
    Extract the rubric answers from the rubric notebook cells.

    Args:
        q_id: The question ID to find the rubric answer for
        rubric_cells: The list of cells from the rubric notebook
    Returns:
        The rubric answers as a dict with question num as key and answer content as value, or an empty dict if not found.
    '''
    answers = {}
    i=0
    while i < len(rubric_cells):
        content=''.join(rubric_cells[i]['source'])
        match = re.search(r"\*\*\s*Q(\d+)",content)
        if match: 
            #this is a question cell. All cells following this till next question cell or end are the answers
            qnum = int(match.group(1))
            for j in range(i+1, len(rubric_cells)):
                content=''.join(rubric_cells[j]['source'])
                qpat = r"\*\*\s*Q(\d+)"
                if re.search(qpat,content):
                    #this is the next question cell, so break
                    break
                else:
                    if qnum not in answers:
                        answers[qnum] = content
                    else:
                        answers[qnum] += content
            i = j
        else:
            i += 1
    return answers

async def evaluate(answer_json, rubric_json, runner: Runner, session_service: FirestoreSessionService, user_id: str) -> tuple[float, float, int, dict]:
    '''Evaluate the submitted notebook by grading all questions using the scoring agent.'''
    try:
        acells = answer_json['cells']
        rcells = rubric_json['cells']
        total_marks = 0.0
        max_marks = 0.0
        num_questions = 0

        qpattern = r"\*\*Q(\d+)\*\*\s*\((\d+\.?\d*)"

        # Extract the questions from the rubric cells and match with the answer cells
        i = 0
        questions = {}
        rubrics = {}
        graded = {}  # graders response and marks
        qmax_marks = {}
        while i < len(rcells):
            if rcells[i]['cell_type'] == 'markdown':
                # Check if it is a question cell
                qmatch = re.search(qpattern, ''.join(rcells[i].get('source', [])))
                if qmatch:
                    qnum = int(qmatch.group(1))
                    qmarks = float(qmatch.group(2))
                    qmax_marks[qnum] = qmarks
                    max_marks += qmarks
                    num_questions += 1
                    questions[qnum] = ''.join(rcells[i].get('source', []))
                    logging.debug(f"Cell {i} qnum={qnum} with max marks {qmarks}")
                    i += 1
                    # Next cell should be the rubric cell
                    if i < len(rcells):
                        rubrics[qnum] = ''.join(rcells[i].get('source', []))
                    else:
                        raise Exception(f"Rubric cell missing after question {qnum}")

            i += 1
        logging.info(f"Extracted {num_questions} questions from rubric notebook with total marks {max_marks}. Now grading answers.")
        i = 0
        while i < len(acells):
            logging.debug(f"Checking cell [{i}] of type {acells[i]['cell_type']}")
            if acells[i]['cell_type'] == 'markdown':
                # Check if it is a question cell
                qmatch = re.search(r"\*\*Q(\d+)\*\*", ''.join(acells[i].get('source', [])))
                if qmatch:
                    qnum = int(qmatch.group(1))
                    i += 1
                    if i < len(acells) and acells[i]['cell_type'] == 'markdown':
                        answer = ''.join(acells[i].get('source', []))
                    else:
                        answer = "No answer provided."
                    logging.debug(f"scoring question {qnum} for user {user_id}")
                    logging.debug(f"Question: {questions[qnum]}")
                    marks, response_text = await score_question(questions[qnum], answer, rubrics[qnum], runner, session_service, user_id)
                    total_marks += marks
                    graded[qnum] = {'marks': marks, 'response': response_text}
                    logging.debug(f"response:{response_text}")
                    logging.info(f"Graded question {qnum}: awarded {marks}/{qmax_marks[qnum]} marks.")
                    if marks > qmax_marks[qnum]:
                        logging.error(f"Error: Awarded marks {marks} exceeds maximum {qmax_marks[qnum]} for question {qnum}.")
            i += 1
        return total_marks, max_marks, num_questions, graded

    except Exception as e:
        print(f"Error during evaluation: {e}", file=sys.stderr)
        traceback.print_exc()

async def get_rubric(rubric_link: str, service_account_info: dict) -> dict:
    '''
    Load the rubric notebook from Google Drive using the service account.

    Args:
        rubric_link: The shareable link to the rubric notebook
        service_account_info: The service account credentials
    '''
    from drive_utils import load_notebook_from_google_drive_sa, extract_file_id_from_share_link
    file_id = extract_file_id_from_share_link(rubric_link)
    if not file_id:
        raise HTTPException(status_code=400, detail="Invalid rubric link provided.")
    rubric_notebook = await asyncio.to_thread(
                load_notebook_from_google_drive_sa, service_account_info, rubric_link)

    if not rubric_notebook:
        raise HTTPException(status_code=500, detail="Failed to load rubric notebook from Google Drive.")
    try:    
        import nbformat
        rubric_notebook = nbformat.reads(rubric_notebook, as_version=4)
        return rubric_notebook
    except Exception as e:
        logging.error(f"Error parsing rubric notebook content: {e}")
        raise HTTPException(status_code=500, detail="Failed to parse rubric notebook content.")
