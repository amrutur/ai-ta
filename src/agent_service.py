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

from fastapi import HTTPException
from google.adk import Runner
from google.adk.sessions import DatabaseSessionService
from google.genai import types


async def run_agent_and_get_response(current_session_id: str, user_id: str, content: types.Content, runner: Runner) -> str:
    """Helper to run the agent and aggregate the response text from the stream."""
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


async def score_question(question: str, answer: str, rubric: str, runner: Runner, session_service: DatabaseSessionService, user_id: str) -> tuple[float, str]:
    '''
    Score a single question-answer with the rubric using the scoring agent.

    Args:
        question: The question asked
        answer: The student's answer
        rubric: The rubric to be used for grading
        runner: The runner with the scoring agent
        session_service: The session service for creating agent sessions
        user_id: The user ID of the student

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
        full_prompt = question + rubric + answer
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


async def evaluate(answer_json, rubric_json, runner: Runner, session_service: DatabaseSessionService, user_id: str) -> tuple[float, float, int, dict]:
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
