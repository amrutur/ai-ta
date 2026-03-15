"""
Tests for agent_service functions.

All Google ADK calls are mocked — no real LLM invocations.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_service import (
    run_agent_and_get_response,
    score_question,
    get_rubric_answers,
    get_semaphore_limit,
    update_semaphore_limit,
    _is_resource_exhausted,
)
from google.genai import types


# ---------------------------------------------------------------------------
# run_agent_and_get_response
# ---------------------------------------------------------------------------

class TestRunAgentAndGetResponse:
    async def test_aggregates_text(self):
        """Verify that text from multiple events is concatenated."""
        runner = MagicMock()

        # Simulate an async stream of events
        event1 = MagicMock()
        event1.content = MagicMock()
        event1.content.parts = [MagicMock(text="Hello ")]
        event1.is_final_response.return_value = False

        event2 = MagicMock()
        event2.content = MagicMock()
        event2.content.parts = [MagicMock(text="World")]
        event2.is_final_response.return_value = True

        async def mock_stream(**kwargs):
            for e in [event1, event2]:
                yield e

        runner.run_async = mock_stream

        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text="test")]
        )
        result = await run_agent_and_get_response("session1", "user1", content, runner)
        assert result == "Hello World"

    async def test_empty_stream(self):
        """An empty stream should return empty string."""
        runner = MagicMock()

        event = MagicMock()
        event.content = None
        event.is_final_response.return_value = True

        async def mock_stream(**kwargs):
            yield event

        runner.run_async = mock_stream

        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text="test")]
        )
        result = await run_agent_and_get_response("s1", "u1", content, runner)
        assert result == ""

    async def test_signature(self):
        """Verify run_agent_and_get_response does NOT accept an 'agent' parameter."""
        import inspect
        sig = inspect.signature(run_agent_and_get_response)
        params = list(sig.parameters.keys())
        assert "agent" not in params
        assert params == ["current_session_id", "user_id", "content", "runner"]


# ---------------------------------------------------------------------------
# score_question
# ---------------------------------------------------------------------------

class TestScoreQuestion:
    async def test_extracts_marks(self, mock_runner, mock_session_service):
        """Score question should parse 'total marks: X' from agent response."""
        # Mock the session creation
        mock_session_service.create_session = AsyncMock()

        # Mock run_agent_and_get_response to return text with marks
        with patch(
            "agent_service.run_agent_and_get_response",
            new_callable=AsyncMock,
            return_value="Good answer. Total marks: 8.5 out of 10."
        ):
            marks, text = await score_question(
                "What is 2+2?", "4", "Answer is 4, worth 10 marks",
                mock_runner, mock_session_service, "user1"
            )

        assert marks == 8.5
        assert "Total marks" in text

    async def test_raises_on_no_marks_in_response(self, mock_runner, mock_session_service):
        """Should raise HTTPException when marks pattern not found."""
        mock_session_service.create_session = AsyncMock()

        with patch(
            "agent_service.run_agent_and_get_response",
            new_callable=AsyncMock,
            return_value="I don't know how to grade this."
        ):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await score_question(
                    "Q", "A", "R",
                    mock_runner, mock_session_service, "user1"
                )
            assert exc_info.value.status_code == 500

    async def test_raises_on_empty_response(self, mock_runner, mock_session_service):
        """Should raise HTTPException when agent returns empty string."""
        mock_session_service.create_session = AsyncMock()

        with patch(
            "agent_service.run_agent_and_get_response",
            new_callable=AsyncMock,
            return_value=""
        ):
            from fastapi import HTTPException
            with pytest.raises(HTTPException):
                await score_question(
                    "Q", "A", "R",
                    mock_runner, mock_session_service, "user1"
                )

    async def test_signature_does_not_use_database_session(self):
        """Type hint should NOT reference the old DatabaseSessionService."""
        import inspect
        sig = inspect.signature(score_question)
        session_param = sig.parameters["session_service"]
        annotation_str = str(session_param.annotation)
        assert "DatabaseSessionService" not in annotation_str, (
            f"session_service type hint still references DatabaseSessionService: "
            f"{annotation_str}"
        )

    async def test_includes_course_material_in_prompt(self, mock_runner, mock_session_service):
        """When course_material is provided, it should be included in the prompt."""
        mock_session_service.create_session = AsyncMock()

        with patch(
            "agent_service.run_agent_and_get_response",
            new_callable=AsyncMock,
            return_value="The total marks is 7."
        ) as mock_run:
            marks, text = await score_question(
                "What is gravity?", "9.8 m/s^2", "Answer mentions 9.8",
                mock_runner, mock_session_service, "user1",
                course_material="Newton's law of gravitation"
            )

        assert marks == 7.0
        # Verify the content passed to run_agent includes course material
        call_args = mock_run.call_args
        content_arg = call_args[0][2]  # third positional arg is content
        prompt_text = content_arg.parts[0].text
        assert "Newton's law of gravitation" in prompt_text


# ---------------------------------------------------------------------------
# _is_resource_exhausted
# ---------------------------------------------------------------------------

class TestIsResourceExhausted:
    def test_resource_exhausted_class_name(self):
        class ResourceExhausted(Exception):
            pass
        assert _is_resource_exhausted(ResourceExhausted("quota")) is True

    def test_429_in_message(self):
        assert _is_resource_exhausted(Exception("Error 429: Too many requests")) is True

    def test_resource_exhausted_in_message(self):
        assert _is_resource_exhausted(Exception("RESOURCE_EXHAUSTED")) is True

    def test_resource_exhausted_lowercase(self):
        assert _is_resource_exhausted(Exception("resource exhausted")) is True

    def test_unrelated_error(self):
        assert _is_resource_exhausted(ValueError("something else")) is False


# ---------------------------------------------------------------------------
# update_semaphore_limit / get_semaphore_limit
# ---------------------------------------------------------------------------

class TestSemaphoreManagement:
    def test_get_default_limit(self):
        # Reset to default first
        update_semaphore_limit(5)
        assert get_semaphore_limit() == 5

    def test_update_semaphore_limit(self):
        update_semaphore_limit(10)
        assert get_semaphore_limit() == 10
        # Reset
        update_semaphore_limit(5)


# ---------------------------------------------------------------------------
# get_rubric_answers
# ---------------------------------------------------------------------------

class TestGetRubricAnswers:
    async def test_extracts_single_question(self):
        cells = [
            {"source": ["** Q1 (10 marks)\nWhat is 2+2?"]},
            {"source": ["The answer is 4."]},
        ]
        answers = await get_rubric_answers(cells)
        assert 1 in answers
        assert "The answer is 4." in answers[1]

    async def test_extracts_multiple_questions(self):
        cells = [
            {"source": ["** Q1 (10)\nQuestion one"]},
            {"source": ["Answer one"]},
            {"source": ["** Q2 (5)\nQuestion two"]},
            {"source": ["Answer two"]},
        ]
        answers = await get_rubric_answers(cells)
        assert 1 in answers
        assert 2 in answers
        assert "Answer one" in answers[1]
        assert "Answer two" in answers[2]

    async def test_multi_cell_answer(self):
        cells = [
            {"source": ["** Q1\nQuestion"]},
            {"source": ["Part A"]},
            {"source": ["Part B"]},
        ]
        answers = await get_rubric_answers(cells)
        assert "Part A" in answers[1]
        assert "Part B" in answers[1]

    async def test_empty_cells(self):
        answers = await get_rubric_answers([])
        assert answers == {}

    async def test_no_question_cells(self):
        cells = [
            {"source": ["Just some text"]},
            {"source": ["More text"]},
        ]
        answers = await get_rubric_answers(cells)
        assert answers == {}
