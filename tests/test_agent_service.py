"""
Tests for agent_service functions.

All Google ADK calls are mocked — no real LLM invocations.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_service import run_agent_and_get_response, score_question
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
