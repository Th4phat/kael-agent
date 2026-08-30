"""Tests for transient-network error recovery in :func:`_run_cycle`.

The execution loop should treat transport-level failures (peer closed
connection, connect/read timeouts, etc.) as recoverable. The OpenAI
Agents SDK already retries these up to ``DEFAULT_MODEL_RETRY.max_retries``
inside ``stream_response_with_retry``; if the SDK's retry budget is
exhausted, the Kael loop should still back off and replay the turn
instead of marking the agent ``crashed`` and parking the scan.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from agents.exceptions import ModelBehaviorError

from kael.core.agents import AgentCoordinator
from kael.core.execution import (
    _MODEL_BEHAVIOR_RETRY_LIMIT,
    _NETWORK_RETRY_LIMIT,
    _append_cli_tool_correction,
    _is_cli_tool_hallucination,
    _run_cycle,
)


class _NeverIter:
    """Async iterator that raises immediately when consumed."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def __aiter__(self) -> _NeverIter:
        return self

    async def __anext__(self) -> Any:
        raise self._exc


class _EmptyIter:
    """Async iterator that completes immediately with no events."""

    def __aiter__(self) -> _EmptyIter:
        return self

    async def __anext__(self) -> Any:
        raise StopAsyncIteration


def _make_failing_stream(exc: BaseException) -> Any:
    stream = MagicMock()

    def events() -> _NeverIter:
        return _NeverIter(exc)

    stream.stream_events = events
    stream.run_loop_exception = None
    return stream


def _make_succeeding_stream() -> Any:
    stream = MagicMock()
    stream.stream_events = _EmptyIter
    stream.run_loop_exception = None
    return stream


async def _run_cycle_with(
    coord: AgentCoordinator,
    run_streamed_side_effect: Any,
) -> Any:
    with patch(
        "kael.core.execution.Runner.run_streamed",
        side_effect=run_streamed_side_effect,
    ):
        return await _run_cycle(
            agent=MagicMock(),
            coordinator=coord,
            agent_id="a1",
            input_data=[],
            run_config=MagicMock(),
            context={"parent_id": None},
            max_turns=10,
            session=None,
            interactive=False,
            event_sink=None,
            hooks=None,
        )


@pytest.mark.asyncio
async def test_run_cycle_recovers_from_remote_protocol_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coord = AgentCoordinator()
    await coord.register("a1", "alpha", parent_id=None)

    sleep_calls: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    monkeypatch.setattr("kael.core.execution.asyncio.sleep", fake_sleep)

    call_count = {"n": 0}

    def fake_run_streamed(*_args: Any, **_kwargs: Any) -> Any:
        call_count["n"] += 1
        if call_count["n"] <= 2:
            return _make_failing_stream(
                httpx.RemoteProtocolError("peer closed connection without sending")
            )
        return _make_succeeding_stream()

    result = await _run_cycle_with(coord, fake_run_streamed)

    assert call_count["n"] == 3, "expected 2 failed attempts + 1 success"
    assert result is not None, "successful stream should be returned"
    assert sleep_calls == [2.0, 4.0], "backoff should be 2s then 4s (exponential)"


@pytest.mark.asyncio
async def test_run_cycle_eventually_crashes_after_network_retries_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coord = AgentCoordinator()
    await coord.register("a1", "alpha", parent_id=None)

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("kael.core.execution.asyncio.sleep", fake_sleep)

    call_count = {"n": 0}

    def fake_run_streamed(*_args: Any, **_kwargs: Any) -> Any:
        call_count["n"] += 1
        return _make_failing_stream(
            httpx.RemoteProtocolError("peer closed connection without sending")
        )

    with pytest.raises(httpx.RemoteProtocolError):
        await _run_cycle_with(coord, fake_run_streamed)

    assert call_count["n"] == _NETWORK_RETRY_LIMIT + 1, (
        f"expected {_NETWORK_RETRY_LIMIT} retries + 1 initial attempt"
    )


@pytest.mark.asyncio
async def test_run_cycle_recovers_from_connect_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coord = AgentCoordinator()
    await coord.register("a1", "alpha", parent_id=None)

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("kael.core.execution.asyncio.sleep", fake_sleep)

    call_count = {"n": 0}

    def fake_run_streamed(*_args: Any, **_kwargs: Any) -> Any:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_failing_stream(httpx.ConnectError("connection refused"))
        return _make_succeeding_stream()

    await _run_cycle_with(coord, fake_run_streamed)

    assert call_count["n"] == 2, "expected 1 failed attempt + 1 success"


@pytest.mark.asyncio
async def test_run_cycle_does_not_retry_non_transient_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coord = AgentCoordinator()
    await coord.register("a1", "alpha", parent_id=None)

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("kael.core.execution.asyncio.sleep", fake_sleep)

    call_count = {"n": 0}

    def fake_run_streamed(*_args: Any, **_kwargs: Any) -> Any:
        call_count["n"] += 1
        return _make_failing_stream(ValueError("nope"))

    with pytest.raises(ValueError):
        await _run_cycle_with(coord, fake_run_streamed)

    assert call_count["n"] == 1, "non-transient error should not trigger retries"


@pytest.mark.asyncio
async def test_run_cycle_does_not_swallow_cancelled_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    coord = AgentCoordinator()
    await coord.register("a1", "alpha", parent_id=None)

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("kael.core.execution.asyncio.sleep", fake_sleep)

    call_count = {"n": 0}

    def fake_run_streamed(*_args: Any, **_kwargs: Any) -> Any:
        call_count["n"] += 1
        return _make_failing_stream(asyncio.CancelledError())

    raised: BaseException | None = None
    try:
        await _run_cycle_with(coord, fake_run_streamed)
    except asyncio.CancelledError as exc:
        raised = exc

    assert isinstance(raised, asyncio.CancelledError), (
        "CancelledError must propagate, not be swallowed by recovery"
    )
    assert call_count["n"] == 1, "CancelledError should not be retried"


class TestCliToolHallucinationDetector:
    """Detect ``agent_browser_*`` hallucinated-as-function-tool errors."""

    def test_matches_agent_browser_subcommand(self) -> None:
        exc = ModelBehaviorError("Tool agent_browser_close not found in agent kael")
        assert _is_cli_tool_hallucination(exc) == "agent_browser_close"

    def test_matches_bare_agent_browser(self) -> None:
        exc = ModelBehaviorError("Tool agent_browser not found in agent root")
        assert _is_cli_tool_hallucination(exc) == "agent_browser"

    def test_case_insensitive(self) -> None:
        exc = ModelBehaviorError("Tool Agent_Browser_Snapshot not found in agent kael")
        assert _is_cli_tool_hallucination(exc) == "Agent_Browser_Snapshot"

    def test_ignores_unrelated_missing_tools(self) -> None:
        exc = ModelBehaviorError("Tool nmap not found in agent kael")
        assert _is_cli_tool_hallucination(exc) is None

    def test_ignores_other_agent_browser_mistakes(self) -> None:
        # Different tool prefix that happens to mention agent_browser.
        exc = ModelBehaviorError("Tool my_agent_browser_thing not found in agent kael")
        assert _is_cli_tool_hallucination(exc) is None

    def test_returns_none_for_non_model_behavior_error(self) -> None:
        assert _is_cli_tool_hallucination(ValueError("nope")) is None
        assert _is_cli_tool_hallucination(RuntimeError("not a model error")) is None

    def test_returns_none_for_unparseable_message(self) -> None:
        exc = ModelBehaviorError("Something else happened")
        assert _is_cli_tool_hallucination(exc) is None


class TestCliToolCorrectionMessage:
    """The recovery message should explicitly point the model at exec_command."""

    @pytest.mark.asyncio
    async def test_message_with_subcommand_suggests_exact_call(self) -> None:
        result = await _append_cli_tool_correction(
            session=None,
            tool_name="agent_browser_close",
            attempt=1,
            limit=_MODEL_BEHAVIOR_RETRY_LIMIT,
        )
        assert len(result) == 1
        item = result[0]
        assert item["role"] == "user"
        assert "agent_browser_close" in item["content"]
        assert "exec_command" in item["content"]
        assert "agent-browser close" in item["content"]
        assert "SHELL CLI" in item["content"]

    @pytest.mark.asyncio
    async def test_message_without_subcommand_uses_ellipsis(self) -> None:
        result = await _append_cli_tool_correction(
            session=None,
            tool_name="agent_browser",
            attempt=1,
            limit=_MODEL_BEHAVIOR_RETRY_LIMIT,
        )
        assert "agent-browser ..." in result[0]["content"]

    @pytest.mark.asyncio
    async def test_message_appended_to_session_when_provided(self) -> None:
        session = MagicMock()
        session.add_items = AsyncMock()

        result = await _append_cli_tool_correction(
            session=session,
            tool_name="agent_browser_snapshot",
            attempt=1,
            limit=_MODEL_BEHAVIOR_RETRY_LIMIT,
        )

        # When a session exists, the function mutates it and returns []
        # so the runner re-enters with no fresh input (session drives next turn).
        assert result == []
        session.add_items.assert_awaited_once()
        items_arg = session.add_items.call_args.args[0]
        assert len(items_arg) == 1
        assert "agent_browser_snapshot" in items_arg[0]["content"]
        assert "agent-browser snapshot" in items_arg[0]["content"]


@pytest.mark.asyncio
async def test_run_cycle_recovers_from_agent_browser_hallucination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hallucinated ``agent_browser_*`` call should be self-corrected, not fatal."""
    coord = AgentCoordinator()
    await coord.register("a1", "alpha", parent_id=None)

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("kael.core.execution.asyncio.sleep", fake_sleep)

    session = MagicMock()
    session.add_items = AsyncMock()

    call_count = {"n": 0}

    def fake_run_streamed(*_args: Any, **_kwargs: Any) -> Any:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_failing_stream(
                ModelBehaviorError("Tool agent_browser_close not found in agent kael")
            )
        return _make_succeeding_stream()

    with patch(
        "kael.core.execution.Runner.run_streamed",
        side_effect=fake_run_streamed,
    ):
        result = await _run_cycle(
            agent=MagicMock(),
            coordinator=coord,
            agent_id="a1",
            input_data=[],
            run_config=MagicMock(),
            context={"parent_id": None},
            max_turns=10,
            session=session,
            interactive=False,
            event_sink=None,
            hooks=None,
        )

    assert call_count["n"] == 2, "expected 1 hallucination + 1 successful recovery"
    assert result is not None
    session.add_items.assert_awaited_once()
    correction = session.add_items.call_args.args[0][0]
    assert "agent_browser_close" in correction["content"]
    assert "agent-browser close" in correction["content"]


@pytest.mark.asyncio
async def test_run_cycle_crashes_after_model_behavior_retries_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the model keeps hallucinating, the scan should fail loudly after the cap."""
    coord = AgentCoordinator()
    await coord.register("a1", "alpha", parent_id=None)

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("kael.core.execution.asyncio.sleep", fake_sleep)

    session = MagicMock()
    session.add_items = AsyncMock()

    def fake_run_streamed(*_args: Any, **_kwargs: Any) -> Any:
        return _make_failing_stream(
            ModelBehaviorError("Tool agent_browser_open not found in agent kael")
        )

    with (
        patch(
            "kael.core.execution.Runner.run_streamed",
            side_effect=fake_run_streamed,
        ),
        pytest.raises(ModelBehaviorError),
    ):
        await _run_cycle(
            agent=MagicMock(),
            coordinator=coord,
            agent_id="a1",
            input_data=[],
            run_config=MagicMock(),
            context={"parent_id": None},
            max_turns=10,
            session=session,
            interactive=False,
            event_sink=None,
            hooks=None,
        )

    # 1 initial attempt + _MODEL_BEHAVIOR_RETRY_LIMIT recoveries
    assert session.add_items.await_count == _MODEL_BEHAVIOR_RETRY_LIMIT
