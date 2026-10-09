"""Control-flow guarantees for the goal loop (fake models, no real SDK).

Covers the plan's first-slice requirements:
- an exhausted budget trips a policy stop at the hook and parks the run
  cleanly in _run_cycle — it is never retried as a transport error;
- an unsupported "success" finish is rejected with the missing criteria;
- the trusted oracle accepting the flag lets the finish complete;
- a child's success=False is reported incomplete.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import kael.tools.finish.tool as finish_tool
from kael.core.agents import AgentCoordinator
from kael.core.execution import _run_cycle
from kael.core.goals import Budget, Criterion, GoalBudgetExhausted, GoalState
from kael.core.hooks import KaelRunHooks
from kael.tools import notes as _notes_pkg  # noqa: F401  (ensure package importable)
from kael.tools.agents_graph.tools import agent_finish
from kael.tools.ctf_tools.submit_flag import submit_flag
from kael.tools.notes import tools as notes


class _NeverIter:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def __aiter__(self) -> _NeverIter:
        return self

    async def __anext__(self) -> Any:
        raise self._exc


def _failing_stream(exc: BaseException) -> Any:
    stream = MagicMock()
    stream.stream_events = lambda: _NeverIter(exc)
    stream.run_loop_exception = None
    return stream


@pytest.mark.asyncio
async def test_hook_gate_raises_only_when_budget_configured_and_exhausted() -> None:
    hooks = KaelRunHooks(model="test")
    agent = MagicMock()

    # No goal → gate inert.
    coord = AgentCoordinator()
    ctx = SimpleNamespace(context={"coordinator": coord})
    await hooks.on_llm_start(ctx, agent, None, [])  # must not raise

    # Configured + already at cap → policy stop.
    coord.goal = GoalState(budget=Budget(max_model_calls=0))
    with pytest.raises(GoalBudgetExhausted):
        await hooks.on_llm_start(ctx, agent, None, [])


@pytest.mark.asyncio
async def test_run_cycle_parks_cleanly_on_budget_policy_stop() -> None:
    coord = AgentCoordinator()
    await coord.register("a1", "alpha", parent_id=None)
    coord.goal = GoalState(budget=Budget(max_model_calls=1))

    call_count = {"n": 0}

    def fake_run_streamed(*_a: Any, **_k: Any) -> Any:
        call_count["n"] += 1
        return _failing_stream(GoalBudgetExhausted("budget_exhausted"))

    with patch("kael.core.execution.Runner.run_streamed", side_effect=fake_run_streamed):
        result = await _run_cycle(
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

    assert result is None
    assert call_count["n"] == 1, "a policy stop must not be retried"
    assert coord.statuses["a1"] == "stopped"
    assert coord.goal.outcome == "incomplete"
    assert coord.goal.stop_reason == "budget_exhausted"


def _finish_ctx(coordinator: AgentCoordinator, store: Any) -> SimpleNamespace:
    return SimpleNamespace(
        context={
            "coordinator": coordinator,
            "agent_id": "root",
            "parent_id": None,
            "notes_store": store,
        },
        tool_name="finish_scan",
        tool_call_id="t1",
    )


@pytest.mark.asyncio
async def test_finish_rejected_until_oracle_verifies_flag(tmp_path, monkeypatch) -> None:
    store = notes.hydrate_notes_from_disk(tmp_path)

    async def inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(finish_tool.asyncio, "to_thread", inline)
    monkeypatch.setattr(
        finish_tool, "_do_finish", lambda **_kw: {"success": True, "scan_completed": True}
    )

    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", None)
    coordinator.goal = GoalState(
        criteria=[Criterion(id="flag", kind="ctf_flag", config={"expected_flag": "flag{win}"})]
    )
    args = json.dumps(
        {
            "executive_summary": "s",
            "methodology": "m",
            "technical_analysis": "a",
            "recommendations": "r",
        }
    )

    # 1. Unverified → rejected with the missing criterion, not a success.
    rejected = json.loads(await finish_tool.finish_scan.on_invoke_tool(_finish_ctx(coordinator, store), args))
    assert rejected["scan_completed"] is False
    assert rejected["goal_outcome"] == "incomplete"
    assert rejected["missing_criteria"] == ["flag"]

    # 2. A wrong flag does not satisfy the oracle.
    bad = json.loads(
        await submit_flag.on_invoke_tool(
            SimpleNamespace(context={"coordinator": coordinator, "agent_id": "root"}, tool_name="submit_flag", tool_call_id="s0"),
            json.dumps({"flag": "flag{nope}"}),
        )
    )
    assert bad["verified"] is False

    # 3. The correct flag is accepted by the oracle...
    good = json.loads(
        await submit_flag.on_invoke_tool(
            SimpleNamespace(context={"coordinator": coordinator, "agent_id": "root"}, tool_name="submit_flag", tool_call_id="s1"),
            json.dumps({"flag": "flag{win}"}),
        )
    )
    assert good["verified"] is True

    # 4. ...and only now can the scan finish as achieved.
    done = json.loads(await finish_tool.finish_scan.on_invoke_tool(_finish_ctx(coordinator, store), args))
    assert done["scan_completed"] is True
    assert done["goal_outcome"] == "achieved"
    assert coordinator.goal.outcome == "achieved"


@pytest.mark.asyncio
async def test_agent_finish_success_false_reports_incomplete() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", None)
    await coordinator.register("child", "child", "root")

    def ctx(call_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            context={"coordinator": coordinator, "agent_id": "child", "parent_id": "root"},
            tool_name="agent_finish",
            tool_call_id=call_id,
        )

    failed = json.loads(
        await agent_finish.on_invoke_tool(
            ctx("c1"), json.dumps({"result_summary": "blocked", "success": False})
        )
    )
    assert failed["goal_outcome"] == "incomplete"

    ok = json.loads(
        await agent_finish.on_invoke_tool(
            ctx("c2"), json.dumps({"result_summary": "done", "success": True})
        )
    )
    assert ok["goal_outcome"] == "achieved"
