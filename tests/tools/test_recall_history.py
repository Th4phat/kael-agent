"""Bounded lookback and automatic task notes."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from kael.core.agents import AgentCoordinator
from kael.tools.agents_graph.tools import agent_finish, recall_history
from kael.tools.finish import tool as finish_tool
from kael.tools.notes import tools as notes


async def test_recall_reads_own_full_session_without_dumping_it() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("me", "agent", None)
    await coordinator.register("other", "other", None)
    own = AsyncMock()
    own.get_items.return_value = [
        {"role": "user", "content": "my task"},
        {"type": "function_call", "call_id": "1", "name": "exec_command", "arguments": "{}"},
        {
            "type": "function_call_output",
            "call_id": "1",
            "output": "x" * 20_000 + "NEEDLE" + "y" * 20_000,
        },
    ]
    await coordinator.attach_runtime("me", session=own)
    other = AsyncMock()
    other.get_items.return_value = [{"role": "user", "content": "other agent secret"}]
    await coordinator.attach_runtime("other", session=other)
    ctx = SimpleNamespace(
        context={"coordinator": coordinator, "agent_id": "me"},
        tool_name="recall_history",
        tool_call_id="t1",
    )

    result = await recall_history.on_invoke_tool(ctx, json.dumps({"query": "needle"}))  # type: ignore[arg-type]

    assert "NEEDLE" in result
    assert "exec_command" in result
    assert len(result) < 2_000
    other.get_items.assert_not_awaited()


async def test_finishing_child_persists_outcome_note(tmp_path) -> None:
    store = notes.hydrate_notes_from_disk(tmp_path)
    try:
        coordinator = AgentCoordinator()
        await coordinator.register("root", "root", None)
        await coordinator.register("child", "validator", "root", task="test login")
        ctx = SimpleNamespace(
            context={
                "coordinator": coordinator,
                "agent_id": "child",
                "parent_id": "root",
                "task": "test login",
                "notes_store": store,
            },
            tool_name="agent_finish",
            tool_call_id="t2",
        )
        result = await agent_finish.on_invoke_tool(  # type: ignore[arg-type]
            ctx,
            json.dumps(
                {
                    "result_summary": "Login bypass failed; rate limit blocked the attempt.",
                    "success": False,
                    "report_to_parent": False,
                }
            ),
        )

        assert json.loads(result)["agent_completed"] is True
        saved = json.loads((tmp_path / "notes" / "child" / "notes.json").read_text())
        assert len(saved) == 1
        note = next(iter(saved.values()))
        assert "failed" in note["tags"]
        assert "rate limit blocked" in note["content"]
        parent_notes = notes.notes_store_from_context({"notes_store": store, "agent_id": "root"})
        assert parent_notes is not None and parent_notes.notes == {}
    finally:
        store.notes.clear()


async def test_finishing_root_persists_summary_note(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = notes.hydrate_notes_from_disk(tmp_path)

    async def inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(finish_tool.asyncio, "to_thread", inline)
    monkeypatch.setattr(
        finish_tool,
        "_do_finish",
        lambda **_kwargs: {"success": True, "scan_completed": True},
    )
    try:
        coordinator = AgentCoordinator()
        await coordinator.register("root", "root", None)
        ctx = SimpleNamespace(
            context={
                "coordinator": coordinator,
                "agent_id": "root",
                "parent_id": None,
                "notes_store": store,
            },
            tool_name="finish_scan",
            tool_call_id="t3",
        )
        result = await finish_tool.finish_scan.on_invoke_tool(  # type: ignore[arg-type]
            ctx,
            json.dumps(
                {
                    "executive_summary": "Assessment done",
                    "methodology": "Checked login",
                    "technical_analysis": "No bypass found",
                    "recommendations": "Keep rate limits",
                }
            ),
        )

        assert json.loads(result)["scan_completed"] is True
        saved = json.loads((tmp_path / "notes" / "root" / "notes.json").read_text())
        note = next(iter(saved.values()))
        assert "completed" in note["tags"]
        assert "No bypass found" in note["content"]
    finally:
        store.notes.clear()
