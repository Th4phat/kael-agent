"""Tests for ``CompactingSession`` middleware and ``think`` tool storage."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest


class _FakeSession:
    """In-memory Session stand-in: a list under the hood, full Protocol compat."""

    def __init__(self, session_id: str = "fake") -> None:
        self.session_id = session_id
        self.session_settings = None
        self._items: list[Any] = []

    async def get_items(self, limit: int | None = None) -> list[Any]:
        return list(self._items) if limit is None else list(self._items[-limit:])

    async def add_items(self, items: list[Any]) -> None:
        self._items.extend(items)

    async def pop_item(self) -> Any:
        return self._items.pop() if self._items else None

    async def clear_session(self) -> None:
        self._items.clear()


def _fc(name: str, args: str) -> dict[str, Any]:
    return {
        "type": "function_call",
        "name": name,
        "arguments": args,
        "call_id": f"{name}_id",
    }


def _fo(name: str, result: str) -> dict[str, Any]:
    return {
        "type": "function_call_output",
        "call_id": f"{name}_id",
        "output": [{"type": "input_text", "text": result}],
    }


class TestCompactingSession:
    async def test_under_threshold_passes_through(self) -> None:
        from kael.core.sessions import CompactingSession

        inner = _FakeSession()
        compact = CompactingSession(inner, threshold=20, keep_recent=5, min_compaction_interval=1)
        for i in range(10):
            await compact.add_items([_fc(f"t{i}", "{}"), _fo(f"t{i}", f"r{i}")])
        items = await compact.get_items()
        assert len(items) == 20
        assert compact.compaction_count == 0

    async def test_over_threshold_compacts(self) -> None:
        from kael.core.sessions import CompactingSession

        inner = _FakeSession()
        # interval=1 so every add_items past the threshold will re-compact.
        # 30 items, threshold=10, keep_recent=4 → 1 summary + 4 recent = 5.
        compact = CompactingSession(inner, threshold=10, keep_recent=4, min_compaction_interval=1)
        for i in range(15):
            await compact.add_items([_fc(f"t{i}", '{"i": 0}'), _fo(f"t{i}", f"result-{i}")])
        items = await compact.get_items()
        # Final state: at least one summary item, recent items preserved.
        assert any(
            item.get("type") == "function_call_output"
            and item.get("call_id") == "session_compaction"
            for item in items
        )
        assert compact.compaction_count >= 1
        # Total items are bounded by keep_recent + 1 summary + slack (at most
        # threshold extras because the next compact waits for the next call).
        assert len(items) <= 5 + 10
        # The summary text references at least one tool name.
        summary = next(
            item
            for item in items
            if item.get("type") == "function_call_output"
            and item.get("call_id") == "session_compaction"
        )
        text = summary["output"][0]["text"]
        assert "compacted" in text
        # First-call tool name appears in the summary.
        assert "t0" in text

    async def test_min_interval_throttles_compaction(self) -> None:
        from kael.core.sessions import CompactingSession

        inner = _FakeSession()
        compact = CompactingSession(inner, threshold=10, keep_recent=4, min_compaction_interval=5)
        for _ in range(4):
            await compact.add_items([_fc("a", "{}"), _fo("a", "x")])
        # 4 calls * 2 items = 8 items, below threshold, no compact.
        assert compact.compaction_count == 0
        await compact.add_items([_fc("b", "{}"), _fo("b", "y")])  # 5th call, 10 items
        # Still not over threshold (10 == threshold) so no compact.
        assert compact.compaction_count == 0
        await compact.add_items([_fc("c", "{}"), _fo("c", "z")])  # 12 items
        # 6th call since last compact-or-init, interval=5 → compact.
        assert compact.compaction_count == 1

    async def test_session_id_proxied(self) -> None:
        from kael.core.sessions import CompactingSession

        inner = _FakeSession(session_id="abc")
        compact = CompactingSession(inner, threshold=100, keep_recent=10)
        assert compact.session_id == "abc"

    @pytest.mark.integration
    async def test_works_with_real_sqlite_session(self) -> None:
        from kael.core.sessions import CompactingSession, open_agent_session

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.db"
            real = open_agent_session("agent-1", path)
            try:
                compact = CompactingSession(
                    real, threshold=6, keep_recent=2, min_compaction_interval=1
                )
                for i in range(10):
                    await compact.add_items([_fc(f"t{i}", "{}"), _fo(f"t{i}", f"r{i}")])
                items = await compact.get_items()
                # Compaction happened at least once; bounded count.
                assert compact.compaction_count >= 1
                assert len(items) < 20
            finally:
                close = getattr(real, "close", None)
                if callable(close):
                    res = close()
                    if asyncio.iscoroutine(res):
                        await res


class TestThinkToolStorage:
    def test_drain_returns_recent_and_clears(self) -> None:
        from kael.tools.thinking.tool import drain_thoughts

        drain_thoughts()
        from kael.tools.thinking.tool import _THINK_LOG

        _THINK_LOG.append({"id": "a", "ts": 1, "text": "first"})
        _THINK_LOG.append({"id": "b", "ts": 2, "text": "second"})
        drained = drain_thoughts()
        assert len(drained) == 2
        assert drained[0]["id"] == "a"
        # Buffer is now empty.
        assert drain_thoughts() == []

    def test_think_records_to_buffer(self) -> None:
        from kael.tools.thinking.tool import _THINK_LOG, drain_thoughts

        drain_thoughts()  # clean
        # Run the function_tool: we need to invoke via .on_invoke_tool which
        # requires a ToolContext. For unit-level, just exercise the same
        # code path the SDK would.
        result = asyncio.run(_invoke_think("plan: enumerate then probe"))
        assert json.loads(result)["success"] is True
        assert "note_id" in json.loads(result)
        assert len(_THINK_LOG) == 1
        assert _THINK_LOG[0]["text"] == "plan: enumerate then probe"
        drain_thoughts()

    def test_think_rejects_empty(self) -> None:
        result = asyncio.run(_invoke_think("   "))
        assert json.loads(result)["success"] is False


async def _invoke_think(thought: str) -> str:
    """Invoke the think FunctionTool via a manually-built JSON payload.

    The SDK's FunctionTool.on_invoke_tool expects a context that
    exposes ``tool_name`` for tracing; we don't need tracing in unit
    tests, so we use a plain object that quacks the same.
    """
    from kael.tools.thinking.tool import think

    class _Ctx:
        tool_name = "think"
        tool_call_id = "t1"

    return await think.on_invoke_tool(_Ctx(), json.dumps({"thought": thought}))  # type: ignore[arg-type]
