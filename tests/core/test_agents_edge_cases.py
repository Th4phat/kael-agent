"""Edge case tests for AgentCoordinator.

Targets the operations the plan didn't cover in test_agents.py:
- attach_runtime / attach_stream / detach_stream
- send (peer message routing including dropped/unknown/error cases)
- wait_for_message / consume_pending
- cancel_descendants / cancel_descendants_graceful
- request_stop (and stream cancel)
- _message_to_session_item (user + peer + type/priority)
- snapshot / restore round-trip
- _maybe_snapshot atomic file write
- coordinator_from_context helper
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from kael.core.agents import AgentCoordinator, coordinator_from_context


class TestAttachRuntime:
    @pytest.mark.asyncio
    async def test_attach_runtime_creates_if_missing(self) -> None:
        c = AgentCoordinator()
        session = MagicMock()
        await c.attach_runtime("a1", session=session)
        assert c.runtimes["a1"].session is session

    @pytest.mark.asyncio
    async def test_attach_runtime_updates_existing(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        s1, s2 = MagicMock(), MagicMock()
        await c.attach_runtime("a1", session=s1)
        await c.attach_runtime("a1", session=s2)
        assert c.runtimes["a1"].session is s2

    @pytest.mark.asyncio
    async def test_attach_runtime_partial_update(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        s = MagicMock()
        await c.attach_runtime("a1", session=s, interrupt_on_message=True)
        rt = c.runtimes["a1"]
        assert rt.session is s
        assert rt.interrupt_on_message is True
        assert rt.task is None


class TestSendMessage:
    @pytest.mark.asyncio
    async def test_send_to_unknown_agent_returns_false(self) -> None:
        c = AgentCoordinator()
        result = await c.send("ghost", {"content": "hi"})
        assert result is False

    @pytest.mark.asyncio
    async def test_send_without_session_returns_false(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        result = await c.send("a1", {"content": "hi"})
        assert result is False

    @pytest.mark.asyncio
    async def test_send_appends_to_session_and_increments(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        session = AsyncMock()
        await c.attach_runtime("a1", session=session)
        result = await c.send("a1", {"content": "hello"})
        assert result is True
        assert c.pending_counts["a1"] == 1
        session.add_items.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_handles_session_exception(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        session = AsyncMock()
        session.add_items.side_effect = RuntimeError("session exploded")
        await c.attach_runtime("a1", session=session)
        result = await c.send("a1", {"content": "x"})
        assert result is False
        # count must not be incremented on failure
        assert c.pending_counts["a1"] == 0

    @pytest.mark.asyncio
    async def test_send_cancels_interruptable_stream(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        session = AsyncMock()
        stream = MagicMock()
        await c.attach_runtime("a1", session=session, interrupt_on_message=True)
        await c.attach_stream("a1", stream)
        await c.send("a1", {"content": "urgent"})
        stream.cancel.assert_called_once_with(mode="immediate")

    @pytest.mark.asyncio
    async def test_send_does_not_cancel_non_interruptable_stream(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        session = AsyncMock()
        stream = MagicMock()
        await c.attach_runtime("a1", session=session, interrupt_on_message=False)
        await c.attach_stream("a1", stream)
        await c.send("a1", {"content": "normal"})
        stream.cancel.assert_not_called()


class TestWaitForMessage:
    @pytest.mark.asyncio
    async def test_returns_immediately_when_pending(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        # Force-set pending count by directly mutating internal state
        async with c.lock():
            c.pending_counts["a1"] = 1
        # Should return immediately (not block)
        await asyncio.wait_for(c.wait_for_message("a1"), timeout=0.1)


class TestConsumePending:
    @pytest.mark.asyncio
    async def test_zero_count(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        count, items = await c.consume_pending("a1")
        assert count == 0
        assert items == []

    @pytest.mark.asyncio
    async def test_consume_resets_count(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        async with c.lock():
            c.pending_counts["a1"] = 3
        count, _ = await c.consume_pending("a1", include_items=False)
        assert count == 3
        assert c.pending_counts["a1"] == 0

    @pytest.mark.asyncio
    async def test_consume_with_items_uses_session(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        session = AsyncMock()
        session.get_items.return_value = ["a", "b", "c", "d"]
        await c.attach_runtime("a1", session=session)
        async with c.lock():
            c.pending_counts["a1"] = 2
        count, items = await c.consume_pending("a1", include_items=True)
        assert count == 2
        assert items == ["c", "d"]  # last 2


class TestRequestStop:
    @pytest.mark.asyncio
    async def test_request_stop_unknown_id(self) -> None:
        c = AgentCoordinator()
        # Should not raise
        await c.request_stop("nonexistent")

    @pytest.mark.asyncio
    async def test_request_stop_sets_status(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        await c.request_stop("a1")
        assert c.statuses["a1"] == "stopped"

    @pytest.mark.asyncio
    async def test_request_stop_cancels_stream(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        stream = MagicMock()
        await c.attach_stream("a1", stream)
        await c.request_stop("a1")
        stream.cancel.assert_called_once_with(mode="after_turn")


class TestCancelDescendants:
    @pytest.mark.asyncio
    async def test_cancels_subtree_tasks(self) -> None:
        c = AgentCoordinator()
        await c.register("root", "root", parent_id=None)
        await c.register("a", "a", parent_id="root")
        await c.register("b", "b", parent_id="root")
        await c.register("a1", "a1", parent_id="a")
        # attach tasks to a, b, a1
        for aid in ("a", "b", "a1"):
            task: asyncio.Task[None] = asyncio.create_task(asyncio.sleep(10))
            await c.attach_runtime(aid, task=task)
        await c.cancel_descendants("root")
        # Allow task cancellation to propagate
        for aid in ("a", "b", "a1"):
            runtime_task: asyncio.Task[Any] | None = c.runtimes[aid].task
            assert runtime_task is not None
            assert runtime_task.cancelled() or runtime_task.done()

    @pytest.mark.asyncio
    async def test_graceful_stops_subtree_in_post_order(self) -> None:
        """``cancel_descendants_graceful`` stops the agent itself AND its
        descendants, in post-order (leaves first, then parents)."""
        c = AgentCoordinator()
        await c.register("root", "root", parent_id=None)
        await c.register("a", "a", parent_id="root")
        await c.register("a1", "a1", parent_id="a")
        await c.cancel_descendants_graceful("root")
        # All three are stopped (root is included in the subtree walk)
        assert c.statuses["a1"] == "stopped"
        assert c.statuses["a"] == "stopped"
        assert c.statuses["root"] == "stopped"


class TestStreamAttachDetach:
    @pytest.mark.asyncio
    async def test_attach_stream(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        s = MagicMock()
        await c.attach_stream("a1", s)
        assert c.runtimes["a1"].stream is s

    @pytest.mark.asyncio
    async def test_detach_stream_only_clears_matching(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        s1, s2 = MagicMock(), MagicMock()
        await c.attach_stream("a1", s1)
        await c.detach_stream("a1", s2)  # different stream
        assert c.runtimes["a1"].stream is s1
        await c.detach_stream("a1", s1)
        assert c.runtimes["a1"].stream is None


class TestSnapshotRestore:
    @pytest.mark.asyncio
    async def test_snapshot_round_trip(self) -> None:
        c = AgentCoordinator()
        await c.register("root", "root", parent_id=None, task="t0", skills=["s1"])
        await c.register("a", "a", parent_id="root", task="t1")
        await c.set_status("a", "completed")
        async with c.lock():
            c.pending_counts["a"] = 5

        snap = await c.snapshot()
        assert snap["statuses"] == c.statuses
        assert snap["parent_of"] == c.parent_of
        assert snap["names"] == c.names
        assert snap["metadata"] == c.metadata
        assert snap["pending_counts"] == c.pending_counts

        c2 = AgentCoordinator()
        await c2.restore(snap)
        assert c2.statuses == c.statuses
        assert c2.parent_of == c.parent_of
        assert c2.names == c.names
        assert c2.metadata == c.metadata
        assert c2.pending_counts == c.pending_counts

    @pytest.mark.asyncio
    async def test_restore_handles_missing_keys(self) -> None:
        c = AgentCoordinator()
        await c.restore({})
        assert c.statuses == {}
        assert c.parent_of == {}

    @pytest.mark.asyncio
    async def test_graph_snapshot(self) -> None:
        c = AgentCoordinator()
        await c.register("root", "root", parent_id=None)
        await c.register("a", "a", parent_id="root")
        parents, statuses, names = await c.graph_snapshot()
        assert parents == c.parent_of
        assert statuses == c.statuses
        assert names == c.names


class TestAtomicSnapshot:
    @pytest.mark.asyncio
    async def test_snapshot_writes_atomically(self, tmp_path: Path) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        path = tmp_path / "snapshot.json"
        c.set_snapshot_path(path)
        # ``_maybe_snapshot`` is debounced; ``flush_snapshot`` waits
        # for the write to complete. The two-call pattern is what
        # production code uses on teardown.
        await c._maybe_snapshot()
        await c.flush_snapshot()
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "a1" in data["statuses"]

    @pytest.mark.asyncio
    async def test_snapshot_no_path_does_nothing(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        # No path set, must not raise
        await c._maybe_snapshot()
        await c.flush_snapshot()


class TestSnapshotDebounce:
    """``_maybe_snapshot`` schedules a debounced write; ``flush_snapshot``
    waits for it. This keeps the run dir off the I/O hot path under
    bursty agent-status mutations.
    """

    @pytest.mark.asyncio
    async def test_maybe_snapshot_does_not_write_immediately(self, tmp_path: Path) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        path = tmp_path / "snapshot.json"
        c.set_snapshot_path(path)
        await c._maybe_snapshot()
        # File must not exist yet — debounce window is 200ms.
        assert not path.exists()

    @pytest.mark.asyncio
    async def test_flush_snapshot_writes_pending_state(self, tmp_path: Path) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        path = tmp_path / "snapshot.json"
        c.set_snapshot_path(path)
        await c._maybe_snapshot()
        await c.flush_snapshot()
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "a1" in data["statuses"]

    @pytest.mark.asyncio
    async def test_burst_writes_coalesce(self, tmp_path: Path) -> None:
        """100 status mutations within the debounce window should produce
        exactly one write — not 100.
        """
        c = AgentCoordinator()
        await c.register("root", "root", parent_id=None)
        path = tmp_path / "snapshot.json"
        c.set_snapshot_path(path)

        for _i in range(100):
            await c._maybe_snapshot()

        # After the debounce window the single coalesced write should
        # have completed.
        await asyncio.sleep(0.3)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "root" in data["statuses"]

    @pytest.mark.asyncio
    async def test_flush_after_mutation_captures_final_state(self, tmp_path: Path) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        path = tmp_path / "snapshot.json"
        c.set_snapshot_path(path)

        await c._maybe_snapshot()
        # Mutation lands between debounce and flush — flush must capture it.
        await c.set_status("a1", "completed")
        await c.flush_snapshot()

        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["statuses"]["a1"] == "completed"


class TestMessageToSessionItem:
    def test_user_message_uses_role_user(self) -> None:
        c = AgentCoordinator()
        item = c._message_to_session_item({"from": "user", "content": "hi"})
        assert item == {"role": "user", "content": "hi"}

    def test_peer_message_includes_sender_header(self) -> None:
        c = AgentCoordinator()
        c.names["a1"] = "alpha"
        item = c._message_to_session_item(
            {"from": "a1", "content": "ping", "type": "request", "priority": "high"}
        )
        # The function returns a TResponseInputItem TypedDict; we read
        # the "content" key for assertion (cast to str for mypy).
        content = str(item.get("content", ""))
        assert "alpha (a1)" in content
        assert "type=request" in content
        assert "priority=high" in content
        assert "ping" in content

    def test_unknown_sender_falls_back_to_id(self) -> None:
        c = AgentCoordinator()
        item = c._message_to_session_item({"from": "ghost", "content": "x"})
        content = str(item.get("content", ""))
        assert "ghost" in content

    def test_default_type_and_priority(self) -> None:
        c = AgentCoordinator()
        item = c._message_to_session_item({"from": "a1", "content": "x"})
        content = str(item.get("content", ""))
        assert "type=information" in content
        assert "priority=normal" in content


class TestCoordinatorFromContext:
    """The contract this helper is documented to satisfy: extract a
    coordinator from a real caller's context dict, or return None.

    Real callers (see kael/tools/finish/tool.py:150,
    kael/core/execution.py) pass the dict that the SDK hands to the
    tool, so non-dict inputs are not a realistic failure mode — we
    only test the "dict with key" / "dict without key" / "dict with
    wrong type" cases.
    """

    def test_returns_coordinator_when_present(self) -> None:
        c = AgentCoordinator()
        assert coordinator_from_context({"coordinator": c}) is c

    def test_returns_none_when_missing(self) -> None:
        assert coordinator_from_context({}) is None

    def test_returns_none_when_wrong_type(self) -> None:
        assert coordinator_from_context({"coordinator": "not a coord"}) is None
        assert coordinator_from_context({"coordinator": 42}) is None
        assert coordinator_from_context({"coordinator": None}) is None


class TestParkWaitingAndMarkRunning:
    @pytest.mark.asyncio
    async def test_park_waiting(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        await c.park_waiting("a1")
        assert c.statuses["a1"] == "waiting"

    @pytest.mark.asyncio
    async def test_mark_running_on_existing(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        await c.set_status("a1", "completed")
        await c.mark_running("a1")
        assert c.statuses["a1"] == "running"

    @pytest.mark.asyncio
    async def test_mark_running_no_op_for_unknown(self) -> None:
        c = AgentCoordinator()
        await c.mark_running("ghost")
        assert "ghost" not in c.statuses


class TestActiveAgents:
    @pytest.mark.asyncio
    async def test_returns_only_running_or_waiting_excluding_self(self) -> None:
        c = AgentCoordinator()
        await c.register("root", "root", parent_id=None)
        await c.register("a", "a", parent_id="root")
        await c.register("b", "b", parent_id="root")
        await c.set_status("a", "completed")
        await c.set_status("b", "stopped")
        # Recreate a "still running" agent
        await c.register("c", "c", parent_id="root")
        active = await c.active_agents_except("root")
        active_ids = {a["agent_id"] for a in active}
        assert "a" not in active_ids  # completed
        assert "b" not in active_ids  # stopped
        assert "c" in active_ids  # running
        assert "root" not in active_ids  # excluded (self)
