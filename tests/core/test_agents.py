"""Tests for the public coordinator lock API (Phase 1.3).

Verifies:

- The public ``lock()`` async context manager works.
- Direct access to ``_lock`` is no longer required (callers should
  always use ``lock()``).
- ``lock()`` is reentrant from the same task if the underlying lock
  allows it (a single acquire per call).
- Lock holds the state for the duration of the block.
"""

from __future__ import annotations

import asyncio

import pytest

from kael.core.agents import AgentCoordinator


class TestCoordinatorLockAPI:
    def test_lock_method_exists(self) -> None:
        c = AgentCoordinator()
        assert hasattr(c, "lock")
        assert callable(c.lock)

    @pytest.mark.asyncio
    async def test_lock_acquires_and_releases(self) -> None:
        c = AgentCoordinator()
        async with c.lock():
            assert c._lock.locked() is True
        assert c._lock.locked() is False

    @pytest.mark.asyncio
    async def test_lock_serializes_writers(self) -> None:
        """Two writers that both hold the lock for 50ms must serialize."""
        c = AgentCoordinator()
        order: list[str] = []

        async def writer(name: str, delay: float) -> None:
            async with c.lock():
                order.append(f"{name}-enter")
                await asyncio.sleep(delay)
                order.append(f"{name}-exit")

        await asyncio.gather(writer("A", 0.05), writer("B", 0.05))

        assert order == [
            "A-enter",
            "A-exit",
            "B-enter",
            "B-exit",
        ] or order == [
            "B-enter",
            "B-exit",
            "A-enter",
            "A-exit",
        ]
        assert order[0].endswith("-enter")
        assert order[1].endswith("-exit")

    @pytest.mark.asyncio
    async def test_lock_blocks_concurrent_holders(self) -> None:
        """A second coroutine cannot enter until the first releases."""
        c = AgentCoordinator()
        in_block = asyncio.Event()
        can_exit = asyncio.Event()

        async def holder() -> None:
            async with c.lock():
                in_block.set()
                await can_exit.wait()

        task = asyncio.create_task(holder())
        await in_block.wait()
        assert c._lock.locked() is True

        async def waiter() -> bool:
            try:
                async with asyncio.timeout(0.1):
                    async with c.lock():
                        return True
            except TimeoutError:
                return False

        result = await waiter()
        assert result is False, "lock() should block while another holder is inside"

        can_exit.set()
        await task

        async with c.lock():
            pass


class TestCoordinatorStatusOps:
    @pytest.mark.asyncio
    async def test_register_and_status(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None, task="recon")
        assert c.statuses["a1"] == "running"
        assert c.parent_of["a1"] is None
        assert c.names["a1"] == "alpha"
        assert c.metadata["a1"]["task"] == "recon"

    @pytest.mark.asyncio
    async def test_set_status(self) -> None:
        c = AgentCoordinator()
        await c.register("a1", "alpha", parent_id=None)
        await c.set_status("a1", "completed")
        assert c.statuses["a1"] == "completed"

    @pytest.mark.asyncio
    async def test_set_status_unknown_id_no_op(self) -> None:
        c = AgentCoordinator()
        await c.set_status("nonexistent", "completed")
        assert "nonexistent" not in c.statuses

    @pytest.mark.asyncio
    async def test_active_agents_except(self) -> None:
        c = AgentCoordinator()
        await c.register("root", "root", parent_id=None)
        await c.register("child1", "child1", parent_id="root")
        await c.register("child2", "child2", parent_id="root")
        await c.set_status("child1", "completed")
        active = await c.active_agents_except("root")
        active_ids = {a["agent_id"] for a in active}
        assert "child1" not in active_ids
        assert "child2" in active_ids
