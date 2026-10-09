"""SDK-native state for Kael's addressable agent graph."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import tempfile
from collections.abc import Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from agents import RunConfig
    from agents.items import TResponseInputItem
    from agents.memory import Session

    from kael.config.settings import Settings


logger = logging.getLogger(__name__)

Status = Literal["running", "waiting", "completed", "stopped", "crashed", "failed"]

# Debounce window for coordinator snapshot writes. Status changes
# arrive in bursts (register, mark_running, set_status, send, ...).
# Coalescing them onto a single delayed write keeps the run dir off
# the I/O hot path under heavy parallel-agent activity. 200 ms is
# well under human-perceptible "live" lag in the TUI's resume view.
_SNAPSHOT_DEBOUNCE_SECONDS = 0.2


@dataclass(slots=True)
class AgentRuntime:
    session: Session | None = None
    task: asyncio.Task[Any] | None = None
    stream: Any | None = None
    interrupt_on_message: bool = False
    wake: asyncio.Event = field(default_factory=asyncio.Event)


class AgentCoordinator:
    """Single owner for graph state, SDK runtimes, messages, and resume snapshots."""

    def __init__(self) -> None:
        self.statuses: dict[str, Status] = {}
        self.parent_of: dict[str, str | None] = {}
        self.names: dict[str, str] = {}
        self.metadata: dict[str, dict[str, Any]] = {}
        self.pending_counts: dict[str, int] = {}
        self.runtimes: dict[str, AgentRuntime] = {}
        self._lock = asyncio.Lock()
        self._snapshot_path: Path | None = None
        self._snapshot_dirty = False
        self._snapshot_task: asyncio.Task[None] | None = None
        self.is_shutting_down = False
        self.run_config: RunConfig | None = None
        self.model_uses_chat_completions: bool | None = None
        self.model_api_base: str | None = None
        # Invoked synchronously after every graph mutation (the TUI uses it
        # to pull a fresh snapshot instead of polling).
        self.on_change: Callable[[], None] | None = None

    def set_snapshot_path(self, path: Path) -> None:
        self._snapshot_path = path

    def mark_shutting_down(self) -> None:
        self.is_shutting_down = True

    def set_openrouter_provider(
        self, provider: dict[str, Any] | None, api_base: str | None = None
    ) -> None:
        """Change routing for the next request of every agent in this run."""
        from kael.config.models import openrouter_extra_body

        config = self.run_config
        if config is None or config.model_settings is None:
            return
        model_name = config.model if isinstance(config.model, str) else ""
        extra_body = config.model_settings.extra_body
        body = dict(extra_body) if isinstance(extra_body, Mapping) else {}
        body.pop("provider", None)
        active_base = (
            self.model_api_base if self.model_uses_chat_completions is not None else api_base
        )
        body.update(openrouter_extra_body(model_name, provider, active_base) or {})
        config.model_settings.extra_body = body or None

    def apply_model_settings(self, settings: Settings) -> bool:
        """Update compatible live requests; defer tool-format changes to a new run."""
        from kael.config.models import (
            KaelProvider,
            configure_sdk_model_defaults,
            uses_chat_completions_tool_schema,
        )
        from kael.core.inputs import make_model_settings

        config = self.run_config
        if config is None:
            return True
        llm = settings.llm
        model = (llm.model or "").strip()
        if not model or (
            self.model_uses_chat_completions is not None
            and self.model_uses_chat_completions
            != uses_chat_completions_tool_schema(model, settings)
        ):
            return False
        fresh = make_model_settings(
            llm.reasoning_effort,
            model_name=model,
            parallel_tool_calls_mode=settings.tool_harness.parallel_tool_calls_mode,
            openrouter_provider=llm.openrouter_provider,
            api_base=llm.api_base,
        )
        current = config.model_settings or fresh
        body = dict(current.extra_body) if isinstance(current.extra_body, Mapping) else {}
        body.pop("provider", None)
        if isinstance(fresh.extra_body, Mapping):
            body.update(fresh.extra_body)
        model_settings = replace(
            current,
            reasoning=fresh.reasoning,
            parallel_tool_calls=fresh.parallel_tool_calls,
            extra_body=body or None,
            extra_args={**(current.extra_args or {}), "timeout": llm.timeout},
        )
        configure_sdk_model_defaults(settings)
        config.model_provider = KaelProvider()
        config.model_settings = model_settings
        config.model = model
        self.model_api_base = llm.api_base
        return True

    @asynccontextmanager
    async def lock(self) -> AsyncIterator[None]:
        """Acquire the coordinator's graph-state lock for the duration of the block.

        Use this instead of touching ``self._lock`` directly — direct access
        is a private implementation detail and will be removed.
        """
        async with self._lock:
            yield None

    async def register(
        self,
        agent_id: str,
        name: str,
        parent_id: str | None,
        *,
        task: str | None = None,
        skills: list[str] | None = None,
    ) -> None:
        async with self._lock:
            self.statuses[agent_id] = "running"
            self.parent_of[agent_id] = parent_id
            self.names[agent_id] = name
            self.pending_counts.setdefault(agent_id, 0)
            self.metadata[agent_id] = {
                "task": task or "",
                "skills": list(skills or []),
            }
            self.runtimes.setdefault(agent_id, AgentRuntime())
        logger.info("agent.register %s (%s) parent=%s", agent_id, name, parent_id or "-")
        await self._maybe_snapshot()

    async def attach_runtime(
        self,
        agent_id: str,
        *,
        session: Session | None = None,
        task: asyncio.Task[Any] | None = None,
        interrupt_on_message: bool | None = None,
    ) -> None:
        async with self._lock:
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            if session is not None:
                runtime.session = session
            if task is not None:
                runtime.task = task
            if interrupt_on_message is not None:
                runtime.interrupt_on_message = interrupt_on_message

    async def mark_running(self, agent_id: str) -> None:
        async with self._lock:
            if agent_id in self.statuses:
                self.statuses[agent_id] = "running"
        await self._maybe_snapshot()

    async def park_waiting(self, agent_id: str) -> None:
        await self.set_status(agent_id, "waiting")

    async def set_status(self, agent_id: str, status: Status | str) -> None:
        async with self._lock:
            if agent_id not in self.statuses:
                return
            self.statuses[agent_id] = status  # type: ignore[assignment]
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            runtime.wake.set()
        logger.info("agent.status %s=%s", agent_id, status)
        await self._maybe_snapshot()

    async def send(self, target_agent_id: str, message: dict[str, Any]) -> bool:
        """Deliver a user/peer message by appending it to the target SDK session."""
        async with self._lock:
            if target_agent_id not in self.statuses:
                logger.debug("agent.send dropped unknown target=%s", target_agent_id)
                return False
            runtime = self.runtimes.setdefault(target_agent_id, AgentRuntime())
            session = runtime.session
            stream = runtime.stream
            interrupt = runtime.interrupt_on_message
        if session is None:
            logger.warning(
                "agent.send dropped target=%s because its SDK session is not attached",
                target_agent_id,
            )
            return False
        try:
            await session.add_items([self._message_to_session_item(message)])
        except Exception:
            logger.exception(
                "agent.send failed to append to SDK session target=%s",
                target_agent_id,
            )
            return False
        async with self._lock:
            self.pending_counts[target_agent_id] = self.pending_counts.get(target_agent_id, 0) + 1
            self.runtimes.setdefault(target_agent_id, AgentRuntime()).wake.set()
        if stream is not None and interrupt:
            stream.cancel(mode="immediate")
        await self._maybe_snapshot()
        return True

    async def wait_for_message(self, agent_id: str) -> None:
        while True:
            async with self._lock:
                if self.pending_counts.get(agent_id, 0) > 0:
                    return
                wake = self.runtimes.setdefault(agent_id, AgentRuntime()).wake
                wake.clear()
            await wake.wait()

    async def consume_pending(
        self,
        agent_id: str,
        *,
        include_items: bool = False,
    ) -> tuple[int, list[Any]]:
        async with self._lock:
            count = self.pending_counts.get(agent_id, 0)
            self.pending_counts[agent_id] = 0
            session = self.runtimes.get(agent_id, AgentRuntime()).session
        if count <= 0:
            return 0, []
        await self._maybe_snapshot()
        if not include_items or session is None:
            return count, []
        items = await session.get_items()
        return count, list(items[-count:])

    async def request_stop(self, agent_id: str) -> None:
        async with self._lock:
            if agent_id not in self.statuses:
                return
            self.statuses[agent_id] = "stopped"
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            runtime.wake.set()
            stream = runtime.stream
        if stream is not None:
            stream.cancel(mode="after_turn")
        await self._maybe_snapshot()

    async def cancel_descendants(self, agent_id: str) -> None:
        tasks = []
        async with self._lock:
            for aid in reversed(self._subtree_order_locked(agent_id)):
                task = self.runtimes.get(aid, AgentRuntime()).task
                if task is not None and not task.done():
                    tasks.append(task)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def cancel_descendants_graceful(self, agent_id: str) -> None:
        async with self._lock:
            order = self._subtree_order_locked(agent_id)
        for aid in reversed(order):
            await self.request_stop(aid)
        await self._maybe_snapshot()

    async def attach_stream(
        self,
        agent_id: str,
        stream: Any,
    ) -> None:
        async with self._lock:
            self.runtimes.setdefault(agent_id, AgentRuntime()).stream = stream

    async def detach_stream(
        self,
        agent_id: str,
        stream: Any,
    ) -> None:
        async with self._lock:
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            if runtime.stream is stream:
                runtime.stream = None

    async def active_agents_except(self, agent_id: str) -> list[dict[str, Any]]:
        async with self._lock:
            return [
                {
                    "agent_id": aid,
                    "name": self.names.get(aid, aid),
                    "status": status,
                    "parent_id": self.parent_of.get(aid),
                }
                for aid, status in self.statuses.items()
                if aid != agent_id and status in {"running", "waiting"}
            ]

    async def graph_snapshot(
        self,
    ) -> tuple[dict[str, str | None], dict[str, Status], dict[str, str]]:
        async with self._lock:
            return dict(self.parent_of), dict(self.statuses), dict(self.names)

    def _message_to_session_item(self, message: dict[str, Any]) -> TResponseInputItem:
        sender = str(message.get("from", "unknown"))
        content = str(message.get("content", ""))
        if sender == "user":
            return cast("TResponseInputItem", {"role": "user", "content": content})
        sender_name = self.names.get(sender, sender)
        msg_type = message.get("type", "information")
        priority = message.get("priority", "normal")
        return cast(
            "TResponseInputItem",
            {
                "role": "user",
                "content": (
                    f"[Message from {sender_name} ({sender}) | type={msg_type} "
                    f"| priority={priority}]\n{content}"
                ),
            },
        )

    def _subtree_order_locked(self, agent_id: str) -> list[str]:
        queue = [agent_id]
        order: list[str] = []
        while queue:
            aid = queue.pop()
            order.append(aid)
            queue.extend(child for child, parent in self.parent_of.items() if parent == aid)
        return order

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "statuses": dict(self.statuses),
                "parent_of": dict(self.parent_of),
                "names": dict(self.names),
                "metadata": {aid: dict(md) for aid, md in self.metadata.items()},
                "pending_counts": dict(self.pending_counts),
            }

    async def restore(self, snap: dict[str, Any]) -> None:
        async with self._lock:
            self.statuses = dict(snap.get("statuses", {}))
            self.parent_of = dict(snap.get("parent_of", {}))
            self.names = dict(snap.get("names", {}))
            self.metadata = {aid: dict(md) for aid, md in snap.get("metadata", {}).items()}
            self.pending_counts = dict(snap.get("pending_counts", {}))
            for aid in self.statuses:
                self.runtimes.setdefault(aid, AgentRuntime())

    async def _maybe_snapshot(self) -> None:
        """Mark the snapshot dirty and schedule a debounced write.

        Returns immediately. Use :meth:`flush_snapshot` to wait for the
        pending write — typically only needed on shutdown or in tests.
        No-op when no snapshot path has been configured.
        """
        if self.on_change is not None:
            self.on_change()
        if self._snapshot_path is None:
            return
        async with self._lock:
            self._snapshot_dirty = True
            if self._snapshot_task is not None and not self._snapshot_task.done():
                return
            self._snapshot_task = asyncio.create_task(
                self._debounced_snapshot(), name="coordinator-snapshot"
            )

    async def _debounced_snapshot(self) -> None:
        """Sleep for the debounce window, then write if still dirty.

        Subsequent ``_maybe_snapshot`` calls during the sleep either
        no-op (task is still running) or schedule a fresh task. The
        actual write is gated on the dirty flag so a single coalesced
        flush captures all mutations in the window.
        """
        try:
            await asyncio.sleep(_SNAPSHOT_DEBOUNCE_SECONDS)
        except asyncio.CancelledError:
            return
        async with self._lock:
            if not self._snapshot_dirty:
                return
            self._snapshot_dirty = False
            path = self._snapshot_path
        if path is None:
            return
        try:
            data = await self.snapshot()
            payload = json.dumps(data, ensure_ascii=False, default=str)
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp:
                tmp.write(payload)
                tmp_path = Path(tmp.name)
            tmp_path.replace(path)
        except Exception:
            logger.exception("coordinator snapshot to %s failed", path)

    async def flush_snapshot(self) -> None:
        """Wait for any pending debounced write to complete and write a
        final synchronous copy of the current state.

        Idempotent — safe to call when no snapshot is pending. Callers
        that need a guaranteed on-disk view (e.g. on scan teardown or
        before user-visible resume) should ``await flush_snapshot()``.
        """
        async with self._lock:
            task = self._snapshot_task
        if task is not None and not task.done():
            with contextlib.suppress(asyncio.CancelledError):
                await task
        # Force a fresh synchronous write so a mutation that lands
        # between the debounce and this call is also captured.
        async with self._lock:
            if self._snapshot_path is None:
                return
            self._snapshot_dirty = False
            path = self._snapshot_path
        try:
            data = await self.snapshot()
            payload = json.dumps(data, ensure_ascii=False, default=str)
            assert path is not None
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp:
                tmp.write(payload)
                tmp_path = Path(tmp.name)
            tmp_path.replace(path)
        except Exception:
            logger.exception("coordinator flush_snapshot to %s failed", path)


def coordinator_from_context(ctx: dict[str, Any]) -> AgentCoordinator | None:
    coordinator = ctx.get("coordinator")
    return coordinator if isinstance(coordinator, AgentCoordinator) else None
