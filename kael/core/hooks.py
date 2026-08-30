"""SDK run hooks used by Kael orchestration."""

from __future__ import annotations

import hashlib
import logging
import time
from collections import deque
from typing import TYPE_CHECKING, Any

from agents.lifecycle import RunHooks

from kael.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents import RunContextWrapper
    from agents.agent import Agent
    from agents.items import ModelResponse


logger = logging.getLogger(__name__)


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage after every model response."""

    def __init__(self, *, model: str) -> None:
        self._model = model

    async def on_llm_end(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        response: ModelResponse,
    ) -> None:
        report_state = get_global_report_state()
        if report_state is None:
            return

        ctx = context.context if isinstance(context.context, dict) else {}
        agent_name = getattr(agent, "name", None)
        if not isinstance(agent_name, str):
            agent_name = None
        agent_id = ctx.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            agent_id = agent_name or "unknown"

        try:
            report_state.record_sdk_usage(
                agent_id=agent_id,
                agent_name=agent_name,
                model=self._model,
                usage=response.usage,
            )
        except Exception:
            logger.exception("failed to record SDK usage for agent %s", agent_id)


def _tool_call_fingerprint(tool_name: str, arguments: Any) -> str:
    """Stable hash of (tool_name, arguments) for dedup detection.

    Ponytail: short sha256 prefix. Stable across runs, fast to compare,
    no risk of false collisions for the dedup-warning use case (model
    loops are coarse-grained — the same tool + same args repeating is
    the signal, not a hash collision).
    """
    raw = f"{tool_name}:{arguments!r}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


class ToolTelemetryHooks(RunHooks[dict[str, Any]]):
    """Per-tool-call telemetry: duration, result size, dedup warnings.

    Lightweight: no I/O, no model calls. The data lives in process
    memory and is logged at INFO; the report-state integration (if
    attached later) can persist a summary at scan end.

    Ponytail: tracks in a per-instance deque. ``dedup_window_turns``
    controls how far back we look for repeat calls. The default 1
    catches the "model called the same tool with the same args twice
    in a row" pattern that wastes a turn on no new information.
    """

    def __init__(self, *, dedup_window_turns: int = 1) -> None:
        self._dedup_window = max(0, dedup_window_turns)
        self._recent_calls: deque[tuple[str, str]] = deque(maxlen=64)
        self._starts: dict[str, float] = {}
        self._call_count = 0

    @property
    def call_count(self) -> int:
        return self._call_count

    async def on_tool_start(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],  # noqa: ARG002 - SDK-required signature
        tool: Any,
    ) -> None:
        tool_name = getattr(tool, "name", None) or "<unknown>"
        tool_call_id = getattr(context, "tool_call_id", "") or ""
        arguments = getattr(context, "tool_arguments", None)
        self._starts[tool_call_id] = time.monotonic()
        fingerprint = _tool_call_fingerprint(tool_name, arguments)
        if self._dedup_window and any(fp == fingerprint for _, fp in self._recent_calls):
            logger.warning(
                "dedup: tool %r called with same args recently — model may be stuck in a loop",
                tool_name,
            )
        self._recent_calls.append((tool_name, fingerprint))
        self._call_count += 1
        logger.debug("tool.start name=%s call_id=%s", tool_name, tool_call_id)

    async def on_tool_end(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],  # noqa: ARG002 - SDK-required signature
        tool: Any,
        result: Any,
    ) -> None:
        tool_name = getattr(tool, "name", None) or "<unknown>"
        tool_call_id = getattr(context, "tool_call_id", "") or ""
        start = self._starts.pop(tool_call_id, None)
        duration = (time.monotonic() - start) if start is not None else None
        result_str = "" if result is None else (str(result) if isinstance(result, str) else "")
        size = len(result_str) if result_str else 0
        if duration is not None:
            logger.info(
                "tool.end name=%s call_id=%s duration_ms=%.1f result_chars=%d",
                tool_name,
                tool_call_id,
                duration * 1000,
                size,
            )
        else:
            logger.debug("tool.end name=%s call_id=%s (no start)", tool_name, tool_call_id)


class KaelRunHooks(ReportUsageHooks, ToolTelemetryHooks):
    """Compound hook: SDK usage persistence + per-tool-call telemetry.

    Ponytail: one instance wired into every run so both fire from a
    single ``hooks=`` argument. Mirrors the previous
    ``ReportUsageHooks``-only wiring; callers see no API change.
    """

    def __init__(self, *, model: str, dedup_window_turns: int = 1) -> None:
        ReportUsageHooks.__init__(self, model=model)
        ToolTelemetryHooks.__init__(self, dedup_window_turns=dedup_window_turns)
