"""SDK session helpers for Kael agents."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, cast

from agents.memory import SQLiteSession


if TYPE_CHECKING:
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.memory import Session


def open_agent_session(agent_id: str, path: Path) -> SQLiteSession:
    path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteSession(session_id=agent_id, db_path=path)


_IMAGE_REJECTED_TEXT = "[image rejected by the model]"


async def strip_all_images_from_session(session: Session) -> bool:
    items = await session.get_items()
    if not items:
        return False

    rebuilt: list[Any] = []
    changed = False
    for item in items:
        item_dict = cast("dict[str, Any]", item) if isinstance(item, dict) else None
        if (
            item_dict is not None
            and item_dict.get("type") == "function_call_output"
            and isinstance(item_dict.get("output"), list)
            and any(
                isinstance(b, dict) and b.get("type") == "input_image" for b in item_dict["output"]
            )
        ):
            rebuilt.append(
                {
                    "type": "function_call_output",
                    "call_id": item_dict.get("call_id"),
                    "output": [{"type": "input_text", "text": _IMAGE_REJECTED_TEXT}],
                },
            )
            changed = True
        else:
            rebuilt.append(item)

    if not changed:
        return False

    rebuilt_items = cast("list[TResponseInputItem]", rebuilt)
    await session.clear_session()
    try:
        await session.add_items(rebuilt_items)
    except Exception:
        with contextlib.suppress(Exception):
            await session.add_items(rebuilt_items)
        raise
    return True


def _summarise_items(items: list[Any]) -> dict[str, Any]:
    """Build a compact summary of N session items.

    Ponytail: no model call. Counts tool calls, concatenates the first
    200 chars of each tool result, and drops raw function arguments
    and outputs. The summary is enough to remember "what happened" at
    a coarse grain, not enough to recover exact values.
    """
    tool_calls: list[str] = []
    preview_chunks: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "function_call":
            tool_calls.append(str(item.get("name", "?")))
        elif item.get("type") == "function_call_output":
            output = item.get("output")
            if isinstance(output, str):
                preview_chunks.append(output[:200])
            elif isinstance(output, list):
                preview_chunks.extend(
                    str(block.get("text", ""))[:200]
                    for block in output
                    if isinstance(block, dict) and block.get("type") == "input_text"
                )
    return {
        "type": "function_call_output",
        "call_id": "session_compaction",
        "output": [
            {
                "type": "input_text",
                "text": (
                    f"[compacted: {len(items)} items, "
                    f"{len(tool_calls)} tool calls: {', '.join(tool_calls[:20])}"
                    f"{'...' if len(tool_calls) > 20 else ''}]"
                    + (f" Previews: {' | '.join(preview_chunks[:5])}" if preview_chunks else "")
                ),
            }
        ],
    }


class CompactingSession:
    """Session wrapper that rolls up history past a size threshold.

    Wraps any :class:`agents.memory.Session`. On every ``add_items``
    call, if the total item count exceeds ``threshold``, the oldest
    ``keep_recent`` items are preserved verbatim and everything older
    is replaced with a single summary item. Compaction runs at most
    once per N ``add_items`` calls (``min_compaction_interval``) to
    avoid rewriting the session on every single tool call.

    Ponytail: no model call. The summary is structural metadata only
    (tool-call list + result previews). Bump up to a real LLM-summary
    if user feedback shows the compaction loses information the agent
    needs; until then, structural summary is the lazy baseline.
    """

    def __init__(
        self,
        inner: Session,
        *,
        threshold: int = 100,
        keep_recent: int = 50,
        min_compaction_interval: int = 20,
    ) -> None:
        self._inner = inner
        self._threshold = max(keep_recent + 1, threshold)
        self._keep_recent = max(1, keep_recent)
        self._min_interval = max(1, min_compaction_interval)
        self._calls_since_compact = 0

    @property
    def session_id(self) -> str:
        return getattr(self._inner, "session_id", "compacting")

    @property
    def session_settings(self) -> Any:
        return getattr(self._inner, "session_settings", None)

    @property
    def inner(self) -> Session:
        """Underlying session, for hooks/middleware that need direct access."""
        return self._inner

    @property
    def compaction_count(self) -> int:
        return getattr(self._inner, "_kael_compaction_count", 0)

    async def get_items(self, limit: int | None = None) -> list[TResponseInputItem]:
        return await self._inner.get_items(limit=limit)

    async def add_items(self, items: list[TResponseInputItem]) -> None:
        await self._inner.add_items(items)
        self._calls_since_compact += 1
        if self._calls_since_compact < self._min_interval:
            return
        current = await self._inner.get_items()
        if len(current) > self._threshold:
            await self._compact(current)

    async def pop_item(self) -> TResponseInputItem | None:
        return await self._inner.pop_item()

    async def clear_session(self) -> None:
        await self._inner.clear_session()

    async def _compact(self, current: list[TResponseInputItem]) -> None:
        keep_from = max(0, len(current) - self._keep_recent)
        to_summarise = list(current[:keep_from])
        if not to_summarise:
            return
        kept = list(current[keep_from:])
        summary = _summarise_items(to_summarise)
        await self._inner.clear_session()
        new_items: list[TResponseInputItem] = [summary, *kept]  # type: ignore[list-item]
        await self._inner.add_items(new_items)
        self._calls_since_compact = 0
        count = getattr(self._inner, "_kael_compaction_count", 0) + 1
        with contextlib.suppress(Exception):  # SQLiteSession may not allow attr set
            self._inner._kael_compaction_count = count  # type: ignore[attr-defined]

    def __getattr__(self, name: str) -> Any:
        # Forward anything else (eg. ``close`` on the underlying session).
        return getattr(self._inner, name)
