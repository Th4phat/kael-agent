"""TUI-owned projection of SDK session history and stream events."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path

from kael.core.paths import runtime_state_dir
from kael.interface.tui.history import load_session_history


# ponytail: cap per-event content on resume. See history.MAX_HYDRATED_EVENTS_PER_AGENT
# for the batch-level cap. This guards the single-message case: a 250KB
# final report rendered with Pygments = thousands of spans = the bulk of
# the 300MB blow-up. Ceiling: resumed messages over this size show a
# truncation marker. Upgrade: lazy render / virtualized chat view.
MAX_HYDRATED_MESSAGE_CHARS = 8_000


class TuiLiveView:
    def __init__(self) -> None:
        self.agents: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self._events_by_agent: dict[str, list[dict[str, Any]]] = {}  # Index for O(1) lookups
        self._next_event_id = 1
        self._open_assistant_event_by_agent: dict[str, dict[str, Any]] = {}
        self._open_reasoning_event_by_agent: dict[str, dict[str, Any]] = {}
        self._tool_event_by_call_id: dict[str, dict[str, Any]] = {}

    def hydrate_from_run_dir(self, run_dir: Path) -> None:
        state_dir = runtime_state_dir(run_dir)
        agents_path = state_dir / "agents.json"
        if not agents_path.exists():
            return
        try:
            agents_data = json.loads(agents_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        statuses = agents_data.get("statuses") or {}
        names = agents_data.get("names") or {}
        parent_of = agents_data.get("parent_of") or {}
        if not isinstance(statuses, dict):
            return
        for agent_id, status in statuses.items():
            if not isinstance(agent_id, str):
                continue
            self.upsert_agent(
                agent_id,
                name=names.get(agent_id, agent_id) if isinstance(names, dict) else agent_id,
                parent_id=parent_of.get(agent_id) if isinstance(parent_of, dict) else None,
                status=str(status),
            )
        self._hydrate_sdk_session_history(run_dir, statuses.keys())

    def _hydrate_sdk_session_history(self, run_dir: Path, agent_ids: Any) -> None:
        for agent_id, item, timestamp in load_session_history(run_dir, agent_ids):
            self._ingest_session_history_item(
                agent_id,
                item,
                timestamp=timestamp,
            )

    def upsert_agent(
        self,
        agent_id: str,
        *,
        name: str | None = None,
        parent_id: str | None = None,
        status: str | None = None,
        error_message: str | None = None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        current = self.agents.setdefault(
            agent_id,
            {
                "id": agent_id,
                "name": name or agent_id,
                "parent_id": parent_id,
                "status": status or "running",
                "created_at": now,
                "updated_at": now,
            },
        )
        if name is not None:
            current["name"] = name
        if parent_id is not None or "parent_id" not in current:
            current["parent_id"] = parent_id
        if status is not None:
            current["status"] = status
        if error_message:
            current["error_message"] = error_message
        current["updated_at"] = now

    def record_user_message(self, agent_id: str, content: str) -> dict[str, Any]:
        return self._append_event(
            agent_id,
            "chat",
            {
                "role": "user",
                "content": content,
                "metadata": {"source": "tui_user"},
            },
        )

    def ingest_sdk_event(self, agent_id: str, event: Any) -> list[dict[str, Any]]:
        """Fold one SDK stream event into the view; return the events it touched."""
        event_type = getattr(event, "type", "")
        if event_type == "raw_response_event":
            return self._ingest_raw_response_event(agent_id, getattr(event, "data", None))
        if event_type != "run_item_stream_event":
            return []

        item = getattr(event, "item", None)
        item_type = getattr(item, "type", "")
        touched: list[dict[str, Any]] = []
        if item_type == "reasoning_item":
            touched += self._close_reasoning(agent_id)
        elif item_type == "message_output_item":
            touched += self._close_reasoning(agent_id)
            touched += self._record_assistant_message(agent_id, _sdk_message_text(item), final=True)
        elif item_type == "tool_call_item":
            touched.append(self._record_tool_call(agent_id, item))
        elif item_type == "tool_call_output_item":
            touched.append(self._record_tool_output(agent_id, item))
        return touched

    def events_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        return self._events_by_agent.get(agent_id, [])

    def has_events_for_agent(self, agent_id: str) -> bool:
        return bool(self._events_by_agent.get(agent_id))

    def _ingest_raw_response_event(self, agent_id: str, data: Any) -> list[dict[str, Any]]:
        data_type = getattr(data, "type", "")
        delta = getattr(data, "delta", "")
        if not delta:
            return []
        if data_type == "response.output_text.delta":
            # Answer text starting means the model is done thinking.
            touched = self._close_reasoning(agent_id)
            touched += self._record_assistant_message(agent_id, str(delta), final=False)
            return touched
        # The SDK normalises both Responses-API reasoning summaries and
        # third-party ``reasoning_content`` into these two event types.
        if data_type in {"response.reasoning_summary_text.delta", "response.reasoning_text.delta"}:
            return [self._record_reasoning(agent_id, str(delta))]
        return []

    def _record_reasoning(self, agent_id: str, delta: str) -> dict[str, Any]:
        existing = self._open_reasoning_event_by_agent.get(agent_id)
        if existing is None:
            event = self._append_event(
                agent_id,
                "chat",
                {
                    "role": "reasoning",
                    "content": delta,
                    "metadata": {"source": "sdk_stream", "streaming": True},
                },
            )
            self._open_reasoning_event_by_agent[agent_id] = event
            return event
        existing["data"]["content"] = f"{existing['data'].get('content', '')}{delta}"
        self._bump_event(existing)
        return existing

    def _close_reasoning(self, agent_id: str) -> list[dict[str, Any]]:
        event = self._open_reasoning_event_by_agent.pop(agent_id, None)
        if event is None:
            return []
        event["data"]["metadata"]["streaming"] = False
        self._bump_event(event)
        return [event]

    def _ingest_session_history_item(
        self,
        agent_id: str,
        item: dict[str, Any],
        *,
        timestamp: str,
    ) -> None:
        item_type = item.get("type")
        role = item.get("role")
        if role in {"user", "assistant"} and (item_type in {None, "message"}):
            content = _session_message_text(item)
            if content:
                # ponytail: truncate resumed message content. A long
                # scan can persist 100KB+ assistant messages (final
                # reports, deep-dive analyses). Rendering those with
                # Pygments creates thousands of spans per message;
                # across hundreds of resumed events that's the 300MB
                # memory blow-up and the multi-second first-heartbeat
                # freeze. The user scrolling back on resume sees the
                # start of each message; full content is in run.json /
                # the executive report.
                # Ceiling: messages over MAX_HYDRATED_MESSAGE_CHARS
                # show a truncation marker instead of the full body.
                # Upgrade: virtualize the chat view so only visible
                # events are rendered (no upfront full-text render).
                if len(content) > MAX_HYDRATED_MESSAGE_CHARS:
                    content = (
                        content[:MAX_HYDRATED_MESSAGE_CHARS]
                        + f"\n\n… ({len(content) - MAX_HYDRATED_MESSAGE_CHARS} more chars; "
                        "see run.json for full content)"
                    )
                self._append_event(
                    agent_id,
                    "chat",
                    {
                        "role": role,
                        "content": content,
                        "metadata": {"source": "sdk_session"},
                    },
                    timestamp=timestamp,
                )
            return

        if item_type == "function_call":
            self._record_tool_call_data(
                agent_id,
                {
                    "call_id": str(item.get("call_id") or item.get("id") or ""),
                    "tool_name": str(item.get("name") or "tool"),
                    "args": _parse_json_object(item.get("arguments")),
                },
                timestamp=timestamp,
            )
            return

        if item_type == "function_call_output":
            self._record_tool_output_data(
                agent_id,
                {
                    "call_id": str(item.get("call_id") or item.get("id") or ""),
                    "tool_name": "tool",
                    "output": item.get("output"),
                },
                timestamp=timestamp,
            )

    def _record_assistant_message(
        self, agent_id: str, content: str, *, final: bool
    ) -> list[dict[str, Any]]:
        if not content:
            return []
        existing = self._open_assistant_event_by_agent.get(agent_id)
        if existing is None:
            event = self._append_event(
                agent_id,
                "chat",
                {
                    "role": "assistant",
                    "content": content,
                    "metadata": {"source": "sdk_stream", "streaming": not final},
                },
            )
            if not final:
                self._open_assistant_event_by_agent[agent_id] = event
            return [event]

        data = existing["data"]
        if final:
            data["content"] = content
            data["metadata"]["streaming"] = False
            self._open_assistant_event_by_agent.pop(agent_id, None)
        else:
            data["content"] = f"{data.get('content', '')}{content}"
        self._bump_event(existing)
        return [existing]

    def _record_tool_call(self, agent_id: str, item: Any) -> dict[str, Any]:
        return self._record_tool_call_data(agent_id, _sdk_tool_call_data(item))

    def _record_tool_call_data(
        self,
        agent_id: str,
        call: dict[str, Any],
        *,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        call_id = call["call_id"]
        existing = self._tool_event_by_call_id.get(call_id)
        tool_data = {
            "tool_name": call["tool_name"],
            "args": call["args"],
            "status": "running",
            "agent_id": agent_id,
            "call_id": call_id,
        }
        if existing is None:
            event = self._append_event(agent_id, "tool", tool_data, timestamp=timestamp)
            self._tool_event_by_call_id[call_id] = event
            return event
        existing["data"].update(tool_data)
        self._bump_event(existing, timestamp=timestamp)
        return existing

    def _record_tool_output(self, agent_id: str, item: Any) -> dict[str, Any]:
        return self._record_tool_output_data(agent_id, _sdk_tool_output_data(item))

    def _record_tool_output_data(
        self,
        agent_id: str,
        output: dict[str, Any],
        *,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        call_id = output["call_id"]
        event = self._tool_event_by_call_id.get(call_id)
        if event is None:
            event = self._append_event(
                agent_id,
                "tool",
                {
                    "tool_name": output["tool_name"],
                    "args": {},
                    "status": "completed",
                    "agent_id": agent_id,
                    "call_id": call_id,
                },
                timestamp=timestamp,
            )
            self._tool_event_by_call_id[call_id] = event

        result = _parse_json_value(output["output"])
        event["data"]["result"] = result
        event["data"]["status"] = _tool_status_from_result(result)
        self._bump_event(event, timestamp=timestamp)
        return event

    def _append_event(
        self,
        agent_id: str,
        event_type: str,
        data: dict[str, Any],
        *,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        event = {
            "id": f"{event_type}_{self._next_event_id}",
            "type": event_type,
            "agent_id": agent_id,
            "timestamp": timestamp or datetime.now(UTC).isoformat(),
            "version": 0,
            "data": data,
        }
        self._next_event_id += 1
        self.events.append(event)

        # Maintain agent index for O(1) lookups
        if agent_id not in self._events_by_agent:
            self._events_by_agent[agent_id] = []
        self._events_by_agent[agent_id].append(event)

        return event

    @staticmethod
    def _bump_event(event: dict[str, Any], *, timestamp: str | None = None) -> None:
        event["version"] = int(event.get("version", 0)) + 1
        event["timestamp"] = timestamp or datetime.now(UTC).isoformat()

    def prune_old_events(self, max_events_per_agent: int = 1000) -> int:
        """Prune old events to prevent unbounded memory growth.

        Keeps the most recent max_events_per_agent events per agent.
        Returns the number of events pruned.
        """
        pruned_count = 0

        for agent_id, events_list in self._events_by_agent.items():
            if len(events_list) > max_events_per_agent:
                # Keep only the most recent events
                events_to_remove = events_list[:-max_events_per_agent]
                pruned_count += len(events_to_remove)

                # Remove from agent index
                self._events_by_agent[agent_id] = events_list[-max_events_per_agent:]

                # Remove from main events list
                events_to_remove_set = set(id(e) for e in events_to_remove)
                self.events = [e for e in self.events if id(e) not in events_to_remove_set]

        return pruned_count


def _sdk_tool_call_data(item: Any) -> dict[str, Any]:
    raw = getattr(item, "raw_item", None)
    call_id = str(_raw_field(raw, "call_id") or _raw_field(raw, "id") or id(item))
    tool_name = str(
        _raw_field(raw, "name") or _raw_field(raw, "type") or getattr(item, "title", None) or "tool"
    )
    return {
        "call_id": call_id,
        "tool_name": tool_name,
        "args": _parse_json_object(_raw_field(raw, "arguments")),
    }


def _sdk_tool_output_data(item: Any) -> dict[str, Any]:
    raw = getattr(item, "raw_item", None)
    call_id = str(_raw_field(raw, "call_id") or _raw_field(raw, "id") or id(item))
    return {
        "call_id": call_id,
        "tool_name": str(_raw_field(raw, "name") or _raw_field(raw, "type") or "tool"),
        "output": getattr(item, "output", _raw_field(raw, "output")),
    }


def _sdk_message_text(item: Any) -> str:
    raw = getattr(item, "raw_item", None)
    return _message_content_text(_raw_field(raw, "content", []))


def _session_message_text(item: dict[str, Any]) -> str:
    return _message_content_text(item.get("content", ""))


def _message_content_text(content: Any) -> str:
    parts: list[str] = []
    content_items = content if isinstance(content, list) else [content]
    for part in content_items:
        if isinstance(part, str):
            parts.append(part)
            continue
        text = _raw_field(part, "text")
        if isinstance(text, str):
            parts.append(text)
    return "".join(parts)


def _raw_field(raw: Any, key: str, default: Any = None) -> Any:
    if isinstance(raw, dict):
        return raw.get(key, default)
    return getattr(raw, key, default)


def _parse_json_object(value: Any) -> dict[str, Any]:
    parsed = _parse_json_value(value)
    return parsed if isinstance(parsed, dict) else {}


def _parse_json_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _tool_status_from_result(result: Any) -> str:
    if isinstance(result, dict) and result.get("success") is False:
        return "failed"
    return "completed"
