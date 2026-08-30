"""Tests for the TUI session-resume hydration path.

Resume loads SDK session history from ``agents.db`` into the live view
for display. Two caps prevent the 300MB memory blow-up and multi-second
first-heartbeat freeze on long sessions:

- ``load_session_history`` limits to the most recent
  ``MAX_HYDRATED_EVENTS_PER_AGENT`` rows per agent (SQL window).
- ``_ingest_session_history_item`` truncates message content over
  ``MAX_HYDRATED_MESSAGE_CHARS`` so a single 250KB final report
  doesn't create thousands of Pygments spans on render.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from kael.core.paths import runtime_state_dir
from kael.interface.tui.history import (
    MAX_HYDRATED_EVENTS_PER_AGENT,
    load_session_history,
)
from kael.interface.tui.live_view import MAX_HYDRATED_MESSAGE_CHARS, TuiLiveView


pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnraisableExceptionWarning",
    "ignore::ResourceWarning",
)


def _make_agents_db(run_dir: Path, rows: list[tuple[str, dict[str, Any]]]) -> Path:
    """Create a minimal agents.db with the given (session_id, item) rows."""
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    db = state_dir / "agents.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            "create table agent_messages "
            "(id integer primary key autoincrement, session_id text, "
            "message_data text, created_at text)"
        )
        for i, (sid, item) in enumerate(rows):
            conn.execute(
                "insert into agent_messages (session_id, message_data, created_at) "
                "values (?, ?, ?)",
                (sid, json.dumps(item), f"2026-01-01 00:00:{i:02d}"),
            )
    return db


class TestLoadSessionHistoryCap:
    def test_caps_to_most_recent_per_agent(self, tmp_path: Path) -> None:
        rows = [
            (f"agent_{i % 2}", {"type": "message", "role": "user", "content": f"m{i}"})
            for i in range(MAX_HYDRATED_EVENTS_PER_AGENT * 4)
        ]
        _make_agents_db(tmp_path, rows)

        result = load_session_history(tmp_path, ["agent_0", "agent_1"])

        per_agent: dict[str, int] = {}
        for agent_id, _item, _ts in result:
            per_agent[agent_id] = per_agent.get(agent_id, 0) + 1
        assert per_agent == {
            "agent_0": MAX_HYDRATED_EVENTS_PER_AGENT,
            "agent_1": MAX_HYDRATED_EVENTS_PER_AGENT,
        }, f"each agent must be capped to {MAX_HYDRATED_EVENTS_PER_AGENT} events; got {per_agent}"

    def test_returns_chronological_order(self, tmp_path: Path) -> None:
        rows = [
            ("a1", {"type": "message", "role": "user", "content": "first"}),
            ("a1", {"type": "message", "role": "user", "content": "second"}),
            ("a1", {"type": "message", "role": "user", "content": "third"}),
        ]
        _make_agents_db(tmp_path, rows)

        result = load_session_history(tmp_path, ["a1"])

        contents = [item["content"] for _aid, item, _ts in result]
        assert contents == ["first", "second", "third"], (
            "capped rows must still be returned in chronological (id) order"
        )

    def test_filters_session_id_in_sql(self, tmp_path: Path) -> None:
        rows = [
            ("a1", {"type": "message", "role": "user", "content": "x"}),
            ("a2", {"type": "message", "role": "user", "content": "y"}),
        ]
        _make_agents_db(tmp_path, rows)

        result = load_session_history(tmp_path, ["a1"])

        assert all(aid == "a1" for aid, _i, _t in result), (
            "only requested agent_ids must be returned (SQL-level filter)"
        )

    def test_empty_when_no_db(self, tmp_path: Path) -> None:
        assert load_session_history(tmp_path, ["a1"]) == []


class TestMessageContentTruncation:
    @staticmethod
    def _live_view() -> TuiLiveView:
        lv = TuiLiveView()
        lv.upsert_agent("a1", name="A1")
        return lv

    def test_short_message_preserved(self) -> None:
        lv = self._live_view()
        lv._ingest_session_history_item(
            "a1",
            {"type": "message", "role": "assistant", "content": "short body"},
            timestamp="2026-01-01T00:00:00Z",
        )
        events = lv.events_for_agent("a1")
        assert len(events) == 1
        assert events[0]["data"]["content"] == "short body"

    def test_long_message_truncated_with_marker(self) -> None:
        lv = self._live_view()
        big = "x" * (MAX_HYDRATED_MESSAGE_CHARS + 50_000)
        lv._ingest_session_history_item(
            "a1",
            {"type": "message", "role": "assistant", "content": big},
            timestamp="2026-01-01T00:00:00Z",
        )
        events = lv.events_for_agent("a1")
        content = events[0]["data"]["content"]
        assert len(content) < len(big), "long message must be truncated"
        assert "more chars" in content, "truncation marker must be present"
        assert "run.json" in content, "marker must point to full content source"
        assert content.startswith("x" * MAX_HYDRATED_MESSAGE_CHARS)

    def test_user_message_also_truncated(self) -> None:
        lv = self._live_view()
        big = "y" * (MAX_HYDRATED_MESSAGE_CHARS + 1000)
        lv._ingest_session_history_item(
            "a1",
            {"type": "message", "role": "user", "content": big},
            timestamp="2026-01-01T00:00:00Z",
        )
        events = lv.events_for_agent("a1")
        assert "more chars" in events[0]["data"]["content"]
