"""Historical SDK session loading for the TUI."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from kael.core.paths import runtime_state_dir


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

# ponytail: cap resumed history. A long scan can write thousands of rows
# to agents.db (one per SDK message + tool call + output). Loading and
# rendering all of them on resume blows memory (~300MB for a 6h session)
# and freezes the UI for seconds on the first heartbeat. The user
# scrolling up on resume wants recent context, not the whole transcript.
# Ceiling: history older than MAX_HYDRATED_EVENTS_PER_AGENT is invisible
# in the TUI chat view on resume. Upgrade: lazy/on-demand hydration —
# load older events when the user scrolls near the top.
MAX_HYDRATED_EVENTS_PER_AGENT = 200


def load_session_history(
    run_dir: Path,
    agent_ids: Any,
    *,
    max_events_per_agent: int = MAX_HYDRATED_EVENTS_PER_AGENT,
) -> list[tuple[str, dict[str, Any], str]]:
    agents_db = runtime_state_dir(run_dir) / "agents.db"
    session_ids = [aid for aid in agent_ids if isinstance(aid, str)]
    if not agents_db.exists() or not session_ids:
        return []
    try:
        with sqlite3.connect(agents_db) as conn:
            # ponytail: filter session_id in SQL (was: fetch all rows,
            # filter in Python — O(all_rows) memory even for one agent).
            # Keep the most recent max_events_per_agent per agent via a
            # row_number() window partitioned by session_id ordered by
            # id descending. Cheaper than N separate LIMIT queries when
            # there are many agents.
            placeholders = ",".join("?" for _ in session_ids)
            query = (
                "select id, session_id, message_data, created_at "
                "from ("
                "  select id, session_id, message_data, created_at, "
                "    row_number() over ("
                "      partition by session_id order by id desc"
                "    ) as rn "
                "  from agent_messages "
                "  where session_id in (" + placeholders + ")"
                ") where rn <= ? order by id"
            )
            rows = conn.execute(query, (*session_ids, max_events_per_agent)).fetchall()
    except sqlite3.Error:
        logger.exception("Failed to hydrate TUI history from %s", agents_db)
        return []

    items: list[tuple[str, dict[str, Any], str]] = []
    for row_id, agent_id, message_data, created_at in rows:
        try:
            item = json.loads(message_data)
        except (TypeError, json.JSONDecodeError):
            logger.debug("Skipping unreadable SDK session item %s for %s", row_id, agent_id)
            continue
        if isinstance(item, dict):
            items.append((str(agent_id), item, _sqlite_timestamp_to_iso(created_at)))
    return items


def _sqlite_timestamp_to_iso(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return datetime.now(UTC).isoformat()
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat()
