"""Per-run notes storage — mirrored to {state_dir}/notes.json.

Learnings (category="learnings") are additionally persisted to a
target-scoped cross-run memory file so agents can avoid repeating
dead ends across separate scans of the same target.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool


if TYPE_CHECKING:
    from kael.config.settings import MemorySettings


logger = logging.getLogger(__name__)


_notes_storage: dict[str, dict[str, Any]] = {}
_VALID_NOTE_CATEGORIES = [
    "general",
    "findings",
    "methodology",
    "questions",
    "plan",
    "wiki",
    "learnings",
]
_VALID_OUTCOMES = ["dead_end", "promising", "confirmed", "unknown"]
_LOCKED_OUTCOMES = {"dead_end", "confirmed"}
_notes_lock = threading.RLock()
_DEFAULT_CONTENT_PREVIEW_CHARS = 280

_notes_path: Path | None = None
_memory_path: Path | None = None  # cross-run learnings file
_memory_file_lock = threading.RLock()  # guards cross-run read-modify-write


def _memory_settings() -> MemorySettings:
    """Resolve memory bounds lazily so test isolation can reset them.

    ``load_settings`` is memoized at process level; tests that mutate
    ``KAEL_MEMORY_*`` env vars will get a fresh value on the next test
    only if the loader cache is invalidated. Importing the loader here
    (rather than at module top) also keeps this module's import surface
    minimal — it's only needed at persist/hydrate time.
    """
    from kael.config.loader import load_settings

    return load_settings().memory


def _prune_learnings(entries: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Drop expired entries and enforce the per-target cap.

    Expiry uses each entry's ``updated_at``; entries missing the field
    (older files) fall back to ``created_at``, then to *now* (treated
    as fresh, so existing data isn't penalized on first migration).

    Cap eviction is value-preserving: oldest ``dead_end`` and ``unknown``
    entries are dropped first, then oldest ``promising``, with
    ``confirmed`` always preserved.
    """
    cfg = _memory_settings()
    ttl_days = cfg.learning_ttl_days
    max_count = cfg.max_learnings_per_target

    now = datetime.now(UTC)
    survivors: dict[str, dict[str, Any]] = {}
    for nid, note in entries.items():
        if ttl_days > 0:
            ts_str = note.get("updated_at") or note.get("created_at")
            if isinstance(ts_str, str):
                try:
                    ts = datetime.fromisoformat(ts_str)
                except ValueError:
                    ts = now
            else:
                ts = now
            age = (now - ts).days
            if age > ttl_days:
                continue
        survivors[nid] = note

    if max_count <= 0 or len(survivors) <= max_count:
        return survivors

    # Over cap — evict lowest-priority entries first.
    priority = {"confirmed": 0, "promising": 1, "dead_end": 2, "unknown": 3}
    default_priority = 4
    ranked = sorted(
        survivors.items(),
        key=lambda item: (
            priority.get(str(item[1].get("outcome", "")), default_priority),
            str(item[1].get("updated_at") or item[1].get("created_at") or ""),
        ),
    )
    return dict(ranked[:max_count])


def hydrate_notes_from_disk(state_dir: Path) -> None:
    global _notes_path  # noqa: PLW0603
    _notes_path = state_dir / "notes.json"
    with _notes_lock:
        _notes_storage.clear()
        if not _notes_path.exists():
            return
        try:
            data = json.loads(_notes_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "notes.json at %s is unreadable; starting with empty notes",
                _notes_path,
            )
            return
        if not isinstance(data, dict):
            return
        _notes_storage.update(
            {
                nid: note
                for nid, note in data.items()
                if isinstance(nid, str) and isinstance(note, dict)
            }
        )
        logger.info(
            "notes hydrated from %s (%d note(s))",
            _notes_path,
            len(_notes_storage),
        )


def hydrate_learnings_from_memory(memory_dir: Path) -> None:
    """Load cross-run learnings into the shared notes store.

    Must be called AFTER hydrate_notes_from_disk so that current-run
    notes are not wiped. Learnings from memory are merged in; current-run
    notes with the same ID take precedence.
    """
    global _memory_path  # noqa: PLW0603
    memory_dir.mkdir(parents=True, exist_ok=True)
    _memory_path = memory_dir / "learnings.json"
    if not _memory_path.exists():
        logger.info("no cross-run learnings at %s", _memory_path)
        return
    try:
        data = json.loads(_memory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.exception("learnings.json at %s is unreadable; skipping", _memory_path)
        return
    if not isinstance(data, dict):
        return
    with _notes_lock:
        # Apply TTL and cap *before* merging so an over-cap, expired
        # cross-run file doesn't blow up per-run memory. Pruning the
        # pruned set preserves the on-disk file as-is — eviction is
        # only persisted on the next write.
        pruned = _prune_learnings({k: v for k, v in data.items() if isinstance(v, dict)})
        loaded = 0
        for nid, note in pruned.items():
            if isinstance(nid, str) and nid not in _notes_storage:
                _notes_storage[nid] = note
                loaded += 1
    logger.info(
        "cross-run learnings merged from %s (%d new, %d pruned)",
        _memory_path,
        loaded,
        len(data) - loaded,
    )


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    try:
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
        logger.exception("atomic write to %s failed", path)


def _persist() -> None:
    path = _notes_path
    if path is None:
        return
    with _notes_lock:
        _atomic_write(path, _notes_storage)


def _persist_learning(note_id: str, note: dict[str, Any]) -> None:
    """Append/update a single learning in the cross-run memory file.

    The read-modify-write of ``learnings.json`` is guarded by an
    in-process ``RLock`` so concurrent agent tasks in the same scan
    can't race and lose a write. Two separate Kael processes writing
    to the same target-slug memory are out of scope; the file is
    per-user, not shared.
    """
    path = _memory_path
    if path is None:
        return
    with _memory_file_lock:
        try:
            existing: dict[str, Any] = {}
            if path.exists():
                with contextlib.suppress(OSError, json.JSONDecodeError):
                    existing = json.loads(path.read_text(encoding="utf-8"))
            existing[note_id] = note
            # Prune expired entries and enforce the per-target cap.
            # Done inside the lock so a concurrent write can't race
            # with us and leave an over-cap file behind.
            pruned = _prune_learnings(existing)
            _atomic_write(path, pruned)
        except Exception:
            logger.exception("learning persist to %s failed", path)


def _filter_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search_query: str | None = None,
    outcome: str | None = None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for note_id, note in _notes_storage.items():
        if category and note.get("category") != category:
            continue
        if tags:
            note_tags = note.get("tags", [])
            if not any(tag in note_tags for tag in tags):
                continue
        if outcome and note.get("outcome") != outcome:
            continue
        if search_query:
            search_lower = search_query.lower()
            title_match = search_lower in note.get("title", "").lower()
            content_match = search_lower in note.get("content", "").lower()
            if not (title_match or content_match):
                continue
        entry = note.copy()
        entry["note_id"] = note_id
        filtered.append(entry)
    filtered.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return filtered


def _to_note_listing_entry(
    note: dict[str, Any],
    *,
    include_content: bool = False,
) -> dict[str, Any]:
    entry = {
        "note_id": note.get("note_id"),
        "title": note.get("title", ""),
        "category": note.get("category", "general"),
        "tags": note.get("tags", []),
        "created_at": note.get("created_at", ""),
        "updated_at": note.get("updated_at", ""),
    }
    if note.get("outcome"):
        entry["outcome"] = note["outcome"]
    content = str(note.get("content", ""))
    if include_content:
        entry["content"] = content
    elif content:
        if len(content) > _DEFAULT_CONTENT_PREVIEW_CHARS:
            entry["content_preview"] = f"{content[:_DEFAULT_CONTENT_PREVIEW_CHARS].rstrip()}..."
        else:
            entry["content_preview"] = content
    return entry


def _create_note_impl(
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
    outcome: str | None = None,
) -> dict[str, Any]:
    with _notes_lock:
        try:
            if not title or not title.strip():
                return {"success": False, "error": "Title cannot be empty", "note_id": None}
            if not content or not content.strip():
                return {"success": False, "error": "Content cannot be empty", "note_id": None}
            if category not in _VALID_NOTE_CATEGORIES:
                return {
                    "success": False,
                    "error": (
                        f"Invalid category. Must be one of: {', '.join(_VALID_NOTE_CATEGORIES)}"
                    ),
                    "note_id": None,
                }
            if outcome is not None and outcome not in _VALID_OUTCOMES:
                return {
                    "success": False,
                    "error": f"Invalid outcome. Must be one of: {', '.join(_VALID_OUTCOMES)}",
                    "note_id": None,
                }

            note_id = str(uuid.uuid4())[:12]
            timestamp = datetime.now(UTC).isoformat()
            note: dict[str, Any] = {
                "title": title.strip(),
                "content": content.strip(),
                "category": category,
                "tags": tags or [],
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            if outcome is not None:
                note["outcome"] = outcome
            _notes_storage[note_id] = note
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to create note: {e}", "note_id": None}
        else:
            _persist()
            if category == "learnings":
                _persist_learning(note_id, note)
            return {
                "success": True,
                "note_id": note_id,
                "message": f"Note '{title}' created successfully",
                "total_count": len(_notes_storage),
            }


def _list_notes_impl(
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    include_content: bool = False,
    outcome: str | None = None,
) -> dict[str, Any]:
    with _notes_lock:
        try:
            filtered = _filter_notes(
                category=category, tags=tags, search_query=search, outcome=outcome
            )
            notes = [_to_note_listing_entry(n, include_content=include_content) for n in filtered]
        except (ValueError, TypeError) as e:
            return {
                "success": False,
                "error": f"Failed to list notes: {e}",
                "notes": [],
                "filtered_count": 0,
                "total_count": 0,
            }
        return {
            "success": True,
            "notes": notes,
            "filtered_count": len(notes),
            "total_count": len(_notes_storage),
        }


def _get_note_impl(note_id: str) -> dict[str, Any]:
    with _notes_lock:
        try:
            if not note_id or not note_id.strip():
                return {"success": False, "error": "Note ID cannot be empty", "note": None}
            note = _notes_storage.get(note_id)
            if note is None:
                return {
                    "success": False,
                    "error": f"Note with ID '{note_id}' not found",
                    "note": None,
                }
            note_with_id = note.copy()
            note_with_id["note_id"] = note_id
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to get note: {e}", "note": None}
        else:
            return {"success": True, "note": note_with_id}


def _update_note_impl(
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
    outcome: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    with _notes_lock:
        try:
            if note_id not in _notes_storage:
                return {"success": False, "error": f"Note with ID '{note_id}' not found"}
            note = _notes_storage[note_id]
            # Guard: locked outcomes require explicit force=True
            current_outcome = note.get("outcome")
            if current_outcome in _LOCKED_OUTCOMES and not force:
                return {
                    "success": False,
                    "error": (
                        f"This learning has outcome='{current_outcome}' which is locked. "
                        "Pass force=True only if you are certain the outcome has changed."
                    ),
                }
            if title is not None:
                if not title.strip():
                    return {"success": False, "error": "Title cannot be empty"}
                note["title"] = title.strip()
            if content is not None:
                if not content.strip():
                    return {"success": False, "error": "Content cannot be empty"}
                note["content"] = content.strip()
            if tags is not None:
                note["tags"] = tags
            if outcome is not None:
                if outcome not in _VALID_OUTCOMES:
                    return {
                        "success": False,
                        "error": (f"Invalid outcome. Must be one of: {', '.join(_VALID_OUTCOMES)}"),
                    }
                note["outcome"] = outcome
            note["updated_at"] = datetime.now(UTC).isoformat()
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to update note: {e}"}
        else:
            _persist()
            if note.get("category") == "learnings":
                _persist_learning(note_id, note)
            return {
                "success": True,
                "note_id": note_id,
                "message": f"Note '{note['title']}' updated successfully",
                "total_count": len(_notes_storage),
            }


def _delete_note_impl(note_id: str) -> dict[str, Any]:
    with _notes_lock:
        try:
            if note_id not in _notes_storage:
                return {"success": False, "error": f"Note with ID '{note_id}' not found"}
            note = _notes_storage[note_id]
            note_title = note["title"]
            del _notes_storage[note_id]
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to delete note: {e}"}
        else:
            _persist()
            return {
                "success": True,
                "note_id": note_id,
                "message": f"Note '{note_title}' deleted successfully",
                "total_count": len(_notes_storage),
            }


@function_tool(timeout=30)
async def create_note(
    ctx: RunContextWrapper,
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> str:
    """Document an observation, finding, methodology step, or research note.

    Notes are visible to every agent in the same scan for the lifetime
    of the run; they live in-memory only and are cleared when the
    process exits.

    For actionable tasks, use ``todo`` instead — notes are for capturing
    information, todos are for tracking work.

    Categories:

    - ``general`` — default, anything that doesn't fit elsewhere.
    - ``findings`` — confirmed vulnerabilities or weaknesses (write
      these up promptly; you'll cite them when filing reports).
    - ``methodology`` — what you tried, what worked, what didn't —
      useful for the final scan report.
    - ``questions`` — open questions / things to come back to.
    - ``plan`` — multi-step plans you want to track.
    - ``wiki`` — long-form repository or target maps.

    Tags are free-form (e.g. ``["sqli", "auth", "critical"]``) — useful
    for later ``list_notes(tags=...)`` filtering.

    Args:
        title: Short headline.
        content: Full note body. Markdown is preserved.
        category: One of the categories above. Default ``"general"``.
        tags: Optional free-form tags.
    """
    return json.dumps(
        await asyncio.to_thread(_create_note_impl, title, content, category, tags),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_notes(
    ctx: RunContextWrapper,
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    include_content: bool = False,
    outcome: str | None = None,
) -> str:
    """List existing notes — metadata-first by default.

    Filters compose: passing ``category="findings"`` and
    ``tags=["sqli"]`` returns notes that are *both* in the findings
    category AND have at least one of those tags.

    By default each entry includes a ``content_preview`` (first 280
    chars). Set ``include_content=True`` to get full bodies — useful
    when you need to scan many notes; expensive in tokens for large
    notes.

    To check memory before attempting a technique:
    ``list_notes(category="learnings", search="<technique>")``
    A ``"dead_end"`` outcome means skip it — it's already been tried.

    Args:
        category: Filter by category.
        tags: Filter to notes that have any of these tags.
        search: Substring match against title and content.
        include_content: When False (default) entries have a preview;
            when True the full ``content`` is included.
        outcome: Filter learnings by outcome — one of ``"dead_end"``,
            ``"promising"``, ``"confirmed"``, ``"unknown"``.
    """
    return json.dumps(
        await asyncio.to_thread(
            _list_notes_impl,
            category=category,
            tags=tags,
            search=search,
            include_content=include_content,
            outcome=outcome,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def get_note(ctx: RunContextWrapper, note_id: str) -> str:
    """Fetch one note by its 12-char ID. Returns the full content.

    Args:
        note_id: Note id from ``create_note`` or a ``list_notes`` entry.
    """
    return json.dumps(
        await asyncio.to_thread(_get_note_impl, note_id), ensure_ascii=False, default=str
    )


@function_tool(timeout=30)
async def update_note(
    ctx: RunContextWrapper,
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
    outcome: str | None = None,
    force: bool = False,
) -> str:
    """Update a note's title, content, tags, or outcome.

    Pass ``None`` for any field you want left unchanged. Replacing
    ``content`` is a full overwrite — to append, fetch first with
    ``get_note``, concat, and pass the result.

    Notes with ``outcome`` of ``"dead_end"`` or ``"confirmed"`` are
    locked — you must pass ``force=True`` to change them. These outcomes
    carry weight: ``"dead_end"`` causes future agents to skip the
    technique, and ``"confirmed"`` flags a real finding. Be certain
    before overriding.

    Args:
        note_id: Target note's 12-char ID.
        title: New title, or ``None`` to keep.
        content: New content, or ``None`` to keep.
        tags: New tags list, or ``None`` to keep.
        outcome: New outcome value, or ``None`` to keep. One of
            ``"dead_end"``, ``"promising"``, ``"confirmed"``, ``"unknown"``.
        force: Required ``True`` to modify a note with outcome
            ``"dead_end"`` or ``"confirmed"``.
    """
    return json.dumps(
        await asyncio.to_thread(
            _update_note_impl,
            note_id=note_id,
            title=title,
            content=content,
            tags=tags,
            outcome=outcome,
            force=force,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def add_learning(
    ctx: RunContextWrapper,
    technique: str,
    context: str,
    outcome: str,
    tags: list[str] | None = None,
) -> str:
    """Record what you tried and what happened — shared memory across runs.

    This is the primary way to add to the agent memory system. Call it
    after any non-trivial attempt so future agents (in this run AND
    future scans against the same target) don't repeat wasted work.

    Before attempting a technique, search for it first:
    ``list_notes(category="learnings", search="<technique>")`` — a
    ``"dead_end"`` outcome means skip it.

    Outcome values:
    - ``"dead_end"`` — tried, definitively doesn't work. Future agents
      skip this. Be certain before using — it blocks future attempts.
    - ``"promising"`` — partial signal, needs more investigation.
    - ``"confirmed"`` — works / vulnerability confirmed. Also locked.
    - ``"unknown"``  — inconclusive result.

    Learnings are visible to all agents in this run and are persisted
    to ``~/.kael/memory/<target-slug>/learnings.json`` so they survive
    across separate scans of the same target.

    Args:
        technique: Short slug for what was attempted, e.g.
            ``"jwt_none_alg"``, ``"sqli_login_form"``.
        context: What exactly was tried and what happened.
        outcome: One of the four outcome values above.
        tags: Optional tags, e.g. ``["jwt", "auth", "login"]``.
    """
    return json.dumps(
        await asyncio.to_thread(
            _create_note_impl,
            title=technique,
            content=context,
            category="learnings",
            tags=tags,
            outcome=outcome,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def delete_note(ctx: RunContextWrapper, note_id: str) -> str:
    """Delete a note.

    Args:
        note_id: Note id to delete.
    """
    return json.dumps(
        await asyncio.to_thread(_delete_note_impl, note_id), ensure_ascii=False, default=str
    )
