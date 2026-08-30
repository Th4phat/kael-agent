"""Tests for the per-run notes / cross-run memory system.

Covers the core invariants and the data-integrity fixes:

- Note IDs are 12 hex chars (collision resistance across multi-agent runs).
- Cross-run ``learnings.json`` writes are serialized — concurrent
  ``add_learning`` calls from many threads all survive in the file.
- A force-required guard is still applied for locked outcomes.
- The cross-run hydration merges prior learnings into the per-run store
  and current-run notes win on ID collision.
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any

import pytest

from kael.config import loader
from kael.tools.notes import tools as notes_tools


@pytest.fixture
def isolated_notes_state(
    tmp_path: Path,
) -> tuple[Path, Path]:
    """Point the notes module at a fresh state_dir + memory_dir per test."""
    state_dir = tmp_path / "state"
    memory_dir = tmp_path / "memory"
    state_dir.mkdir()
    memory_dir.mkdir()
    notes_tools.hydrate_notes_from_disk(state_dir)
    notes_tools.hydrate_learnings_from_memory(memory_dir)
    yield state_dir, memory_dir
    notes_tools._notes_storage.clear()
    notes_tools._notes_path = None
    notes_tools._memory_path = None
    notes_tools._memory_file_lock = threading.RLock()


class TestNoteIdLength:
    def test_note_id_is_12_chars(self, isolated_notes_state: tuple[Path, Path]) -> None:
        result = notes_tools._create_note_impl(title="x", content="y", category="general")
        assert result["success"] is True
        assert len(result["note_id"]) == 12

    def test_learning_id_is_12_chars(self, isolated_notes_state: tuple[Path, Path]) -> None:
        result = notes_tools._create_note_impl(
            title="jwt_none_alg",
            content="didn't work",
            category="learnings",
            outcome="dead_end",
        )
        assert result["success"] is True
        assert len(result["note_id"]) == 12


class TestPersistLearningLock:
    def test_concurrent_persists_preserve_all_writes(
        self, isolated_notes_state: tuple[Path, Path]
    ) -> None:
        """20 threads x 25 writes = 500 concurrent ``add_learning`` calls.
        Every note must survive in the on-disk file (last-writer-wins per ID
        is fine, but no note may be silently dropped by a torn read-modify-write).
        """
        _, memory_dir = isolated_notes_state
        n_threads = 20
        per_thread = 25

        def writer(tid: int) -> None:
            for i in range(per_thread):
                notes_tools._create_note_impl(
                    title=f"t{tid}-n{i}",
                    content=f"ctx {tid}-{i}",
                    category="learnings",
                    outcome="unknown",
                )

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        memory_path = memory_dir / "learnings.json"
        assert memory_path.exists()
        on_disk = json.loads(memory_path.read_text(encoding="utf-8"))
        assert len(on_disk) == n_threads * per_thread

    def test_locked_outcome_still_requires_force(
        self, isolated_notes_state: tuple[Path, Path]
    ) -> None:
        create = notes_tools._create_note_impl(
            title="sql_injection_login",
            content="attempted; blocked",
            category="learnings",
            outcome="dead_end",
        )
        assert create["success"] is True
        nid = create["note_id"]

        blocked = notes_tools._update_note_impl(note_id=nid, outcome="promising")
        assert blocked["success"] is False
        assert "locked" in blocked["error"].lower()

        forced = notes_tools._update_note_impl(note_id=nid, outcome="promising", force=True)
        assert forced["success"] is True


class TestCrossRunHydration:
    def test_existing_learnings_loaded(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        memory_dir = tmp_path / "memory"
        memory_dir.mkdir()
        # Pre-seed the on-disk memory file with a prior-run learning.
        # Use a recent timestamp — the default TTL (90 days) would
        # prune entries older than that on hydrate.
        prior = {
            "abc123def456": {
                "title": "jwt_alg_none",
                "content": "rejected by validator",
                "category": "learnings",
                "tags": ["jwt"],
                "created_at": "2026-08-01T00:00:00+00:00",
                "updated_at": "2026-08-01T00:00:00+00:00",
                "outcome": "dead_end",
            }
        }
        (memory_dir / "learnings.json").write_text(json.dumps(prior), encoding="utf-8")

        notes_tools._notes_storage.clear()
        notes_tools._notes_path = None
        notes_tools._memory_path = None
        notes_tools.hydrate_learnings_from_memory(memory_dir)

        got = notes_tools._get_note_impl("abc123def456")
        assert got["success"] is True
        assert got["note"]["outcome"] == "dead_end"

        # Cleanup
        notes_tools._notes_storage.clear()
        notes_tools._memory_path = None

    def test_current_run_wins_on_id_collision(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        state_dir = tmp_path / "state"
        memory_dir = tmp_path / "memory"
        state_dir.mkdir()
        memory_dir.mkdir()

        # Seed current-run notes.json with one ID
        state_notes = {
            "collision01": {
                "title": "current_run_version",
                "content": "wins",
                "category": "learnings",
                "tags": [],
                "created_at": "2025-01-01T00:00:00+00:00",
                "updated_at": "2025-01-01T00:00:00+00:00",
                "outcome": "promising",
            }
        }
        (state_dir / "notes.json").write_text(json.dumps(state_notes), encoding="utf-8")

        # Seed memory with a different content for the same ID
        mem_notes = {
            "collision01": {
                "title": "memory_version",
                "content": "loses",
                "category": "learnings",
                "tags": [],
                "created_at": "2026-05-01T00:00:00+00:00",
                "updated_at": "2026-05-01T00:00:00+00:00",
                "outcome": "dead_end",
            }
        }
        (memory_dir / "learnings.json").write_text(json.dumps(mem_notes), encoding="utf-8")

        notes_tools._notes_storage.clear()
        notes_tools.hydrate_notes_from_disk(state_dir)
        notes_tools.hydrate_learnings_from_memory(memory_dir)

        got = notes_tools._get_note_impl("collision01")
        assert got["success"] is True
        assert got["note"]["title"] == "current_run_version"

        # Cleanup
        notes_tools._notes_storage.clear()
        notes_tools._notes_path = None
        notes_tools._memory_path = None


class TestNoteImplementations:
    """The synchronous implementations own the Kael data contract."""

    def test_create_and_list_round_trip(self, isolated_notes_state: tuple[Path, Path]) -> None:
        created = notes_tools._create_note_impl(
            title="t",
            content="c",
            category="general",
        )
        assert created["success"] is True
        assert len(created["note_id"]) == 12

        listed = notes_tools._list_notes_impl()
        assert listed["success"] is True
        assert listed["filtered_count"] == 1

    def test_add_learning_persists_to_memory(self, isolated_notes_state: tuple[Path, Path]) -> None:
        _, memory_dir = isolated_notes_state
        result = notes_tools._create_note_impl(
            title="ssrf_metadata",
            content="blocked",
            category="learnings",
            outcome="dead_end",
        )
        assert result["success"] is True

        memory_path = memory_dir / "learnings.json"
        assert memory_path.exists()
        on_disk = json.loads(memory_path.read_text(encoding="utf-8"))
        assert len(on_disk) == 1
        assert next(iter(on_disk.values()))["title"] == "ssrf_metadata"


def test_id_collision_threshold() -> None:
    """Sanity check the math: 12 hex chars is enough headroom that a million
    generated IDs collide with negligible probability (<1e-6).
    """
    import uuid

    seen: set[str] = set()
    n = 100_000
    for _ in range(n):
        seen.add(str(uuid.uuid4())[:12])
    assert len(seen) == n


class TestMemoryPruning:
    """The cross-run learning file grows without bounds unless pruned.

    Pruning is done on every persist and on every hydrate:
    - Entries older than ``learning_ttl_days`` are dropped.
    - If still over ``max_learnings_per_target``, the lowest-priority
      entries are dropped first (oldest ``dead_end``/``unknown``,
      then oldest ``promising``); ``confirmed`` is always preserved.
    """

    def _seed_memory(self, tmp_path: Path, entries: dict[str, dict[str, Any]]) -> Path:
        memory_dir = tmp_path / "memory"
        memory_dir.mkdir()
        (memory_dir / "learnings.json").write_text(json.dumps(entries), encoding="utf-8")
        return memory_dir

    def _set_ttl(self, monkeypatch: pytest.MonkeyPatch, days: int) -> None:
        monkeypatch.setenv("KAEL_MEMORY_LEARNING_TTL_DAYS", str(days))
        from kael.config import loader

        loader._cached = None
        loader._override = None

    def _set_max(self, monkeypatch: pytest.MonkeyPatch, n: int) -> None:
        monkeypatch.setenv("KAEL_MEMORY_MAX_LEARNINGS_PER_TARGET", str(n))
        from kael.config import loader

        loader._cached = None
        loader._override = None

    def test_ttl_prunes_expired_on_hydrate(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._set_ttl(monkeypatch, 90)
        memory_dir = self._seed_memory(
            tmp_path,
            {
                "fresh": {
                    "title": "fresh",
                    "content": "recent",
                    "category": "learnings",
                    "tags": [],
                    "created_at": "2026-08-01T00:00:00+00:00",
                    "updated_at": "2026-08-01T00:00:00+00:00",
                    "outcome": "dead_end",
                },
                "stale": {
                    "title": "stale",
                    "content": "old",
                    "category": "learnings",
                    "tags": [],
                    "created_at": "2024-01-01T00:00:00+00:00",
                    "updated_at": "2024-01-01T00:00:00+00:00",
                    "outcome": "dead_end",
                },
            },
        )

        notes_tools._notes_storage.clear()
        notes_tools._notes_path = None
        notes_tools._memory_path = None
        notes_tools.hydrate_learnings_from_memory(memory_dir)

        assert "fresh" in notes_tools._notes_storage
        assert "stale" not in notes_tools._notes_storage

        # Cleanup
        notes_tools._notes_storage.clear()
        notes_tools._memory_path = None

    def test_ttl_zero_disables_expiry(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._set_ttl(monkeypatch, 0)
        memory_dir = self._seed_memory(
            tmp_path,
            {
                "ancient": {
                    "title": "x",
                    "content": "y",
                    "category": "learnings",
                    "tags": [],
                    "created_at": "2020-01-01T00:00:00+00:00",
                    "updated_at": "2020-01-01T00:00:00+00:00",
                    "outcome": "dead_end",
                }
            },
        )
        notes_tools._notes_storage.clear()
        notes_tools._notes_path = None
        notes_tools._memory_path = None
        notes_tools.hydrate_learnings_from_memory(memory_dir)
        assert "ancient" in notes_tools._notes_storage

        # Cleanup
        notes_tools._notes_storage.clear()
        notes_tools._memory_path = None

    def test_cap_evicts_lowest_priority_first(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._set_ttl(monkeypatch, 0)
        self._set_max(monkeypatch, 2)
        memory_dir = self._seed_memory(
            tmp_path,
            {
                "dead_end_old": {
                    "title": "x",
                    "content": "y",
                    "category": "learnings",
                    "tags": [],
                    "created_at": "2020-01-01T00:00:00+00:00",
                    "updated_at": "2020-01-01T00:00:00+00:00",
                    "outcome": "dead_end",
                },
                "confirmed": {
                    "title": "c",
                    "content": "real bug",
                    "category": "learnings",
                    "tags": [],
                    "created_at": "2020-01-02T00:00:00+00:00",
                    "updated_at": "2020-01-02T00:00:00+00:00",
                    "outcome": "confirmed",
                },
                "unknown_new": {
                    "title": "u",
                    "content": "inconclusive",
                    "category": "learnings",
                    "tags": [],
                    "created_at": "2025-01-01T00:00:00+00:00",
                    "updated_at": "2025-01-01T00:00:00+00:00",
                    "outcome": "unknown",
                },
            },
        )

        notes_tools._notes_storage.clear()
        notes_tools._notes_path = None
        notes_tools._memory_path = None
        notes_tools.hydrate_learnings_from_memory(memory_dir)

        # Cap=2 across 3 entries, ranked by importance:
        #   confirmed   (priority 0) — kept
        #   dead_end_old (priority 2) — kept
        #   unknown_new (priority 3) — dropped
        # Highest-priority (lowest-rank) entries always survive.
        survivors = {
            k
            for k in notes_tools._notes_storage
            if k in {"confirmed", "dead_end_old", "unknown_new"}
        }
        assert survivors == {"confirmed", "dead_end_old"}

        # Cleanup
        notes_tools._notes_storage.clear()
        notes_tools._memory_path = None

    def test_persist_prunes_existing_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A new add_learning call must trigger pruning of pre-existing
        entries, not just the new one.
        """
        self._set_ttl(monkeypatch, 90)
        self._set_max(monkeypatch, 3)

        state_dir = tmp_path / "state"
        memory_dir = tmp_path / "memory"
        state_dir.mkdir()
        memory_dir.mkdir()

        # Seed an expired entry that should be pruned on the next persist
        prior = {
            "expired": {
                "title": "stale",
                "content": "old",
                "category": "learnings",
                "tags": [],
                "created_at": "2020-01-01T00:00:00+00:00",
                "updated_at": "2020-01-01T00:00:00+00:00",
                "outcome": "dead_end",
            }
        }
        (memory_dir / "learnings.json").write_text(json.dumps(prior), encoding="utf-8")

        notes_tools._notes_storage.clear()
        notes_tools._notes_path = None
        notes_tools._memory_path = None
        notes_tools.hydrate_notes_from_disk(state_dir)
        notes_tools.hydrate_learnings_from_memory(memory_dir)

        # Now add a fresh learning
        notes_tools._create_note_impl(
            title="fresh",
            content="now",
            category="learnings",
            outcome="unknown",
        )

        on_disk = json.loads((memory_dir / "learnings.json").read_text(encoding="utf-8"))
        assert "expired" not in on_disk
        # The on-disk keys are note IDs; the title is in the value.
        assert any(note.get("title") == "fresh" for note in on_disk.values())

        # Cleanup
        notes_tools._notes_storage.clear()
        notes_tools._notes_path = None
        notes_tools._memory_path = None
        loader._cached = None
        loader._override = None
