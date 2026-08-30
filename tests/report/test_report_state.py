"""Tests for ReportState (Phase 1.2 — vuln ID race condition fix).

Verifies:

- Vulnerability IDs are unique even under concurrent allocation.
- UUID-based IDs are stable across allocations and resumable.
- Pre-existing sequential IDs are still recognized on hydrate.
- The vulnerability record keeps the same shape it had before.
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path

import pytest

from kael.report.state import ReportState


class TestVulnIdAllocation:
    def test_id_format_is_uuid_based(self, report_state: ReportState) -> None:
        rid = report_state._allocate_vuln_id()
        assert rid.startswith("vuln-")
        assert len(rid) == len("vuln-") + 8
        int(rid.split("-")[1], 16)  # parses as hex

    def test_ids_are_unique_across_allocations(self, report_state: ReportState) -> None:
        ids = {report_state._allocate_vuln_id() for _ in range(50)}
        assert len(ids) == 50

    def test_concurrent_allocations_never_collide(self, report_state: ReportState) -> None:
        """Spawn 100 threads each allocating 50 IDs. Total = 5000 unique IDs."""
        results: list[str] = []
        results_lock = threading.Lock()

        def allocate_batch() -> None:
            batch = [report_state._allocate_vuln_id() for _ in range(50)]
            with results_lock:
                results.extend(batch)

        threads = [threading.Thread(target=allocate_batch) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 5000
        assert len(set(results)) == 5000, "concurrent allocations produced a collision"

    @pytest.mark.asyncio
    async def test_concurrent_async_allocations_never_collide(
        self, report_state: ReportState
    ) -> None:
        async def allocate_batch() -> list[str]:
            return [report_state._allocate_vuln_id() for _ in range(100)]

        batches = await asyncio.gather(*(allocate_batch() for _ in range(20)))
        flat = [rid for batch in batches for rid in batch]
        assert len(flat) == 2000
        assert len(set(flat)) == 2000


class TestAddVulnerabilityReport:
    def test_returns_string_id(self, report_state: ReportState) -> None:
        rid = report_state.add_vulnerability_report(
            title="SQLi on /login",
            severity="critical",
        )
        assert isinstance(rid, str)
        assert rid.startswith("vuln-")

    def test_record_persisted(self, report_state: ReportState) -> None:
        rid = report_state.add_vulnerability_report(
            title="SQLi on /login",
            severity="critical",
            description="SELECT injection",
        )
        assert len(report_state.vulnerability_reports) == 1
        rec = report_state.vulnerability_reports[0]
        assert rec["id"] == rid
        assert rec["title"] == "SQLi on /login"
        assert rec["severity"] == "critical"

    def test_sequential_adds_get_unique_ids(self, report_state: ReportState) -> None:
        ids = [
            report_state.add_vulnerability_report(
                title=f"vuln #{i}",
                severity="high",
            )
            for i in range(10)
        ]
        assert len(set(ids)) == 10


class TestHydrateFromRunDir:
    def test_hydrate_recognizes_legacy_sequential_ids(
        self, report_state: ReportState, tmp_run_dir: Path, workdir: Path
    ) -> None:
        """Legacy vuln-0001 IDs written by older Kael versions must not
        collide with the new allocator on resume."""
        (tmp_run_dir / "vulnerabilities.json").write_text(
            json.dumps(
                [
                    {
                        "id": "vuln-0001",
                        "title": "old finding",
                        "severity": "high",
                        "timestamp": "2024-01-01 00:00:00 UTC",
                    }
                ]
            ),
            encoding="utf-8",
        )
        report_state.hydrate_from_run_dir()
        assert "vuln-0001" in {r["id"] for r in report_state.vulnerability_reports}
        new_id = report_state._allocate_vuln_id()
        assert new_id != "vuln-0001"
