"""Tests for the report writer (Phase 4.3 — atomic executive report writes)."""

from __future__ import annotations

from pathlib import Path

from kael.report.writer import (
    _atomic_write_text,
    read_run_record,
    write_executive_report,
    write_run_record,
    write_vulnerabilities,
)


class TestAtomicWrite:
    def test_atomic_write_creates_file(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        _atomic_write_text(target, "hello")
        assert target.read_text(encoding="utf-8") == "hello"

    def test_atomic_write_overwrites(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        _atomic_write_text(target, "first")
        _atomic_write_text(target, "second")
        assert target.read_text(encoding="utf-8") == "second"

    def test_atomic_write_creates_parent(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "deep" / "out.txt"
        _atomic_write_text(target, "x")
        assert target.read_text(encoding="utf-8") == "x"

    def test_atomic_write_no_partial_files(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        _atomic_write_text(target, "x")
        leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".out.txt.")]
        assert leftovers == [], f"atomic write left partial files: {leftovers}"


class TestExecutiveReport:
    def test_executive_report_written_atomically(self, tmp_path: Path) -> None:
        write_executive_report(tmp_path, "# Summary\n\nFound things.")
        report = tmp_path / "penetration_test_report.md"
        assert report.exists()
        body = report.read_text(encoding="utf-8")
        assert "Security Penetration Test Report" in body
        assert "Found things." in body
        assert "Generated" in body

    def test_executive_report_overwrite_atomic(self, tmp_path: Path) -> None:
        write_executive_report(tmp_path, "first")
        write_executive_report(tmp_path, "second")
        assert (tmp_path / "penetration_test_report.md").exists()
        assert "second" in (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
        # No leftover .tmp files
        assert [p for p in tmp_path.iterdir() if p.name.startswith(".penetration")] == []


class TestRunRecordIO:
    def test_write_and_read_run_record(self, tmp_path: Path) -> None:
        record = {"run_id": "abc", "status": "running", "start_time": "2025-01-01T00:00:00Z"}
        write_run_record(tmp_path, record)
        loaded = read_run_record(tmp_path)
        assert loaded == record

    def test_read_run_record_missing_returns_empty(self, tmp_path: Path) -> None:
        assert read_run_record(tmp_path) == {}


class TestVulnerabilityCSV:
    def test_csv_uses_severity_then_timestamp_sort(self, tmp_path: Path) -> None:
        reports = [
            {
                "id": "vuln-aaaa0001",
                "title": "old high",
                "severity": "high",
                "timestamp": "2024-01-01 00:00:00 UTC",
            },
            {
                "id": "vuln-bbbb0002",
                "title": "newer critical",
                "severity": "critical",
                "timestamp": "2024-06-01 00:00:00 UTC",
            },
            {
                "id": "vuln-cccc0003",
                "title": "older critical",
                "severity": "critical",
                "timestamp": "2024-05-01 00:00:00 UTC",
            },
        ]
        saved: set[str] = set()
        write_vulnerabilities(tmp_path, reports, saved)
        csv_text = (tmp_path / "vulnerabilities.csv").read_text(encoding="utf-8")
        lines = csv_text.strip().splitlines()
        # header + 3 rows
        assert len(lines) == 4
        # First row should be the older critical (sorted by severity first, then timestamp)
        assert "older critical" in lines[1] or "vuln-cccc" in lines[1]
        # Criticals before high
        crit_rows = [ln for ln in lines[1:] if "CRITICAL" in ln]
        high_rows = [ln for ln in lines[1:] if "HIGH" in ln]
        assert len(crit_rows) == 2
        assert len(high_rows) == 1
        assert csv_text.find("CRITICAL") < csv_text.find("HIGH")

    def test_dedup_skips_already_saved(self, tmp_path: Path) -> None:
        reports = [
            {
                "id": "vuln-0001",
                "title": "x",
                "severity": "low",
                "timestamp": "2024-01-01 00:00:00 UTC",
            }
        ]
        saved: set[str] = {"vuln-0001"}
        new_count = write_vulnerabilities(tmp_path, reports, saved)
        assert new_count == 0
        # The MD file should NOT have been written
        assert not (tmp_path / "vulnerabilities" / "vuln-0001.md").exists()
        # But the JSON should be there
        assert (tmp_path / "vulnerabilities.json").exists()
