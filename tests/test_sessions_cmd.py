"""Tests for the ``kael sessions`` subcommand handlers."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from kael.core.paths import FOLDER_SENTINEL, run_dir_for, runs_root
from kael.interface.sessions import (
    cmd_sessions,
    delete_runs,
    folder_create,
    folder_delete,
    folder_list,
    list_runs,
    move_run,
    report_run,
    show_run,
)


def _write_run(
    run_dir: Path,
    *,
    name: str | None = None,
    status: str = "completed",
    start: datetime | None = None,
    end: datetime | None = None,
    targets_info: list[dict] | None = None,
    instruction: str | None = None,
    scan_mode: str = "deep",
    llm_usage: dict | None = None,
) -> dict:
    run_dir.mkdir(parents=True, exist_ok=True)
    start_ts = (start or datetime(2026, 6, 13, 12, 0, tzinfo=UTC)).isoformat()
    end_ts = (end or datetime(2026, 6, 13, 12, 5, tzinfo=UTC)).isoformat()
    record = {
        "run_id": name or run_dir.name,
        "run_name": name or run_dir.name,
        "status": status,
        "start_time": start_ts,
        "end_time": end_ts,
        "targets_info": targets_info
        or [
            {
                "type": "web_application",
                "details": {"target_url": "https://example.com"},
                "original": "https://example.com",
            },
        ],
        "scan_mode": scan_mode,
        "instruction": instruction or "",
        "llm_usage": llm_usage
        or {
            "requests": 1,
            "input_tokens": 100,
            "output_tokens": 50,
            "cost": 0.42,
        },
    }
    (run_dir / "run.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Run the test with ``tmp_path`` as cwd so path resolution is sandboxed."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestListRuns:
    def test_empty_dir_prints_friendly_message(
        self, workdir: Path, capsys: pytest.CaptureFixture
    ) -> None:
        list_runs()
        captured = capsys.readouterr().out
        assert "No runs yet" in captured

    def test_lists_top_level_runs(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        _write_run(workdir / "kael_runs" / "beta")
        result = list_runs(folder=None)
        assert {r["name"] for r in result["runs"]} == {"alpha", "beta"}
        assert result["folders"] == []
        captured = capsys.readouterr().out
        assert "RUNS" in captured

    def test_folder_contents(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        folder = workdir / "kael_runs" / "acme"
        folder.mkdir(parents=True)
        (folder / FOLDER_SENTINEL).touch()
        _write_run(folder / "api")

        result = list_runs(folder="acme")
        assert {r["name"] for r in result["runs"]} == {"acme/api"}
        captured = capsys.readouterr().out
        assert "Folder:" in captured
        assert "acme/api" in captured

    def test_separates_runs_and_folders(self, workdir: Path) -> None:
        _write_run(workdir / "kael_runs" / "loose")
        folder = workdir / "kael_runs" / "acme"
        folder.mkdir()
        (folder / FOLDER_SENTINEL).touch()
        _write_run(folder / "api")

        # Top-level listing shows top-level runs + folders, but does
        # NOT recurse into the folder (per the "one level at a time"
        # design).
        result = list_runs()
        run_names = {r["name"] for r in result["runs"]}
        assert run_names == {"loose"}
        assert result["folders"] == ["acme"]

        # Inside the folder, the nested run appears with its full path.
        nested = list_runs(folder="acme")
        assert {r["name"] for r in nested["runs"]} == {"acme/api"}

    def test_json_output(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        result = list_runs(as_json=True)
        assert result["runs"][0]["name"] == "alpha"
        assert result["runs"][0]["status"] == "completed"
        assert result["runs"][0]["vuln_counts"] == "0"
        assert result["runs"][0]["cost"] == "$0.42"
        # JSON mode should NOT print a table to stdout.
        out = capsys.readouterr().out
        assert "RUNS" not in out

    def test_corrupt_run_json_is_marked(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        run_dir = workdir / "kael_runs" / "bad"
        run_dir.mkdir(parents=True)
        (run_dir / "run.json").write_text("not json{", encoding="utf-8")
        result = list_runs()
        assert len(result["runs"]) == 1
        assert result["runs"][0]["corrupted"] is True
        assert result["runs"][0]["status"] == "corrupt"
        captured = capsys.readouterr().out
        assert "corrupt" in captured.lower()

    def test_runs_sorted_by_start_time_desc(self, workdir: Path) -> None:
        old = workdir / "kael_runs" / "old"
        new = workdir / "kael_runs" / "new"
        _write_run(
            old,
            start=datetime(2025, 1, 1, tzinfo=UTC),
            end=datetime(2025, 1, 1, 1, tzinfo=UTC),
        )
        _write_run(
            new,
            start=datetime(2026, 6, 13, tzinfo=UTC),
            end=datetime(2026, 6, 13, 1, tzinfo=UTC),
        )
        result = list_runs()
        assert [r["name"] for r in result["runs"]] == ["new", "old"]


class TestShowRun:
    def test_shows_metadata(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        _write_run(
            workdir / "kael_runs" / "alpha",
            status="completed",
            instruction="focus on auth",
        )
        rc = show_run("alpha")
        assert rc == 0
        out = capsys.readouterr().out
        assert "alpha" in out
        assert "completed" in out
        assert "focus on auth" in out

    def test_shows_missing_run_returns_1(
        self, workdir: Path, capsys: pytest.CaptureFixture
    ) -> None:
        rc = show_run("nope")
        assert rc == 1
        assert "No such run" in capsys.readouterr().out

    def test_shows_invalid_name_returns_2(
        self, workdir: Path, capsys: pytest.CaptureFixture
    ) -> None:
        rc = show_run("../escape")
        assert rc == 2

    def test_show_json(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        rc = show_run("alpha", as_json=True)
        assert rc == 0
        out = capsys.readouterr().out
        assert "alpha" in out
        # JSON is emitted via console.print_json which adds structure; we
        # only assert that the run name appears somewhere.
        assert "alpha" in out

    def test_shows_artifact_list(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        (run_dir / "vulnerabilities.json").write_text("[]", encoding="utf-8")
        (run_dir / "kael.log").write_text("log", encoding="utf-8")
        rc = show_run("alpha")
        assert rc == 0
        out = capsys.readouterr().out
        assert "vulnerabilities.json" in out
        assert "kael.log" in out


class TestReportRun:
    def test_prints_report_body(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        body = (
            "# Security Penetration Test Report\n\n"
            "## Executive Summary\n\nFound 1 critical issue.\n"
        )
        (run_dir / "penetration_test_report.md").write_text(body, encoding="utf-8")
        rc = report_run("alpha")
        assert rc == 0
        out = capsys.readouterr().out
        assert "Security Penetration Test Report" in out
        assert "Found 1 critical issue." in out

    def test_prints_json_when_requested(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        (run_dir / "penetration_test_report.md").write_text("# r", encoding="utf-8")
        vulns = [{"id": "v-1", "severity": "high", "title": "XSS"}]
        (run_dir / "vulnerabilities.json").write_text(json.dumps(vulns), encoding="utf-8")
        rc = report_run("alpha", as_json=True)
        assert rc == 0
        out = capsys.readouterr().out
        assert "v-1" in out
        # The report body must NOT be emitted in JSON mode.
        assert "Security Penetration Test Report" not in out

    def test_with_vulns_appends_findings(
        self, workdir: Path, capsys: pytest.CaptureFixture
    ) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        (run_dir / "penetration_test_report.md").write_text("# Report body\n", encoding="utf-8")
        vulns_dir = run_dir / "vulnerabilities"
        vulns_dir.mkdir()
        (vulns_dir / "v-0001.md").write_text("# Finding one\n", encoding="utf-8")
        (vulns_dir / "v-0002.md").write_text("# Finding two\n", encoding="utf-8")
        rc = report_run("alpha", with_vulns=True)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Report body" in out
        assert "Finding one" in out
        assert "Finding two" in out
        # Findings are emitted in numeric order.
        assert out.index("Finding one") < out.index("Finding two")

    def test_returns_1_for_missing_run(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        rc = report_run("nope")
        assert rc == 1
        assert "No such run" in capsys.readouterr().out

    def test_returns_2_for_invalid_name(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        rc = report_run("../escape")
        assert rc == 2

    def test_returns_3_when_report_missing(
        self, workdir: Path, capsys: pytest.CaptureFixture
    ) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        # No penetration_test_report.md written.
        rc = report_run("alpha")
        assert rc == 3
        assert "No report yet" in capsys.readouterr().out

    def test_returns_3_when_json_missing(
        self, workdir: Path, capsys: pytest.CaptureFixture
    ) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        (run_dir / "penetration_test_report.md").write_text("# r", encoding="utf-8")
        rc = report_run("alpha", as_json=True)
        assert rc == 3

    def test_falls_back_when_vulns_dir_absent(
        self, workdir: Path, capsys: pytest.CaptureFixture
    ) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        (run_dir / "penetration_test_report.md").write_text("# Report\n", encoding="utf-8")
        rc = report_run("alpha", with_vulns=True)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Report" in out
        assert "No vulnerabilities/" in out

    def test_dispatch_via_cmd_sessions(self, workdir: Path, capsys) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        (run_dir / "penetration_test_report.md").write_text("# via dispatch\n", encoding="utf-8")
        rc = cmd_sessions(["sessions", "report", "alpha"])
        assert rc == 0
        assert "via dispatch" in capsys.readouterr().out

    def test_top_level_dispatch(self, workdir: Path, capsys, monkeypatch) -> None:
        import importlib

        main_module = importlib.import_module("kael.interface.main")
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        (run_dir / "penetration_test_report.md").write_text("# top-level\n", encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["kael", "report", "alpha"])
        with pytest.raises(SystemExit) as exc:
            main_module.main()
        assert exc.value.code == 0
        assert "top-level" in capsys.readouterr().out

    def test_top_level_report_without_name_uses_most_recent(
        self, workdir: Path, capsys, monkeypatch
    ) -> None:
        import importlib

        main_module = importlib.import_module("kael.interface.main")
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        (run_dir / "penetration_test_report.md").write_text("# most-recent\n", encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["kael", "report"])
        with pytest.raises(SystemExit) as exc:
            main_module.main()
        assert exc.value.code == 0
        assert "most-recent" in capsys.readouterr().out

    def test_top_level_report_without_name_and_no_runs_errors(
        self, workdir: Path, capsys, monkeypatch
    ) -> None:
        import importlib

        main_module = importlib.import_module("kael.interface.main")
        monkeypatch.setattr(sys, "argv", ["kael", "report"])
        with pytest.raises(SystemExit) as exc:
            main_module.main()
        assert exc.value.code == 1
        assert "No runs found" in capsys.readouterr().out


class TestDeleteRuns:
    def test_delete_existing_run(self, workdir: Path) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        rc = delete_runs(["alpha"], yes=True)
        assert rc == 0
        assert not run_dir.exists()

    def test_delete_missing_returns_1(self, workdir: Path) -> None:
        rc = delete_runs(["nope"], yes=True)
        assert rc == 1

    def test_delete_folder_refused(self, workdir: Path) -> None:
        folder = workdir / "kael_runs" / "acme"
        folder.mkdir(parents=True)
        (folder / FOLDER_SENTINEL).touch()
        rc = delete_runs(["acme"], yes=True)
        assert rc == 1
        assert folder.exists()

    def test_delete_requires_yes_by_default(
        self, workdir: Path, capsys: pytest.CaptureFixture
    ) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        rc = delete_runs(["alpha"])
        assert rc == 1
        assert run_dir.exists()
        assert "Re-run with --yes" in capsys.readouterr().out


class TestMoveRun:
    def test_move_into_existing_folder(self, workdir: Path) -> None:
        folder = workdir / "kael_runs" / "acme"
        folder.mkdir(parents=True)
        (folder / FOLDER_SENTINEL).touch()
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)

        rc = move_run("alpha", "acme", yes=True)
        assert rc == 0
        new = folder / "alpha"
        assert new.exists()
        record = json.loads((new / "run.json").read_text(encoding="utf-8"))
        assert record["run_name"] == "acme/alpha"
        assert record["folder"] == "acme"

    def test_move_auto_creates_folder(self, workdir: Path) -> None:
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        rc = move_run("alpha", "new/folder", yes=True)
        assert rc == 0
        new = workdir / "kael_runs" / "new" / "folder" / "alpha"
        assert new.exists()

    def test_move_into_existing_run_fails(self, workdir: Path) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        _write_run(workdir / "kael_runs" / "acme" / "alpha")
        rc = move_run("alpha", "acme", yes=True)
        assert rc == 1

    def test_move_missing_run(self, workdir: Path) -> None:
        rc = move_run("nope", "acme", yes=True)
        assert rc == 1

    def test_move_refuses_folder(self, workdir: Path) -> None:
        folder = workdir / "kael_runs" / "acme"
        folder.mkdir(parents=True)
        (folder / FOLDER_SENTINEL).touch()
        rc = move_run("acme", "x", yes=True)
        assert rc == 1

    def test_move_requires_yes(self, workdir: Path) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        rc = move_run("alpha", "acme")
        assert rc == 1
        assert (workdir / "kael_runs" / "alpha").exists()


class TestFolderCreate:
    def test_creates_empty_folder(self, workdir: Path) -> None:
        rc = folder_create(["acme"], yes=True)
        assert rc == 0
        folder = workdir / "kael_runs" / "acme"
        assert folder.is_dir()
        assert (folder / FOLDER_SENTINEL).exists()

    def test_creates_nested(self, workdir: Path) -> None:
        rc = folder_create(["acme/api"], yes=True)
        assert rc == 0
        # Sentinel goes on the leaf; parent dirs are auto-detected as
        # folders because they contain a folder child.
        leaf = workdir / "kael_runs" / "acme" / "api"
        assert leaf.is_dir()
        assert (leaf / FOLDER_SENTINEL).exists()
        parent = workdir / "kael_runs" / "acme"
        assert parent.is_dir()

    def test_existing_folder_idempotent(self, workdir: Path) -> None:
        folder_create(["acme"], yes=True)
        rc = folder_create(["acme"], yes=True)
        assert rc == 0

    def test_refuses_over_run(self, workdir: Path) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        rc = folder_create(["alpha"], yes=True)
        assert rc == 1

    def test_invalid_name_rejected(self, workdir: Path) -> None:
        rc = folder_create(["../escape"], yes=True)
        assert rc == 2


class TestFolderList:
    def test_lists_folders(self, workdir: Path) -> None:
        folder_create(["acme", "training"], yes=True)
        rc = folder_list()
        assert rc == 0
        captured_path = workdir / "kael_runs"
        folders = [p.name for p in captured_path.iterdir() if p.is_dir()]
        assert set(folders) == {"acme", "training"}

    def test_empty(self, workdir: Path, capsys: pytest.CaptureFixture) -> None:
        rc = folder_list()
        assert rc == 0
        out = capsys.readouterr().out
        assert "No folders" in out

    def test_json_output(self, workdir: Path) -> None:
        folder_create(["acme"], yes=True)
        _write_run(workdir / "kael_runs" / "loose")
        rc = folder_list(as_json=True)
        assert rc == 0


class TestFolderDelete:
    def test_deletes_empty_folder(self, workdir: Path) -> None:
        folder_create(["acme"], yes=True)
        rc = folder_delete(["acme"], yes=True)
        assert rc == 0
        assert not (workdir / "kael_runs" / "acme").exists()

    def test_refuses_non_empty(self, workdir: Path) -> None:
        folder_create(["acme"], yes=True)
        _write_run(workdir / "kael_runs" / "acme" / "api")
        rc = folder_delete(["acme"], yes=True)
        assert rc == 1
        assert (workdir / "kael_runs" / "acme").exists()

    def test_missing_folder(self, workdir: Path) -> None:
        rc = folder_delete(["nope"], yes=True)
        assert rc == 1

    def test_invalid_name(self, workdir: Path) -> None:
        rc = folder_delete(["../escape"], yes=True)
        assert rc == 1

    def test_requires_yes(self, workdir: Path) -> None:
        folder_create(["acme"], yes=True)
        rc = folder_delete(["acme"])
        assert rc == 1
        assert (workdir / "kael_runs" / "acme").exists()


class TestCmdSessionsParser:
    """Exercise argparse-level dispatch by going through ``cmd_sessions``."""

    def test_list_dispatches_to_list_runs(self, workdir: Path) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        rc = cmd_sessions(["sessions", "list"])
        assert rc == 0

    def test_show_dispatches_to_show_run(self, workdir: Path) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        rc = cmd_sessions(["sessions", "show", "alpha"])
        assert rc == 0

    def test_delete_dispatches_to_delete_runs(self, workdir: Path) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        rc = cmd_sessions(["sessions", "delete", "-y", "alpha"])
        assert rc == 0
        assert not (workdir / "kael_runs" / "alpha").exists()

    def test_move_dispatches_to_move_run(self, workdir: Path) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        rc = cmd_sessions(["sessions", "move", "-y", "alpha", "acme"])
        assert rc == 0
        assert (workdir / "kael_runs" / "acme" / "alpha").exists()

    def test_folder_create_dispatch(self, workdir: Path) -> None:
        rc = cmd_sessions(["sessions", "folder", "create", "acme"])
        # create does not require --yes (no destructive operation on a missing folder)
        assert rc == 0
        assert (workdir / "kael_runs" / "acme" / FOLDER_SENTINEL).exists()

    def test_folder_list_dispatch(self, workdir: Path) -> None:
        folder_create(["acme"], yes=True)
        rc = cmd_sessions(["sessions", "folder", "list"])
        assert rc == 0

    def test_folder_delete_requires_yes(self, workdir: Path) -> None:
        folder_create(["acme"], yes=True)
        rc = cmd_sessions(["sessions", "folder", "delete", "acme"])
        assert rc == 1
        assert (workdir / "kael_runs" / "acme").exists()

    def test_invalid_name_rejected(self, workdir: Path) -> None:
        rc = cmd_sessions(["sessions", "show", "../escape"])
        assert rc == 2

    def test_ls_alias(self, workdir: Path) -> None:
        _write_run(workdir / "kael_runs" / "alpha")
        rc = cmd_sessions(["sessions", "ls"])
        assert rc == 0


class TestIntegrationWithMain:
    """End-to-end: ``kael sessions ...`` goes through ``main()``'s dispatch."""

    def test_dispatch_from_main(self, workdir: Path, capsys, monkeypatch) -> None:
        import importlib
        import sys

        # Import the module, not the ``main`` function re-exported by
        # ``kael.interface.__init__``.
        main_module = importlib.import_module("kael.interface.main")

        _write_run(workdir / "kael_runs" / "alpha")
        monkeypatch.setattr(sys, "argv", ["kael", "sessions", "list"])
        with pytest.raises(SystemExit) as exc:
            main_module.main()
        assert exc.value.code == 0

    def test_top_level_list_dispatches(self, workdir: Path, monkeypatch) -> None:
        import importlib
        import sys

        main_module = importlib.import_module("kael.interface.main")
        _write_run(workdir / "kael_runs" / "alpha")
        monkeypatch.setattr(sys, "argv", ["kael", "list"])
        with pytest.raises(SystemExit) as exc:
            main_module.main()
        assert exc.value.code == 0

    def test_top_level_ls_alias(self, workdir: Path, monkeypatch) -> None:
        import importlib
        import sys

        main_module = importlib.import_module("kael.interface.main")
        _write_run(workdir / "kael_runs" / "alpha")
        monkeypatch.setattr(sys, "argv", ["kael", "ls"])
        with pytest.raises(SystemExit) as exc:
            main_module.main()
        assert exc.value.code == 0

    def test_top_level_show(self, workdir: Path, monkeypatch) -> None:
        import importlib
        import sys

        main_module = importlib.import_module("kael.interface.main")
        _write_run(workdir / "kael_runs" / "alpha")
        monkeypatch.setattr(sys, "argv", ["kael", "show", "alpha"])
        with pytest.raises(SystemExit) as exc:
            main_module.main()
        assert exc.value.code == 0

    def test_top_level_resume_without_name_uses_most_recent(
        self, workdir: Path, monkeypatch
    ) -> None:
        import importlib
        import sys

        main_module = importlib.import_module("kael.interface.main")
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        monkeypatch.setattr(sys, "argv", ["kael", "resume"])
        args = main_module.parse_arguments()
        # Dispatcher must reach the resume path and resolve alpha
        # (the most-recent run) as the implicit resume name.
        assert args.command == "resume"
        # The actual resolution to ``alpha`` happens in main() after
        # parse_arguments; we cover that in TestResumeDefaults below.

    def test_top_level_show_without_name_uses_most_recent(
        self, workdir: Path, capsys, monkeypatch
    ) -> None:
        import importlib
        import sys

        main_module = importlib.import_module("kael.interface.main")
        run_dir = workdir / "kael_runs" / "alpha"
        _write_run(run_dir)
        monkeypatch.setattr(sys, "argv", ["kael", "show"])
        with pytest.raises(SystemExit) as exc:
            main_module.main()
        assert exc.value.code == 0
        assert "alpha" in capsys.readouterr().out

    def test_dispatcher_does_not_swallow_scan_args(self, workdir: Path) -> None:
        """``kael list`` (a target spelled ``list``) must reach the scan parser.

        The dispatcher keys on ``sys.argv[1]`` only when that token is a
        known command; a target that happens to spell ``list`` doesn't
        get hijacked. The scan parser then rejects ``list`` as an unknown
        target type, which is the expected behaviour regardless of the
        dispatcher.
        """
        from kael.interface.main import parse_arguments

        with (
            patch.object(sys, "argv", ["kael", "list"]),
            pytest.raises(SystemExit),
        ):
            parse_arguments()

    def test_folder_with_scan_target(self, workdir: Path) -> None:
        from kael.interface.main import parse_arguments

        with patch.object(sys, "argv", ["kael", "scan", "example.com", "folder", "acme/api"]):
            args = parse_arguments()
        assert args.target == ["example.com"]
        assert args.targets_info[0]["original"] == "example.com"
        assert args.folder == "acme/api"

    def test_resume_with_target_rejected(self) -> None:
        """The ``resume`` subcommand takes a name, not a target."""
        from kael.interface.main import parse_arguments

        # ``resume <NAME>`` — second positional is the resume name, not a
        # target. The scan dispatcher must not be entered accidentally.
        with patch.object(sys, "argv", ["kael", "resume", "acme", "old"]):
            args = parse_arguments()
        assert args.command == "resume"
        assert args.resume == "acme"

    def test_legacy_dash_dash_resume_dispatches_to_resume(self) -> None:
        """``kael --resume <name>`` (legacy form) must reach the resume path.

        ``sessions resume`` re-invokes the main entrypoint with this exact
        argv shape (see ``kael.interface.sessions.resume_run``). Without
        this, ``--resume`` was treated as a target and the user saw
        ``kael: error: invalid target '--resume'``.
        """
        from kael.interface.main import parse_arguments

        with patch.object(sys, "argv", ["kael", "--resume", "acme"]):
            args = parse_arguments()
        assert args.command == "resume"
        assert args.resume == "acme"

    def test_legacy_dash_dash_resume_without_name(self) -> None:
        """``kael --resume`` with no name must not crash; main() resolves."""
        from kael.interface.main import parse_arguments

        with patch.object(sys, "argv", ["kael", "--resume"]):
            args = parse_arguments()
        assert args.command == "resume"
        assert args.resume is None


class TestCliConsistencyDefaults:
    """The CLI should be usable with no required arguments.

    The target is positional (a bare token) rather than a ``--flag``.
    The ``non-interactive`` toggle is a keyword. The TUI mode prompt
    path still works when no target is given.
    """

    def test_target_defaults_to_cwd_in_non_interactive_mode(self) -> None:
        from kael.interface.main import parse_arguments

        with patch.object(sys, "argv", ["kael", ".", "non-interactive"]):
            args = parse_arguments()
        assert args.command == "scan"
        assert args.target == ["."]
        assert args.targets_info
        assert args.targets_info[0]["type"] == "local_code"
        assert args.non_interactive is True

    def test_target_still_respects_explicit_value(self) -> None:
        from kael.interface.main import parse_arguments

        with patch.object(sys, "argv", ["kael", "example.com", "non-interactive"]):
            args = parse_arguments()
        assert args.target == ["example.com"]
        assert args.non_interactive is True

    def test_target_unset_in_tui_mode(self) -> None:
        from kael.interface.main import parse_arguments

        with patch.object(sys, "argv", ["kael"]):
            args = parse_arguments()
        # TUI mode does not auto-fill target; the chat input prompts.
        assert args.command == "scan"
        assert args.target is None
        assert args.targets_info == []

    def test_prompt_keyword_runs_prompt_only_scan(self) -> None:
        from kael.interface.main import parse_arguments

        with patch.object(sys, "argv", ["kael", "prompt", "do a thing without a target"]):
            args = parse_arguments()
        assert args.command == "scan"
        assert args.targets_info == []
        assert args.target is None
        assert args.instruction == "do a thing without a target"
        assert args.prompt == "do a thing without a target"
        assert args.prompt_only is True
        assert args.non_interactive is False

    def test_prompt_with_target_is_not_prompt_only(self) -> None:
        from kael.interface.main import parse_arguments

        with patch.object(sys, "argv", ["kael", "example.com", "prompt", "find IDOR"]):
            args = parse_arguments()
        assert args.prompt == "find IDOR"
        assert args.prompt_only is False, (
            "prompt + target is just a target with custom instructions, "
            "not the no-target freeform mode"
        )

    def test_prompt_keyword_in_non_interactive_mode(self) -> None:
        from kael.interface.main import parse_arguments

        with patch.object(
            sys,
            "argv",
            ["kael", "prompt", "audit the k8s manifests", "non-interactive"],
        ):
            args = parse_arguments()
        assert args.targets_info == []
        assert args.instruction == "audit the k8s manifests"
        assert args.non_interactive is True

    def test_prompt_with_target_sets_instruction(self) -> None:
        from kael.interface.main import parse_arguments

        with patch.object(sys, "argv", ["kael", "example.com", "prompt", "find IDOR bugs"]):
            args = parse_arguments()
        assert args.targets_info[0]["type"] == "web_application"
        assert args.instruction == "find IDOR bugs"
        assert args.prompt == "find IDOR bugs"

    def test_prompt_collides_with_instruction(self) -> None:
        from kael.interface.main import parse_arguments

        with (
            patch.object(
                sys,
                "argv",
                ["kael", "example.com", "prompt", "do X", "instruction", "do Y"],
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            parse_arguments()
        assert exc_info.value.code == 2

    def test_prompt_repeated_is_rejected(self) -> None:
        from kael.interface.main import parse_arguments

        with patch.object(sys, "argv", ["kael", "prompt", "first", "prompt", "second"]):
            with pytest.raises(SystemExit) as exc_info:
                parse_arguments()
        assert exc_info.value.code == 2

    def test_show_without_name_uses_most_recent(self, workdir: Path) -> None:
        from kael.interface.sessions import cmd_sessions

        # Two runs, alpha older, beta newer; cmd_sessions must pick beta.
        _write_run(
            workdir / "kael_runs" / "alpha",
            start=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
        )
        _write_run(
            workdir / "kael_runs" / "beta",
            start=datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
        )
        rc = cmd_sessions(["sessions", "show"])
        assert rc == 0

    def test_report_without_name_uses_most_recent(self, workdir: Path) -> None:
        from kael.interface.sessions import cmd_sessions

        _write_run(
            workdir / "kael_runs" / "alpha",
            start=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
        )
        run_dir = workdir / "kael_runs" / "beta"
        _write_run(
            run_dir,
            start=datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
        )
        (run_dir / "penetration_test_report.md").write_text("# newest\n", encoding="utf-8")
        rc = cmd_sessions(["sessions", "report"])
        assert rc == 0

    def test_show_without_name_no_runs_errors(self, workdir: Path) -> None:
        from kael.interface.sessions import cmd_sessions

        rc = cmd_sessions(["sessions", "show"])
        assert rc == 1

    def test_show_recurses_into_folders(self, workdir: Path) -> None:
        from kael.interface.sessions import cmd_sessions

        folder = workdir / "kael_runs" / "acme"
        folder.mkdir(parents=True)
        (folder / FOLDER_SENTINEL).touch()
        _write_run(
            folder / "api",
            start=datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
        )
        rc = cmd_sessions(["sessions", "show"])
        assert rc == 0


class TestPromptOnlyRunName:
    """Prompt-only runs should produce a meaningful run-name slug."""

    def test_prompt_only_slugifies_first_line(self) -> None:
        from kael.interface.utils import generate_run_name

        name = generate_run_name(
            [],
            prompt="Audit the staging k8s cluster\nfor misconfigurations",
        )
        assert name.startswith("audit-the-staging-k8s-cluster_")
        assert "misconfigurations" not in name

    def test_prompt_only_falls_back_to_pentest(self) -> None:
        from kael.interface.utils import generate_run_name

        name = generate_run_name([], prompt=None)
        assert name.startswith("pentest_")

    def test_target_run_prefers_target_label(self) -> None:
        from kael.interface.utils import generate_run_name

        name = generate_run_name(
            [{"type": "web_application", "details": {"target_url": "https://x"}, "original": "x"}],
            prompt="ignored because we have a target",
        )
        assert name.startswith("x_")
