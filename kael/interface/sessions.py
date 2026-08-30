"""CLI subcommands for managing Kael runs (list, show, resume, delete, folder ...).

Runs live as subdirectories of ``kael_runs/`` — each run dir contains a
``run.json`` describing the scan, and Folders are subdirectories that
either hold runs, sub-folders, or carry a ``.kael_folder`` sentinel.
A run name with optional folder prefix is a slash-separated path
(``acme/api/run_xx``); the first non-``sessions`` arg to ``kael`` is
forwarded here when the user types ``kael sessions ...``.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from kael.core.paths import (
    FOLDER_SENTINEL,
    RUN_RECORD_FILENAME,
    InvalidSessionPathError,
    is_folder_dir,
    is_run_dir,
    run_dir_for,
    runs_root,
    validate_session_path,
)
from kael.report.writer import read_run_record, write_run_record


if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


logger = logging.getLogger(__name__)


_TERMINAL_STATUS_STYLES: dict[str, str] = {
    "running": "bold yellow",
    "completed": "bold #22c55e",
    "stopped": "bold #eab308",
    "interrupted": "bold #eab308",
    "failed": "bold red",
}


@dataclass(frozen=True)
class RunSummary:
    """Lightweight in-memory view of a single run, derived from run.json."""

    name: str
    run_dir: Path
    record: dict[str, Any]
    corrupted: bool = False
    error: str | None = None

    @property
    def status(self) -> str:
        if self.corrupted:
            return "corrupt"
        value = self.record.get("status")
        return str(value) if isinstance(value, str) and value else "unknown"

    @property
    def start_time(self) -> str | None:
        value = self.record.get("start_time") if not self.corrupted else None
        return str(value) if isinstance(value, str) else None

    @property
    def end_time(self) -> str | None:
        value = self.record.get("end_time") if not self.corrupted else None
        return str(value) if isinstance(value, str) else None

    @property
    def duration(self) -> str | None:
        if not self.start_time or not self.end_time:
            return None
        try:
            start = datetime.fromisoformat(self.start_time)
            end = datetime.fromisoformat(self.end_time)
        except ValueError:
            return None
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
        delta = end - start
        seconds = int(delta.total_seconds())
        if seconds < 0:
            return None
        if seconds < 60:
            return f"{seconds}s"
        minutes, rem = divmod(seconds, 60)
        if minutes < 60:
            return f"{minutes}m{rem}s"
        hours, rem = divmod(minutes, 60)
        return f"{hours}h{rem}m"

    @property
    def targets(self) -> str:
        if self.corrupted:
            return "—"
        targets = self.record.get("targets_info") or []
        if not isinstance(targets, list) or not targets:
            return "—"
        labels: list[str] = []
        for target in targets:
            if not isinstance(target, dict):
                continue
            original = target.get("original") or target.get("details", {}).get("target_url")
            if isinstance(original, str) and original:
                labels.append(original)
        if not labels:
            return "—"
        if len(labels) == 1:
            return labels[0]
        return f"{labels[0]} +{len(labels) - 1}"

    @property
    def vuln_counts(self) -> str:
        if self.corrupted:
            return "—"
        total = self.record.get("vulnerability_reports_count")
        if not isinstance(total, int):
            # Best-effort: count via scan_results if present.
            scan_results = self.record.get("scan_results")
            if isinstance(scan_results, dict):
                vulns = scan_results.get("vulnerabilities")
                total = len(vulns) if isinstance(vulns, list) else 0
            else:
                total = 0
        return str(total)

    @property
    def cost(self) -> str:
        if self.corrupted:
            return "—"
        usage = self.record.get("llm_usage")
        if not isinstance(usage, dict):
            return "—"
        try:
            value = float(usage.get("cost") or 0.0)
        except (TypeError, ValueError):
            return "—"
        return f"${value:.2f}"


def _load_run_summary(name: str, run_dir: Path) -> RunSummary:
    record_path = run_dir / RUN_RECORD_FILENAME
    if not record_path.exists():
        return RunSummary(name=name, run_dir=run_dir, record={})
    try:
        record = read_run_record(run_dir)
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        return RunSummary(
            name=name,
            run_dir=run_dir,
            record={},
            corrupted=True,
            error=str(exc),
        )
    return RunSummary(name=name, run_dir=run_dir, record=record)


def _scan_directory(folder: str, *, base: Path) -> tuple[list[RunSummary], list[str]]:
    """Return (run_summaries, folder_names) for the given folder, sorted.

    Runs sort by ``start_time`` desc (None last). Folders sort alphabetically.
    """
    runs: list[RunSummary] = []
    folders: list[str] = []

    if not base.exists():
        return runs, folders

    try:
        children = sorted(base.iterdir(), key=lambda p: p.name)
    except OSError as exc:
        logger.warning("Failed to read %s: %s", base, exc)
        return runs, folders

    for child in children:
        if not child.is_dir():
            continue
        if is_run_dir(child):
            child_name = f"{folder}/{child.name}" if folder else child.name
            runs.append(_load_run_summary(child_name, child))
        elif is_folder_dir(child):
            folders.append(child.name)

    def _run_sort_key(summary: RunSummary) -> tuple[int, str]:
        ts = summary.start_time
        if not ts:
            return (1, summary.name)
        return (0, ts)

    runs.sort(key=_run_sort_key, reverse=True)
    folders.sort()
    return runs, folders


def _collect_all_runs(base: Path | None = None) -> list[RunSummary]:
    """Recursively collect every run under ``kael_runs/``, sorted most-recent first.

    Used by commands that default to the latest run when no name is given
    (e.g. ``kael show`` with no positional). Returns an empty list if the
    runs root is missing or has no runs.
    """
    root = base if base is not None else runs_root()
    runs: list[RunSummary] = []
    if not root.exists():
        return runs

    stack: list[tuple[Path, str]] = [(root, "")]
    while stack:
        folder_path, prefix = stack.pop()
        try:
            children = sorted(folder_path.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            logger.warning("Failed to read %s: %s", folder_path, exc)
            continue
        for child in children:
            if not child.is_dir():
                continue
            if is_run_dir(child):
                name = f"{prefix}/{child.name}" if prefix else child.name
                runs.append(_load_run_summary(name, child))
            elif is_folder_dir(child):
                child_prefix = f"{prefix}/{child.name}" if prefix else child.name
                stack.append((child, child_prefix))

    def _sort_key(summary: RunSummary) -> tuple[int, str]:
        ts = summary.start_time
        if not ts:
            return (1, summary.name)
        return (0, ts)

    runs.sort(key=_sort_key, reverse=True)
    return runs


def _most_recent_run_name() -> str | None:
    """Return the name of the most recently started run, or ``None`` if there are none."""
    runs = _collect_all_runs()
    if not runs:
        return None
    return runs[0].name


def _format_started_at(value: str | None) -> str:
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def _resolve_folder_arg(folder: str | None) -> Path:
    """Resolve a folder argument to an absolute path under ``kael_runs/``.

    Returns the path even if it does not exist; callers decide how to
    handle the missing case.
    """
    root = runs_root()
    if folder:
        try:
            validate_session_path(folder)
        except InvalidSessionPathError as exc:
            raise SystemExit(f"Invalid folder: {exc}") from exc
        return root / folder
    return root


def list_runs(
    folder: str | None = None,
    *,
    as_json: bool = False,
    console: Console | None = None,
) -> dict[str, Any]:
    """List runs and folders under ``kael_runs[/folder]``.

    Returns a dict payload so tests can inspect it; renders to ``console``
    (stdout by default) when ``as_json`` is False.
    """
    console = console or Console()
    try:
        base = _resolve_folder_arg(folder)
    except SystemExit as exc:
        raise SystemExit(str(exc)) from exc

    runs, folders = _scan_directory(folder or "", base=base)

    payload: dict[str, Any] = {
        "folder": folder or "",
        "runs": [
            {
                "name": r.name,
                "run_dir": str(r.run_dir),
                "status": r.status,
                "start_time": r.start_time,
                "end_time": r.end_time,
                "duration": r.duration,
                "targets": r.targets,
                "vuln_counts": r.vuln_counts,
                "cost": r.cost,
                "corrupted": r.corrupted,
                "error": r.error,
            }
            for r in runs
        ],
        "folders": folders,
    }

    if as_json:
        return payload

    console.print()
    if not base.exists():
        console.print("[dim]No runs yet — start one with[/] [bold]kael <URL>[/]")
        console.print()
        return payload

    if folder:
        console.print(f"[bold cyan]Folder:[/] [white]{folder}[/]")

    if folders:
        table = Table(
            title="FOLDERS",
            title_justify="left",
            show_header=True,
            header_style="bold #60a5fa",
            border_style="#60a5fa",
        )
        table.add_column("NAME", style="bold white", no_wrap=True)
        for name in folders:
            table.add_row(name)
        console.print()
        console.print(table)

    if runs:
        table = Table(
            title="RUNS",
            title_justify="left",
            show_header=True,
            header_style="bold #22c55e",
            border_style="#22c55e",
        )
        table.add_column("NAME", style="bold white", no_wrap=True, overflow="ellipsis")
        table.add_column("STATUS", no_wrap=True)
        table.add_column("STARTED", style="dim", no_wrap=True)
        table.add_column("DURATION", justify="right", no_wrap=True)
        table.add_column("TARGETS", overflow="ellipsis")
        table.add_column("VULNS", justify="right", no_wrap=True)
        table.add_column("COST", justify="right", no_wrap=True)

        for run in runs:
            status_style = _TERMINAL_STATUS_STYLES.get(run.status, "white")
            if run.corrupted:
                status_text = Text("corrupt", style="bold red")
            else:
                status_text = Text(run.status, style=status_style)
            table.add_row(
                run.name,
                status_text,
                _format_started_at(run.start_time),
                run.duration or "—",
                run.targets,
                run.vuln_counts,
                run.cost,
            )
        console.print()
        console.print(table)
    elif not folders:
        console.print()
        console.print("[dim]No runs found in this folder.[/]")

    console.print()
    return payload


def show_run(name: str, *, as_json: bool = False, console: Console | None = None) -> int:
    """Show a single run's metadata + on-disk artifacts. Returns exit code."""
    console = console or Console()
    try:
        validate_session_path(name)
    except InvalidSessionPathError as exc:
        console.print(f"[bold red]Invalid run name:[/] {exc}")
        return 2

    run_dir = run_dir_for(name)
    if not run_dir.exists():
        console.print(f"[bold red]No such run:[/] {name}")
        console.print(f"  expected at: {run_dir}")
        return 1

    summary = _load_run_summary(name, run_dir)

    if as_json:
        payload = {
            "name": summary.name,
            "run_dir": str(summary.run_dir),
            "corrupted": summary.corrupted,
            "error": summary.error,
            "record": summary.record,
        }
        console.print_json(data=payload)
        return 0

    console.print()
    console.print(f"[bold cyan]Run:[/] [white]{summary.name}[/]")
    console.print(f"[dim]Path:[/]  {summary.run_dir}")
    if summary.corrupted:
        console.print(f"[bold red]Corrupt run.json:[/] {summary.error}")
        console.print()
        return 0

    record = summary.record
    fields: list[tuple[str, Any]] = [
        ("Status", record.get("status", "unknown")),
        ("Started", _format_started_at(summary.start_time)),
        ("Ended", _format_started_at(summary.end_time)),
        ("Duration", summary.duration or "—"),
        ("Scan mode", record.get("scan_mode", "—")),
        ("Targets", summary.targets),
        ("Vulnerabilities", summary.vuln_counts),
        ("Cost", summary.cost),
    ]
    instruction = record.get("instruction")
    if isinstance(instruction, str) and instruction.strip():
        fields.append(("Instruction", instruction.strip()[:200]))

    for label, value in fields:
        console.print(f"  [dim]{label:<14}[/] {value}")

    artifacts = sorted(p.name for p in run_dir.iterdir() if p.is_file())
    if artifacts:
        console.print()
        console.print("  [dim]Artifacts:[/]")
        for art in artifacts:
            console.print(f"    - {art}")
    console.print()
    return 0


REPORT_FILENAME = "penetration_test_report.md"
VULNS_DIRNAME = "vulnerabilities"


def report_run(
    name: str,
    *,
    with_vulns: bool = False,
    as_json: bool = False,
    console: Console | None = None,
) -> int:
    """Print the completed report body to stdout.

    Default mode reads ``{run_dir}/penetration_test_report.md`` and prints
    it. With ``with_vulns=True``, the markdown for every finding under
    ``{run_dir}/vulnerabilities/*.md`` is appended in numeric order. With
    ``as_json=True``, the contents of ``vulnerabilities.json`` are emitted
    (which is the canonical structured form regardless of whether the
    run finished cleanly).

    Returns 0 on success, 1 if the run is missing, 2 if the name is
    invalid, 3 if the report file hasn't been written yet.
    """
    console = console or Console()
    try:
        validate_session_path(name)
    except InvalidSessionPathError as exc:
        console.print(f"[bold red]Invalid run name:[/] {exc}")
        return 2

    run_dir = run_dir_for(name)
    if not run_dir.exists():
        console.print(f"[bold red]No such run:[/] {name}")
        console.print(f"  expected at: {run_dir}")
        return 1

    if as_json:
        json_path = run_dir / "vulnerabilities.json"
        if not json_path.exists():
            console.print(
                f"[bold red]No vulnerabilities.json for run:[/] {name}\n  expected at: {json_path}",
            )
            return 3
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            console.print(f"[bold red]Corrupt vulnerabilities.json:[/] {exc}")
            return 3
        console.print_json(data=payload)
        return 0

    report_path = run_dir / REPORT_FILENAME
    if not report_path.exists():
        console.print(
            f"[bold red]No report yet for run:[/] {name}\n"
            f"  expected at: {report_path}\n"
            f"  The scan is still in progress or was interrupted before the "
            f"executive report was written. Re-run with `kael --resume {name}` "
            f"to pick it up.",
        )
        return 3

    try:
        body = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        console.print(f"[bold red]Failed to read report:[/] {exc}")
        return 3

    # Write directly to stdout, bypassing Console's reformatting so
    # the markdown body round-trips cleanly. Console.file is the
    # underlying writer; falling back to print() is safe because
    # Console's stdout is just sys.stdout.
    out = console.file
    out.write(body)
    if not body.endswith("\n"):
        out.write("\n")

    if with_vulns:
        vulns_dir = run_dir / VULNS_DIRNAME
        if not vulns_dir.is_dir():
            out.write("\n[dim]No vulnerabilities/ directory for this run.[/]\n")
            return 0
        findings = sorted(p for p in vulns_dir.iterdir() if p.is_file() and p.suffix == ".md")
        if not findings:
            out.write("\n[dim]No individual finding markdown files were saved.[/]\n")
            return 0
        for finding in findings:
            text = finding.read_text(encoding="utf-8")
            out.write("\n---\n\n")
            out.write(text)
            if not text.endswith("\n"):
                out.write("\n")
    return 0


def resume_run(
    name: str,
    *,
    instruction: str | None = None,
    instruction_file: str | None = None,
    extra: Sequence[str] | None = None,
) -> int:
    """Re-invoke ``kael --resume <name>`` in-process.

    Returns the exit code from the nested ``main()`` call.
    """
    try:
        validate_session_path(name)
    except InvalidSessionPathError as exc:
        Console().print(f"[bold red]Invalid run name:[/] {exc}")
        return 2
    if not run_dir_for(name).exists():
        Console().print(f"[bold red]No such run:[/] {name}")
        return 1

    new_argv = ["kael", "--resume", name]
    if instruction:
        new_argv.extend(["--instruction", instruction])
    if instruction_file:
        new_argv.extend(["--instruction-file", instruction_file])
    if extra:
        new_argv.extend(extra)

    from kael.interface.main import main as kael_main

    saved = sys.argv
    sys.argv = new_argv
    try:
        kael_main()
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1
    finally:
        sys.argv = saved
    return 0


def delete_runs(names: Sequence[str], *, yes: bool = False) -> int:
    """Delete one or more runs (refuses if a path resolves to a folder)."""
    console = Console()
    if not names:
        console.print("[bold red]No run names provided.[/]")
        return 2

    targets: list[tuple[str, Path]] = []
    for name in names:
        try:
            validate_session_path(name)
        except InvalidSessionPathError as exc:
            console.print(f"[bold red]Invalid run name:[/] {name}: {exc}")
            return 2
        run_dir = run_dir_for(name)
        if not run_dir.exists():
            console.print(f"[bold red]No such run:[/] {name}")
            return 1
        if is_folder_dir(run_dir):
            console.print(
                f"[bold red]Refusing to delete folder as a run:[/] {name}\n"
                f"  Use 'kael sessions folder delete {name}' instead.",
            )
            return 1
        targets.append((name, run_dir))

    if not yes:
        console.print("[bold yellow]About to delete the following runs:[/]")
        for name, _ in targets:
            console.print(f"  - {name}")
        console.print()
        console.print("Re-run with --yes to confirm.")
        return 1

    for name, run_dir in targets:
        shutil.rmtree(run_dir)
        console.print(f"[green]deleted[/] {name}")
    return 0


def move_run(name: str, folder: str, *, yes: bool = False) -> int:
    """Move a run into a folder (creating the folder if needed)."""
    console = Console()
    try:
        validate_session_path(name)
    except InvalidSessionPathError as exc:
        console.print(f"[bold red]Invalid run name:[/] {name}: {exc}")
        return 2
    try:
        validated_folder = validate_session_path(folder)
    except InvalidSessionPathError as exc:
        console.print(f"[bold red]Invalid folder:[/] {folder}: {exc}")
        return 2

    src = run_dir_for(name)
    if not src.exists():
        console.print(f"[bold red]No such run:[/] {name}")
        return 1
    if is_folder_dir(src):
        console.print(f"[bold red]Refusing to move a folder:[/] {name}")
        return 1

    dest = run_dir_for(f"{validated_folder}/{src.name}")
    if dest.exists():
        console.print(
            f"[bold red]Destination already exists:[/] {dest}",
        )
        return 1
    if not yes:
        console.print(f"Move [bold]{name}[/] into [bold]{validated_folder}[/]?")
        console.print("Re-run with --yes to confirm.")
        return 1

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))

    record_path = dest / RUN_RECORD_FILENAME
    if record_path.exists():
        try:
            record = read_run_record(dest)
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            console.print(
                f"[bold red]Moved {name} but run.json is unreadable:[/] {exc}",
            )
            return 1
        if isinstance(record, dict):
            new_name = f"{validated_folder}/{src.name}"
            record["run_name"] = new_name
            record["folder"] = validated_folder
            try:
                write_run_record(dest, record)
            except OSError as exc:
                console.print(
                    f"[bold red]Moved {name} but failed to update run.json:[/] {exc}",
                )
                return 1

    new_name = f"{validated_folder}/{src.name}"
    console.print(f"[green]moved[/] {name} -> {new_name}")
    return 0


def folder_create(names: Sequence[str], *, yes: bool = False) -> int:
    """Create one or more empty folders under ``kael_runs/``."""
    console = Console()
    root = runs_root()
    if not root.exists():
        root.mkdir(parents=True, exist_ok=True)

    created: list[str] = []
    for raw_name in names:
        try:
            name = validate_session_path(raw_name)
        except InvalidSessionPathError as exc:
            console.print(f"[bold red]Invalid folder name:[/] {raw_name}: {exc}")
            return 2
        target = root / name
        if target.exists() and not target.is_dir():
            console.print(f"[bold red]Path exists and is not a directory:[/] {name}")
            return 1
        if target.exists() and is_folder_dir(target):
            console.print(f"[dim]already exists[/] {name}")
            continue
        if target.exists() and is_run_dir(target):
            console.print(
                f"[bold red]Refusing to create folder over an existing run:[/] {name}",
            )
            return 1
        target.mkdir(parents=True, exist_ok=True)
        (target / FOLDER_SENTINEL).touch(exist_ok=True)
        created.append(name)
        console.print(f"[green]created[/] {name}")

    if not created and not yes:
        console.print("[dim]Nothing to do.[/]")
    return 0


def folder_list(*, as_json: bool = False, console: Console | None = None) -> int:
    """List immediate folder children of ``kael_runs/``."""
    console = console or Console()
    root = runs_root()
    if not root.exists():
        if as_json:
            console.print_json(data={"folders": []})
        else:
            console.print()
            console.print("[dim]No folders yet.[/]")
            console.print()
        return 0

    folders: list[dict[str, Any]] = []
    names: list[str] = []
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if not child.is_dir():
            continue
        if is_run_dir(child):
            continue
        if not is_folder_dir(child):
            continue
        try:
            run_count = sum(1 for sub in child.iterdir() if is_run_dir(sub))
        except OSError:
            run_count = 0
        names.append(child.name)
        folders.append({"name": child.name, "runs": run_count})

    if as_json:
        console.print_json(data={"folders": folders})
        return 0

    console.print()
    if not folders:
        console.print("[dim]No folders yet.[/]")
        console.print()
        return 0

    table = Table(
        title="FOLDERS",
        title_justify="left",
        show_header=True,
        header_style="bold #60a5fa",
        border_style="#60a5fa",
    )
    table.add_column("NAME", style="bold white", no_wrap=True)
    table.add_column("RUNS", justify="right", no_wrap=True)
    for entry in folders:
        table.add_row(entry["name"], str(entry["runs"]))
    console.print(table)
    console.print()
    return 0


def folder_delete(names: Sequence[str], *, yes: bool = False) -> int:
    """Delete one or more folders (refuses if non-empty)."""
    console = Console()
    root = runs_root()
    failed = False
    for raw_name in names:
        try:
            name = validate_session_path(raw_name)
        except InvalidSessionPathError as exc:
            console.print(f"[bold red]Invalid folder name:[/] {raw_name}: {exc}")
            failed = True
            continue
        target = root / name
        if not target.exists() or not target.is_dir():
            console.print(f"[bold red]No such folder:[/] {name}")
            failed = True
            continue
        if is_run_dir(target):
            console.print(f"[bold red]Path is a run, not a folder:[/] {name}")
            failed = True
            continue
        if not is_folder_dir(target):
            console.print(f"[bold red]Not a folder (empty/unrecognized):[/] {name}")
            failed = True
            continue
        if any(child.name != FOLDER_SENTINEL for child in target.iterdir()):
            console.print(
                f"[bold red]Folder is not empty:[/] {name}\n"
                f"  Remove its contents first, then retry.",
            )
            failed = True
            continue
        if not yes:
            console.print(f"[bold yellow]About to delete folder:[/] {name}")
            console.print("Re-run with --yes to confirm.")
            failed = True
            continue
        sentinel = target / FOLDER_SENTINEL
        if sentinel.exists():
            sentinel.unlink()
        target.rmdir()
        console.print(f"[green]deleted[/] {name}")

    return 1 if failed else 0


# ---------------------------------------------------------------------------
# Argparse plumbing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kael sessions",
        description=(
            "Manage Kael runs and folders. Runs live as subdirectories of "
            "kael_runs/; folders are subdirectories you can use to group runs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sub = parser.add_subparsers(dest="subcommand", required=True, metavar="<command>")

    # list
    list_p = sub.add_parser(
        "list",
        aliases=["ls"],
        help="List runs and folders (one level deep).",
        description="List runs and folders under kael_runs[/FOLDER].",
    )
    list_p.add_argument(
        "folder",
        nargs="?",
        default=None,
        help="Optional folder to list contents of. Omit to list the top level.",
    )
    list_p.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit machine-readable JSON instead of a table.",
    )
    list_p.set_defaults(handler=_handle_list)

    # show
    show_p = sub.add_parser(
        "show",
        help="Show details of a single run.",
    )
    show_p.add_argument(
        "name",
        nargs="?",
        default=None,
        help="Run name (e.g. acme/api_xx). Omit to show the most recent run.",
    )
    show_p.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit machine-readable JSON.",
    )
    show_p.set_defaults(handler=_handle_show)

    # report
    report_p = sub.add_parser(
        "report",
        help="Print the completed penetration test report body to stdout.",
        description=(
            "Prints kael_runs/<NAME>/penetration_test_report.md. "
            "Use --vulns to also append each finding's markdown. "
            "Use --json to emit vulnerabilities.json instead. "
            "Omit <NAME> to print the most recent run's report."
        ),
    )
    report_p.add_argument(
        "name",
        nargs="?",
        default=None,
        help="Run name (e.g. acme/api_xx). Omit to print the most recent run's report.",
    )
    report_p.add_argument(
        "--vulns",
        action="store_true",
        dest="with_vulns",
        help="Also append the markdown body of every finding.",
    )
    report_p.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit vulnerabilities.json instead of the markdown report.",
    )
    report_p.set_defaults(handler=_handle_report)

    # resume
    resume_p = sub.add_parser(
        "resume",
        help="Resume a prior run (equivalent to `kael --resume <NAME>`). "
        "Omit <NAME> to resume the most recent run.",
    )
    resume_p.add_argument(
        "name",
        nargs="?",
        default=None,
        help="Run name to resume. Omit to resume the most recent run.",
    )
    resume_p.add_argument("--instruction", help="Optional new instruction for the resumed run.")
    resume_p.add_argument(
        "--instruction-file",
        dest="instruction_file",
        help="Path to an instruction file for the resumed run.",
    )
    resume_p.set_defaults(handler=_handle_resume)

    # delete
    delete_p = sub.add_parser(
        "delete",
        help="Delete one or more runs (irreversible).",
    )
    delete_p.add_argument("name", nargs="+", help="Run name(s) to delete.")
    delete_p.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt.",
    )
    delete_p.set_defaults(handler=_handle_delete)

    # move
    move_p = sub.add_parser(
        "move",
        help="Move a run into a folder (creating the folder if needed).",
    )
    move_p.add_argument("name", help="Run name to move.")
    move_p.add_argument("folder", help="Destination folder (auto-created).")
    move_p.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt.",
    )
    move_p.set_defaults(handler=_handle_move)

    # folder
    folder_p = sub.add_parser(
        "folder",
        help="Manage folders (create / list / delete).",
    )
    folder_sub = folder_p.add_subparsers(dest="folder_command", required=True, metavar="<command>")

    fc = folder_sub.add_parser("create", help="Create one or more folders.")
    fc.add_argument("name", nargs="+", help="Folder name(s) to create.")
    fc.add_argument("-y", "--yes", action="store_true", help="Skip the confirmation prompt.")
    fc.set_defaults(handler=_handle_folder_create)

    fl = folder_sub.add_parser("list", help="List folders under kael_runs/.")
    fl.add_argument("--json", action="store_true", dest="as_json")
    fl.set_defaults(handler=_handle_folder_list)

    fd = folder_sub.add_parser("delete", help="Delete one or more empty folders.")
    fd.add_argument("name", nargs="+", help="Folder name(s) to delete.")
    fd.add_argument("-y", "--yes", action="store_true", help="Skip the confirmation prompt.")
    fd.set_defaults(handler=_handle_folder_delete)

    return parser


def _handle_list(args: argparse.Namespace) -> int:
    console = Console()
    payload = list_runs(
        folder=args.folder,
        as_json=bool(getattr(args, "as_json", False)),
        console=console,
    )
    if bool(getattr(args, "as_json", False)):
        console.print_json(data=payload)
    return 0


def _resolve_run_name(name: str | None) -> str | None:
    """Resolve an optional run-name argument to an actual run name.

    When ``name`` is provided it's returned unchanged. When it's ``None``,
    the most-recent run is used, or ``None`` is returned and a friendly
    error is printed if there are no runs yet. Callers should treat
    ``None`` as "bail with the printed error already shown".
    """
    if name:
        return name
    most_recent = _most_recent_run_name()
    if most_recent is None:
        console = Console()
        console.print("[bold red]No runs found.[/]")
        console.print("  Start one with [bold]kael <URL>[/] or [bold]kael[/]")
        return None
    return most_recent


def _handle_show(args: argparse.Namespace) -> int:
    name = _resolve_run_name(args.name)
    if name is None:
        return 1
    return show_run(name, as_json=bool(getattr(args, "as_json", False)))


def _handle_report(args: argparse.Namespace) -> int:
    name = _resolve_run_name(args.name)
    if name is None:
        return 1
    return report_run(
        name,
        with_vulns=bool(getattr(args, "with_vulns", False)),
        as_json=bool(getattr(args, "as_json", False)),
    )


def _handle_resume(args: argparse.Namespace) -> int:
    name = _resolve_run_name(args.name)
    if name is None:
        return 1
    return resume_run(
        name,
        instruction=args.instruction,
        instruction_file=args.instruction_file,
    )


def _handle_delete(args: argparse.Namespace) -> int:
    return delete_runs(args.name, yes=bool(args.yes))


def _handle_move(args: argparse.Namespace) -> int:
    return move_run(args.name, args.folder, yes=bool(args.yes))


def _handle_folder_create(args: argparse.Namespace) -> int:
    return folder_create(args.name, yes=bool(args.yes))


def _handle_folder_list(args: argparse.Namespace) -> int:
    return folder_list(as_json=bool(getattr(args, "as_json", False)))


def _handle_folder_delete(args: argparse.Namespace) -> int:
    return folder_delete(args.name, yes=bool(args.yes))


def cmd_sessions(argv: Sequence[str]) -> int:
    """Entry point invoked from ``kael.interface.main`` when ``sys.argv[1] == 'sessions'``.

    ``argv`` is the full ``sys.argv`` slice starting at ``"sessions"``.
    """
    parser = _build_parser()
    args = parser.parse_args(argv[1:])
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    try:
        return int(handler(args))
    except KeyboardInterrupt:
        return 130
