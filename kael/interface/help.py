"""Unified command + options reference for the Kael CLI.

Used by ``kael help`` to print every command and its options in one
place. The CLI is primarily subcommand + positional-keyword based.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


_USAGE = """\
  [bold white]kael[/]                                          [dim]# launch the TUI[/]
  [bold white]kael[/] [cyan]<target>[/]                                [dim]# scan a target[/]
  [bold white]kael scan[/] [cyan]<target>[/] [keyword value ...]      [dim]# explicit scan[/]
  [bold white]kael <command>[/] [args]                          [dim]# run a subcommand[/]
  [bold white]kael help[/]                                      [dim]# show this reference[/]\
"""


_COMMANDS: list[tuple[str, str, str | None]] = [
    (
        "[bold cyan]kael[/] [bold white]help[/]",
        "Print this unified command + options reference.",
        None,
    ),
    (
        "[bold cyan]kael[/] [bold white]version[/]",
        "Print the kael version and exit.",
        "alias: -v",
    ),
    (
        "[bold cyan]kael[/] [bold white]<target>[/]",
        "Scan a single target in the TUI. The target is whatever comes first "
        "(URL, repo, path, domain, IP).",
        None,
    ),
    (
        "[bold cyan]kael[/] [bold white]scan <target>[/]",
        "Same as ``kael <target>`` but explicit. Use this when the target "
        "name could be confused with a keyword (e.g. a folder called ``resume``).",
        None,
    ),
    (
        "[bold cyan]kael[/] [bold white]resume [NAME][/]",
        "Resume a prior run. Defaults to the most recent run when NAME is omitted. "
        "``kael --resume [NAME]`` is also accepted.",
        None,
    ),
    (
        "[bold cyan]kael[/] [bold white]list [FOLDER][/]",
        "List runs and folders. Alias: [bold]ls[/].",
        None,
    ),
    (
        "[bold cyan]kael[/] [bold white]show [NAME][/]",
        "Show details of a run. Defaults to the most recent run.",
        None,
    ),
    (
        "[bold cyan]kael[/] [bold white]report [NAME][/]",
        "Print a run's penetration test report. Defaults to the most recent run.",
        None,
    ),
    (
        "[bold cyan]kael[/] [bold white]sessions ...[/]",
        "Full subcommand tree: list, show, report, resume, delete, move, folder ...",
        None,
    ),
    (
        "[bold cyan]kael[/] [bold white]sandbox build[/]",
        "Build the version-matched local sandbox image from this source checkout.",
        "option: --force",
    ),
    (
        "[bold cyan]kael[/] [bold white]demo [TOKENS_PER_SEC][/]",
        "Try the TUI with a scripted scan stream. No Docker or LLM needed.",
        None,
    ),
]


_SCAN_KEYWORDS: list[tuple[str, str, str | None, str | None]] = [
    (
        "[bold cyan]mode[/] [dim]<MODE>[/]",
        "Scan depth: quick (CI/CD), standard (routine), deep (thorough), "
        "malware_re (reverse engineering), or ctf (CTF challenges).",
        "deep",
        "quick | standard | deep | malware_re | ctf",
    ),
    (
        "[bold cyan]instruction[/] [dim]<TEXT>[/]",
        "Custom instructions for the scan (focus areas, test credentials, etc.).",
        None,
        None,
    ),
    (
        "[bold cyan]instruction-file[/] [dim]<PATH>[/]",
        "Read instructions from a file (useful for long, structured prompts).",
        None,
        None,
    ),
    (
        "[bold cyan]prompt[/] [dim]<TEXT>[/]",
        "Run a prompt-only scan with no target. The agent does whatever the "
        "prompt asks. Shortcut for `instruction` when you have no specific "
        "target (e.g. `kael prompt 'audit the k8s manifests in /tmp/k'`).",
        None,
        None,
    ),
    (
        "[bold cyan]scope-mode[/] [dim]<MODE>[/]",
        "Code-target scope: auto (PR diff in CI/headless), diff (force diff-scope), "
        "full (disable diff-scope).",
        "auto",
        "auto | diff | full",
    ),
    (
        "[bold cyan]diff-base[/] [dim]<REF>[/]",
        "Git ref to diff against (e.g. origin/main). Defaults to the repo's default branch.",
        None,
        None,
    ),
    (
        "[bold cyan]config[/] [dim]<PATH>[/]",
        "Path to a custom config JSON (overrides ~/.kael/cli-config.json).",
        None,
        None,
    ),
    (
        "[bold cyan]non-interactive[/]",
        "Run without launching the TUI; exit when the scan finishes. No value (it's a toggle).",
        None,
        None,
    ),
    (
        "[bold cyan]--build-sandbox[/]",
        "Build the local sandbox image if it is missing. KAEL_AUTO_BUILD_SANDBOX=1 is equivalent.",
        None,
        None,
    ),
]


_SESSIONS_COMMANDS: list[tuple[str, str, str]] = [
    (
        "kael sessions list [FOLDER]",
        "[FOLDER] [--json]",
        "List runs and folders one level deep under kael_runs/[FOLDER].",
    ),
    (
        "kael sessions show [RUN]",
        "[RUN] [--json]",
        "Show details of a run. Defaults to the most recent run.",
    ),
    (
        "kael sessions report [RUN]",
        "[RUN] [--vulns] [--json]",
        "Print a run's penetration test report. Defaults to the most recent run.",
    ),
    (
        "kael sessions resume [RUN]",
        "[RUN] [--instruction TEXT] [--instruction-file PATH]",
        "Resume a prior run. Defaults to the most recent run.",
    ),
    (
        "kael sessions delete <RUN>...",
        "<RUN> [<RUN> ...] [-y|--yes]",
        "Delete one or more runs (irreversible). Folders are refused.",
    ),
    (
        "kael sessions move <RUN> <FOLDER>",
        "<RUN> <FOLDER> [-y|--yes]",
        "Move a run into a folder (auto-creates the folder).",
    ),
    (
        "kael sessions folder create <NAME>...",
        "<NAME> [<NAME> ...] [-y|--yes]",
        "Create one or more empty folders under kael_runs/.",
    ),
    (
        "kael sessions folder list",
        "[--json]",
        "List folders directly under kael_runs/.",
    ),
    (
        "kael sessions folder delete <NAME>...",
        "<NAME> [<NAME> ...] [-y|--yes]",
        "Delete one or more empty folders (refuses non-empty).",
    ),
]


_EXAMPLES: list[tuple[str, str | None]] = [
    ("  kael https://example.com", None),
    ("  kael ./my-project", None),
    ("  kael git@github.com:user/repo.git", None),
    ("  kael scan ./sample.exe mode malware_re", "# malware reverse engineering"),
    ("  kael . non-interactive", "# scan the current working directory, no TUI"),
    ("  kael sandbox build", "# build kael-sandbox:0.1.0 locally"),
    ('  kael example.com instruction "Focus on auth bypass"', None),
    ("  kael example.com mode deep instruction-file ./prompts.md", None),
    (
        '  kael prompt "audit the staging k8s cluster for misconfigurations"',
        "# prompt-only run, no target",
    ),
    ("  kael list", None),
    ("  kael show", "# show most recent run"),
    ("  kael report --vulns", "# most recent report + every finding"),
    ("  kael resume", "# resume the most recent run"),
    ("  kael sessions delete <RUN> -y", None),
    ("  kael sessions folder create acme training", None),
]


def _build_usage_panel() -> Panel:
    return Panel(
        Text.from_markup(_USAGE),
        title="[bold]USAGE[/]",
        border_style="#22c55e",
        padding=(0, 1),
    )


def _build_commands_table() -> Table:
    table = Table(
        title="TOP-LEVEL COMMANDS",
        title_justify="left",
        show_header=True,
        header_style="bold #22c55e",
        border_style="#22c55e",
        expand=True,
    )
    table.add_column("USAGE", style="bold white", no_wrap=True)
    table.add_column("DESCRIPTION", overflow="fold")
    for usage, desc, note in _COMMANDS:
        if note:
            table.add_row(usage, f"{desc}  [dim]({note})[/]")
        else:
            table.add_row(usage, desc)
    return table


def _build_scan_keywords_table() -> Table:
    table = Table(
        title="SCAN KEYWORDS",
        title_justify="left",
        show_header=True,
        header_style="bold #60a5fa",
        border_style="#60a5fa",
        expand=True,
    )
    table.add_column("KEYWORD", style="bold white", no_wrap=True)
    table.add_column("DESCRIPTION", overflow="fold")
    for kw, desc, default, choices in _SCAN_KEYWORDS:
        hint_parts: list[str] = []
        if default:
            hint_parts.append(f"[dim](default: {default})[/]")
        if choices:
            hint_parts.append(f"[dim]choices: {choices}[/]")
        if hint_parts:
            full_desc = f"{desc}  {' '.join(hint_parts)}" if desc else " ".join(hint_parts)
        else:
            full_desc = desc or ""
        table.add_row(kw, full_desc)
    return table


def _build_sessions_table() -> Table:
    table = Table(
        title="SESSIONS SUBCOMMANDS",
        title_justify="left",
        show_header=True,
        header_style="bold #60a5fa",
        border_style="#60a5fa",
        expand=True,
    )
    table.add_column("COMMAND", style="bold white", no_wrap=True)
    table.add_column("ARGUMENTS / OPTIONS", overflow="fold")
    table.add_column("DESCRIPTION", overflow="fold")
    for cmd, args, desc in _SESSIONS_COMMANDS:
        args_styled = " ".join(
            f"[bold cyan]{token}[/]" if not token.startswith("[") else token
            for token in args.split()
        )
        table.add_row(cmd, args_styled, desc)
    return table


def _build_examples_panel() -> Panel:
    body = Text()
    for text, comment in _EXAMPLES:
        body.append(text, style="bold white")
        if comment:
            body.append("  " + comment, style="dim")
        body.append("\n")
    return Panel(body, title="[bold]EXAMPLES[/]", border_style="#60a5fa", padding=(0, 1))


def print_full_help(console: Console | None = None) -> None:
    """Print the unified command + options reference."""
    console = console or Console()
    console.print()
    console.print(_build_usage_panel())
    console.print()
    console.print(_build_commands_table())
    console.print()
    console.print(_build_scan_keywords_table())
    console.print()
    console.print(_build_sessions_table())
    console.print()
    console.print(_build_examples_panel())
    console.print()
