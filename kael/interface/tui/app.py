"""Kael TUI - main Textual app.

Rendering is push-driven: the scan thread posts Textual messages
(``SdkEvent``, ``GraphChanged``, ``NewFinding``, ``ScanFinished``) and each
handler updates exactly the widgets that changed. Nothing polls.
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import logging
import shutil
import signal
import subprocess
import sys
import threading
from datetime import UTC, datetime
from functools import lru_cache, partial
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    ContentSwitcher,
    Footer,
    Header,
    Label,
    ListItem,
    ListView,
    LoadingIndicator,
    Markdown,
    Static,
    TextArea,
    Tree,
)

from kael.config import load_settings
from kael.config.models import openrouter_extra_body
from kael.core.runner import run_kael_scan
from kael.interface.tui.live_view import TuiLiveView
from kael.interface.tui.messages import send_user_message_to_agent
from kael.interface.tui.settings import SettingsScreen
from kael.interface.tui.theme import KAEL_THEME
from kael.interface.tui.widgets import (
    MAX_MOUNTED_EVENTS,
    ChatStream,
    agent_label,
    make_event_widget,
    update_event_widget,
)
from kael.interface.utils import (
    assign_workspace_subdirs,
    build_tui_stats_text,
    collect_local_sources,
    get_severity_color,
    infer_target_type,
    rewrite_localhost_targets,
)
from kael.report.state import ReportState, set_global_report_state
from kael.runtime import session_manager


if TYPE_CHECKING:
    import argparse
    from collections.abc import Iterable

    from textual.screen import Screen
    from textual.theme import Theme
    from textual.timer import Timer
    from textual.widget import Widget
    from textual.widgets.tree import TreeNode


HOST_GATEWAY_HOSTNAME = "host.docker.internal"

WELCOME_MD = """\
# kael

Autonomous penetration-testing agent.

**Enter a target** below to start a scan:

- `https://example.com` — web application
- `https://github.com/user/repo` — repository
- `./my-project` — local code
- `example.com` or `10.0.0.5` — host

Or type a free-form prompt to run without a target. Add a blank line, \
then extra instructions.

`Enter` send · `ctrl+j` newline · `ctrl+p` commands · `F6` provider · `F7` model · `F8` settings · `F1` help · `ctrl+q` quit
"""

logger = logging.getLogger(__name__)


def _copy_to_system_clipboard(text: str) -> bool:
    """Best-effort copy to the OS clipboard via a subprocess tool.

    Tries platform-specific helpers in order. Returns True on the first
    one that is on ``PATH`` and exits 0; False if none worked (or the
    subprocess raised). Textual's OSC52 path is a separate fallback in
    the caller — this function only handles the system side.

    Stdlib only, no extra deps.
    """
    commands: list[tuple[str, ...]] = [
        ("pbcopy",),
        ("xclip", "-selection", "clipboard"),
        ("xsel", "--clipboard", "--input"),
        ("wl-copy",),
        ("clip.exe",),
        ("clip",),
    ]
    for cmd in commands:
        binary = cmd[0]
        if not shutil.which(binary):
            continue
        try:
            # ``cmd`` is a hardcoded tuple from the local allow-list above;
            # ``input`` is the user's selected text being piped to stdin of
            # the clipboard tool, not a shell command. ``stdout=DEVNULL`` /
            # ``stderr=DEVNULL`` avoids the stdin-pipe deadlock that happens
            # with ``capture_output=True`` on tools like ``xclip`` that
            # never close their stdout before exit.
            completed = subprocess.run(  # noqa: S603
                cmd,
                input=text,
                text=True,
                timeout=2,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.debug("Clipboard helper %s failed: %s", binary, exc)
            continue
        if completed.returncode == 0:
            return True
        logger.debug(
            "Clipboard helper %s returned %d: %s",
            binary,
            completed.returncode,
            completed.stderr.strip(),
        )
    return False


@lru_cache(maxsize=1)
def get_package_version() -> str:
    try:
        return pkg_version("kael-agent")
    except PackageNotFoundError:
        return "dev"


# --- messages posted from the scan thread ---------------------------------


class SdkEvent(Message):
    def __init__(self, agent_id: str, event: Any) -> None:
        super().__init__()
        self.agent_id = agent_id
        self.event = event


class GraphChanged(Message):
    def __init__(
        self,
        parent_of: dict[str, str | None],
        statuses: dict[str, str],
        names: dict[str, str],
    ) -> None:
        super().__init__()
        self.parent_of = parent_of
        self.statuses = statuses
        self.names = names


class NewFinding(Message):
    def __init__(self, report: dict[str, Any]) -> None:
        super().__init__()
        self.report = report


class ScanFinished(Message):
    def __init__(self, error: BaseException | None) -> None:
        super().__init__()
        self.error = error


# --- widgets ---------------------------------------------------------------


class ChatTextArea(TextArea):  # type: ignore[misc]
    class Submitted(Message):
        def __init__(self, text: str) -> None:
            super().__init__()
            self.text = text

    def on_mount(self) -> None:
        self._update_height()

    async def _on_key(self, event: events.Key) -> None:
        # ctrl+j is delivered by every terminal; shift+enter only by ones
        # speaking the kitty keyboard protocol.
        if event.key in ("ctrl+j", "shift+enter"):
            self.insert("\n")
            event.prevent_default()
            event.stop()
            return
        if event.key == "enter":
            event.prevent_default()
            event.stop()
            message = str(self.text).strip()
            if message:
                self.text = ""
                self.post_message(self.Submitted(message))
            return
        await super()._on_key(event)

    @on(TextArea.Changed)  # type: ignore[misc]
    def _update_height(self, _event: TextArea.Changed | None = None) -> None:
        if not self.parent:
            return
        target_lines = min(max(1, self.document.line_count), 8)
        new_height = target_lines + 2
        if self.parent.styles.height != new_height:
            self.parent.styles.height = new_height
            self.scroll_cursor_visible()


class StopAgentScreen(ModalScreen):  # type: ignore[misc]
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "dismiss", "Cancel"),
        Binding("left,up", "app.focus_previous", show=False),
        Binding("right,down", "app.focus_next", show=False),
    ]

    def __init__(self, agent_name: str, agent_id: str):
        super().__init__()
        self.agent_name = agent_name
        self.agent_id = agent_id

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(f"Stop '{self.agent_name}'?", id="stop_agent_title"),
            Grid(
                Button("Yes", variant="error", id="stop_agent"),
                Button("No", variant="default", id="cancel_stop"),
                id="stop_agent_buttons",
            ),
            id="stop_agent_dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#cancel_stop", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()
        if event.button.id == "stop_agent":
            self.app.action_confirm_stop_agent(self.agent_id)


class VulnerabilityDetailScreen(ModalScreen):  # type: ignore[misc]
    BINDINGS: ClassVar[list[Binding]] = [Binding("escape", "dismiss", "Close")]

    def __init__(self, vulnerability: dict[str, Any]) -> None:
        super().__init__()
        self.vulnerability = vulnerability

    def compose(self) -> ComposeResult:
        yield Grid(
            VerticalScroll(
                Markdown(self._get_markdown_report(), open_links=False, id="vuln_detail_content"),
                id="vuln_detail_scroll",
            ),
            Horizontal(
                Button("Copy", variant="default", id="copy_vuln_detail"),
                Button("Done", variant="default", id="close_vuln_detail"),
                id="vuln_detail_buttons",
            ),
            id="vuln_detail_dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#close_vuln_detail", Button).focus()

    def _get_markdown_report(self) -> str:
        """Markdown version of the report (rendered here and copied)."""
        vuln = self.vulnerability
        lines: list[str] = []

        title = vuln.get("title", "Untitled Vulnerability")
        lines.append(f"# {title}")
        lines.append("")

        # One bullet per field: consecutive plain lines would merge into
        # a single paragraph when rendered as markdown.
        if vuln.get("id"):
            lines.append(f"- **ID:** {vuln['id']}")
        if vuln.get("severity"):
            lines.append(f"- **Severity:** {vuln['severity'].upper()}")
        if vuln.get("timestamp"):
            lines.append(f"- **Found:** {vuln['timestamp']}")
        if vuln.get("agent_name"):
            lines.append(f"- **Agent:** {vuln['agent_name']}")
        if vuln.get("target"):
            lines.append(f"- **Target:** {vuln['target']}")
        if vuln.get("endpoint"):
            lines.append(f"- **Endpoint:** {vuln['endpoint']}")
        if vuln.get("method"):
            lines.append(f"- **Method:** {vuln['method']}")
        if vuln.get("cve"):
            lines.append(f"- **CVE:** {vuln['cve']}")
        if vuln.get("cvss") is not None:
            lines.append(f"- **CVSS:** {vuln['cvss']}")

        cvss_breakdown = vuln.get("cvss_breakdown", {})
        if cvss_breakdown:
            abbrevs = {
                "attack_vector": "AV",
                "attack_complexity": "AC",
                "privileges_required": "PR",
                "user_interaction": "UI",
                "scope": "S",
                "confidentiality": "C",
                "integrity": "I",
                "availability": "A",
            }
            parts = [
                f"{abbrevs.get(k, k)}:{v}" for k, v in cvss_breakdown.items() if v and k in abbrevs
            ]
            if parts:
                lines.append(f"- **CVSS Vector:** {'/'.join(parts)}")

        lines.append("")
        lines.append("## Description")
        lines.append("")
        lines.append(vuln.get("description") or "No description provided.")

        if vuln.get("impact"):
            lines.extend(["", "## Impact", "", vuln["impact"]])

        if vuln.get("technical_analysis"):
            lines.extend(["", "## Technical Analysis", "", vuln["technical_analysis"]])

        if vuln.get("poc_description") or vuln.get("poc_script_code"):
            lines.extend(["", "## Proof of Concept", ""])
            if vuln.get("poc_description"):
                lines.append(vuln["poc_description"])
                lines.append("")
            if vuln.get("poc_script_code"):
                lines.append("```python")
                lines.append(vuln["poc_script_code"])
                lines.append("```")

        if vuln.get("code_locations"):
            lines.extend(["", "## Code Analysis", ""])
            for i, loc in enumerate(vuln["code_locations"]):
                file_ref = loc.get("file", "unknown")
                line_ref = ""
                if loc.get("start_line") is not None:
                    if loc.get("end_line") and loc["end_line"] != loc["start_line"]:
                        line_ref = f" (lines {loc['start_line']}-{loc['end_line']})"
                    else:
                        line_ref = f" (line {loc['start_line']})"
                lines.append(f"**Location {i + 1}:** `{file_ref}`{line_ref}")
                if loc.get("label"):
                    lines.append(f"  {loc['label']}")
                if loc.get("snippet"):
                    lines.append(f"```\n{loc['snippet']}\n```")
                if loc.get("fix_before") or loc.get("fix_after"):
                    lines.append("**Suggested Fix:**")
                    lines.append("```diff")
                    if loc.get("fix_before"):
                        lines.extend(f"- {line}" for line in loc["fix_before"].splitlines())
                    if loc.get("fix_after"):
                        lines.extend(f"+ {line}" for line in loc["fix_after"].splitlines())
                    lines.append("```")
                lines.append("")

        if vuln.get("remediation_steps"):
            lines.extend(["", "## Remediation", "", vuln["remediation_steps"]])

        lines.append("")
        return "\n".join(lines)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy_vuln_detail":
            self.app.copy_text(self._get_markdown_report())
            copy_button = self.query_one("#copy_vuln_detail", Button)
            copy_button.label = "Copied!"
            self.set_timer(1.5, lambda: setattr(copy_button, "label", "Copy"))
        else:
            self.dismiss()


class QuitScreen(ModalScreen):  # type: ignore[misc]
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "dismiss", "Cancel"),
        Binding("left,up", "app.focus_previous", show=False),
        Binding("right,down", "app.focus_next", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Quit Kael?", id="quit_title"),
            Grid(
                Button("Yes", variant="error", id="quit"),
                Button("No", variant="default", id="cancel"),
                id="quit_buttons",
            ),
            id="quit_dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            await self.app.action_custom_quit()
        else:
            self.dismiss()


# --- app -------------------------------------------------------------------


class KaelTUIApp(App):  # type: ignore[misc]
    CSS_PATH = str(Path(__file__).resolve().parent.parent / "assets" / "tui_styles.tcss")
    ALLOW_SELECT = True

    SIDEBAR_MIN_WIDTH = 120

    selected_agent_id: reactive[str | None] = reactive(default=None)

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("f1", "toggle_help", "Help"),
        Binding("f6", "change_openrouter_provider", "Provider", priority=True),
        Binding("f7", "change_model", "Model", priority=True),
        Binding("f8", "edit_settings", "Settings", priority=True),
        Binding("ctrl+q", "request_quit", "Quit", priority=True),
        # No priority: TextArea copy → screen copy-selection → quit, each
        # skipping itself when there is nothing to copy.
        Binding("ctrl+c", "request_quit", "Quit", show=False),
        Binding("escape", "escape", "Stop agent", priority=True),
        Binding("ctrl+o", "toggle_fold_all", "Fold"),
        Binding("ctrl+up,alt+up", "cycle_agent(-1)", "Prev agent", key_display="^↑"),
        Binding("ctrl+down,alt+down", "cycle_agent(1)", "Next agent", key_display="^↓"),
        Binding("ctrl+g", "jump_to_latest", "Latest", show=False),
        Binding("ctrl+b", "toggle_sidebar", "Sidebar", show=False),
    ]

    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self.args = args

        # Prompt-only mode: no target, but a prompt is set. Start the scan
        # immediately instead of showing the "enter a target" welcome.
        self._prompt_only: bool = bool(getattr(args, "prompt_only", False)) or (
            not bool(args.targets_info) and bool((args.instruction or "").strip())
        )
        self._awaiting_target: bool = not bool(args.targets_info) and not self._prompt_only
        self._prompt_injected: bool = False

        self.scan_config = self._build_scan_config(args)

        self.report_state = ReportState(self.scan_config["run_name"])
        self.report_state.hydrate_from_run_dir()
        self.report_state.set_scan_config(self.scan_config)
        self.report_state.save_run_data()
        set_global_report_state(self.report_state)
        self.live_view = TuiLiveView()
        self.live_view.hydrate_from_run_dir(self.report_state.get_run_dir())

        from kael.core.agents import AgentCoordinator

        self.coordinator = AgentCoordinator()

        self.agent_nodes: dict[str, TreeNode] = {}
        self._unread: dict[str, int] = {}
        self._populated_agents: set[str] = set()
        self._mounted_versions: dict[str, int] = {}
        self._findings: list[dict[str, Any]] = []
        self._palette: dict[str, str] = {}
        self._unseen_below = False
        self._tick_count = 0
        self._tick_timer: Timer | None = None
        self._sidebar_user_hidden = False
        self._mouse_up_had_selection = False
        self._last_stats_plain: str | None = None

        self._scan_thread: threading.Thread | None = None
        self._scan_loop: asyncio.AbstractEventLoop | None = None
        self._scan_stop_event = threading.Event()
        self._scan_completed = threading.Event()
        self._scan_error: BaseException | None = None

        self._setup_cleanup_handlers()

    def _build_scan_config(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "scan_id": args.run_name,
            "targets": args.targets_info,
            "user_instructions": args.instruction or "",
            "run_name": args.run_name,
            "diff_scope": getattr(args, "diff_scope", {"active": False}),
            "scan_mode": getattr(args, "scan_mode", "deep"),
            "non_interactive": bool(getattr(args, "non_interactive", False)),
            "local_sources": getattr(args, "local_sources", None) or [],
            "scope_mode": getattr(args, "scope_mode", "auto"),
            "diff_base": getattr(args, "diff_base", None),
            "resume_instruction": getattr(args, "user_explicit_instruction", None) or "",
            "prompt_only": self._prompt_only,
        }

    def _setup_cleanup_handlers(self) -> None:
        def cleanup_on_exit() -> None:
            self.report_state.cleanup()

        def signal_handler(_signum: int, _frame: Any) -> None:
            self._fire_sandbox_cleanup()
            self.report_state.cleanup(status="interrupted")
            sys.exit(0)

        atexit.register(cleanup_on_exit)
        # ctrl+c never reaches us as SIGINT: Textual's driver runs the
        # terminal with ISIG off, so it arrives as a key binding instead.
        signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)

    # --- layout ------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(icon="◆")
        with Horizontal(id="content_container"):
            with Vertical(id="chat_area_container"):
                with ContentSwitcher(
                    id="chat_area",
                    initial="welcome" if self._awaiting_target else "placeholder",
                ):
                    yield Markdown(WELCOME_MD, id="welcome", open_links=False)
                    yield Static("Starting agent…", id="placeholder", classes="chat-placeholder")
                yield Static("", id="new_messages")
                with Horizontal(id="status_row"):
                    yield LoadingIndicator(id="spinner")
                    yield Static("", id="status_text")
                with Horizontal(id="chat_input_container"):
                    yield Static("›", id="chat_prompt")
                    yield ChatTextArea(
                        "",
                        id="chat_input",
                        show_line_numbers=False,
                        placeholder=self._input_placeholder(),
                    )
            with Vertical(id="sidebar"):
                yield Tree("Agents", id="agents_tree")
                yield ListView(id="findings")
                with VerticalScroll(id="stats_scroll"):
                    yield Static("", id="stats_display")
                    yield Static("", id="elapsed_display")
        yield Footer()

    def _input_placeholder(self) -> str:
        if self._awaiting_target:
            return "Enter a target (URL, repo, path, domain, IP) or a free-form prompt"
        return "Message the agent · Enter sends · ctrl+j newline · ctrl+p commands"

    def on_mount(self) -> None:
        self.register_theme(KAEL_THEME)
        self.theme = "kael"
        self.title = "kael"
        self.sub_title = self._subtitle()
        self._palette = self.get_css_variables()
        self.theme_changed_signal.subscribe(self, self._on_theme_changed)

        tree = self.query_one("#agents_tree", Tree)
        tree.show_root = False
        tree.guide_depth = 3
        tree.root.expand()
        tree.border_title = "agents"
        self.query_one("#findings", ListView).border_title = "findings"
        self.query_one("#stats_scroll", VerticalScroll).border_title = "session"
        self.query_one("#new_messages", Static).display = False
        self.query_one("#status_row", Horizontal).display = False

        self.coordinator.on_change = self._on_coordinator_change
        self.report_state.vulnerability_found_callback = self._on_vulnerability_found
        for report in self.report_state.vulnerability_reports:
            self._append_finding(report)

        # Resume: agents and history were hydrated in __init__.
        for agent in list(self.live_view.agents.values()):
            self._ensure_agent_node(agent)

        if not self._awaiting_target:
            self._start_scan_thread()

        self._tick_timer = self.set_interval(1.0, self._tick)
        self._update_elapsed()
        self._update_stats_display()
        self._refresh_status()
        self.query_one("#chat_input", ChatTextArea).focus()

    def _subtitle(self) -> str:
        parts: list[str] = []
        targets = self.scan_config.get("targets") or []
        if targets:
            parts.append(str(targets[0].get("original") or targets[0].get("type") or "target"))
        elif self._prompt_only:
            parts.append("prompt-only")
        parts.append(str(self.scan_config.get("run_name") or ""))
        llm = load_settings().llm
        model = llm.model
        if model:
            parts.append(str(model))
        active = self.coordinator.run_config
        if (
            active
            and isinstance(active.model, str)
            and (
                active.model != model
                or (
                    self.coordinator.model_uses_chat_completions is not None
                    and self.coordinator.model_api_base != llm.api_base
                )
            )
        ):
            parts.append(f"active model: {active.model}; pending configuration requires a new run")
        if openrouter_extra_body(model or "", llm.openrouter_provider, llm.api_base):
            only = (llm.openrouter_provider or {}).get("only")
            provider = only[0] if isinstance(only, list) and len(only) == 1 else "custom routing"
            parts.append(f"provider: {provider}")
        return " · ".join(p for p in parts if p)

    def _on_theme_changed(self, _theme: Theme) -> None:
        self._palette = self.get_css_variables()
        for agent_id in list(self.agent_nodes):
            self._relabel_agent(agent_id)

    # --- scan thread bridge ------------------------------------------------

    def _post_threadsafe(self, message: Message) -> None:
        """post_message from the scan thread; harmless once the app is gone."""
        with contextlib.suppress(RuntimeError):
            self.post_message(message)

    def _capture_sdk_event(self, agent_id: str, event: Any) -> None:
        self._post_threadsafe(SdkEvent(agent_id, event))

    def _on_coordinator_change(self) -> None:
        coordinator = self.coordinator
        self._post_threadsafe(
            GraphChanged(
                dict(coordinator.parent_of),
                dict(coordinator.statuses),
                dict(coordinator.names),
            )
        )

    def _on_vulnerability_found(self, report: dict[str, Any]) -> None:
        self._post_threadsafe(NewFinding(dict(report)))

    def _start_scan_thread(self) -> None:
        if not (load_settings().llm.model or "").strip():
            self.notify("Choose a model with F7 or configure settings with F8 before starting.")
            return

        def scan_target() -> None:
            error: BaseException | None = None
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._scan_loop = loop

                try:
                    if not self._scan_stop_event.is_set():
                        image = load_settings().runtime.image
                        loop.run_until_complete(
                            run_kael_scan(
                                scan_config=self.scan_config,
                                scan_id=self.scan_config["run_name"],
                                image=str(image),
                                local_sources=getattr(self.args, "local_sources", None) or [],
                                coordinator=self.coordinator,
                                interactive=True,
                                event_sink=self._capture_sdk_event,
                            ),
                        )

                except (KeyboardInterrupt, asyncio.CancelledError):
                    logger.info("Scan interrupted by user")
                except Exception as e:
                    logging.exception("Error during scan")
                    self._scan_error = error = e
                finally:
                    with contextlib.suppress(Exception):
                        loop.run_until_complete(
                            session_manager.cleanup(self.scan_config["run_name"]),
                        )
                    loop.close()
                    self._scan_completed.set()

            except Exception as e:
                logging.exception("Error setting up scan thread")
                error = e
                self._scan_completed.set()
            self._post_threadsafe(ScanFinished(error))

        self._scan_thread = threading.Thread(target=scan_target, daemon=True)
        self._scan_thread.start()

    # --- message handlers --------------------------------------------------

    async def on_sdk_event(self, message: SdkEvent) -> None:
        for event in self.live_view.ingest_sdk_event(message.agent_id, message.event):
            await self._sync_event(event)

    async def on_graph_changed(self, message: GraphChanged) -> None:
        previous = {aid: a.get("status") for aid, a in self.live_view.agents.items()}
        for agent_id, status in message.statuses.items():
            self.live_view.upsert_agent(
                agent_id,
                name=message.names.get(agent_id, agent_id),
                parent_id=message.parent_of.get(agent_id),
                status=status,
            )
            self._ensure_agent_node(self.live_view.agents[agent_id])
            self._relabel_agent(agent_id)
            old = previous.get(agent_id)
            if old is not None and old != status and status in {"completed", "failed", "crashed"}:
                name = message.names.get(agent_id, agent_id)
                self.notify(
                    f"{name} {status}",
                    severity="information" if status == "completed" else "error",
                )
        await self._maybe_inject_prompt_message(message.parent_of, message.statuses)
        self._refresh_status()
        self._update_stats_display()

    def on_new_finding(self, message: NewFinding) -> None:
        report = message.report
        self._append_finding(report)
        agent_id = report.get("agent_id")
        if isinstance(agent_id, str):
            self._relabel_agent(agent_id)
        severity = str(report.get("severity") or "info").lower()
        self.notify(
            f"[{severity.upper()}] {report.get('title', 'Untitled')}",
            title="New finding",
            severity="error"
            if severity in {"critical", "high"}
            else "warning"
            if severity == "medium"
            else "information",
        )

    def on_scan_finished(self, message: ScanFinished) -> None:
        self._refresh_status()
        self._update_stats_display()
        if message.error is not None:
            self.notify(f"Scan failed: {message.error}", severity="error", timeout=10)
        else:
            self.notify("Scan finished", timeout=5)

    @on(ChatTextArea.Submitted)  # type: ignore[misc]
    async def on_chat_submitted(self, message: ChatTextArea.Submitted) -> None:
        await self._send_user_message(message.text)
        if self._awaiting_target:
            self.query_one("#chat_input", ChatTextArea).text = message.text

    @on(ListView.Selected, "#findings")  # type: ignore[misc]
    def on_finding_selected(self, event: ListView.Selected) -> None:
        if 0 <= event.index < len(self._findings):
            self.push_screen(VulnerabilityDetailScreen(self._findings[event.index]))

    @on(Tree.NodeHighlighted)  # type: ignore[misc]
    def handle_tree_highlight(self, event: Tree.NodeHighlighted) -> None:
        node = event.node
        if self.focused is event.control and node.data:
            agent_id = node.data.get("agent_id")
            if agent_id:
                self.selected_agent_id = agent_id

    @on(Tree.NodeSelected)  # type: ignore[misc]
    def handle_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        node = event.node
        if node.allow_expand:
            node.toggle()

    @on(Markdown.LinkClicked)  # type: ignore[misc]
    def on_link_clicked(self, event: Markdown.LinkClicked) -> None:
        self.copy_text(event.href)

    async def watch_selected_agent_id(self, agent_id: str | None) -> None:
        if agent_id is None or not self.is_running:
            return
        self._unread.pop(agent_id, None)
        container = await self._agent_container(agent_id)
        if agent_id not in self._populated_agents:
            await self._sync_agent(agent_id)
        self.query_one("#chat_area", ContentSwitcher).current = container.id
        self.call_after_refresh(container.maybe_anchor)
        self._hide_new_messages()
        self._relabel_agent(agent_id)
        self._refresh_status()

    # --- chat --------------------------------------------------------------

    async def _agent_container(self, agent_id: str) -> ChatStream:
        # Agent ids may start with a digit, which is not a valid DOM id.
        container_id = f"agent-{agent_id}"
        switcher = self.query_one("#chat_area", ContentSwitcher)
        try:
            return switcher.get_child_by_id(container_id, ChatStream)
        except NoMatches:
            container = ChatStream(id=container_id)
            await switcher.add_content(container)
            return container

    async def _sync_agent(self, agent_id: str) -> None:
        """Mount the agent's recent events (first view of that agent)."""
        container = await self._agent_container(agent_id)
        self._populated_agents.add(agent_id)
        events_ = self.live_view.events_for_agent(agent_id)[-MAX_MOUNTED_EVENTS:]
        widgets: list[Widget] = []
        for event in events_:
            widgets.append(make_event_widget(event))
            self._mounted_versions[event["id"]] = int(event.get("version", 0))
        if widgets:
            with self.batch_update():
                await container.mount_all(widgets)

    async def _sync_event(self, event: dict[str, Any]) -> None:
        """Reflect one new/changed event in its agent's chat container."""
        agent_id = event["agent_id"]
        selected = agent_id == self.selected_agent_id
        if agent_id not in self._populated_agents:
            await self._sync_agent(agent_id)
            if not selected:
                self._unread[agent_id] = self._unread.get(agent_id, 0) + 1
                self._relabel_agent(agent_id)
            return
        container = await self._agent_container(agent_id)
        event_id = event["id"]
        version = int(event.get("version", 0))
        try:
            widget: Widget | None = container.get_child_by_id(event_id)
        except NoMatches:
            widget = None
        if widget is not None:
            if self._mounted_versions.get(event_id) != version:
                self._mounted_versions[event_id] = version
                update_event_widget(widget, event)
                if selected and not container.is_vertical_scroll_end:
                    self._show_new_messages()
            return

        at_end = container.is_vertical_scroll_end
        first_event = not container.children
        self._mounted_versions[event_id] = version
        await container.mount(make_event_widget(event))
        if not selected:
            self._unread[agent_id] = self._unread.get(agent_id, 0) + 1
            self._relabel_agent(agent_id)
        elif first_event:
            self._refresh_status()  # "starting" → "working"
        elif not at_end:
            self._show_new_messages()
        if len(container.children) > MAX_MOUNTED_EVENTS:
            oldest = container.children[0]
            if oldest.id:
                self._mounted_versions.pop(oldest.id, None)
            await oldest.remove()

    def _show_new_messages(self) -> None:
        if not self._unseen_below:
            self._unseen_below = True
            pill = self.query_one("#new_messages", Static)
            pill.update("↓ new messages below · click or ctrl+g")
            pill.display = True

    def _hide_new_messages(self) -> None:
        self._unseen_below = False
        self.query_one("#new_messages", Static).display = False

    def _selected_container(self) -> ChatStream | None:
        if not self.selected_agent_id:
            return None
        try:
            return self.query_one(f"#agent-{self.selected_agent_id}", ChatStream)
        except NoMatches:
            return None

    async def _maybe_inject_prompt_message(
        self,
        parent_of: dict[str, str | None],
        statuses: dict[str, Any],
    ) -> None:
        """Inject the initial prompt as a chat event for the root agent.

        Only fires once, in prompt-only mode (no target, prompt set on the
        CLI). The synthetic user message appears at the top of the chat so
        the user can see what they asked before the agent's response.
        """
        if not self._prompt_only or self._prompt_injected:
            return
        prompt = (self.args.instruction or "").strip()
        if not prompt:
            return
        for agent_id, parent in parent_of.items():
            if parent is None and agent_id in statuses:
                self._prompt_injected = True
                await self._sync_event(self.live_view.record_user_message(agent_id, prompt))
                return

    # --- sidebar -----------------------------------------------------------

    def _ensure_agent_node(self, agent: dict[str, Any]) -> None:
        agent_id = agent["id"]
        if agent_id in self.agent_nodes:
            return
        tree = self.query_one("#agents_tree", Tree)
        parent_id = agent.get("parent_id")
        parent_node = self.agent_nodes.get(parent_id) if parent_id else None
        node = (parent_node or tree.root).add(
            self._label_for(agent_id), data={"agent_id": agent_id}, expand=True
        )
        if parent_node is not None:
            parent_node.allow_expand = True
        node.allow_expand = False
        self.agent_nodes[agent_id] = node

        if len(self.agent_nodes) == 1:
            tree.select_node(node)
            self.selected_agent_id = agent_id

        self._reorganize_orphaned_agents(agent_id)

    def _label_for(self, agent_id: str) -> Text:
        agent = self.live_view.agents.get(agent_id, {})
        return agent_label(
            str(agent.get("name") or agent_id),
            str(agent.get("status") or "running"),
            vuln_count=self._agent_vulnerability_count(agent_id),
            unread=self._unread.get(agent_id, 0),
            palette=self._palette,
        )

    def _relabel_agent(self, agent_id: str) -> None:
        node = self.agent_nodes.get(agent_id)
        if node is None:
            return
        label = self._label_for(agent_id)
        if node.label != label:
            node.set_label(label)

    def _copy_node_under(self, node_to_copy: TreeNode, new_parent: TreeNode) -> None:
        agent_id = node_to_copy.data["agent_id"]
        new_node = new_parent.add(self._label_for(agent_id), data=node_to_copy.data)
        new_node.allow_expand = node_to_copy.allow_expand
        self.agent_nodes[agent_id] = new_node
        for child in node_to_copy.children:
            self._copy_node_under(child, new_node)
        if node_to_copy.is_expanded:
            new_node.expand()

    def _reorganize_orphaned_agents(self, new_parent_id: str) -> None:
        """Children that arrived before their parent get re-homed under it.

        ``TreeNode`` has no reparent, so the subtree is copied and the old
        node removed.
        """
        parent_node = self.agent_nodes[new_parent_id]
        moved = False
        for agent_id, agent in list(self.live_view.agents.items()):
            if agent.get("parent_id") != new_parent_id or agent_id == new_parent_id:
                continue
            old_node = self.agent_nodes.get(agent_id)
            if old_node is None or old_node.parent is parent_node:
                continue
            self._copy_node_under(old_node, parent_node)
            old_node.remove()
            moved = True
        if moved:
            parent_node.allow_expand = True
            parent_node.expand()

    def _tree_order(self) -> list[str]:
        order: list[str] = []

        def walk(node: TreeNode) -> None:
            for child in node.children:
                if child.data:
                    order.append(child.data["agent_id"])
                walk(child)

        walk(self.query_one("#agents_tree", Tree).root)
        return order

    def _agent_vulnerability_count(self, agent_id: str) -> int:
        return sum(
            1
            for vuln in self.report_state.vulnerability_reports
            if vuln.get("agent_id") == agent_id
        )

    def _append_finding(self, report: dict[str, Any]) -> None:
        report = dict(report)
        agent_id = report.get("agent_id")
        if not report.get("agent_name") and isinstance(agent_id, str):
            report["agent_name"] = self._get_agent_name(agent_id)
        self._findings.append(report)
        severity = str(report.get("severity") or "info").lower()
        label = Text()
        label.append("● ", style=get_severity_color(severity))
        label.append(str(report.get("title") or "Untitled"))
        findings = self.query_one("#findings", ListView)
        findings.append(ListItem(Static(label)))
        findings.border_title = f"findings ({len(self._findings)})"
        findings.display = True

    def _get_agent_name(self, agent_id: str) -> str:
        name = self.live_view.agents.get(agent_id, {}).get("name")
        return name if isinstance(name, str) else "Unknown Agent"

    # --- status / stats ----------------------------------------------------

    def _refresh_status(self) -> None:
        row = self.query_one("#status_row", Horizontal)
        agent_id = self.selected_agent_id
        agent = self.live_view.agents.get(agent_id) if agent_id else None
        if agent is None or agent_id is None:
            row.display = False
            return
        status = str(agent.get("status") or "running")
        name = str(agent.get("name") or agent_id)
        spinning = False
        if status == "running":
            spinning = True
            if self.live_view.has_events_for_agent(agent_id):
                text = f"{name} is working · esc to stop"
            else:
                text = f"{name} is starting"
        elif status == "waiting":
            text = f"{name} is waiting — send a message to resume"
        elif status in {"failed", "crashed"}:
            text = str(agent.get("error_message") or f"{name} failed")
        else:
            text = f"{name} {status}"
        row.display = True
        self.query_one("#spinner", LoadingIndicator).display = spinning
        status_text = self.query_one("#status_text", Static)
        status_text.update(text)
        status_text.set_class(status in {"failed", "crashed"}, "error")
        self.query_one("#chat_input_container", Horizontal).border_title = name

    def _tick(self) -> None:
        # The interval can still fire while shutdown is removing widgets.
        if not self.is_running:
            return
        self._tick_count += 1
        self._update_elapsed()
        self._update_stats_display()
        if self._tick_count % 60 == 0:
            self.live_view.prune_old_events(max_events_per_agent=1000)
        if self._unseen_below:
            container = self._selected_container()
            if container is not None and container.is_vertical_scroll_end:
                self._hide_new_messages()

    def _update_elapsed(self) -> None:
        try:
            started = datetime.fromisoformat(str(self.report_state.start_time))
        except ValueError:
            return
        if started.tzinfo is None:
            started = started.replace(tzinfo=UTC)
        seconds = max(0, int((datetime.now(UTC) - started).total_seconds()))
        hours, rest = divmod(seconds, 3600)
        minutes, secs = divmod(rest, 60)
        elapsed = f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes:02d}:{secs:02d}"
        self.query_one("#elapsed_display", Static).update(f"elapsed {elapsed}")

    def _update_stats_display(self) -> None:
        stats_text = build_tui_stats_text(self.report_state)
        total = len(self.live_view.agents)
        if total:
            running = sum(1 for a in self.live_view.agents.values() if a.get("status") == "running")
            stats_text.append(f"\n{running}/{total} agents running")
        plain = stats_text.plain
        if plain == self._last_stats_plain:
            return
        self._last_stats_plain = plain
        stats_text.append(f"\nv{get_package_version()}", style="dim")
        self.query_one("#stats_display", Static).update(stats_text)

    # --- input -------------------------------------------------------------

    async def _send_user_message(self, message: str) -> None:
        if self._awaiting_target:
            self._submit_target(message)
            return

        if not self.selected_agent_id:
            return

        logger.info("TUI: user message -> %s (len=%d)", self.selected_agent_id, len(message))
        event = send_user_message_to_agent(
            coordinator=self.coordinator,
            loop=self._scan_loop,
            live_view=self.live_view,
            target_agent_id=self.selected_agent_id,
            message=message,
        )
        if event is None:
            self.notify("Scan loop is not ready; message was not sent", severity="warning")
            return
        await self._sync_event(event)
        self.action_jump_to_latest()

    def _submit_target(self, message: str) -> None:
        lines = message.splitlines()
        target_raw = lines[0].strip() if lines else ""
        extra_instruction = "\n".join(lines[1:]).strip()

        if not target_raw:
            self.notify("Enter a target or a prompt to begin", severity="warning")
            return

        try:
            target_type, target_dict = infer_target_type(target_raw)
        except ValueError:
            if target_raw.startswith(("./", "../", "/", "~")):
                self.notify(
                    f"Cannot open local target: {target_raw}\n"
                    f"Check the filename and path. Relative paths use {Path.cwd()}.",
                    severity="error",
                    timeout=10,
                )
                return
            # Free-form text that doesn't parse as a target → prompt-only run.
            self._submit_prompt_only(message)
            return

        display_target = (
            target_dict.get("target_path") or target_dict.get("target_file") or target_raw
        )
        target_info = {
            "type": target_type,
            "details": target_dict,
            "original": display_target,
        }

        self.args.targets_info = [target_info]
        self.scan_config["targets"] = self.args.targets_info

        if extra_instruction:
            self.args.instruction = extra_instruction
            self.scan_config["user_instructions"] = extra_instruction

        assign_workspace_subdirs(self.args.targets_info)
        rewrite_localhost_targets(self.args.targets_info, HOST_GATEWAY_HOSTNAME)
        self.args.local_sources = collect_local_sources(self.args.targets_info)
        self.scan_config["local_sources"] = self.args.local_sources

        self._begin_scan()
        self.notify(f"Target set: {display_target}", timeout=3)

    def _submit_prompt_only(self, message: str) -> None:
        """Start a prompt-only run from free-form text in the target field.

        Triggered when ``_submit_target`` can't parse the first line as a
        target. The full message becomes the agent's initial instruction.
        """
        prompt = message.strip()
        if not prompt:
            self.notify("Enter a target or a prompt to begin", severity="warning")
            return

        self.args.instruction = prompt
        self.args.prompt_only = True
        self.scan_config["user_instructions"] = prompt
        self.scan_config["prompt_only"] = True
        self._prompt_only = True

        self._begin_scan()
        self.notify("Prompt-only run started", timeout=3)

    def _begin_scan(self) -> None:
        self.report_state.set_scan_config(self.scan_config)
        self.report_state.save_run_data()
        self._persist_target_metadata()
        self._awaiting_target = False
        self._start_scan_thread()
        if self.is_running:
            self.sub_title = self._subtitle()
            self.query_one("#chat_area", ContentSwitcher).current = "placeholder"
            self.query_one("#chat_input", ChatTextArea).placeholder = self._input_placeholder()
            self._update_stats_display()

    def _persist_target_metadata(self) -> None:
        """Mirror the latest targets_info into the run record on disk."""
        run_record = self.report_state.run_record
        run_record["targets_info"] = self.args.targets_info
        if self.args.instruction is not None:
            run_record["instruction"] = self.args.instruction
        try:
            from kael.report.writer import write_run_record

            write_run_record(self.report_state.get_run_dir(), run_record)
        except Exception:
            logger.exception("Failed to persist run record after target submit")

    # --- actions -----------------------------------------------------------

    def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
        yield from super().get_system_commands(screen)
        yield SystemCommand(
            "Change OpenRouter provider",
            "Configure and save OpenRouter provider routing",
            self.action_change_openrouter_provider,
        )
        yield SystemCommand(
            "Change model", "Edit the model used by every agent", self.action_change_model
        )
        yield SystemCommand(
            "Edit settings",
            "Configure and save model, provider, credentials, tools, and runtime",
            self.action_edit_settings,
        )
        for agent_id, agent in self.live_view.agents.items():
            name = agent.get("name", agent_id)
            yield SystemCommand(
                f"Switch to {name}",
                f"Show this agent's conversation ({agent.get('status', 'running')})",
                partial(self._select_agent, agent_id),
            )
        yield SystemCommand(
            "Stop agent",
            "Stop the selected agent and its sub-agents",
            self.action_stop_selected_agent,
        )
        yield SystemCommand(
            "Fold tool output", "Fold or unfold every tool-call block", self.action_toggle_fold_all
        )
        yield SystemCommand(
            "Copy last message",
            "Copy the selected agent's last message to the clipboard",
            self.action_copy_last_message,
        )
        yield SystemCommand(
            "Jump to latest",
            "Scroll the conversation to the newest message",
            self.action_jump_to_latest,
        )
        yield SystemCommand(
            "Toggle sidebar", "Show or hide the sidebar", self.action_toggle_sidebar
        )

    def action_change_openrouter_provider(self) -> None:
        self.action_edit_settings("KAEL_OPENROUTER_PROVIDER")

    def action_change_model(self) -> None:
        self.action_edit_settings("KAEL_LLM")

    def action_edit_settings(self, initial_key: str | None = None) -> None:
        if len(self.screen_stack) > 1:
            return
        self.push_screen(SettingsScreen(initial_key), self._settings_saved)

    async def _settings_saved(self, changed: set[str] | None) -> None:
        if changed is None:
            return
        if not changed:
            self.notify("No settings changed.")
            return

        async def apply() -> bool:
            return self.coordinator.apply_model_settings(load_settings())

        loop = self._scan_loop
        if loop is not None and loop.is_running():
            coroutine = apply()
            try:
                pending = asyncio.run_coroutine_threadsafe(coroutine, loop)
            except RuntimeError:
                coroutine.close()
                applied = await apply()
            else:
                applied = await asyncio.wrap_future(pending)
        else:
            applied = await apply()
        self.sub_title = self._subtitle()
        message = "Settings saved to config file."
        if not applied:
            message += " The model or API/tool format change requires a new run."
        else:
            message += " Compatible model settings apply to the next request."
        self.notify(message, timeout=8)
        if self._scan_thread is None and not self._awaiting_target:
            self._start_scan_thread()

    def _select_agent(self, agent_id: str) -> None:
        self.selected_agent_id = agent_id
        node = self.agent_nodes.get(agent_id)
        if node is not None:
            self.query_one("#agents_tree", Tree).move_cursor(node)

    def action_cycle_agent(self, delta: int) -> None:
        order = self._tree_order()
        if not order:
            return
        try:
            index = order.index(self.selected_agent_id or "")
        except ValueError:
            index = -1 if delta > 0 else 0
        self._select_agent(order[(index + delta) % len(order)])

    def action_toggle_fold_all(self) -> None:
        blocks = self.query(".tool-call, .reasoning")
        fold = any(not block.has_class("folded") for block in blocks)
        blocks.set_class(fold, "folded")

    def action_jump_to_latest(self) -> None:
        container = self._selected_container()
        if container is not None:
            container.scroll_end(animate=False)
        self._hide_new_messages()

    def action_copy_last_message(self) -> None:
        if not self.selected_agent_id:
            return
        for event in reversed(self.live_view.events_for_agent(self.selected_agent_id)):
            data = event.get("data") or {}
            if event["type"] == "chat" and data.get("role") == "assistant":
                self.copy_text(str(data.get("content") or ""))
                return
        self.notify("No assistant message yet", severity="warning")

    def action_toggle_sidebar(self) -> None:
        self._sidebar_user_hidden = not self._sidebar_user_hidden
        self._apply_sidebar(self.size.width)

    def _apply_sidebar(self, width: int) -> None:
        hidden = self._sidebar_user_hidden or width < self.SIDEBAR_MIN_WIDTH
        self.query_one("#sidebar", Vertical).set_class(hidden, "-hidden")
        self.query_one("#chat_area_container", Vertical).set_class(hidden, "-full-width")

    def on_resize(self, event: events.Resize) -> None:
        if self.is_running:
            self._apply_sidebar(event.size.width)

    def action_toggle_help(self) -> None:
        if self.screen.query("HelpPanel"):
            self.action_hide_help_panel()
        else:
            self.action_show_help_panel()

    async def action_request_quit(self) -> None:
        if not self.is_running:
            await self.action_custom_quit()
            return
        if len(self.screen_stack) > 1:
            return
        self.push_screen(QuitScreen())

    def action_escape(self) -> None:
        if len(self.screen_stack) > 1:
            self.pop_screen()
            return
        if self.screen.selections:
            self.screen.clear_selection()
            return
        self.action_stop_selected_agent()

    def action_stop_selected_agent(self) -> None:
        if not self.is_running or len(self.screen_stack) > 1 or not self.selected_agent_id:
            return
        agent = self.live_view.agents.get(self.selected_agent_id, {})
        if agent.get("status", "running") not in {"running", "waiting"}:
            return
        if not self.live_view.has_events_for_agent(self.selected_agent_id):
            return
        name = str(agent.get("name") or self.selected_agent_id)
        self.push_screen(StopAgentScreen(name, self.selected_agent_id))

    def action_confirm_stop_agent(self, agent_id: str) -> None:
        if self._scan_loop is None or self._scan_loop.is_closed():
            logger.warning("No active scan loop; cannot stop agent %s", agent_id)
            return
        logger.info("TUI: graceful stop requested for %s (cascade)", agent_id)
        asyncio.run_coroutine_threadsafe(
            self.coordinator.cancel_descendants_graceful(agent_id),
            self._scan_loop,
        )

    async def action_custom_quit(self) -> None:
        self._fire_sandbox_cleanup()

        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_stop_event.set()

        self.report_state.cleanup()

        self.exit()

    def _fire_sandbox_cleanup(self) -> None:
        self.coordinator.mark_shutting_down()
        loop = self._scan_loop
        if loop is None or loop.is_closed():
            return
        run_name = self.scan_config.get("run_name")
        if not run_name:
            return
        with contextlib.suppress(Exception):
            asyncio.run_coroutine_threadsafe(session_manager.cleanup(run_name), loop)

    # --- mouse / clipboard -------------------------------------------------

    def on_click(self, event: events.Click) -> None:
        if event.widget is None:
            return
        if event.widget.id == "new_messages":
            self.action_jump_to_latest()
            return
        # Finishing a drag-select must not fold the block underneath.
        if self._mouse_up_had_selection:
            return
        for node in event.widget.ancestors_with_self:
            if node.has_class("tool-call") or node.has_class("reasoning"):
                node.toggle_class("folded")
                return

    def on_mouse_up(self, _event: events.MouseUp) -> None:
        self._mouse_up_had_selection = bool(self.screen.selections)
        self._auto_copy_selection()

    _ICON_PREFIXES: ClassVar[tuple[str, ...]] = (
        "🐞 ",
        "🌐 ",
        "📋 ",
        "🧠 ",
        "◆ ",
        "◇ ",
        "◈ ",
        "→ ",
        "○ ",
        "● ",
        "✓ ",
        "✗ ",
        "⚠ ",
        "▍ ",
        "▍",
        "┃ ",
        "• ",
        ">_ ",
        "</> ",
        "<~> ",
        "[ ] ",
        "[~] ",
        "[•] ",
    )

    _DECORATIVE_LINES: ClassVar[frozenset[str]] = frozenset(
        {
            "● In progress...",
            "✓ Done",
            "✗ Failed",
            "✗ Error",
            "○ Unknown",
        }
    )

    @staticmethod
    def _clean_copied_text(text: str) -> str:
        lines = text.split("\n")
        cleaned: list[str] = []
        for line in lines:
            stripped = line.lstrip()
            if stripped in KaelTUIApp._DECORATIVE_LINES:
                continue
            if stripped and all(c == "─" for c in stripped):
                continue
            out = line
            for prefix in KaelTUIApp._ICON_PREFIXES:
                if stripped.startswith(prefix):
                    leading = line[: len(line) - len(line.lstrip())]
                    out = leading + stripped[len(prefix) :]
                    break
            cleaned.append(out)
        return "\n".join(cleaned)

    def _auto_copy_selection(self) -> None:
        text = ""
        if self.screen.selections:
            selected = self.screen.get_selected_text()
            self.screen.clear_selection()
            if selected and selected.strip():
                cleaned = self._clean_copied_text(selected)
                text = cleaned if cleaned.strip() else selected
        if not text:
            try:
                chat_input = self.query_one("#chat_input", ChatTextArea)
            except NoMatches:
                return
            selected = chat_input.selected_text
            if selected and selected.strip():
                text = selected
                chat_input.move_cursor(chat_input.cursor_location)
        if text:
            self.copy_text(text)

    def copy_text(self, text: str) -> None:
        """OSC52 first (instant), then the OS clipboard tool off the UI thread."""
        self.copy_to_clipboard(text)
        self.run_worker(
            partial(self._copy_to_os_clipboard, text),
            thread=True,
            exclusive=True,
            group="clipboard",
            exit_on_error=False,
        )

    def _copy_to_os_clipboard(self, text: str) -> None:
        # Worker thread: the subprocess may block for up to 2s.
        if _copy_to_system_clipboard(text):
            self.call_from_thread(self.notify, "Copied to clipboard", timeout=2)
        else:
            self.call_from_thread(
                self.notify,
                "Copied via terminal clipboard (no OS clipboard tool found)",
                timeout=4,
                severity="warning",
            )


async def run_tui(args: argparse.Namespace) -> None:
    app = KaelTUIApp(args)
    await app.run_async()
    if app._scan_error is not None:
        raise app._scan_error
