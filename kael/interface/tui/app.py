"""Kael TUI - main Textual app."""

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
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from rich.console import Group
from rich.style import Style
from rich.text import Span, Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static, TextArea, Tree

from kael.config import load_settings
from kael.core.runner import run_kael_scan
from kael.interface.utils import (
    assign_workspace_subdirs,
    build_tui_stats_text,
    infer_target_type,
    rewrite_localhost_targets,
)
from kael.report.state import ReportState, set_global_report_state
from kael.runtime import session_manager


if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable

    from textual.timer import Timer
    from textual.widgets.tree import TreeNode
from kael.interface.tui.live_view import TuiLiveView
from kael.interface.tui.messages import send_user_message_to_agent
from kael.interface.tui.renderers import render_tool_widget
from kael.interface.tui.renderers.agent_message_renderer import AgentMessageRenderer
from kael.interface.tui.renderers.user_message_renderer import UserMessageRenderer


HOST_GATEWAY_HOSTNAME = "host.docker.internal"


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


def get_package_version() -> str:
    try:
        return pkg_version("kael-agent")
    except PackageNotFoundError:
        return "dev"


class ChatTextArea(TextArea):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._app_reference: KaelTUIApp | None = None

    def set_app_reference(self, app: KaelTUIApp) -> None:
        self._app_reference = app

    def on_mount(self) -> None:
        self._update_height()

    async def _on_key(self, event: events.Key) -> None:
        if event.key == "shift+enter":
            self.insert("\n")
            event.prevent_default()
            return

        if event.key == "enter" and self._app_reference:
            text_content = str(self.text)  # type: ignore[has-type]
            message = text_content.strip()
            if message:
                self.text = ""

                self._app_reference._send_user_message(message)

                event.prevent_default()
                return

        await super()._on_key(event)

    @on(TextArea.Changed)  # type: ignore[misc]
    def _update_height(self, _event: TextArea.Changed | None = None) -> None:
        if not self.parent:
            return

        line_count = self.document.line_count
        target_lines = min(max(1, line_count), 8)

        new_height = target_lines + 2

        if self.parent.styles.height != new_height:
            self.parent.styles.height = new_height
            self.scroll_cursor_visible()


class HelpScreen(ModalScreen):  # type: ignore[misc]
    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Kael Help", id="help_title"),
            Label(
                "F1        Help\nCtrl+Q/C  Quit\nESC       Stop Agent\n"
                "Enter     Send message to agent\nTab       Switch panels\n↑/↓       Navigate tree",
                id="help_content",
            ),
            id="dialog",
        )

    def on_key(self, _event: events.Key) -> None:
        self.app.pop_screen()


class StopAgentScreen(ModalScreen):  # type: ignore[misc]
    def __init__(self, agent_name: str, agent_id: str):
        super().__init__()
        self.agent_name = agent_name
        self.agent_id = agent_id

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(f"🛑 Stop '{self.agent_name}'?", id="stop_agent_title"),
            Grid(
                Button("Yes", variant="error", id="stop_agent"),
                Button("No", variant="default", id="cancel_stop"),
                id="stop_agent_buttons",
            ),
            id="stop_agent_dialog",
        )

    def on_mount(self) -> None:
        cancel_button = self.query_one("#cancel_stop", Button)
        cancel_button.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("left", "right", "up", "down"):
            focused = self.focused

            if focused and focused.id == "stop_agent":
                cancel_button = self.query_one("#cancel_stop", Button)
                cancel_button.focus()
            else:
                stop_button = self.query_one("#stop_agent", Button)
                stop_button.focus()

            event.prevent_default()
        elif event.key == "enter":
            focused = self.focused
            if focused and isinstance(focused, Button):
                focused.press()
            event.prevent_default()
        elif event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.app.pop_screen()
        if event.button.id == "stop_agent":
            self.app.action_confirm_stop_agent(self.agent_id)


class VulnerabilityDetailScreen(ModalScreen):  # type: ignore[misc]
    SEVERITY_COLORS: ClassVar[dict[str, str]] = {
        "critical": "#dc2626",  # Red
        "high": "#ea580c",  # Orange
        "medium": "#d97706",  # Amber
        "low": "#22c55e",  # Green
        "info": "#3b82f6",  # Blue
    }

    FIELD_STYLE: ClassVar[str] = "bold #4ade80"

    def __init__(self, vulnerability: dict[str, Any]) -> None:
        super().__init__()
        self.vulnerability = vulnerability

    def compose(self) -> ComposeResult:
        content = self._render_vulnerability()
        yield Grid(
            VerticalScroll(Static(content, id="vuln_detail_content"), id="vuln_detail_scroll"),
            Horizontal(
                Button("Copy", variant="default", id="copy_vuln_detail"),
                Button("Done", variant="default", id="close_vuln_detail"),
                id="vuln_detail_buttons",
            ),
            id="vuln_detail_dialog",
        )

    def on_mount(self) -> None:
        close_button = self.query_one("#close_vuln_detail", Button)
        close_button.focus()

    def _get_cvss_color(self, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "#dc2626"
        if cvss_score >= 7.0:
            return "#ea580c"
        if cvss_score >= 4.0:
            return "#d97706"
        if cvss_score >= 0.1:
            return "#65a30d"
        return "#6b7280"

    def _highlight_python(self, code: str) -> Text:
        try:
            from pygments.lexers import PythonLexer
            from pygments.styles import get_style_by_name

            lexer = PythonLexer()
            style = get_style_by_name("native")
            colors = {
                token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]
            }

            text = Text()
            for token_type, token_value in lexer.get_tokens(code):
                if not token_value:
                    continue
                color = None
                tt = token_type
                while tt:
                    if tt in colors:
                        color = colors[tt]
                        break
                    tt = tt.parent
                text.append(token_value, style=color)
        except (ImportError, KeyError, AttributeError):
            return Text(code)
        else:
            return text

    def _render_vulnerability(self) -> Text:
        vuln = self.vulnerability
        text = Text()

        text.append("🐞 ")
        text.append("Vulnerability Report", style="bold #ea580c")

        agent_name = vuln.get("agent_name", "")
        if agent_name:
            text.append("\n\n")
            text.append("Agent: ", style=self.FIELD_STYLE)
            text.append(agent_name)

        title = vuln.get("title", "")
        if title:
            text.append("\n\n")
            text.append("Title: ", style=self.FIELD_STYLE)
            text.append(title)

        severity = vuln.get("severity", "")
        if severity:
            text.append("\n\n")
            text.append("Severity: ", style=self.FIELD_STYLE)
            severity_color = self.SEVERITY_COLORS.get(severity.lower(), "#6b7280")
            text.append(severity.upper(), style=f"bold {severity_color}")

        cvss_score = vuln.get("cvss")
        if cvss_score is not None:
            text.append("\n\n")
            text.append("CVSS Score: ", style=self.FIELD_STYLE)
            cvss_color = self._get_cvss_color(float(cvss_score))
            text.append(str(cvss_score), style=f"bold {cvss_color}")

        target = vuln.get("target", "")
        if target:
            text.append("\n\n")
            text.append("Target: ", style=self.FIELD_STYLE)
            text.append(target)

        endpoint = vuln.get("endpoint", "")
        if endpoint:
            text.append("\n\n")
            text.append("Endpoint: ", style=self.FIELD_STYLE)
            text.append(endpoint)

        method = vuln.get("method", "")
        if method:
            text.append("\n\n")
            text.append("Method: ", style=self.FIELD_STYLE)
            text.append(method)

        cve = vuln.get("cve", "")
        if cve:
            text.append("\n\n")
            text.append("CVE: ", style=self.FIELD_STYLE)
            text.append(cve)

        cvss_breakdown = vuln.get("cvss_breakdown", {})
        if cvss_breakdown:
            cvss_parts = []
            if cvss_breakdown.get("attack_vector"):
                cvss_parts.append(f"AV:{cvss_breakdown['attack_vector']}")
            if cvss_breakdown.get("attack_complexity"):
                cvss_parts.append(f"AC:{cvss_breakdown['attack_complexity']}")
            if cvss_breakdown.get("privileges_required"):
                cvss_parts.append(f"PR:{cvss_breakdown['privileges_required']}")
            if cvss_breakdown.get("user_interaction"):
                cvss_parts.append(f"UI:{cvss_breakdown['user_interaction']}")
            if cvss_breakdown.get("scope"):
                cvss_parts.append(f"S:{cvss_breakdown['scope']}")
            if cvss_breakdown.get("confidentiality"):
                cvss_parts.append(f"C:{cvss_breakdown['confidentiality']}")
            if cvss_breakdown.get("integrity"):
                cvss_parts.append(f"I:{cvss_breakdown['integrity']}")
            if cvss_breakdown.get("availability"):
                cvss_parts.append(f"A:{cvss_breakdown['availability']}")
            if cvss_parts:
                text.append("\n\n")
                text.append("CVSS Vector: ", style=self.FIELD_STYLE)
                text.append("/".join(cvss_parts), style="dim")

        description = vuln.get("description", "")
        if description:
            text.append("\n\n")
            text.append("Description", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(description)

        impact = vuln.get("impact", "")
        if impact:
            text.append("\n\n")
            text.append("Impact", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(impact)

        technical_analysis = vuln.get("technical_analysis", "")
        if technical_analysis:
            text.append("\n\n")
            text.append("Technical Analysis", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(technical_analysis)

        poc_description = vuln.get("poc_description", "")
        if poc_description:
            text.append("\n\n")
            text.append("PoC Description", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(poc_description)

        poc_script_code = vuln.get("poc_script_code", "")
        if poc_script_code:
            text.append("\n\n")
            text.append("PoC Code", style=self.FIELD_STYLE)
            text.append("\n")
            text.append_text(self._highlight_python(poc_script_code))

        remediation_steps = vuln.get("remediation_steps", "")
        if remediation_steps:
            text.append("\n\n")
            text.append("Remediation", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(remediation_steps)

        return text

    def _get_markdown_report(self) -> str:
        """Get Markdown version of vulnerability report for clipboard."""
        vuln = self.vulnerability
        lines: list[str] = []

        title = vuln.get("title", "Untitled Vulnerability")
        lines.append(f"# {title}")
        lines.append("")

        if vuln.get("id"):
            lines.append(f"**ID:** {vuln['id']}")
        if vuln.get("severity"):
            lines.append(f"**Severity:** {vuln['severity'].upper()}")
        if vuln.get("timestamp"):
            lines.append(f"**Found:** {vuln['timestamp']}")
        if vuln.get("agent_name"):
            lines.append(f"**Agent:** {vuln['agent_name']}")
        if vuln.get("target"):
            lines.append(f"**Target:** {vuln['target']}")
        if vuln.get("endpoint"):
            lines.append(f"**Endpoint:** {vuln['endpoint']}")
        if vuln.get("method"):
            lines.append(f"**Method:** {vuln['method']}")
        if vuln.get("cve"):
            lines.append(f"**CVE:** {vuln['cve']}")
        if vuln.get("cvss") is not None:
            lines.append(f"**CVSS:** {vuln['cvss']}")

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
                lines.append(f"**CVSS Vector:** {'/'.join(parts)}")

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

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy_vuln_detail":
            markdown_text = self._get_markdown_report()
            self.app.copy_to_clipboard(markdown_text)

            copy_button = self.query_one("#copy_vuln_detail", Button)
            copy_button.label = "Copied!"
            self.set_timer(1.5, lambda: setattr(copy_button, "label", "Copy"))
        elif event.button.id == "close_vuln_detail":
            self.app.pop_screen()


class VulnerabilityItem(Static):  # type: ignore[misc]
    ALLOW_SELECT = True

    def __init__(self, label: Text, vuln_data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(label, **kwargs)
        self.vuln_data = vuln_data

    def on_click(self, _event: events.Click) -> None:
        """Handle click to open vulnerability detail."""
        self.app.push_screen(VulnerabilityDetailScreen(self.vuln_data))


class VulnerabilitiesPanel(VerticalScroll):  # type: ignore[misc]
    SEVERITY_COLORS: ClassVar[dict[str, str]] = {
        "critical": "#dc2626",  # Red
        "high": "#ea580c",  # Orange
        "medium": "#d97706",  # Amber
        "low": "#22c55e",  # Green
        "info": "#3b82f6",  # Blue
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._vulnerabilities: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        return []

    def update_vulnerabilities(self, vulnerabilities: list[dict[str, Any]]) -> None:
        """Update the list of vulnerabilities and re-render."""
        if self._vulnerabilities == vulnerabilities:
            return
        self._vulnerabilities = list(vulnerabilities)
        self._render_panel()

    def _render_panel(self) -> None:
        """Render the vulnerabilities panel content."""
        for child in list(self.children):
            if isinstance(child, VulnerabilityItem):
                child.remove()

        if not self._vulnerabilities:
            return

        for vuln in self._vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            title = vuln.get("title", "Unknown Vulnerability")
            color = self.SEVERITY_COLORS.get(severity, "#3b82f6")

            label = Text()
            label.append("● ", style=Style(color=color))
            label.append(title, style=Style(color="#d4d4d4"))

            item = VulnerabilityItem(label, vuln, classes="vuln-item")
            self.mount(item)


class QuitScreen(ModalScreen):  # type: ignore[misc]
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
        cancel_button = self.query_one("#cancel", Button)
        cancel_button.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("left", "right", "up", "down"):
            focused = self.focused

            if focused and focused.id == "quit":
                cancel_button = self.query_one("#cancel", Button)
                cancel_button.focus()
            else:
                quit_button = self.query_one("#quit", Button)
                quit_button.focus()

            event.prevent_default()
        elif event.key == "enter":
            focused = self.focused
            if focused and isinstance(focused, Button):
                focused.press()
            event.prevent_default()
        elif event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            await self.app.action_custom_quit()
        else:
            self.app.pop_screen()


class KaelTUIApp(App):  # type: ignore[misc]
    CSS_PATH = str(Path(__file__).resolve().parent.parent / "assets" / "tui_styles.tcss")
    ALLOW_SELECT = True

    SIDEBAR_MIN_WIDTH = 120

    selected_agent_id: reactive[str | None] = reactive(default=None)

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("f1", "toggle_help", "Help", priority=True),
        Binding("ctrl+q", "request_quit", "Quit", priority=True),
        Binding("ctrl+c", "request_quit", "Quit", priority=True),
        Binding("escape", "stop_selected_agent", "Stop Agent", priority=True),
    ]

    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self.args = args

        # Prompt-only mode: no target, but a prompt is set. Start the scan
        # immediately instead of showing the "enter a target" placeholder.
        # Computed before _build_scan_config so the scan_config can carry it.
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
        self._agent_graph_sync_future: Any | None = None

        from kael.core.agents import AgentCoordinator

        self.coordinator = AgentCoordinator()

        self.agent_nodes: dict[str, TreeNode] = {}

        self._displayed_agents: set[str] = set()
        self._displayed_events: list[str] = []

        # Rendered event cache to avoid re-rendering unchanged events
        self._rendered_event_cache: dict[str, Any] = {}
        self._last_rendered_content: Any | None = None

        self._scan_thread: threading.Thread | None = None
        self._scan_loop: asyncio.AbstractEventLoop | None = None
        self._scan_stop_event = threading.Event()
        self._scan_completed = threading.Event()
        self._scan_error: BaseException | None = None

        self._spinner_frame_index: int = 0
        self._sweep_num_squares: int = 6
        self._sweep_colors: list[str] = [
            "#000000",  # Dimmest (shows dot)
            "#031a09",
            "#052e16",
            "#0d4a2a",
            "#15803d",
            "#22c55e",
            "#4ade80",
            "#86efac",  # Brightest
        ]
        self._dot_animation_timer: Any | None = None

        self._heartbeat_timer: Timer | None = None

        self._chat_history: VerticalScroll | None = None
        self._chat_display: Static | None = None
        self._agents_tree: Tree | None = None
        self._stats_display: Static | None = None
        self._vulnerabilities_panel: VulnerabilitiesPanel | None = None
        self._status_display: Horizontal | None = None
        self._status_text: Static | None = None
        self._keymap_indicator: Static | None = None

        self._last_stats_plain: str | None = None
        self._last_vuln_signature: tuple | None = None

        # Vulnerability count cache to avoid O(n*m) scans every heartbeat
        self._vuln_count_cache: dict[str, int] = {}
        self._vuln_cache_signature: int = -1

        # Event pruning to prevent unbounded growth
        self._update_counter: int = 0

        # Per-event tail-render bookkeeping for streaming assistant messages.
        # Keyed by event id; tracks how many characters of ``data["content"]``
        # have already been rendered so subsequent deltas only need to render
        # the new tail instead of the full accumulated content.
        self._rendered_content_len: dict[str, int] = {}

        # Deferred chat content: when the user scrolls up to read history,
        # Static.update() is skipped (it re-converts the whole chat Text via
        # Content.from_rich_text — ~200ms for a 250KB report). The latest
        # (content, css_class) is stashed here and flushed once they scroll
        # back to the bottom or the scan completes. ``_displayed_events`` is
        # committed at stash time so a no-change heartbeat short-circuits.
        self._pending_chat_content: tuple[Any, str] | None = None

        self._setup_cleanup_handlers()

    def _build_scan_config(self, args: argparse.Namespace) -> dict[str, Any]:
        prompt_only = bool(getattr(args, "prompt_only", False)) or (
            not bool(args.targets_info) and bool((args.instruction or "").strip())
        )
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
            "prompt_only": prompt_only,
        }

    def _setup_cleanup_handlers(self) -> None:
        def cleanup_on_exit() -> None:
            self.report_state.cleanup()

        def signal_handler(_signum: int, _frame: Any) -> None:
            self._fire_sandbox_cleanup()
            self.report_state.cleanup(status="interrupted")
            sys.exit(0)

        atexit.register(cleanup_on_exit)
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)

    def compose(self) -> ComposeResult:
        yield from ()

    def on_mount(self) -> None:
        self.title = "kael"
        self._mount_main_ui()

        if not self._awaiting_target:
            self._start_scan_thread()

        self._heartbeat_timer = self.set_interval(0.5, self._update_ui)

    def _mount_main_ui(self) -> None:
        main_container = Vertical(id="main_container")
        self.mount(main_container)

        content_container = Horizontal(id="content_container")
        main_container.mount(content_container)

        chat_area_container = Vertical(id="chat_area_container")

        chat_display = Static("", id="chat_display")
        chat_display.ALLOW_SELECT = True
        chat_history = VerticalScroll(chat_display, id="chat_history")
        chat_history.can_focus = True

        status_text = Static("", id="status_text")
        status_text.ALLOW_SELECT = False
        keymap_indicator = Static("", id="keymap_indicator")
        keymap_indicator.ALLOW_SELECT = False

        agent_status_display = Horizontal(
            status_text, keymap_indicator, id="agent_status_display", classes="hidden"
        )

        chat_prompt = Static("> ", id="chat_prompt")
        chat_prompt.ALLOW_SELECT = False
        if self._awaiting_target:
            chat_input_placeholder = (
                "Enter a target (URL, repo, path, domain, or IP) "
                "or just type a prompt to run with no target."
            )
        elif self._prompt_only:
            chat_input_placeholder = (
                "Prompt-only run in progress. Type a follow-up message to steer the agent."
            )
        else:
            chat_input_placeholder = ""
        chat_input = ChatTextArea(
            "",
            id="chat_input",
            show_line_numbers=False,
            placeholder=chat_input_placeholder,
        )
        chat_input.set_app_reference(self)
        chat_input_container = Horizontal(chat_prompt, chat_input, id="chat_input_container")

        agents_tree = Tree("Agents", id="agents_tree")
        agents_tree.root.expand()
        agents_tree.show_root = False

        agents_tree.show_guides = True
        agents_tree.guide_depth = 3
        agents_tree.guide_style = "dashed"

        stats_display = Static("", id="stats_display")
        stats_display.ALLOW_SELECT = True
        stats_scroll = VerticalScroll(stats_display, id="stats_scroll")

        vulnerabilities_panel = VulnerabilitiesPanel(id="vulnerabilities_panel")
        vulnerabilities_panel.ALLOW_SELECT = True

        sidebar = Vertical(agents_tree, vulnerabilities_panel, stats_scroll, id="sidebar")

        content_container.mount(chat_area_container)
        content_container.mount(sidebar)

        chat_area_container.mount(chat_history)
        chat_area_container.mount(agent_status_display)
        chat_area_container.mount(chat_input_container)

        self._chat_history = chat_history
        self._chat_display = chat_display
        self._agents_tree = agents_tree
        self._stats_display = stats_display
        self._vulnerabilities_panel = vulnerabilities_panel
        self._status_display = agent_status_display
        self._status_text = status_text
        self._keymap_indicator = keymap_indicator

        self.call_after_refresh(self._focus_chat_input)

    def _focus_chat_input(self) -> None:
        if len(self.screen_stack) > 1:
            return

        if not self.is_mounted:
            return

        try:
            chat_input = self.query_one("#chat_input", ChatTextArea)
            chat_input.show_vertical_scrollbar = False
            chat_input.show_horizontal_scrollbar = False
            chat_input.focus()
        except (ValueError, Exception):
            self.call_after_refresh(self._focus_chat_input)

    def _focus_agents_tree(self) -> None:
        if len(self.screen_stack) > 1:
            return

        if not self.is_mounted:
            return

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
            agents_tree.focus()

            if agents_tree.root.children:
                first_node = agents_tree.root.children[0]
                agents_tree.select_node(first_node)
        except (ValueError, Exception):
            self.call_after_refresh(self._focus_agents_tree)

    def _update_ui(self) -> None:
        if len(self.screen_stack) > 1:
            return

        if not self.is_mounted:
            return

        if self._chat_history is None or self._agents_tree is None:
            return
        if not self._is_widget_safe(self._chat_history) or not self._is_widget_safe(
            self._agents_tree
        ):
            return

        self._sync_agent_graph()

        agents_changed = False
        for agent_id, agent_data in list(self.live_view.agents.items()):
            if agent_id not in self._displayed_agents:
                self._add_agent_node(agent_data)
                self._displayed_agents.add(agent_id)
                agents_changed = True
            else:
                agents_changed = self._update_agent_node(agent_id, agent_data) or agents_changed

        with self.batch_update():
            self._update_chat_view()
            self._update_agent_status_display()
            self._update_stats_display()
            self._update_vulnerabilities_panel()

        # Periodically prune old events to prevent unbounded memory growth
        self._update_counter += 1
        if self._update_counter % 100 == 0:  # Every ~50 seconds at 0.5s interval
            pruned = self.live_view.prune_old_events(max_events_per_agent=1000)
            if pruned > 0:
                # Clear stale rendered cache entries
                if len(self._rendered_event_cache) > 2000:
                    self._rendered_event_cache.clear()
                    self._rendered_content_len.clear()

        if (
            self._scan_completed.is_set()
            and self._heartbeat_timer is not None
            and not self._has_active_agents()
        ):
            # ponytail: flush any deferred chat content before the
            # heartbeat stops, otherwise the user (if scrolled up) would
            # never see the final report — no future tick to flush it.
            # scroll_to_end=False preserves their reading position.
            self._flush_pending_chat(scroll_to_end=False)
            self._heartbeat_timer.stop()
            self._heartbeat_timer = None

    def _has_active_agents(self) -> bool:
        return any(
            data.get("status", "running") in {"running", "waiting"}
            for data in self.live_view.agents.values()
        )

    def _sync_agent_graph(self) -> None:
        future = self._agent_graph_sync_future
        if future is not None:
            if not future.done():
                if self._scan_loop is not None and self._scan_loop.is_closed():
                    future.cancel()
                    self._agent_graph_sync_future = None
                else:
                    return
            else:
                self._agent_graph_sync_future = None
                try:
                    parent_of, statuses, names = future.result()
                except Exception:
                    logger.exception("TUI agent graph sync failed")
                else:
                    for agent_id, status in statuses.items():
                        self.live_view.upsert_agent(
                            agent_id,
                            name=names.get(agent_id, agent_id),
                            parent_id=parent_of.get(agent_id),
                            status=status,
                        )
                    self._maybe_inject_prompt_message(parent_of, statuses)

        if self._scan_loop is None or self._scan_loop.is_closed():
            return

        async def collect() -> tuple[dict[str, str | None], dict[str, Any], dict[str, str]]:
            return await self.coordinator.graph_snapshot()

        self._agent_graph_sync_future = asyncio.run_coroutine_threadsafe(collect(), self._scan_loop)

    def _maybe_inject_prompt_message(
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
                self.live_view.record_user_message(agent_id, prompt)
                self._prompt_injected = True
                # Clear the placeholder tracker so the next render shows
                # the synthetic user message instead of "Starting agent…".
                self._displayed_events.clear()
                return

    def _update_agent_node(self, agent_id: str, agent_data: dict[str, Any]) -> bool:
        if agent_id not in self.agent_nodes:
            return False

        try:
            agent_node = self.agent_nodes[agent_id]
            agent_name_raw = agent_data.get("name", "Agent")
            status = agent_data.get("status", "running")

            status_indicators = {
                "running": "⚪",
                "waiting": "⏸",
                "completed": "🟢",
                "failed": "🔴",
                "stopped": "■",
            }

            status_icon = status_indicators.get(status, "○")
            vuln_count = self._agent_vulnerability_count(agent_id)
            vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
            agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

            if agent_node.label != agent_name:
                agent_node.set_label(agent_name)
                return True

        except (KeyError, AttributeError, ValueError) as e:
            logger.warning(f"Failed to update agent node label: {e}")

        return False

    def _get_chat_content(
        self,
    ) -> tuple[Any, str | None, list[str] | None]:
        """Compute chat content for the selected agent.

        Returns ``(content, css_class, event_ids_to_commit)``. The caller
        assigns ``event_ids_to_commit`` to ``_displayed_events`` only when
        the content is actually applied (or stashed for deferred flush) —
        not here, so that a deferred-then-short-circuited heartbeat does
        not falsely report the content as displayed. ``None`` for
        ``event_ids_to_commit`` means the caller should not touch state
        (placeholder paths commit ``_displayed_events`` themselves; a
        no-change tick returns ``None`` for content too).
        """
        if self._awaiting_target:
            content, css_class = self._get_chat_placeholder_content(
                "No target provided.\n\n"
                "Enter a target below to start the scan.\n"
                "Examples:\n"
                "  https://example.com\n"
                "  https://github.com/user/repo\n"
                "  ./my-project\n"
                "  example.com\n\n"
                "No target? Just type a free-form prompt and the agent will run on it.\n"
                "Optional: add a blank line, then custom instructions.",
                "placeholder-awaiting-target",
            )
            return content, css_class, None

        if not self.selected_agent_id:
            content, css_class = self._get_chat_placeholder_content(
                "Loading...", "placeholder-no-agent"
            )
            return content, css_class, None

        events = self._gather_agent_events(self.selected_agent_id)

        if not events:
            content, css_class = self._get_chat_placeholder_content(
                "Starting agent...", "placeholder-no-activity"
            )
            return content, css_class, None

        current_event_ids = [f"{e['id']}:{e.get('version', 0)}" for e in events]
        if current_event_ids == self._displayed_events:
            return None, None, None

        return (
            self._get_rendered_events_content(events),
            "chat-content",
            current_event_ids,
        )

    def _update_chat_view(self) -> None:
        if len(self.screen_stack) > 1 or not self.is_mounted:
            return

        if self.screen.selections:
            return

        chat_history = self._chat_history
        chat_display = self._chat_display
        if chat_history is None or chat_display is None or not self._is_widget_safe(chat_history):
            return

        try:
            is_at_bottom = chat_history.scroll_y >= chat_history.max_scroll_y
        except (AttributeError, ValueError):
            is_at_bottom = True

        # Flush deferred content the moment the user scrolls back to the
        # bottom (next heartbeat sees is_at_bottom=True).
        if is_at_bottom and self._pending_chat_content is not None:
            self._flush_pending_chat(scroll_to_end=True)
            return

        content, css_class, event_ids = self._get_chat_content()
        if content is None:
            return

        if event_ids is not None:
            self._displayed_events = event_ids

        # ponytail: Static.update() re-converts the *entire* chat Text via
        # Content.from_rich_text — ~200ms for a 250KB report with thousands
        # of Pygments spans. It fires on every heartbeat while agents are
        # active (streaming deltas / tool events bump event versions). When
        # the user has scrolled up to read history, that 200ms freeze lands
        # on the UI thread mid-scroll → the "random" scroll lag. Skip the
        # update while scrolled up; stash and flush on return to bottom.
        # Ceiling: content is stale by up to one heartbeat while reading
        # history — desired "viewing history" behaviour. Upgrade: per-event
        # widget virtualization so the scroll container only renders visible
        # events (no full-text re-conversion on update).
        if not is_at_bottom:
            self._pending_chat_content = (content, css_class)
            return

        self._pending_chat_content = None
        self._safe_widget_operation(chat_display.update, content)
        chat_display.set_classes(css_class)

        self.call_later(chat_history.scroll_end, animate=False)

    def _flush_pending_chat(self, *, scroll_to_end: bool) -> None:
        """Apply deferred chat content to the widget.

        Called when the user scrolls back to the bottom (``scroll_to_end``
        re-pins to follow the stream) or when the scan completes
        (``scroll_to_end=False`` preserves the user's reading position).
        """
        pending = self._pending_chat_content
        if pending is None:
            return
        chat_display = self._chat_display
        chat_history = self._chat_history
        if chat_display is None or chat_history is None:
            self._pending_chat_content = None
            return
        content, css_class = pending
        self._pending_chat_content = None
        self._safe_widget_operation(chat_display.update, content)
        chat_display.set_classes(css_class)
        if scroll_to_end:
            self.call_later(chat_history.scroll_end, animate=False)

    def _get_chat_placeholder_content(
        self, message: str, placeholder_class: str
    ) -> tuple[Text, str]:
        self._displayed_events = [placeholder_class]
        text = Text()
        text.append(message)
        return text, f"chat-placeholder {placeholder_class}"

    @staticmethod
    def _merge_renderables(renderables: list[Any]) -> Text:
        """Merge renderables into a single Text for mouse text selection support."""
        combined = Text()
        for i, item in enumerate(renderables):
            if i > 0:
                combined.append("\n")
            KaelTUIApp._append_renderable(combined, item)
        return KaelTUIApp._sanitize_text(combined)

    @staticmethod
    def _sanitize_text(text: Text) -> Text:
        """Clamp spans so Rich/Textual can't crash on malformed offsets."""
        plain = text.plain
        text_length = len(plain)
        sanitized_spans: list[Span] = []

        for span in text.spans:
            start = max(0, min(span.start, text_length))
            end = max(0, min(span.end, text_length))
            if end > start:
                sanitized_spans.append(Span(start, end, span.style))

        return Text(
            plain,
            style=text.style,
            justify=text.justify,
            overflow=text.overflow,
            no_wrap=text.no_wrap,
            end=text.end,
            tab_size=text.tab_size,
            spans=sanitized_spans,
        )

    @staticmethod
    def _append_renderable(combined: Text, item: Any) -> None:
        """Recursively append a renderable's text content to a combined Text."""
        if isinstance(item, Text):
            # ponytail: skip per-item sanitize — the final combined
            # sanitize in _merge_renderables catches any malformed
            # spans from tool widgets. Doubling it here was the
            # biggest contributor to multi-event chat re-render cost.
            combined.append_text(item)
        elif isinstance(item, Group):
            for j, sub in enumerate(item.renderables):
                if j > 0:
                    combined.append("\n")
                KaelTUIApp._append_renderable(combined, sub)
        else:
            inner = getattr(item, "content", None) or getattr(item, "renderable", None)
            if inner is not None:
                KaelTUIApp._append_renderable(combined, inner)
            else:
                combined.append(str(item))

    def _get_rendered_events_content(self, events: list[dict[str, Any]]) -> Any:
        renderables: list[Any] = []

        if not events:
            return Text()

        for event in events:
            content = self._render_event_content(event)

            if content:
                if renderables:
                    renderables.append(Text(""))
                renderables.append(content)

        if not renderables:
            return Text()

        if len(renderables) == 1 and isinstance(renderables[0], Text):
            # ponytail: chat renders (streaming tail + finalized) are
            # well-formed by our own renderer — skip the per-tick
            # _sanitize_text (which materializes text.plain and
            # re-walks every span). The final sanitize is reserved
            # for the multi-renderable merge path, where tool widgets
            # can inject spans we don't control.
            return renderables[0]

        return self._merge_renderables(renderables)

    def _render_event_content(self, event: dict[str, Any]) -> Any:
        """Render a single event, using the tail fast-path for streaming
        assistant messages.

        The cache is keyed on ``(id, version)`` for finalized events (and
        for tool events). For a streaming assistant event the cache key
        changes on every delta (the live view bumps ``version`` on every
        mutation), so we additionally check whether the event is the
        currently-open streaming message: if so, we render only the new
        tail and append it onto the cached ``Text`` keyed by event id
        alone. The full content is only ever re-rendered from scratch
        when the streaming event is finalized or when this is the first
        time we have ever seen the event.
        """
        version = event.get("version", 0)
        event_key = f"{event['id']}:{version}"

        if event["type"] == "chat":
            data = event.get("data") or {}
            streaming = self._is_open_streaming_chat(event)

            if streaming:
                content = self._render_or_extend_streaming(event, data)
            else:
                # Finalized chat (or user chat): drop the streaming cache
                # entry for this id, if any, so it doesn't linger.
                self._rendered_event_cache.pop(event["id"], None)
                cached = self._rendered_event_cache.get(event_key)
                if cached is not None:
                    content = cached
                else:
                    content = self._render_chat_content(data)
                    if content is not None:
                        self._rendered_event_cache[event_key] = content
        elif event["type"] == "tool":
            if event_key in self._rendered_event_cache:
                content = self._rendered_event_cache[event_key]
            else:
                content = render_tool_widget(event["data"])
                if content is not None:
                    self._rendered_event_cache[event_key] = content
        else:
            content = None

        return content

    def _render_or_extend_streaming(
        self,
        event: dict[str, Any],
        data: dict[str, Any],
    ) -> Any:
        """Cache key for streaming events is the event id alone, not
        ``(id, version)``, because ``version`` bumps on every delta.

        ``_rendered_content_len`` tracks the length of the *rendered* text
        (not the raw ``data["content"]`` length) so the boundary into the
        next tail slices at the correct position even when the markdown
        pass trims trailing whitespace.
        """
        event_id = event["id"]
        cached = self._rendered_event_cache.get(event_id)
        if cached is None:
            content = self._render_chat_content(data)
            if content is not None:
                self._rendered_event_cache[event_id] = content
                self._rendered_content_len[event_id] = (
                    len(content.plain) if isinstance(content, Text) else 0
                )
            return content
        return self._append_streaming_tail(event, cached, data)

    def _is_open_streaming_chat(self, event: dict[str, Any]) -> bool:
        if event["type"] != "chat":
            return False
        data = event.get("data") or {}
        if data.get("role") != "assistant":
            return False
        metadata = data.get("metadata") or {}
        streaming = bool(metadata.get("streaming"))
        is_open = self.live_view.is_open_assistant_event(event["id"])
        return streaming and is_open

    def _append_streaming_tail(
        self,
        event: dict[str, Any],
        cached: Any,
        data: dict[str, Any],
    ) -> Any:
        """Concatenate a freshly-rendered tail onto the cached ``Text``.

        The tail is sliced from the raw content starting at the position
        of the previous render's plain-text length, so the markdown pass
        can re-process the boundary characters (including any leading
        whitespace) without losing them.

        Cheap: only the new characters (since the last render) are run
        through the markdown pass. The previous ``Text`` is preserved
        verbatim.

        ponytail: mutate the cached Text in place — O(tail) per delta,
        not O(content). The cached Text lives in
        ``self._rendered_event_cache[event_id]`` and is safe to extend
        (we never re-render from a streaming cache; finalize pops it).
        Earlier we built a fresh ``combined = Text(); combined.append_text(cached)``
        on every delta, which copied the full accumulated Text every
        tick. For a 500KB final report that was ~120ms per delta in
        Textual — the post-completion lag.
        """
        if not isinstance(cached, Text):
            return cached
        content = data.get("content", "") or ""
        prev_len = self._rendered_content_len.get(event["id"], 0)
        if len(content) <= prev_len:
            return cached
        tail = content[prev_len:]
        tail_text = AgentMessageRenderer.render_tail(tail)
        if not tail_text.plain:
            return cached
        cached.append_text(tail_text)
        self._rendered_content_len[event["id"]] = len(cached.plain)
        return cached

    def _get_status_display_content(
        self, agent_id: str, agent_data: dict[str, Any]
    ) -> tuple[Text | None, Text, bool]:
        status = agent_data.get("status", "running")

        def keymap_styled(keys: list[tuple[str, str]]) -> Text:
            t = Text()
            for i, (key, action) in enumerate(keys):
                if i > 0:
                    t.append(" · ", style="dim")
                t.append(key, style="white")
                t.append(" ", style="dim")
                t.append(action, style="dim")
            return t

        simple_statuses: dict[str, tuple[str, str]] = {
            "stopped": ("Agent stopped", ""),
            "completed": ("Agent completed", ""),
        }

        if status in simple_statuses:
            msg, _ = simple_statuses[status]
            text = Text()
            text.append(msg)
            return (text, Text(), False)

        if status == "failed":
            error_msg = agent_data.get("error_message", "")
            text = Text()
            if error_msg:
                text.append(error_msg, style="red")
            else:
                text.append("Scan failed", style="red")
            self._stop_dot_animation()
            return (text, Text(), False)

        if status == "waiting":
            text = Text()
            text.append("Send message to resume", style="dim")
            return (text, Text(), False)

        if status == "running":
            if self._agent_has_real_activity(agent_id):
                animated_text = Text()
                animated_text.append_text(self._get_sweep_animation(self._sweep_colors))
                animated_text.append("esc", style="white")
                animated_text.append(" ", style="dim")
                animated_text.append("stop", style="dim")
                return (animated_text, keymap_styled([("ctrl-q", "quit")]), True)
            animated_text = self._get_animated_verb_text(agent_id, "Initializing")
            return (animated_text, keymap_styled([("ctrl-q", "quit")]), True)

        return (None, Text(), False)

    def _update_agent_status_display(self) -> None:
        status_display = self._status_display
        status_text = self._status_text
        keymap_indicator = self._keymap_indicator
        if status_display is None or status_text is None or keymap_indicator is None:
            return
        widgets = [status_display, status_text, keymap_indicator]
        if not all(self._is_widget_safe(w) for w in widgets):
            return

        if not self.selected_agent_id:
            self._safe_widget_operation(status_display.add_class, "hidden")
            return

        try:
            agent_data = self.live_view.agents[self.selected_agent_id]
            content, keymap, should_animate = self._get_status_display_content(
                self.selected_agent_id, agent_data
            )

            if not content:
                self._safe_widget_operation(status_display.add_class, "hidden")
                return

            self._safe_widget_operation(status_text.update, content)
            self._safe_widget_operation(keymap_indicator.update, keymap)
            self._safe_widget_operation(status_display.remove_class, "hidden")

            if should_animate:
                self._start_dot_animation()

        except (KeyError, Exception):
            self._safe_widget_operation(status_display.add_class, "hidden")

    def _update_stats_display(self) -> None:
        stats_display = self._stats_display
        if stats_display is None:
            return
        if not self._is_widget_safe(stats_display):
            return

        if self.screen.selections:
            return

        stats_text = build_tui_stats_text(self.report_state)
        plain = stats_text.plain if stats_text else ""

        if plain == self._last_stats_plain:
            return

        self._last_stats_plain = plain

        version = get_package_version()
        if plain:
            stats_text.append(f"\nv{version}", style="white")

        self._safe_widget_operation(stats_display.update, stats_text)

    def _update_vulnerabilities_panel(self) -> None:
        """Update the vulnerabilities panel with current vulnerability data."""
        vuln_panel = self._vulnerabilities_panel
        if vuln_panel is None:
            return
        if not self._is_widget_safe(vuln_panel):
            return

        vulnerabilities = self.report_state.vulnerability_reports

        if not vulnerabilities:
            self._last_vuln_signature = None
            self._safe_widget_operation(vuln_panel.add_class, "hidden")
            return

        signature = (
            len(vulnerabilities),
            tuple(
                (
                    v.get("id"),
                    v.get("severity"),
                    v.get("title"),
                    v.get("agent_id"),
                )
                for v in vulnerabilities
            ),
        )
        if signature == self._last_vuln_signature:
            return
        self._last_vuln_signature = signature

        enriched_vulns = []
        for vuln in vulnerabilities:
            enriched = dict(vuln)
            agent_name = enriched.get("agent_name")
            agent_id = enriched.get("agent_id")
            if not agent_name and isinstance(agent_id, str):
                agent_name = self._get_agent_name(agent_id)
            if agent_name:
                enriched["agent_name"] = agent_name
            enriched_vulns.append(enriched)

        self._safe_widget_operation(vuln_panel.remove_class, "hidden")
        vuln_panel.update_vulnerabilities(enriched_vulns)

    def _get_sweep_animation(self, color_palette: list[str]) -> Text:
        text = Text()
        num_squares = self._sweep_num_squares
        num_colors = len(color_palette)

        offset = num_colors - 1
        max_pos = (num_squares - 1) + offset
        total_range = max_pos + offset
        cycle_length = total_range * 2
        frame_in_cycle = self._spinner_frame_index % cycle_length

        wave_pos = total_range - abs(total_range - frame_in_cycle)
        sweep_pos = wave_pos - offset

        dot_color = "#0a3d1f"

        for i in range(num_squares):
            dist = abs(i - sweep_pos)
            color_idx = max(0, num_colors - 1 - dist)

            if color_idx == 0:
                text.append("·", style=Style(color=dot_color))
            else:
                color = color_palette[color_idx]
                text.append("▪", style=Style(color=color))

        text.append(" ")
        return text

    def _get_animated_verb_text(self, agent_id: str, verb: str) -> Text:  # noqa: ARG002
        text = Text()
        sweep = self._get_sweep_animation(self._sweep_colors)
        text.append_text(sweep)
        parts = verb.split(" ", 1)
        text.append(parts[0], style="white")
        if len(parts) > 1:
            text.append(" ", style="dim")
            text.append(parts[1], style="dim")
        return text

    def _start_dot_animation(self) -> None:
        if self._dot_animation_timer is None:
            self._dot_animation_timer = self.set_interval(0.06, self._animate_dots)

    def _stop_dot_animation(self) -> None:
        if self._dot_animation_timer is not None:
            self._dot_animation_timer.stop()
            self._dot_animation_timer = None

    def _animate_dots(self) -> None:
        has_active_agents = False

        if self.selected_agent_id and self.selected_agent_id in self.live_view.agents:
            agent_data = self.live_view.agents[self.selected_agent_id]
            status = agent_data.get("status", "running")
            if status in ["running", "waiting"]:
                has_active_agents = True
                num_colors = len(self._sweep_colors)
                offset = num_colors - 1
                max_pos = (self._sweep_num_squares - 1) + offset
                total_range = max_pos + offset
                cycle_length = total_range * 2
                self._spinner_frame_index = (self._spinner_frame_index + 1) % cycle_length
                self._update_agent_status_display()

        if not has_active_agents:
            has_active_agents = any(
                agent_data.get("status", "running") in ["running", "waiting"]
                for agent_data in self.live_view.agents.values()
            )

        if not has_active_agents:
            self._stop_dot_animation()
            self._spinner_frame_index = 0

    def _agent_has_real_activity(self, agent_id: str) -> bool:
        return self.live_view.has_events_for_agent(agent_id)

    def _agent_vulnerability_count(self, agent_id: str) -> int:
        # Cache vulnerability counts to avoid repeated O(n) scans
        current_count = len(self.report_state.vulnerability_reports)
        if current_count != self._vuln_cache_signature:
            self._vuln_count_cache.clear()
            self._vuln_cache_signature = current_count

        if agent_id not in self._vuln_count_cache:
            self._vuln_count_cache[agent_id] = sum(
                1
                for vuln in self.report_state.vulnerability_reports
                if vuln.get("agent_id") == agent_id
            )
        return self._vuln_count_cache[agent_id]

    def _gather_agent_events(self, agent_id: str) -> list[dict[str, Any]]:
        return self.live_view.events_for_agent(agent_id)

    def watch_selected_agent_id(self, _agent_id: str | None) -> None:
        if len(self.screen_stack) > 1:
            return

        if not self.is_mounted:
            return

        self._displayed_events.clear()
        self._pending_chat_content = None

        self.call_later(self._update_chat_view)
        self._update_agent_status_display()

    def _start_scan_thread(self) -> None:
        def scan_target() -> None:
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
                except (ConnectionError, TimeoutError) as e:
                    logging.exception("Network error during scan")
                    self._scan_error = e
                except RuntimeError as e:
                    logging.exception("Runtime error during scan")
                    self._scan_error = e
                except Exception as e:
                    logging.exception("Unexpected error during scan")
                    self._scan_error = e
                finally:
                    with contextlib.suppress(Exception):
                        loop.run_until_complete(
                            session_manager.cleanup(self.scan_config["run_name"]),
                        )
                    loop.close()
                    self._scan_completed.set()

            except Exception:
                logging.exception("Error setting up scan thread")
                self._scan_completed.set()

        self._scan_thread = threading.Thread(target=scan_target, daemon=True)
        self._scan_thread.start()

    def _capture_sdk_event(self, agent_id: str, event: Any) -> None:
        try:
            self.call_from_thread(self._record_sdk_event, agent_id, event)
        except RuntimeError:
            self._record_sdk_event(agent_id, event)

    def _record_sdk_event(self, agent_id: str, event: Any) -> None:
        self.live_view.ingest_sdk_event(agent_id, event)

    def _add_agent_node(self, agent_data: dict[str, Any]) -> None:
        if len(self.screen_stack) > 1:
            return

        if not self.is_mounted:
            return

        agent_id = agent_data["id"]
        parent_id = agent_data.get("parent_id")
        status = agent_data.get("status", "running")

        agents_tree = self._agents_tree
        if agents_tree is None:
            try:
                agents_tree = self.query_one("#agents_tree", Tree)
            except (ValueError, Exception):
                return

        agent_name_raw = agent_data.get("name", "Agent")

        status_indicators = {
            "running": "⚪",
            "waiting": "⏸",
            "completed": "🟢",
            "failed": "🔴",
            "stopped": "■",
        }

        status_icon = status_indicators.get(status, "○")
        vuln_count = self._agent_vulnerability_count(agent_id)
        vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
        agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

        try:
            if parent_id and parent_id in self.agent_nodes:
                parent_node = self.agent_nodes[parent_id]
                agent_node = parent_node.add(
                    agent_name,
                    data={"agent_id": agent_id},
                )
                parent_node.allow_expand = True
            else:
                agent_node = agents_tree.root.add(
                    agent_name,
                    data={"agent_id": agent_id},
                )

            agent_node.allow_expand = False
            agent_node.expand()
            self.agent_nodes[agent_id] = agent_node

            if len(self.agent_nodes) == 1:
                agents_tree.select_node(agent_node)
                self.selected_agent_id = agent_id

            self._reorganize_orphaned_agents(agent_id)
        except (AttributeError, ValueError, RuntimeError) as e:
            logger.warning(f"Failed to add agent node {agent_id}: {e}")

    def _copy_node_under(self, node_to_copy: TreeNode, new_parent: TreeNode) -> None:
        agent_id = node_to_copy.data["agent_id"]
        agent_data = self.live_view.agents.get(agent_id, {})
        agent_name_raw = agent_data.get("name", "Agent")
        status = agent_data.get("status", "running")

        status_indicators = {
            "running": "⚪",
            "waiting": "⏸",
            "completed": "🟢",
            "failed": "🔴",
            "stopped": "■",
        }

        status_icon = status_indicators.get(status, "○")
        vuln_count = self._agent_vulnerability_count(agent_id)
        vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
        agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

        new_node = new_parent.add(
            agent_name,
            data=node_to_copy.data,
        )
        new_node.allow_expand = node_to_copy.allow_expand

        self.agent_nodes[agent_id] = new_node

        for child in node_to_copy.children:
            self._copy_node_under(child, new_node)

        if node_to_copy.is_expanded:
            new_node.expand()

    def _reorganize_orphaned_agents(self, new_parent_id: str) -> None:
        agents_to_move = []

        for agent_id, agent_data in list(self.live_view.agents.items()):
            if (
                agent_data.get("parent_id") == new_parent_id
                and agent_id in self.agent_nodes
                and agent_id != new_parent_id
            ):
                agents_to_move.append(agent_id)

        if not agents_to_move:
            return

        parent_node = self.agent_nodes[new_parent_id]

        for child_agent_id in agents_to_move:
            if child_agent_id in self.agent_nodes:
                old_node = self.agent_nodes[child_agent_id]

                if old_node.parent is parent_node:
                    continue

                self._copy_node_under(old_node, parent_node)

                old_node.remove()

        parent_node.allow_expand = True
        parent_node.expand()

    def _render_chat_content(self, msg_data: dict[str, Any]) -> Any:
        role = msg_data.get("role")
        content = msg_data.get("content", "")
        metadata = msg_data.get("metadata", {})

        if not content:
            return None

        del metadata
        if role == "user":
            return UserMessageRenderer.render_simple(content)

        return AgentMessageRenderer.render_simple(content)

    @on(Tree.NodeHighlighted)  # type: ignore[misc]
    def handle_tree_highlight(self, event: Tree.NodeHighlighted) -> None:
        if len(self.screen_stack) > 1:
            return

        if not self.is_mounted:
            return

        node = event.node

        agents_tree = self._agents_tree
        if agents_tree is None:
            try:
                agents_tree = self.query_one("#agents_tree", Tree)
            except (ValueError, Exception):
                return

        if self.focused == agents_tree and node.data:
            agent_id = node.data.get("agent_id")
            if agent_id:
                self.selected_agent_id = agent_id

    @on(Tree.NodeSelected)  # type: ignore[misc]
    def handle_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if len(self.screen_stack) > 1:
            return

        if not self.is_mounted:
            return

        node = event.node

        if node.allow_expand:
            if node.is_expanded:
                node.collapse()
            else:
                node.expand()

    def _send_user_message(self, message: str) -> None:
        if self._awaiting_target:
            self._submit_target(message)
            return

        if not self.selected_agent_id:
            return

        logger.info(
            "TUI: user message -> %s (len=%d)",
            self.selected_agent_id,
            len(message),
        )
        target_agent_id = self.selected_agent_id

        submitted = send_user_message_to_agent(
            coordinator=self.coordinator,
            loop=self._scan_loop,
            live_view=self.live_view,
            target_agent_id=target_agent_id,
            message=message,
        )
        if not submitted:
            self.notify("Scan loop is not ready; message was not sent", severity="warning")
            return

        self._displayed_events.clear()
        self._update_chat_view()

        self.call_after_refresh(self._focus_chat_input)

    def _submit_target(self, message: str) -> None:
        lines = message.splitlines()
        target_raw = lines[0].strip()
        extra_instruction = "\n".join(lines[1:]).strip()

        if not target_raw:
            self.notify("Enter a target or a prompt to begin", severity="warning")
            return

        try:
            target_type, target_dict = infer_target_type(target_raw)
        except ValueError:
            # Free-form text that doesn't parse as a target → prompt-only run.
            self._submit_prompt_only(message)
            return

        display_target = (
            target_dict.get("target_path", target_raw)
            if target_type == "local_code"
            else target_raw
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

        self.report_state.set_scan_config(self.scan_config)
        self.report_state.save_run_data()

        self._persist_target_metadata()

        self._awaiting_target = False
        self._start_scan_thread()
        self._update_chat_view()
        self._update_stats_display()
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

        self.report_state.set_scan_config(self.scan_config)
        self.report_state.save_run_data()

        self._persist_target_metadata()

        self._awaiting_target = False
        self._start_scan_thread()
        self._update_chat_view()
        self._update_stats_display()
        self.notify("Prompt-only run started", timeout=3)

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

    def _get_agent_name(self, agent_id: str) -> str:
        try:
            if agent_id in self.live_view.agents:
                agent_name = self.live_view.agents[agent_id].get("name")
                if isinstance(agent_name, str):
                    return agent_name
        except (KeyError, AttributeError) as e:
            logger.warning(f"Could not retrieve agent name for {agent_id}: {e}")
        return "Unknown Agent"

    def action_toggle_help(self) -> None:
        if not self.is_mounted:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            return

        if isinstance(self.screen, HelpScreen):
            self.pop_screen()
            return

        if len(self.screen_stack) > 1:
            return

        self.push_screen(HelpScreen())

    async def action_request_quit(self) -> None:
        if not self.is_mounted:
            await self.action_custom_quit()
            return

        if len(self.screen_stack) > 1:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            await self.action_custom_quit()
            return

        self.push_screen(QuitScreen())

    def action_stop_selected_agent(self) -> None:
        if not self.is_mounted:
            return

        if len(self.screen_stack) > 1:
            self.pop_screen()
            return

        if not self.selected_agent_id:
            return

        agent_name, should_stop = self._validate_agent_for_stopping()
        if not should_stop:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            return

        self.push_screen(StopAgentScreen(agent_name, self.selected_agent_id))

    def _validate_agent_for_stopping(self) -> tuple[str, bool]:
        agent_name = "Unknown Agent"

        try:
            if self.selected_agent_id in self.live_view.agents:
                agent_data = self.live_view.agents[self.selected_agent_id]
                agent_name = agent_data.get("name", "Unknown Agent")

                agent_status = agent_data.get("status", "running")
                if agent_status not in ["running", "waiting"]:
                    return agent_name, False

                agent_events = self._gather_agent_events(self.selected_agent_id)
                if not agent_events:
                    return agent_name, False

                return agent_name, True

        except (KeyError, AttributeError, ValueError) as e:
            logger.warning(f"Failed to gather agent events: {e}")

        return agent_name, False

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

    def _is_widget_safe(self, widget: Any) -> bool:
        try:
            _ = widget.screen
        except (AttributeError, ValueError, Exception):
            return False
        else:
            return bool(widget.is_mounted)

    def _safe_widget_operation(
        self, operation: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> bool:
        try:
            operation(*args, **kwargs)
        except (AttributeError, ValueError, Exception):
            return False
        else:
            return True

    def on_resize(self, event: events.Resize) -> None:
        if not self.is_mounted:
            return

        try:
            sidebar = self.query_one("#sidebar", Vertical)
            chat_area = self.query_one("#chat_area_container", Vertical)
        except (ValueError, Exception):
            return

        if event.size.width < self.SIDEBAR_MIN_WIDTH:
            sidebar.add_class("-hidden")
            chat_area.add_class("-full-width")
        else:
            sidebar.remove_class("-hidden")
            chat_area.remove_class("-full-width")

    def on_mouse_up(self, _event: events.MouseUp) -> None:
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
        copied = False
        text = ""

        try:
            if self.screen.selections:
                selected = self.screen.get_selected_text()
                self.screen.clear_selection()
                if selected and selected.strip():
                    cleaned = self._clean_copied_text(selected)
                    text = cleaned if cleaned.strip() else selected
                    copied = True
        except Exception:
            logger.debug("Failed to copy screen selection", exc_info=True)

        if not copied:
            try:
                chat_input = self.query_one("#chat_input", ChatTextArea)
                selected = chat_input.selected_text
                if selected and selected.strip():
                    text = selected
                    chat_input.move_cursor(chat_input.cursor_location)
                    copied = True
            except Exception:
                logger.debug("Failed to copy chat input selection", exc_info=True)

        if not copied or not text:
            return

        os_copied = _copy_to_system_clipboard(text)
        try:
            self.copy_to_clipboard(text)
        except Exception:
            logger.debug("Textual clipboard write failed", exc_info=True)

        if os_copied:
            self.notify("Copied to clipboard", timeout=2)
        else:
            preview = text if len(text) <= 200 else text[:197] + "..."
            self.notify(
                f"Copied to TUI clipboard only (no OS clipboard tool found).\n{preview}",
                timeout=8,
                severity="warning",
            )


async def run_tui(args: argparse.Namespace) -> None:
    app = KaelTUIApp(args)
    await app.run_async()
    if app._scan_error is not None:
        raise app._scan_error
