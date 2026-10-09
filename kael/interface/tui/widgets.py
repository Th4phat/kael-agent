"""Per-event chat widgets and label helpers for the Kael TUI.

Every live-view event maps to exactly one widget mounted in its agent's
``VerticalScroll``. Updates touch only that widget, so the cost of a
streamed token or a finished tool call is independent of history size.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.containers import VerticalScroll
from textual.content import Content
from textual.widgets import Markdown, Static

from kael.interface.tui.renderers import render_tool_widget


if TYPE_CHECKING:
    from textual.geometry import Size
    from textual.timer import Timer
    from textual.widget import Widget

# ponytail: mounted-widget ceiling per agent. Older events stay in the
# live view (and on disk) but are unmounted from the chat. Upgrade: mount
# older events on scroll-to-top.
MAX_MOUNTED_EVENTS = 300

# ponytail: ``Markdown.update()`` on a huge document (a 300KB final report
# on resume) costs ~1s; a plain Static is instant. Streamed messages never
# hit this — they grow via ``append`` — only non-streamed ones do.
MARKDOWN_MAX_CHARS = 64_000

# status -> (glyph, theme palette key or literal Rich style)
STATUS_GLYPHS: dict[str, tuple[str, str]] = {
    "running": ("●", "success"),
    "waiting": ("◐", "warning"),
    "completed": ("✓", "dim"),
    "failed": ("✗", "error"),
    "crashed": ("✗", "error"),
    "stopped": ("■", "dim"),
}


class ChatStream(VerticalScroll):
    """One agent's transcript. Follows the bottom once content overflows.

    Textual's ``anchor()`` pins ``scroll_y`` to ``content_bottom - height``,
    which goes negative (content rendered bottom-aligned) while the content
    is shorter than the viewport — so only anchor after it overflows. From
    then on Textual releases/re-attaches the anchor as the user scrolls.
    """

    def watch_virtual_size(self, _size: Size) -> None:
        # Sizes are only consistent after the layout pass completes.
        self.call_after_refresh(self.maybe_anchor)

    def maybe_anchor(self) -> None:
        if (
            not self.is_anchored
            and self.container_size.height > 0
            and self.virtual_size.height > self.container_size.height
        ):
            self.anchor()


class AssistantMessage(Markdown):
    """A streaming assistant (or reasoning) message.

    ``set_text`` is O(1): it stores the latest full text and arms a single
    timer. The flush appends only the new tail, so a burst of token deltas
    costs one ``Markdown.append`` per 100ms regardless of message size.
    """

    FLUSH_INTERVAL = 0.1

    def __init__(self, text: str, *, classes: str = "") -> None:
        super().__init__(text, classes=classes, open_links=False)
        self._shown = text
        self._text = text
        self._flush_timer: Timer | None = None

    @property
    def text(self) -> str:
        """The latest full text handed to :meth:`set_text`."""
        return self._text

    def set_text(self, text: str) -> None:
        self._text = text
        if self._flush_timer is None and self.is_attached:
            self._flush_timer = self.set_timer(self.FLUSH_INTERVAL, self._flush)

    def on_mount(self) -> None:
        if self._text != self._shown:
            self.set_text(self._text)

    async def _flush(self) -> None:
        self._flush_timer = None
        text, shown = self._text, self._shown
        if text == shown or not self.is_attached:
            return
        if text.startswith(shown):
            await self.append(text[len(shown) :])
        else:
            await self.update(text)
        self._shown = text


def make_event_widget(event: dict[str, Any]) -> Widget:
    """Build the widget for a live-view event. Its DOM id is the event id."""
    data = event.get("data") or {}
    widget: Widget
    if event["type"] == "tool":
        widget = render_tool_widget(data)
    else:
        role = data.get("role")
        content = str(data.get("content") or "")
        streaming = bool((data.get("metadata") or {}).get("streaming"))
        if role == "user":
            widget = Static(Content(content), classes="user-message")
        elif role == "reasoning":
            widget = AssistantMessage(content, classes="assistant reasoning folded")
            widget.border_title = "thinking"
        elif len(content) > MARKDOWN_MAX_CHARS and not streaming:
            widget = Static(Content(content), classes="assistant plain")
        else:
            widget = AssistantMessage(content, classes="assistant")
    widget.id = event["id"]
    return widget


def update_event_widget(widget: Widget, event: dict[str, Any]) -> None:
    """Apply a newer version of ``event`` to the widget built for it."""
    data = event.get("data") or {}
    if isinstance(widget, AssistantMessage):
        widget.set_text(str(data.get("content") or ""))
        return
    if not isinstance(widget, Static):
        return
    if event["type"] == "tool":
        fresh = render_tool_widget(data)
        folded = widget.has_class("folded")
        widget.update(fresh.content)
        widget.set_classes(fresh.classes)
        widget.set_class(folded, "folded")
    else:
        widget.update(Content(str(data.get("content") or "")))


def agent_label(
    name: str,
    status: str,
    *,
    vuln_count: int = 0,
    unread: int = 0,
    palette: dict[str, str],
) -> Text:
    """Tree label: status glyph, name, findings count, unread badge."""
    glyph, style = STATUS_GLYPHS.get(status, ("○", "dim"))
    label = Text()
    label.append(glyph, style=palette.get(style, style))
    label.append(f" {name}")
    if vuln_count:
        label.append(f" ({vuln_count})", style=palette.get("warning", ""))
    if unread:
        label.append(f" +{unread}", style=palette.get("accent", ""))
    return label
