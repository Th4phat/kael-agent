"""Note tool renderers — one parameterized class covers all five CRUD ops."""

from __future__ import annotations

from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


def _render_note_summary(text: Text, result: dict[str, Any], mode: str, fallback_verb: str) -> None:
    """Render the result body for a note op.

    ``mode`` is "create" (raw args), "update" (args echoed), "list" (table
    of notes), or "get" (single note). All four share the loading/empty
    branches; only the success branch differs.
    """
    if mode == "list":
        count = result.get("total_count", 0)
        notes = result.get("notes", []) or []
        if count == 0:
            text.append("\n  ")
            text.append("No notes", style="dim")
            return
        for note in notes:
            title = note.get("title", "").strip() or "(untitled)"
            category = note.get("category", "general")
            content = note.get("content", "").strip() or note.get("content_preview", "").strip()
            text.append("\n  - ")
            text.append(title)
            text.append(f" ({category})", style="dim")
            if content:
                text.append("\n    ")
                text.append(content, style="dim")
        return

    if mode == "get":
        note = result.get("note", {}) or {}
        title = str(note.get("title", "")).strip() or "(untitled)"
        category = note.get("category", "general")
        content = str(note.get("content", "")).strip()
        text.append("\n  ")
        text.append(title)
        text.append(f" ({category})", style="dim")
        if content:
            text.append("\n  ")
            text.append(content, style="dim")
        return

    # create / update: nothing to render from the result dict itself.
    text.append("\n  ")
    text.append(f"{fallback_verb}...", style="dim")


def _make_note_renderer(
    name: str,
    header: str,
    header_style: str,
    mode: str,
    show_args: bool = False,
) -> type[BaseToolRenderer]:
    """Build a Note tool renderer for one CRUD operation."""

    class _Renderer(BaseToolRenderer):
        css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

        @classmethod
        def render(cls, tool_data: dict[str, Any]) -> Static:
            args = tool_data.get("args", {})
            result = tool_data.get("result")

            text = Text()
            text.append("◇ ", style="#fbbf24")
            text.append(header, style=header_style)

            if show_args:
                title = args.get("title", "")
                content = args.get("content", "")
                category = args.get("category", "general")
                if mode == "create":
                    text.append(f" ({category})", style="dim")
                if title:
                    text.append("\n  ")
                    text.append(title.strip())
                if content:
                    text.append("\n  ")
                    text.append(content.strip(), style="dim")
                if not title and not content:
                    text.append("\n  ")
                    text.append("Capturing...", style="dim")
                return Static(text, classes=cls.get_css_classes("completed"))

            if isinstance(result, str) and result.strip():
                text.append("\n  ")
                text.append(result.strip(), style="dim")
            elif result and isinstance(result, dict) and result.get("success"):
                _render_note_summary(text, result, mode, "Loading")
            else:
                text.append("\n  ")
                text.append("Loading...", style="dim")

            return Static(text, classes=cls.get_css_classes("completed"))

    _Renderer.tool_name = name
    _Renderer.__name__ = f"NoteRenderer_{name}"
    return _Renderer


CreateNoteRenderer = register_tool_renderer(
    _make_note_renderer(
        "create_note",
        "note",
        "dim",
        "create",
        show_args=True,
    )
)
DeleteNoteRenderer = register_tool_renderer(
    _make_note_renderer(
        "delete_note",
        "note removed",
        "dim",
        "delete",
    )
)
UpdateNoteRenderer = register_tool_renderer(
    _make_note_renderer(
        "update_note",
        "note updated",
        "dim",
        "update",
        show_args=True,
    )
)
ListNotesRenderer = register_tool_renderer(
    _make_note_renderer(
        "list_notes",
        "notes",
        "dim",
        "list",
    )
)
GetNoteRenderer = register_tool_renderer(
    _make_note_renderer(
        "get_note",
        "note read",
        "dim",
        "get",
    )
)
