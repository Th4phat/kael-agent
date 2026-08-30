"""Todo tool renderers — one parameterized class covers all six CRUD ops."""

from __future__ import annotations

from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


STATUS_MARKERS: dict[str, str] = {
    "pending": "[ ]",
    "in_progress": "[~]",
    "done": "[•]",
}


def _format_todo_lines(text: Text, result: dict[str, Any]) -> None:
    todos = result.get("todos")
    if not isinstance(todos, list) or not todos:
        text.append("\n  ")
        text.append("No todos", style="dim")
        return

    for todo in todos:
        status = todo.get("status", "pending")
        marker = STATUS_MARKERS.get(status, STATUS_MARKERS["pending"])
        title = todo.get("title", "").strip() or "(untitled)"

        text.append("\n  ")
        text.append(marker)
        text.append(" ")

        if status == "done":
            text.append(title, style="dim strike")
        elif status == "in_progress":
            text.append(title, style="italic")
        else:
            text.append(title)


def _make_todo_renderer(
    name: str,
    title: str,
    title_style: str,
    fallback_verb: str,
    error_label: str,
) -> type[BaseToolRenderer]:
    """Build a Todo tool renderer for one CRUD operation.

    The six todo tools differ only in: tool_name, header title, header
    color, the in-progress verb shown while the result is pending, and
    the error label. Everything else is shared.
    """

    class _Renderer(BaseToolRenderer):
        css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

        @classmethod
        def render(cls, tool_data: dict[str, Any]) -> Static:
            result = tool_data.get("result")

            text = Text()
            text.append("📋 ")
            text.append(title, style=title_style)

            if isinstance(result, str) and result.strip():
                text.append("\n  ")
                text.append(result.strip(), style="dim")
            elif result and isinstance(result, dict):
                if result.get("success"):
                    _format_todo_lines(text, result)
                else:
                    error = result.get("error", error_label)
                    text.append("\n  ")
                    text.append(error, style="#ef4444")
            else:
                text.append("\n  ")
                text.append(f"{fallback_verb}...", style="dim")

            return Static(text, classes=cls.get_css_classes("completed"))

    _Renderer.tool_name = name
    _Renderer.__name__ = f"TodoRenderer_{name}"
    return _Renderer


CreateTodoRenderer = register_tool_renderer(
    _make_todo_renderer(
        "create_todo",
        "Todo",
        "bold #a78bfa",
        "Creating",
        "Failed to create todo",
    )
)
ListTodosRenderer = register_tool_renderer(
    _make_todo_renderer(
        "list_todos",
        "Todos",
        "bold #a78bfa",
        "Loading",
        "Unable to list todos",
    )
)
UpdateTodoRenderer = register_tool_renderer(
    _make_todo_renderer(
        "update_todo",
        "Todo Updated",
        "bold #a78bfa",
        "Updating",
        "Failed to update todo",
    )
)
MarkTodoDoneRenderer = register_tool_renderer(
    _make_todo_renderer(
        "mark_todo_done",
        "Todo Completed",
        "bold #a78bfa",
        "Marking done",
        "Failed to mark todo done",
    )
)
MarkTodoPendingRenderer = register_tool_renderer(
    _make_todo_renderer(
        "mark_todo_pending",
        "Todo Reopened",
        "bold #f59e0b",
        "Reopening",
        "Failed to reopen todo",
    )
)
DeleteTodoRenderer = register_tool_renderer(
    _make_todo_renderer(
        "delete_todo",
        "Todo Removed",
        "bold #94a3b8",
        "Removing",
        "Failed to remove todo",
    )
)
