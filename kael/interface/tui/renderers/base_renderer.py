from abc import ABC, abstractmethod
from functools import cache
from typing import Any, ClassVar

from pygments.lexer import Lexer
from pygments.lexers import get_lexer_by_name
from pygments.styles import get_style_by_name
from rich.text import Text
from textual.widgets import Static


@cache
def _style_colors() -> dict[Any, str]:
    style = get_style_by_name("native")
    return {token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]}


def highlight(code: str, lexer: str | Lexer) -> Text:
    """Foreground-only Pygments highlighting as Rich ``Text``.

    Shared by every renderer that shows code; ``lexer`` is a Pygments
    lexer name or instance.
    """
    if isinstance(lexer, str):
        lexer = get_lexer_by_name(lexer)
    colors = _style_colors()
    text = Text()
    for token_type, token_value in lexer.get_tokens(code):
        if not token_value:
            continue
        token = token_type
        while token and token not in colors:
            token = token.parent
        text.append(token_value, style=colors[token] if token else None)
    return text


class BaseToolRenderer(ABC):
    tool_name: ClassVar[str] = ""
    css_classes: ClassVar[list[str]] = ["tool-call"]

    @classmethod
    @abstractmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        pass

    @classmethod
    def status_icon(cls, status: str) -> tuple[str, str]:
        icons = {
            "running": ("● In progress...", "#f59e0b"),
            "completed": ("✓ Done", "#22c55e"),
            "failed": ("✗ Failed", "#dc2626"),
            "error": ("✗ Error", "#dc2626"),
        }
        return icons.get(status, ("○ Unknown", "dim"))

    @classmethod
    def get_css_classes(cls, status: str) -> str:
        base_classes = cls.css_classes.copy()
        base_classes.append(f"status-{status}")
        return " ".join(base_classes)
