"""Selection meta-tools: discover the catalog at runtime.

Ponytail: thin SDK ``FunctionTool`` wrappers around
:pyfunc:`kael.tools.registry.ToolRegistry` queries. Agents that need
to pick a tool they have not seen yet can call ``list_tools`` /
``describe_tool`` instead of guessing. The system prompt also renders
a static catalog via :pyfunc:`REGISTRY.tool_schema_for_prompt` so the
LLM has the catalog in context without burning a tool call.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agents import function_tool

from kael.tools.registry import REGISTRY


if TYPE_CHECKING:
    from agents.tool import Tool


@function_tool
def list_tools(category: str | None = None, scan_mode: str = "deep") -> list[str]:
    """List every tool available in this scan mode, optionally filtered by category.

    Use this when you need to confirm a tool exists before calling it,
    or to browse the catalog by category (``"re"``, ``"ctf"``,
    ``"web_research"``, ``"meta"``, ``"proxy"``, ``"agent_graph"``,
    ``"reporting"``, ``"lifecycle"``).
    """
    return REGISTRY.names(category=category, scan_mode=scan_mode)


@function_tool
def describe_tool(name: str, scan_mode: str = "deep") -> str:
    """Return the full description, "when to use" guidance, and examples for one tool.

    Use this when a tool's name appeared in a catalog and you need its
    exact argument schema before calling it. Returns an empty string
    if the tool is not registered in this scan mode.
    """
    entry = REGISTRY.get(name)
    if entry is None or scan_mode not in entry.scan_modes:
        return ""
    description = getattr(entry.tool, "description", "") or ""
    parts: list[str] = [f"# {entry.name} [{entry.category}]", "", description]
    if entry.when_to_use:
        parts.extend(["", "## When to use", "", entry.when_to_use])
    if entry.examples:
        parts.append("")
        parts.append("## Examples")
        parts.extend(f"- {ex}" for ex in entry.examples)
    return "\n".join(parts)


def selection_tools() -> tuple[Tool, ...]:
    """Return the selection meta-tools as a tuple for agent registration."""
    return (list_tools, describe_tool)
