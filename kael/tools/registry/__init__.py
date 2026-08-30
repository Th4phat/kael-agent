"""Tool registry: process-wide catalog of every Kael tool.

Ponytail: replaces the hard-coded ``_BASE_TOOLS`` tuple in
``kael.agents/factory.py`` and the per-mode append logic in
``get_base_tools``. Tool modules can self-register at import time, or
factory.py can bulk-register the default set.

The registry also produces a compact ``<available_tools>`` markdown
block the system prompt can render so the LLM sees a categorised
catalog of what it can call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal


if TYPE_CHECKING:
    from agents.tool import Tool


CostTier = Literal["none", "low", "med", "high"]

DEFAULT_SCAN_MODES: frozenset[str] = frozenset({"deep"})
ALL_BUILTIN_SCAN_MODES: frozenset[str] = frozenset({"deep", "malware_re", "ctf"})


@dataclass(frozen=True)
class ToolEntry:
    name: str
    tool: Tool
    category: str
    scan_modes: frozenset[str] = DEFAULT_SCAN_MODES
    timeout_sec: int = 60
    cost_tier: CostTier = "low"
    parallel_safe: bool = True
    when_to_use: str = ""
    examples: tuple[str, ...] = ()


class ToolRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, ToolEntry] = {}

    def register(
        self,
        tool: Tool,
        *,
        category: str,
        scan_modes: frozenset[str] | set[str] = DEFAULT_SCAN_MODES,
        timeout_sec: int = 60,
        cost_tier: CostTier = "low",
        parallel_safe: bool = True,
        when_to_use: str = "",
        examples: tuple[str, ...] | list[str] = (),
    ) -> ToolEntry:
        entry = ToolEntry(
            name=tool.name,
            tool=tool,
            category=category,
            scan_modes=frozenset(scan_modes),
            timeout_sec=timeout_sec,
            cost_tier=cost_tier,
            parallel_safe=parallel_safe,
            when_to_use=when_to_use,
            examples=tuple(examples),
        )
        if entry.name in self._entries:
            raise ValueError(f"Tool {entry.name!r} already registered in this registry")
        self._entries[entry.name] = entry
        return entry

    def get(self, name: str) -> ToolEntry | None:
        return self._entries.get(name)

    def names(self, *, category: str | None = None, scan_mode: str = "deep") -> list[str]:
        return [e.name for e in self._iter(category=category, scan_mode=scan_mode)]

    def categories(self, *, scan_mode: str = "deep") -> list[str]:
        seen: list[str] = []
        for e in self._iter(scan_mode=scan_mode):
            if e.category not in seen:
                seen.append(e.category)
        return seen

    def filter(
        self,
        *,
        scan_mode: str = "deep",
        allow: set[str] | None = None,
        deny: set[str] | None = None,
    ) -> list[Tool]:
        out: list[Tool] = []
        for entry in self._iter(scan_mode=scan_mode):
            if allow is not None and entry.name not in allow:
                continue
            if deny is not None and entry.name in deny:
                continue
            out.append(entry.tool)
        return out

    def tool_schema_for_prompt(self, *, scan_mode: str = "deep") -> str:
        """Render a compact categorised catalog for system-prompt injection.

        Each tool gets a one-line summary. Tools that opted into
        ``when_to_use`` get a second "When to use:" line — this is the
        cheap if-X-then-y hint that P3 calls for, and lives in the
        registry instead of being baked into every tool module.
        """
        lines: list[str] = []
        for category in self.categories(scan_mode=scan_mode):
            entries = self._iter(category=category, scan_mode=scan_mode)
            if not entries:
                continue
            lines.append(f"## {category}")
            for entry in entries:
                description = getattr(entry.tool, "description", "") or ""
                first_line = description.splitlines()[0] if description else ""
                lines.append(f"- `{entry.name}` — {first_line}")
                if entry.when_to_use:
                    lines.append(f"  - When: {entry.when_to_use}")
                lines.extend(f"  - e.g. {ex}" for ex in entry.examples)
        return "\n".join(lines)

    def _iter(self, *, category: str | None = None, scan_mode: str = "deep") -> list[ToolEntry]:
        return [
            entry
            for entry in self._entries.values()
            if scan_mode in entry.scan_modes and (category is None or entry.category == category)
        ]


REGISTRY = ToolRegistry()
"""Process-wide registry. Populated by ``kael.agents.factory._register_default_tools``
at import time, and by tool modules that opt into self-registration."""
