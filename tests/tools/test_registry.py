"""Tests for the kael.tools.registry module.

Covers the registry data structure itself, independent of the
factory bootstrap. Uses a fresh ``ToolRegistry`` per test for isolation.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest


def _make_mock_tool(name: str, description: str = "test tool"):
    tool = MagicMock()
    tool.name = name
    tool.description = description
    tool.on_invoke_tool = None
    return tool


class TestToolRegistryRegister:
    def test_register_returns_entry_with_name(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        tool = _make_mock_tool("alpha")
        entry = reg.register(tool, category="meta")
        assert entry.name == "alpha"
        assert entry.tool is tool
        assert entry.category == "meta"

    def test_register_default_scan_modes_is_deep(self) -> None:
        from kael.tools.registry import DEFAULT_SCAN_MODES, ToolRegistry

        reg = ToolRegistry()
        tool = _make_mock_tool("alpha")
        entry = reg.register(tool, category="meta")
        assert entry.scan_modes == DEFAULT_SCAN_MODES
        assert "deep" in entry.scan_modes

    def test_register_with_custom_scan_modes(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        tool = _make_mock_tool("re_tool")
        entry = reg.register(tool, category="re", scan_modes=frozenset({"malware_re"}))
        assert "malware_re" in entry.scan_modes
        assert "deep" not in entry.scan_modes

    def test_register_with_kwargs(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        tool = _make_mock_tool("slow_tool")
        entry = reg.register(
            tool,
            category="web_research",
            timeout_sec=330,
            cost_tier="med",
            parallel_safe=False,
        )
        assert entry.timeout_sec == 330
        assert entry.cost_tier == "med"
        assert entry.parallel_safe is False

    def test_duplicate_registration_raises(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        tool = _make_mock_tool("dup")
        reg.register(tool, category="meta")
        with pytest.raises(ValueError, match="already registered"):
            reg.register(tool, category="other")


class TestToolRegistryGet:
    def test_get_returns_entry(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        tool = _make_mock_tool("alpha")
        reg.register(tool, category="meta")
        assert reg.get("alpha").tool is tool

    def test_get_missing_returns_none(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        assert reg.get("nope") is None


class TestToolRegistryFilter:
    def test_filter_by_scan_mode(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        reg.register(_make_mock_tool("deep_only"), category="meta")
        reg.register(
            _make_mock_tool("re_tool"),
            category="re",
            scan_modes=frozenset({"malware_re"}),
        )

        deep = reg.filter(scan_mode="deep")
        re = reg.filter(scan_mode="malware_re")

        assert [t.name for t in deep] == ["deep_only"]
        assert [t.name for t in re] == ["re_tool"]

    def test_filter_allow_list(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        for n in ("a", "b", "c"):
            reg.register(_make_mock_tool(n), category="meta")
        out = reg.filter(allow={"a", "c"})
        assert sorted(t.name for t in out) == ["a", "c"]

    def test_filter_deny_list(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        for n in ("a", "b", "c"):
            reg.register(_make_mock_tool(n), category="meta")
        out = reg.filter(deny={"b"})
        assert sorted(t.name for t in out) == ["a", "c"]

    def test_filter_combines_scan_mode_and_lists(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        reg.register(_make_mock_tool("keep"), category="meta")
        reg.register(
            _make_mock_tool("re_only"),
            category="re",
            scan_modes=frozenset({"malware_re"}),
        )
        reg.register(_make_mock_tool("drop"), category="meta")
        out = reg.filter(scan_mode="deep", deny={"drop"})
        assert [t.name for t in out] == ["keep"]


class TestToolRegistryCategoriesAndNames:
    def test_names(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        reg.register(_make_mock_tool("a"), category="meta")
        reg.register(_make_mock_tool("b"), category="proxy")
        assert sorted(reg.names()) == ["a", "b"]

    def test_names_filtered_by_category(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        reg.register(_make_mock_tool("a"), category="meta")
        reg.register(_make_mock_tool("b"), category="proxy")
        assert reg.names(category="proxy") == ["b"]

    def test_categories_ordered_by_insertion(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        reg.register(_make_mock_tool("a"), category="meta")
        reg.register(_make_mock_tool("b"), category="proxy")
        reg.register(_make_mock_tool("c"), category="meta")
        assert reg.categories() == ["meta", "proxy"]


class TestToolRegistrySchemaForPrompt:
    def test_renders_categorised_markdown(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        reg.register(_make_mock_tool("think", "Chain of thought note."), category="meta")
        reg.register(_make_mock_tool("web_search", "Search the web."), category="web_research")

        out = reg.tool_schema_for_prompt()
        assert "## meta" in out
        assert "## web_research" in out
        assert "`think`" in out
        assert "Chain of thought note." in out
        assert "`web_search`" in out

    def test_uses_first_line_of_multiline_description(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        reg.register(
            _make_mock_tool("x", "First line.\nSecond line.\nThird."),
            category="meta",
        )
        out = reg.tool_schema_for_prompt()
        assert "First line." in out
        assert "Second line." not in out

    def test_renders_when_to_use_and_examples(self) -> None:
        from kael.tools.registry import ToolRegistry

        reg = ToolRegistry()
        reg.register(
            _make_mock_tool("web_search", "Search the web."),
            category="web_research",
            when_to_use="When you need a how-to.",
            examples=("How does XSS work?", "Latest CVEs for log4j"),
        )
        out = reg.tool_schema_for_prompt()
        assert "When: When you need a how-to." in out
        assert "e.g. How does XSS work?" in out
        assert "e.g. Latest CVEs for log4j" in out


class TestProcessRegistry:
    @pytest.fixture(autouse=True)
    def _bootstrap_factory(self) -> None:
        import kael.agents.factory  # triggers _register_default_tools()

    def test_global_registry_populated_by_factory_import(self) -> None:
        from kael.tools.registry import REGISTRY

        names = set(REGISTRY.names())
        assert "think" in names
        assert "load_skill" in names
        assert "create_vulnerability_report" in names
        assert "finish_scan" in names
        assert "agent_finish" in names

    def test_factory_get_base_tools_deep_returns_base_count(self) -> None:
        from kael.agents.factory import _BASE_TOOLS, get_base_tools

        assert len(_BASE_TOOLS) == len(get_base_tools("deep"))
        assert len(_BASE_TOOLS) >= 25  # matches existing test_factory.py contract

    def test_factory_get_base_tools_malware_re_registers_lazy(self) -> None:
        from kael.agents.factory import get_base_tools

        tools = get_base_tools("malware_re")
        names = {t.name for t in tools}
        assert "think" in names
        assert "file_triage" in names
        assert "yara_scan" in names
        assert "sandbox_detonate" in names
        # base + 13 re
        assert len(tools) >= 30 + 13

    def test_factory_get_base_tools_ctf_registers_lazy(self) -> None:
        from kael.agents.factory import get_base_tools
        from kael.tools.ctf_tools import ALL_CTF_TOOLS

        tools = get_base_tools("ctf")
        ctf_names = {t.name for t in ALL_CTF_TOOLS}
        returned = {t.name for t in tools}
        assert ctf_names.issubset(returned)
        assert "think" in returned

    def test_registry_has_categories_meta_web_research_proxy(self) -> None:
        from kael.tools.registry import REGISTRY

        cats = set(REGISTRY.categories())
        assert {"meta", "web_research", "reporting", "proxy", "agent_graph"}.issubset(cats)

    def test_selection_tools_registered(self) -> None:
        from kael.tools.registry import REGISTRY

        assert REGISTRY.get("list_tools") is not None
        assert REGISTRY.get("describe_tool") is not None

    def test_search_tools_have_when_to_use_metadata(self) -> None:
        from kael.tools.registry import REGISTRY

        for name in ("web_search", "exploit_search", "exploit_db_search", "cve_lookup"):
            entry = REGISTRY.get(name)
            assert entry is not None, name
            assert entry.when_to_use, f"{name} missing when_to_use"
            assert entry.examples, f"{name} missing examples"
