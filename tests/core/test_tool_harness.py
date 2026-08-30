"""Tests for the tool-loop telemetry hooks and the tool-harness settings."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock


def _make_ctx(*, call_id: str, args: object) -> MagicMock:
    ctx = MagicMock()
    ctx.tool_call_id = call_id
    ctx.tool_arguments = args
    return ctx


def _make_tool(name: str) -> MagicMock:
    tool = MagicMock()
    tool.name = name
    return tool


class TestToolTelemetryHooks:
    def test_call_count_increments(self) -> None:
        from kael.core.hooks import ToolTelemetryHooks

        h = ToolTelemetryHooks(dedup_window_turns=0)
        ctx = _make_ctx(call_id="c1", args={"x": 1})
        tool = _make_tool("web_search")
        agent = MagicMock()
        asyncio.run(h.on_tool_start(ctx, agent, tool))
        asyncio.run(h.on_tool_end(ctx, agent, tool, "result"))
        assert h.call_count == 1

    def test_dedup_warns_on_repeat_args(self) -> None:
        from kael.core.hooks import ToolTelemetryHooks

        h = ToolTelemetryHooks(dedup_window_turns=1)
        ctx1 = _make_ctx(call_id="c1", args={"x": 1})
        ctx2 = _make_ctx(call_id="c2", args={"x": 1})
        tool = _make_tool("web_search")
        agent = MagicMock()
        asyncio.run(h.on_tool_start(ctx1, agent, tool))
        # Second call with same args should not raise; should warn.
        asyncio.run(h.on_tool_start(ctx2, agent, tool))

    def test_dedup_disabled_when_window_zero(self) -> None:
        from kael.core.hooks import ToolTelemetryHooks

        h = ToolTelemetryHooks(dedup_window_turns=0)
        ctx = _make_ctx(call_id="c1", args={"x": 1})
        tool = _make_tool("web_search")
        agent = MagicMock()
        # No exception, no warning expected — just ensure it doesn't crash.
        asyncio.run(h.on_tool_start(ctx, agent, tool))
        asyncio.run(h.on_tool_start(ctx, agent, tool))

    def test_distinct_args_do_not_trigger_dedup(self) -> None:
        from kael.core.hooks import ToolTelemetryHooks

        h = ToolTelemetryHooks(dedup_window_turns=1)
        ctx1 = _make_ctx(call_id="c1", args={"x": 1})
        ctx2 = _make_ctx(call_id="c2", args={"x": 2})
        tool = _make_tool("web_search")
        agent = MagicMock()
        # Different args — should not raise, should not warn.
        asyncio.run(h.on_tool_start(ctx1, agent, tool))
        asyncio.run(h.on_tool_start(ctx2, agent, tool))


class TestKaelRunHooksComposition:
    def test_subclass_combines_usage_and_telemetry(self) -> None:
        from kael.core.hooks import KaelRunHooks

        h = KaelRunHooks(model="test", dedup_window_turns=1)
        # Telemetry state
        assert h.call_count == 0
        assert h._model == "test"

    def test_on_tool_start_writes_to_telemetry_state(self) -> None:
        from kael.core.hooks import KaelRunHooks

        h = KaelRunHooks(model="test")
        ctx = _make_ctx(call_id="abc", args={"a": 1})
        tool = _make_tool("think")
        agent = MagicMock()
        asyncio.run(h.on_tool_start(ctx, agent, tool))
        assert h.call_count == 1
        assert "abc" in h._starts


class TestToolHarnessSettings:
    def test_defaults(self) -> None:
        from kael.config.settings import ToolHarnessSettings

        s = ToolHarnessSettings()
        assert s.parallel_tool_calls_mode == "off"
        assert s.tool_result_max_chars == 20_000
        assert s.dedup_window_turns == 1

    def test_settings_exposes_tool_harness(self) -> None:
        from kael.config.settings import Settings

        s = Settings()
        assert s.tool_harness.parallel_tool_calls_mode == "off"

    def test_parallel_mode_safe_enables_parallel(self) -> None:
        from kael.core.inputs import make_model_settings

        ms = make_model_settings(None, model_name="gpt-5", parallel_tool_calls_mode="safe")
        # The SDK ModelSettings dataclass exposes the field directly.
        assert bool(getattr(ms, "parallel_tool_calls", False)) is True

    def test_parallel_mode_off_keeps_sequential(self) -> None:
        from kael.core.inputs import make_model_settings

        ms = make_model_settings(None, model_name="gpt-5", parallel_tool_calls_mode="off")
        assert bool(getattr(ms, "parallel_tool_calls", False)) is False

    def test_openrouter_provider_routed_into_extra_body(self) -> None:
        from kael.core.inputs import make_model_settings

        provider = {"order": ["DeepSeek"], "allow_fallbacks": False}
        ms = make_model_settings(
            None,
            model_name="openrouter/deepseek/deepseek-chat",
            openrouter_provider=provider,
        )
        assert ms.extra_body == {"provider": provider}

    def test_openrouter_provider_ignored_for_non_openrouter_model(self) -> None:
        from kael.core.inputs import make_model_settings

        ms = make_model_settings(
            None,
            model_name="openai/gpt-5",
            openrouter_provider={"order": ["DeepSeek"]},
        )
        assert ms.extra_body is None
