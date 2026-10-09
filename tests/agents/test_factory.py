"""Tests for the agent factory tool registration and tool wrapper helpers.

Targets the parts of ``kael/agents/factory.py`` that are reachable
without invoking the OpenAI Agents SDK's agent loop (which needs a
live LLM): the static tool list, the wrapper helpers, and the tool-
use-behavior decision logic.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest


def _run(coro_or_value):
    """Await a possibly-coroutine result from a mock ``on_invoke_tool``."""
    if asyncio.iscoroutine(coro_or_value):
        return asyncio.run(coro_or_value)
    return coro_or_value


class TestBaseToolsRegistration:
    """Smoke tests for the tools registered on every Kael agent.

    The factory imports 24+ tool functions; we verify the *changed*
    contract — that ``exploit_search`` is now in the base toolset
    alongside ``web_search``, and that the agent builder accepts the
    factory kwargs without raising.
    """

    def test_exploit_search_is_in_base_tools(self) -> None:
        from kael.agents.factory import _BASE_TOOLS
        from kael.tools.exploit_search.tool import exploit_search
        from kael.tools.web_search.tool import web_search

        tool_names = {t.name for t in _BASE_TOOLS}
        assert "exploit_search" in tool_names
        assert "web_search" in tool_names
        assert any(t is exploit_search for t in _BASE_TOOLS)
        assert any(t is web_search for t in _BASE_TOOLS)

    def test_all_expected_base_tools_present(self) -> None:
        from kael.agents.factory import _BASE_TOOLS

        tool_names = {t.name for t in _BASE_TOOLS}
        expected = {
            "think",
            "load_skill",
            "create_todo",
            "list_todos",
            "update_todo",
            "mark_todo_done",
            "mark_todo_pending",
            "delete_todo",
            "create_note",
            "list_notes",
            "get_note",
            "update_note",
            "delete_note",
            "web_search",
            "exploit_search",
            "create_vulnerability_report",
            "list_requests",
            "view_request",
            "repeat_request",
            "list_sitemap",
            "view_sitemap_entry",
            "scope_rules",
            "view_agent_graph",
            "send_message_to_agent",
            "wait_for_message",
            "create_agent",
            "stop_agent",
        }
        assert expected.issubset(tool_names)

    def test_no_duplicate_tool_names(self) -> None:
        from kael.agents.factory import _BASE_TOOLS

        names = [t.name for t in _BASE_TOOLS]
        assert len(names) == len(set(names)), f"Duplicate tool names: {names}"


class TestWrapFunctionTool:
    """The unified tool wrapper: validation + manifest errors → readable strings.

    Without ``catch_errors=True`` only ValidationError and
    InvalidManifestPathError are caught — other exceptions propagate.
    With ``catch_errors=True`` every exception is caught and returned
    as a result string (used for chat-completions backends).
    """

    def test_validation_error_becomes_readable_string(self) -> None:
        from pydantic import BaseModel, Field

        from kael.agents.factory import _wrap_function_tool

        class _Args(BaseModel):
            x: int = Field(...)

        async def invoke(_ctx, _raw):
            _Args(x="not an int")  # type: ignore[arg-type]
            return "ok"

        tool = MagicMock()
        tool.name = "my_tool"
        tool.on_invoke_tool = invoke
        wrapped = _wrap_function_tool(tool)
        result = _run(wrapped.on_invoke_tool(MagicMock(), "{}"))
        assert result.startswith("my_tool: invalid arguments")
        assert "x" in result

    def test_invalid_manifest_path_returns_workdir_hint(self) -> None:
        from agents.sandbox.errors import InvalidManifestPathError

        from kael.agents.factory import _wrap_function_tool

        async def invoke(_ctx, _raw):
            raise InvalidManifestPathError(rel="/etc/passwd", reason="escape_root")

        tool = MagicMock()
        tool.name = "exec_command"
        tool.on_invoke_tool = invoke
        wrapped = _wrap_function_tool(tool)
        result = _run(wrapped.on_invoke_tool(MagicMock(), "{}"))
        assert "workdir must be a path inside /workspace" in result
        assert "/etc/passwd" in result

    def test_unrelated_exception_propagates_when_not_catching(self) -> None:
        from kael.agents.factory import _wrap_function_tool

        async def invoke(_ctx, _raw):
            raise RuntimeError("boom")

        tool = MagicMock()
        tool.name = "test_tool"
        tool.on_invoke_tool = invoke
        wrapped = _wrap_function_tool(tool)
        with pytest.raises(RuntimeError, match="boom"):
            _run(wrapped.on_invoke_tool(MagicMock(), "{}"))

    def test_unrelated_exception_returned_as_string_when_catching(self) -> None:
        from kael.agents.factory import _wrap_function_tool

        async def invoke(_ctx, _raw):
            raise RuntimeError("boom")

        tool = MagicMock()
        tool.name = "test_tool"
        tool.on_invoke_tool = invoke
        wrapped = _wrap_function_tool(tool, catch_errors=True)
        result = _run(wrapped.on_invoke_tool(MagicMock(), "{}"))
        assert "boom" in result

    def test_normal_result_passes_through(self) -> None:
        from kael.agents.factory import _wrap_function_tool

        tool = MagicMock()
        tool.name = "test_tool"
        tool.on_invoke_tool = AsyncMock(return_value="ok result")
        wrapped = _wrap_function_tool(tool)
        result = _run(wrapped.on_invoke_tool(MagicMock(), "{}"))
        assert result == "ok result"

    def test_repeated_invalid_shell_json_requests_recovery(self) -> None:
        from agents.tool import FunctionTool
        from pydantic import BaseModel

        from kael.agents.factory import (
            RepeatedInvalidToolArguments,
            _configure_shell_tools,
        )

        class Args(BaseModel):
            session_id: int
            chars: str = ""

        async def invoke(_ctx, raw):
            Args.model_validate_json(raw)
            return "ok"

        shell = MagicMock()
        shell.write_stdin = FunctionTool(
            name="write_stdin",
            description="Write to a running process",
            params_json_schema=Args.model_json_schema(),
            on_invoke_tool=invoke,
            strict_json_schema=False,
        )
        _configure_shell_tools(shell, chat_completions=True)
        ctx = MagicMock(context={})
        bad = '{"session_id":49984,"chars":'

        first = _run(shell.write_stdin.on_invoke_tool(ctx, bad))
        assert "Invalid JSON" in first
        assert "interrupt=true" in first
        with pytest.raises(RepeatedInvalidToolArguments):
            _run(shell.write_stdin.on_invoke_tool(ctx, bad))

        assert _run(shell.write_stdin.on_invoke_tool(ctx, '{"session_id":49984}')) == "ok"
        assert shell.write_stdin.params_json_schema["properties"]["interrupt"]["type"] == "boolean"

    def test_write_stdin_interrupt_sends_ctrl_c(self) -> None:
        from types import SimpleNamespace

        from agents.sandbox.capabilities.tools.shell_tool import WriteStdinTool

        from kael.agents.factory import _configure_shell_tools

        session = MagicMock()
        session.supports_pty.return_value = True
        session.pty_write_stdin = AsyncMock(
            return_value=SimpleNamespace(
                output=b"", exit_code=None, process_id=49984, original_token_count=None
            )
        )
        shell = SimpleNamespace(write_stdin=WriteStdinTool(session=session))
        _configure_shell_tools(shell, chat_completions=True)

        _run(
            shell.write_stdin.on_invoke_tool(
                MagicMock(context={}), '{"session_id":49984,"interrupt":true}'
            )
        )

        assert session.pty_write_stdin.await_args.kwargs["chars"] == "\x03"


class TestFormatToolError:
    def test_uses_str_when_available(self) -> None:
        from kael.agents.factory import _format_tool_error

        assert _format_tool_error(ValueError("custom message")) == "custom message"

    def test_uses_class_name_when_str_empty(self) -> None:
        from kael.agents.factory import _format_tool_error

        class EmptyError(Exception):
            def __str__(self) -> str:
                return ""

        assert _format_tool_error(EmptyError()) == "EmptyError"


class TestLifecycleToolCompleted:
    def test_agent_finish_success(self) -> None:
        from kael.agents.factory import _lifecycle_tool_completed

        assert (
            _lifecycle_tool_completed(
                "agent_finish",
                json.dumps({"success": True, "agent_completed": True}),
            )
            is True
        )

    def test_finish_scan_success(self) -> None:
        from kael.agents.factory import _lifecycle_tool_completed

        assert (
            _lifecycle_tool_completed(
                "finish_scan",
                json.dumps({"success": True, "scan_completed": True}),
            )
            is True
        )

    def test_other_tool_returns_false(self) -> None:
        from kael.agents.factory import _lifecycle_tool_completed

        assert (
            _lifecycle_tool_completed(
                "web_search",
                json.dumps({"success": True}),
            )
            is False
        )

    def test_missing_success_key(self) -> None:
        from kael.agents.factory import _lifecycle_tool_completed

        assert (
            _lifecycle_tool_completed(
                "agent_finish",
                json.dumps({"agent_completed": True}),
            )
            is False
        )

    def test_missing_completion_key(self) -> None:
        from kael.agents.factory import _lifecycle_tool_completed

        assert (
            _lifecycle_tool_completed(
                "agent_finish",
                json.dumps({"success": True}),
            )
            is False
        )

    def test_non_string_output(self) -> None:
        from kael.agents.factory import _lifecycle_tool_completed

        assert _lifecycle_tool_completed("agent_finish", {"already": "parsed"}) is False
        assert _lifecycle_tool_completed("agent_finish", None) is False

    def test_invalid_json(self) -> None:
        from kael.agents.factory import _lifecycle_tool_completed

        assert _lifecycle_tool_completed("agent_finish", "{not json") is False


class TestWaitToolParked:
    def test_parked_returns_true(self) -> None:
        from kael.agents.factory import _wait_tool_parked

        assert (
            _wait_tool_parked(
                json.dumps({"success": True, "wait_outcome": "waiting"}),
            )
            is True
        )

    def test_other_outcome_returns_false(self) -> None:
        from kael.agents.factory import _wait_tool_parked

        assert (
            _wait_tool_parked(
                json.dumps({"success": True, "wait_outcome": "message_arrived"}),
            )
            is False
        )

    def test_non_string_output(self) -> None:
        from kael.agents.factory import _wait_tool_parked

        assert _wait_tool_parked({"already": "parsed"}) is False
        assert _wait_tool_parked(None) is False
