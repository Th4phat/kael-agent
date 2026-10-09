"""Build SandboxAgents for root + child Kael runs."""

from __future__ import annotations

import inspect
import json
import logging
from typing import TYPE_CHECKING, Any

from agents.agent import ToolsToFinalOutputResult
from agents.exceptions import ModelBehaviorError
from agents.sandbox import SandboxAgent
from agents.sandbox.capabilities import Filesystem, Shell
from agents.sandbox.errors import InvalidManifestPathError
from agents.tool import CustomTool, FunctionTool, Tool
from pydantic import ValidationError

from kael.agents.prompt import render_system_prompt
from kael.tools import registry as _registry_mod
from kael.tools.agents_graph.tools import (
    agent_finish,
    create_agent,
    recall_history,
    send_message_to_agent,
    stop_agent,
    view_agent_graph,
    wait_for_message,
)
from kael.tools.cvedb.tool import cve_lookup
from kael.tools.exploit_db.tool import exploit_db_search
from kael.tools.exploit_search.tool import exploit_search
from kael.tools.finish.tool import finish_scan
from kael.tools.load_skill.tool import load_skill
from kael.tools.notes.tools import (
    add_learning,
    create_note,
    delete_note,
    get_note,
    list_notes,
    update_note,
)
from kael.tools.proxy.tools import (
    list_requests,
    list_sitemap,
    repeat_request,
    scope_rules,
    view_request,
    view_sitemap_entry,
)
from kael.tools.registry.selection import (
    describe_tool as _describe_tool,
)
from kael.tools.registry.selection import (
    list_tools as _list_tools,
)
from kael.tools.reporting.tool import create_vulnerability_report
from kael.tools.thinking.tool import think
from kael.tools.todo.tools import (
    create_todo,
    delete_todo,
    list_todos,
    mark_todo_done,
    mark_todo_pending,
    update_todo,
)
from kael.tools.view_image.tool import ViewImageTool as _KaelViewImageTool
from kael.tools.web_search.tool import web_search


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from agents import RunContextWrapper
    from agents.tool import FunctionToolResult


logger = logging.getLogger(__name__)


class RepeatedInvalidToolArguments(ModelBehaviorError):
    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        super().__init__(f"Repeated invalid JSON arguments for {tool_name}")


def _format_tool_error(exc: Exception) -> str:
    return str(exc) or exc.__class__.__name__


def _wrap_function_tool(
    tool: FunctionTool, *, name: str | None = None, catch_errors: bool = False
) -> FunctionTool:
    """Replace ``on_invoke_tool`` with one that translates validation + manifest
    errors into model-readable strings. When ``catch_errors`` is True, every
    other exception is also caught and returned as a result string (used for
    chat-completions backends that can't tolerate raised exceptions).
    """
    invoke_tool = tool.on_invoke_tool
    tool_name = name or tool.name

    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            result = await invoke_tool(ctx, raw_input)
            if isinstance(getattr(ctx, "context", None), dict):
                ctx.context["_invalid_tool_json_count"] = 0
            return result
        except ValidationError as exc:
            invalid_json = any(err.get("type") == "json_invalid" for err in exc.errors())
            if invalid_json and isinstance(getattr(ctx, "context", None), dict):
                count = ctx.context.get("_invalid_tool_json_count", 0) + 1
                ctx.context["_invalid_tool_json_count"] = count
                if count >= 2:
                    ctx.context["_invalid_tool_json_count"] = 0
                    raise RepeatedInvalidToolArguments(tool_name) from exc
            parts: list[str] = []
            for err in exc.errors():
                loc = ".".join(str(x) for x in err.get("loc", ()))
                msg = err.get("msg", "invalid")
                parts.append(f"{loc}: {msg}" if loc else msg)
            hint = (
                " Use complete JSON; for Ctrl+C set interrupt=true with the session_id."
                if invalid_json and tool_name == "write_stdin"
                else ""
            )
            return f"{tool_name}: invalid arguments — " + "; ".join(parts) + hint
        except InvalidManifestPathError as exc:
            rel = exc.context.get("rel", "?")
            return (
                "exec_command: workdir must be a path inside /workspace "
                "(or omitted to use the turn's cwd). "
                f"Got: {rel!r}."
            )
        except Exception as exc:
            if not catch_errors:
                raise
            logger.debug("Tool %s failed; returning error as result", tool_name, exc_info=True)
            return _format_tool_error(exc)

    tool.on_invoke_tool = invoke
    return tool


# apply_patch is the only CustomTool whose SDK JSON schema needs collapsing
# to a single string field. All other CustomTools keep the SDK's schema.
_APPLY_PATCH_INPUT_FIELD = "patch"


def _custom_tool_as_function_tool(tool: CustomTool) -> FunctionTool:
    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            parsed = json.loads(raw_input) if isinstance(raw_input, str) else raw_input
        except json.JSONDecodeError:
            parsed = None
        custom_input = parsed.get(_APPLY_PATCH_INPUT_FIELD) if isinstance(parsed, dict) else None
        if not isinstance(custom_input, str) or not custom_input:
            return f"`{_APPLY_PATCH_INPUT_FIELD}` must be a non-empty string."
        try:
            return await tool.on_invoke_tool(ctx, custom_input)
        except Exception as exc:  # noqa: BLE001 - matches SDK CustomTool error-as-result behavior.
            logger.debug("Tool %s failed; returning error as result", tool.name, exc_info=True)
            return _format_tool_error(exc)

    needs_approval = tool.runtime_needs_approval()
    function_needs_approval: bool | Callable[[Any, dict[str, Any], str], Awaitable[bool]]
    if callable(needs_approval):

        async def approve(ctx: Any, args: dict[str, Any], call_id: str) -> bool:
            raw = args.get(_APPLY_PATCH_INPUT_FIELD, "")
            result = needs_approval(ctx, raw, call_id) if isinstance(raw, str) else False
            if inspect.isawaitable(result):
                result = await result
            return bool(result)

        function_needs_approval = approve
    else:
        function_needs_approval = needs_approval

    return FunctionTool(
        name=tool.name,
        description=(
            f"{tool.description}\n\n"
            f"Pass the complete `{tool.name}` payload in `{_APPLY_PATCH_INPUT_FIELD}`."
        ),
        params_json_schema={
            "type": "object",
            "properties": {
                _APPLY_PATCH_INPUT_FIELD: {
                    "type": "string",
                    "description": (
                        f"Complete `{tool.name}` payload. Follow the tool description exactly."
                    ),
                },
            },
            "required": [_APPLY_PATCH_INPUT_FIELD],
            "additionalProperties": False,
        },
        on_invoke_tool=invoke,
        strict_json_schema=False,
        needs_approval=function_needs_approval,
    )


def _configure_chat_completions_filesystem_tools(toolset: Any) -> None:
    _swap_view_image(toolset)
    for name, tool in vars(toolset).items():
        if isinstance(tool, CustomTool):
            setattr(toolset, name, _custom_tool_as_function_tool(tool))
        elif isinstance(tool, FunctionTool):
            setattr(toolset, name, _wrap_function_tool(tool, catch_errors=True))


def _configure_filesystem_tools(toolset: Any) -> None:
    _swap_view_image(toolset)


def _swap_view_image(toolset: Any) -> None:
    """Replace the SDK's image-returning view_image with the Kael vision sub-agent."""
    existing = getattr(toolset, "view_image", None)
    if existing is None:
        return
    session = getattr(existing, "session", None)
    user = getattr(existing, "user", None)
    needs_approval = getattr(existing, "needs_approval", False)
    if session is None:
        return
    toolset.view_image = _KaelViewImageTool(
        session=session,
        user=user,
        needs_approval=needs_approval,
    )


def _decode_write_stdin_chars(raw_input: str) -> str:
    """Normalize escaped characters and the JSON-safe interrupt shortcut."""
    try:
        parsed = json.loads(raw_input)
    except json.JSONDecodeError:
        return raw_input
    if isinstance(parsed, dict) and parsed.pop("interrupt", False) is True:
        parsed["chars"] = "\x03"
        return json.dumps(parsed)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("chars"), str):
        return raw_input
    chars = parsed["chars"]
    if "\\" not in chars:
        return raw_input
    parsed["chars"] = chars.encode("utf-8").decode("unicode_escape")
    return json.dumps(parsed)


def _wrap_write_stdin(tool: FunctionTool) -> FunctionTool:
    """Stack a char-escape pre-decode on top of the standard wrapper."""
    invoke_tool = tool.on_invoke_tool
    tool.params_json_schema["properties"]["interrupt"] = {
        "type": "boolean",
        "description": "Set true to send Ctrl+C to the running process.",
    }
    tool.description += " To stop a running process, use interrupt=true with its session_id."

    async def invoke(ctx: Any, raw_input: str) -> Any:
        return await invoke_tool(ctx, _decode_write_stdin_chars(raw_input))

    tool.on_invoke_tool = invoke
    return tool


def _configure_shell_tools(toolset: Any, *, chat_completions: bool) -> None:
    for name, tool in vars(toolset).items():
        if not isinstance(tool, FunctionTool):
            continue
        wrapped = _wrap_write_stdin(tool) if tool.name == "write_stdin" else tool
        wrapped = _wrap_function_tool(wrapped, catch_errors=chat_completions)
        setattr(toolset, name, wrapped)


def _make_shell_configurator(*, chat_completions: bool) -> Any:
    def configure(toolset: Any) -> None:
        _configure_shell_tools(toolset, chat_completions=chat_completions)

    return configure


_LIFECYCLE_COMPLETION_KEY: dict[str, str] = {
    "agent_finish": "agent_completed",
    "finish_scan": "scan_completed",
}


def _parse_tool_output(output: Any) -> dict[str, Any] | None:
    """Return the JSON-dict result of a tool call, or None on any mismatch."""
    if not isinstance(output, str):
        return None
    try:
        parsed = json.loads(output)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _lifecycle_tool_completed(tool_name: str, output: Any) -> bool:
    """True if a lifecycle tool (agent_finish, finish_scan) reported success."""
    completion_key = _LIFECYCLE_COMPLETION_KEY.get(tool_name)
    if completion_key is None:
        return False
    parsed = _parse_tool_output(output)
    return bool(parsed and parsed.get("success") and parsed.get(completion_key))


def _wait_tool_parked(output: Any) -> bool:
    """True if ``wait_for_message`` reported a parked state."""
    parsed = _parse_tool_output(output)
    return bool(parsed and parsed.get("success") and parsed.get("wait_outcome") == "waiting")


def _finish_tool_use_behavior(
    ctx: RunContextWrapper[Any],
    tool_results: list[FunctionToolResult],
) -> ToolsToFinalOutputResult:
    """Stop only after a lifecycle tool reports successful completion."""
    interactive = (
        bool(ctx.context.get("interactive", False)) if isinstance(ctx.context, dict) else False
    )
    for tool_result in tool_results:
        if _lifecycle_tool_completed(tool_result.tool.name, tool_result.output):
            return ToolsToFinalOutputResult(
                is_final_output=True,
                final_output=tool_result.output,
            )
        if (
            interactive
            and tool_result.tool.name == "wait_for_message"
            and _wait_tool_parked(tool_result.output)
        ):
            return ToolsToFinalOutputResult(
                is_final_output=True,
                final_output=tool_result.output,
            )
    return ToolsToFinalOutputResult(is_final_output=False, final_output=None)


_BASE_TOOLS: tuple[Tool, ...] = (
    think,
    load_skill,
    create_todo,
    list_todos,
    update_todo,
    mark_todo_done,
    mark_todo_pending,
    delete_todo,
    create_note,
    list_notes,
    get_note,
    update_note,
    add_learning,
    delete_note,
    web_search,
    exploit_search,
    exploit_db_search,
    cve_lookup,
    create_vulnerability_report,
    list_requests,
    view_request,
    repeat_request,
    list_sitemap,
    view_sitemap_entry,
    scope_rules,
    view_agent_graph,
    send_message_to_agent,
    wait_for_message,
    create_agent,
    recall_history,
    stop_agent,
)


# P3 metadata: when_to_use + examples for the high-leverage tools.
# Ponytail: keep this table small. Add rows only when a tool is
# consistently picked wrong by the model — extra rows cost prompt
# tokens for every scan. Shape: (tool, category, when_to_use, examples).
_DEFAULT_TOOL_META: tuple[tuple[Tool, str, str, tuple[str, ...]], ...] = (
    *(
        (t, "meta", "", ())
        for t in (
            think,
            load_skill,
            create_todo,
            list_todos,
            update_todo,
            mark_todo_done,
            mark_todo_pending,
            delete_todo,
            create_note,
            list_notes,
            get_note,
            update_note,
            add_learning,
            delete_note,
        )
    ),
    (
        web_search,
        "web_research",
        "LLM-written how-tos, explanations, and synthesis — not raw artifacts.",
        ("How does CRLF injection bypass WAFs?", "Latest GraphQL authz bugs"),
    ),
    (
        exploit_search,
        "web_research",
        "Find exploit code, github repos, or nuclei templates — not Exploit-DB.",
        ("nuclei template CVE-2024-3094", "github exploit Log4Shell"),
    ),
    (
        exploit_db_search,
        "web_research",
        "Verified PoCs from OffSec's Exploit-DB — returns download_url for raw exploit.",
        ("PoC for CVE-2021-40352", "OpenEMR 7.0.2 exploit-db"),
    ),
    (
        cve_lookup,
        "web_research",
        "First stop for any CVE. CVE-YYYY-NNNN for full record, or filter by product/kev/date.",
        ("Show KEV CVEs for log4j",),
    ),
    (create_vulnerability_report, "reporting", "", ()),
    *(
        (t, "proxy", "", ())
        for t in (
            list_requests,
            view_request,
            repeat_request,
            list_sitemap,
            view_sitemap_entry,
            scope_rules,
        )
    ),
    *(
        (t, "agent_graph", "", ())
        for t in (
            view_agent_graph,
            send_message_to_agent,
            wait_for_message,
            create_agent,
            recall_history,
            stop_agent,
        )
    ),
    (
        _list_tools,
        "meta",
        "Browse the catalog by category when you don't know what tools exist.",
        (),
    ),
    (
        _describe_tool,
        "meta",
        "Read before calling a tool whose argument schema you don't remember.",
        (),
    ),
)

_registered_scan_modes: set[str] = set()


def _register_default_tools() -> None:
    all_modes = frozenset({"deep", "malware_re", "ctf"})
    for tool, category, when_to_use, examples in _DEFAULT_TOOL_META:
        try:
            _registry_mod.REGISTRY.register(
                tool,
                category=category,
                scan_modes=all_modes,
                when_to_use=when_to_use,
                examples=examples,
            )
        except ValueError:
            pass
    try:
        _registry_mod.REGISTRY.register(finish_scan, category="lifecycle", scan_modes=all_modes)
    except ValueError:
        pass
    try:
        _registry_mod.REGISTRY.register(agent_finish, category="lifecycle", scan_modes=all_modes)
    except ValueError:
        pass
    _registered_scan_modes.add("deep")


def _ensure_re_tools_registered() -> None:
    if "malware_re" in _registered_scan_modes:
        return
    from kael.tools.re_tools.c2_beacon_detect import c2_beacon_detect
    from kael.tools.re_tools.extract_strings import extract_strings
    from kael.tools.re_tools.file_triage import file_triage
    from kael.tools.re_tools.generate_research_report import generate_research_report
    from kael.tools.re_tools.import_analyzer import import_analyzer
    from kael.tools.re_tools.memory_snapshot import memory_snapshot
    from kael.tools.re_tools.protocol_dissect import protocol_dissect
    from kael.tools.re_tools.radare2_analyze import radare2_analyze
    from kael.tools.re_tools.resource_analyzer import resource_analyzer
    from kael.tools.re_tools.sandbox_detonate import sandbox_detonate
    from kael.tools.re_tools.string_deobfuscator import string_deobfuscator
    from kael.tools.re_tools.unpack_generic import unpack_generic
    from kael.tools.re_tools.yara_scan import yara_scan

    for tool in (
        file_triage,
        extract_strings,
        yara_scan,
        radare2_analyze,
        sandbox_detonate,
        memory_snapshot,
        c2_beacon_detect,
        protocol_dissect,
        unpack_generic,
        generate_research_report,
        import_analyzer,
        resource_analyzer,
        string_deobfuscator,
    ):
        try:
            _registry_mod.REGISTRY.register(
                tool, category="re", scan_modes=frozenset({"malware_re"})
            )
        except ValueError:
            pass
    _registered_scan_modes.add("malware_re")


def _ensure_ctf_tools_registered() -> None:
    if "ctf" in _registered_scan_modes:
        return
    from kael.tools.ctf_tools import ALL_CTF_TOOLS

    for tool in ALL_CTF_TOOLS:
        try:
            _registry_mod.REGISTRY.register(tool, category="ctf", scan_modes=frozenset({"ctf"}))
        except ValueError:
            pass
    _registered_scan_modes.add("ctf")


def get_base_tools(scan_mode: str = "deep") -> tuple[Tool, ...]:
    """Get base tools for a given scan mode.

    Args:
        scan_mode: The scan mode (quick, standard, deep, malware_re)

    Returns:
        Tuple of tools available for this scan mode
    """
    if scan_mode == "malware_re":
        _ensure_re_tools_registered()
        return tuple(_registry_mod.REGISTRY.filter(scan_mode="malware_re"))

    if scan_mode == "ctf":
        _ensure_ctf_tools_registered()
        return tuple(_registry_mod.REGISTRY.filter(scan_mode="ctf"))

    return _BASE_TOOLS


def build_kael_agent(
    *,
    name: str = "kael",
    skills: list[str] | None = None,
    is_root: bool,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    interactive: bool = False,
    chat_completions_tools: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
    prompt_only: bool = False,
) -> SandboxAgent[Any]:
    """Build a SandboxAgent for either root or child use.

    Args:
        chat_completions_tools: Wrap SDK custom tools as function tools
            when the selected backend cannot accept Responses custom tools.
        prompt_only: Render the prompt-only system prompt that drops the
            security scope / authorized-targets guard rails. Used when the
            user runs ``kael prompt "..."`` with no specific target.
    """
    instructions = render_system_prompt(
        skills=skills,
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        is_root=is_root,
        interactive=interactive,
        system_prompt_context=system_prompt_context,
        prompt_only=prompt_only,
    )

    base_tools = get_base_tools(scan_mode=scan_mode)
    if is_root:
        tools: list[Tool] = [*base_tools, finish_scan]
    else:
        tools = [*base_tools, agent_finish]

    logger.info(
        "Built %s agent '%s' (skills=%d, tools=%d, scan_mode=%s, whitebox=%s)",
        "root" if is_root else "child",
        name,
        len(skills or []),
        len(tools),
        scan_mode,
        is_whitebox,
    )

    return SandboxAgent(
        name=name,
        instructions=instructions,
        tools=tools,
        tool_use_behavior=_finish_tool_use_behavior,
        model=None,
        capabilities=[
            Filesystem(
                configure_tools=(
                    _configure_chat_completions_filesystem_tools
                    if chat_completions_tools
                    else _configure_filesystem_tools
                ),
            ),
            Shell(
                configure_tools=_make_shell_configurator(
                    chat_completions=chat_completions_tools,
                ),
            ),
        ],
    )


def make_child_factory(
    *,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    interactive: bool = False,
    chat_completions_tools: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
    prompt_only: bool = False,
) -> Any:
    """Return the runner-owned builder used by ``spawn_child_agent``.

    Run-level arguments (``scan_mode``, ``is_whitebox``, etc.) are
    captured in a closure so each child inherits scan-level configuration
    without the graph tool knowing about runner internals.
    """

    def _factory(*, name: str, skills: list[str]) -> SandboxAgent[Any]:
        return build_kael_agent(
            name=name,
            skills=skills,
            is_root=False,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=system_prompt_context,
            prompt_only=prompt_only,
        )

    return _factory


_register_default_tools()
