"""Execution loop for addressable SDK-backed Kael agents."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

import httpx
from agents import RunConfig, Runner
from agents.exceptions import AgentsException, MaxTurnsExceeded, ModelBehaviorError, UserError
from agents.sandbox.errors import ExecTransportError
from docker import errors as docker_errors  # type: ignore[import-untyped, unused-ignore]
from openai import APIConnectionError, APIError, APITimeoutError

from kael.agents.factory import RepeatedInvalidToolArguments
from kael.core.goals import GoalBudgetExhausted
from kael.core.inputs import child_initial_input
from kael.core.sessions import open_agent_session, strip_all_images_from_session


if TYPE_CHECKING:
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.lifecycle import RunHooks
    from agents.memory import Session, SQLiteSession
    from agents.result import RunResultBase

    from kael.core.agents import AgentCoordinator, Status


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]

_INPUT_REJECTION_CODES = frozenset({400, 404, 422})

_TRANSIENT_NETWORK_EXCEPTIONS: tuple[type[BaseException], ...] = (
    httpx.RemoteProtocolError,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.WriteError,
    httpx.PoolTimeout,
    httpx.TimeoutException,
    APIConnectionError,
    APITimeoutError,
)
_NETWORK_RETRY_LIMIT = 3
_NETWORK_RETRY_INITIAL_DELAY = 2.0
_NETWORK_RETRY_MAX_DELAY = 30.0

# Cap non-interactive recovery attempts independently of ``max_turns``.
# A misbehaving agent that emits plain text instead of a lifecycle tool
# is unlikely to self-correct after the first few nudges; burning
# ``max_turns`` cycles on the same recovery loop is wasted budget.
_INVALID_FINAL_OUTPUT_LIMIT = 5

# Cap on the number of times we can self-correct a hallucinated
# ``agent_browser_*`` function call before giving up. The agent-browser
# is a shell CLI (see ``kael/skills/tooling/agent_browser.md``), not a
# function tool — the model sometimes misreads the skill as a tool with
# sub-methods and calls ``agent_browser_close`` etc. We detect that
# specific failure mode, inject a corrective message, and let the model
# try again. The cap prevents infinite loops if the model keeps making
# the same mistake.
_MODEL_BEHAVIOR_RETRY_LIMIT = 1

_MISSING_TOOL_RE = re.compile(r"^Tool\s+(?P<name>\S+)\s+not found in agent\s+\S+", re.IGNORECASE)


def _as_goal_policy_stop(exc: BaseException) -> GoalBudgetExhausted | None:
    """Find a goal policy-stop anywhere in the exception chain.

    The SDK may wrap a hook exception, so check ``__cause__`` /
    ``__context__`` as well as the exception itself.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, GoalBudgetExhausted):
            return current
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return None


def _is_cli_tool_hallucination(exc: BaseException) -> str | None:
    """Return the hallucinated tool name if ``exc`` is a CLI-mistaken tool call.

    Specifically matches the case where the model treats
    ``agent_browser_<subcommand>`` as a function tool. The agent-browser
    is a shell CLI; there is no such function tool.
    """
    if not isinstance(exc, ModelBehaviorError):
        return None
    match = _MISSING_TOOL_RE.match(getattr(exc, "message", "") or "")
    if not match:
        return None
    name = match.group("name").lower()
    if not name.startswith("agent_browser_") and name != "agent_browser":
        return None
    return match.group("name")


async def _append_cli_tool_correction(
    *,
    session: Session | None,
    tool_name: str,
    attempt: int,
    limit: int,
) -> list[dict[str, str]]:
    """Append a corrective user message telling the model to use ``exec_command``.

    Mirrors :func:`_append_noninteractive_tool_required_message` — when
    a session exists, we mutate the session and return ``[]`` so the
    runner re-enters with no fresh input (the session drives the next
    turn). Without a session, we synthesize a one-shot user message.
    """
    subcommand = (
        tool_name[len("agent_browser_") :] if tool_name.startswith("agent_browser_") else ""
    )
    hint = (
        f'`exec_command("agent-browser {subcommand}")`'
        if subcommand
        else '`exec_command("agent-browser ...")`'
    )
    message = (
        f"Your previous turn called `{tool_name}` as a function tool, which does not "
        f"exist. The `agent-browser` program is a SHELL CLI inside the sandbox, not a "
        f"function tool. There is no `agent_browser_*` function tool registered on any "
        f"agent. To run an agent-browser subcommand, call the `exec_command` tool with "
        f"the shell command, e.g. {hint}. See the `tooling/agent_browser` skill for the "
        f"full command reference. This is recovery attempt {attempt}/{limit}."
    )
    item = {"role": "user", "content": message}
    if session is None:
        return [item]
    await session.add_items([cast("TResponseInputItem", item)])
    return []


async def run_agent_loop(
    *,
    agent: Any,
    initial_input: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    coordinator: AgentCoordinator,
    agent_id: str,
    interactive: bool,
    session: Session | None = None,
    start_parked: bool = False,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> RunResultBase | None:
    await coordinator.attach_runtime(
        agent_id,
        session=session,
        interrupt_on_message=interactive,
    )
    result: RunResultBase | None = None

    if not (start_parked and interactive):
        if interactive:
            result = await _run_cycle(
                agent,
                coordinator,
                agent_id,
                input_data=initial_input,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
            )
        else:
            result = await _run_noninteractive_until_lifecycle(
                agent,
                coordinator,
                agent_id,
                initial_input=initial_input,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                event_sink=event_sink,
                hooks=hooks,
            )

    if not interactive:
        return result

    while True:
        try:
            await coordinator.wait_for_message(agent_id)
        except asyncio.CancelledError:
            return result

        await coordinator.consume_pending(agent_id)
        result = await _run_cycle(
            agent,
            coordinator,
            agent_id,
            input_data=[],
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            session=session,
            interactive=interactive,
            event_sink=event_sink,
            hooks=hooks,
        )


async def spawn_child_agent(
    *,
    coordinator: AgentCoordinator,
    factory: Any,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    parent_ctx: dict[str, Any],
    name: str,
    task: str,
    skills: list[str],
    parent_history: list[Any],
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    parent_id = parent_ctx.get("agent_id")
    if not isinstance(parent_id, str):
        raise TypeError("Parent agent_id missing from context")

    child_id = uuid.uuid4().hex[:8]
    child_agent = factory(name=name, skills=skills)
    await coordinator.register(
        child_id,
        name,
        parent_id,
        task=task,
        skills=skills,
    )

    await _start_child_runner(
        parent_ctx=parent_ctx,
        coordinator=coordinator,
        agents_db_path=agents_db_path,
        sessions_to_close=sessions_to_close,
        run_config=run_config,
        max_turns=max_turns,
        interactive=interactive,
        child_agent=child_agent,
        child_id=child_id,
        name=name,
        parent_id=parent_id,
        task=task,
        initial_input=child_initial_input(
            name=name,
            child_id=child_id,
            parent_id=parent_id,
            task=task,
            parent_history=parent_history,
        ),
        event_sink=event_sink,
        hooks=hooks,
    )

    return {
        "success": True,
        "agent_id": child_id,
        "name": name,
        "parent_id": parent_id,
        "message": f"Spawned '{name}' ({child_id}) running in parallel.",
    }


async def respawn_subagents(
    *,
    coordinator: AgentCoordinator,
    factory: Any,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    parent_ctx: dict[str, Any],
    root_id: str,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> None:
    async with coordinator.lock():
        agents_snapshot = [
            (aid, status, dict(coordinator.metadata.get(aid, {})))
            for aid, status in coordinator.statuses.items()
        ]
        candidates: list[tuple[str, str, str | None, dict[str, Any]]] = []
        for aid, status, md in agents_snapshot:
            if not interactive and status not in {"running", "waiting"}:
                continue
            if coordinator.parent_of.get(aid) is None or aid == root_id:
                continue
            md["_restored_status"] = status
            candidates.append(
                (
                    aid,
                    coordinator.names.get(aid, aid),
                    coordinator.parent_of.get(aid),
                    md,
                )
            )

    for child_id, name, parent_id, md in candidates:
        try:
            restored_status = str(md.get("_restored_status") or "running")
            start_parked = interactive and restored_status != "running"

            if start_parked:
                logger.warning(
                    "respawn %s (%s): starting parked from status=%s",
                    child_id,
                    name,
                    restored_status,
                )

            child_skills = list(md.get("skills") or [])
            child_agent = factory(name=name, skills=child_skills)
            await _start_child_runner(
                parent_ctx=parent_ctx,
                coordinator=coordinator,
                agents_db_path=agents_db_path,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                child_agent=child_agent,
                child_id=child_id,
                name=name,
                parent_id=parent_id,
                task=str(md.get("task", "")),
                initial_input=[],
                start_parked=start_parked,
                event_sink=event_sink,
                hooks=hooks,
            )
            logger.info(
                "respawned %s (%s) parent=%s task_len=%d",
                child_id,
                name,
                parent_id or "-",
                len(md.get("task", "")),
            )
        except Exception:
            logger.exception("respawn %s failed; marking crashed", child_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(child_id, "crashed")


async def _run_noninteractive_until_lifecycle(
    agent: Any,
    coordinator: AgentCoordinator,
    agent_id: str,
    *,
    initial_input: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    session: Session | None,
    event_sink: StreamEventSink | None,
    hooks: RunHooks[dict[str, Any]] | None,
) -> RunResultBase | None:
    """Non-chat mode keeps running until finish_scan / agent_finish settles status."""
    result: RunResultBase | None = None
    input_data: Any = initial_input
    invalid_final_outputs = 0
    # ``max_turns`` bounds the LLM call budget for one cycle; the recovery
    # loop is a separate (cheap) bound. Cap it at a small constant so a
    # stuck agent can't burn the whole ``max_turns`` budget on retries.
    invalid_final_output_limit = min(_INVALID_FINAL_OUTPUT_LIMIT, max(1, max_turns))

    while True:
        result = await _run_cycle(
            agent,
            coordinator,
            agent_id,
            input_data=input_data,
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            session=session,
            interactive=False,
            event_sink=event_sink,
            hooks=hooks,
        )

        status = await _agent_status(coordinator, agent_id)
        if status != "running":
            return result

        invalid_final_outputs += 1
        logger.warning(
            "agent %s produced non-lifecycle final output in non-interactive mode; "
            "forcing tool continuation (%d/%d): %s",
            agent_id,
            invalid_final_outputs,
            invalid_final_output_limit,
            _final_output_preview(result),
        )

        if invalid_final_outputs >= invalid_final_output_limit:
            await coordinator.set_status(agent_id, "crashed")
            await _notify_parent_on_crash(coordinator, agent_id, "crashed")
            raise MaxTurnsExceeded(
                "Agent exhausted non-interactive recovery attempts without calling "
                "finish_scan or agent_finish."
            )

        input_data = await _append_noninteractive_tool_required_message(
            session=session,
            context=context,
            attempt=invalid_final_outputs,
            limit=invalid_final_output_limit,
        )


async def _run_cycle(  # noqa: PLR0912, PLR0915
    agent: Any,
    coordinator: AgentCoordinator,
    agent_id: str,
    *,
    input_data: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    session: Session | None,
    interactive: bool,
    event_sink: StreamEventSink | None,
    hooks: RunHooks[dict[str, Any]] | None,
) -> RunResultBase | None:
    image_strips = 0
    network_retries = 0
    model_behavior_retries = 0
    while True:
        try:
            await coordinator.mark_running(agent_id)
            stream = Runner.run_streamed(
                agent,
                input=input_data,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                hooks=hooks,
            )
            await coordinator.attach_stream(agent_id, stream)
            try:
                try:
                    async for event in stream.stream_events():
                        if event_sink is not None:
                            try:
                                event_sink(agent_id, event)
                            except Exception:
                                logger.exception("stream event sink failed for %s", agent_id)
                    if stream.run_loop_exception is not None:
                        raise stream.run_loop_exception
                except RuntimeError as stream_exc:
                    if "after shutdown" not in str(stream_exc):
                        raise
                    logger.warning(
                        "Ignoring LiteLLM end-of-stream shutdown race for %s",
                        agent_id,
                    )
                except (ExecTransportError, docker_errors.NotFound):
                    if not coordinator.is_shutting_down:
                        raise
                    logger.warning(
                        "Ignoring sandbox container error during teardown for %s",
                        agent_id,
                        exc_info=True,
                    )
            finally:
                await coordinator.detach_stream(agent_id, stream)
        except Exception as exc:
            policy_stop = _as_goal_policy_stop(exc)
            if policy_stop is not None:
                # A host budget gate tripped. This is an expected terminal
                # outcome, not an error: park the agent cleanly with a
                # partial result and never retry it (plan §96).
                logger.info(
                    "agent %s stopped by goal policy (%s); parking as stopped",
                    agent_id,
                    policy_stop.reason,
                )
                await coordinator.mark_goal_stop("incomplete", policy_stop.reason)
                await coordinator.set_status(agent_id, "stopped")
                return None
            if network_retries < _NETWORK_RETRY_LIMIT and isinstance(
                exc, _TRANSIENT_NETWORK_EXCEPTIONS
            ):
                network_retries += 1
                delay = min(
                    _NETWORK_RETRY_INITIAL_DELAY * (2 ** (network_retries - 1)),
                    _NETWORK_RETRY_MAX_DELAY,
                )
                logger.warning(
                    "Transient LLM transport error for %s (%s: %s); "
                    "backing off %.1fs and replaying the turn (%d/%d)",
                    agent_id,
                    type(exc).__name__,
                    exc,
                    delay,
                    network_retries,
                    _NETWORK_RETRY_LIMIT,
                )
                await asyncio.sleep(delay)
                input_data = []
                continue
            hallucinated_tool = _is_cli_tool_hallucination(exc)
            if (
                isinstance(exc, RepeatedInvalidToolArguments)
                and model_behavior_retries < _MODEL_BEHAVIOR_RETRY_LIMIT
            ):
                model_behavior_retries += 1
                message = (
                    f"Your calls to {exc.tool_name} contained incomplete JSON. "
                    "Use the actual function tool with one complete JSON object; do not "
                    "write <tool_call> markup in message text. For Ctrl+C, call "
                    'write_stdin with {"session_id":123,"interrupt":true}, '
                    "replacing 123 with the running session ID. Use recall_history "
                    "if you need an earlier result, then continue the task."
                )
                item = {"role": "user", "content": message}
                if session is not None:
                    await session.add_items([cast("TResponseInputItem", item)])
                    input_data = []
                else:
                    input_data = [item]
                logger.warning(
                    "Correcting repeated malformed %s calls for %s", exc.tool_name, agent_id
                )
                continue
            if (
                hallucinated_tool is not None
                and model_behavior_retries < _MODEL_BEHAVIOR_RETRY_LIMIT
            ):
                model_behavior_retries += 1
                logger.warning(
                    "Model tried to call `%s` as a function tool for %s; "
                    "injecting CLI-vs-tool correction and retrying (%d/%d)",
                    hallucinated_tool,
                    agent_id,
                    model_behavior_retries,
                    _MODEL_BEHAVIOR_RETRY_LIMIT,
                )
                input_data = await _append_cli_tool_correction(
                    session=session,
                    tool_name=hallucinated_tool,
                    attempt=model_behavior_retries,
                    limit=_MODEL_BEHAVIOR_RETRY_LIMIT,
                )
                continue
            if (
                image_strips < 3
                and session is not None
                and getattr(exc, "status_code", None) in _INPUT_REJECTION_CODES
            ):
                try:
                    stripped = await strip_all_images_from_session(session)
                except Exception:
                    logger.exception("image-strip recovery failed for %s", agent_id)
                    stripped = False
                if stripped:
                    image_strips += 1
                    logger.info(
                        "Stripped images from %s session after rejection; retrying (%d)",
                        agent_id,
                        image_strips,
                    )
                    input_data = []
                    continue
            if not interactive:
                raise
            if isinstance(exc, MaxTurnsExceeded):
                status: Status = "stopped"
            elif isinstance(exc, UserError | AgentsException | APIError):
                status = "failed"
            else:
                status = "crashed"
            logger.exception("agent run failed for %s; parking as %s", agent_id, status)
            await coordinator.set_status(agent_id, status)
            await _notify_parent_on_crash(coordinator, agent_id, status)
            if context.get("parent_id") is None and status in {"failed", "crashed"}:
                raise
            return None
        else:
            await _settle_run_result(coordinator, agent_id, interactive)
            return stream


async def _settle_run_result(
    coordinator: AgentCoordinator,
    agent_id: str,
    interactive: bool,
) -> None:
    async with coordinator.lock():
        current_status = coordinator.statuses.get(agent_id)

    if current_status != "running":
        return

    if not interactive:
        return

    await coordinator.set_status(agent_id, "waiting")


async def _agent_status(coordinator: AgentCoordinator, agent_id: str) -> Status | None:
    async with coordinator.lock():
        return coordinator.statuses.get(agent_id)


def _final_output_preview(result: RunResultBase | None) -> str:
    final_output = getattr(result, "final_output", None)
    if final_output is None:
        return "<none>"
    text = str(final_output).replace("\n", " ").strip()
    if not text:
        return "<empty>"
    return text[:300]


async def _append_noninteractive_tool_required_message(
    *,
    session: Session | None,
    context: dict[str, Any],
    attempt: int,
    limit: int,
) -> list[dict[str, str]]:
    finish_tool = "finish_scan" if context.get("parent_id") is None else "agent_finish"
    message = (
        "Your previous response ended the autonomous Kael run without a lifecycle tool call. "
        "That is invalid in non-interactive mode; plain text final answers are ignored. "
        "Continue immediately and call exactly one tool. "
        f"If your work is complete, call {finish_tool}. "
        "If you are blocked waiting for another agent, call wait_for_message. "
        "Otherwise use the appropriate execution or planning tool. "
        f"This is recovery attempt {attempt}/{limit}."
    )
    item = {"role": "user", "content": message}
    if session is None:
        return [item]

    await session.add_items([cast("TResponseInputItem", item)])
    return []


async def _notify_parent_on_crash(
    coordinator: AgentCoordinator,
    agent_id: str,
    status: str,
) -> None:
    if status != "crashed":
        return
    async with coordinator.lock():
        parent = coordinator.parent_of.get(agent_id)
        name = coordinator.names.get(agent_id, agent_id)
    if parent is None:
        return
    await coordinator.send(
        parent,
        {
            "from": agent_id,
            "type": "crash",
            "priority": "high",
            "content": (
                f"[Agent crash] {name} ({agent_id}) terminated unexpectedly. "
                "Stop waiting on this child unless you want to message it again."
            ),
        },
    )


async def _start_child_runner(
    *,
    parent_ctx: dict[str, Any],
    coordinator: AgentCoordinator,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    child_agent: Any,
    child_id: str,
    name: str,
    parent_id: str | None,
    task: str,
    initial_input: Any,
    start_parked: bool = False,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> None:
    session = open_agent_session(child_id, agents_db_path)
    sessions_to_close.append(session)
    await coordinator.attach_runtime(child_id, session=session)

    child_ctx: dict[str, Any] = dict(parent_ctx)
    child_ctx["agent_id"] = child_id
    child_ctx["parent_id"] = parent_id
    child_ctx["task"] = task

    task_handle = asyncio.create_task(
        run_agent_loop(
            agent=child_agent,
            initial_input=initial_input,
            run_config=run_config,
            context=child_ctx,
            max_turns=max_turns,
            coordinator=coordinator,
            agent_id=child_id,
            interactive=interactive,
            session=session,
            start_parked=start_parked,
            event_sink=event_sink,
            hooks=hooks,
        ),
        name=f"agent-{name}-{child_id}",
    )
    await coordinator.attach_runtime(child_id, task=task_handle)
