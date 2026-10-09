"""Top-level Kael scan runner."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from agents import RunConfig
from agents.sandbox import SandboxRunConfig

from kael.agents.factory import build_kael_agent, make_child_factory
from kael.config import load_settings
from kael.config.models import (
    KaelProvider,
    configure_sdk_model_defaults,
    uses_chat_completions_tool_schema,
)
from kael.core.agents import AgentCoordinator
from kael.core.execution import (
    respawn_subagents,
    run_agent_loop,
)
from kael.core.execution import (
    spawn_child_agent as start_child_agent,
)
from kael.core.goals import goal_from_scan_config
from kael.core.hooks import KaelRunHooks
from kael.core.inputs import (
    DEFAULT_MAX_TURNS,
    build_root_task,
    build_scope_context,
    limit_model_input,
    make_model_settings,
)
from kael.core.paths import run_dir_for, runtime_state_dir
from kael.core.sessions import open_agent_session
from kael.log_utils import set_scan_id, setup_scan_logging
from kael.runtime import session_manager


if TYPE_CHECKING:
    from agents.memory import SQLiteSession
    from agents.result import RunResultBase


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]


async def _budget_watchdog(
    coordinator: AgentCoordinator,
    root_id: str,
    poll_seconds: float,
) -> None:
    """Host watchdog for the goal budget.

    A hook gate only fires between calls, so a single stalled model/tool
    call or a stuck dependency can't evade it — this polls the wall clock
    and call counts and gracefully stops the whole subtree when any hard
    limit is reached (plan §84).
    """
    try:
        while True:
            await asyncio.sleep(poll_seconds)
            if await coordinator.goal_budget_exhausted():
                logger.warning("goal budget watchdog: hard limit reached; stopping scan subtree")
                await coordinator.mark_goal_stop("incomplete", "budget_exhausted")
                await coordinator.cancel_descendants_graceful(root_id)
                return
    except asyncio.CancelledError:
        return


def _finalize_partial_report(goal: Any) -> None:
    """Persist an honest partial report when the host stops a run.

    The host writes this itself so a budget-exhausted actor isn't asked to
    make another finish call after its budget expired (plan §78).
    """
    from kael.report.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        logger.warning("goal stop (%s): no report state to persist a partial result", goal.stop_reason)
        return
    if report_state.scan_results and report_state.scan_results.get("scan_completed"):
        return  # a verified-complete report already exists; don't overwrite it
    unmet = goal.unmet_ids()
    summary = (
        f"Scan stopped before completion (outcome={goal.outcome}, reason={goal.stop_reason}). "
        f"Model calls used: {goal.budget.consumed_model_calls}; "
        f"tool calls used: {goal.budget.consumed_tool_calls}. "
        + (
            f"Unmet acceptance criteria: {', '.join(unmet)}."
            if unmet
            else "No required acceptance criteria were configured."
        )
    )
    report_state.finalize_partial_report(
        goal_outcome=goal.outcome,
        stop_reason=goal.stop_reason,
        summary=summary,
    )
    logger.info("Persisted partial report (outcome=%s, reason=%s)", goal.outcome, goal.stop_reason)


async def run_kael_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, str]] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
) -> RunResultBase | None:
    """Run or resume one Kael scan against a sandbox."""
    if scan_id is None:
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"

    run_dir = run_dir_for(scan_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    teardown_logging = setup_scan_logging(run_dir)
    set_scan_id(scan_id)

    agents_path = state_dir / "agents.json"
    agents_db = state_dir / "agents.db"
    is_resume = agents_path.exists()

    logger.info(
        "%s Kael scan %s (image=%s, max_turns=%d, interactive=%s, run_dir=%s)",
        "Resuming" if is_resume else "Starting",
        scan_id,
        image,
        max_turns,
        interactive,
        run_dir,
    )

    settings = load_settings()
    resolved_model = (model or settings.llm.model or "").strip()
    if not resolved_model:
        raise RuntimeError(
            "No LLM model configured. Set KAEL_LLM env or pass model= to run_kael_scan().",
        )

    if coordinator is None:
        coordinator = AgentCoordinator()
    coordinator.set_snapshot_path(agents_path)

    from kael.tools.notes.tools import hydrate_notes_from_disk
    from kael.tools.todo.tools import hydrate_todos_from_disk

    hydrate_todos_from_disk(state_dir)
    notes_store = hydrate_notes_from_disk(
        state_dir,
        targets=scan_config.get("targets") or [],
        scope=settings.memory.scope,
    )

    root_id: str | None = None
    if is_resume:
        try:
            snap = json.loads(agents_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json is unreadable: {exc}",
            ) from exc
        if not agents_db.exists():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: missing SDK session database at {agents_db}",
            )
        await coordinator.restore(snap)
        for aid, parent in coordinator.parent_of.items():
            if parent is None:
                root_id = aid
                break
        if root_id is None:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json has no root agent (parent=None)",
            )
        logger.info(
            "Resume: restored coordinator with %d agent(s); root=%s",
            len(coordinator.statuses),
            root_id,
        )
    else:
        root_id = uuid.uuid4().hex[:8]

    logger.info("Bringing up sandbox session for scan %s", scan_id)
    bundle = await session_manager.create_or_reuse(
        scan_id,
        image=image,
        local_sources=local_sources or [],
    )
    logger.info("Sandbox ready for scan %s", scan_id)

    sessions_to_close: list[SQLiteSession] = []

    try:
        settings = load_settings()
        resolved_model = (model or settings.llm.model or "").strip()
        if not resolved_model:
            raise RuntimeError("No LLM model configured. Choose a model before starting the scan.")
        configure_sdk_model_defaults(settings)
        logger.info("LLM model resolved: %s", resolved_model)
        chat_completions_tools = uses_chat_completions_tool_schema(resolved_model, settings)
        targets = scan_config.get("targets") or []
        scan_mode = str(scan_config.get("scan_mode") or "deep")
        is_whitebox = any(t.get("type") == "local_code" for t in targets)
        prompt_only = bool(scan_config.get("prompt_only"))
        skills = list(scan_config.get("skills") or [])
        root_task = build_root_task(scan_config)
        model_settings = make_model_settings(
            settings.llm.reasoning_effort,
            model_name=resolved_model,
            parallel_tool_calls_mode=settings.tool_harness.parallel_tool_calls_mode,
            openrouter_provider=settings.llm.openrouter_provider,
            api_base=settings.llm.api_base,
        )
        model_settings.extra_args = {"timeout": settings.llm.timeout}
        run_config = RunConfig(
            model=resolved_model,
            model_provider=KaelProvider(),
            model_settings=model_settings,
            call_model_input_filter=limit_model_input,
            sandbox=SandboxRunConfig(client=bundle["client"], session=bundle["session"]),
            trace_include_sensitive_data=False,
        )
        coordinator.run_config = run_config
        coordinator.model_uses_chat_completions = chat_completions_tools
        coordinator.model_api_base = settings.llm.api_base
        hooks = KaelRunHooks(
            model=resolved_model,
            dedup_window_turns=settings.tool_harness.dedup_window_turns,
        )

        # Attach the host-owned goal. On resume it is restored from the
        # snapshot (preserving consumed budget + verdicts); otherwise build
        # a fresh one from host-controlled config. Inert unless configured.
        if coordinator.goal is None:
            coordinator.goal = goal_from_scan_config(scan_config, settings)
        coordinator.goal.budget.start_segment()

        scope_context = build_scope_context(scan_config)
        scope_context["notes_scope"] = notes_store.scope

        root_agent = build_kael_agent(
            name="kael",
            skills=skills,
            is_root=True,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=scope_context,
            prompt_only=prompt_only,
        )

        if not is_resume:
            await coordinator.register(
                root_id,
                "kael",
                parent_id=None,
                task=root_task,
                skills=skills,
            )

        child_agent_builder = make_child_factory(
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=scope_context,
            prompt_only=prompt_only,
        )

        async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
            return await start_child_agent(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
                **kwargs,
            )

        context: dict[str, Any] = {
            "coordinator": coordinator,
            "sandbox_session": bundle["session"],
            "mitm_client": bundle["mitm_client"],
            "agent_id": root_id,
            "parent_id": None,
            "interactive": interactive,
            "spawn_child_agent": spawn_child_agent,
            "notes_store": notes_store,
        }

        root_session = open_agent_session(root_id, agents_db)
        sessions_to_close.append(root_session)
        await coordinator.attach_runtime(root_id, session=root_session)

        if is_resume:
            await respawn_subagents(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                parent_ctx=context,
                root_id=root_id,
                event_sink=event_sink,
                hooks=hooks,
            )

        initial_input: Any = [] if is_resume else root_task

        # Resume + new ``--instruction``: SDK replay drives root from
        # agents.db with ``initial_input=[]``, so a brand-new instruction
        # passed on the resume CLI would otherwise be silently ignored.
        # Inject it as a fresh user message in root's SDK session; the
        # next run cycle will replay it with the rest of the session.
        resume_instruction = str(scan_config.get("resume_instruction") or "").strip()
        if is_resume and resume_instruction:
            await coordinator.send(
                root_id,
                {
                    "from": "user",
                    "type": "instruction",
                    "priority": "high",
                    "content": resume_instruction,
                },
            )
            logger.info(
                "Resume: injected new instruction into root SDK session (len=%d)",
                len(resume_instruction),
            )

        async with coordinator.lock():
            root_status = coordinator.statuses.get(root_id)

        watchdog_task: asyncio.Task[None] | None = None
        if coordinator.goal.budget.configured():
            watchdog_task = asyncio.create_task(
                _budget_watchdog(coordinator, root_id, settings.goal.watchdog_poll_seconds),
                name="goal-watchdog",
            )

        try:
            result = await run_agent_loop(
                agent=root_agent,
                initial_input=initial_input,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                coordinator=coordinator,
                agent_id=root_id,
                interactive=interactive,
                session=root_session,
                start_parked=bool(interactive and is_resume and root_status != "running"),
                event_sink=event_sink,
                hooks=hooks,
            )
        finally:
            if watchdog_task is not None:
                watchdog_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await watchdog_task

        goal = coordinator.goal
        if not interactive and goal is not None and goal.outcome in {
            "incomplete",
            "needs_input",
            "cancelled",
        }:
            logger.info("Scan %s ended with goal outcome=%s", scan_id, goal.outcome)
            _finalize_partial_report(goal)
        if not interactive and result is not None:
            final = getattr(result, "final_output", None)
            scan_completed = False
            if isinstance(final, str):
                try:
                    parsed = json.loads(final)
                    scan_completed = bool(isinstance(parsed, dict) and parsed.get("scan_completed"))
                except (ValueError, TypeError):
                    scan_completed = False
            elif isinstance(final, dict):
                scan_completed = bool(final.get("scan_completed"))
            if not scan_completed:
                logger.error(
                    "Scan %s ended without calling finish_scan. The agent "
                    "emitted a text-only turn instead of a lifecycle tool call, "
                    "so no executive report was written. Final output (first "
                    "300 chars): %r",
                    scan_id,
                    str(final)[:300],
                )
        return result  # noqa: TRY300
    except BaseException:
        logger.exception("Kael scan %s failed", scan_id)
        if root_id is not None:
            await coordinator.cancel_descendants(root_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "failed")
        raise
    finally:
        coordinator.run_config = None
        coordinator.model_uses_chat_completions = None
        coordinator.model_api_base = None
        for s in sessions_to_close:
            with contextlib.suppress(Exception):
                s.close()
        with contextlib.suppress(Exception):
            # Persist this segment's active wall-time before snapshotting so
            # resume preserves consumed budget (plan §56).
            if coordinator.goal is not None:
                coordinator.goal.budget.fold_segment()
        with contextlib.suppress(Exception):
            # Coordinator snapshot writes are debounced; on teardown
            # we want a guaranteed fresh copy of the final state.
            await coordinator.flush_snapshot()
        if cleanup_on_exit:
            logger.info("Tearing down sandbox session for scan %s", scan_id)
            await session_manager.cleanup(scan_id)
        logger.info("Kael scan %s done", scan_id)
        teardown_logging()
