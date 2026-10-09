#!/usr/bin/env python3
"""
Kael Agent Interface
"""

import argparse
import asyncio
import shutil
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from kael.config import (
    apply_config_override,
    load_settings,
    persist_current,
)
from kael.core.paths import run_dir_for
from kael.interface.utils import (
    assign_workspace_subdirs,
    build_final_stats_text,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    generate_run_name,
    image_exists,
    infer_target_type,
    process_pull_line,
    resolve_diff_scope_context,
    rewrite_localhost_targets,
    validate_config_file,
)
from kael.log_utils import configure_dependency_logging
from kael.report.writer import read_run_record, write_run_record
from kael.version import default_sandbox_image, get_version


HOST_GATEWAY_HOSTNAME = "host.docker.internal"


import logging  # noqa: E402


logger = logging.getLogger(__name__)


def validate_environment() -> None:
    logger.info("Validating environment")
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    settings = load_settings()

    if not settings.llm.model:
        missing_required_vars.append("KAEL_LLM")

    if not settings.llm.api_key:
        missing_optional_vars.append("LLM_API_KEY")

    if not settings.llm.api_base:
        missing_optional_vars.append("LLM_API_BASE")

    if not settings.integrations.perplexity_api_key:
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if missing_required_vars:
        error_text = Text()
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        for var in missing_required_vars:
            if var == "KAEL_LLM":
                error_text.append("• ", style="white")
                error_text.append("KAEL_LLM", style="bold cyan")
                error_text.append(
                    " - Model name to use (e.g., 'openai/gpt-5.4' or "
                    "'anthropic/claude-opus-4-7')\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for the LLM provider "
                        "(not needed for local models, Vertex AI, AWS, etc.)\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Custom API base URL if using local models (e.g., Ollama, LMStudio)\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for Perplexity AI web search (enables real-time research)\n",
                        style="white",
                    )
                elif var == "KAEL_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("KAEL_REASONING_EFFORT", style="bold cyan")
                    error_text.append(
                        " - Reasoning effort level: none, minimal, low, medium, high, xhigh "
                        "(default: high)\n",
                        style="white",
                    )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append("export KAEL_LLM='openai/gpt-5.4'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  "
                        "# not needed for local models, Vertex AI, AWS, etc.\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# needed for local models only\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "export PERPLEXITY_API_KEY='your-perplexity-key-here'\n", style="dim white"
                    )
                elif var == "KAEL_REASONING_EFFORT":
                    error_text.append(
                        "export KAEL_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]KAEL",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        logger.error("Missing required env vars: %s", missing_required_vars)
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    logger.info(
        "Environment OK (optional missing: %s)",
        missing_optional_vars or "none",
    )


def check_docker_installed() -> None:
    backend = load_settings().runtime.backend.strip().lower()
    if shutil.which(backend) is None:
        logger.error("Container runtime CLI not found in PATH: %s", backend)
        console = Console()
        error_text = Text()
        error_text.append("CONTAINER RUNTIME NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append(f"The {backend!r} CLI was not found in your PATH.\n", style="white")
        error_text.append(
            f"Install {backend} and ensure its command is available.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold white]KAEL",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)
    logger.debug("Container runtime CLI present: %s", backend)


async def warm_up_llm() -> None:
    from agents.model_settings import ModelSettings
    from agents.models.interface import ModelTracing

    from kael.config.models import (
        KaelProvider,
        configure_sdk_model_defaults,
        is_known_openai_bare_model,
        openrouter_extra_body,
    )

    console = Console()
    logger.info("Warming up LLM connection")

    try:
        settings = load_settings()
        configure_sdk_model_defaults(settings)
        llm = settings.llm

        raw_model = (llm.model or "").strip()
        if (
            raw_model
            and "/" not in raw_model
            and not is_known_openai_bare_model(raw_model)
            and not llm.api_base
        ):
            warn_text = Text()
            warn_text.append("UNKNOWN MODEL NAME", style="bold yellow")
            warn_text.append("\n\n", style="white")
            warn_text.append(f"'{raw_model}'", style="bold cyan")
            warn_text.append(
                " is not a known OpenAI model. Bare names route to OpenAI by default.\n"
                "If you meant a non-OpenAI provider, use the '",
                style="white",
            )
            warn_text.append("<provider>/<model>", style="bold cyan")
            warn_text.append(
                "' form, e.g. 'anthropic/claude-opus-4-7', 'deepseek/deepseek-v4-pro'.",
                style="white",
            )
            console.print(
                Panel(
                    warn_text,
                    title="[bold white]KAEL",
                    title_align="left",
                    border_style="yellow",
                    padding=(1, 2),
                ),
            )
            sys.exit(1)

        model = KaelProvider().get_model(raw_model)
        await asyncio.wait_for(
            model.get_response(
                system_instructions="You are a helpful assistant.",
                input="Reply with just 'OK'.",
                model_settings=ModelSettings(
                    extra_body=openrouter_extra_body(
                        raw_model, llm.openrouter_provider, llm.api_base
                    ),
                ),
                tools=[],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            ),
            timeout=llm.timeout,
        )
        logger.info("LLM warm-up succeeded for model %s", (llm.model or "").strip())

    except Exception as e:
        logger.exception("LLM warm-up failed")
        error_text = Text()
        error_text.append("LLM CONNECTION FAILED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Could not establish connection to the language model.\n", style="white")
        error_text.append("Please check your configuration and try again.\n", style="white")
        error_text.append(f"\nError: {e}", style="dim white")

        panel = Panel(
            error_text,
            title="[bold white]KAEL",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI argument model
# ---------------------------------------------------------------------------
#
# The CLI primarily uses a subcommand + positional-keyword design.
# ``kael scan <target> [keyword value]...``
# collects all scan options as keywords; everything else (``resume``, ``list``,
# ``show``, ``report``, ``help``) is a top-level subcommand.

_SCAN_KEYWORDS_WITH_VALUE: frozenset[str] = frozenset(
    {
        "mode",
        "instruction",
        "instruction-file",
        "prompt",
        "scope-mode",
        "diff-base",
        "config",
        "folder",
    }
)
_SCAN_BOOL_KEYWORDS: frozenset[str] = frozenset(
    {"non-interactive", "build-sandbox", "--build-sandbox"}
)
_SCAN_KEYWORDS: frozenset[str] = _SCAN_KEYWORDS_WITH_VALUE | _SCAN_BOOL_KEYWORDS

_VALID_SCAN_MODES: tuple[str, ...] = ("quick", "standard", "deep", "malware_re", "ctf")
_VALID_SCOPE_MODES: tuple[str, ...] = ("auto", "diff", "full")


@dataclass
class ScanArgs:
    """Parsed ``kael scan [...]`` arguments."""

    raw: list[str]
    targets: list[str]
    mode: str | None = None
    instruction: str | None = None
    instruction_file: str | None = None
    prompt: str | None = None
    scope_mode: str | None = None
    diff_base: str | None = None
    config: str | None = None
    non_interactive: bool = False
    build_sandbox: bool = False
    folder: str | None = None

    @property
    def has_targets(self) -> bool:
        return bool(self.targets)

    @property
    def has_prompt(self) -> bool:
        return bool(self.prompt) or bool(self.instruction) or bool(self.instruction_file)


def _parse_scan_keywords(tokens: list[str]) -> ScanArgs:
    """Parse a flat token list of the form::

        <target> [<target> ...] [keyword value]...

    Keywords are recognised in any order. Repeated single-value keywords
    are an error. Boolean keywords (including ``--build-sandbox``) are flags.
    """
    args = ScanArgs(raw=list(tokens), targets=[])
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _SCAN_KEYWORDS_WITH_VALUE:
            if i + 1 >= len(tokens):
                raise ValueError(f"keyword '{tok}' requires a value")
            value = tokens[i + 1]
            if getattr(args, tok.replace("-", "_"), None) is not None:
                raise ValueError(f"keyword '{tok}' specified more than once")
            setattr(args, tok.replace("-", "_"), value)
            i += 2
            continue
        if tok in _SCAN_BOOL_KEYWORDS:
            attribute = tok.removeprefix("--").replace("-", "_")
            if getattr(args, attribute):
                raise ValueError(f"keyword '{tok}' specified more than once")
            setattr(args, attribute, True)
            i += 1
            continue
        args.targets.append(tok)
        i += 1

    if args.mode is None:
        args.mode = "deep"
    elif args.mode not in _VALID_SCAN_MODES:
        raise ValueError(
            f"invalid mode '{args.mode}' (expected one of: {', '.join(_VALID_SCAN_MODES)})"
        )
    if args.scope_mode is None:
        args.scope_mode = "auto"
    elif args.scope_mode not in _VALID_SCOPE_MODES:
        raise ValueError(
            f"invalid scope-mode '{args.scope_mode}' "
            f"(expected one of: {', '.join(_VALID_SCOPE_MODES)})"
        )
    if args.instruction and args.instruction_file:
        raise ValueError("cannot use both 'instruction' and 'instruction-file' — pick one")
    if args.prompt and (args.instruction or args.instruction_file):
        raise ValueError("cannot use 'prompt' together with 'instruction' or 'instruction-file'")
    return args


# Top-level commands the dispatcher recognises as the first argv token.
# Anything else is treated as the start of an implicit ``scan`` invocation.
_TOP_LEVEL_COMMANDS: frozenset[str] = frozenset(
    {
        "scan",
        "resume",
        "list",
        "ls",
        "show",
        "report",
        "help",
        "sessions",
        "sandbox",
        "version",
        "demo",
    }
)

# Conventional single-letter flag aliases for ``version`` and ``help``.
# These are accepted alongside the ``version`` / ``help`` subcommands for
# muscle-memory compatibility (``kael -v``, ``kael --help``).
_VERSION_FLAGS: frozenset[str] = frozenset({"-v", "--version"})
_HELP_FLAGS: frozenset[str] = frozenset({"-h", "--help"})


def _dispatch(argv: list[str]) -> argparse.Namespace:
    """Top-level dispatch: returns the parsed args, or runs a subcommand.

    Returns a normal ``argparse.Namespace`` for scan/resume; raises
    ``SystemExit`` for ``list``/``show``/``report``/``help``/``sessions``
    (because those are handled by ``cmd_sessions`` or the help renderer).
    """
    if len(argv) < 2:
        return _build_scan_namespace([])

    first = argv[1]
    if first in _VERSION_FLAGS or first == "version":
        print(f"kael {get_version()}")
        raise SystemExit(0)
    if first in _HELP_FLAGS or first == "help":
        from kael.interface.help import print_full_help

        print_full_help()
        raise SystemExit(0)
    if first == "sandbox":
        raise SystemExit(_run_sandbox_command(argv[2:]))
    if first in {"demo", "--demo"}:
        from kael.interface.tui.demo import run_demo

        raise SystemExit(run_demo(argv[2:]))
    if first in {"list", "ls", "show", "report", "sessions"}:
        from kael.interface.sessions import cmd_sessions

        if first in {"resume", "show", "report"}:
            new_argv = ["kael", "sessions", first, *argv[2:]]
        elif first in {"list", "ls"}:
            new_argv = ["kael", "sessions", "list", *argv[2:]]
        else:
            new_argv = argv
        raise SystemExit(cmd_sessions(new_argv[1:]))
    if first in {"resume", "--resume"}:
        return _build_resume_namespace(argv[2:])

    # Either `scan` (explicit) or a bare target — treat as scan.
    tokens = argv[2:] if first == "scan" else argv[1:]
    return _build_scan_namespace(tokens)


def _run_sandbox_command(rest: list[str]) -> int:
    """Run ``kael sandbox build`` without initializing an LLM or scan."""
    if not rest or rest[0] in _HELP_FLAGS:
        print("Usage: kael sandbox build [--force]")
        return 0
    if rest[0] != "build" or any(token not in {"--force"} for token in rest[1:]):
        print("kael: error: expected `kael sandbox build [--force]`", file=sys.stderr)
        return 2

    from kael.runtime.sandbox_image import SandboxImageError, build_sandbox_image

    try:
        build_sandbox_image(force="--force" in rest[1:])
    except SandboxImageError as exc:
        print(f"kael: error: {exc}", file=sys.stderr)
        return 1
    return 0


def _build_resume_namespace(rest: list[str]) -> argparse.Namespace:
    """Build a namespace for ``kael resume [NAME]`` (NAME optional, defaults to most recent)."""
    args = argparse.Namespace()
    args.command = "resume"
    args.resume = rest[0] if rest else None
    args.targets_info = []
    args.instruction = None
    args.instruction_file = None
    args.prompt = None
    args.prompt_only = False
    args.scan_mode = "deep"
    args.scope_mode = "auto"
    args.diff_base = None
    args.config = None
    args.non_interactive = False
    args.build_sandbox = False
    args.folder = None
    args.user_explicit_instruction = None
    return args


def _build_scan_namespace(tokens: list[str]) -> argparse.Namespace:
    """Build a scan-mode namespace from the post-``scan`` token list (or implicit scan)."""
    try:
        scan = _parse_scan_keywords(tokens)
    except ValueError as exc:
        print(f"kael: error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    if scan.instruction_file:
        instruction_path = Path(scan.instruction_file)
        try:
            scan.instruction = instruction_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            print(f"kael: error: failed to read instruction file: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        if not scan.instruction:
            print(
                f"kael: error: instruction file '{instruction_path}' is empty",
                file=sys.stderr,
            )
            raise SystemExit(2)
        scan.instruction_file = None

    # Default to current working directory in non-interactive mode so
    # ``kael . non-interactive`` and the implicit ``kael .`` are equivalent.
    # A bare prompt (``kael prompt "..."``) also skips the default — the
    # agent runs in prompt-only mode with no target.
    targets = scan.targets or (["."] if scan.non_interactive and not scan.prompt else [])

    args = argparse.Namespace()
    args.command = "scan"
    args.target = targets or None
    args.targets_info = []
    args.scan_mode = scan.mode
    args.instruction = scan.prompt or scan.instruction
    args.instruction_file = scan.instruction_file
    args.prompt = scan.prompt
    # Prompt-only when the user provided a prompt and no target. Used by
    # the runner to swap to the prompt-only system prompt (no security
    # guard rails) and by the UI to label the run.
    args.prompt_only = bool(scan.prompt) and not targets
    args.scope_mode = scan.scope_mode
    args.diff_base = scan.diff_base
    args.config = scan.config
    args.non_interactive = scan.non_interactive
    args.build_sandbox = scan.build_sandbox
    args.folder = scan.folder
    args.resume = None
    args.user_explicit_instruction = None

    for target in targets:
        try:
            target_type, target_dict = infer_target_type(target)
        except ValueError:
            print(f"kael: error: invalid target '{target}'", file=sys.stderr)
            raise SystemExit(2) from None
        if target_type == "local_code":
            display_target = target_dict.get("target_path", target)
        elif target_type == "malware_sample":
            display_target = target_dict.get("target_file", target)
        else:
            display_target = target
        args.targets_info.append(
            {"type": target_type, "details": target_dict, "original": display_target}
        )

    if args.targets_info:
        assign_workspace_subdirs(args.targets_info)
        rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)

    return args


def parse_arguments() -> argparse.Namespace:
    """Parse argv into an ``argparse.Namespace`` describing the requested run."""
    return _dispatch(sys.argv)


def _persist_run_record(args: argparse.Namespace) -> None:
    run_dir = run_dir_for(args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_record = {
        "run_id": args.run_name,
        "run_name": args.run_name,
        "status": "running",
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": None,
        "targets_info": args.targets_info,
        "scan_mode": args.scan_mode,
        "instruction": args.instruction,
        "non_interactive": args.non_interactive,
        "local_sources": getattr(args, "local_sources", []),
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scope_mode": args.scope_mode,
        "diff_base": args.diff_base,
    }
    write_run_record(run_dir, run_record)


def _load_resume_state(args: argparse.Namespace) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json."""

    def _fail(msg: str) -> None:
        print(f"kael: error: {msg}", file=sys.stderr)
        raise SystemExit(2)

    run_dir = run_dir_for(args.resume)
    state_path = run_dir / "run.json"
    if not state_path.exists():
        _fail(
            f"resume {args.resume}: no such run "
            f"(missing {state_path}; pick a different run or start fresh)"
        )
    try:
        state = read_run_record(run_dir)
    except RuntimeError as exc:
        _fail(f"resume {args.resume}: run.json unreadable: {exc}")

    args.targets_info = state.get("targets_info") or []
    if not args.targets_info:
        _fail(f"resume {args.resume}: run.json has no targets_info")

    for target in args.targets_info:
        if not isinstance(target, dict):
            continue
        details = target.get("details") or {}
        if target.get("type") != "repository":
            continue
        cloned = details.get("cloned_repo_path")
        if not cloned:
            continue
        if not Path(cloned).expanduser().exists():
            _fail(
                f"resume {args.resume}: cloned repo at {cloned} is missing. "
                f"It was deleted between runs. Pick a fresh run to re-clone, "
                f"or restore the directory before resuming."
            )

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if state.get("local_sources"):
        args.local_sources = state.get("local_sources")
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    from kael.report.state import get_global_report_state

    console = Console()
    report_state = get_global_report_state()

    scan_completed = False
    if report_state:
        scan_completed = report_state.run_record.get("status") == "completed"

    completion_text = Text()
    if scan_completed:
        completion_text.append("Penetration test completed", style="bold #22c55e")
    else:
        completion_text.append("SESSION ENDED", style="bold #eab308")

    target_text = Text()
    if args.targets_info:
        target_text.append("Target", style="dim")
        target_text.append("  ")
        if len(args.targets_info) == 1:
            target_text.append(args.targets_info[0]["original"], style="bold white")
        else:
            target_text.append(f"{len(args.targets_info)} targets", style="bold white")
            for target_info in args.targets_info:
                target_text.append("\n        ")
                target_text.append(target_info["original"], style="white")
    else:
        target_text.append("Mode", style="dim")
        target_text.append("  ")
        target_text.append("Prompt-only (no target)", style="bold white")

    stats_text = build_final_stats_text(report_state)

    panel_parts: list[Text | str] = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    results_text = Text()
    results_text.append("\n")
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(str(results_path), style="#60a5fa")
    panel_parts.extend(["\n", results_text])

    if not scan_completed:
        resume_text = Text()
        resume_text.append("\n")
        resume_text.append("Resume", style="dim")
        resume_text.append("  ")
        resume_text.append(f"kael --resume {args.run_name}", style="#22c55e")
        panel_parts.extend(["\n", resume_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#22c55e" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold white]KAEL",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print(
        "[#60a5fa]github.com/Th4phat/kael-agent[/]  [dim]·[/]  "
        "[#60a5fa]github.com/Th4phat/kael-agent/discussions[/]"
    )
    console.print()


def pull_docker_image(*, build_requested: bool = False) -> None:
    console = Console()
    client = check_docker_connection()

    image = load_settings().runtime.image

    if image_exists(client, image):
        logger.debug("Docker image already present locally: %s", image)
        return

    if image == default_sandbox_image():
        from kael.runtime.sandbox_image import (
            SandboxImageError,
            build_sandbox_image,
            missing_image_message,
            should_build_missing_image,
        )

        if not should_build_missing_image(explicit=build_requested):
            print(f"kael: error: {missing_image_message(image)}", file=sys.stderr)
            raise SystemExit(1)
        try:
            build_sandbox_image(image=image)
        except SandboxImageError as exc:
            print(f"kael: error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        if not image_exists(client, image):
            print(
                f"kael: error: build completed but image {image!r} was not found",
                file=sys.stderr,
            )
            raise SystemExit(1)
        return

    logger.info("Pulling docker image: %s", image)
    console.print()
    console.print(f"[dim]Pulling image[/] {image}")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(image, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            logger.exception("Failed to pull docker image %s", image)
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {image}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]KAEL",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    logger.info("Docker image %s ready", image)
    success_text = Text()
    success_text.append("Docker image ready", style="#22c55e")
    console.print(success_text)
    console.print()


def main() -> None:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = parse_arguments()
    configure_dependency_logging()

    if args.command == "resume":
        if not args.resume:
            from kael.interface.sessions import _most_recent_run_name

            args.resume = _most_recent_run_name()
            if not args.resume:
                print(
                    "kael: error: no runs found. Start one with `kael <target>` first.",
                    file=sys.stderr,
                )
                raise SystemExit(1)
        # Reuse the same hydration path as the legacy --resume flag.
        _load_resume_state(args)

    if args.config:
        apply_config_override(validate_config_file(args.config))

    if args.non_interactive or (load_settings().llm.model or "").strip():
        check_docker_installed()
        pull_docker_image(build_requested=args.build_sandbox)
        validate_environment()
        asyncio.run(warm_up_llm())
        persist_current()

    args.run_name = args.resume or generate_run_name(
        args.targets_info, prompt=getattr(args, "instruction", None)
    )

    if not args.resume:
        for target_info in args.targets_info:
            if target_info["type"] == "repository":
                repo_url = target_info["details"]["target_repo"]
                dest_name = target_info["details"].get("workspace_subdir")
                cloned_path = clone_repository(repo_url, args.run_name, dest_name)
                target_info["details"]["cloned_repo_path"] = cloned_path

        args.local_sources = collect_local_sources(args.targets_info)
        try:
            diff_scope = resolve_diff_scope_context(
                local_sources=args.local_sources,
                scope_mode=args.scope_mode,
                diff_base=args.diff_base,
                non_interactive=args.non_interactive,
            )
        except ValueError as e:
            console = Console()
            error_text = Text()
            error_text.append("DIFF SCOPE RESOLUTION FAILED", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(str(e), style="white")

            panel = Panel(
                error_text,
                title="[bold white]KAEL",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print("\n")
            console.print(panel)
            console.print()
            sys.exit(1)

        args.diff_scope = diff_scope.metadata
        if diff_scope.instruction_block:
            if args.instruction:
                args.instruction = f"{diff_scope.instruction_block}\n\n{args.instruction}"
            else:
                args.instruction = diff_scope.instruction_block

        _persist_run_record(args)

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            from kael.interface.cli import run_cli

            asyncio.run(run_cli(args))
        else:
            from kael.interface.tui import run_tui

            asyncio.run(run_tui(args))
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception:
        exit_reason = "error"
        raise
    finally:
        from kael.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state:
            status = {"interrupted": "interrupted", "error": "failed"}.get(
                exit_reason,
                "stopped",
            )
            report_state.cleanup(status=status)

    results_path = run_dir_for(args.run_name)
    display_completion_message(args, results_path)

    if args.non_interactive:
        from kael.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state and report_state.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
