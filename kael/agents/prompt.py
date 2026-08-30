"""Jinja-based system-prompt renderer."""

from __future__ import annotations

import functools
import logging
import os
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from kael.skills import get_available_skills, load_skills
from kael.tools.registry import REGISTRY
from kael.utils.resource_paths import get_kael_resource_path


logger = logging.getLogger(__name__)


_PROMPT_DIRNAME = "prompts"


class SystemPromptRenderError(RuntimeError):
    """Raised when the system prompt template fails to render.

    Previously these failures were swallowed and an empty string was
    returned, leaving the agent with no system prompt — an agent with
    no system prompt behaves unpredictably and silently produces
    broken scans. Now the failure surfaces so the caller can fail loud.
    """


def _resolve_skills(
    *,
    requested: list[str] | None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    browser_backend: str = "",
) -> list[str]:
    """Build the deduped, ordered skills list for the prompt render.

    Order:

    1. Whatever the caller asked for, in order.
    2. ``scan_modes/<mode>`` (always).
    3. ``tooling/agent_browser`` (always — every agent has shell + the
       agent-browser CLI).
    4. ``tooling/agent_browser_vercel_sandbox`` when ``BROWSER_BACKEND=vercel-sandbox``.
    5. ``tooling/python`` (always — Python runs through ``exec_command``;
       sandbox scripts can import ``mitm_control`` for proxy automation).
    6. ``coordination/root_agent`` for the root agent only — orchestration
       guidance for delegating to specialist subagents.
    7. Whitebox-specific skills if applicable.
    """
    ordered: list[str] = list(requested or [])
    ordered.append(f"scan_modes/{scan_mode}")
    ordered.append("tooling/agent_browser")
    if browser_backend == "vercel-sandbox":
        ordered.append("tooling/agent_browser_vercel_sandbox")
    ordered.append("tooling/python")
    if is_root:
        ordered.append("coordination/root_agent")
    if is_whitebox:
        ordered.append("coordination/source_aware_whitebox")
        ordered.append("custom/source_aware_sast")

    deduped: list[str] = []
    seen: set[str] = set()
    for skill in ordered:
        if skill and skill not in seen:
            deduped.append(skill)
            seen.add(skill)
    return deduped


@functools.cache
def _build_env_and_skills(
    *,
    skills: tuple[str, ...],
    scan_mode: str,
    is_whitebox: bool,
    is_root: bool,
    browser_backend: str,
) -> tuple[Environment, dict[str, str]]:
    """Build the Jinja env and load skill content for a (skills, mode) key.

    Memoized so repeated agent builds (e.g. child agents in a graph)
    don't re-read templates from disk and re-parse every skill.
    """
    prompt_dir = get_kael_resource_path("agents", _PROMPT_DIRNAME)
    skills_dir = get_kael_resource_path("skills")
    env = Environment(
        loader=FileSystemLoader([prompt_dir, skills_dir]),
        autoescape=select_autoescape(
            enabled_extensions=(),
            default_for_string=False,
        ),
    )

    skills_to_load = _resolve_skills(
        requested=list(skills),
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        is_root=is_root,
        browser_backend=browser_backend,
    )
    skill_content = load_skills(skills_to_load)
    env.globals["get_skill"] = lambda name: skill_content.get(name, "")
    return env, skill_content


def render_system_prompt(
    *,
    skills: list[str] | None = None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    interactive: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
    prompt_only: bool = False,
) -> str:
    """Render the system prompt.

    Raises :class:`SystemPromptRenderError` if template loading or
    rendering fails. The previous behavior returned ``""`` on any
    exception, which produced agents with no prompt and unpredictable
    downstream behavior — the new contract fails loud instead.

    When ``prompt_only`` is true the dedicated
    ``system_prompt_prompt_only.jinja`` template is rendered instead of
    the security-scoped default. That template has no authorized-target
    / refusal-avoidance section, so the agent will execute freeform
    tasks the user pastes in (``kael prompt "..."``) without tripping
    the "no in-scope targets" guard.
    """
    skills_key = tuple(skills or ())
    browser_backend = os.environ.get("BROWSER_BACKEND", "")
    try:
        env, skill_content = _build_env_and_skills(
            skills=skills_key,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_root=is_root,
            browser_backend=browser_backend,
        )
        # Lazy import of factory to populate REGISTRY: factory.py
        # imports this module for ``render_system_prompt``, so a
        # top-level import here would be circular. The lazy import is
        # safe because render is called after both modules are loaded.
        from kael.agents import factory as _factory  # noqa: PLC0415

        # Lazy registration of scan-mode-specific tools so the catalog
        # in the rendered prompt includes the right tools for the
        # scan_mode the agent is about to run. Base tools are already
        # registered at factory import time.
        if scan_mode == "malware_re":
            _factory._ensure_re_tools_registered()
        elif scan_mode == "ctf":
            _factory._ensure_ctf_tools_registered()

        tool_catalog = REGISTRY.tool_schema_for_prompt(scan_mode=scan_mode)
        template_name = "system_prompt_prompt_only.jinja" if prompt_only else "system_prompt.jinja"
        rendered = env.get_template(template_name).render(
            loaded_skill_names=list(skill_content.keys()),
            available_skills=get_available_skills(),
            interactive=interactive,
            system_prompt_context=system_prompt_context or {},
            tool_catalog=tool_catalog,
            **skill_content,
        )
    except Exception as exc:
        logger.exception("render_system_prompt failed")
        raise SystemPromptRenderError(
            f"Failed to render system prompt (scan_mode={scan_mode!r}, "
            f"is_root={is_root}, is_whitebox={is_whitebox}, "
            f"skills={len(skills_key)}): {exc}"
        ) from exc
    else:
        logger.debug(
            "render_system_prompt: scan_mode=%s root=%s whitebox=%s skills=%d prompt_len=%d",
            scan_mode,
            is_root,
            is_whitebox,
            len(skill_content),
            len(rendered),
        )
        return str(rendered)
