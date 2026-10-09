"""Pure input builders for Kael scan runs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from agents.run_config import CallModelData, ModelInputData
from openai.types.shared import Reasoning

from kael.config.models import (
    DEFAULT_MODEL_RETRY,
    model_supports_reasoning,
    openrouter_extra_body,
)


if TYPE_CHECKING:
    from kael.config.settings import ReasoningEffort


DEFAULT_MAX_TURNS = 500
_MAX_HISTORY_CHARS = 60_000
_MAX_TOOL_OUTPUT_CHARS = 8_000
# ponytail: character limits approximate tokens; use model-specific counting if needed.


def limit_model_input(data: CallModelData[Any]) -> ModelInputData:
    """Bound replayed history on every model call, including long single runs."""
    items = data.model_data.input
    trimmed = []
    for item in items:
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            output = item.get("output")
            if isinstance(output, str) and len(output) > _MAX_TOOL_OUTPUT_CHARS:
                item = {
                    **item,
                    "output": (
                        output[:6_000]
                        + f"\n[output truncated: {len(output)} characters; inspect the saved artifact or rerun a narrower query]\n"
                        + output[-2_000:]
                    ),
                }
        trimmed.append(item)

    def size(item: Any) -> int:
        return len(json.dumps(item, default=str))

    if sum(map(size, trimmed)) <= _MAX_HISTORY_CHARS:
        return ModelInputData(input=trimmed, instructions=data.model_data.instructions)

    first = []
    start = 0
    if trimmed and isinstance(trimmed[0], dict) and trimmed[0].get("role") == "user":
        # Older child sessions stored the entire parent history in item 0.
        # Keep the child's own task (item 2) when that legacy preamble is huge.
        inherited = str(trimmed[0].get("content", "")).startswith(
            "== Inherited context from parent"
        )
        if inherited and len(trimmed) > 2:
            first, start = [trimmed[2]], 3
        else:
            first, start = trimmed[:1], 1
    for index in range(len(trimmed) - 1, start - 1, -1):
        if isinstance(trimmed[index], dict) and trimmed[index].get("role") == "user":
            first.append(trimmed[index])
            start = index + 1
            break
    budget = _MAX_HISTORY_CHARS - sum(map(size, first))
    recent = []
    for item in reversed(trimmed[start:]):
        item_size = size(item)
        if recent and item_size > budget:
            break
        recent.append(item)
        budget -= item_size
    recent.reverse()

    # A suffix can begin between a tool call and its result. Drop orphaned
    # results so the Responses API receives valid call/output pairs.
    call_ids = {
        item.get("call_id")
        for item in recent
        if isinstance(item, dict) and item.get("type") == "function_call"
    }
    recent = [
        item
        for item in recent
        if not (
            isinstance(item, dict)
            and item.get("type") == "function_call_output"
            and item.get("call_id") not in call_ids
        )
    ]
    return ModelInputData(input=[*first, *recent], instructions=data.model_data.instructions)


def build_root_task(scan_config: dict[str, Any]) -> str:
    targets = scan_config.get("targets", []) or []
    diff_scope = scan_config.get("diff_scope") or {}
    user_instructions = scan_config.get("user_instructions", "") or ""
    prompt_only = bool(scan_config.get("prompt_only"))

    # Prompt-only runs: no target metadata, no diff scope — the user
    # prompt IS the task. Avoid any target-list / scope preambles that
    # the prompt-only system prompt doesn't expect.
    if prompt_only:
        if user_instructions:
            return (
                "Run the following task end-to-end. Use the sandboxed shell, "
                "filesystem, and any other available tools as needed. "
                "When done, call finish_scan with a short summary of what you "
                "did, what you found, and any blockers.\n\n"
                f"Task: {user_instructions}"
            )
        return (
            "No task provided. Ask the user to specify what they want done, "
            "or call finish_scan with a note that no task was given."
        )

    sections: dict[str, list[str]] = {
        "Repositories": [],
        "Local Codebases": [],
        "Malware Samples": [],
        "URLs": [],
        "IP Addresses": [],
    }

    for target in targets:
        ttype = target.get("type")
        details = target.get("details") or {}
        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

        if ttype == "repository":
            url = details.get("target_repo", "")
            cloned = details.get("cloned_repo_path")
            sections["Repositories"].append(
                f"- {url} (available at: {workspace_path})" if cloned else f"- {url}",
            )
        elif ttype == "local_code":
            path = details.get("target_path", "unknown")
            sections["Local Codebases"].append(f"- {path} (available at: {workspace_path})")
        elif ttype == "malware_sample":
            path = details.get("target_file", "unknown")
            sections["Malware Samples"].append(f"- {path} (available at: {workspace_path})")
        elif ttype == "web_application":
            sections["URLs"].append(f"- {details.get('target_url', '')}")
        elif ttype == "ip_address":
            sections["IP Addresses"].append(f"- {details.get('target_ip', '')}")

    parts: list[str] = []
    for label, items in sections.items():
        if items:
            parts.append(f"\n\n{label}:")
            parts.extend(items)

    if diff_scope.get("active"):
        parts.append("\n\nScope Constraints:")
        parts.append(
            "- Pull request diff-scope mode is active. Prioritize changed files "
            "and use other files only for context.",
        )
        for repo_scope in diff_scope.get("repos", []) or []:
            label = (
                repo_scope.get("workspace_subdir") or repo_scope.get("source_path") or "repository"
            )
            changed = repo_scope.get("analyzable_files_count", 0)
            deleted = repo_scope.get("deleted_files_count", 0)
            parts.append(f"- {label}: {changed} changed file(s) in primary scope")
            if deleted:
                parts.append(f"- {label}: {deleted} deleted file(s) are context-only")

    task = " ".join(parts)
    if user_instructions:
        task = f"{task}\n\nSpecial instructions: {user_instructions}"
    return task


def build_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
    authorized: list[dict[str, str]] = []
    value_keys = {
        "repository": "target_repo",
        "local_code": "target_path",
        "malware_sample": "target_file",
        "web_application": "target_url",
        "ip_address": "target_ip",
    }
    for target in scan_config.get("targets", []) or []:
        ttype = target.get("type", "unknown")
        details = target.get("details") or {}
        key = value_keys.get(ttype)
        value = details.get(key, "") if key is not None else target.get("original", "")

        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""
        authorized.append(
            {"type": ttype, "value": value, "workspace_path": workspace_path},
        )

    # Add reverse engineering settings if available
    from kael.config import load_settings

    settings = load_settings()
    re_settings = {
        "analysis_mode": settings.reverse_engineering.re_analysis_mode,
        "network_mode": settings.reverse_engineering.re_network_mode,
        "max_runtime_sec": settings.reverse_engineering.re_max_runtime_sec,
        "enable_memory_dumps": settings.reverse_engineering.re_enable_memory_dumps,
    }

    prompt_only = bool(scan_config.get("prompt_only"))

    return {
        "scope_source": "user_prompt" if prompt_only else "system_scan_config",
        "authorization_source": (
            "user_prompt_only" if prompt_only else "kael_platform_verified_targets"
        ),
        "authorized_targets": authorized,
        "user_instructions_do_not_expand_scope": not prompt_only,
        "re_settings": re_settings,
    }


def make_model_settings(
    reasoning_effort: ReasoningEffort | None,
    *,
    model_name: str,
    parallel_tool_calls_mode: str = "off",
    openrouter_provider: dict[str, Any] | None = None,
    api_base: str | None = None,
) -> ModelSettings:
    # Parallel tool calls are opt-in (default "off") to keep the
    # previous hard-coded sequential behavior. "safe" enables parallel
    # for the model — the registry's ``parallel_safe`` flag is the
    # intended contract, but the SDK doesn't surface "this batch is
    # parallel" to our hooks, so the "safe" claim is best-effort
    # (telemetry warns on repeat non-safe calls in a turn).
    parallel = parallel_tool_calls_mode in ("safe", "all")
    model_settings = ModelSettings(
        parallel_tool_calls=parallel,
        retry=DEFAULT_MODEL_RETRY,
        include_usage=True,
        extra_body=openrouter_extra_body(model_name, openrouter_provider, api_base),
    )
    # Custom OpenAI-compatible endpoints (LLM_API_BASE) aren't in litellm's
    # model registry, so model_supports_reasoning() can't see them. `reasoning_effort`
    # is the OpenAI-compatible thinking param, so send it whenever a custom
    # base URL is configured — the user chose that endpoint deliberately.
    if (
        reasoning_effort is not None
        and reasoning_effort != "none"
        and (api_base is not None or model_supports_reasoning(model_name))
    ):
        model_settings = model_settings.resolve(
            ModelSettings(reasoning=Reasoning(effort=reasoning_effort)),
        )
    return model_settings


def child_initial_input(
    *,
    name: str,
    child_id: str,
    parent_id: str,
    task: str,
    parent_history: list[Any],
) -> list[dict[str, Any]]:
    initial_input: list[dict[str, Any]] = []
    if parent_history:
        rendered = json.dumps(parent_history, ensure_ascii=False, default=str)
        if len(rendered) > 8_000:
            rendered = "[Earlier parent context omitted] ..." + rendered[-8_000:]
        initial_input.append(
            {
                "role": "user",
                "content": (
                    "== Inherited context from parent (background only) ==\n"
                    f"{rendered}\n"
                    "== End of inherited context ==\n"
                    "Use the above as background only; do not continue the "
                    "parent's work. Your task follows."
                ),
            },
        )
    initial_input.append(
        {
            "role": "user",
            "content": (
                f"You are agent {name} ({child_id}); your parent is {parent_id}. "
                "Maintain your own identity. Call agent_finish when your task "
                "is complete."
            ),
        }
    )
    initial_input.append({"role": "user", "content": task})
    return initial_input
