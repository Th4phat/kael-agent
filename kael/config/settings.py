"""Kael application settings — pydantic-settings powered."""

from __future__ import annotations

import json
from pathlib import Path  # noqa: TC003 - used by pydantic at runtime for re_yara_rules_dir
from typing import TYPE_CHECKING, Annotated, Any, Literal, get_args

from pydantic import AliasChoices, Field, ValidationInfo, field_validator
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from kael.version import default_sandbox_image


if TYPE_CHECKING:
    from pydantic.fields import FieldInfo


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh"]

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


def _aliases_for(finfo: FieldInfo) -> list[str]:
    """Collect every env-var name that should populate ``finfo``."""
    aliases: list[str] = []
    if finfo.alias:
        aliases.append(finfo.alias)
    va = finfo.validation_alias
    if isinstance(va, AliasChoices):
        aliases.extend(c for c in va.choices if isinstance(c, str))
    elif isinstance(va, str):
        aliases.append(va)
    return list(dict.fromkeys(aliases))


class _KaelBaseSettings(BaseSettings):
    """Base settings with Kael's documented source precedence."""

    model_config = _BASE_CONFIG

    @field_validator("*", mode="before")
    @classmethod
    def empty_optional_value(cls, value: Any, info: ValidationInfo) -> Any:
        if (
            value == ""
            and info.field_name is not None
            and type(None) in get_args(cls.model_fields[info.field_name].annotation)
        ):
            return None
        return value

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        del dotenv_settings
        if isinstance(env_settings, EnvSettingsSource):
            configured = init_settings()
            overridden: set[str] = set()
            for name, info in settings_cls.model_fields.items():
                names = [name, *_aliases_for(info)]
                if any(key in configured for key in names):
                    overridden.update(key.lower() for key in names)
            env_settings.env_vars = {
                key: value for key, value in env_settings.env_vars.items() if key not in overridden
            }
        return init_settings, env_settings, file_secret_settings


class LlmSettings(_KaelBaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(
        default=None,
        alias="KAEL_LLM",
        description="Provider/model identifier, such as openrouter/anthropic/claude-sonnet-4.6.",
    )
    api_key: str | None = Field(
        default=None,
        title="API key",
        validation_alias=AliasChoices("LLM_API_KEY", "OPENAI_API_KEY"),
    )
    api_base: str | None = Field(
        default=None,
        title="API base URL",
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ),
    )
    reasoning_effort: ReasoningEffort = Field(default="high", alias="KAEL_REASONING_EFFORT")
    timeout: int = Field(default=300, gt=0, alias="LLM_TIMEOUT")
    openrouter_provider: Annotated[dict[str, Any] | None, NoDecode] = Field(
        default=None,
        alias="KAEL_OPENROUTER_PROVIDER",
        title="OpenRouter provider",
        description=(
            "OpenRouter provider slug (e.g. deepinfra) to allow only that provider, "
            'or routing preferences as JSON (e.g. {"order":["deepinfra"]}). '
            "Only applied to OpenRouter requests. See "
            "https://openrouter.ai/docs/guides/routing/provider-selection"
        ),
    )
    vision_model: str | None = Field(
        default=None,
        alias="KAEL_VISION_LLM",
        description=(
            "Dedicated vision model for the view_image tool. When set, the "
            "main `model` is assumed to be text-only and never receives "
            "images; the view_image tool calls this model instead and "
            "returns plain text. Same format as KAEL_LLM "
            "(e.g. openai/gpt-4o, openrouter/anthropic/claude-3.5-sonnet)."
        ),
    )
    vision_api_key: str | None = Field(
        default=None,
        alias="VISION_LLM_API_KEY",
        description="API key for the vision model. Falls back to LLM_API_KEY.",
    )
    vision_api_base: str | None = Field(
        default=None,
        alias="VISION_LLM_API_BASE",
        description="API base URL for the vision model. Falls back to LLM_API_BASE.",
    )

    @field_validator("openrouter_provider", mode="before")
    @classmethod
    def parse_openrouter_provider(cls, value: Any) -> dict[str, Any] | None:
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return None
            if value.startswith(("{", "[")) or value == "null":
                value = json.loads(value)
            else:
                return {"only": [value]}
        if value is not None and not isinstance(value, dict):
            raise ValueError("Enter a provider slug or a JSON routing object.")
        return value


class RuntimeSettings(_KaelBaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default_factory=default_sandbox_image,
        alias="KAEL_IMAGE",
    )
    backend: str = Field(default="docker", alias="KAEL_RUNTIME_BACKEND")
    auto_build_sandbox: bool = Field(default=False, alias="KAEL_AUTO_BUILD_SANDBOX")
    container_socket: str | None = Field(
        default=None,
        alias="KAEL_CONTAINER_SOCKET",
    )
    sandbox_dns: str | None = Field(
        default=None,
        alias="KAEL_SANDBOX_DNS",
        description=(
            "Comma-separated nameservers for the sandbox. Unset inherits the "
            "runtime default (host resolv.conf), which breaks under rootless "
            "Podman when the host's first resolvers are unreachable (e.g. Tailscale)."
        ),
    )


class IntegrationSettings(_KaelBaseSettings):
    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(default=None, alias="PERPLEXITY_API_KEY")
    tavily_api_key: str | None = Field(default=None, alias="TAVILY_API_KEY")
    tavily_search_depth: Literal["basic", "advanced"] = Field(
        default="advanced",
        alias="TAVILY_SEARCH_DEPTH",
    )
    tavily_max_results: int = Field(default=10, alias="TAVILY_MAX_RESULTS")
    tavily_include_answer: bool = Field(default=True, alias="TAVILY_INCLUDE_ANSWER")
    exploitdb_max_results: int = Field(default=15, alias="EXPLOITDB_MAX_RESULTS")
    exploitdb_timeout: int = Field(default=60, alias="EXPLOITDB_TIMEOUT")


class MemorySettings(_KaelBaseSettings):
    """Private agent notes and optional shared learning memory.

    With target scope selected, learnings are kept in
    ``~/.kael/memory/<target-slug>/learnings.json`` across scans of the same target. To keep that
    file from growing unbounded:

    - ``learning_ttl_days`` - how old an entry can be (by ``updated_at``)
      before it is pruned. ``0`` disables expiry.
    - ``max_learnings_per_target`` - hard cap on the per-slug entry count.
      When the cap is hit, oldest ``dead_end`` / ``unknown`` entries are
      dropped first; ``confirmed`` and ``promising`` entries are always
      preserved (they're the highest-signal).
    """

    model_config = _BASE_CONFIG

    scope: Literal["agent", "session", "target"] = Field(
        default="agent",
        alias="KAEL_MEMORY_SCOPE",
        title="Notes scope",
        description=(
            "agent keeps notes private to each agent in this session; "
            "session shares notes within a run; target also shares learnings "
            "across runs with the same targets."
        ),
    )
    learning_ttl_days: int = Field(default=90, alias="KAEL_MEMORY_LEARNING_TTL_DAYS")
    max_learnings_per_target: int = Field(default=500, alias="KAEL_MEMORY_MAX_LEARNINGS_PER_TARGET")


class ReverseEngineeringSettings(_KaelBaseSettings):
    """Reverse engineering and malware analysis settings."""

    model_config = _BASE_CONFIG

    re_analysis_mode: Literal["static", "dynamic", "both"] = Field(
        default="both",
        alias="KAEL_RE_ANALYSIS_MODE",
        description=(
            "static = only static analysis (no execution); "
            "dynamic = only dynamic execution; "
            "both = static + dynamic analysis (recommended)"
        ),
    )
    re_max_runtime_sec: int = Field(
        default=120,
        alias="KAEL_RE_MAX_RUNTIME_SEC",
        description="Maximum seconds for a single sample detonation",
    )
    re_network_mode: Literal["off", "controlled", "live"] = Field(
        default="controlled",
        alias="KAEL_RE_NETWORK_MODE",
        description=(
            "off = no network; "
            "controlled = log+capture outbound, drop blocked CIDRs; "
            "live = full outbound (use with caution)"
        ),
    )
    re_blocked_cidrs: list[str] = Field(
        default=["169.254.169.254/32"],
        alias="KAEL_RE_BLOCKED_CIDRS",
        description="CIDRs to DROP during controlled detonation (cloud metadata, etc.)",
    )
    re_yara_rules_dir: Path | None = Field(
        default=None,
        alias="KAEL_RE_YARA_RULES_DIR",
        description="Custom YARA rules directory (merged with bundled rules)",
    )
    re_enable_memory_dumps: bool = Field(
        default=True,
        alias="KAEL_RE_ENABLE_MEMORY_DUMPS",
        description="Allow gcore memory dumps during detonation (requires CAP_SYS_PTRACE)",
    )


ParallelToolCallsMode = Literal["off", "safe", "all"]


class ToolHarnessSettings(_KaelBaseSettings):
    """Tool-loop ergonomics: parallel tool calls, telemetry, dedup.

    Ponytail: defaults match the previous hard-coded behavior
    (``parallel_tool_calls=False``) so enabling this is strictly
    opt-in via env. The catalog is small and tool costs vary widely;
    sequential execution is the safe default and parallel opt-in is
    the exception, not the rule.
    """

    model_config = _BASE_CONFIG

    parallel_tool_calls_mode: ParallelToolCallsMode = Field(
        default="off",
        alias="KAEL_PARALLEL_TOOL_CALLS",
        description=(
            "off = sequential (default, matches pre-harness behavior); "
            "safe = enable parallel only for tools marked parallel_safe=True in the registry; "
            "all = let the model issue any parallel calls it wants (no validation)"
        ),
    )
    tool_result_max_chars: int = Field(
        default=20_000,
        alias="KAEL_TOOL_RESULT_MAX_CHARS",
        description="Soft cap on individual tool result size.",
    )
    dedup_window_turns: int = Field(
        default=1,
        alias="KAEL_DEDUP_WINDOW_TURNS",
        description="Warn if the same tool+args fires again within this many turns.",
    )


class GoalSettings(_KaelBaseSettings):
    """Goal-wide hard limits, shared across root, children, recovery, and
    the verifier (see ``kael.core.goals``). All default to ``None`` =
    unlimited, so the goal budget is strictly opt-in and a scan without
    these set behaves as before. ``max_turns`` remains a separate
    per-invocation SDK guard.
    """

    model_config = _BASE_CONFIG

    max_model_calls: int | None = Field(default=None, alias="KAEL_GOAL_MAX_MODEL_CALLS", gt=0)
    max_tool_calls: int | None = Field(default=None, alias="KAEL_GOAL_MAX_TOOL_CALLS", gt=0)
    max_wall_seconds: int | None = Field(default=None, alias="KAEL_GOAL_MAX_WALL_SECONDS", gt=0)
    watchdog_poll_seconds: float = Field(
        default=5.0,
        alias="KAEL_GOAL_WATCHDOG_POLL_SECONDS",
        gt=0,
        description="How often the wall-clock/budget watchdog checks the goal budget.",
    )


class Settings(_KaelBaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    memory: MemorySettings = Field(default_factory=MemorySettings)
    reverse_engineering: ReverseEngineeringSettings = Field(
        default_factory=ReverseEngineeringSettings
    )
    tool_harness: ToolHarnessSettings = Field(default_factory=ToolHarnessSettings)
    goal: GoalSettings = Field(default_factory=GoalSettings)
