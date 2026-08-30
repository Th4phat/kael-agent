"""Kael application settings — pydantic-settings powered."""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 - used by pydantic at runtime for re_yara_rules_dir
from typing import Any, Literal

from pydantic import AliasChoices, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from kael.version import default_sandbox_image


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh"]

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
    env_file=".env",
    env_file_encoding="utf-8",
)


class _KaelBaseSettings(BaseSettings):
    """Base settings with Kael's documented source precedence."""

    model_config = _BASE_CONFIG

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        del settings_cls
        return env_settings, dotenv_settings, init_settings, file_secret_settings


class LlmSettings(_KaelBaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="KAEL_LLM")
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "OPENAI_API_KEY"),
    )
    api_base: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ),
    )
    reasoning_effort: ReasoningEffort = Field(default="high", alias="KAEL_REASONING_EFFORT")
    timeout: int = Field(default=300, alias="LLM_TIMEOUT")
    openrouter_provider: dict[str, Any] | None = Field(
        default=None,
        alias="KAEL_OPENROUTER_PROVIDER",
        description=(
            "OpenRouter provider routing preferences as JSON, e.g. "
            '{"order":["DeepSeek"],"allow_fallbacks":false}. Only applied when '
            "the model resolves through openrouter. See "
            "https://openrouter.ai/docs/features/provider-routing"
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
    """Cross-run learning memory bounds.

    Learnings are kept in ``~/.kael/memory/<target-slug>/learnings.json``
    and persist across separate scans of the same target. To keep that
    file from growing unbounded:

    - ``learning_ttl_days`` - how old an entry can be (by ``updated_at``)
      before it is pruned. ``0`` disables expiry.
    - ``max_learnings_per_target`` - hard cap on the per-slug entry count.
      When the cap is hit, oldest ``dead_end`` / ``unknown`` entries are
      dropped first; ``confirmed`` and ``promising`` entries are always
      preserved (they're the highest-signal).
    """

    model_config = _BASE_CONFIG

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
