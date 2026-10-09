"""End-to-end setting validation, config saving, and model reconfiguration."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from agents import Agent, RunConfig, RunContextWrapper, Runner, function_tool
from agents.items import ModelResponse
from agents.model_settings import ModelSettings
from agents.models.interface import Model, ModelProvider
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from kael.config import loader
from kael.config.editor import editable_settings, save_settings
from kael.config.models import KaelProvider, configure_sdk_model_defaults
from kael.core.agents import AgentCoordinator
from kael.core.hooks import ReportUsageHooks


def test_catalog_covers_all_schema_aliases_and_migrated_dotenv_variables() -> None:
    Path(".env").write_text(
        "BROWSER_BACKEND=lightpanda\nCUSTOM_TOKEN=private-value\n", encoding="utf-8"
    )
    settings = loader.load_settings()
    catalog = editable_settings()
    for section in type(settings).model_fields:
        model = getattr(settings, section)
        for info in type(model).model_fields.values():
            assert set(loader._aliases_for(info)) <= catalog.keys()
    assert {"BROWSER_BACKEND", "CUSTOM_TOKEN"} <= catalog.keys()
    assert catalog["CUSTOM_TOKEN"].secret
    assert catalog["BROWSER_BACKEND"].value() == "lightpanda"
    assert os.environ["BROWSER_BACKEND"] == "lightpanda"
    assert loader.read_config()["env"]["CUSTOM_TOKEN"] == "private-value"


def test_every_schema_setting_and_alias_can_be_saved_and_reloaded() -> None:
    catalog = editable_settings()
    for name, entry in catalog.items():
        if entry.field is None:
            continue
        default = entry.default()
        save_settings({name: default})
        for alias in entry.aliases:
            os.environ.pop(alias, None)
        loader._cached = None
        assert editable_settings()[name].value() == default, name


@pytest.mark.parametrize(
    ("name", "raw", "section", "field", "value"),
    [
        ("KAEL_LLM", "openrouter/new-model", "llm", "model", "openrouter/new-model"),
        ("LLM_TIMEOUT", "42", "llm", "timeout", 42),
        ("KAEL_REASONING_EFFORT", "none", "llm", "reasoning_effort", "none"),
        ("KAEL_MEMORY_SCOPE", "agent", "memory", "scope", "agent"),
        ("KAEL_MEMORY_SCOPE", "session", "memory", "scope", "session"),
        ("KAEL_MEMORY_SCOPE", "target", "memory", "scope", "target"),
        ("TAVILY_INCLUDE_ANSWER", "false", "integrations", "tavily_include_answer", False),
        (
            "KAEL_RE_BLOCKED_CIDRS",
            '["10.0.0.0/8"]',
            "reverse_engineering",
            "re_blocked_cidrs",
            ["10.0.0.0/8"],
        ),
        (
            "KAEL_RE_YARA_RULES_DIR",
            "./rules",
            "reverse_engineering",
            "re_yara_rules_dir",
            Path("./rules"),
        ),
        (
            "KAEL_OPENROUTER_PROVIDER",
            "deepinfra",
            "llm",
            "openrouter_provider",
            {"only": ["deepinfra"]},
        ),
        ("VISION_LLM_API_KEY", "", "llm", "vision_api_key", None),
    ],
)
def test_typed_values_survive_save_and_reload(
    name: str,
    raw: str,
    section: str,
    field: str,
    value: object,
) -> None:
    save_settings({name: raw})
    assert getattr(getattr(loader.load_settings(), section), field) == value
    loader._cached = None
    assert getattr(getattr(loader.load_settings(), section), field) == value


def test_save_preserves_metadata_unrelated_keys_and_updates_aliases() -> None:
    path = Path("selected.json")
    path.write_text(
        json.dumps(
            {
                "note": "keep this metadata",
                "env": {
                    "OPENAI_API_KEY": "old",
                    "LLM_API_KEY": "old",
                    "BROWSER_BACKEND": "lightpanda",
                },
            }
        ),
        encoding="utf-8",
    )
    loader.apply_config_override(path)
    loader.load_settings()
    save_settings({"OPENAI_API_KEY": "new'key", "CUSTOM_SETTING": "$(literal) `text`"})
    config = json.loads(path.read_text())
    data = config["env"]
    assert data["OPENAI_API_KEY"] == data["LLM_API_KEY"] == "new'key"
    assert data["CUSTOM_SETTING"] == "$(literal) `text`"
    assert config["note"] == "keep this metadata"
    assert data["BROWSER_BACKEND"] == "lightpanda"
    assert path.stat().st_mode & 0o777 == 0o600
    assert loader.load_settings().llm.api_key == "new'key"
    assert os.environ["LLM_API_KEY"] == os.environ["OPENAI_API_KEY"] == "new'key"
    assert not Path(".env").exists()


def test_clearing_optional_value_overrides_old_json_and_dotenv_aliases(tmp_path: Path) -> None:
    Path(".env").write_text("LLM_API_KEY=old\nOPENAI_API_KEY=old\n", encoding="utf-8")
    config = tmp_path / "selected.json"
    config.write_text(json.dumps({"env": {"LLM_API_KEY": "json-old"}}), encoding="utf-8")
    loader.apply_config_override(config)
    assert loader.load_settings().llm.api_key == "json-old"
    save_settings({"LLM_API_KEY": ""})
    for name in ("LLM_API_KEY", "OPENAI_API_KEY"):
        os.environ.pop(name, None)
    loader._cached = None
    assert loader.load_settings().llm.api_key is None


@pytest.mark.parametrize(
    "changes",
    [
        {"LLM_TIMEOUT": "zero"},
        {"LLM_TIMEOUT": "0"},
        {"KAEL_REASONING_EFFORT": "invalid"},
        {"KAEL_RE_BLOCKED_CIDRS": "not-json"},
        {"TAVILY_INCLUDE_ANSWER": "private-invalid-value"},
        {"LLM_API_KEY": "a", "OPENAI_API_KEY": "b"},
        {"INVALID-NAME": "value"},
        {"CUSTOM_SETTING": "invalid\x00value"},
    ],
)
def test_invalid_changes_do_not_write_or_change_live_values(changes: dict[str, str]) -> None:
    path = Path("config.json")
    original = json.dumps({"env": {"KAEL_LLM": "openrouter/original"}})
    path.write_text(original, encoding="utf-8")
    loader.apply_config_override(path)
    settings = loader.load_settings()
    previous_env = dict(os.environ)
    with pytest.raises(ValueError) as exc:
        save_settings({"KAEL_LLM": "openrouter/changed", **changes})
    assert "private-invalid-value" not in str(exc.value)
    assert path.read_text() == original
    assert settings.llm.model == "openrouter/original"
    assert dict(os.environ) == previous_env


def test_failed_replace_leaves_disk_and_live_settings_intact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("config.json")
    original = json.dumps({"env": {"KAEL_LLM": "openrouter/original"}})
    path.write_text(original, encoding="utf-8")
    loader.apply_config_override(path)
    settings = loader.load_settings()
    previous_env = dict(os.environ)
    monkeypatch.setattr(
        "kael.config.loader.os.replace", MagicMock(side_effect=OSError("write failed"))
    )
    with pytest.raises(OSError, match="write failed"):
        save_settings({"KAEL_LLM": "openrouter/changed"})
    assert path.read_text() == original
    assert settings.llm.model == "openrouter/original"
    assert dict(os.environ) == previous_env
    assert not list(path.parent.glob(".kael-config-*"))


def test_corrupted_config_is_not_overwritten_by_save() -> None:
    save_settings({"KAEL_LLM": "openrouter/original"})
    settings = loader.load_settings()
    previous_env = dict(os.environ)
    path = loader.config_path()
    path.write_text("invalid json {", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        save_settings({"KAEL_LLM": "openrouter/changed"})
    assert path.read_text() == "invalid json {"
    assert settings.llm.model == "openrouter/original"
    assert dict(os.environ) == previous_env


def test_invalid_legacy_environment_is_not_migrated() -> None:
    Path(".env").write_text("CUSTOM_TOKEN='invalid\x00value'\n", encoding="utf-8")
    original_env = dict(os.environ)
    with pytest.raises(ValueError, match="Invalid environment variable"):
        loader.load_settings()
    assert not loader.config_path().exists()
    assert dict(os.environ) == original_env


def test_provider_snapshot_uses_current_credentials_and_endpoint() -> None:
    settings = loader.load_settings()
    settings.llm.api_key = "original"
    settings.llm.api_base = "https://old.example/api"
    first = KaelProvider().get_model("openrouter/test-model")
    settings.llm.api_key = "changed"
    settings.llm.api_base = "https://new.example/api"
    second = KaelProvider().get_model("openrouter/test-model")
    assert first.api_key == "original" and first.base_url == "https://old.example/api"
    assert second.api_key == "changed" and second.base_url == "https://new.example/api"


def test_clearing_defaults_removes_only_generated_provider_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import litellm

    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(
        litellm, "validate_environment", lambda **kwargs: {"missing_keys": ["OPENROUTER_API_KEY"]}
    )
    settings = loader.load_settings()
    settings.llm.model = "openrouter/test"
    settings.llm.api_key = "first"
    settings.llm.api_base = "https://old.example/api"
    configure_sdk_model_defaults(settings)
    assert os.environ["OPENROUTER_API_KEY"] == "first"
    settings.llm.api_key = "second"
    configure_sdk_model_defaults(settings)
    assert os.environ["OPENROUTER_API_KEY"] == "second"
    save_settings({"OPENROUTER_API_KEY": "second"})
    settings.llm.api_key = None
    settings.llm.api_base = None
    configure_sdk_model_defaults(settings)
    assert litellm.api_key is None and litellm.api_base is None
    assert os.environ["OPENROUTER_API_KEY"] == "second"


def test_tool_format_changes_are_saved_for_new_run() -> None:
    settings = loader.load_settings()
    settings.llm.model = "openrouter/new-model"
    coordinator = AgentCoordinator()
    coordinator.run_config = RunConfig(model="openai/gpt-test", model_settings=ModelSettings())
    coordinator.model_uses_chat_completions = False
    assert not coordinator.apply_model_settings(settings)
    assert coordinator.run_config.model == "openai/gpt-test"


def test_pending_endpoint_does_not_apply_openrouter_routing_to_active_openai_call() -> None:
    coordinator = AgentCoordinator()
    coordinator.run_config = RunConfig(model="openai/gpt-test", model_settings=ModelSettings())
    coordinator.model_uses_chat_completions = False
    coordinator.set_openrouter_provider({"only": ["deepinfra"]}, "https://openrouter.ai/api/v1")
    assert coordinator.run_config.model_settings.extra_body is None


async def test_settings_changed_during_sandbox_setup_reach_first_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kael.core import runner

    loader.load_settings().llm.model = "openrouter/first"

    async def create(scan_id: str, **kwargs: object) -> dict[str, object]:
        save_settings({"KAEL_LLM": "openrouter/updated-during-setup"})
        return {"client": MagicMock(), "session": MagicMock(), "mitm_client": MagicMock()}

    loop = AsyncMock(return_value=None)
    monkeypatch.setattr(runner.session_manager, "create_or_reuse", create)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda settings: None)
    monkeypatch.setattr(runner, "build_kael_agent", lambda **kwargs: Agent(name="test"))
    monkeypatch.setattr(runner, "run_agent_loop", loop)

    await runner.run_kael_scan(
        scan_config={}, scan_id="setup-settings", image="test-image", cleanup_on_exit=False
    )

    assert loop.call_args.kwargs["run_config"].model == "openrouter/updated-during-setup"


def test_new_lowercase_alias_updates_cached_setting() -> None:
    save_settings({"llm_api_key": "changed-key"})
    assert loader.load_settings().llm.api_key == "changed-key"
    assert loader.read_config()["env"]["LLM_API_KEY"] == "changed-key"


async def test_sdk_resolves_new_model_on_next_turn(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str | None, object]] = []
    model = MagicMock(spec=Model)

    class Provider(ModelProvider):
        def get_model(self, name: str | None) -> Model:
            async def respond(**kwargs: object) -> ModelResponse:
                calls.append((name, kwargs["model_settings"]))
                output = (
                    [
                        ResponseFunctionToolCall(
                            type="function_call",
                            call_id="switch",
                            name="switch_model",
                            arguments="{}",
                        )
                    ]
                    if len(calls) == 1
                    else [
                        ResponseOutputMessage(
                            id="done",
                            type="message",
                            role="assistant",
                            status="completed",
                            content=[
                                ResponseOutputText(type="output_text", text="done", annotations=[])
                            ],
                        )
                    ]
                )
                return ModelResponse(output=output, usage=Usage(), response_id=None)

            model.get_response = AsyncMock(side_effect=respond)
            return model

    settings = loader.load_settings()
    settings.llm.model = "openrouter/first"
    coordinator = AgentCoordinator()
    config = RunConfig(
        model=settings.llm.model,
        model_provider=Provider(),
        model_settings=ModelSettings(extra_body={"other": "preserved"}),
        tracing_disabled=True,
    )
    coordinator.run_config = config
    coordinator.model_uses_chat_completions = True
    monkeypatch.setattr("kael.config.models.KaelProvider", Provider)
    monkeypatch.setattr("kael.config.models.configure_sdk_model_defaults", lambda settings: None)

    @function_tool
    def switch_model() -> str:
        settings.llm.model = "openrouter/second"
        settings.llm.openrouter_provider = {"only": ["deepinfra"]}
        settings.llm.timeout = 42
        assert coordinator.apply_model_settings(settings)
        return "changed"

    result = await Runner.run(Agent(name="test", tools=[switch_model]), "begin", run_config=config)
    assert result.final_output == "done"
    assert [name for name, _ in calls] == ["openrouter/first", "openrouter/second"]
    assert calls[1][1].extra_body == {"other": "preserved", "provider": {"only": ["deepinfra"]}}
    assert calls[1][1].extra_args["timeout"] == 42


async def test_usage_keeps_model_of_in_progress_request(monkeypatch: pytest.MonkeyPatch) -> None:
    report = MagicMock()
    monkeypatch.setattr("kael.core.hooks.get_global_report_state", lambda: report)
    coordinator = AgentCoordinator()
    coordinator.run_config = RunConfig(model="openrouter/first")
    context = RunContextWrapper(context={"coordinator": coordinator, "agent_id": "root"})
    agent = Agent(name="test")
    hooks = ReportUsageHooks(model="openrouter/first")
    response = ModelResponse(output=[], usage=Usage(), response_id=None)
    await hooks.on_llm_start(context, agent, None, [])
    coordinator.run_config.model = "openrouter/second"
    await hooks.on_llm_end(context, agent, response)
    await hooks.on_llm_start(context, agent, None, [])
    await hooks.on_llm_end(context, agent, response)
    assert [call.kwargs["model"] for call in report.record_sdk_usage.call_args_list] == [
        "openrouter/first",
        "openrouter/second",
    ]
