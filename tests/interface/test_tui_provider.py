"""Provider changes through the TUI and the shared live run configuration."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from agents import Agent, RunConfig, Runner, function_tool
from agents.items import ModelResponse
from agents.model_settings import ModelSettings
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)
from textual.widgets import Input, Label

from kael.config import load_settings, loader
from kael.core.inputs import make_model_settings
from kael.interface.tui.app import KaelTUIApp
from kael.interface.tui.settings import SettingsScreen


@pytest.fixture
def app(monkeypatch: pytest.MonkeyPatch) -> KaelTUIApp:
    model = "openrouter/meta-llama/llama-3.3-70b-instruct"
    monkeypatch.setenv("KAEL_LLM", model)
    monkeypatch.setattr(KaelTUIApp, "_setup_cleanup_handlers", lambda self: None)
    instance = KaelTUIApp(
        argparse.Namespace(run_name="test-provider", targets_info=[], instruction="")
    )
    instance.coordinator.run_config = RunConfig(
        model=model, model_settings=make_model_settings(None, model_name=model)
    )
    return instance


@pytest.mark.parametrize(
    ("value", "provider"),
    [
        ("deepinfra", {"only": ["deepinfra"]}),
        ("", None),
        ('{"order":["deepinfra","together"]}', {"order": ["deepinfra", "together"]}),
    ],
)
async def test_apply_changes_live_routing(
    app: KaelTUIApp, value: str, provider: dict[str, Any] | None
) -> None:
    llm = load_settings().llm
    llm.openrouter_provider = {"only": ["openai"]}
    app.coordinator.set_openrouter_provider(llm.openrouter_provider)
    async with app.run_test(size=(90, 30)) as pilot:
        app._scan_loop = asyncio.get_running_loop()
        await pilot.press("f6")
        assert isinstance(app.screen, SettingsScreen)
        assert app.screen.selected_key == "KAEL_OPENROUTER_PROVIDER"
        field = app.screen.query_one("#setting_value", Input)
        assert json.loads(field.value) == {"only": ["openai"]}
        assert field.has_focus
        field.value = value
        await pilot.click("#settings_save")
        await pilot.pause()

        assert not isinstance(app.screen, SettingsScreen)
        assert load_settings().llm.openrouter_provider == provider
        assert loader.read_config()["env"]["KAEL_OPENROUTER_PROVIDER"] == provider
        config = app.coordinator.run_config
        assert config is not None and config.model_settings is not None
        assert config.model_settings.extra_body == ({"provider": provider} if provider else None)
        if provider and "only" in provider:
            assert "provider: deepinfra" in app.sub_title


@pytest.mark.parametrize("cancel", ["escape", "button"])
async def test_cancel_keeps_existing_routing(app: KaelTUIApp, cancel: str) -> None:
    original = {"order": ["deepinfra"], "allow_fallbacks": False}
    load_settings().llm.openrouter_provider = original
    async with app.run_test(size=(90, 30)) as pilot:
        await pilot.press("f6")
        field = app.screen.query_one("#setting_value", Input)
        assert json.loads(field.value) == original
        field.value = "together"
        if cancel == "escape":
            await pilot.press("escape")
        else:
            await pilot.click("#settings_cancel")
        assert not isinstance(app.screen, SettingsScreen)
        assert load_settings().llm.openrouter_provider == original


@pytest.mark.parametrize("value", ['{"only":', '["deepinfra"]'])
async def test_invalid_routing_stays_in_dialog(app: KaelTUIApp, value: str) -> None:
    async with app.run_test(size=(90, 30)) as pilot:
        await pilot.press("f6")
        app.screen.query_one("#setting_value", Input).value = value
        await pilot.press("enter")
        assert isinstance(app.screen, SettingsScreen)
        error = app.screen.query_one("#settings_error", Label)
        assert error.display
        assert "KAEL_OPENROUTER_PROVIDER" in str(error.render())
        assert load_settings().llm.openrouter_provider is None


async def test_command_palette_opens_provider_dialog(app: KaelTUIApp) -> None:
    async with app.run_test(size=(90, 30)) as pilot:
        await pilot.press("ctrl+p")
        await pilot.press(*"Change OpenRouter provider")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)


@pytest.mark.parametrize("size", [(120, 40), (60, 24), (40, 18)])
@pytest.mark.parametrize("theme", ["kael", "textual-light"])
async def test_provider_dialog_keyboard_and_layout(
    app: KaelTUIApp, size: tuple[int, int], theme: str
) -> None:
    async with app.run_test(size=size) as pilot:
        app.theme = theme
        await pilot.press("f6")
        dialog = app.screen.query_one("#settings_dialog")
        assert 0 <= dialog.region.x < dialog.region.right <= size[0]
        assert 0 <= dialog.region.y < dialog.region.bottom <= size[1]
        await pilot.press(*"deepinfra", "ctrl+s")
        await pilot.pause()
        assert load_settings().llm.openrouter_provider == {"only": ["deepinfra"]}
        assert loader.read_config()["env"]["KAEL_OPENROUTER_PROVIDER"] == {"only": ["deepinfra"]}
        await pilot.press("f6", "escape")
        assert not isinstance(app.screen, SettingsScreen)


def test_changing_provider_preserves_other_request_options(app: KaelTUIApp) -> None:
    config = app.coordinator.run_config
    assert config is not None
    config.model_settings = ModelSettings(
        extra_body={"other": "value", "provider": {"only": ["a"]}}
    )
    app.coordinator.set_openrouter_provider({"only": ["deepinfra"]})
    assert config.model_settings.extra_body == {
        "other": "value",
        "provider": {"only": ["deepinfra"]},
    }
    app.coordinator.set_openrouter_provider(None)
    assert config.model_settings.extra_body == {"other": "value"}


async def test_running_sdk_uses_changed_provider_on_next_call(app: KaelTUIApp) -> None:
    bodies = []
    outputs = [
        [
            ResponseFunctionToolCall(
                type="function_call", call_id="call-1", name="switch_provider", arguments="{}"
            )
        ],
        [
            ResponseOutputMessage(
                id="msg-1",
                type="message",
                role="assistant",
                status="completed",
                content=[ResponseOutputText(type="output_text", text="done", annotations=[])],
            )
        ],
    ]

    async def respond(**kwargs: Any) -> ModelResponse:
        bodies.append(kwargs["model_settings"].extra_body)
        return ModelResponse(output=outputs[len(bodies) - 1], usage=Usage(), response_id=None)

    model = MagicMock(spec=Model)
    model.get_response = AsyncMock(side_effect=respond)
    config = RunConfig(
        model=model,
        model_settings=ModelSettings(extra_body={"provider": {"only": ["openai"]}}),
        tracing_disabled=True,
    )
    app.coordinator.run_config = config

    @function_tool
    def switch_provider() -> str:
        app.coordinator.set_openrouter_provider(
            {"only": ["deepinfra"]}, "https://openrouter.ai/api/v1"
        )
        return "Provider changed"

    result = await Runner.run(
        Agent(name="test", tools=[switch_provider]), "Begin", run_config=config
    )
    assert result.final_output == "done"
    assert bodies == [
        {"provider": {"only": ["openai"]}},
        {"provider": {"only": ["deepinfra"]}},
    ]
