"""Keyboard, mouse, validation, and persistence checks for the settings editor."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from agents import RunConfig
from agents.model_settings import ModelSettings
from textual.widgets import Input, Label, OptionList

from kael.config import load_settings, loader
from kael.interface.tui.app import KaelTUIApp
from kael.interface.tui.settings import SettingsScreen


@pytest.fixture
def app(monkeypatch: pytest.MonkeyPatch) -> KaelTUIApp:
    monkeypatch.setenv("KAEL_LLM", "openrouter/current-model")
    monkeypatch.setattr(KaelTUIApp, "_setup_cleanup_handlers", lambda self: None)
    instance = KaelTUIApp(
        argparse.Namespace(run_name="settings-test", targets_info=[], instruction="")
    )
    instance.coordinator.run_config = RunConfig(
        model=load_settings().llm.model,
        model_settings=ModelSettings(extra_body={"other": "preserved"}),
    )
    instance.coordinator.model_uses_chat_completions = True
    return instance


async def test_f7_changes_and_persists_model_for_live_agents(app: KaelTUIApp) -> None:
    async with app.run_test(size=(100, 36)) as pilot:
        app._scan_loop = asyncio.get_running_loop()
        await pilot.press("f7")
        assert isinstance(app.screen, SettingsScreen)
        field = app.screen.query_one("#setting_value", Input)
        assert field.has_focus and field.value == "openrouter/current-model"
        field.value = "openrouter/changed-model"
        await pilot.press("enter")
        await pilot.pause()
        assert not isinstance(app.screen, SettingsScreen)
        assert load_settings().llm.model == "openrouter/changed-model"
        config = app.coordinator.run_config
        assert config is not None and config.model == "openrouter/changed-model"
        assert config.model_settings.extra_body == {"other": "preserved"}
        assert loader.read_config()["env"]["KAEL_LLM"] == "openrouter/changed-model"
        assert not Path(".env").exists()
        assert "openrouter/changed-model" in app.sub_title


async def test_settings_support_multiple_typed_edits_and_search(app: KaelTUIApp) -> None:
    changes = {
        "TAVILY_INCLUDE_ANSWER": "false",
        "KAEL_RE_BLOCKED_CIDRS": '["10.0.0.0/8"]',
        "KAEL_RUNTIME_BACKEND": "podman",
    }
    async with app.run_test(size=(100, 36)) as pilot:
        await pilot.press("f8")
        for name, value in changes.items():
            await pilot.press("ctrl+f")
            app.screen.query_one("#settings_filter", Input).value = name
            await pilot.pause()
            await pilot.press("enter")
            assert app.screen.selected_key == name
            app.screen.query_one("#setting_value", Input).value = value
            await pilot.pause()
        await pilot.click("#settings_save")
        await pilot.pause()
        assert not isinstance(app.screen, SettingsScreen)
        settings = load_settings()
        assert settings.integrations.tavily_include_answer is False
        assert settings.reverse_engineering.re_blocked_cidrs == ["10.0.0.0/8"]
        assert settings.runtime.backend == "podman"
        assert loader.read_config()["env"] == {
            "TAVILY_INCLUDE_ANSWER": False,
            "KAEL_RE_BLOCKED_CIDRS": ["10.0.0.0/8"],
            "KAEL_RUNTIME_BACKEND": "podman",
        }


@pytest.mark.parametrize("size", [(100, 36), (40, 18)])
@pytest.mark.parametrize("theme", ["kael", "textual-light"])
async def test_notes_scope_is_searchable_validated_and_saved(
    app: KaelTUIApp, size: tuple[int, int], theme: str
) -> None:
    async with app.run_test(size=size) as pilot:
        app.theme = theme
        await pilot.press("f8")
        app.screen.query_one("#settings_filter", Input).value = "notes scope"
        await pilot.pause()
        await pilot.press("enter")
        assert app.screen.selected_key == "KAEL_MEMORY_SCOPE"
        field = app.screen.query_one("#setting_value", Input)
        assert field.value == "agent"
        description = str(app.screen.query_one("#setting_description", Label).render())
        assert "Used on a new run." in description
        assert "Used on the next request" not in description
        dialog = app.screen.query_one("#settings_dialog")
        assert 0 <= dialog.region.x < dialog.region.right <= size[0]
        assert 0 <= dialog.region.y < dialog.region.bottom <= size[1]

        field.value = "global"
        await pilot.press("enter")
        assert isinstance(app.screen, SettingsScreen)
        assert app.screen.query_one("#settings_error", Label).display
        assert load_settings().memory.scope == "agent"
        assert not loader.config_path().exists()

        field.value = "target"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert not isinstance(app.screen, SettingsScreen)
        assert loader.read_config()["env"]["KAEL_MEMORY_SCOPE"] == "target"
        loader._cached = None
        assert load_settings().memory.scope == "target"


async def test_f8_configures_model_provider_and_key_in_selected_file(
    app: KaelTUIApp, tmp_path: Path
) -> None:
    config = tmp_path / "profile.json"
    config.write_text('{"env": {"CUSTOM_EXISTING": "keep"}}', encoding="utf-8")
    loader.apply_config_override(config)
    async with app.run_test(size=(100, 36)) as pilot:
        await pilot.press("f8")
        assert str(config) in str(app.screen.query_one("#settings_path", Label).render())
        for search, name, value in (
            ("model", "KAEL_LLM", "openrouter/configured"),
            ("openrouter provider", "KAEL_OPENROUTER_PROVIDER", "deepinfra"),
            ("LLM_API_KEY", "LLM_API_KEY", "saved-secret"),
        ):
            await pilot.press("ctrl+f")
            app.screen.query_one("#settings_filter", Input).value = search
            await pilot.pause()
            await pilot.press("enter")
            assert app.screen.selected_key == name
            field = app.screen.query_one("#setting_value", Input)
            assert field.password == (name == "LLM_API_KEY")
            field.value = value
            await pilot.pause()
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert not isinstance(app.screen, SettingsScreen)
        assert loader.read_config()["env"] == {
            "CUSTOM_EXISTING": "keep",
            "KAEL_LLM": "openrouter/configured",
            "KAEL_OPENROUTER_PROVIDER": {"only": ["deepinfra"]},
            "LLM_API_KEY": "saved-secret",
        }
        assert not Path(".env").exists()
        assert not loader._DEFAULT_PATH.exists()
        loader._cached = None
        settings = load_settings()
        assert settings.llm.model == "openrouter/configured"
        assert settings.llm.openrouter_provider == {"only": ["deepinfra"]}
        assert settings.llm.api_key == "saved-secret"


async def test_secret_values_are_masked_in_rendered_ui(app: KaelTUIApp) -> None:
    load_settings().llm.api_key = "secret-not-for-screenshot"
    async with app.run_test(size=(100, 36)) as pilot:
        app.action_edit_settings("LLM_API_KEY")
        await pilot.pause()
        field = app.screen.query_one("#setting_value", Input)
        assert field.password and field.value == "secret-not-for-screenshot"
        assert "secret-not-for-screenshot" not in app.export_screenshot()
        await pilot.press("escape")


async def test_aliases_share_unsaved_edits(app: KaelTUIApp) -> None:
    async with app.run_test(size=(100, 36)) as pilot:
        app.action_edit_settings("LLM_API_KEY")
        await pilot.pause()
        app.screen.query_one("#setting_value", Input).value = "first-edit"
        await pilot.press("ctrl+f")
        app.screen.query_one("#settings_filter", Input).value = "OPENAI_API_KEY"
        await pilot.pause()
        await pilot.press("enter")
        field = app.screen.query_one("#setting_value", Input)
        assert field.value == "first-edit"
        field.value = "final-edit"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert load_settings().llm.api_key == "final-edit"
        assert loader.read_config()["env"]["LLM_API_KEY"] == "final-edit"


@pytest.mark.parametrize("cancel", ["escape", "button"])
async def test_cancel_discards_changes_without_writing(app: KaelTUIApp, cancel: str) -> None:
    original = json.dumps({"env": {"KAEL_LLM": "openrouter/current-model"}})
    path = loader.config_path()
    path.parent.mkdir(parents=True)
    path.write_text(original, encoding="utf-8")
    async with app.run_test(size=(100, 36)) as pilot:
        await pilot.press("f7")
        app.screen.query_one("#setting_value", Input).value = "openrouter/discarded"
        if cancel == "escape":
            await pilot.press("escape")
        else:
            await pilot.click("#settings_cancel")
        assert not isinstance(app.screen, SettingsScreen)
        assert path.read_text() == original
        assert load_settings().llm.model == "openrouter/current-model"


async def test_invalid_value_stays_open_without_saving(app: KaelTUIApp) -> None:
    async with app.run_test(size=(100, 36)) as pilot:
        app.action_edit_settings("LLM_TIMEOUT")
        await pilot.pause()
        app.screen.query_one("#setting_value", Input).value = "invalid-private-value"
        await pilot.press("ctrl+s")
        assert isinstance(app.screen, SettingsScreen)
        label = app.screen.query_one("#settings_error", Label)
        assert label.display
        assert "LLM_TIMEOUT" in str(label.render())
        assert "invalid-private-value" not in str(label.render())
        assert load_settings().llm.timeout == 300
        assert not loader.config_path().exists()


async def test_reset_default_can_be_saved(app: KaelTUIApp) -> None:
    load_settings().llm.reasoning_effort = "low"
    async with app.run_test(size=(100, 36)) as pilot:
        app.action_edit_settings("KAEL_REASONING_EFFORT")
        await pilot.pause()
        await pilot.click("#setting_reset")
        assert app.screen.query_one("#setting_value", Input).value == "high"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert load_settings().llm.reasoning_effort == "high"
        assert loader.read_config()["env"]["KAEL_REASONING_EFFORT"] == "high"


async def test_add_variable_and_empty_search_state(app: KaelTUIApp) -> None:
    async with app.run_test(size=(100, 36)) as pilot:
        await pilot.press("f8")
        app.screen.query_one("#settings_filter", Input).value = "CUSTOM_API_TOKEN"
        await pilot.pause()
        assert app.screen.query_one("#settings_list", OptionList).get_option_at_index(0).disabled
        await pilot.click("#setting_add")
        field = app.screen.query_one("#setting_value", Input)
        assert field.has_focus and field.password
        field.value = "token-value"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert loader.read_config()["env"]["CUSTOM_API_TOKEN"] == "token-value"


async def test_failed_save_shows_error_and_keeps_editor_open(
    app: KaelTUIApp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "kael.interface.tui.settings.save_settings", MagicMock(side_effect=OSError("write failed"))
    )
    async with app.run_test(size=(100, 36)) as pilot:
        await pilot.press("f7")
        app.screen.query_one("#setting_value", Input).value = "openrouter/changed"
        await pilot.press("ctrl+s")
        assert isinstance(app.screen, SettingsScreen)
        assert "write failed" in str(app.screen.query_one("#settings_error", Label).render())
        assert load_settings().llm.model == "openrouter/current-model"


@pytest.mark.parametrize("command", ["Edit settings", "Change model"])
async def test_command_palette_opens_editor(app: KaelTUIApp, command: str) -> None:
    async with app.run_test(size=(100, 36)) as pilot:
        await pilot.press("ctrl+p")
        await pilot.press(*command)
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)


@pytest.mark.parametrize("size", [(120, 40), (60, 24), (40, 18)])
@pytest.mark.parametrize("theme", ["kael", "textual-light"])
async def test_settings_layout_and_keyboard_on_small_terminals(
    app: KaelTUIApp,
    size: tuple[int, int],
    theme: str,
) -> None:
    async with app.run_test(size=size) as pilot:
        app.theme = theme
        await pilot.press("f7")
        dialog = app.screen.query_one("#settings_dialog")
        assert 0 <= dialog.region.x < dialog.region.right <= size[0]
        assert 0 <= dialog.region.y < dialog.region.bottom <= size[1]
        save = app.screen.query_one("#settings_save")
        assert save.region.bottom <= size[1] and save.region.right <= size[0]
        field = app.screen.query_one("#setting_value", Input)
        assert field.has_focus
        field.value = "openrouter/keyboard-model"
        await pilot.press("tab", "tab", "tab", "enter")
        await pilot.pause()
        assert not isinstance(app.screen, SettingsScreen)
        assert load_settings().llm.model == "openrouter/keyboard-model"


@pytest.mark.parametrize("theme", ["kael", "textual-light"])
async def test_validation_error_and_controls_fit_small_terminal(
    app: KaelTUIApp, theme: str
) -> None:
    async with app.run_test(size=(40, 18)) as pilot:
        app.theme = theme
        app.action_edit_settings("LLM_TIMEOUT")
        await pilot.pause()
        app.screen.query_one("#setting_value", Input).value = "0"
        await pilot.press("ctrl+s")
        error = app.screen.query_one("#settings_error", Label)
        assert error.display and 0 <= error.region.y < error.region.bottom <= 18
        assert app.screen.query_one("#settings_save").region.bottom <= 18
        field = app.screen.query_one("#setting_value", Input)
        assert field.has_focus
        field.value = "42"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert load_settings().llm.timeout == 42


async def test_incompatible_model_keeps_active_route_and_shows_new_run_scope(
    app: KaelTUIApp,
) -> None:
    app.coordinator.model_uses_chat_completions = False
    app.coordinator.run_config.model = "openai/active"
    async with app.run_test(size=(100, 36)) as pilot:
        await pilot.press("f7")
        app.screen.query_one("#setting_value", Input).value = "openrouter/new"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert load_settings().llm.model == "openrouter/new"
        assert app.coordinator.run_config.model == "openai/active"
        assert "active model: openai/active" in app.sub_title
        assert loader.read_config()["env"]["KAEL_LLM"] == "openrouter/new"


async def test_no_model_allows_configuration_before_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(KaelTUIApp, "_setup_cleanup_handlers", lambda self: None)
    app = KaelTUIApp(argparse.Namespace(run_name="setup", targets_info=[], instruction="run task"))
    async with app.run_test(size=(100, 36)) as pilot:
        assert app._scan_thread is None
        await pilot.press("f7")
        assert isinstance(app.screen, SettingsScreen)
        app.screen.query_one("#setting_value", Input).value = "openrouter/configured"
        start = MagicMock()
        monkeypatch.setattr(app, "_start_scan_thread", start)
        await pilot.press("ctrl+s")
        await pilot.pause()
        start.assert_called_once()
