"""Tests for the config loader's JSON-persistence and alias-handling paths.

The basic test_settings.py covers the happy path of env-var loading.
This file targets:

- apply_config_override (switching the JSON source)
- _read_json_overrides: malformed JSON, non-dict env block, config-file
  precedence, case-insensitive key matching
- _aliases_for: handling both string and AliasChoices validation aliases
- persist_current: writing env-block + chmod 0o600
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from kael.config import loader


class TestApplyConfigOverride:
    def test_override_switches_source(self, tmp_path: Path) -> None:
        target = tmp_path / "custom.json"
        target.write_text('{"env": {"KAEL_LLM": "anthropic/claude-3"}}', encoding="utf-8")
        loader.apply_config_override(target)
        # Loader now reads from target
        s = loader.load_settings()
        assert s.llm.model == "anthropic/claude-3"
        loader.apply_config_override(Path.home() / ".kael" / "cli-config.json")  # reset

    def test_override_in_cwd(self, tmp_path: Path) -> None:
        target = tmp_path / "override.json"
        target.write_text(
            '{"env": {"TAVILY_API_KEY": "tvly-override"}}',
            encoding="utf-8",
        )
        loader.apply_config_override(target)
        s = loader.load_settings()
        assert s.integrations.tavily_api_key == "tvly-override"
        loader.apply_config_override(Path.home() / ".kael" / "cli-config.json")

    def test_json_wins_over_dotenv(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text(
            "KAEL_IMAGE=kael-sandbox:dotenv\n",
            encoding="utf-8",
        )
        target = tmp_path / "override.json"
        target.write_text(
            '{"env": {"KAEL_IMAGE": "kael-sandbox:json"}}',
            encoding="utf-8",
        )
        loader.apply_config_override(target)
        try:
            assert loader.load_settings().runtime.image == "kael-sandbox:json"
        finally:
            loader.apply_config_override(Path.home() / ".kael" / "cli-config.json")


class TestReadJsonOverrides:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = loader._read_json_overrides(tmp_path / "missing.json")
        assert result == {}

    def test_malformed_json_is_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("not json {", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid JSON"):
            loader._read_json_overrides(f)

    def test_non_object_root_is_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "list.json"
        f.write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(ValueError, match="must contain an 'env' object"):
            loader._read_json_overrides(f)

    def test_env_block_must_be_object(self, tmp_path: Path) -> None:
        f = tmp_path / "bad_env.json"
        f.write_text('{"env": "not an object"}', encoding="utf-8")
        with pytest.raises(ValueError, match="must contain an 'env' object"):
            loader._read_json_overrides(f)

    def test_json_wins_over_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # JSON says PERPLEXITY_API_KEY=json-key, env says env-key
        f = tmp_path / "test.json"
        f.write_text('{"env": {"PERPLEXITY_API_KEY": "json-key"}}', encoding="utf-8")
        monkeypatch.setenv("PERPLEXITY_API_KEY", "env-key")
        result = loader._read_json_overrides(f)
        assert result["integrations"]["PERPLEXITY_API_KEY"] == "json-key"
        loader.apply_config_override(f)
        assert loader.load_settings().integrations.perplexity_api_key == "json-key"

    def test_json_loaded_when_env_not_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        f = tmp_path / "test.json"
        f.write_text('{"env": {"TAVILY_API_KEY": "json-key"}}', encoding="utf-8")
        result = loader._read_json_overrides(f)
        assert result["integrations"]["TAVILY_API_KEY"] == "json-key"

    def test_case_insensitive_key_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        f = tmp_path / "test.json"
        # Lowercase key in JSON
        f.write_text('{"env": {"tavily_api_key": "lower-key"}}', encoding="utf-8")
        result = loader._read_json_overrides(f)
        assert result["integrations"]["TAVILY_API_KEY"] == "lower-key"


class TestAliasesFor:
    def test_string_alias(self) -> None:
        # Use tavily_api_key (single string alias)
        tavily_finfo = type(loader.load_settings().integrations).model_fields["tavily_api_key"]
        aliases = loader._aliases_for(tavily_finfo)
        assert "TAVILY_API_KEY" in aliases

    def test_alias_choices(self) -> None:
        # LLM api_key has multiple aliases
        llm_cls = type(loader.load_settings().llm)
        api_key_finfo = llm_cls.model_fields["api_key"]
        aliases = loader._aliases_for(api_key_finfo)
        assert "LLM_API_KEY" in aliases
        assert "OPENAI_API_KEY" in aliases

    def test_no_alias_returns_empty(self) -> None:
        # Internal field with no alias
        from pydantic import Field
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class Dummy(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")
            x: int = Field(default=0)

        finfo = Dummy.model_fields["x"]
        assert loader._aliases_for(finfo) == []


class TestPersistCurrent:
    def test_persist_writes_env_block(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PERPLEXITY_API_KEY", "persist-key")
        loader._cached = None
        # Override target to a tmp file
        target = tmp_path / "persist.json"
        loader.apply_config_override(target)
        try:
            loader.persist_current()
            data = json.loads(target.read_text(encoding="utf-8"))
            assert "env" in data
            assert data["env"]["PERPLEXITY_API_KEY"] == "persist-key"
        finally:
            loader.apply_config_override(Path.home() / ".kael" / "cli-config.json")
            loader._cached = None


def test_dotenv_import_is_once_and_survives_removal_and_cwd_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy = tmp_path / ".env"
    original = (
        "# legacy setup\nKAEL_LLM=openrouter/imported\n"
        "KAEL_OPENROUTER_PROVIDER=deepinfra\n"
        "BROWSER_BACKEND=lightpanda\nCUSTOM_TOKEN='literal-${VALUE}'\n"
    )
    legacy.write_text(original, encoding="utf-8")
    settings = loader.load_settings()
    path = loader.config_path()
    assert settings.llm.model == "openrouter/imported"
    assert settings.llm.openrouter_provider == {"only": ["deepinfra"]}
    assert loader.read_config()["env"]["CUSTOM_TOKEN"] == "literal-${VALUE}"
    assert os.environ["BROWSER_BACKEND"] == "lightpanda"
    assert legacy.read_text() == original
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    legacy.write_text("KAEL_LLM=openrouter/ignored\nCUSTOM_NEW=ignored\n", encoding="utf-8")
    loader._cached = None
    assert loader.load_settings().llm.model == "openrouter/imported"
    assert "CUSTOM_NEW" not in loader.read_config()["env"]
    legacy.unlink()
    other = tmp_path / "other-project"
    other.mkdir()
    monkeypatch.chdir(other)
    loader._cached = None
    assert loader.load_settings().llm.model == "openrouter/imported"
    assert loader.config_path() == path


def test_file_values_override_shell_aliases_and_empty_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KAEL_LLM", "openrouter/shell-model")
    monkeypatch.setenv("LLM_API_KEY", "shell-key")
    monkeypatch.setenv("OPENAI_API_KEY", "shell-alias")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://shell.example/v1")
    monkeypatch.setenv("TAVILY_INCLUDE_ANSWER", "true")
    monkeypatch.setenv("KAEL_RE_BLOCKED_CIDRS", "invalid-shadowed-json")
    config = tmp_path / "selected.json"
    config.write_text(
        json.dumps(
            {
                "env": {
                    "KAEL_LLM": "openrouter/file-model",
                    "OPENAI_API_KEY": None,
                    "LLM_API_BASE": "https://file.example/v1",
                    "TAVILY_INCLUDE_ANSWER": False,
                    "BROWSER_BACKEND": "lightpanda",
                    "KAEL_RE_BLOCKED_CIDRS": ["10.0.0.0/8"],
                }
            }
        ),
        encoding="utf-8",
    )
    loader.apply_config_override(config)
    settings = loader.load_settings()
    assert settings.llm.model == "openrouter/file-model"
    assert settings.llm.api_key is None
    assert settings.llm.api_base == "https://file.example/v1"
    assert settings.integrations.tavily_include_answer is False
    assert settings.reverse_engineering.re_blocked_cidrs == ["10.0.0.0/8"]
    assert os.environ["OPENAI_BASE_URL"] == "https://file.example/v1"
    assert os.environ["BROWSER_BACKEND"] == "lightpanda"


def test_changing_config_removes_previous_values_and_restores_shell_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KAEL_LLM", "openrouter/shell-model")
    monkeypatch.setenv("BROWSER_BACKEND", "shell-browser")
    first = tmp_path / "first.json"
    first.write_text(
        json.dumps(
            {
                "env": {
                    "KAEL_LLM": "openrouter/first",
                    "BROWSER_BACKEND": "lightpanda",
                    "CONFIG_ONLY_TOKEN": "first-token",
                }
            }
        ),
        encoding="utf-8",
    )
    second = tmp_path / "second.json"
    second.write_text('{"env": {"LLM_TIMEOUT": 42}}', encoding="utf-8")
    loader.apply_config_override(first)
    assert loader.load_settings().llm.model == "openrouter/first"
    assert os.environ["CONFIG_ONLY_TOKEN"] == "first-token"
    loader.apply_config_override(second)
    settings = loader.load_settings()
    assert settings.llm.model == "openrouter/shell-model"
    assert settings.llm.timeout == 42
    assert os.environ["BROWSER_BACKEND"] == "shell-browser"
    assert "CONFIG_ONLY_TOKEN" not in os.environ


def test_startup_persistence_preserves_file_choices_extras_and_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "selected.json"
    config.write_text(
        json.dumps(
            {
                "note": "keep metadata",
                "env": {
                    "KAEL_LLM": "openrouter/file",
                    "CUSTOM_TOKEN": "saved",
                    "LLM_API_KEY": None,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("KAEL_LLM", "openrouter/shell")
    monkeypatch.setenv("LLM_API_KEY", "shell-key")
    loader.apply_config_override(config)
    loader.persist_current()
    data = loader.read_config()
    assert data["note"] == "keep metadata"
    assert data["env"]["KAEL_LLM"] == "openrouter/file"
    assert data["env"]["CUSTOM_TOKEN"] == "saved"
    assert data["env"]["LLM_API_KEY"] is None


def test_persist_skips_unset_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    loader.apply_config_override(tmp_path / "persist.json")
    loader.persist_current()
    data = loader.read_config()
    assert "PERPLEXITY_API_KEY" not in data["env"]
    assert "TAVILY_API_KEY" not in data["env"]


def test_persist_handles_alias_choices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_API_KEY", "alias-key")
    loader.apply_config_override(tmp_path / "persist.json")
    loader.persist_current()
    assert loader.read_config()["env"]["LLM_API_KEY"] == "alias-key"
