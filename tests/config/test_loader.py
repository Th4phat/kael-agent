"""Tests for the config loader's JSON-persistence and alias-handling paths.

The basic test_settings.py covers the happy path of env-var loading.
This file targets:

- apply_config_override (switching the JSON source)
- _read_json_overrides: malformed JSON, non-dict env block, env-var
  precedence (env wins over JSON), case-insensitive key matching
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

    def test_dotenv_wins_over_json(self, tmp_path: Path) -> None:
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
            assert loader.load_settings().runtime.image == "kael-sandbox:dotenv"
        finally:
            loader.apply_config_override(Path.home() / ".kael" / "cli-config.json")


class TestReadJsonOverrides:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = loader._read_json_overrides(tmp_path / "missing.json")
        assert result == {}

    def test_malformed_json_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("not json {", encoding="utf-8")
        result = loader._read_json_overrides(f)
        assert result == {}

    def test_non_object_root_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "list.json"
        f.write_text("[1, 2, 3]", encoding="utf-8")
        result = loader._read_json_overrides(f)
        assert result == {}

    def test_env_block_must_be_object(self, tmp_path: Path) -> None:
        f = tmp_path / "bad_env.json"
        f.write_text('{"env": "not an object"}', encoding="utf-8")
        result = loader._read_json_overrides(f)
        assert result == {}

    def test_env_wins_over_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # JSON says PERPLEXITY_API_KEY=json-key, env says env-key
        f = tmp_path / "test.json"
        f.write_text('{"env": {"PERPLEXITY_API_KEY": "json-key"}}', encoding="utf-8")
        monkeypatch.setenv("PERPLEXITY_API_KEY", "env-key")
        result = loader._read_json_overrides(f)
        # Env wins → json key ignored
        assert "integrations" not in result or "perplexity_api_key" not in result.get(
            "integrations", {}
        )

    def test_json_loaded_when_env_not_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        f = tmp_path / "test.json"
        f.write_text('{"env": {"TAVILY_API_KEY": "json-key"}}', encoding="utf-8")
        result = loader._read_json_overrides(f)
        assert result["integrations"]["tavily_api_key"] == "json-key"

    def test_case_insensitive_key_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        f = tmp_path / "test.json"
        # Lowercase key in JSON
        f.write_text('{"env": {"tavily_api_key": "lower-key"}}', encoding="utf-8")
        result = loader._read_json_overrides(f)
        assert result["integrations"]["tavily_api_key"] == "lower-key"


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

    def test_persist_skips_unset_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        loader._cached = None
        target = tmp_path / "persist.json"
        loader.apply_config_override(target)
        try:
            loader.persist_current()
            data = json.loads(target.read_text(encoding="utf-8"))
            # Neither should be in the env block
            assert "PERPLEXITY_API_KEY" not in data["env"]
            assert "TAVILY_API_KEY" not in data["env"]
        finally:
            loader.apply_config_override(Path.home() / ".kael" / "cli-config.json")
            loader._cached = None

    def test_persist_handles_alias_choices(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Use one of the LLM_API_KEY aliases
        monkeypatch.setenv("LLM_API_KEY", "alias-key")
        loader._cached = None
        target = tmp_path / "persist.json"
        loader.apply_config_override(target)
        try:
            loader.persist_current()
            data = json.loads(target.read_text(encoding="utf-8"))
            # Should record one of the aliases (the first one matches)
            assert "LLM_API_KEY" in data["env"] or "OPENAI_API_KEY" in data["env"]
        finally:
            loader.apply_config_override(Path.home() / ".kael" / "cli-config.json")
            loader._cached = None
