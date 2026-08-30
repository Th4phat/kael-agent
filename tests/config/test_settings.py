"""Tests for the configuration loader and settings models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kael.config import load_settings, loader
from kael.config.settings import (
    IntegrationSettings,
    LlmSettings,
    RuntimeSettings,
    Settings,
)


class TestSettings:
    def test_default_settings_load(self) -> None:
        s = load_settings()
        assert isinstance(s, Settings)
        assert isinstance(s.llm, LlmSettings)
        assert isinstance(s.runtime, RuntimeSettings)
        assert isinstance(s.integrations, IntegrationSettings)

    def test_perplexity_api_key_picks_up_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PERPLEXITY_API_KEY", "pplx-test-key")
        loader._cached = None
        s = load_settings()
        assert s.integrations.perplexity_api_key == "pplx-test-key"
        loader._cached = None

    def test_tavily_api_key_picks_up_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAVILY_API_KEY", "tvly-test-key")
        monkeypatch.setenv("TAVILY_SEARCH_DEPTH", "basic")
        monkeypatch.setenv("TAVILY_MAX_RESULTS", "5")
        loader._cached = None
        s = load_settings()
        assert s.integrations.tavily_api_key == "tvly-test-key"
        assert s.integrations.tavily_search_depth == "basic"
        assert s.integrations.tavily_max_results == 5
        loader._cached = None

    def test_tavily_search_depth_validates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAVILY_SEARCH_DEPTH", "ultra-fast")
        loader._cached = None
        with pytest.raises(ValidationError):
            load_settings()
        loader._cached = None

    def test_settings_memoized(self) -> None:
        a = load_settings()
        b = load_settings()
        assert a is b
