"""Tests for kael.utils.resource_paths."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from kael.utils.resource_paths import get_kael_resource_path


class TestGetKaelResourcePath:
    def test_returns_path_under_kael_package(self) -> None:
        result = get_kael_resource_path("skills")
        assert result == Path(__file__).resolve().parent.parent.parent / "kael" / "skills"

    def test_joins_multiple_parts(self) -> None:
        result = get_kael_resource_path("agents", "prompts", "system_prompt.jinja")
        assert (
            result
            == Path(__file__).resolve().parent.parent.parent
            / "kael"
            / "agents"
            / "prompts"
            / "system_prompt.jinja"
        )

    def test_handles_no_parts(self) -> None:
        result = get_kael_resource_path()
        assert result == Path(__file__).resolve().parent.parent.parent / "kael"

    def test_handles_frozen_path(self, tmp_path: Path) -> None:
        """When running under PyInstaller (``sys._MEIPASS``), resources
        live under ``<frozen>/kael``."""
        frozen_kael = tmp_path / "kael"
        frozen_kael.mkdir()
        (frozen_kael / "prompts").mkdir()
        with patch.object(sys, "_MEIPASS", str(tmp_path), create=True):
            result = get_kael_resource_path("prompts")
        assert result == frozen_kael / "prompts"

    def test_frozen_path_skips_if_kael_dir_missing(self, tmp_path: Path) -> None:
        """If ``<frozen>/kael`` doesn't exist (mislocated resources),
        fall back to the package-relative path."""
        with patch.object(sys, "_MEIPASS", str(tmp_path), create=True):
            result = get_kael_resource_path("prompts")
        assert result == Path(__file__).resolve().parent.parent.parent / "kael" / "prompts"
