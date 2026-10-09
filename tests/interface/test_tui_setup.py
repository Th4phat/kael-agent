"""An unconfigured interactive launch must reach the settings editor."""

from importlib import import_module
from unittest.mock import AsyncMock, MagicMock

import pytest


entrypoint = import_module("kael.interface.main")


def test_interactive_launch_without_model_skips_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["kael"])
    run_tui = AsyncMock()
    monkeypatch.setattr("kael.interface.tui.run_tui", run_tui)
    monkeypatch.setattr("kael.report.state.get_global_report_state", lambda: None)
    monkeypatch.setattr(entrypoint, "display_completion_message", MagicMock())
    for name in (
        "check_docker_installed",
        "pull_docker_image",
        "validate_environment",
        "warm_up_llm",
    ):
        monkeypatch.setattr(
            entrypoint, name, MagicMock(side_effect=AssertionError("preflight before setup"))
        )

    entrypoint.main()

    run_tui.assert_awaited_once()
