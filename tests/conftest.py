"""Shared, hermetic pytest configuration."""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from kael.config import loader
from kael.config.settings import Settings
from kael.report.state import ReportState


@pytest.fixture(autouse=True)
def isolate_process_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> Iterator[None]:
    """Keep developer dotenv/config values out of the test process."""
    original_env = dict(os.environ)
    integration_runtime_keys = {
        "KAEL_CONTAINER_SOCKET",
        "KAEL_IMAGE",
        "KAEL_RUNTIME_BACKEND",
    }
    preserved = (
        {key: os.environ[key] for key in integration_runtime_keys if key in os.environ}
        if request.node.get_closest_marker("integration")
        else {}
    )
    settings_keys = {
        alias
        for section in Settings.model_fields.values()
        for info in section.annotation.model_fields.values()
        for alias in loader._aliases_for(info)
    } | {"BROWSER_BACKEND"}
    for key in list(os.environ):
        if key.startswith("KAEL_") or key.upper() in settings_keys:
            monkeypatch.delenv(key, raising=False)

    for key, value in preserved.items():
        monkeypatch.setenv(key, value)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(loader, "_DEFAULT_PATH", tmp_path / ".kael" / "cli-config.json")
    monkeypatch.setattr(loader, "_config_environment", {})
    loader._override = None
    loader._cached = None
    yield
    loader._restore_config_environment()
    loader._override = None
    loader._cached = None
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def report_state() -> ReportState:
    """Return an isolated report writer rooted in the per-test cwd."""
    return ReportState(run_name="test-run")


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """Expose the autouse fixture's isolated working directory."""
    return tmp_path


@pytest.fixture
def tmp_run_dir(workdir: Path) -> Path:
    """Create the run directory used by report hydration tests."""
    run_dir = workdir / "kael_runs" / "test-run"
    run_dir.mkdir(parents=True)
    return run_dir
