"""Shared, hermetic pytest configuration."""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from kael.config import loader
from kael.report.state import ReportState


@pytest.fixture(autouse=True)
def isolate_process_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> Iterator[None]:
    """Keep developer dotenv/config values out of the test process."""
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
    for key in list(os.environ):
        if key.startswith("KAEL_") or key in {
            "LLM_API_KEY",
            "LLM_API_BASE",
            "OPENAI_API_KEY",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
            "PERPLEXITY_API_KEY",
            "TAVILY_API_KEY",
            "VISION_LLM_API_KEY",
            "VISION_LLM_API_BASE",
        }:
            monkeypatch.delenv(key, raising=False)

    for key, value in preserved.items():
        monkeypatch.setenv(key, value)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(loader, "_DEFAULT_PATH", tmp_path / ".kael" / "cli-config.json")
    loader._override = None
    loader._cached = None
    yield
    loader._override = None
    loader._cached = None


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
