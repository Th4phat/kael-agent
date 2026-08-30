"""Tests for the version-matched local sandbox lifecycle."""

from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from kael.runtime import sandbox_image
from kael.version import default_sandbox_image, get_version


def test_source_version_and_image_tag_match() -> None:
    assert get_version() == "0.1.0"
    assert default_sandbox_image() == "kael-sandbox:0.1.0"


def test_find_source_root_from_nested_path() -> None:
    root = Path(__file__).resolve().parents[2]
    assert sandbox_image.find_source_root(root / "kael" / "runtime") == root


def test_noninteractive_build_requires_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(sandbox_image.AUTO_BUILD_ENV, raising=False)
    assert not sandbox_image.should_build_missing_image(
        explicit=False,
        interactive=False,
    )


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_environment_can_opt_in(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(sandbox_image.AUTO_BUILD_ENV, value)
    assert sandbox_image.should_build_missing_image(explicit=False, interactive=False)


def test_interactive_prompt_accepts_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(sandbox_image.AUTO_BUILD_ENV, raising=False)
    output = io.StringIO()
    assert sandbox_image.should_build_missing_image(
        explicit=False,
        interactive=True,
        input_stream=io.StringIO("yes\n"),
        output_stream=output,
    )
    assert "kael-sandbox:0.1.0" in output.getvalue()


def test_build_uses_configured_backend_and_version_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).resolve().parents[2]
    settings = SimpleNamespace(
        runtime=SimpleNamespace(backend="docker", image=default_sandbox_image())
    )
    completed = SimpleNamespace(returncode=0)
    run = Mock(return_value=completed)
    monkeypatch.setattr(sandbox_image, "load_settings", lambda: settings)
    monkeypatch.setattr(sandbox_image.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(sandbox_image.subprocess, "run", run)

    result = sandbox_image.build_sandbox_image(source_root=root)

    assert result == "kael-sandbox:0.1.0"
    command = run.call_args.args[0]
    assert command[:2] == ["/usr/bin/docker", "build"]
    assert command[-1] == str(root)
    assert command[command.index("--tag") + 1] == result


def test_podman_build_uses_host_network(monkeypatch: pytest.MonkeyPatch) -> None:
    root = Path(__file__).resolve().parents[2]
    settings = SimpleNamespace(
        runtime=SimpleNamespace(backend="podman", image=default_sandbox_image())
    )
    run = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(sandbox_image, "load_settings", lambda: settings)
    monkeypatch.setattr(sandbox_image.shutil, "which", lambda _name: "/usr/bin/podman")
    monkeypatch.setattr(sandbox_image.subprocess, "run", run)

    sandbox_image.build_sandbox_image(source_root=root)

    command = run.call_args.args[0]
    assert command[:4] == ["/usr/bin/podman", "build", "--network", "host"]


def test_build_failure_is_actionable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).resolve().parents[2]
    settings = SimpleNamespace(
        runtime=SimpleNamespace(backend="docker", image=default_sandbox_image())
    )
    monkeypatch.setattr(sandbox_image, "load_settings", lambda: settings)
    monkeypatch.setattr(sandbox_image.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        sandbox_image.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=17),
    )

    with pytest.raises(sandbox_image.SandboxImageError, match="exit code 17"):
        sandbox_image.build_sandbox_image(source_root=root)


def test_scan_parser_accepts_documented_build_flag() -> None:
    from kael.interface.main import _build_scan_namespace

    args = _build_scan_namespace([".", "non-interactive", "--build-sandbox"])
    assert args.build_sandbox is True
    assert args.non_interactive is True
