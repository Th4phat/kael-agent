"""Build and first-run policy for Kael's local sandbox image."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TextIO

from kael.config import load_settings
from kael.version import default_sandbox_image


AUTO_BUILD_ENV = "KAEL_AUTO_BUILD_SANDBOX"


class SandboxImageError(RuntimeError):
    """Raised when Kael cannot prepare the configured sandbox image."""


def find_source_root(start: Path | None = None) -> Path:
    """Find a source checkout containing the sandbox Dockerfile."""
    candidate = (start or Path(__file__)).resolve()
    for parent in (candidate, *candidate.parents):
        if (parent / "pyproject.toml").is_file() and (
            parent / "containers" / "Dockerfile"
        ).is_file():
            return parent
    raise SandboxImageError(
        "The sandbox can only be built from a Kael source checkout. "
        "Clone https://github.com/Th4phat/kael-agent and run `kael sandbox build`."
    )


def build_sandbox_image(
    *,
    image: str | None = None,
    force: bool = False,
    source_root: Path | None = None,
) -> str:
    """Build the configured sandbox image and return its tag."""
    settings = load_settings()
    backend = settings.runtime.backend.strip().lower()
    if backend not in {"docker", "podman"}:
        raise SandboxImageError(
            f"Unsupported KAEL_RUNTIME_BACKEND={backend!r}; expected 'docker' or 'podman'."
        )
    executable = shutil.which(backend)
    if executable is None:
        raise SandboxImageError(f"The {backend!r} command is not available in PATH.")

    root = find_source_root(source_root)
    target = image or settings.runtime.image
    command = [
        executable,
        "build",
    ]
    # Rootless Podman's default build network commonly cannot resolve DNS even
    # while the API daemon is healthy. Host networking keeps the documented
    # `kael sandbox build` path reliable without changing Docker behavior.
    if backend == "podman":
        command.extend(["--network", "host"])
    command.extend(
        [
            "--file",
            str(root / "containers" / "Dockerfile"),
            "--tag",
            target,
        ]
    )
    if force:
        command.append("--no-cache")
    command.append(str(root))

    print(f"Building {target} from {root}")
    try:
        completed = subprocess.run(command, check=False)  # noqa: S603
    except OSError as exc:
        raise SandboxImageError(f"Could not start {backend}: {exc}") from exc
    if completed.returncode != 0:
        raise SandboxImageError(f"Sandbox build failed with exit code {completed.returncode}.")
    print(f"Sandbox image ready: {target}")
    return target


def _env_opted_in() -> bool:
    value = os.environ.get(AUTO_BUILD_ENV, "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def should_build_missing_image(
    *,
    explicit: bool,
    interactive: bool | None = None,
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stdout,
) -> bool:
    """Resolve explicit/env/interactive consent for a first local build."""
    if explicit or _env_opted_in():
        return True
    if interactive is None:
        interactive = input_stream.isatty() and output_stream.isatty()
    if not interactive:
        return False

    output_stream.write(
        f"Kael needs to build {default_sandbox_image()} locally (this can take a while). "
        "Build it now? [y/N] "
    )
    output_stream.flush()
    answer = input_stream.readline().strip().lower()
    return answer in {"y", "yes"}


def missing_image_message(image: str) -> str:
    """Return actionable guidance for a declined or noninteractive build."""
    return (
        f"Required local sandbox image {image!r} is missing. Run "
        "`kael sandbox build`, pass `--build-sandbox` to the scan, or set "
        f"{AUTO_BUILD_ENV}=1."
    )
