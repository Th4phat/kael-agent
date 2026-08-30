"""Single source of truth for Kael's public versioned identifiers."""

from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


DIST_NAME = "kael-agent"
SOURCE_VERSION = "0.1.0"


def get_version() -> str:
    """Return installed distribution metadata, or the source-tree version."""
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if pyproject.is_file():
        try:
            declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
        except (KeyError, OSError, tomllib.TOMLDecodeError):
            pass
        else:
            if isinstance(declared, str) and declared:
                return declared
    try:
        return version(DIST_NAME)
    except PackageNotFoundError:
        return SOURCE_VERSION


def default_sandbox_image() -> str:
    """Return the local sandbox tag paired with this Kael version."""
    return f"kael-sandbox:{get_version()}"
