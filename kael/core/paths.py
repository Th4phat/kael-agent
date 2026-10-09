"""Run directory path helpers."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path


RUNS_DIR_NAME = "kael_runs"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"
FOLDER_SENTINEL = ".kael_folder"

# A single path segment must consist only of these characters.  This is
# deliberately stricter than the filesystem allows: no spaces, no shell
# metacharacters, no leading dots (so we never collide with the
# .kael_folder sentinel, .state, .git, etc.).
_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


class InvalidSessionPathError(ValueError):
    """Raised when a run name or folder name fails path validation."""


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    return base / RUNS_DIR_NAME / run_name


def runtime_state_dir(run_dir: Path) -> Path:
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME


def target_slug(targets: Iterable[object]) -> str | None:
    """Identify the exact target set without merging normalized names."""
    value_keys = {
        "repository": "target_repo",
        "local_code": "target_path",
        "malware_sample": "target_file",
        "web_application": "target_url",
        "ip_address": "target_ip",
    }
    identities: set[tuple[str, str]] = set()
    for target in targets:
        if not isinstance(target, dict):
            return None
        target_type = str(target.get("type") or "unknown")
        details = target.get("details") or {}
        key = value_keys.get(target_type)
        value = details.get(key) if key and isinstance(details, dict) else None
        value = value or target.get("value") or target.get("workspace_path")
        if not value or not str(value).strip():
            return None
        identities.add((target_type, str(value)))
    if not identities:
        return None

    ordered = sorted(identities)
    payload = json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
    label = re.sub(r"[^a-z0-9]+", "-", ordered[0][1].lower()).strip("-")[:40] or "target"
    return f"{label}-{digest}"


def memory_dir_for(slug: str) -> Path:
    """Return the cross-run memory directory for a target slug."""
    return Path.home() / ".kael" / "memory" / slug


def runs_root(*, cwd: Path | None = None) -> Path:
    """Return the ``kael_runs/`` root directory (does not create it)."""
    return (cwd or Path.cwd()) / RUNS_DIR_NAME


def _validate_segment(segment: str, *, role: str) -> str:
    if not segment:
        raise InvalidSessionPathError(f"{role} path segment cannot be empty")
    if segment in {".", ".."}:
        raise InvalidSessionPathError(f"{role} path segment cannot be '.' or '..'")
    if segment.startswith(".") and len(segment) > 1:
        # Reject ".kael_folder", ".state", ".git", etc. so user-supplied
        # names never collide with internal markers.
        raise InvalidSessionPathError(
            f"{role} path segment cannot start with '.': {segment!r}",
        )
    if not _SEGMENT_PATTERN.match(segment):
        raise InvalidSessionPathError(
            f"{role} path segment contains invalid characters: {segment!r}. "
            "Allowed: letters, digits, '.', '_', '-'",
        )
    return segment


def validate_session_path(name: str) -> str:
    """Validate a slash-separated session/folder path.

    Each segment is checked individually; the full path may contain
    forward slashes to express folder nesting (e.g. ``acme/api``).
    The path is relative to the ``kael_runs/`` root — it must not be
    absolute and must not contain ``..`` segments. Returns the same
    string on success so callers can chain.
    """
    if not isinstance(name, str) or not name:
        raise InvalidSessionPathError("session path must be a non-empty string")
    if name != name.strip():
        raise InvalidSessionPathError("session path cannot have leading or trailing whitespace")
    if name.startswith(("/", "~")):
        raise InvalidSessionPathError("session path must be relative to kael_runs/")
    if "\\" in name:
        raise InvalidSessionPathError("session path cannot contain backslashes")
    parts = name.split("/")
    for part in parts:
        _validate_segment(part, role="session")
    return name


def is_run_dir(path: Path) -> bool:
    """True iff ``path`` looks like a kael run directory (has ``run.json``)."""
    return path.is_dir() and (path / RUN_RECORD_FILENAME).is_file()


def is_folder_dir(path: Path) -> bool:
    """True iff ``path`` looks like a kael folder directory.

    A folder is either explicitly marked with the ``.kael_folder``
    sentinel, or is a directory containing at least one sub-entry and
    no ``run.json`` (i.e. a folder the user has populated with runs or
    sub-folders). This second branch is the disambiguation between
    "folder" and "run dir whose runner crashed before writing
    ``run.json``" — we only treat the latter as a folder if the user
    has actually put something under it.
    """
    if not path.is_dir():
        return False
    if (path / FOLDER_SENTINEL).exists():
        return True
    if (path / RUN_RECORD_FILENAME).is_file():
        return False
    try:
        return any(path.iterdir())
    except OSError:
        return False
