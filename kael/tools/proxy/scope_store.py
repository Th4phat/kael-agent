"""JSON-backed CRUD store for soft scope rules.

mitmproxy has no server-side scope concept (no per-flow filter rules on
the proxy itself), so the agent needs a place to keep allow/deny lists
across process restarts. This module is the single source of truth for
that store. The mitmproxy addon reads it on every ``request`` to tag
incoming flows with the matching scope id; the host SDK reads it to
answer ``scope_rules`` tool calls.

Storage layout::

    {
      "scopes": [
        {
          "id": "default",
          "name": "default",
          "allowlist": [],          # empty = allow all hosts
          "denylist": ["*.gif", ...]
        },
        ...
      ]
    }

Atomic writes: every mutation goes through a temp-file + ``os.replace``
to avoid leaving a half-written JSON behind if the process dies
mid-write (the addon runs inside the proxy event loop; a crash here is
not unusual).
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import threading
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Iterable


logger = logging.getLogger(__name__)


_DEFAULT_SCOPE_ID = "default"
_DEFAULT_SCOPE_NAME = "default"


@dataclass
class Scope:
    """Allow/deny rule set for grouping captured traffic."""

    id: str
    name: str
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Scope:
        return cls(
            id=str(payload.get("id") or uuid.uuid4()),
            name=str(payload.get("name") or "unnamed"),
            allowlist=[str(p) for p in payload.get("allowlist") or []],
            denylist=[str(p) for p in payload.get("denylist") or []],
        )


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a glob pattern (``*``, ``?``, ``[abc]``) into a regex.

    Uses simple proxy-scope glob semantics: ``*`` is any run of
    non-dot characters plus dot-segments, ``?`` is exactly one
    non-dot character, ``[abc]`` is a character class. An empty
    pattern matches anything.
    """
    if not pattern:
        return re.compile(r".*")
    out: list[str] = ["^"]
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            out.append("[^.]*")
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                out.append(".*")
                i += 1
        elif ch == "?":
            out.append("[^.]")
        elif ch == "[":
            j = pattern.find("]", i)
            if j == -1:
                out.append(re.escape("["))
            else:
                out.append(pattern[i : j + 1])
                i = j
        elif ch in r".^$+(){}|\\":
            out.append(re.escape(ch))
        else:
            out.append(re.escape(ch))
        i += 1
    out.append("$")
    return re.compile("".join(out))


def _match_any(host: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        if _glob_to_regex(pattern).match(host):
            return True
    return False


def match_host(scope: Scope, host: str) -> bool:
    """Return True when ``host`` is in-scope for ``scope``.

    Semantics:

    - Empty allowlist means "allow all".
    - Denylist always overrides allowlist.
    """
    if _match_any(host, scope.denylist):
        return False
    if not scope.allowlist:
        return True
    return _match_any(host, scope.allowlist)


class ScopeStore:
    """Thread-safe CRUD wrapper around a single JSON file on disk."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._scopes: dict[str, Scope] = {}
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> None:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if not self._path.exists():
                self._scopes = {self._default().id: self._default()}
                self._write_unlocked()
                return
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                logger.warning("scope store %s unreadable; resetting", self._path, exc_info=True)
                self._scopes = {self._default().id: self._default()}
                self._write_unlocked()
                return
            scopes_raw = raw.get("scopes") if isinstance(raw, dict) else None
            scopes: dict[str, Scope] = {}
            if isinstance(scopes_raw, list):
                for entry in scopes_raw:
                    if not isinstance(entry, dict):
                        continue
                    try:
                        scope = Scope.from_dict(entry)
                    except (TypeError, ValueError):
                        continue
                    scopes[scope.id] = scope
            if not scopes:
                default = self._default()
                scopes[default.id] = default
            self._scopes = scopes

    def _write_unlocked(self) -> None:
        payload = {"scopes": [s.to_dict() for s in self._scopes.values()]}
        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix=".scopes.", suffix=".json", dir=str(self._path.parent)
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as fp:
                json.dump(payload, fp, indent=2, sort_keys=True)
            Path(tmp_path).replace(self._path)
        except Exception:
            Path(tmp_path).unlink(missing_ok=True)
            raise

    @staticmethod
    def _default() -> Scope:
        return Scope(id=_DEFAULT_SCOPE_ID, name=_DEFAULT_SCOPE_NAME)

    def list(self) -> list[Scope]:
        with self._lock:
            return list(self._scopes.values())

    def get(self, scope_id: str) -> Scope | None:
        with self._lock:
            return self._scopes.get(scope_id)

    def create(
        self,
        *,
        name: str,
        allowlist: list[str] | None = None,
        denylist: list[str] | None = None,
        scope_id: str | None = None,
    ) -> Scope:
        with self._lock:
            new_id = scope_id or uuid.uuid4().hex
            if new_id in self._scopes:
                raise ValueError(f"Scope {new_id!r} already exists")
            scope = Scope(
                id=new_id,
                name=name,
                allowlist=list(allowlist or []),
                denylist=list(denylist or []),
            )
            self._scopes[scope.id] = scope
            self._write_unlocked()
            return scope

    def update(
        self,
        scope_id: str,
        *,
        name: str,
        allowlist: list[str] | None = None,
        denylist: list[str] | None = None,
    ) -> Scope:
        with self._lock:
            existing = self._scopes.get(scope_id)
            if existing is None:
                raise KeyError(f"Scope {scope_id!r} not found")
            updated = Scope(
                id=existing.id,
                name=name,
                allowlist=list(allowlist) if allowlist is not None else existing.allowlist,
                denylist=list(denylist) if denylist is not None else existing.denylist,
            )
            self._scopes[scope_id] = updated
            self._write_unlocked()
            return updated

    def delete(self, scope_id: str) -> None:
        with self._lock:
            if scope_id not in self._scopes:
                raise KeyError(f"Scope {scope_id!r} not found")
            del self._scopes[scope_id]
            if not self._scopes:
                default = self._default()
                self._scopes[default.id] = default
            self._write_unlocked()

    def reload(self) -> None:
        """Re-read from disk. Used by the addon on addon start to pick up
        scopes written by an external process (the host SDK)."""
        self._load()

    def matching_scope_id(self, host: str) -> str | None:
        """Return the id of the scope that matches ``host``, or
        ``None`` if no scope matches.

        Scopes are scanned in reverse-insertion order: the most
        recently created scope wins, so a user-created ``strict``
        scope is preferred over the implicit ``default`` catch-all.
        If no scope matches, ``None`` is returned (the flow is
        out-of-scope).
        """
        with self._lock:
            scopes = list(self._scopes.values())
            for scope in reversed(scopes):
                if match_host(scope, host):
                    return scope.id
        return None
