"""Tests for kael.tools.proxy.scope_store."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kael.tools.proxy.scope_store import Scope, ScopeStore, _glob_to_regex, match_host


class TestGlobToRegex:
    def test_empty_matches_anything(self) -> None:
        assert _glob_to_regex("").match("anything") is not None

    def test_star_matches_subdomain(self) -> None:
        rx = _glob_to_regex("*.example.com")
        assert rx.match("api.example.com") is not None
        assert rx.match("a.b.example.com") is None  # * is non-recursive per our rules

    def test_double_star_matches_subpaths(self) -> None:
        rx = _glob_to_regex("**.example.com")
        assert rx.match("a.b.example.com") is not None


class TestMatchHost:
    def test_empty_allowlist_allows_all(self) -> None:
        scope = Scope(id="x", name="x", allowlist=[], denylist=[])
        assert match_host(scope, "anywhere.test") is True

    def test_denylist_overrides_allowlist(self) -> None:
        scope = Scope(
            id="x",
            name="x",
            allowlist=["*.example.com"],
            denylist=["admin.example.com"],
        )
        assert match_host(scope, "api.example.com") is True
        assert match_host(scope, "admin.example.com") is False


class TestScopeStoreRoundTrip:
    def test_first_load_creates_default(self, tmp_path: Path) -> None:
        path = tmp_path / "scopes.json"
        store = ScopeStore(path)
        assert path.exists()
        scopes = store.list()
        assert len(scopes) == 1
        assert scopes[0].id == "default"
        assert scopes[0].name == "default"

    def test_create_list_get_update_delete(self, tmp_path: Path) -> None:
        path = tmp_path / "scopes.json"
        store = ScopeStore(path)
        created = store.create(
            name="target",
            allowlist=["*.example.com"],
            denylist=["*.static.example.com"],
        )
        assert created.id
        assert any(s.id == created.id for s in store.list())
        fetched = store.get(created.id)
        assert fetched is not None
        assert fetched.name == "target"

        updated = store.update(created.id, name="target2", allowlist=["api.example.com"])
        assert updated.name == "target2"
        assert updated.allowlist == ["api.example.com"]
        assert updated.denylist == ["*.static.example.com"]  # preserved when not passed

        store.delete(created.id)
        assert store.get(created.id) is None

    def test_delete_last_falls_back_to_default(self, tmp_path: Path) -> None:
        path = tmp_path / "scopes.json"
        store = ScopeStore(path)
        default_id = store.list()[0].id
        store.delete(default_id)
        assert any(s.id == "default" for s in store.list())

    def test_duplicate_id_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "scopes.json"
        store = ScopeStore(path)
        store.create(name="a", scope_id="dup")
        with pytest.raises(ValueError, match="already exists"):
            store.create(name="b", scope_id="dup")

    def test_reload_picks_up_external_writes(self, tmp_path: Path) -> None:
        path = tmp_path / "scopes.json"
        store = ScopeStore(path)
        payload = {
            "scopes": [
                {
                    "id": "external",
                    "name": "external",
                    "allowlist": ["external.test"],
                    "denylist": [],
                }
            ]
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        store.reload()
        assert store.get("external") is not None
        assert store.get("default") is None

    def test_matching_scope_id(self, tmp_path: Path) -> None:
        path = tmp_path / "scopes.json"
        store = ScopeStore(path)
        strict = store.create(
            name="strict",
            allowlist=["api.example.com"],
        )
        assert store.matching_scope_id("api.example.com") == strict.id
        # other hosts fall through to default
        assert store.matching_scope_id("unrelated.test") == "default"

    def test_corrupt_file_recovers(self, tmp_path: Path) -> None:
        path = tmp_path / "scopes.json"
        path.write_text("{ not json", encoding="utf-8")
        store = ScopeStore(path)
        assert any(s.id == "default" for s in store.list())
