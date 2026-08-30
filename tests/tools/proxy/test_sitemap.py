"""Tests for kael.tools.proxy.sitemap (synthesis from JSONL)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from kael.tools.proxy.sitemap import build_entry_view, build_sitemap


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _flow(
    *,
    flow_id: str,
    method: str,
    host: str,
    path: str,
    port: int = 443,
    scheme: str = "https",
    status_code: int = 200,
) -> dict:
    return {
        "id": flow_id,
        "timestamp": 0,
        "request": {
            "method": method,
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "headers": [],
            "content_b64": "",
        },
        "response": {
            "status_code": status_code,
            "reason": "OK",
            "headers": [],
            "content_b64": "",
            "roundtrip_ms": 0,
        },
    }


class TestBuildSitemap:
    def test_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "flows.jsonl"
        p.write_text("", encoding="utf-8")
        out = build_sitemap(p)
        assert out["success"] is True
        assert out["entries"] == []
        assert out["total_count"] == 0

    def test_root_domains(self, tmp_path: Path) -> None:
        p = tmp_path / "flows.jsonl"
        p.write_text(
            "\n".join(
                json.dumps(_flow(flow_id=f"id{i}", method="GET", host=h, path="/x"))
                for i, h in enumerate(["a.example.com", "b.example.com"])
            )
            + "\n",
            encoding="utf-8",
        )
        out = build_sitemap(p, page_size=10)
        labels = [e["label"] for e in out["entries"]]
        assert labels == ["a.example.com", "b.example.com"]
        for entry in out["entries"]:
            assert entry["kind"] == "DOMAIN"
            assert entry["has_descendants"] is True
            assert entry["metadata"]["is_tls"] is True
            assert entry["metadata"]["port"] == 443

    def test_descend_into_directory(self, tmp_path: Path) -> None:
        p = tmp_path / "flows.jsonl"
        p.write_text(
            json.dumps(
                _flow(flow_id="i1", method="GET", host="api.example.com", path="/v1/users/42")
            )
            + "\n",
            encoding="utf-8",
        )
        out = build_sitemap(p, page_size=10)
        # root level
        root_entries = out["entries"]
        assert len(root_entries) == 1
        domain = root_entries[0]
        assert domain["kind"] == "DOMAIN"
        domain_id = domain["id"]

        # descend one level
        deeper = build_sitemap(p, parent_id=domain_id, page_size=10)
        labels = [e["label"] for e in deeper["entries"]]
        assert labels == ["v1"]
        assert deeper["entries"][0]["kind"] == "DIRECTORY"
        v1_id = deeper["entries"][0]["id"]

        v1_children = build_sitemap(p, parent_id=v1_id, page_size=10)
        assert [c["label"] for c in v1_children["entries"]] == ["users"]
        users_id = v1_children["entries"][0]["id"]

        users_children = build_sitemap(p, parent_id=users_id, page_size=10)
        assert [c["label"] for c in users_children["entries"]] == ["42"]
        leaf_id = users_children["entries"][0]["id"]

        leaf = build_sitemap(p, parent_id=leaf_id, page_size=10)
        assert len(leaf["entries"]) == 1
        leaf_entry = leaf["entries"][0]
        assert leaf_entry["kind"] == "REQUEST"
        assert leaf_entry["label"] == "GET /v1/users/42"
        assert leaf_entry["request"]["method"] == "GET"
        assert leaf_entry["request"]["response"]["status_code"] == 200

    def test_pagination(self, tmp_path: Path) -> None:
        p = tmp_path / "flows.jsonl"
        flows = [
            json.dumps(_flow(flow_id=f"id{i}", method="GET", host=f"h{i}.example.com", path="/"))
            for i in range(5)
        ]
        p.write_text("\n".join(flows) + "\n", encoding="utf-8")
        page1 = build_sitemap(p, page=1, page_size=2)
        page2 = build_sitemap(p, page=2, page_size=2)
        page3 = build_sitemap(p, page=3, page_size=2)
        assert [e["label"] for e in page1["entries"]] == ["h0.example.com", "h1.example.com"]
        assert [e["label"] for e in page2["entries"]] == ["h2.example.com", "h3.example.com"]
        assert [e["label"] for e in page3["entries"]] == ["h4.example.com"]
        assert page1["has_more"] is True
        assert page3["has_more"] is False
        assert page1["total_pages"] == 3

    def test_scope_filter(self, tmp_path: Path) -> None:
        p = tmp_path / "flows.jsonl"
        flow_in = _flow(flow_id="a", method="GET", host="in.test", path="/")
        flow_in["tags"] = ["scope:in"]
        flow_out = _flow(flow_id="b", method="GET", host="out.test", path="/")
        flow_out["tags"] = ["scope:default"]
        p.write_text(
            json.dumps(flow_in) + "\n" + json.dumps(flow_out) + "\n",
            encoding="utf-8",
        )
        out = build_sitemap(
            p,
            scope_filter=lambda f: "scope:in" in (f.get("tags") or []),
        )
        labels = [e["label"] for e in out["entries"]]
        assert labels == ["in.test"]


class TestBuildEntryView:
    def test_unknown_entry(self, tmp_path: Path) -> None:
        p = tmp_path / "flows.jsonl"
        p.write_text("", encoding="utf-8")
        out = build_entry_view(p, "missing-id")
        assert out["success"] is False
        assert "not found" in out["error"]

    def test_related_requests_for_request_node(self, tmp_path: Path) -> None:
        p = tmp_path / "flows.jsonl"
        p.write_text(
            json.dumps(
                _flow(
                    flow_id="x1", method="POST", host="api.test", path="/v1/login", status_code=401
                )
            )
            + "\n"
            + json.dumps(
                _flow(
                    flow_id="x2", method="POST", host="api.test", path="/v1/login", status_code=200
                )
            )
            + "\n",
            encoding="utf-8",
        )
        sitemap = build_sitemap(p, page_size=10)
        domain_id = sitemap["entries"][0]["id"]
        deeper = build_sitemap(p, parent_id=domain_id, page_size=10)
        v1_id = deeper["entries"][0]["id"]
        v1_kids = build_sitemap(p, parent_id=v1_id, page_size=10)
        login_id = v1_kids["entries"][0]["id"]
        login_kids = build_sitemap(p, parent_id=login_id, page_size=10)
        request_id = login_kids["entries"][0]["id"]
        assert login_kids["entries"][0]["kind"] == "REQUEST"

        view = build_entry_view(p, request_id)
        assert view["success"] is True
        entry = view["entry"]
        assert entry["kind"] == "REQUEST"
        assert entry["label"] == "POST /v1/login"
        related = entry["related_requests"]
        assert related["total_count"] == 2
        statuses = sorted(r["response"]["status_code"] for r in related["requests"])
        assert statuses == [200, 401]
