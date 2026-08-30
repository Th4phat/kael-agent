"""Sitemap synthesis from a JSONL flow log.

mitmproxy has no built-in sitemap concept, but the existing kael
agent tool surface (and its TUI renderer) expects a stable tree:
``DOMAIN`` → ``DIRECTORY`` (path segments) → ``REQUEST`` (per
method+path). This module reads captured flows from a JSONL file and
reconstructs that tree on demand. Pagination is implemented client-side.

Output shape::

    {
      "success": True,
      "entries": [
        {
          "id": "...",
          "kind": "DOMAIN" | "DIRECTORY" | "REQUEST",
          "label": "api.example.com",
          "has_descendants": True,
          "metadata": {"is_tls": True, "port": 443},   # DOMAIN only
          "request": {"method": "POST", "path": "/v1/x",
                      "response": {"status_code": 200}}
        }, ...
      ],
      "page": 1,
      "page_size": 30,
      "total_pages": 4,
      "total_count": 100,
      "has_more": True
    }
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


DEFAULT_PAGE_SIZE = 30


@dataclass
class _Node:
    kind: str  # "DOMAIN" | "DIRECTORY" | "REQUEST"
    label: str
    has_descendants: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    request: dict[str, Any] | None = None
    children: dict[str, _Node] = field(default_factory=dict)
    descendants_count: int = 0
    request_count: int = 0

    def to_entry(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self._id,
            "kind": self.kind,
            "label": self.label,
            "has_descendants": self.has_descendants,
        }
        if self.metadata:
            out["metadata"] = self.metadata
        if self.request is not None:
            out["request"] = self.request
        return out

    @property
    def _id(self) -> str:
        h = hashlib.sha1(f"{self.kind}:{self.label}".encode(), usedforsecurity=False).hexdigest()[
            :16
        ]
        return f"{self.kind.lower()[0]}-{h}"


def _decode(b64: str | None) -> str:
    if not b64:
        return ""
    try:
        return base64.b64decode(b64).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _parse_flow_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _iter_flows(path: Path) -> Iterable[dict[str, Any]]:
    """Yield parsed JSONL flow records from ``path``.

    Malformed lines are skipped (logged once) rather than aborting the
    whole synthesis — the JSONL may be appended by a long-running
    addon process.
    """
    if not path.exists():
        return iter([])
    yielded = 0
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            rec = _parse_flow_line(line)
            if rec is None:
                continue
            yielded += 1
            yield rec
    if yielded == 0:
        return
    # implicit return None keeps the generator reference stable


def _build_tree(flows: Iterable[dict[str, Any]]) -> dict[str, _Node]:
    roots: dict[str, _Node] = {}
    for flow in flows:
        req = flow.get("request") or {}
        host = req.get("host") or ""
        if not host:
            continue
        scheme = (req.get("scheme") or "http").lower()
        port = int(req.get("port") or (443 if scheme == "https" else 80))
        path = req.get("path") or "/"
        method = (req.get("method") or "GET").upper()
        resp = flow.get("response") or {}
        status_code = resp.get("status_code")

        domain = roots.get(host)
        if domain is None:
            domain = _Node(
                kind="DOMAIN",
                label=host,
                metadata={"is_tls": scheme == "https", "port": port},
            )
            roots[host] = domain
        domain.request_count += 1

        segments = [s for s in path.split("/") if s]
        cursor = domain
        for segment in segments:
            child = cursor.children.get(segment)
            if child is None:
                child = _Node(kind="DIRECTORY", label=segment)
                cursor.children[segment] = child
            child.request_count += 1
            cursor = child

        request_label = f"{method} {path}"
        request_node = cursor.children.get(request_label)
        if request_node is None:
            request_summary: dict[str, Any] = {"method": method, "path": path}
            if status_code is not None:
                request_summary["response"] = {"status_code": int(status_code)}
            request_node = _Node(
                kind="REQUEST",
                label=request_label,
                request=request_summary,
            )
            cursor.children[request_label] = request_node
        request_node.request_count += 1
        if status_code is not None:
            existing_resp = request_node.request.get("response") or {}
            existing_resp.setdefault("status_code", int(status_code))
            request_node.request["response"] = existing_resp

    def _compute_descendants(node: _Node) -> int:
        total = 0
        for child in node.children.values():
            total += _compute_descendants(child)
        node.descendants_count = total
        node.has_descendants = bool(node.children)
        return total + node.request_count

    for domain in roots.values():
        _compute_descendants(domain)
    return roots


def _flatten(
    nodes: dict[str, _Node], *, depth: str, page: int, page_size: int
) -> tuple[list[dict[str, Any]], int, int]:
    """Apply depth filter and pagination, returning (entries, total, total_pages)."""
    if depth == "ALL":
        flat: list[_Node] = []

        def _walk(n: _Node) -> None:
            for child in n.children.values():
                flat.append(child)
                _walk(child)

        for root in nodes.values():
            _walk(root)
    else:
        flat = list(nodes.values())

    flat.sort(key=lambda n: (n.label.lower(), n.kind))
    total = len(flat)
    total_pages = (total + page_size - 1) // page_size if total else 0
    skip = max(0, (page - 1) * page_size)
    sliced = flat[skip : skip + page_size]
    return [n.to_entry() for n in sliced], total, total_pages


def build_sitemap(
    jsonl_path: str | os.PathLike[str],
    *,
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: str = "DIRECT",
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    scope_filter: callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Build a sitemap page from a JSONL flow log.

    ``scope_filter`` is an optional callable ``flow_record -> bool``
    that lets the host SDK restrict results to a particular scope id
    (mitmproxy already tags each flow with ``tags: [scope:<id>]`` in
    the JSONL).
    """
    path = Path(jsonl_path)
    flows_iter: Iterable[dict[str, Any]] = _iter_flows(path)
    if scope_filter is not None:
        flows_iter = (f for f in flows_iter if scope_filter(f))

    roots = _build_tree(flows_iter)
    started = time.time()

    if parent_id:
        target = _find_by_id(roots, parent_id)
        if target is None:
            return {
                "success": False,
                "error": f"parent_id {parent_id!r} not found in sitemap",
            }
        nodes = target.children
    else:
        nodes = roots

    entries, total, total_pages = _flatten(nodes, depth=depth, page=page, page_size=page_size)

    if scope_id is not None and parent_id is None:
        # root-level scope filtering: keep only domains with a matching scope tag.
        if not scope_id or scope_id == "default":
            pass
        else:
            return {
                "success": False,
                "error": (
                    f"scope_id={scope_id!r} filtering at root not supported; "
                    "apply the scope filter when capturing flows"
                ),
            }

    return {
        "success": True,
        "entries": entries,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "total_count": total,
        "has_more": page < total_pages,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def _find_by_id(roots: dict[str, _Node], node_id: str) -> _Node | None:
    for root in roots.values():
        if root._id == node_id:
            return root
        found = _find_in_children(root, node_id)
        if found is not None:
            return found
    return None


def _find_in_children(node: _Node, node_id: str) -> _Node | None:
    for child in node.children.values():
        if child._id == node_id:
            return child
        nested = _find_in_children(child, node_id)
        if nested is not None:
            return nested
    return None


def build_entry_view(
    jsonl_path: str | os.PathLike[str],
    entry_id: str,
    *,
    related_limit: int = 30,
    scope_filter: callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Return detail for a single sitemap entry plus recent related flows."""
    path = Path(jsonl_path)
    flows_iter: Iterable[dict[str, Any]] = _iter_flows(path)
    if scope_filter is not None:
        flows_iter = (f for f in flows_iter if scope_filter(f))

    roots = _build_tree(flows_iter)
    target = _find_by_id(roots, entry_id)
    if target is None:
        return {"success": False, "error": f"entry {entry_id!r} not found"}

    cleaned: dict[str, Any] = target.to_entry()

    related: list[dict[str, Any]] = []
    target_path = ""
    target_method = ""
    if target.kind == "REQUEST":
        parts = target.label.split(" ", 1)
        target_method = parts[0] if parts else ""
        target_path = parts[1] if len(parts) > 1 else ""
    elif target.kind == "DIRECTORY":
        target_path = "/" + target.label
    else:
        target_path = "/"

    if target.kind == "REQUEST" and target_path:
        for flow in _iter_flows(path):
            req = flow.get("request") or {}
            if (req.get("method") or "").upper() == target_method and req.get(
                "path"
            ) == target_path:
                related.append(
                    {
                        "method": (req.get("method") or "").upper(),
                        "path": req.get("path") or "",
                        "response": (
                            {"status_code": (flow.get("response") or {}).get("status_code")}
                            if flow.get("response", {}).get("status_code") is not None
                            else None
                        ),
                    }
                )
                if len(related) >= related_limit:
                    break

    cleaned["related_requests"] = {
        "requests": related,
        "total_count": len(related),
    }
    return {"success": True, "entry": cleaned}
