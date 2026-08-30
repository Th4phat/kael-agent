"""Host-side client for the in-container mitmproxy control endpoint.

The mitmproxy addon runs inside ``mitmdump`` and exposes a small JSON
HTTP API on port 8081 inside the sandbox. This module is the host-side
mirror: it speaks the same JSON shapes, but routes calls through
``httpx`` to the port that the SDK session manager publishes only on
the host loopback interface.

The returned dictionaries use the stable shapes consumed by Kael's
agent-facing proxy tools and can also be imported by sandbox Python scripts.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Literal

import httpx


logger = logging.getLogger(__name__)


DEFAULT_CONTROL_URL = "http://127.0.0.1:8081"
DEFAULT_TIMEOUT_SECONDS = 30.0
REPLAY_TIMEOUT_SECONDS = 45.0


SortBy = Literal[
    "timestamp",
    "host",
    "method",
    "path",
    "status_code",
    "response_time",
    "response_size",
    "source",
]
SortOrder = Literal["asc", "desc"]
RequestPart = Literal["request", "response"]
SitemapDepth = Literal["DIRECT", "ALL"]
ScopeAction = Literal["get", "list", "create", "update", "delete"]


def control_url(base_url: str | None = None) -> str:
    if base_url:
        return base_url.rstrip("/")
    return os.environ.get("KAEL_MITM_CONTROL_URL", DEFAULT_CONTROL_URL).rstrip("/")


class MitmControlError(RuntimeError):
    """Raised when the in-container addon rejects a request."""


def _sync_client(
    timeout: float = DEFAULT_TIMEOUT_SECONDS, *, base_url: str | None = None
) -> httpx.Client:
    return httpx.Client(base_url=control_url(base_url), timeout=timeout)


def _async_client(
    timeout: float = DEFAULT_TIMEOUT_SECONDS, *, base_url: str | None = None
) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=control_url(base_url), timeout=timeout)


def health(*, attempts: int = 10, delay: float = 1.0, base_url: str | None = None) -> bool:
    """Synchronous health check. Useful from entrypoint scripts and tests."""
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            with _sync_client(timeout=2.0, base_url=base_url) as client:
                r = client.get("/health")
                if r.status_code == 200 and r.json().get("status") == "ok":
                    return True
        except (httpx.RequestError, ValueError) as exc:
            last_exc = exc
        time.sleep(delay)
    if last_exc is not None:
        logger.debug("mitm health check failed: %s", last_exc)
    return False


async def ahealth(*, attempts: int = 10, delay: float = 1.0, base_url: str | None = None) -> bool:
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            async with _async_client(timeout=2.0, base_url=base_url) as client:
                r = await client.get("/health")
                if r.status_code == 200 and r.json().get("status") == "ok":
                    return True
        except (httpx.RequestError, ValueError) as exc:
            last_exc = exc
        await asyncio.sleep(delay)
    if last_exc is not None:
        logger.debug("mitm health check failed: %s", last_exc)
    return False


async def list_flows(
    *,
    mitm_filter: str | None = None,
    first: int = 50,
    after: str | None = None,
    sort_by: SortBy = "timestamp",
    sort_order: SortOrder = "desc",
    scope_id: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "first": first,
        "sort_by": sort_by,
        "sort_order": sort_order,
    }
    if mitm_filter:
        body["filter"] = mitm_filter
    if after:
        body["after"] = after
    if scope_id:
        body["scope_id"] = scope_id

    async with _async_client(base_url=base_url) as client:
        r = await client.post("/flows/search", json=body)
    _raise_for_status(r)
    return r.json()


async def view_flow(
    flow_id: str, *, part: RequestPart = "request", base_url: str | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {"part": part}
    async with _async_client(base_url=base_url) as client:
        r = await client.post(f"/flows/{flow_id}", json=body)
    _raise_for_status(r)
    return r.json()


async def replay_flow(
    flow_id: str,
    *,
    modifications: dict[str, Any] | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"modifications": modifications or {}}
    async with _async_client(timeout=REPLAY_TIMEOUT_SECONDS, base_url=base_url) as client:
        r = await client.post(f"/flows/{flow_id}/replay", json=body)
    _raise_for_status(r)
    return r.json()


async def list_sitemap(
    *,
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: SitemapDepth = "DIRECT",
    page: int = 1,
    base_url: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"depth": depth, "page": page}
    if scope_id is not None:
        body["scope_id"] = scope_id
    if parent_id is not None:
        body["parent_id"] = parent_id
    async with _async_client(base_url=base_url) as client:
        r = await client.post("/sitemap", json=body)
    _raise_for_status(r)
    return r.json()


async def view_sitemap_entry(entry_id: str, *, base_url: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"entry_id": entry_id}
    async with _async_client(base_url=base_url) as client:
        r = await client.post("/sitemap/entry", json=body)
    _raise_for_status(r)
    return r.json()


async def scope_rules(
    action: ScopeAction,
    *,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"action": action}
    if allowlist is not None:
        body["allowlist"] = allowlist
    if denylist is not None:
        body["denylist"] = denylist
    if scope_id is not None:
        body["scope_id"] = scope_id
    if scope_name is not None:
        body["scope_name"] = scope_name

    async with _async_client(base_url=base_url) as client:
        r = await client.post("/scopes", json=body)
    _raise_for_status(r)
    return r.json()


def _raise_for_status(response: httpx.Response) -> None:
    if response.status_code >= 400:
        try:
            detail = response.json().get("error", response.text)
        except ValueError:
            detail = response.text
        raise MitmControlError(
            f"mitm control {response.request.url.path} -> {response.status_code}: {detail}"
        )


__all__ = [
    "DEFAULT_CONTROL_URL",
    "DEFAULT_TIMEOUT_SECONDS",
    "REPLAY_TIMEOUT_SECONDS",
    "MitmControlError",
    "RequestPart",
    "ScopeAction",
    "SitemapDepth",
    "SortBy",
    "SortOrder",
    "ahealth",
    "control_url",
    "health",
    "list_flows",
    "list_sitemap",
    "replay_flow",
    "scope_rules",
    "view_flow",
    "view_sitemap_entry",
]
