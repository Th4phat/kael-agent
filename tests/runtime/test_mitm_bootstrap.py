"""Tests for kael.runtime.mitm_bootstrap (host-side bootstrap)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from kael.runtime import mitm_bootstrap


class _StubTransport(httpx.AsyncBaseTransport):
    def __init__(self, replies: list[httpx.Response]) -> None:
        self._replies = list(replies)
        self.calls: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request.url.path)
        if not self._replies:
            return httpx.Response(503, json={"error": "no scripted reply"})
        return self._replies.pop(0)


def _patched_async_client(
    transport: httpx.AsyncBaseTransport,
) -> Any:
    """Return a callable that produces AsyncClient with the given transport."""
    original_async_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        if "base_url" not in kwargs:
            kwargs["base_url"] = "http://addon.test:8081"
        if "timeout" not in kwargs:
            kwargs["timeout"] = 2.0
        return original_async_client(*args, **kwargs)

    return factory


@pytest.mark.asyncio
async def test_bootstrap_returns_handle_when_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _StubTransport([httpx.Response(200, json={"status": "ok"})])
    monkeypatch.setattr(mitm_bootstrap.httpx, "AsyncClient", _patched_async_client(transport))

    client = await mitm_bootstrap.bootstrap_mitmproxy(
        host_url="http://addon.test:8081",
        container_url="http://127.0.0.1:8081",
    )
    assert client.host_url == "http://addon.test:8081"
    assert client.container_url == "http://127.0.0.1:8081"
    assert transport.calls == ["/health"]


@pytest.mark.asyncio
async def test_bootstrap_retries_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _StubTransport(
        [
            httpx.Response(500, json={"error": "x"}),
            httpx.Response(500, json={"error": "x"}),
            httpx.Response(200, json={"status": "ok"}),
        ]
    )
    monkeypatch.setattr(mitm_bootstrap.httpx, "AsyncClient", _patched_async_client(transport))

    sleeps: list[float] = []
    real_sleep = mitm_bootstrap.asyncio.sleep

    async def _fast_sleep(t: float) -> None:
        sleeps.append(t)

    monkeypatch.setattr(mitm_bootstrap.asyncio, "sleep", _fast_sleep)
    client = await mitm_bootstrap.bootstrap_mitmproxy(
        host_url="http://addon.test:8081",
        container_url="http://127.0.0.1:8081",
    )
    assert client is not None
    assert transport.calls == ["/health", "/health", "/health"]
    assert sleeps, "expected at least one backoff sleep"

    await real_sleep(0)


@pytest.mark.asyncio
async def test_bootstrap_gives_up_after_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _StubTransport([])  # always 503
    monkeypatch.setattr(mitm_bootstrap.httpx, "AsyncClient", _patched_async_client(transport))

    async def _zero_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(mitm_bootstrap.asyncio, "sleep", _zero_sleep)

    with pytest.raises(RuntimeError, match="did not become ready"):
        await mitm_bootstrap.bootstrap_mitmproxy(
            host_url="http://addon.test:8081",
            container_url="http://127.0.0.1:8081",
        )
    assert len(transport.calls) >= 1


@pytest.mark.asyncio
async def test_mitm_control_health_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Smoke test against the full chain via the re-exported ``health``."""
    transport = _StubTransport([httpx.Response(200, json={"status": "ok"})])
    monkeypatch.setattr(mitm_bootstrap.httpx, "AsyncClient", _patched_async_client(transport))
    assert await mitm_bootstrap.ahealth(attempts=1, delay=0) is True


class _RoundTripTransport(httpx.AsyncBaseTransport):
    """Routes responses by path so we can test a full round-trip in one call."""

    def __init__(self, responses: dict[str, httpx.Response]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, dict]] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = request.read()
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        self.requests.append((request.url.path, data))
        return self.responses.get(
            request.url.path,
            httpx.Response(404, json={"error": "no scripted reply for path"}),
        )


@pytest.mark.asyncio
async def test_mitm_control_list_flows_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _RoundTripTransport(
        {
            "/flows/search": httpx.Response(
                200,
                json={"success": True, "entries": [], "page_info": {}, "total": 0},
            )
        }
    )
    monkeypatch.setattr(mitm_bootstrap.httpx, "AsyncClient", _patched_async_client(transport))
    result = await mitm_bootstrap.list_flows(mitm_filter="~m POST", first=10)
    assert result["success"] is True
    path, body = transport.requests[0]
    assert path == "/flows/search"
    assert body["filter"] == "~m POST"
    assert body["first"] == 10
