"""Tests for kael.tools.proxy.mitm_control (host-side HTTP client)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from kael.tools.proxy import mitm_control
from kael.tools.proxy.mitm_control import MitmControlError


class _FakeRouter:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict]] = []
        # path -> (status_code, payload) | Exception
        self.responses: dict[str, Any] = {}

    def set(self, path: str, payload: Any, status: int = 200) -> None:
        self.responses[path] = (status, payload)


def _build_mock_transport(router: _FakeRouter) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read()
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        router.requests.append((request.url.path, data))
        if request.url.path in router.responses:
            entry = router.responses[request.url.path]
            if isinstance(entry, Exception):
                raise entry
            status, payload = entry
            return httpx.Response(status, json=payload)
        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler)


@pytest.fixture
def mock_router(monkeypatch: pytest.MonkeyPatch) -> _FakeRouter:
    router = _FakeRouter()
    transport = _build_mock_transport(router)
    original_client = httpx.AsyncClient

    def _patched_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        if not kwargs.get("base_url"):
            kwargs["base_url"] = "http://addon.test:8081"
        if "timeout" not in kwargs:
            kwargs["timeout"] = 5.0
        return original_client(*args, **kwargs)

    monkeypatch.setattr(mitm_control, "_async_client", _patched_client)
    monkeypatch.setenv("KAEL_MITM_CONTROL_URL", "http://addon.test:8081")
    return router


@pytest.mark.asyncio
class TestHealth:
    async def test_health_healthy(self, mock_router: _FakeRouter) -> None:
        mock_router.set("/health", {"status": "ok"})
        result = await mitm_control.ahealth(attempts=1, delay=0)
        assert result is True

    async def test_health_failure(self, mock_router: _FakeRouter) -> None:
        mock_router.responses.clear()
        mock_router.responses["/health"] = httpx.ConnectError(
            "nope", request=httpx.Request("GET", "/health")
        )
        assert await mitm_control.ahealth(attempts=1, delay=0) is False


@pytest.mark.asyncio
class TestListFlows:
    async def test_basic_call(self, mock_router: _FakeRouter) -> None:
        mock_router.set(
            "/flows/search",
            {"success": True, "entries": [], "page_info": {}, "total": 0},
        )
        result = await mitm_control.list_flows(mitm_filter="~m POST", first=10)
        assert result["success"] is True
        path, body = mock_router.requests[0]
        assert path == "/flows/search"
        assert body["filter"] == "~m POST"
        assert body["first"] == 10
        assert body["sort_order"] == "desc"

    async def test_4xx_raises(self, mock_router: _FakeRouter) -> None:
        mock_router.set("/flows/search", {"error": "bad filter"}, status=400)
        with pytest.raises(MitmControlError):
            await mitm_control.list_flows(mitm_filter="~bad", first=1)


@pytest.mark.asyncio
class TestReplayFlow:
    async def test_passes_modifications(self, mock_router: _FakeRouter) -> None:
        mock_router.set(
            "/flows/abc123/replay",
            {"success": True, "flow": {"id": "new"}},
        )
        result = await mitm_control.replay_flow(
            "abc123",
            modifications={"headers": {"X-Test": "1"}},
        )
        assert result["success"] is True
        path, body = mock_router.requests[0]
        assert path == "/flows/abc123/replay"
        assert body["modifications"]["headers"] == {"X-Test": "1"}


@pytest.mark.asyncio
class TestScopeRules:
    async def test_create(self, mock_router: _FakeRouter) -> None:
        mock_router.set(
            "/scopes",
            {
                "success": True,
                "scope": {"id": "new", "name": "x", "allowlist": [], "denylist": []},
            },
        )
        result = await mitm_control.scope_rules("create", scope_name="x", allowlist=["*.test"])
        assert result["scope"]["id"] == "new"
        _path, body = mock_router.requests[0]
        assert body["action"] == "create"
        assert body["allowlist"] == ["*.test"]


class TestControlUrl:
    def test_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("KAEL_MITM_CONTROL_URL", raising=False)
        assert mitm_control.control_url() == mitm_control.DEFAULT_CONTROL_URL

    def test_overridden(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KAEL_MITM_CONTROL_URL", "http://x:9999/")
        assert mitm_control.control_url() == "http://x:9999"


@pytest.mark.asyncio
class TestRaiseForStatus:
    async def test_404(self, mock_router: _FakeRouter) -> None:
        mock_router.set("/flows/missing", {"error": "no such flow"}, status=404)
        with pytest.raises(MitmControlError, match="404"):
            await mitm_control.view_flow("missing")
