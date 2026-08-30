"""Tests for sandbox session startup readiness."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from kael.runtime import session_manager
from kael.runtime.session_manager import _wait_for_entrypoint


@pytest.mark.asyncio
async def test_wait_for_entrypoint_retries_until_ready() -> None:
    session = SimpleNamespace(exec=AsyncMock())
    session.exec.side_effect = [
        SimpleNamespace(ok=lambda: False, exit_code=1),
        SimpleNamespace(ok=lambda: True, exit_code=0),
    ]

    await _wait_for_entrypoint(session, attempts=2, delay=0)

    assert session.exec.await_count == 2
    session.exec.assert_awaited_with("test", "-f", "/tmp/kael-ready", timeout=5)


@pytest.mark.asyncio
async def test_wait_for_entrypoint_reports_timeout() -> None:
    session = SimpleNamespace(
        exec=AsyncMock(return_value=SimpleNamespace(ok=lambda: False, exit_code=1))
    )

    with pytest.raises(RuntimeError, match="did not become ready after 2 attempts"):
        await _wait_for_entrypoint(session, attempts=2, delay=0)


@pytest.mark.asyncio
async def test_create_or_reuse_wires_mitmproxy_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_client = SimpleNamespace(delete=AsyncMock())
    sandbox_session = SimpleNamespace(
        exec=AsyncMock(return_value=SimpleNamespace(ok=lambda: True, exit_code=0)),
        resolve_exposed_port=AsyncMock(return_value=SimpleNamespace(host="127.0.0.1", port=49152)),
    )
    create_session = AsyncMock(return_value=(runtime_client, sandbox_session))
    mitm_client = SimpleNamespace(aclose=AsyncMock())
    bootstrap = AsyncMock(return_value=mitm_client)
    settings = SimpleNamespace(
        runtime=SimpleNamespace(backend="podman"),
        reverse_engineering=SimpleNamespace(
            re_network_mode="controlled",
            re_max_runtime_sec=120,
        ),
    )

    monkeypatch.setattr(session_manager, "create_docker_session", create_session)
    monkeypatch.setattr(session_manager, "bootstrap_mitmproxy", bootstrap)
    monkeypatch.setattr(session_manager, "load_settings", lambda: settings)
    session_manager._SESSION_CACHE.clear()

    bundle = await session_manager.create_or_reuse(
        "mitm-wiring-test",
        image="kael-sandbox:test",
        local_sources=[],
    )

    assert bundle["mitm_client"] is mitm_client
    call = create_session.await_args
    assert call.kwargs["exposed_ports"] == (8081,)
    environment = await call.kwargs["manifest"].environment.resolve()
    assert environment["HTTP_PROXY"] == "http://127.0.0.1:8080"
    assert environment["HTTPS_PROXY"] == "http://127.0.0.1:8080"
    assert environment["KAEL_MITM_CONTROL_URL"] == "http://127.0.0.1:8081"
    bootstrap.assert_awaited_once_with(
        host_url="http://127.0.0.1:49152",
        container_url="http://127.0.0.1:8081",
    )

    await session_manager.cleanup("mitm-wiring-test")
    mitm_client.aclose.assert_awaited_once_with()
    runtime_client.delete.assert_awaited_once_with(sandbox_session)
