"""End-to-end sandbox startup and proxy capture checks."""

from __future__ import annotations

import uuid

import pytest

from kael.config import load_settings
from kael.runtime import session_manager
from kael.tools.proxy import mitm_control


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sandbox_starts_and_captures_http_through_mitmproxy() -> None:
    scan_id = f"integration-{uuid.uuid4().hex}"
    bundle = await session_manager.create_or_reuse(
        scan_id,
        image=load_settings().runtime.image,
        local_sources=[],
    )
    try:
        session = bundle["session"]
        server = await session.exec(
            "bash",
            "-lc",
            "mkdir -p /tmp/kael-http-root && "
            "touch /tmp/kael-http-root/kael-proxy-smoke && "
            "nohup python3 -m http.server 8765 --bind 0.0.0.0 "
            "--directory /tmp/kael-http-root >/tmp/kael-http.log 2>&1 &",
            timeout=10,
        )
        assert server.ok(), server.stderr

        request = await session.exec(
            "bash",
            "-lc",
            "target_ip=$(hostname -I | awk '{print $1}'); "
            "curl -fsS --retry 10 --retry-connrefused --retry-delay 1 "
            "http://${target_ip}:8765/kael-proxy-smoke",
            timeout=30,
        )
        assert request.ok(), request.stderr

        flows = await mitm_control.list_flows(
            mitm_filter="~u /kael-proxy-smoke",
            first=10,
            base_url=bundle["mitm_client"].host_url,
        )
        assert flows["success"] is True
        assert any(entry["request"]["path"] == "/kael-proxy-smoke" for entry in flows["entries"])
    finally:
        await session_manager.cleanup(scan_id)
