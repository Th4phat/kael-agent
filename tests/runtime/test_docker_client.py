"""Tests for the sandbox container create kwargs."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from kael.runtime import docker_client
from kael.runtime.docker_client import KaelDockerSandboxClient


def _create_kwargs(monkeypatch: pytest.MonkeyPatch, sandbox_dns: str | None) -> dict:
    monkeypatch.setattr(
        docker_client,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(sandbox_dns=sandbox_dns)),
    )
    runtime = MagicMock()
    runtime.containers.create.return_value = SimpleNamespace(short_id="abc")
    client = KaelDockerSandboxClient(runtime)
    monkeypatch.setattr(client, "image_exists", lambda image: True)

    import asyncio

    asyncio.run(client._create_container("kael-sandbox:test"))
    return runtime.containers.create.call_args.kwargs


def test_sandbox_dns_passed_to_container(monkeypatch: pytest.MonkeyPatch) -> None:
    kwargs = _create_kwargs(monkeypatch, " 1.1.1.1, 8.8.8.8 ,")
    assert kwargs["dns"] == ["1.1.1.1", "8.8.8.8"]
    assert "NET_ADMIN" in kwargs["cap_add"]


def test_sandbox_dns_unset_inherits_runtime_default(monkeypatch: pytest.MonkeyPatch) -> None:
    assert "dns" not in _create_kwargs(monkeypatch, None)
