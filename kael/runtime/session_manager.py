"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
from pathlib import Path
from typing import Any

from agents.sandbox.entries import BaseEntry, LocalDir, LocalFile
from agents.sandbox.manifest import EnvEntry, Environment, EnvValue, Manifest

from kael.config import load_settings
from kael.runtime.backends import create_docker_session
from kael.runtime.mitm_bootstrap import bootstrap_mitmproxy


logger = logging.getLogger(__name__)


# In-container mitmproxy ports (match ``containers/docker-entrypoint.sh``).
_CONTAINER_MITM_PROXY_PORT = 8080
_CONTAINER_MITM_CONTROL_PORT = 8081
_ENTRYPOINT_READY_FILE = "/tmp/kael-ready"


_SESSION_CACHE: dict[str, dict[str, Any]] = {}


async def _wait_for_entrypoint(
    session: Any,
    *,
    attempts: int = 75,
    delay: float = 1.0,
) -> None:
    """Wait until the image entrypoint has finished all startup work."""
    last_error = "readiness marker not present"
    for attempt in range(1, attempts + 1):
        try:
            result = await session.exec(
                "test",
                "-f",
                _ENTRYPOINT_READY_FILE,
                timeout=5,
            )
            if result.ok():
                return
            last_error = f"test exited with status {result.exit_code}"
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        logger.debug(
            "Sandbox entrypoint readiness attempt %d/%d failed: %s",
            attempt,
            attempts,
            last_error,
        )
        if attempt < attempts:
            await asyncio.sleep(delay)

    raise RuntimeError(
        f"Sandbox entrypoint did not become ready after {attempts} attempts: {last_error}"
    )


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, str]],
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry mounts its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container.
    """
    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    entries: dict[str | Path, BaseEntry] = {}
    workspace_mounts = []  # Track mounts for RE tools path resolution

    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue

        # Check if this is a file (for malware_sample) or directory
        is_file = src.get("is_file", False)
        logger.debug(
            "Mounting %s: ws_subdir=%s, host_path=%s, is_file=%s",
            "file" if is_file else "directory",
            ws_subdir,
            host_path,
            is_file,
        )

        resolved_host_path = str(Path(host_path).expanduser().resolve())
        if is_file:
            entries[ws_subdir] = LocalFile(src=Path(resolved_host_path))
        else:
            entries[ws_subdir] = LocalDir(src=Path(resolved_host_path))

        # Track mount for path resolution (used by RE tools running on host)
        workspace_mounts.append(f"{ws_subdir}:{resolved_host_path}")

    # mitmproxy runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # agent-browser CDP daemon's localhost traffic from looping back
    # through the proxy.
    container_proxy_url = f"http://127.0.0.1:{_CONTAINER_MITM_PROXY_PORT}"
    container_control_url = f"http://127.0.0.1:{_CONTAINER_MITM_CONTROL_PORT}"

    # Detect scan mode for security hardening
    settings = load_settings()
    scan_mode = "deep"  # Default

    # Try to infer scan_mode from local_sources (may have malware_sample type)
    for src in local_sources:
        if src.get("type") == "malware_sample":
            scan_mode = "malware_re"
            break
        if src.get("type") == "ctf_challenge":
            scan_mode = "ctf"
            break

    # Build environment variables
    env_vars: dict[str, str | EnvEntry | EnvValue] = {
        "PYTHONUNBUFFERED": "1",
        "HOST_GATEWAY": "host.docker.internal",
        "http_proxy": container_proxy_url,
        "https_proxy": container_proxy_url,
        "HTTP_PROXY": container_proxy_url,
        "HTTPS_PROXY": container_proxy_url,
        "ALL_PROXY": container_proxy_url,
        "KAEL_MITM_CONTROL_URL": container_control_url,
        "NO_PROXY": "localhost,127.0.0.1",
        "KAEL_SCAN_MODE": scan_mode,  # Signal to docker_client for hardening
        "AGENT_BROWSER_ENCRYPTION_KEY": secrets.token_hex(32),
    }

    # Add RE settings for malware_re mode
    if scan_mode == "malware_re":
        env_vars["KAEL_RE_NETWORK_MODE"] = settings.reverse_engineering.re_network_mode
        env_vars["KAEL_RE_MAX_RUNTIME_SEC"] = str(settings.reverse_engineering.re_max_runtime_sec)
        logger.info(
            "Malware RE mode detected, network_mode=%s",
            settings.reverse_engineering.re_network_mode,
        )

    # Add workspace mounts for RE tools path resolution (workspace_name:host_path,...)
    if workspace_mounts:
        mounts_str = ",".join(workspace_mounts)
        env_vars["KAEL_WORKSPACE_MOUNTS"] = mounts_str
        # Also set on the host process so function tools can access it
        # (function tools run on the host, not in the container)
        os.environ["KAEL_WORKSPACE_MOUNTS"] = mounts_str
        logger.debug("Set KAEL_WORKSPACE_MOUNTS (container + host): %s", mounts_str)

    manifest = Manifest(
        entries=entries,
        environment=Environment(value=env_vars),
    )

    backend_name = load_settings().runtime.backend
    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )
    client, session = await create_docker_session(
        image=image,
        manifest=manifest,
        exposed_ports=(_CONTAINER_MITM_CONTROL_PORT,),
    )

    try:
        await _wait_for_entrypoint(session)
        control_endpoint = await session.resolve_exposed_port(_CONTAINER_MITM_CONTROL_PORT)
        host_control_url = f"http://{control_endpoint.host}:{control_endpoint.port}"
        logger.debug("mitmproxy control endpoint resolved: %s", host_control_url)

        mitm_client = await bootstrap_mitmproxy(
            host_url=host_control_url,
            container_url=container_control_url,
        )
    except Exception:
        logger.exception("Sandbox startup failed for scan %s; deleting container", scan_id)
        os.environ.pop("KAEL_WORKSPACE_MOUNTS", None)
        try:
            await client.delete(session)
        except Exception:  # noqa: BLE001
            logger.exception(
                "Could not delete failed sandbox for scan %s; container may need manual reaping",
                scan_id,
            )
        raise

    bundle = {
        "client": client,
        "session": session,
        "mitm_client": mitm_client,
    }
    _SESSION_CACHE[scan_id] = bundle
    logger.info("Sandbox session for scan %s ready and cached", scan_id)
    return bundle


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Best-effort: any error during ``client.delete`` is logged and
    swallowed. We never want a cleanup failure to prevent the next
    scan from starting; the worst case is a stranded container that
    Docker's normal reaping will catch on next ``docker prune``.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
        return

    # Clean up host environment variable
    os.environ.pop("KAEL_WORKSPACE_MOUNTS", None)

    mitm_client = bundle.get("mitm_client")
    if mitm_client is not None:
        try:
            await mitm_client.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): mitm_client.aclose() raised", scan_id, exc_info=True)

    try:
        await bundle["client"].delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        logger.exception(
            "cleanup(%s): client.delete raised; container may need manual reaping",
            scan_id,
        )
