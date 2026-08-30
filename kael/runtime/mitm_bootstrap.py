"""Host-side bootstrap for the in-container mitmproxy addon.

The mitmproxy addon does
not need any GraphQL handshake or cloud auth — the only thing the host
must do is wait for the control HTTP endpoint to come up, then return
a callable that the rest of the runtime can use to talk to the addon.

The returned ``MitmControl`` object is a thin wrapper around
:mod:`kael.tools.proxy.mitm_control` that:

- Exposes sync and async close methods. There are currently no persistent
  client resources to release, but the lifecycle hooks keep the session
  manager interface explicit.
- Surfaces a ``health()`` method for the entrypoint.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from kael.tools.proxy import mitm_control


logger = logging.getLogger(__name__)


class MitmControl:
    """Lightweight handle on the in-container mitmproxy control endpoint.

    The actual HTTP calls are made by the module-level functions in
    :mod:`kael.tools.proxy.mitm_control`; this class is a marker that
    the host runtime can stash in the session bundle and that
    ``tools.py`` can pick up via ``_ctx_mitm(ctx)``.
    """

    def __init__(self, host_url: str, container_url: str) -> None:
        self.host_url = host_url
        self.container_url = container_url

    def health(self) -> bool:
        try:
            with httpx.Client(base_url=self.host_url, timeout=2.0) as client:
                r = client.get("/health")
                return r.status_code == 200 and r.json().get("status") == "ok"
        except (httpx.RequestError, ValueError):
            return False

    async def aclose(self) -> None:
        return None

    def close(self) -> None:
        return None


async def bootstrap_mitmproxy(
    *,
    host_url: str,
    container_url: str,
) -> MitmControl:
    """Wait for the in-container control endpoint, then return a handle.

    The retry loop doubles as the readiness probe: mitmdump may take a
    few seconds to generate its CA cert, install it, and bind the
    control port. We poll ``/health`` with exponential backoff up to
    ~30 s before giving up.
    """
    logger.info("Bootstrapping mitmproxy client (host=%s, container=%s)", host_url, container_url)

    last_err: str | None = None
    for attempt in range(1, 31):
        try:
            async with httpx.AsyncClient(base_url=host_url, timeout=2.0) as client:
                r = await client.get("/health")
                if r.status_code == 200 and r.json().get("status") == "ok":
                    logger.info("mitmproxy control endpoint ready on attempt %d", attempt)
                    return MitmControl(host_url=host_url, container_url=container_url)
                last_err = f"unexpected status {r.status_code}: {r.text[:200]}"
        except (httpx.RequestError, ValueError) as exc:
            last_err = str(exc) or exc.__class__.__name__
        logger.debug("mitm health attempt %d/30 failed: %s", attempt, last_err)
        await asyncio.sleep(1.0)

    raise RuntimeError(f"mitmproxy control endpoint did not become ready within ~30s: {last_err}")


# Re-export the public helpers from the control module so callers can
# ``from kael.runtime.mitm_bootstrap import list_flows`` if they want.
list_flows = mitm_control.list_flows
view_flow = mitm_control.view_flow
replay_flow = mitm_control.replay_flow
scope_rules = mitm_control.scope_rules
health = mitm_control.health
ahealth = mitm_control.ahealth
control_url = mitm_control.control_url
MitmControlError = mitm_control.MitmControlError
