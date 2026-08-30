"""Sandbox backend — Docker (Podman uses the same Docker-compatible client)."""

from __future__ import annotations

import logging

from agents.sandbox.manifest import Manifest
from agents.sandbox.session import SandboxSession

from kael.runtime.docker_client import KaelDockerSandboxClient


logger = logging.getLogger(__name__)


async def create_docker_session(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
) -> tuple[KaelDockerSandboxClient, SandboxSession]:
    """Bring up a session backed by Docker or any Docker-compatible runtime
    (Podman, rootless Podman via the docker socket, etc).

    ``session.start()`` materializes the manifest entries (LocalDir
    copies, mount setup) into the running container — the SDK's
    ``client.create()`` only builds the inner session object without
    applying the manifest. ``async with session:`` would call it too,
    but Kael manages session lifetime explicitly via ``client.delete()``
    so we trigger ``start()`` ourselves.
    """
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from kael.interface.utils import get_container_client

    client = KaelDockerSandboxClient(get_container_client())
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session
