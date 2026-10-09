"""KaelDockerSandboxClient — preserves the image's ENTRYPOINT and adds
NET_ADMIN/NET_RAW capabilities + host-gateway.

The SDK's ``DockerSandboxClient._create_container`` does not expose a hook for
extending ``create_kwargs`` before ``containers.create`` is called. We subclass
and reimplement the method body verbatim from the SDK source, with three
deltas:

1. Drop the SDK's ``entrypoint=["tail"]`` override; supply ``["tail", "-f",
   "/dev/null"]`` as ``command`` instead. This lets our image's
   ``docker-entrypoint.sh`` actually run — without it, the mitmproxy sidecar
   never starts and its control endpoint remains unavailable.
2. Append NET_ADMIN/NET_RAW to ``cap_add`` (required by ``nmap -sS`` and
   other raw-socket tools).
3. Add ``host.docker.internal`` → host-gateway to ``extra_hosts`` so the
   agent can reach host-served apps.

Pinned to ``openai-agents==0.14.6``. Bumping the SDK requires
re-merging the parent body. Track upstream for an injection hook.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from typing import Any

from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient,
    _build_docker_volume_mounts,
    _docker_port_key,
    _manifest_requires_fuse,
    _manifest_requires_sys_admin,
)
from agents.sandbox.session.sandbox_session import SandboxSession
from docker import errors as docker_errors  # type: ignore[import-untyped, unused-ignore]
from docker.models.containers import Container  # type: ignore[import-untyped, unused-ignore]
from docker.utils import parse_repository_tag  # type: ignore[import-untyped, unused-ignore]

from kael.config import load_settings


logger = logging.getLogger(__name__)


class KaelDockerSandboxClient(DockerSandboxClient):
    async def _create_container(
        self,
        image: str,
        *,
        manifest: Manifest | None = None,
        exposed_ports: tuple[int, ...] = (),
        session_id: uuid.UUID | None = None,
    ) -> Container:
        # ----- BEGIN VERBATIM COPY of DockerSandboxClient._create_container -----
        # SDK ref: src/agents/sandbox/sandboxes/docker.py:1434-1477 (v0.14.6).
        if not self.image_exists(image):
            repo, tag = parse_repository_tag(image)
            self.docker_client.images.pull(repo, tag=tag or None, all_tags=False)

        assert self.image_exists(image)
        environment: dict[str, str] | None = None
        if manifest:
            environment = await manifest.environment.resolve()
        # Kael delta from the SDK body: drop ``entrypoint`` override and
        # supply ``tail -f /dev/null`` as ``command`` so the image's
        # ENTRYPOINT (``docker-entrypoint.sh``) runs setup, then ``exec
        # "$@"`` becomes ``exec tail -f /dev/null`` for the keep-alive.
        # Without this, mitmproxy + the in-container CA trust never get
        # initialized.
        create_kwargs: dict[str, Any] = {
            "image": image,
            "detach": True,
            "command": ["tail", "-f", "/dev/null"],
            "environment": environment,
        }
        if manifest is not None:
            docker_mounts = _build_docker_volume_mounts(
                manifest,
                session_id=session_id,
            )
            if docker_mounts:
                create_kwargs["mounts"] = docker_mounts
            if _manifest_requires_fuse(manifest):
                create_kwargs.update(
                    devices=["/dev/fuse"],
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
            elif _manifest_requires_sys_admin(manifest):
                create_kwargs.update(
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
        if exposed_ports:
            create_kwargs["ports"] = {
                _docker_port_key(port): ("127.0.0.1", None) for port in exposed_ports
            }
        # ----- END VERBATIM COPY -----

        # Kael injections — append, don't overwrite, so FUSE/SYS_ADMIN survives.
        cap_add = create_kwargs.setdefault("cap_add", [])
        if not isinstance(cap_add, list):
            cap_add = list(cap_add)
            create_kwargs["cap_add"] = cap_add
        for cap in ("NET_ADMIN", "NET_RAW"):
            if cap not in cap_add:
                cap_add.append(cap)

        extra_hosts = create_kwargs.setdefault("extra_hosts", {})
        extra_hosts["host.docker.internal"] = "host-gateway"

        # Rootless Podman prepends slirp4netns's 10.0.2.3 to the host's
        # resolv.conf; with unreachable host resolvers ahead of the working
        # one, glibc's 3-nameserver limit leaves the sandbox unable to
        # resolve anything and mitmproxy answers every request with 502.
        dns_setting = load_settings().runtime.sandbox_dns or ""
        if dns := [d.strip() for d in dns_setting.split(",") if d.strip()]:
            create_kwargs["dns"] = dns

        # Malware RE hardening: drop all capabilities except NET_ADMIN/NET_RAW/SYS_ADMIN
        # Check if this is a malware_re session by looking at manifest environment
        is_malware_re = False
        if manifest and manifest.environment:
            env = await manifest.environment.resolve()
            is_malware_re = env.get("KAEL_SCAN_MODE") == "malware_re"

        if is_malware_re:
            logger.warning("🔒 MALWARE RE MODE: Applying security hardening")

            # Drop all default capabilities except what we explicitly need
            create_kwargs["cap_drop"] = ["ALL"]

            # Re-add only essential capabilities
            # NET_ADMIN/NET_RAW: for network analysis (tcpdump, traffic capture)
            # SYS_ADMIN: only if manifest requires it (FUSE mounts)
            essential_caps = ["NET_ADMIN", "NET_RAW"]
            if "SYS_ADMIN" in cap_add:
                essential_caps.append("SYS_ADMIN")
            create_kwargs["cap_add"] = essential_caps

            # Enable read-only root filesystem
            create_kwargs["read_only"] = True

            # Add writable tmpfs for /tmp (malware needs somewhere to write)
            if "tmpfs" not in create_kwargs:
                create_kwargs["tmpfs"] = {}
            # These are paths inside the isolated container, not host temp files.
            create_kwargs["tmpfs"]["/tmp"] = "rw,noexec,nosuid,size=512m"
            create_kwargs["tmpfs"]["/var/tmp"] = "rw,noexec,nosuid,size=512m"
            create_kwargs["tmpfs"]["/workspace/.re-runs"] = "rw,nosuid,size=2g"
            create_kwargs["tmpfs"]["/workspace/.mitm"] = "rw,noexec,nosuid,size=256m"
            create_kwargs["tmpfs"]["/workspace/.agent-browser-screenshots"] = (
                "rw,noexec,nosuid,size=256m"
            )
            create_kwargs["tmpfs"]["/home/pentester/.mitmproxy"] = "rw,noexec,nosuid,size=64m"
            create_kwargs["tmpfs"]["/home/pentester/.pki"] = "rw,noexec,nosuid,size=64m"

            # Resource limits to prevent DoS
            create_kwargs["mem_limit"] = "4g"  # 4GB RAM limit
            create_kwargs["memswap_limit"] = "4g"  # No swap
            create_kwargs["cpu_quota"] = 200000  # 2 CPUs (200% of 100000 period)
            create_kwargs["pids_limit"] = 512  # Max 512 processes (prevents fork bombs)

            # Disable network by default (can be overridden by RE settings)
            env_network_mode = env.get("KAEL_RE_NETWORK_MODE", "off")
            if env_network_mode == "off":
                create_kwargs["network_mode"] = "none"
                logger.warning("🔒 Network disabled for malware analysis")

            # Security options
            security_opts = create_kwargs.get("security_opt", [])
            if not isinstance(security_opts, list):
                security_opts = list(security_opts)

            # Add seccomp profile to block dangerous syscalls
            # Using Docker's default profile which blocks ~44 dangerous syscalls
            if "apparmor:unconfined" not in security_opts:
                security_opts.append("seccomp=default")

            # No new privileges (prevents setuid escalation)
            security_opts.append("no-new-privileges=true")

            create_kwargs["security_opt"] = security_opts

            logger.info(
                "🔒 Malware RE hardening applied: caps=%s, read_only=True, "
                "mem=4g, cpus=2, pids=512, network=%s",
                essential_caps,
                env_network_mode,
            )

        logger.debug(
            "Creating sandbox container: image=%s caps=%s exposed_ports=%s",
            image,
            cap_add,
            list(exposed_ports),
        )
        container = self.docker_client.containers.create(**create_kwargs)
        logger.info(
            "Sandbox container created: id=%s image=%s",
            container.short_id if hasattr(container, "short_id") else "?",
            image,
        )
        return container

    async def delete(self, session: SandboxSession) -> SandboxSession:
        container_id = getattr(getattr(session._inner, "state", None), "container_id", None)
        if container_id:
            with contextlib.suppress(docker_errors.NotFound, docker_errors.APIError):
                self.docker_client.containers.get(container_id).kill()
        return await super().delete(session)
