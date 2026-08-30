"""Path resolver for RE tools - converts container paths to host paths."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_container_path_to_host(container_path: str) -> str | None:
    """Convert a container path like /workspace/sample to the actual host path.

    RE tools run on the HOST (not in the container), so they need to access
    files via their actual host filesystem paths. However, the agent sees
    container paths (e.g., /workspace/sample_helper).

    This function maps container paths back to host paths by reading the
    scan configuration.

    Args:
        container_path: Path as seen inside container (e.g., /workspace/sample_helper)

    Returns:
        Host filesystem path, or None if not found
    """
    # The agent stores workspace mounts in an environment variable during scan
    # For now, we'll use a simpler approach: check if the file exists as-is,
    # and if not, try to infer the host path from the container path

    # First, check if the path exists as-is (might be running in container)
    if os.path.exists(container_path):
        return container_path

    # Container paths start with /workspace/
    if not container_path.startswith("/workspace/"):
        return container_path if os.path.exists(container_path) else None

    # Extract the workspace subdirectory name
    # Example: /workspace/sample_helper -> sample_helper
    workspace_subdir = container_path.replace("/workspace/", "").split("/")[0]

    # Try to resolve via environment variable if available
    # The agent framework should set KAEL_WORKSPACE_MOUNTS in the format:
    # "workspace_subdir1:host_path1,workspace_subdir2:host_path2,..."
    mounts_env = os.environ.get("KAEL_WORKSPACE_MOUNTS", "")
    if mounts_env:
        for mount in mounts_env.split(","):
            if ":" in mount:
                ws_name, host_path = mount.split(":", 1)
                if ws_name == workspace_subdir:
                    # Rebuild the full path with the host base
                    relative_path = container_path.replace(
                        f"/workspace/{workspace_subdir}", ""
                    ).lstrip("/")
                    if relative_path:
                        return str(Path(host_path) / relative_path)
                    return host_path

    # Fallback: return None to indicate path not found
    return None


def ensure_host_path(container_path: str) -> tuple[bool, str, str | None]:
    """Ensure we have a valid host path for file access.

    Args:
        container_path: Path as provided by agent (might be container or host path)

    Returns:
        Tuple of (success, path_to_use, error_message)
        - success: True if path was resolved successfully
        - path_to_use: The host path to use for file operations
        - error_message: Error description if success=False, None otherwise
    """
    resolved = resolve_container_path_to_host(container_path)

    if resolved is None:
        return (
            False,
            container_path,
            f"Cannot resolve container path to host: {container_path}. "
            "File may not be mounted or path is invalid.",
        )

    if not os.path.exists(resolved):
        return (
            False,
            resolved,
            f"Resolved path does not exist: {resolved} (from container path: {container_path})",
        )

    return (True, resolved, None)
