"""Sandbox detonation tool."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from agents.tool import function_tool

from ._path_resolver import ensure_host_path


def get_sample_hash(sample_path: str) -> str:
    """Calculate SHA256 hash of sample."""
    sha256 = hashlib.sha256()
    with open(sample_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def can_run_on_platform(sample_path: str) -> tuple[bool, str]:
    """Check if sample can be executed on this platform."""
    if not Path(sample_path).is_file():
        return False, "Invalid sample path"
    try:
        result = subprocess.run(
            ["file", "-b", sample_path], capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or "File type detection failed"
        file_type = result.stdout.strip()

        if "PE32" in file_type or "PE64" in file_type:
            # Check for Wine
            wine_check = subprocess.run(["wine64", "--version"], capture_output=True)
            if wine_check.returncode == 0:
                return True, "wine64"
            return False, "PE binary requires wine64"

        if "ELF" in file_type:
            # Check architecture match
            if "x86-64" in file_type or "x86_64" in file_type:
                return True, "native"
            if "ARM" in file_type or "aarch64" in file_type:
                # Check for qemu-user
                qemu_check = subprocess.run(
                    ["qemu-aarch64-static", "--version"], capture_output=True
                )
                if qemu_check.returncode == 0:
                    return True, "qemu-aarch64-static"
                return False, "ARM binary requires qemu-aarch64-static"
            return True, "native"

        if "script" in file_type.lower():
            if "Python" in file_type:
                return True, "python3"
            if "shell" in file_type.lower() or "bash" in file_type.lower():
                return True, "bash"
            return True, "native"

        return True, "native"

    except Exception as e:
        return False, f"Failed to detect file type: {e!s}"


@contextmanager
def traffic_capture(pcap_path: str, network_mode: str) -> Iterator[subprocess.Popen | None]:
    """Start tcpdump to capture network traffic."""
    proc = None
    try:
        if network_mode != "off":
            # Start tcpdump
            proc = subprocess.Popen(
                ["tcpdump", "-i", "any", "-U", "-w", pcap_path, "not host 127.0.0.1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.5)  # Give tcpdump time to start
        yield proc
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


@contextmanager
def iptables_restore() -> Iterator[None]:
    """Save and restore iptables rules."""
    saved_rules = None
    try:
        result = subprocess.run(["iptables-save"], capture_output=True, text=True)
        if result.returncode == 0:
            saved_rules = result.stdout
        yield
    finally:
        if saved_rules:
            try:
                subprocess.run(["iptables-restore"], input=saved_rules, text=True)
            except Exception:
                pass


def setup_network_restrictions(network_mode: str, blocked_cidrs: list[str]) -> None:
    """Configure network restrictions via iptables."""
    if network_mode == "controlled":
        # Block specified CIDRs
        for cidr in blocked_cidrs:
            try:
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", cidr, "-j", "DROP"], check=False)
            except Exception:
                pass

        # Log all outbound connections
        try:
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-j", "LOG", "--log-prefix", "KAEL_NET: "], check=False
            )
        except Exception:
            pass


def snapshot_filesystem() -> dict:
    """Take a snapshot of filesystem state."""
    snapshot = {}
    # These are deliberately observed inside the isolated malware sandbox.
    paths_to_check = ["/tmp", "/var/tmp"]

    for base_path in paths_to_check:
        if not os.path.exists(base_path):
            continue
        try:
            for root, _dirs, files in os.walk(base_path):
                for file in files:
                    try:
                        filepath = os.path.join(root, file)
                        stat = os.stat(filepath)
                        snapshot[filepath] = {"size": stat.st_size, "mtime": stat.st_mtime}
                    except Exception:
                        continue
        except Exception:
            continue

    return snapshot


def diff_filesystem(before: dict, output_dir: Path) -> dict:
    """Compare filesystem before and after."""
    after = snapshot_filesystem()

    changes = {"created": [], "modified": [], "deleted": []}

    # Find created and modified files
    for path, after_info in after.items():
        if path not in before:
            changes["created"].append(path)
        elif before[path]["mtime"] != after_info["mtime"]:
            changes["modified"].append(path)

    # Find deleted files
    for path in before:
        if path not in after:
            changes["deleted"].append(path)

    return changes


def parse_strace_log(strace_path: str) -> dict:
    """Parse strace output for interesting syscalls."""
    if not os.path.exists(strace_path):
        return {"error": "strace log not found"}

    syscalls = {
        "summary": {},
        "interesting": {
            "process_injection": [],
            "persistence": [],
            "code_execution": [],
            "network": [],
        },
    }

    try:
        # For strace -ff, we may have multiple files (strace.log.PID)
        strace_files = []
        strace_dir = os.path.dirname(strace_path)
        strace_base = os.path.basename(strace_path)

        if os.path.isfile(strace_path):
            strace_files.append(strace_path)

        # Find all strace.log.* files
        for file in os.listdir(strace_dir):
            if file.startswith(strace_base + "."):
                strace_files.append(os.path.join(strace_dir, file))

        for strace_file in strace_files[:10]:  # Limit to first 10 files
            with open(strace_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Count syscalls
                    if "(" in line:
                        syscall = line.split("(")[0].strip().split()[-1]
                        syscalls["summary"][syscall] = syscalls["summary"].get(syscall, 0) + 1

                    # Look for interesting patterns
                    if "process_vm_writev" in line or "ptrace" in line:
                        syscalls["interesting"]["process_injection"].append(line[:200])
                    elif "execve" in line:
                        syscalls["interesting"]["code_execution"].append(line[:200])
                    elif "connect" in line or "sendto" in line:
                        syscalls["interesting"]["network"].append(line[:200])
                    elif "open" in line and (
                        ".bashrc" in line or ".profile" in line or "autostart" in line
                    ):
                        syscalls["interesting"]["persistence"].append(line[:200])
    except Exception as e:
        syscalls["error"] = str(e)

    return syscalls


def sandbox_detonate_sync(
    sample_path: str,
    timeout: int = 60,
    network_mode: str = "controlled",
    snapshot_memory: bool = False,
    quick_mode: bool = False,
) -> str:
    """Synchronous sandbox detonation implementation."""

    # Resolve container path to host path
    success, resolved_path, error = ensure_host_path(sample_path)
    if not success:
        return json.dumps(
            {
                "success": False,
                "error": error,
                "original_path": sample_path,
            }
        )

    sample_path = resolved_path

    # Check file size
    sample_size = os.path.getsize(sample_path)
    if sample_size > 500 * 1024 * 1024:  # 500 MB
        return json.dumps(
            {
                "success": False,
                "error": f"Sample too large: {sample_size / (1024 * 1024):.1f} MB (max 500 MB)",
            }
        )

    # Check if we can run this sample
    can_run, reason = can_run_on_platform(sample_path)
    if not can_run:
        return json.dumps({"success": False, "error": f"Cannot run sample: {reason}"})

    # Check for bwrap
    bwrap_check = subprocess.run(["bwrap", "--version"], capture_output=True)
    if bwrap_check.returncode != 0:
        return json.dumps({"success": False, "error": "bubblewrap not available"})

    # Setup output directory
    sample_hash = get_sample_hash(sample_path)
    output_dir = Path(f"/workspace/.re-runs/{sample_hash}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Take filesystem snapshot
    fs_before = snapshot_filesystem()

    # Prepare paths
    pcap_path = str(output_dir / "traffic.pcap")
    strace_path = str(output_dir / "strace.log")
    ltrace_path = str(output_dir / "ltrace.log")
    report_path = str(output_dir / "report.json")

    start_time = time.time()
    execution_result = {}

    try:
        # Start traffic capture and configure network
        with traffic_capture(pcap_path, network_mode):
            with iptables_restore():
                if network_mode == "controlled":
                    # Get blocked CIDRs from config (for now, use empty list)
                    setup_network_restrictions(network_mode, [])

                # Build bwrap command with maximum isolation
                bwrap_cmd = [
                    "bwrap",
                    # Namespace isolation
                    "--unshare-user",  # New user namespace (malware runs as nobody)
                    "--unshare-pid",  # New PID namespace (can't see host processes)
                    "--unshare-net",  # New network namespace (fully isolated unless we create interfaces)
                    "--unshare-ipc",  # New IPC namespace (no shared memory access)
                    "--unshare-uts",  # New hostname namespace
                    "--unshare-cgroup",  # New cgroup namespace
                    # Filesystem: read-only root, writable work dir only
                    "--ro-bind",
                    "/",
                    "/",
                    "--bind",
                    str(output_dir),
                    "/work",
                    "--tmpfs",
                    "/tmp",
                    "--tmpfs",
                    "/var/tmp",
                    "--tmpfs",
                    "/home",
                    "--tmpfs",
                    "/run",
                    # Process controls
                    "--die-with-parent",  # Kill sandbox if parent dies
                    "--new-session",  # New session ID (can't send signals to parent)
                    # Security: drop all capabilities
                    "--cap-drop",
                    "ALL",
                    # Prevent new privileges
                    "--unsetenv",
                    "LD_PRELOAD",
                    "--unsetenv",
                    "LD_LIBRARY_PATH",
                    # Set minimal environment
                    "--setenv",
                    "PATH",
                    "/usr/local/bin:/usr/bin:/bin",
                    "--setenv",
                    "HOME",
                    "/tmp",
                    "--setenv",
                    "TMPDIR",
                    "/tmp",
                ]

                # Add tracing
                if not quick_mode:
                    bwrap_cmd.extend(
                        ["strace", "-ff", "-ttt", "-e", "trace=all", "-o", "/work/strace.log"]
                    )
                    bwrap_cmd.extend(["ltrace", "-f", "-o", "/work/ltrace.log", "-l", "*", "--"])

                # Add runner
                bwrap_cmd.extend(
                    [
                        "/opt/kael-re/re_runner.py",
                        sample_path,
                        "--timeout",
                        str(timeout),
                        "--output",
                        "/work/report.json",
                    ]
                )

                # Execute
                try:
                    proc = subprocess.run(
                        bwrap_cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout + 10,  # Give extra time for cleanup
                    )
                    execution_result["exit_status"] = proc.returncode
                    execution_result["stdout"] = proc.stdout[:1000]
                    execution_result["stderr"] = proc.stderr[:1000]
                except subprocess.TimeoutExpired:
                    execution_result["exit_status"] = "timeout"
                    execution_result["timed_out"] = True

    except Exception as e:
        return json.dumps({"success": False, "error": f"Detonation failed: {e!s}"})

    duration = time.time() - start_time

    # Post-detonation analysis
    fs_changes = diff_filesystem(fs_before, output_dir)

    # Parse strace logs
    syscalls = {}
    if os.path.exists(strace_path) or any(
        f.startswith("strace.log.") for f in os.listdir(output_dir)
    ):
        syscalls = parse_strace_log(strace_path)

    # Load runner report if available
    runner_report = {}
    if os.path.exists(report_path):
        try:
            with open(report_path) as f:
                runner_report = json.load(f)
        except Exception:
            pass

    # Check for network activity in PCAP
    network_info = {
        "pcap_path": pcap_path if os.path.exists(pcap_path) else None,
        "pcap_size_bytes": os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0,
    }

    # Build final report
    result = {
        "success": True,
        "sample_hash": sample_hash,
        "output_dir": str(output_dir),
        "execution": {
            "duration_sec": round(duration, 2),
            "exit_status": execution_result.get("exit_status", "unknown"),
            "command": " ".join(bwrap_cmd),
            "runner_report": runner_report,
        },
        "filesystem_changes": fs_changes,
        "network": network_info,
        "syscalls": syscalls,
        "artifacts": {
            "strace_log": strace_path if os.path.exists(strace_path) else None,
            "ltrace_log": ltrace_path if os.path.exists(ltrace_path) else None,
            "pcap": pcap_path if os.path.exists(pcap_path) else None,
            "report_json": report_path if os.path.exists(report_path) else None,
        },
    }

    return json.dumps(result, indent=2)


@function_tool(timeout=180)
async def sandbox_detonate(
    sample_path: str,
    timeout: int = 60,
    network_mode: str = "controlled",
    snapshot_memory: bool = False,
    quick_mode: bool = False,
) -> str:
    """Detonate sample in isolated bwrap sandbox with forensic capture.

    Args:
        sample_path: Path to the sample to execute
        timeout: Execution timeout in seconds (default: 60)
        network_mode: Network isolation mode - "off", "controlled", or "live" (default: "controlled")
        snapshot_memory: Whether to capture memory dumps (default: False)
        quick_mode: Skip ltrace/strace for faster execution (default: False)

    Returns:
        JSON string with execution results, filesystem changes, network activity, and syscalls
    """
    return await asyncio.to_thread(
        sandbox_detonate_sync,
        sample_path,
        timeout,
        network_mode,
        snapshot_memory,
        quick_mode,
    )
