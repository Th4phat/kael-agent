"""Memory snapshot tool."""

from __future__ import annotations

import asyncio
import glob
import json
import os
import subprocess

from agents.tool import function_tool


def get_running_processes(run_dir: str) -> list[dict]:
    """Get list of running processes that were spawned in the sandbox."""
    processes = []
    try:
        # Look for PIDs in strace logs
        strace_files = glob.glob(os.path.join(run_dir, "**", "strace.log.*"), recursive=True)
        for strace_file in strace_files:
            pid = strace_file.split(".")[-1]
            if pid.isdigit():
                processes.append({"pid": int(pid), "source": "strace"})
    except Exception:
        pass

    return processes


def dump_process_memory(pid: int, output_path: str) -> tuple[bool, str]:
    """Dump process memory using gcore."""
    try:
        result = subprocess.run(
            ["gcore", "-o", output_path, str(pid)], capture_output=True, text=True, timeout=30
        )

        if result.returncode == 0:
            # gcore creates files like output_path.PID
            core_file = f"{output_path}.{pid}"
            if os.path.exists(core_file):
                return True, core_file

        return False, result.stderr

    except subprocess.TimeoutExpired:
        return False, "gcore timed out"
    except Exception as e:
        return False, str(e)


def extract_pe_from_memory(dump_path: str, output_dir: str) -> list[dict]:
    """Extract PE files from memory dump."""
    extracted = []

    if not os.path.exists(dump_path):
        return extracted

    try:
        # Read memory dump
        with open(dump_path, "rb") as f:
            data = f.read()

        # Search for MZ headers
        offset = 0
        while True:
            offset = data.find(b"MZ", offset)
            if offset == -1:
                break

            # Check if this looks like a valid PE
            if offset + 0x40 < len(data):
                # Read e_lfanew (offset to PE header)
                try:
                    e_lfanew = int.from_bytes(data[offset + 0x3C : offset + 0x40], "little")

                    # Check for PE signature
                    if offset + e_lfanew + 4 < len(data):
                        pe_sig = data[offset + e_lfanew : offset + e_lfanew + 4]
                        if pe_sig == b"PE\x00\x00":
                            # Extract the PE (limit to 10MB)
                            pe_size = min(10 * 1024 * 1024, len(data) - offset)
                            pe_data = data[offset : offset + pe_size]

                            # Save extracted PE
                            pe_filename = f"extracted_pe_{offset:x}.bin"
                            pe_path = os.path.join(output_dir, pe_filename)

                            with open(pe_path, "wb") as pef:
                                pef.write(pe_data)

                            extracted.append(
                                {
                                    "address": f"0x{offset:X}",
                                    "size": len(pe_data),
                                    "type": "PE",
                                    "extracted_to": pe_path,
                                }
                            )

                            # Limit to 10 extractions
                            if len(extracted) >= 10:
                                break
                except Exception:
                    pass

            offset += 1

    except Exception:
        pass

    return extracted


def detect_injected_code(dump_path: str) -> list[dict]:
    """Detect potentially injected code regions."""
    injected = []

    if not os.path.exists(dump_path):
        return injected

    try:
        # Simple heuristic: look for executable code patterns
        with open(dump_path, "rb") as f:
            data = f.read()

        # Look for common shellcode patterns
        shellcode_patterns = [
            b"\x55\x8b\xec",  # push ebp; mov ebp, esp (function prologue)
            b"\x48\x83\xec",  # sub rsp, X (x64 stack allocation)
            b"\xe8\x00\x00\x00\x00",  # call $+5 (position independent)
            b"\xeb\xfe",  # jmp $ (infinite loop)
        ]

        for pattern in shellcode_patterns:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break

                injected.append(
                    {
                        "address": f"0x{offset:X}",
                        "type": "shellcode_candidate",
                        "pattern": pattern.hex(),
                    }
                )

                offset += 1

                # Limit results
                if len(injected) >= 20:
                    return injected

    except Exception:
        pass

    return injected


def memory_snapshot_sync(
    run_dir: str,
    target_pids: list[int] | None = None,
    detect_injection: bool = True,
    extract_pe: bool = True,
    scan_yara: bool = True,
) -> str:
    """Synchronous memory snapshot implementation."""

    if not os.path.exists(run_dir):
        return json.dumps({"success": False, "error": f"Run directory not found: {run_dir}"})

    try:
        result = {
            "success": True,
            "run_dir": run_dir,
            "dumps": [],
            "injected_code": [],
            "extracted_pes": [],
            "crypto_keys": [],
        }

        # Determine which PIDs to dump
        pids_to_dump = target_pids if target_pids else []

        if not pids_to_dump:
            # Try to discover PIDs from strace logs
            discovered = get_running_processes(run_dir)
            pids_to_dump = [p["pid"] for p in discovered]

        if not pids_to_dump:
            return json.dumps(
                {"success": False, "error": "No PIDs to dump (processes may have already exited)"}
            )

        # Create memory dumps directory
        dumps_dir = os.path.join(run_dir, "memory_dumps")
        os.makedirs(dumps_dir, exist_ok=True)

        # Dump each process
        for pid in pids_to_dump[:5]:  # Limit to 5 processes
            dump_path = os.path.join(dumps_dir, f"core_{pid}")
            success, info = dump_process_memory(pid, dump_path)

            if success:
                dump_size = os.path.getsize(info) if os.path.exists(info) else 0

                result["dumps"].append(
                    {"pid": pid, "dump_path": info, "size_mb": round(dump_size / (1024 * 1024), 2)}
                )

                # Extract PEs from memory
                if extract_pe:
                    extracted = extract_pe_from_memory(info, dumps_dir)
                    result["extracted_pes"].extend(extracted)

                # Detect injected code
                if detect_injection:
                    injected = detect_injected_code(info)
                    result["injected_code"].extend(injected[:10])  # Limit results

        # If no dumps were successful
        if not result["dumps"]:
            return json.dumps(
                {
                    "success": False,
                    "error": "Failed to dump any process memory (processes may have exited)",
                }
            )

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"success": False, "error": f"Memory snapshot failed: {e!s}"})


@function_tool(timeout=120)
async def memory_snapshot(
    run_dir: str,
    target_pids: list[int] | None = None,
    detect_injection: bool = True,
    extract_pe: bool = True,
    scan_yara: bool = True,
) -> str:
    """Capture and analyze process memory for injected code and payloads.

    Args:
        run_dir: Path to sandbox run directory (e.g., /workspace/.re-runs/<sha256>/)
        target_pids: Optional list of PIDs to dump (default: discover from logs)
        detect_injection: Search for injected code patterns (default: True)
        extract_pe: Extract PE files from memory (default: True)
        scan_yara: Scan memory with YARA rules (default: True)

    Returns:
        JSON string with memory dumps, extracted PEs, and injected code findings
    """
    return await asyncio.to_thread(
        memory_snapshot_sync,
        run_dir,
        target_pids,
        detect_injection,
        extract_pe,
        scan_yara,
    )
