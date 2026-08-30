#!/usr/bin/env python3
"""RE Runner - Executes malware samples inside bwrap sandbox.

This script runs inside the bubblewrap namespace and captures execution behavior.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time


class TimeoutException(Exception):
    """Raised when execution times out."""


def timeout_handler(signum, frame):
    """Signal handler for timeout."""
    raise TimeoutException("Execution timeout")


def detect_file_type(sample_path: str) -> dict:
    """Detect file type using the 'file' command."""
    try:
        result = subprocess.run(
            ["file", "-b", sample_path], capture_output=True, text=True, timeout=5
        )
        file_type = result.stdout.strip()

        return {
            "file_type": file_type,
            "is_pe": "PE32" in file_type or "PE64" in file_type,
            "is_elf": "ELF" in file_type,
            "is_script": "script" in file_type.lower(),
            "is_python": "Python" in file_type,
            "is_shell": "shell" in file_type.lower(),
        }
    except Exception as e:
        return {"file_type": "unknown", "error": str(e)}


def determine_execution_method(file_info: dict, sample_path: str) -> list[str]:
    """Determine how to execute the sample."""
    if file_info.get("is_pe"):
        # Try to run PE with Wine
        return ["wine64", sample_path]
    if file_info.get("is_elf"):
        # Make executable and run directly
        try:
            os.chmod(sample_path, 0o700)
        except Exception:
            pass
        return [sample_path]
    if file_info.get("is_python"):
        return ["python3", sample_path]
    if file_info.get("is_shell"):
        return ["bash", sample_path]
    # Try to execute directly
    try:
        os.chmod(sample_path, 0o700)
    except Exception:
        pass
    return [sample_path]


def execute_sample(sample_path: str, timeout_sec: int) -> dict:
    """Execute the sample and capture results."""
    result = {
        "exit_status": None,
        "stdout": "",
        "stderr": "",
        "execution_time_ms": 0,
        "timed_out": False,
        "error": None,
    }

    # Detect file type
    file_info = detect_file_type(sample_path)
    result["file_info"] = file_info

    # Determine execution method
    cmd = determine_execution_method(file_info, sample_path)
    result["command"] = " ".join(cmd)

    start_time = time.time()

    try:
        # Set up timeout signal
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout_sec)

        # Execute the sample
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)

        # Cancel the alarm
        signal.alarm(0)

        result["exit_status"] = proc.returncode
        result["stdout"] = proc.stdout[:10000]  # Limit output size
        result["stderr"] = proc.stderr[:10000]

    except subprocess.TimeoutExpired:
        result["timed_out"] = True
        result["error"] = f"Execution timed out after {timeout_sec}s"
    except TimeoutException:
        result["timed_out"] = True
        result["error"] = f"Execution timed out after {timeout_sec}s"
    except Exception as e:
        result["error"] = str(e)
        result["exit_status"] = -1
    finally:
        # Cancel alarm if still set
        signal.alarm(0)
        result["execution_time_ms"] = int((time.time() - start_time) * 1000)

    return result


def main():
    parser = argparse.ArgumentParser(description="Execute sample in sandbox")
    parser.add_argument("sample", help="Path to sample to execute")
    parser.add_argument("--timeout", type=int, default=60, help="Execution timeout in seconds")
    parser.add_argument("--output", default="/work/report.json", help="Output report path")
    args = parser.parse_args()

    # Verify sample exists
    if not os.path.exists(args.sample):
        result = {"success": False, "error": f"Sample not found: {args.sample}"}
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        return 1

    # Execute the sample
    result = execute_sample(args.sample, args.timeout)
    result["success"] = True

    # Write report
    try:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
    except Exception as e:
        print(f"Failed to write report: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
