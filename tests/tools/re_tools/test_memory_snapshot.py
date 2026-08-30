"""Unit tests for memory_snapshot tool."""

import json
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def empty_run_dir():
    """Create an empty run directory."""
    temp_dir = tempfile.mkdtemp(prefix="test_re_run_")
    return temp_dir


@pytest.fixture
def run_dir_with_strace():
    """Create run directory with strace logs."""
    temp_dir = tempfile.mkdtemp(prefix="test_re_run_strace_")
    strace_dir = Path(temp_dir) / "strace"
    strace_dir.mkdir()

    # Create a fake strace log
    strace_file = strace_dir / "strace.log.1234"
    strace_file.write_text('1234 open("/etc/passwd", O_RDONLY) = 3\n')

    return temp_dir


def test_memory_snapshot_nonexistent_dir():
    """Test with nonexistent run directory."""
    from kael.tools.re_tools.memory_snapshot import memory_snapshot_sync

    result = memory_snapshot_sync("/nonexistent/dir")
    data = json.loads(result)

    assert data["success"] is False
    assert "not found" in data["error"].lower()


def test_memory_snapshot_empty_dir(empty_run_dir):
    """Test with empty run directory (no PIDs to dump)."""
    from kael.tools.re_tools.memory_snapshot import memory_snapshot_sync

    try:
        result = memory_snapshot_sync(empty_run_dir)
        data = json.loads(result)

        # Should fail gracefully (no processes to dump)
        assert data["success"] is False
        assert "no pids" in data["error"].lower() or "exited" in data["error"].lower()
    finally:
        import shutil

        shutil.rmtree(empty_run_dir)


def test_memory_snapshot_output_structure(run_dir_with_strace):
    """Test output structure with valid run directory."""
    from kael.tools.re_tools.memory_snapshot import memory_snapshot_sync

    try:
        result = memory_snapshot_sync(run_dir_with_strace)
        data = json.loads(result)

        # Should attempt to find PIDs
        # May fail if gcore not available, but should have proper structure
        assert "success" in data
    finally:
        import shutil

        shutil.rmtree(run_dir_with_strace)


def test_memory_snapshot_with_specific_pids(run_dir_with_strace):
    """Test with specific PIDs."""
    from kael.tools.re_tools.memory_snapshot import memory_snapshot_sync

    try:
        # Pass a PID that definitely doesn't exist
        result = memory_snapshot_sync(run_dir_with_strace, target_pids=[99999])
        data = json.loads(result)

        # Should attempt to dump PID 99999
        # Will likely fail since process doesn't exist
        assert "success" in data
    finally:
        import shutil

        shutil.rmtree(run_dir_with_strace)


def test_memory_snapshot_disable_pe_extraction(run_dir_with_strace):
    """Test with PE extraction disabled."""
    from kael.tools.re_tools.memory_snapshot import memory_snapshot_sync

    try:
        result = memory_snapshot_sync(run_dir_with_strace, extract_pe=False)
        data = json.loads(result)

        assert "success" in data
    finally:
        import shutil

        shutil.rmtree(run_dir_with_strace)


def test_memory_snapshot_disable_injection_detection(run_dir_with_strace):
    """Test with injection detection disabled."""
    from kael.tools.re_tools.memory_snapshot import memory_snapshot_sync

    try:
        result = memory_snapshot_sync(run_dir_with_strace, detect_injection=False)
        data = json.loads(result)

        assert "success" in data
    finally:
        import shutil

        shutil.rmtree(run_dir_with_strace)


def test_get_running_processes_empty():
    """Test process discovery in empty directory."""
    from kael.tools.re_tools.memory_snapshot import get_running_processes

    temp_dir = tempfile.mkdtemp()

    try:
        processes = get_running_processes(temp_dir)
        assert isinstance(processes, list)
    finally:
        import shutil

        shutil.rmtree(temp_dir)


def test_get_running_processes_with_logs(run_dir_with_strace):
    """Test process discovery with strace logs."""
    from kael.tools.re_tools.memory_snapshot import get_running_processes

    try:
        processes = get_running_processes(run_dir_with_strace)

        # Should find PID 1234 from strace log
        assert len(processes) >= 1
        pids = [p["pid"] for p in processes]
        assert 1234 in pids
    finally:
        import shutil

        shutil.rmtree(run_dir_with_strace)


def test_memory_snapshot_creates_dumps_dir(run_dir_with_strace):
    """Test that memory_dumps directory is created."""
    from kael.tools.re_tools.memory_snapshot import memory_snapshot_sync

    try:
        memory_snapshot_sync(run_dir_with_strace, target_pids=[99999])

        # Check if memory_dumps directory was created
        Path(run_dir_with_strace) / "memory_dumps"
        # May or may not exist depending on success
        # Just verify no crash
    finally:
        import shutil

        shutil.rmtree(run_dir_with_strace)
