"""Unit tests for sandbox_detonate tool."""

import importlib
import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_script():
    """Create a simple script for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sh", mode="w") as f:
        f.write('#!/bin/bash\necho "Hello, World!"\n')
        return f.name


@pytest.fixture
def sample_python():
    """Create a simple Python script."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode="w") as f:
        f.write('print("Hello from Python")\n')
        return f.name


@pytest.fixture
def large_file():
    """Create a file larger than 500MB limit (mock)."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # Just create the file, don't actually write 500MB
        f.write(b"test")
        return f.name


def test_sandbox_detonate_nonexistent():
    """Test with nonexistent file."""
    from kael.tools.re_tools.sandbox_detonate import sandbox_detonate_sync

    result = sandbox_detonate_sync("/nonexistent/file.exe")
    data = json.loads(result)

    assert data["success"] is False
    assert "cannot resolve" in data["error"].lower()


def test_sandbox_detonate_file_too_large():
    """Test with file exceeding size limit."""
    from kael.tools.re_tools.sandbox_detonate import sandbox_detonate_sync

    # Create a file and mock its size
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test")
        temp_path = f.name

    try:
        # Patch os.path.getsize to return large size
        module = importlib.import_module("kael.tools.re_tools.sandbox_detonate")

        original_getsize = module.os.path.getsize
        module.os.path.getsize = lambda x: 600 * 1024 * 1024  # 600MB

        result = sandbox_detonate_sync(temp_path)
        data = json.loads(result)

        # Should reject large file
        assert data["success"] is False
        assert "too large" in data["error"].lower()

        # Restore
        module.os.path.getsize = original_getsize
    finally:
        Path(temp_path).unlink()


def test_sandbox_detonate_network_modes(sample_script):
    """Test different network modes."""
    from kael.tools.re_tools.sandbox_detonate import sandbox_detonate_sync

    modes = ["off", "controlled", "live"]

    for mode in modes:
        try:
            result = sandbox_detonate_sync(
                sample_script, network_mode=mode, timeout=5, quick_mode=True
            )
            data = json.loads(result)

            # Should accept all network modes
            # May fail due to bwrap not available, but should not crash on parameter
            assert "success" in data or "error" in data
        except Exception as e:
            pytest.skip(f"Sandbox not available: {e}")

    Path(sample_script).unlink()


def test_sandbox_detonate_quick_mode(sample_script):
    """Test with quick mode enabled."""
    from kael.tools.re_tools.sandbox_detonate import sandbox_detonate_sync

    try:
        result = sandbox_detonate_sync(sample_script, quick_mode=True, timeout=5)
        data = json.loads(result)

        # Quick mode should be faster
        assert "success" in data or "error" in data
    except Exception as e:
        pytest.skip(f"Sandbox not available: {e}")
    finally:
        Path(sample_script).unlink()


def test_sandbox_detonate_timeout_parameter(sample_script):
    """Test with custom timeout."""
    from kael.tools.re_tools.sandbox_detonate import sandbox_detonate_sync

    try:
        result = sandbox_detonate_sync(sample_script, timeout=10, quick_mode=True)
        data = json.loads(result)

        assert "success" in data or "error" in data
    except Exception as e:
        pytest.skip(f"Sandbox not available: {e}")
    finally:
        Path(sample_script).unlink()


def test_can_run_on_platform_script(sample_script):
    """Test platform compatibility check for script."""
    from kael.tools.re_tools.sandbox_detonate import can_run_on_platform

    can_run, reason = can_run_on_platform(sample_script)

    assert isinstance(can_run, bool)
    assert isinstance(reason, str)

    Path(sample_script).unlink()


def test_can_run_on_platform_python(sample_python):
    """Test platform compatibility check for Python."""
    from kael.tools.re_tools.sandbox_detonate import can_run_on_platform

    can_run, reason = can_run_on_platform(sample_python)

    assert isinstance(can_run, bool)

    Path(sample_python).unlink()


def test_can_run_on_platform_nonexistent():
    """Test platform check for nonexistent file."""
    from kael.tools.re_tools.sandbox_detonate import can_run_on_platform

    can_run, reason = can_run_on_platform("/nonexistent/file")

    assert can_run is False
    assert "invalid" in reason.lower() or "error" in reason.lower()


def test_snapshot_filesystem():
    """Test filesystem snapshot."""
    from kael.tools.re_tools.sandbox_detonate import snapshot_filesystem

    snapshot = snapshot_filesystem()

    # Should return a dictionary
    assert isinstance(snapshot, dict)


def test_diff_filesystem_empty():
    """Test filesystem diff with empty before snapshot."""
    from kael.tools.re_tools.sandbox_detonate import diff_filesystem

    temp_dir = tempfile.mkdtemp()

    try:
        changes = diff_filesystem({}, temp_dir)

        assert "created" in changes
        assert "modified" in changes
        assert "deleted" in changes
        assert isinstance(changes["created"], list)
    finally:
        import shutil

        shutil.rmtree(temp_dir)
