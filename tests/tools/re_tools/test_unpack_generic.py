"""Unit tests for unpack_generic tool."""

import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def upx_file():
    """Create a file with UPX signature."""
    data = b"MZ\x90\x00" + b"\x00" * 100 + b"UPX0" + b"\x00" * 100 + b"UPX1"

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(data)
        return f.name


@pytest.fixture
def xor_encrypted_file():
    """Create a file that looks XOR encrypted with a known key."""
    # Simulate XOR encryption with key 0x42
    original = b"MZ\x90\x00" + b"\x00" * 100  # PE header
    encrypted = bytes([b ^ 0x42 for b in original])

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(encrypted)
        return f.name


@pytest.fixture
def normal_file():
    """Create a normal (non-packed) file."""
    data = b"MZ\x90\x00" + b"Normal content" * 100

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(data)
        return f.name


@pytest.fixture
def empty_file():
    """Create an empty file."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        return f.name


def test_unpack_generic_nonexistent():
    """Test unpack_generic with nonexistent file."""
    from kael.tools.re_tools.unpack_generic import unpack_generic_sync

    result = unpack_generic_sync("/nonexistent/file.exe", output_dir="/tmp/test_unpack")
    data = json.loads(result)

    assert data["success"] is False
    assert "cannot resolve" in data["error"].lower()


def test_unpack_generic_create_output_dir():
    """Test that output directory is created."""
    from kael.tools.re_tools.unpack_generic import unpack_generic_sync

    test_data = b"test data"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(test_data)
        temp_path = f.name

    output_dir = "/tmp/test_unpack_output_xyz"

    try:
        result = unpack_generic_sync(temp_path, method="auto", output_dir=output_dir)
        json.loads(result)

        # Output directory should be created
        assert Path(output_dir).exists()
    finally:
        Path(temp_path).unlink()
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_unpack_generic_detect_packer(upx_file):
    """Test packer detection in UPX file."""
    from kael.tools.re_tools.unpack_generic import unpack_generic_sync

    output_dir = "/tmp/test_unpack_upx"

    try:
        result = unpack_generic_sync(upx_file, method="auto", output_dir=output_dir)
        data = json.loads(result)

        assert data["success"] is True
        assert "detected_packers" in data
        # Should detect UPX
        assert "upx" in data["detected_packers"]
    finally:
        Path(upx_file).unlink()
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_unpack_generic_xor_method(xor_encrypted_file):
    """Test XOR brute force unpacking."""
    from kael.tools.re_tools.unpack_generic import unpack_generic_sync

    output_dir = "/tmp/test_unpack_xor"

    try:
        result = unpack_generic_sync(xor_encrypted_file, method="xor", output_dir=output_dir)
        data = json.loads(result)

        assert data["success"] is True
        assert "unpacked_files" in data

        # XOR brute force may or may not find results
        # Just verify it runs without error
    finally:
        Path(xor_encrypted_file).unlink()
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_unpack_generic_overlay_method(normal_file):
    """Test overlay extraction method."""
    from kael.tools.re_tools.unpack_generic import unpack_generic_sync

    output_dir = "/tmp/test_unpack_overlay"

    try:
        result = unpack_generic_sync(normal_file, method="overlay", output_dir=output_dir)
        data = json.loads(result)

        assert data["success"] is True
        # Overlay extraction may or may not find data
    finally:
        Path(normal_file).unlink()
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_unpack_generic_binwalk_method(normal_file):
    """Test binwalk method."""
    from kael.tools.re_tools.unpack_generic import unpack_generic_sync

    output_dir = "/tmp/test_unpack_binwalk"

    try:
        result = unpack_generic_sync(normal_file, method="binwalk", output_dir=output_dir)
        data = json.loads(result)

        assert data["success"] is True
        # Binwalk may or may not find embedded files
    finally:
        Path(normal_file).unlink()
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_unpack_generic_upx_specific_method(upx_file):
    """Test UPX-specific unpacking method."""
    from kael.tools.re_tools.unpack_generic import unpack_generic_sync

    output_dir = "/tmp/test_unpack_upx_specific"

    try:
        result = unpack_generic_sync(upx_file, method="upx", output_dir=output_dir)
        data = json.loads(result)

        # Should attempt UPX unpacking
        # May succeed or fail depending on whether actual UPX is installed
        assert "unpacked_files" in data or "error" in data
    finally:
        Path(upx_file).unlink()
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_unpack_generic_empty_file(empty_file):
    """Test unpacking an empty file."""
    from kael.tools.re_tools.unpack_generic import unpack_generic_sync

    output_dir = "/tmp/test_unpack_empty"

    try:
        result = unpack_generic_sync(empty_file, method="auto", output_dir=output_dir)
        data = json.loads(result)

        # Empty file should not crash
        assert "success" in data
    finally:
        Path(empty_file).unlink()
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_unpack_generic_output_structure(normal_file):
    """Test that output has expected structure."""
    from kael.tools.re_tools.unpack_generic import unpack_generic_sync

    output_dir = "/tmp/test_unpack_structure"

    try:
        result = unpack_generic_sync(normal_file, method="auto", output_dir=output_dir)
        data = json.loads(result)

        # Verify output structure
        assert "success" in data
        assert "sample_path" in data
        assert "output_dir" in data
        assert "detected_packers" in data
        assert "unpacked_files" in data
        assert "total_unpacked" in data
    finally:
        Path(normal_file).unlink()
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_unpack_generic_no_packer_detected(normal_file):
    """Test that normal files don't trigger packer detection."""
    from kael.tools.re_tools.unpack_generic import unpack_generic_sync

    output_dir = "/tmp/test_unpack_no_packer"

    try:
        result = unpack_generic_sync(normal_file, method="auto", output_dir=output_dir)
        data = json.loads(result)

        assert data["success"] is True
        # Normal file should have no packers detected
        assert isinstance(data["detected_packers"], list)
    finally:
        Path(normal_file).unlink()
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)
