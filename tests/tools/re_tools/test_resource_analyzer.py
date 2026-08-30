"""Unit tests for resource_analyzer tool."""

import json
import os
import tempfile

import pytest

from kael.tools.re_tools.resource_analyzer import (
    RESOURCE_TYPES,
    detect_steganography,
    parse_version_info,
    resource_analysis_sync,
)


@pytest.fixture
def fake_pe_file():
    """Create a fake PE file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 1024)
        f.flush()
        yield f.name
    os.unlink(f.name)


def test_resource_types_defined():
    """Test that resource types are defined."""
    assert len(RESOURCE_TYPES) > 20
    assert RESOURCE_TYPES[2] == "BITMAP"
    assert RESOURCE_TYPES[3] == "ICON"
    assert RESOURCE_TYPES[10] == "RCDATA"
    assert RESOURCE_TYPES[16] == "VERSION"


def test_resource_analysis_non_pe():
    """Test resource analysis with non-PE file."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"not a PE file")
        f.flush()
        result = resource_analysis_sync(f.name)
        os.unlink(f.name)

    data = json.loads(result)
    assert data["success"] is False
    assert "PE" in data["error"]


def test_resource_analysis_nonexistent():
    """Test with nonexistent file."""
    result = resource_analysis_sync("/nonexistent/file.exe")
    data = json.loads(result)
    assert data["success"] is False


def test_resource_analysis_fake_pe(fake_pe_file):
    """Test with fake PE file (will fail parsing gracefully)."""
    result = resource_analysis_sync(fake_pe_file)
    data = json.loads(result)
    # Should not crash, may have error in resource_analysis
    assert "resource_analysis" in data or "error" in data


def test_parse_version_info_empty():
    """Test version info parsing with empty data."""
    result = parse_version_info(b"")
    assert isinstance(result, dict)


def test_detect_steganography_nonexistent():
    """Test steganography detection on nonexistent file."""
    result = detect_steganography("/nonexistent/file.exe")
    assert result["suspicious"] is False
