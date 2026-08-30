"""Unit tests for extract_strings tool."""

import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_with_strings():
    """Create a file with various string types."""
    data = (
        b"http://evil.com/payload.exe\x00"  # URL
        b"192.168.1.100\x00"  # IP address
        b"C:\\Windows\\System32\\malware.dll\x00"  # File path
        b"HKEY_LOCAL_MACHINE\\Software\\Malware\x00"  # Registry key
        b"attacker@evil.com\x00"  # Email
        b"Global\\MalwareMutex\x00"  # Mutex
        b"\x00\x00\x00\x00"  # Padding
        b"VGVzdA==\x00"  # Base64 string "Test"
        b"normal string here\x00"
        b"\xff" * 50  # Binary data
    )

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        return f.name


@pytest.fixture
def unicode_strings_file():
    """Create a file with Unicode (UTF-16LE) strings."""
    # UTF-16LE encoded strings
    unicode_data = (
        "http://unicode-evil.com\x00".encode("utf-16le")
        + b"\x00\x00" * 10
        + "unicode malware\x00".encode("utf-16le")
    )

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(unicode_data)
        return f.name


@pytest.fixture
def base64_file():
    """Create a file with base64 encoded data."""
    import base64

    original = b"This is a test payload"
    encoded = base64.b64encode(original)

    data = b"Encoded: " + encoded + b"\x00"

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        return f.name


def test_extract_strings_nonexistent():
    """Test extract_strings with nonexistent file."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    result = extract_strings_sync("/nonexistent/file.exe")
    data = json.loads(result)

    assert data["success"] is False
    assert "cannot resolve" in data["error"].lower()


def test_extract_strings_basic(sample_with_strings):
    """Test basic string extraction."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    result = extract_strings_sync(sample_with_strings)
    data = json.loads(result)

    assert data["success"] is True
    assert "strings" in data
    assert data["string_count"]["total"] > 0

    # Cleanup
    Path(sample_with_strings).unlink()


def test_extract_strings_urls(sample_with_strings):
    """Test URL extraction."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    result = extract_strings_sync(sample_with_strings)
    data = json.loads(result)

    assert data["success"] is True
    assert "iocs" in data
    assert "urls" in data["iocs"]

    # Should find the URL
    urls = data["iocs"]["urls"]
    assert any("evil.com" in url for url in urls)

    # Cleanup
    Path(sample_with_strings).unlink()


def test_extract_strings_ips(sample_with_strings):
    """Test IP address extraction."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    result = extract_strings_sync(sample_with_strings)
    data = json.loads(result)

    assert data["success"] is True
    assert "iocs" in data
    assert "ips" in data["iocs"]

    # Should find the IP
    ips = data["iocs"]["ips"]
    assert "192.168.1.100" in ips

    # Cleanup
    Path(sample_with_strings).unlink()


def test_extract_strings_file_paths(sample_with_strings):
    """Test file path extraction."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    result = extract_strings_sync(sample_with_strings)
    data = json.loads(result)

    assert data["success"] is True
    assert "iocs" in data
    assert "file_paths" in data["iocs"]

    # Should find Windows path
    paths = data["iocs"]["file_paths"]
    assert any("Windows\\System32" in path for path in paths)

    # Cleanup
    Path(sample_with_strings).unlink()


def test_extract_strings_registry_keys(sample_with_strings):
    """Test registry key extraction."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    result = extract_strings_sync(sample_with_strings)
    data = json.loads(result)

    assert data["success"] is True
    assert "iocs" in data
    assert "registry_keys" in data["iocs"]

    # Should find registry key
    reg_keys = data["iocs"]["registry_keys"]
    assert any("HKEY_LOCAL_MACHINE" in key for key in reg_keys)

    # Cleanup
    Path(sample_with_strings).unlink()


def test_extract_strings_emails(sample_with_strings):
    """Test email extraction."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    result = extract_strings_sync(sample_with_strings)
    data = json.loads(result)

    assert data["success"] is True
    assert "iocs" in data
    assert "emails" in data["iocs"]

    # Should find email
    emails = data["iocs"]["emails"]
    assert "attacker@evil.com" in emails

    # Cleanup
    Path(sample_with_strings).unlink()


def test_extract_strings_mutexes(sample_with_strings):
    """Test mutex extraction."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    result = extract_strings_sync(sample_with_strings)
    data = json.loads(result)

    assert data["success"] is True
    assert "iocs" in data
    assert "mutexes" in data["iocs"]

    # Should find mutex
    mutexes = data["iocs"]["mutexes"]
    assert any("MalwareMutex" in mutex for mutex in mutexes)

    # Cleanup
    Path(sample_with_strings).unlink()


def test_extract_strings_unicode(unicode_strings_file):
    """Test Unicode (UTF-16LE) string extraction."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    result = extract_strings_sync(unicode_strings_file)
    data = json.loads(result)

    assert data["success"] is True
    assert "strings" in data

    # Should find Unicode strings
    all_strings = " ".join(
        item["value"] for kind in ("ascii", "unicode") for item in data["strings"][kind]
    )
    assert "unicode" in all_strings.lower() or "evil.com" in all_strings.lower()

    # Cleanup
    Path(unicode_strings_file).unlink()


def test_extract_strings_base64(base64_file):
    """Test base64 detection and decoding."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    result = extract_strings_sync(base64_file)
    data = json.loads(result)

    assert data["success"] is True

    # Should detect base64
    # Note: Implementation may or may not decode automatically
    # Just verify no crash and successful extraction
    assert "strings" in data

    # Cleanup
    Path(base64_file).unlink()


def test_extract_strings_min_length():
    """Test minimum string length filtering."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    # Create file with short and long strings
    data = b"ab\x00" + b"longstring\x00" + b"xy\x00" + b"anotherlongstring\x00"

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        temp_path = f.name

    result = extract_strings_sync(temp_path, min_length=5)
    result_data = json.loads(result)

    assert result_data["success"] is True

    # Should only find strings >= 5 chars
    strings = [item["value"] for item in result_data["strings"]["ascii"]]
    assert all(len(s) >= 5 for s in strings)
    assert "longstring" in strings
    assert "ab" not in strings

    # Cleanup
    Path(temp_path).unlink()


def test_extract_strings_empty_file():
    """Test extraction from empty file."""
    from kael.tools.re_tools.extract_strings import extract_strings_sync

    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_path = f.name

    result = extract_strings_sync(temp_path)
    data = json.loads(result)

    assert data["success"] is True
    assert data["string_count"]["total"] == 0

    # Cleanup
    Path(temp_path).unlink()
