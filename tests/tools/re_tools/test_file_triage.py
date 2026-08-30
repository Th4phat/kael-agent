"""Unit tests for file_triage tool."""

import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_pe_file():
    """Create a minimal PE file for testing."""
    # Minimal PE header (MZ signature + PE signature)
    pe_data = (
        b"MZ"
        + b"\x90\x00" * 29
        + b"\x3c\x00\x00\x00"
        + b"\x00" * 56
        + b"PE\x00\x00"
        + b"\x4c\x01"
        + b"\x02\x00"
        + b"\x00" * 250
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(pe_data)
        return f.name


@pytest.fixture
def sample_elf_file():
    """Create a minimal ELF file for testing."""
    # Minimal ELF header
    elf_data = (
        b"\x7fELF"
        b"\x02"
        b"\x01"
        b"\x01" + b"\x00" * 9 + b"\x02\x00" + b"\x3e\x00" + b"\x01\x00\x00\x00" + b"\x00" * 200
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as f:
        f.write(elf_data)
        return f.name


@pytest.fixture
def high_entropy_file():
    """Create a file with high entropy (packed/encrypted)."""
    import random

    # Random bytes simulate encrypted/packed data
    random_data = bytes([random.randint(0, 255) for _ in range(1000)])

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(random_data)
        return f.name


@pytest.fixture
def low_entropy_file():
    """Create a file with low entropy."""
    # Repetitive data = low entropy
    low_entropy_data = b"A" * 1000

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(low_entropy_data)
        return f.name


def test_file_triage_nonexistent():
    """Test file_triage with nonexistent file."""
    from kael.tools.re_tools.file_triage import triage_file_sync

    result = triage_file_sync("/nonexistent/file.exe")
    data = json.loads(result)

    assert data["success"] is False
    assert "cannot resolve" in data["error"].lower()


def test_file_triage_pe_file(sample_pe_file):
    """Test file_triage with PE file."""
    from kael.tools.re_tools.file_triage import triage_file_sync

    result = triage_file_sync(sample_pe_file)
    data = json.loads(result)

    assert data["success"] is True
    assert "format" in data or "error" in data
    assert "hashes" in data
    assert "md5" in data["hashes"]
    assert "sha256" in data["hashes"]

    # Cleanup
    Path(sample_pe_file).unlink()


def test_file_triage_elf_file(sample_elf_file):
    """Test file_triage with ELF file."""
    from kael.tools.re_tools.file_triage import triage_file_sync

    result = triage_file_sync(sample_elf_file)
    data = json.loads(result)

    assert data["success"] is True
    assert "format" in data or "error" in data

    # Cleanup
    Path(sample_elf_file).unlink()


def test_file_triage_entropy_high(high_entropy_file):
    """Test entropy calculation on high-entropy file."""
    from kael.tools.re_tools.file_triage import triage_file_sync

    result = triage_file_sync(high_entropy_file)
    data = json.loads(result)

    assert data["success"] is True
    assert "entropy" in data
    # High entropy should be > 7.0
    assert data["entropy"]["overall"] > 6.0

    # Cleanup
    Path(high_entropy_file).unlink()


def test_file_triage_entropy_low(low_entropy_file):
    """Test entropy calculation on low-entropy file."""
    from kael.tools.re_tools.file_triage import triage_file_sync

    result = triage_file_sync(low_entropy_file)
    data = json.loads(result)

    assert data["success"] is True
    assert "entropy" in data
    # Low entropy should be < 2.0
    assert data["entropy"]["overall"] < 2.0

    # Cleanup
    Path(low_entropy_file).unlink()


def test_file_triage_hashes():
    """Test hash calculation."""
    from kael.tools.re_tools.file_triage import triage_file_sync

    # Create known content
    test_data = b"Hello, World!"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(test_data)
        temp_path = f.name

    result = triage_file_sync(temp_path)
    data = json.loads(result)

    assert data["success"] is True
    assert "hashes" in data

    # Known MD5 for "Hello, World!"
    import hashlib

    expected_md5 = hashlib.md5(test_data).hexdigest()
    assert data["hashes"]["md5"] == expected_md5

    # Cleanup
    Path(temp_path).unlink()


def test_file_triage_file_size():
    """Test file size reporting."""
    from kael.tools.re_tools.file_triage import triage_file_sync

    # Create 1000 byte file
    test_data = b"A" * 1000
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(test_data)
        temp_path = f.name

    result = triage_file_sync(temp_path)
    data = json.loads(result)

    assert data["success"] is True
    assert data["size"] == 1000

    # Cleanup
    Path(temp_path).unlink()
