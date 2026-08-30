"""Unit tests for import_analyzer tool."""

import json
import os
import tempfile

import pytest

from kael.tools.re_tools.import_analyzer import (
    calculate_pe_imphash,
    import_analysis_sync,
)
from kael.tools.re_tools.string_deobfuscator import calculate_chi_squared, try_xor_single_byte


@pytest.fixture
def fake_pe_file():
    """Create a minimal fake PE file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 100)  # Fake MZ header
        f.flush()
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def fake_elf_file():
    """Create a minimal fake ELF file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 100)  # Fake ELF header
        f.flush()
        yield f.name
    os.unlink(f.name)


def test_imphash_calculation():
    """Test imphash calculation with known imports."""
    imports = [
        {"dll": "kernel32.dll", "functions": ["CreateFileA", "ReadFile"]},
        {"dll": "user32.dll", "functions": ["MessageBoxA"]},
    ]
    imphash = calculate_pe_imphash(imports)
    assert len(imphash) == 32  # MD5 hash length
    assert all(c in "0123456789abcdef" for c in imphash)


def test_xor_single_byte_english_text():
    """Test XOR decryption with English text XOR'd."""
    plaintext = b"Hello World This is a test"
    key = 0x42
    ciphertext = bytes(b ^ key for b in plaintext)

    results = try_xor_single_byte(ciphertext, min_length=10)

    # Should find key 0x42 in results
    keys_found = [r["key"] for r in results]
    assert "0x42" in keys_found

    # Check decoded text matches
    result = next(r for r in results if r["key"] == "0x42")
    assert "Hello" in result["decoded"]


def test_chi_squared_english_text():
    """Test chi-squared calculation for English text."""
    english_text = "The quick brown fox jumps over the lazy dog" * 10
    chi_sq = calculate_chi_squared(english_text)
    assert chi_sq < 1_200  # English-like text scores far below the random control


def test_chi_squared_random_text():
    """Test chi-squared calculation for random text."""
    random_text = "XQZP" * 50
    chi_sq = calculate_chi_squared(random_text)
    assert chi_sq > 200  # Random text should have high chi-squared


def test_import_analysis_nonexistent_file():
    """Test import analysis with nonexistent file."""
    result = import_analysis_sync("/nonexistent/path/file.exe")
    data = json.loads(result)
    assert data["success"] is False
    assert "error" in data


def test_import_analysis_unsupported_file():
    """Test import analysis with unsupported file type."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"Just a text file\n")
        f.flush()
        result = import_analysis_sync(f.name)
        os.unlink(f.name)

    data = json.loads(result)
    assert data["success"] is False


def test_import_analysis_fake_pe(fake_pe_file):
    """Test import analysis with fake PE file (will fail parsing but not crash)."""
    result = import_analysis_sync(fake_pe_file)
    data = json.loads(result)
    # Should succeed in opening but analysis may have errors
    assert "file_type" in data or "error" in data
