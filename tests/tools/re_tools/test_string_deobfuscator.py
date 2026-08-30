"""Unit tests for string_deobfuscator tool."""

import json
import os
import tempfile

import pytest

from kael.tools.re_tools.string_deobfuscator import (
    calculate_chi_squared,
    detect_api_hashing,
    string_deobfuscation_sync,
    try_rot13,
    try_xor_multi_byte,
    try_xor_single_byte,
)


@pytest.fixture
def xor_encrypted_file():
    """Create a file with XOR-encrypted content."""
    plaintext = b"Hello World This is a test of XOR encryption"
    key = 0x37
    ciphertext = bytes(b ^ key for b in plaintext)

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(ciphertext)
        f.flush()
        yield f.name
    os.unlink(f.name)


def test_xor_decryption_finds_key(xor_encrypted_file):
    """Test that XOR decryption finds the correct key."""
    result = string_deobfuscation_sync(
        xor_encrypted_file,
        try_xor=True,
        try_rot13=False,
        detect_stack=False,
    )
    data = json.loads(result)
    assert data["success"] is True
    assert len(data["xor_single_byte"]) > 0

    # Check if key 0x37 is in the results
    keys_found = [r["key"] for r in data["xor_single_byte"]]
    assert "0x37" in keys_found


def test_rot13_detection():
    """Test ROT13 detection."""
    rot13_encoded = "Uryyb Jbeyq"

    result = try_rot13(rot13_encoded.encode())
    assert result is not None
    assert result["encoding"] == "ROT13"
    assert "Hello" in result["decoded"]


def test_api_hashing_detection_crc32():
    """Test CRC32 polynomial detection."""
    data = b"\x20\x83\xb8\xed" + b"some other data"
    patterns = detect_api_hashing(data)

    assert len(patterns) > 0
    types = [p["type"] for p in patterns]
    assert "CRC32_polynomial" in types


def test_api_hashing_detection_fnv():
    """Test FNV hash detection."""
    data = b"\xc5\x9d\x1c\x81" + b"some other data"
    patterns = detect_api_hashing(data)

    assert len(patterns) > 0
    types = [p["type"] for p in patterns]
    assert "FNV1_hash" in types


def test_string_deobfuscation_nonexistent():
    """Test with nonexistent file."""
    result = string_deobfuscation_sync("/nonexistent/file.bin")
    data = json.loads(result)
    assert data["success"] is False
    assert "error" in data


def test_chi_squared_calculation():
    """Test chi-squared calculation."""
    # English text should have low chi-squared
    english = "the quick brown fox jumps over the lazy dog " * 20
    chi_sq_eng = calculate_chi_squared(english)
    assert chi_sq_eng < 200

    # Random text should have high chi-squared
    random = "xqzpjkwmfvnb" * 20
    chi_sq_rand = calculate_chi_squared(random)
    assert chi_sq_rand > 200


def test_xor_multi_byte_basic():
    """Test multi-byte XOR with known key."""
    plaintext = b"AAAAAAAABBBBBBBBCCCCCCCC"
    key = b"\x01\x02\x03"
    ciphertext = bytes(plaintext[i] ^ key[i % 3] for i in range(len(plaintext)))

    results = try_xor_multi_byte(ciphertext, key_length=3)
    assert len(results) > 0
    # Should find key length 3 in results
    key_lengths = [r["key_length"] for r in results]
    assert 3 in key_lengths
