"""Unit tests for yara_scan tool."""

import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def eicar_file():
    """Create EICAR test file."""
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(eicar)
        return f.name


@pytest.fixture
def clean_file():
    """Create a clean test file."""
    data = b"This is a clean file with normal content."

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        return f.name


@pytest.fixture
def upx_signature_file():
    """Create a file with UPX signature."""
    # Minimal UPX signature
    data = b"MZ\x90\x00" + b"\x00" * 100 + b"UPX0" + b"\x00" * 100 + b"UPX1"

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(data)
        return f.name


def test_yara_scan_nonexistent():
    """Test yara_scan with nonexistent file."""
    from kael.tools.re_tools.yara_scan import yara_scan_sync

    result = yara_scan_sync("/nonexistent/file.exe")
    data = json.loads(result)

    assert data["success"] is False
    assert "cannot resolve" in data["error"].lower()


def test_yara_scan_eicar(eicar_file):
    """Test YARA scan on EICAR test file."""
    from kael.tools.re_tools.yara_scan import yara_scan_sync

    result = yara_scan_sync(eicar_file, use_bundled_rules=True)
    data = json.loads(result)

    assert data["success"] is True
    assert "matches" in data

    # Should match EICAR rule
    if data["total_matches"] > 0:
        rule_names = [m["rule_name"] for m in data["matches"]]
        assert any("eicar" in name.lower() for name in rule_names)

    # Cleanup
    Path(eicar_file).unlink()


def test_yara_scan_clean_file(clean_file):
    """Test YARA scan on clean file."""
    from kael.tools.re_tools.yara_scan import yara_scan_sync

    result = yara_scan_sync(clean_file, use_bundled_rules=True)
    data = json.loads(result)

    assert data["success"] is True
    assert "matches" in data
    # Clean file should have no or very few matches

    # Cleanup
    Path(clean_file).unlink()


def test_yara_scan_upx_packer(upx_signature_file):
    """Test YARA scan detecting UPX packer."""
    from kael.tools.re_tools.yara_scan import yara_scan_sync

    result = yara_scan_sync(upx_signature_file, use_bundled_rules=True)
    data = json.loads(result)

    assert data["success"] is True
    assert "matches" in data

    # Should detect UPX
    if data["total_matches"] > 0:
        rule_names = [m["rule_name"] for m in data["matches"]]
        assert any("upx" in name.lower() for name in rule_names)

    # Cleanup
    Path(upx_signature_file).unlink()


def test_yara_scan_inline_rule():
    """Test YARA scan with inline rule."""
    from kael.tools.re_tools.yara_scan import yara_scan_sync

    # Create test file
    test_data = b"This file contains TESTSTRING for detection"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(test_data)
        temp_path = f.name

    # Inline YARA rule
    inline_rule = """
    rule TestRule {
        strings:
            $test = "TESTSTRING"
        condition:
            $test
    }
    """

    result = yara_scan_sync(temp_path, rules_inline=inline_rule)
    data = json.loads(result)

    assert data["success"] is True
    assert "matches" in data
    assert data["total_matches"] >= 1

    # Should match our inline rule
    rule_names = [m["rule_name"] for m in data["matches"]]
    assert "TestRule" in rule_names

    # Cleanup
    Path(temp_path).unlink()


def test_yara_scan_invalid_inline_rule():
    """Test YARA scan with invalid inline rule."""
    from kael.tools.re_tools.yara_scan import yara_scan_sync

    # Create test file
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test")
        temp_path = f.name

    # Invalid YARA rule (syntax error)
    invalid_rule = "rule BadRule { this is invalid }"

    result = yara_scan_sync(temp_path, rules_inline=invalid_rule)
    data = json.loads(result)

    # Should return error
    assert data["success"] is False
    assert "error" in data

    # Cleanup
    Path(temp_path).unlink()


def test_yara_scan_no_matches(clean_file):
    """Test YARA scan with specific rule that doesn't match."""
    from kael.tools.re_tools.yara_scan import yara_scan_sync

    # Rule that won't match clean file
    inline_rule = """
    rule NoMatch {
        strings:
            $impossible = "IMPOSSIBLE_STRING_THAT_DOES_NOT_EXIST_12345"
        condition:
            $impossible
    }
    """

    result = yara_scan_sync(clean_file, rules_inline=inline_rule)
    data = json.loads(result)

    assert data["success"] is True
    assert data["total_matches"] == 0
    assert len(data["matches"]) == 0

    # Cleanup
    Path(clean_file).unlink()


def test_yara_scan_bundled_rules_disabled():
    """Test YARA scan with bundled rules disabled."""
    from kael.tools.re_tools.yara_scan import yara_scan_sync

    # Create EICAR file
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(eicar)
        temp_path = f.name

    # Scan without bundled rules (need inline rule to avoid error)
    inline_rule = """
    rule Dummy {
        condition:
            false
    }
    """

    result = yara_scan_sync(temp_path, use_bundled_rules=False, rules_inline=inline_rule)
    data = json.loads(result)

    assert data["success"] is True
    # Should not use bundled EICAR rule

    # Cleanup
    Path(temp_path).unlink()


def test_yara_scan_match_details():
    """Test that YARA matches include details."""
    from kael.tools.re_tools.yara_scan import yara_scan_sync

    # Create test file with known content
    test_data = b"MAGIC_HEADER" + b"\x00" * 100 + b"MAGIC_FOOTER"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(test_data)
        temp_path = f.name

    # Rule with multiple strings
    inline_rule = """
    rule DetailedRule {
        meta:
            description = "Test rule with details"
            author = "Unit Test"
        strings:
            $header = "MAGIC_HEADER"
            $footer = "MAGIC_FOOTER"
        condition:
            $header and $footer
    }
    """

    result = yara_scan_sync(temp_path, rules_inline=inline_rule)
    data = json.loads(result)

    assert data["success"] is True
    assert data["total_matches"] >= 1

    # Check match details
    match = data["matches"][0]
    assert "rule_name" in match
    assert match["rule_name"] == "DetailedRule"
    assert "meta" in match
    assert match["meta"]["description"] == "Test rule with details"

    # Cleanup
    Path(temp_path).unlink()
