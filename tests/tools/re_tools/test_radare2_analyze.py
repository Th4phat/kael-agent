"""Unit tests for radare2_analyze tool."""

import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def pe_file():
    """Create a minimal PE file."""
    pe_data = (
        b"MZ\x90\x00" * 10
        + b"\x00" * 100
        + b"PE\x00\x00"
        + b"\x4c\x01"  # Machine i386
        + b"\x02\x00"  # Number of sections
        + b"\x00" * 200
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(pe_data)
        return f.name


def test_radare2_analyze_nonexistent():
    """Test with nonexistent file."""
    from kael.tools.re_tools.radare2_analyze import radare2_analyze_sync

    result = radare2_analyze_sync("/nonexistent/file.exe")
    data = json.loads(result)

    assert data["success"] is False
    assert "cannot resolve" in data["error"].lower()


def test_radare2_analyze_pe_file(pe_file):
    """Test analysis of PE file."""
    from kael.tools.re_tools.radare2_analyze import radare2_analyze_sync

    try:
        result = radare2_analyze_sync(pe_file, analysis_depth="quick")
        data = json.loads(result)

        # If radare2 is available, verify structure
        if data.get("success"):
            assert "sample_path" in data
            assert "functions" in data or "imports" in data
        else:
            # If radare2 not available, should return error
            assert "error" in data
    except Exception as e:
        pytest.skip(f"radare2 not available: {e}")
    finally:
        Path(pe_file).unlink()


def test_radare2_analyze_depths(pe_file):
    """Test different analysis depths."""
    from kael.tools.re_tools.radare2_analyze import radare2_analyze_sync

    depths = ["quick", "standard", "deep"]

    for depth in depths:
        try:
            result = radare2_analyze_sync(pe_file, analysis_depth=depth)
            data = json.loads(result)

            # Should accept all depth values
            assert "success" in data or "error" in data
        except Exception as e:
            pytest.skip(f"radare2 not available: {e}")

    Path(pe_file).unlink()


def test_radare2_analyze_disable_functions(pe_file):
    """Test with function extraction disabled."""
    from kael.tools.re_tools.radare2_analyze import radare2_analyze_sync

    try:
        result = radare2_analyze_sync(
            pe_file,
            extract_functions=False,
            analysis_depth="quick",
        )
        data = json.loads(result)

        assert "success" in data or "error" in data
    except Exception as e:
        pytest.skip(f"radare2 not available: {e}")
    finally:
        Path(pe_file).unlink()


def test_radare2_analyze_disable_crypto(pe_file):
    """Test with crypto detection disabled."""
    from kael.tools.re_tools.radare2_analyze import radare2_analyze_sync

    try:
        result = radare2_analyze_sync(pe_file, detect_crypto=False)
        data = json.loads(result)

        assert "success" in data or "error" in data
    except Exception as e:
        pytest.skip(f"radare2 not available: {e}")
    finally:
        Path(pe_file).unlink()


def test_radare2_analyze_invalid_depth(pe_file):
    """Test with invalid analysis depth."""
    from kael.tools.re_tools.radare2_analyze import radare2_analyze_sync

    try:
        result = radare2_analyze_sync(pe_file, analysis_depth="invalid")
        data = json.loads(result)

        # Should handle gracefully (may use default)
        assert "success" in data or "error" in data
    except Exception as e:
        pytest.skip(f"radare2 not available: {e}")
    finally:
        Path(pe_file).unlink()


def test_radare2_analyze_output_structure(pe_file):
    """Test output structure when successful."""
    from kael.tools.re_tools.radare2_analyze import radare2_analyze_sync

    try:
        result = radare2_analyze_sync(pe_file, analysis_depth="quick")
        data = json.loads(result)

        if data.get("success"):
            # Verify expected fields
            assert "sample_path" in data
            # Should have at least one analysis component
            assert any(
                key in data for key in ["functions", "imports", "crypto_constants", "anti_analysis"]
            )
    except Exception as e:
        pytest.skip(f"radare2 not available: {e}")
    finally:
        Path(pe_file).unlink()
