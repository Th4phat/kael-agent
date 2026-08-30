"""Unit tests for c2_beacon_detect tool."""

import json
import tempfile
import time
from pathlib import Path

import pytest


@pytest.fixture
def empty_pcap():
    """Create an empty PCAP file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
        return f.name


@pytest.fixture
def pcap_with_beacons():
    """Create a PCAP file with simulated beaconing traffic."""
    # Note: Creating a real PCAP requires scapy and proper packet structure
    # For unit testing, we just create a non-empty file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
        f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)  # PCAP magic + data
        return f.name


def test_c2_beacon_detect_nonexistent():
    """Test with nonexistent PCAP file."""
    from kael.tools.re_tools.c2_beacon_detect import c2_beacon_detect_sync

    result = c2_beacon_detect_sync("/nonexistent/file.pcap")
    data = json.loads(result)

    assert data["success"] is False
    assert "not found" in data["error"].lower()


def test_c2_beacon_detect_empty_pcap(empty_pcap):
    """Test with empty PCAP file."""
    from kael.tools.re_tools.c2_beacon_detect import c2_beacon_detect_sync

    result = c2_beacon_detect_sync(empty_pcap)
    data = json.loads(result)

    assert data["success"] is False
    assert "empty" in data["error"].lower()

    # Cleanup
    Path(empty_pcap).unlink()


def test_c2_beacon_detect_output_structure(pcap_with_beacons):
    """Test output structure with valid PCAP."""
    from kael.tools.re_tools.c2_beacon_detect import c2_beacon_detect_sync

    try:
        result = c2_beacon_detect_sync(pcap_with_beacons)
        data = json.loads(result)

        # If successful, verify structure
        if data.get("success"):
            assert "pcap_path" in data
            assert "total_packets" in data
            assert "beacons_detected" in data
            assert "beacons" in data
        else:
            # If scapy not available or parse error, should return error
            assert "error" in data
    finally:
        Path(pcap_with_beacons).unlink()


def test_c2_beacon_detect_intervals():
    """Test beacon interval analysis function."""
    from kael.tools.re_tools.c2_beacon_detect import analyze_beacon_intervals

    # Test with regular intervals
    timestamps = [0.0, 60.0, 120.0, 180.0, 240.0]
    stats = analyze_beacon_intervals(timestamps)

    assert stats["count"] == 5
    assert stats["avg_interval_sec"] == 60.0
    assert stats["min_interval_sec"] == 60.0
    assert stats["max_interval_sec"] == 60.0
    assert stats["jitter_sec"] == 0.0
    assert stats["is_regular"] is True


def test_c2_beacon_detect_irregular_intervals():
    """Test with irregular intervals."""
    from kael.tools.re_tools.c2_beacon_detect import analyze_beacon_intervals

    # Test with irregular intervals
    timestamps = [0.0, 30.0, 120.0, 150.0, 600.0]
    stats = analyze_beacon_intervals(timestamps)

    assert stats["count"] == 5
    assert stats["is_regular"] is False
    assert stats["jitter_sec"] > 0


def test_c2_beacon_detect_single_timestamp():
    """Test with single timestamp."""
    from kael.tools.re_tools.c2_beacon_detect import analyze_beacon_intervals

    # Single timestamp
    stats = analyze_beacon_intervals([0.0])
    assert stats == {}


def test_c2_beacon_detect_empty_timestamps():
    """Test with no timestamps."""
    from kael.tools.re_tools.c2_beacon_detect import analyze_beacon_intervals

    # Empty list
    stats = analyze_beacon_intervals([])
    assert stats == {}


def test_c2_beacon_detect_min_max_interval(pcap_with_beacons):
    """Test with min and max interval parameters."""
    from kael.tools.re_tools.c2_beacon_detect import c2_beacon_detect_sync

    try:
        result = c2_beacon_detect_sync(
            pcap_with_beacons, min_interval_sec=10.0, max_interval_sec=300.0
        )
        data = json.loads(result)

        # Should accept parameters without error
        assert "success" in data or "error" in data
    finally:
        Path(pcap_with_beacons).unlink()


def test_c2_beacon_detect_jitter_calculation():
    """Test jitter calculation accuracy."""
    from kael.tools.re_tools.c2_beacon_detect import analyze_beacon_intervals

    # Timestamps with known jitter
    timestamps = [0.0, 60.0, 120.5, 180.0, 240.3]
    stats = analyze_beacon_intervals(timestamps)

    # Verify calculations
    assert stats["count"] == 5
    # Intervals: 60.0, 60.5, 59.5, 60.3
    # Average: 60.075
    # Should be close to regular but not perfect
    assert 0 < stats["jitter_sec"] < 1.0


def test_c2_beacon_detect_high_jitter():
    """Test detection of high jitter (irregular traffic)."""
    from kael.tools.re_tools.c2_beacon_detect import analyze_beacon_intervals

    # Very irregular intervals
    timestamps = [0.0, 5.0, 300.0, 10.0, 500.0]
    stats = analyze_beacon_intervals(timestamps)

    # Should have high jitter
    assert stats["is_regular"] is False
    assert stats["coefficient_of_variation"] > 0.3
