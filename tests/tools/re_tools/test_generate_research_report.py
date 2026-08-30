"""Unit tests for generate_research_report tool."""

import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_analysis_data():
    """Create sample analysis data."""
    return json.dumps(
        {
            "file_triage": {
                "success": True,
                "file_type": "PE32 executable",
                "file_size": 45000,
                "hashes": {"md5": "a1b2c3d4e5f6", "sha256": "abc123def456"},
                "entropy": 5.4,
                "packer_detected": False,
            },
            "strings": {"success": True, "total_strings": 250},
            "yara": {
                "success": True,
                "total_matches": 2,
                "matches": [{"rule_name": "Test_Rule", "meta": {"description": "Test"}}],
            },
            "radare2": {"success": True, "total_functions": 45},
            "sandbox": {
                "success": True,
                "execution": {"duration_sec": 12.5, "exit_status": 0},
                "filesystem_changes": {
                    "created": ["/tmp/payload.exe"],
                    "modified": [],
                    "deleted": [],
                },
                "network": {"pcap_size_bytes": 1024},
                "syscalls": {"summary": {"open": 45, "socket": 3}},
            },
            "c2_beacon": {
                "success": True,
                "beacons": [
                    {
                        "destination": "1.2.3.4:443",
                        "protocol": "TCP",
                        "packet_count": 45,
                        "confidence": "high",
                        "statistics": {"avg_interval_sec": 60.0, "jitter_sec": 0.8},
                    }
                ],
            },
            "protocol": {"total_packets": 100},
            "unpack": {"total_unpacked": 0},
            "memory": {"dumps": []},
        }
    )


@pytest.fixture
def sample_sha256():
    """Sample SHA256 hash."""
    return "abc123def456789012345678901234567890123456789012345678901234abcd"


@pytest.fixture
def minimal_analysis_data():
    """Create minimal analysis data."""
    return json.dumps(
        {
            "file_triage": {"success": True},
            "strings": {"success": True, "total_strings": 0},
            "yara": {"success": True, "matches": []},
            "radare2": {"success": True, "total_functions": 0},
            "sandbox": {"success": True},
            "c2_beacon": {"success": True, "beacons": []},
            "protocol": {"total_packets": 0},
            "unpack": {"total_unpacked": 0},
            "memory": {"dumps": []},
        }
    )


def test_generate_report_basic(sample_sha256, sample_analysis_data):
    """Test basic report generation."""
    from kael.tools.re_tools.generate_research_report import generate_research_report_sync

    output_dir = "/tmp/test_reports_basic"

    try:
        result = generate_research_report_sync(
            sample_sha256=sample_sha256, analysis_data=sample_analysis_data, output_dir=output_dir
        )
        data = json.loads(result)

        assert data["success"] is True
        assert data["sample_sha256"] == sample_sha256
        assert "report_markdown" in data
        assert "report_json" in data
        assert "artifacts_tarball" in data
    finally:
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_generate_report_creates_files(sample_sha256, sample_analysis_data):
    """Test that report files are created."""
    from kael.tools.re_tools.generate_research_report import generate_research_report_sync

    output_dir = "/tmp/test_reports_files"

    try:
        result = generate_research_report_sync(
            sample_sha256=sample_sha256, analysis_data=sample_analysis_data, output_dir=output_dir
        )
        data = json.loads(result)

        # Check markdown report exists
        assert Path(data["report_markdown"]).exists()

        # Check JSON report exists
        assert Path(data["report_json"]).exists()
    finally:
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_generate_report_markdown_content(sample_sha256, sample_analysis_data):
    """Test that markdown report contains expected sections."""
    from kael.tools.re_tools.generate_research_report import generate_research_report_sync

    output_dir = "/tmp/test_reports_markdown"

    try:
        result = generate_research_report_sync(
            sample_sha256=sample_sha256, analysis_data=sample_analysis_data, output_dir=output_dir
        )
        data = json.loads(result)

        # Read markdown report
        with open(data["report_markdown"]) as f:
            content = f.read()

        # Verify key sections
        assert sample_sha256 in content
        assert "Executive Summary" in content
        assert "File Triage" in content
        assert "YARA Matches" in content
        assert "Sandbox Execution" in content
        assert "C2 Beaconing" in content
    finally:
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_generate_report_json_content(sample_sha256, sample_analysis_data):
    """Test that JSON report contains analysis data."""
    from kael.tools.re_tools.generate_research_report import generate_research_report_sync

    output_dir = "/tmp/test_reports_json"

    try:
        result = generate_research_report_sync(
            sample_sha256=sample_sha256, analysis_data=sample_analysis_data, output_dir=output_dir
        )
        data = json.loads(result)

        # Read JSON report
        with open(data["report_json"]) as f:
            json_content = json.load(f)

        # Verify structure
        assert "file_triage" in json_content
        assert "yara" in json_content
        assert "sandbox" in json_content
    finally:
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_generate_report_invalid_json(sample_sha256):
    """Test with invalid JSON input."""
    from kael.tools.re_tools.generate_research_report import generate_research_report_sync

    output_dir = "/tmp/test_reports_invalid"

    try:
        result = generate_research_report_sync(
            sample_sha256=sample_sha256, analysis_data="not valid json", output_dir=output_dir
        )
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data
    finally:
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_generate_report_minimal_data(sample_sha256, minimal_analysis_data):
    """Test with minimal analysis data."""
    from kael.tools.re_tools.generate_research_report import generate_research_report_sync

    output_dir = "/tmp/test_reports_minimal"

    try:
        result = generate_research_report_sync(
            sample_sha256=sample_sha256, analysis_data=minimal_analysis_data, output_dir=output_dir
        )
        data = json.loads(result)

        # Should still generate a report
        assert data["success"] is True
        assert Path(data["report_markdown"]).exists()
    finally:
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_generate_report_creates_output_dir(sample_sha256, sample_analysis_data):
    """Test that output directory is created if it doesn't exist."""
    from kael.tools.re_tools.generate_research_report import generate_research_report_sync

    output_dir = "/tmp/test_reports_new_dir_xyz"

    # Ensure it doesn't exist
    if Path(output_dir).exists():
        import shutil

        shutil.rmtree(output_dir)

    try:
        result = generate_research_report_sync(
            sample_sha256=sample_sha256, analysis_data=sample_analysis_data, output_dir=output_dir
        )
        json.loads(result)

        # Directory should be created
        assert Path(output_dir).exists()
    finally:
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)


def test_generate_report_includes_c2_info(sample_sha256, sample_analysis_data):
    """Test that C2 information is included in report."""
    from kael.tools.re_tools.generate_research_report import generate_research_report_sync

    output_dir = "/tmp/test_reports_c2"

    try:
        result = generate_research_report_sync(
            sample_sha256=sample_sha256, analysis_data=sample_analysis_data, output_dir=output_dir
        )
        data = json.loads(result)

        # Read markdown
        with open(data["report_markdown"]) as f:
            content = f.read()

        # Should include C2 destination
        assert "1.2.3.4:443" in content
    finally:
        if Path(output_dir).exists():
            import shutil

            shutil.rmtree(output_dir)
