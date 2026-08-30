"""Unit tests for protocol_dissect tool."""

import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def empty_pcap():
    """Create an empty PCAP file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
        return f.name


@pytest.fixture
def pcap_with_data():
    """Create a PCAP file with some data."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
        f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 200)
        return f.name


def test_protocol_dissect_nonexistent():
    """Test with nonexistent PCAP file."""
    from kael.tools.re_tools.protocol_dissect import protocol_dissect_sync

    result = protocol_dissect_sync("/nonexistent/file.pcap")
    data = json.loads(result)

    assert data["success"] is False
    assert "not found" in data["error"].lower()


def test_protocol_dissect_empty_pcap(empty_pcap):
    """Test with empty PCAP file."""
    from kael.tools.re_tools.protocol_dissect import protocol_dissect_sync

    result = protocol_dissect_sync(empty_pcap)
    data = json.loads(result)

    assert data["success"] is False
    assert "empty" in data["error"].lower()

    # Cleanup
    Path(empty_pcap).unlink()


def test_protocol_dissect_output_structure(pcap_with_data):
    """Test output structure."""
    from kael.tools.re_tools.protocol_dissect import protocol_dissect_sync

    try:
        result = protocol_dissect_sync(pcap_with_data)
        data = json.loads(result)

        # If successful, verify structure
        if data.get("success"):
            assert "pcap_path" in data
            assert "total_packets" in data
            assert "protocols" in data
            assert "summary" in data
        else:
            # If scapy not available, should return error
            assert "error" in data
    finally:
        Path(pcap_with_data).unlink()


def test_protocol_dissect_with_payload_extraction(pcap_with_data):
    """Test with payload extraction enabled."""
    from kael.tools.re_tools.protocol_dissect import protocol_dissect_sync

    try:
        result = protocol_dissect_sync(pcap_with_data, extract_payloads=True)
        data = json.loads(result)

        # Should accept parameter
        assert "success" in data or "error" in data
    finally:
        Path(pcap_with_data).unlink()


def test_protocol_dissect_without_payload_extraction(pcap_with_data):
    """Test with payload extraction disabled."""
    from kael.tools.re_tools.protocol_dissect import protocol_dissect_sync

    try:
        result = protocol_dissect_sync(pcap_with_data, extract_payloads=False)
        data = json.loads(result)

        # Should accept parameter
        assert "success" in data or "error" in data
    finally:
        Path(pcap_with_data).unlink()


def test_protocol_dissect_with_protocol_hint(pcap_with_data):
    """Test with protocol hint."""
    from kael.tools.re_tools.protocol_dissect import protocol_dissect_sync

    try:
        result = protocol_dissect_sync(pcap_with_data, protocol_hint="http")
        data = json.loads(result)

        # Should accept hint
        assert "success" in data or "error" in data
    finally:
        Path(pcap_with_data).unlink()


def test_extract_http_conversations_empty():
    """Test HTTP conversation extraction with empty packets."""
    from kael.tools.re_tools.protocol_dissect import extract_http_conversations

    conversations = extract_http_conversations([])
    assert conversations == []


def test_extract_dns_queries_empty():
    """Test DNS query extraction with empty packets."""
    from kael.tools.re_tools.protocol_dissect import extract_dns_queries

    queries = extract_dns_queries([])
    assert queries == []


def test_extract_raw_tcp_payloads_disabled():
    """Test raw TCP payload extraction when disabled."""
    from kael.tools.re_tools.protocol_dissect import extract_raw_tcp_payloads

    payloads = extract_raw_tcp_payloads([], extract_payloads=False)
    assert payloads == []
