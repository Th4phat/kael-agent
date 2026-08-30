"""Protocol dissection tool."""

from __future__ import annotations

import asyncio
import base64
import json
import os
from collections import defaultdict

from agents.tool import function_tool


def extract_http_conversations(packets) -> list[dict]:
    """Extract HTTP requests and responses."""
    if not packets:
        return []

    from scapy.all import TCP, Raw

    conversations = []

    # Group packets by TCP stream
    streams = defaultdict(list)

    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            stream_key = (pkt[TCP].sport, pkt[TCP].dport)
            streams[stream_key].append(pkt)

    # Analyze each stream
    for _stream_key, stream_packets in streams.items():
        for pkt in stream_packets:
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)

                # Check for HTTP request
                if (
                    payload.startswith(b"GET ")
                    or payload.startswith(b"POST ")
                    or payload.startswith(b"PUT ")
                    or payload.startswith(b"HEAD ")
                ):
                    try:
                        payload_str = payload.decode("utf-8", errors="ignore")
                        lines = payload_str.split("\r\n")

                        if lines:
                            method_line = lines[0]
                            headers = {}

                            for line in lines[1:]:
                                if ":" in line:
                                    key, val = line.split(":", 1)
                                    headers[key.strip()] = val.strip()

                            conversations.append(
                                {
                                    "type": "http_request",
                                    "method": method_line.split()[0]
                                    if method_line.split()
                                    else "unknown",
                                    "uri": method_line.split()[1]
                                    if len(method_line.split()) > 1
                                    else "/",
                                    "headers": headers,
                                    "timestamp": float(pkt.time),
                                }
                            )
                    except Exception:
                        pass

                # Check for HTTP response
                elif payload.startswith(b"HTTP/"):
                    try:
                        payload_str = payload.decode("utf-8", errors="ignore")
                        lines = payload_str.split("\r\n")

                        if lines:
                            status_line = lines[0]
                            headers = {}
                            body_start = None

                            for i, line in enumerate(lines[1:], 1):
                                if line == "":
                                    body_start = i + 1
                                    break
                                if ":" in line:
                                    key, val = line.split(":", 1)
                                    headers[key.strip()] = val.strip()

                            body = "\r\n".join(lines[body_start:]) if body_start else ""

                            conversations.append(
                                {
                                    "type": "http_response",
                                    "status": status_line,
                                    "headers": headers,
                                    "body_preview": body[:200],
                                    "timestamp": float(pkt.time),
                                }
                            )
                    except Exception:
                        pass

    return conversations


def extract_dns_queries(packets) -> list[dict]:
    """Extract DNS queries."""
    if not packets:
        return []

    from scapy.all import DNS, DNSQR

    queries = []

    for pkt in packets:
        if DNS in pkt and DNSQR in pkt:
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
                queries.append(
                    {"type": "dns_query", "domain": qname.rstrip("."), "timestamp": float(pkt.time)}
                )
            except Exception:
                pass

    return queries


def extract_raw_tcp_payloads(packets, extract_payloads: bool) -> list[dict]:
    """Extract raw TCP payloads from non-HTTP streams."""
    payloads = []

    if not extract_payloads or not packets:
        return payloads

    from scapy.all import IP, TCP, Raw

    for pkt in packets:
        if TCP in pkt and Raw in pkt and IP in pkt:
            payload = bytes(pkt[Raw].load)

            # Skip HTTP traffic
            if (
                payload.startswith(b"GET ")
                or payload.startswith(b"POST ")
                or payload.startswith(b"HTTP/")
            ):
                continue

            # Only include if payload is substantial
            if len(payload) > 10:
                # Try to detect encoding
                is_printable = all(32 <= b < 127 or b in [9, 10, 13] for b in payload[:50])

                if is_printable:
                    payload_preview = payload[:200].decode("utf-8", errors="ignore")
                else:
                    payload_preview = base64.b64encode(payload[:200]).decode("utf-8")

                payloads.append(
                    {
                        "type": "raw_tcp",
                        "src": f"{pkt[IP].src}:{pkt[TCP].sport}",
                        "dst": f"{pkt[IP].dst}:{pkt[TCP].dport}",
                        "size": len(payload),
                        "payload_preview": payload_preview,
                        "is_printable": is_printable,
                        "timestamp": float(pkt.time),
                    }
                )

                # Limit to 50 payloads
                if len(payloads) >= 50:
                    break

    return payloads


def protocol_dissect_sync(
    pcap_path: str,
    protocol_hint: str | None = None,
    extract_payloads: bool = True,
) -> str:
    """Synchronous protocol dissection implementation."""

    if not os.path.exists(pcap_path):
        return json.dumps({"success": False, "error": f"PCAP not found: {pcap_path}"})

    pcap_size = os.path.getsize(pcap_path)
    if pcap_size == 0:
        return json.dumps({"success": False, "error": "PCAP file is empty"})

    try:
        from scapy.all import rdpcap
    except (ImportError, OSError) as exc:
        return json.dumps({"success": False, "error": f"scapy unavailable: {exc}"})

    try:
        # Read PCAP
        packets = rdpcap(pcap_path)

        if not packets:
            return json.dumps({"success": False, "error": "No packets in PCAP"})

        result = {
            "success": True,
            "pcap_path": pcap_path,
            "total_packets": len(packets),
            "protocols": {},
        }

        # Extract HTTP conversations
        http_conversations = extract_http_conversations(packets)
        if http_conversations:
            result["protocols"]["http"] = {
                "count": len(http_conversations),
                "conversations": http_conversations[:20],  # Limit to 20
            }

        # Extract DNS queries
        dns_queries = extract_dns_queries(packets)
        if dns_queries:
            result["protocols"]["dns"] = {
                "count": len(dns_queries),
                "queries": dns_queries[:50],  # Limit to 50
                "unique_domains": list(set([q["domain"] for q in dns_queries]))[:20],
            }

        # Extract raw TCP payloads
        raw_payloads = extract_raw_tcp_payloads(packets, extract_payloads)
        if raw_payloads:
            result["protocols"]["raw_tcp"] = {
                "count": len(raw_payloads),
                "payloads": raw_payloads[:20],  # Limit to 20
            }

        # Summary
        result["summary"] = {
            "http_requests": len([c for c in http_conversations if c["type"] == "http_request"]),
            "http_responses": len([c for c in http_conversations if c["type"] == "http_response"]),
            "dns_queries": len(dns_queries),
            "raw_tcp_streams": len(raw_payloads),
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"success": False, "error": f"Protocol dissection failed: {e!s}"})


@function_tool(timeout=60)
async def protocol_dissect(
    pcap_path: str,
    protocol_hint: str | None = None,
    extract_payloads: bool = True,
) -> str:
    """Dissect and analyze protocols in network capture.

    Args:
        pcap_path: Path to PCAP file from sandbox detonation
        protocol_hint: Optional protocol hint (e.g., "http", "dns", "custom")
        extract_payloads: Whether to extract raw payloads (default: True)

    Returns:
        JSON string with protocol conversations, HTTP requests, DNS queries, and raw payloads
    """
    return await asyncio.to_thread(
        protocol_dissect_sync,
        pcap_path,
        protocol_hint,
        extract_payloads,
    )
