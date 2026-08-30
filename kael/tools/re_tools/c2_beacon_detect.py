"""C2 beacon detection tool."""

from __future__ import annotations

import asyncio
import json
import os
from collections import defaultdict

from agents.tool import function_tool


def analyze_beacon_intervals(timestamps: list[float]) -> dict:
    """Analyze beacon timing patterns."""
    if len(timestamps) < 2:
        return {}

    # Calculate intervals
    intervals = []
    for i in range(1, len(timestamps)):
        intervals.append(timestamps[i] - timestamps[i - 1])

    if not intervals:
        return {}

    # Calculate statistics
    avg_interval = sum(intervals) / len(intervals)
    min_interval = min(intervals)
    max_interval = max(intervals)

    # Calculate jitter (standard deviation)
    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
    jitter = variance**0.5

    # Calculate coefficient of variation
    cv = (jitter / avg_interval) if avg_interval > 0 else 0

    # Determine if beaconing is regular
    is_regular = cv < 0.3  # Low jitter indicates regular beaconing

    return {
        "count": len(timestamps),
        "avg_interval_sec": round(avg_interval, 2),
        "min_interval_sec": round(min_interval, 2),
        "max_interval_sec": round(max_interval, 2),
        "jitter_sec": round(jitter, 2),
        "coefficient_of_variation": round(cv, 3),
        "is_regular": is_regular,
    }


def c2_beacon_detect_sync(
    pcap_path: str,
    min_interval_sec: float = 1.0,
    max_interval_sec: float = 3600.0,
) -> str:
    """Synchronous C2 beacon detection implementation."""

    if not os.path.exists(pcap_path):
        return json.dumps({"success": False, "error": f"PCAP not found: {pcap_path}"})

    # Check file size
    pcap_size = os.path.getsize(pcap_path)
    if pcap_size == 0:
        return json.dumps(
            {"success": False, "error": "PCAP file is empty (no network activity captured)"}
        )

    try:
        from scapy.all import IP, TCP, UDP, rdpcap
    except (ImportError, OSError) as exc:
        return json.dumps({"success": False, "error": f"scapy unavailable: {exc}"})

    try:
        # Read PCAP
        packets = rdpcap(pcap_path)

        if not packets:
            return json.dumps({"success": False, "error": "No packets in PCAP"})

        # Group connections by destination
        connections = defaultdict(list)

        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                timestamp = float(pkt.time)

                # Track outbound connections
                if TCP in pkt or UDP in pkt:
                    if TCP in pkt:
                        dst_port = pkt[TCP].dport
                        protocol = "TCP"
                    else:
                        dst_port = pkt[UDP].dport
                        protocol = "UDP"

                    connection_key = f"{dst_ip}:{dst_port}/{protocol}"
                    connections[connection_key].append(
                        {"timestamp": timestamp, "src": src_ip, "size": len(pkt)}
                    )

        # Analyze each connection for beaconing
        beacons = []

        for conn_key, packets_list in connections.items():
            if len(packets_list) < 3:  # Need at least 3 packets to detect pattern
                continue

            timestamps = [p["timestamp"] for p in packets_list]
            timestamps.sort()

            # Analyze intervals
            stats = analyze_beacon_intervals(timestamps)

            if not stats:
                continue

            # Check if intervals match our criteria
            avg_interval = stats.get("avg_interval_sec", 0)
            if min_interval_sec <= avg_interval <= max_interval_sec:
                # Check if pattern is regular enough
                if stats.get("is_regular", False):
                    dst_parts = conn_key.split("/")
                    dst_addr = dst_parts[0]
                    protocol = dst_parts[1] if len(dst_parts) > 1 else "unknown"

                    beacons.append(
                        {
                            "destination": dst_addr,
                            "protocol": protocol,
                            "packet_count": len(packets_list),
                            "first_seen": timestamps[0],
                            "last_seen": timestamps[-1],
                            "duration_sec": round(timestamps[-1] - timestamps[0], 2),
                            "statistics": stats,
                            "confidence": "high"
                            if stats["coefficient_of_variation"] < 0.15
                            else "medium",
                        }
                    )

        # Sort by confidence and regularity
        beacons.sort(
            key=lambda x: (x["confidence"] == "high", -x["statistics"]["coefficient_of_variation"]),
            reverse=True,
        )

        # Extract unique destinations
        unique_destinations = list(set([b["destination"] for b in beacons]))

        result = {
            "success": True,
            "pcap_path": pcap_path,
            "pcap_size_bytes": pcap_size,
            "total_packets": len(packets),
            "total_connections": len(connections),
            "beacons_detected": len(beacons),
            "beacons": beacons[:20],  # Limit to top 20
            "unique_c2_candidates": unique_destinations[:10],  # Top 10 destinations
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"success": False, "error": f"Beacon detection failed: {e!s}"})


@function_tool(timeout=60)
async def c2_beacon_detect(
    pcap_path: str,
    min_interval_sec: float = 1.0,
    max_interval_sec: float = 3600.0,
) -> str:
    """Detect C2 beaconing patterns in network traffic capture.

    Args:
        pcap_path: Path to PCAP file from sandbox detonation
        min_interval_sec: Minimum beacon interval to consider (default: 1.0)
        max_interval_sec: Maximum beacon interval to consider (default: 3600.0)

    Returns:
        JSON string with detected beacons, timing statistics, and C2 candidates
    """
    return await asyncio.to_thread(
        c2_beacon_detect_sync,
        pcap_path,
        min_interval_sec,
        max_interval_sec,
    )
