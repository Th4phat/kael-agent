"""``format_string_offset`` — find format-string offset + arg positions.

Given a target program and a marker pattern, returns the offset at
which the pattern appears on the stack via the printf format-string
vulnerability. This is the canonical first step in a format-string
exploit.

The agent should use this to *bootstrap* the offset; subsequent
``%n`` writes can use ``pwntools.fmtstr_payload``.
"""

from __future__ import annotations

import json
from typing import Any

from agents import function_tool


@function_tool(timeout=10, strict_mode=False)
async def format_string_offset(  # type: ignore[no-untyped-def]
    ctx,
    marker: str = "AAAABBBB",
    start: int = 1,
    end: int = 30,
) -> str:
    """Plan a format-string offset probe.

    Generates the ``%N$p`` probe strings you should send to the target
    to discover the stack offset at which the format-string buffer
    appears. Look for the response that contains the hex encoding of
    your marker (``0x4242424241414141`` for ``AAAABBBB``).

    This is a *planning* helper — it does not run the exploit. Use
    the generated probes with ``exec_command`` (e.g. via pwntools
    loop) and feed the result back.

    Args:
        marker: 8-byte pattern to embed in the input (default
            ``AAAABBBB`` = ``0x41414141 42424242``).
        start: First stack offset to probe.
        end: Last stack offset to probe (inclusive).

    Returns:
        JSON with ``probes`` (list of strings to send) and a
        ``match_regex`` (regex to apply to responses to find the
        offset that prints the marker).
    """
    return json.dumps(_build_probes(marker, start, end), ensure_ascii=False, indent=2)


def _build_probes(marker: str, start: int, end: int) -> dict[str, Any]:
    """Sync impl of format_string_offset for direct unit-test use."""
    if len(marker) != 8:
        return {
            "success": False,
            "error": "marker must be exactly 8 bytes (use AAAABBBB or 0xDEADBEEF-style)",
        }

    low = int.from_bytes(marker[:4].encode("latin-1"), "little")
    high = int.from_bytes(marker[4:].encode("latin-1"), "little")

    probes = []
    for i in range(start, end + 1):
        probes.append(f"{marker}%{i}$p")

    return {
        "success": True,
        "marker": marker,
        "match_regex": rf"0x{high:08x}.{{0,4}}0x{low:08x}|0x{low:08x}.{{0,4}}0x{high:08x}",
        "probes": probes,
        "next_step": (
            "Once the offset N is found, use `fmtstr_payload(N, {target: value}, "
            "write_size='short')` from pwntools to build the write payload."
        ),
    }
