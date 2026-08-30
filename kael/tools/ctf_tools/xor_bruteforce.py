"""``xor_bruteforce`` — single-byte and short-key XOR brute-forcer.

Detects XOR'd data by scoring decoded candidates against printable
ASCII. Returns all keys whose first ``window`` bytes decode to
printable text, ranked by English bigram frequency.
"""

from __future__ import annotations

import json
from typing import Any

from agents import function_tool

from .flag_format import looks_like_flag as _looks_like_flag


_ENGLISH_BIGRAMS = {
    "th": 1.52,
    "he": 1.28,
    "in": 0.94,
    "er": 0.94,
    "an": 0.82,
    "re": 0.68,
    "nd": 0.63,
    "at": 0.59,
    "on": 0.57,
    "nt": 0.56,
    "ha": 0.56,
    "es": 0.56,
    "st": 0.55,
    "en": 0.55,
    "ed": 0.53,
    "to": 0.52,
    "it": 0.50,
    "ou": 0.50,
    "ea": 0.47,
    "hi": 0.46,
    "is": 0.46,
    "or": 0.43,
    "ti": 0.34,
    "as": 0.33,
    "te": 0.27,
    "et": 0.19,
    "ng": 0.18,
    "of": 0.16,
    "al": 0.09,
    "de": 0.09,
    "se": 0.08,
    "le": 0.08,
    "sa": 0.06,
    "si": 0.05,
    "ar": 0.04,
    "ve": 0.04,
    "ra": 0.04,
    "ri": 0.04,
    "ne": 0.04,
}


def _parse_input(data: str) -> bytes:
    """Parse the input string: hex (``0x..`` or bare), base64, or raw text."""
    s = data.strip()
    try:
        if s.startswith("0x") or s.startswith("\\x"):
            return bytes.fromhex(s.replace("0x", "").replace("\\x", "").replace(" ", ""))
        if all(c in "0123456789abcdefABCDEF \n" for c in s) and len(s) % 2 == 0:
            try:
                return bytes.fromhex(s.replace(" ", "").replace("\n", ""))
            except ValueError:
                pass
        import base64

        if len(s) % 4 == 0 and all(
            c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in s
        ):
            try:
                return base64.b64decode(s, validate=True)
            except (ValueError, Exception):
                pass
    except (ValueError, AttributeError):
        pass
    return data.encode("utf-8", errors="replace")


def _score_english(s: str) -> float:
    """Higher score = more likely English text."""
    if not s:
        return 0.0
    s_lower = s.lower()
    score = 0.0
    for bg in _ENGLISH_BIGRAMS:
        score += s_lower.count(bg) * _ENGLISH_BIGRAMS[bg]
    printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\t\n")
    score *= printable / max(len(s), 1)
    return score


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _is_printable_window(s: str, window: int = 64) -> bool:
    sample = s[:window]
    if not sample:
        return False
    return all(9 <= ord(c) <= 13 or 32 <= ord(c) < 127 for c in sample)


def _has_flag_marker(s: str, expected_format: str | None = None) -> bool:
    return _looks_like_flag(s, expected_format=expected_format)


def _brute_single_byte(
    data: bytes, top_n: int = 10, expected_format: str | None = None
) -> list[dict[str, Any]]:
    results = []
    for key in range(256):
        decoded = _xor_bytes(data, bytes([key]))
        try:
            text = decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            try:
                text = decoded.decode("latin-1")
            except Exception:
                continue
        if not _is_printable_window(text):
            continue
        score = _score_english(text)
        results.append(
            {
                "key_hex": f"0x{key:02x}",
                "key_int": key,
                "key_char": chr(key) if 32 <= key < 127 else None,
                "score": round(score, 3),
                "preview": text[:200],
                "flag_marker": _has_flag_marker(text, expected_format),
            }
        )
    results.sort(key=lambda r: (r["flag_marker"], r["score"]), reverse=True)
    return results[:top_n]


def _brute_short_key(
    data: bytes,
    max_key_len: int = 4,
    top_n: int = 5,
    expected_format: str | None = None,
) -> list[dict[str, Any]]:
    """Brute 2-4 byte XOR keys. For longer keys, use `xortool` via the sandbox."""
    if max_key_len < 2:
        return []

    results = []
    candidates_per_len: dict[int, list[dict[str, Any]]] = {}

    for klen in range(2, max_key_len + 1):
        best_for_len: list[dict[str, Any]] = []
        key_int_total = 256**klen
        if key_int_total > 2_000_000:
            best_for_len.append(
                {
                    "key_len": klen,
                    "skipped": True,
                    "reason": f"{key_int_total:,} combinations; use xortool via exec_command",
                    "xortool_command": f"xortool -l {klen} -c 00 input.bin",
                }
            )
            candidates_per_len[klen] = best_for_len
            continue
        for key_int in range(key_int_total):
            key = key_int.to_bytes(klen, "big")
            decoded = _xor_bytes(data, key)
            try:
                text = decoded.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                try:
                    text = decoded.decode("latin-1")
                except Exception:
                    continue
            if not _is_printable_window(text):
                continue
            score = _score_english(text)
            if score <= 0:
                continue
            best_for_len.append(
                {
                    "key_hex": key.hex(),
                    "key_repr": repr(key),
                    "score": round(score, 3),
                    "preview": text[:200],
                    "flag_marker": _has_flag_marker(text, expected_format),
                }
            )
        best_for_len.sort(key=lambda r: (r["flag_marker"], r["score"]), reverse=True)
        candidates_per_len[klen] = best_for_len[:top_n]

    for klen in sorted(candidates_per_len):
        results.extend(candidates_per_len[klen])
    return results


@function_tool(timeout=60, strict_mode=False)
async def xor_bruteforce(  # type: ignore[no-untyped-def]
    ctx,
    data: str,
    max_key_len: int = 4,
    expected_format: str | None = None,
) -> str:
    """Brute-force XOR encryption (single byte and short keys).

    CTFs love XOR with a single byte or a short repeating key. This
    helper tries every single-byte key (256 candidates, returns top 10
    by English bigram score) and every key from 2 to ``max_key_len``
    bytes (capped at ~2M combinations per length; for longer keys, the
    result suggests the ``xortool`` command to run in the sandbox).

    Input can be raw bytes, hex (``0x..`` or bare hex), or base64.

    Args:
        data: Encoded ciphertext (raw, hex, or base64).
        max_key_len: Maximum key length to brute-force for multi-byte
            keys. Defaults to 4; above 6, prefer ``xortool`` in the
            sandbox.
        expected_format: Optional Python regex for the flag shape
            (``r"^flag\\{.+\\}$"`` or platform-specific). When
            supplied, the built-in CTF format library is bypassed and
            only this regex is used to flag a hit.

    Returns:
        JSON with ``single_byte`` (top 10 candidates) and
        ``multi_byte`` (per-length top candidates or a ``xortool``
        hint).
    """
    blob = _parse_input(data)
    if not blob:
        return json.dumps({"success": False, "error": "Empty input"})

    single = _brute_single_byte(blob, expected_format=expected_format)
    multi = _brute_short_key(blob, max_key_len=max_key_len, expected_format=expected_format)

    return json.dumps(
        {
            "success": True,
            "input_length_bytes": len(blob),
            "single_byte": single,
            "multi_byte": multi,
            "hint": (
                "If nothing matches, run `xortool -c 00 -b 8` (or longer) "
                "via exec_command on the raw bytes."
            ),
        },
        ensure_ascii=False,
        indent=2,
    )
