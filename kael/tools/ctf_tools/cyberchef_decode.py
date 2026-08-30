"""``cyberchef_decode`` — multi-layer encoding chain decoder.

Walks an input string through repeated decodes (base64, base32, hex,
URL, HTML entities, ROT13, base58, base85, unicode escapes, decimal,
binary, octal) and returns the most plausible plaintext along with
the chain of operations that produced it. Inspired by CyberChef's
"Magic" operation.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
from html import unescape as html_unescape
from typing import Any
from urllib.parse import unquote as url_unquote

from agents import function_tool

from .flag_format import looks_like_flag as _looks_like_flag


_HEX_RE = re.compile(rb"^[0-9a-fA-F]+$")
_BIN_RE = re.compile(r"^[01\s]+$")
_OCT_RE = re.compile(r"^[0-7\s]+$")
_DEC_RE = re.compile(r"^\d+(\s+\d+)*$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")
_B32_RE = re.compile(r"^[A-Z2-7]*={0,6}$")
_B58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")
_B85_RE = re.compile(r"^[A-Za-z0-9!#$%&()*+\-;<=>?@^_`{|}~]+$")


def _try_base64(s: str) -> bytes | None:
    s = s.strip()
    if not s or len(s) < 8 or not _B64_RE.match(s):
        return None
    if len(s) % 4 != 0:
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _try_base64url(s: str) -> bytes | None:
    s = s.strip()
    if not s or len(s) < 8 or not _B64URL_RE.match(s):
        return None
    if len(s) % 4 not in (0, 2, 3):
        return None
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None


def _try_base32(s: str) -> bytes | None:
    s = s.strip().upper()
    if not s or len(s) < 8 or not _B32_RE.match(s):
        return None
    if len(s) % 8 != 0:
        return None
    try:
        return base64.b32decode(s)
    except (binascii.Error, ValueError):
        return None


def _try_hex(s: str) -> bytes | None:
    s = s.strip().replace(" ", "").replace("0x", "").replace("\\x", "")
    if not s or len(s) < 4 or len(s) % 2 != 0 or not _HEX_RE.match(s.encode()):
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


def _try_binary(s: str) -> bytes | None:
    s = s.strip().replace(" ", "")
    if not _BIN_RE.match(s) or len(s) < 8 or len(s) % 8 != 0:
        return None
    return bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))


def _try_octal(s: str) -> bytes | None:
    s = s.strip()
    if not _OCT_RE.match(s):
        return None
    parts = s.split()
    if not parts:
        return None
    try:
        return bytes(int(p, 8) for p in parts)
    except ValueError:
        return None


def _try_decimal(s: str) -> bytes | None:
    s = s.strip()
    if not _DEC_RE.match(s):
        return None
    parts = s.split()
    if not parts or any(int(p) > 255 for p in parts):
        return None
    try:
        return bytes(int(p) for p in parts)
    except ValueError:
        return None


def _try_base85(s: str) -> bytes | None:
    s = s.strip()
    if not s or len(s) < 8 or not _B85_RE.match(s):
        return None
    for decoder in (base64.a85decode, base64.b85decode):
        try:
            return decoder(s)
        except (binascii.Error, ValueError):
            continue
    return None


def _try_base58(s: str) -> bytes | None:
    s = s.strip()
    if not s or len(s) < 8 or not _B58_RE.match(s):
        return None
    try:
        import base58  # type: ignore[import-not-found]

        return base58.b58decode(s)
    except (ImportError, ValueError):
        return None


def _try_url(s: str) -> str | None:
    if "%" not in s:
        return None
    try:
        decoded = url_unquote(s)
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if decoded != s else None


def _try_html(s: str) -> str | None:
    if "&" not in s or ";" not in s:
        return None
    try:
        decoded = html_unescape(s)
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if decoded != s else None


def _try_rot13(s: str) -> str | None:
    if not re.search(r"[a-zA-Z]{4,}", s):
        return None
    decoded = codecs.encode(s, "rot_13")
    return decoded if decoded != s else None


def _try_unicode_escape(s: str) -> str | None:
    if "\\u" not in s and "\\x" not in s:
        return None
    try:
        decoded = s.encode("utf-8").decode("unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded != s else None


def _is_printable(b: bytes) -> bool:
    return all(9 <= c <= 13 or 32 <= c < 127 for c in b)


def _iter_decodings(s: str) -> list[tuple[str, bytes | str]]:
    """Yield ``(op_name, decoded)`` candidates in priority order."""
    candidates: list[tuple[str, bytes | str]] = []
    s_bytes = s.encode("utf-8", errors="replace")

    if s_bytes.startswith(b"\\u"):
        decoded = _try_unicode_escape(s)
        if decoded is not None:
            candidates.append(("unicode_escape", decoded))

    if _try_hex(s) is not None:
        candidates.append(("hex", _try_hex(s)))  # type: ignore[arg-type]
    if _try_binary(s) is not None:
        candidates.append(("binary", _try_binary(s)))  # type: ignore[arg-type]
    if _try_decimal(s) is not None:
        candidates.append(("decimal", _try_decimal(s)))  # type: ignore[arg-type]
    if _try_octal(s) is not None:
        candidates.append(("octal", _try_octal(s)))  # type: ignore[arg-type]
    if _try_base64(s) is not None:
        candidates.append(("base64", _try_base64(s)))  # type: ignore[arg-type]
    if _try_base64url(s) is not None:
        candidates.append(("base64url", _try_base64url(s)))  # type: ignore[arg-type]
    if _try_base32(s) is not None:
        candidates.append(("base32", _try_base32(s)))  # type: ignore[arg-type]
    if _try_base85(s) is not None:
        candidates.append(("base85", _try_base85(s)))  # type: ignore[arg-type]
    if _try_base58(s) is not None:
        candidates.append(("base58", _try_base58(s)))  # type: ignore[arg-type]

    decoded = _try_url(s)
    if decoded is not None:
        candidates.append(("url", decoded))
    decoded = _try_html(s)
    if decoded is not None:
        candidates.append(("html", decoded))
    decoded = _try_rot13(s)
    if decoded is not None:
        candidates.append(("rot13", decoded))

    return candidates


_STRUCTURAL_OPS = frozenset(
    {"hex", "binary", "octal", "decimal", "base64", "base64url", "base32", "base85", "base58"}
)


def _score_chain(final: str, ops: list[str], input_str: str) -> float:
    """Score a decoded chain. Higher is better.

    Heuristics:
    - Contains a flag prefix → +1000
    - Chain contains a structural decoder (base64, hex, etc.) → +100 per op
    - Final is shorter than input → +50 (compression-style ops reduce)
    - Final is alphanumeric only (vs input has lots of `+/=` etc.) → +20
    - Final has whitespace (looks like a sentence) → +5
    """
    score = 0.0
    if _looks_like_flag(final):
        score += 1000.0
    for op in ops:
        if op in _STRUCTURAL_OPS:
            score += 100.0
    if len(final) < len(input_str) and len(final) > 0:
        score += 50.0
    if final and all(c.isalnum() or c in " -_{}!?:;.,'" for c in final):
        score += 20.0
    if " " in final:
        score += 5.0
    return score


def _decode_chain(
    input_str: str, max_depth: int = 6, expected_format: str | None = None
) -> dict[str, Any]:
    """Greedy multi-layer decode. Returns the chain that yields a flag
    or a printable string. Stops on the first chain that produces a
    plausible flag; otherwise returns the highest-scoring chain.
    """
    if not input_str:
        return {"success": False, "error": "Empty input"}

    seen: set[str] = {input_str}
    chains: list[dict[str, Any]] = []
    queue: list[tuple[str, list[str], list[Any]]] = [(input_str, [], [])]
    flag_chains: list[dict[str, Any]] = []

    while queue:
        current, ops, payloads = queue.pop(0)
        if current in seen and (current, tuple(ops)) == (input_str, ()):
            pass
        if current in seen and (current, tuple(ops)) != (input_str, ()):
            continue

        if len(ops) >= max_depth:
            chains.append(
                {
                    "ops": list(ops),
                    "final": current,
                    "found_flag": _looks_like_flag(current),
                }
            )
            continue

        produced_new = False
        for op, decoded in _iter_decodings(current):
            if isinstance(decoded, bytes):
                if not _is_printable(decoded):
                    continue
                try:
                    next_str = decoded.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    continue
            else:
                next_str = decoded

            if next_str == current:
                continue

            new_ops = ops + [op]
            new_payloads = payloads + [current]
            entry = {
                "ops": list(new_ops),
                "payloads": new_payloads,
                "final": next_str,
                "found_flag": _looks_like_flag(next_str, expected_format=expected_format),
            }
            if entry["found_flag"]:
                flag_chains.append(entry)
            chains.append(entry)
            if next_str not in seen and len(new_ops) < max_depth:
                seen.add(next_str)
                queue.append((next_str, new_ops, new_payloads))
            produced_new = True

        if not produced_new:
            chains.append(
                {
                    "ops": list(ops),
                    "final": current,
                    "found_flag": _looks_like_flag(current),
                }
            )

    if flag_chains:
        chosen = flag_chains[0]
    elif chains:
        chosen = max(
            chains,
            key=lambda c: _score_chain(c.get("final", ""), c.get("ops", []), input_str),
        )
    else:
        return {"success": False, "error": "No decodable chain found"}

    return {
        "success": True,
        "input": input_str,
        "chain": chosen.get("ops", []),
        "final": chosen.get("final", ""),
        "found_flag": chosen.get("found_flag", False),
        "stages": chosen.get("payloads", []),
    }


@function_tool(timeout=30, strict_mode=False)
async def cyberchef_decode(  # type: ignore[no-untyped-def]
    ctx,
    input: str,
    expected_format: str | None = None,
) -> str:
    """Decode a string through a chain of common encodings (CTF helper).

    Iteratively tries to peel off encodings in the order: hex, binary,
    decimal, octal, base64, base64url, base32, base85, base58, URL
    encoding, HTML entities, ROT13, and unicode escapes. Returns the
    most plausible decoded plaintext (preferring chains that contain a
    flag-shaped string) along with the chain of operations that
    produced it.

    Inspired by CyberChef's "Magic" operation. Use this for the CTF
    "decoder ring" / multi-layer encoding challenges.

    Args:
        input: The encoded string. May be wrapped in 1-10 layers.
        expected_format: Optional Python regex (e.g. ``r"^flag\\{.+\\}$"``
            or ``r"^DASCTF\\{.+\\}$"``) the agent extracted from the
            challenge description. When supplied, the built-in CTF
            format library is bypassed and only this regex is used to
            detect a flag-shaped final value. Use it when the challenge
            uses a non-standard prefix.

    Returns:
        JSON with ``chain`` (list of operations), ``final`` (decoded
        output), ``found_flag`` (bool), and ``stages`` (intermediate
        values).
    """
    result = _decode_chain(input, expected_format=expected_format)
    return json.dumps(result, ensure_ascii=False, indent=2)
