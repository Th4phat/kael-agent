"""Flag format detection for CTF challenges.

A flag in CTF can take many shapes:

- Standard with braces: ``flag{...}``, ``CTF{...}``, ``picoCTF{...}``
- Exotic: ``flag_xxxxx``, ``https://ctf.example/flag/xxxxx``,
  ``FLAG:xxxxx``, ``uuid``, or just a base64 string.
- No flag at all: the "flag" is the entire answer (e.g. a city, a domain).

The :func:`looks_like_flag` function takes an optional ``expected_format``
regex (from the challenge description) and falls back to a library of
known CTF patterns. The :data:`KNOWN_FORMATS` mapping enumerates the
common CTF flag prefixes.

This module is shared by every tool in :mod:`kael.tools.ctf_tools` so
the same detection rules apply across the whole agent.
"""

from __future__ import annotations

import re
from typing import Final


# Comprehensive catalog of CTF flag prefixes and patterns.
# Order: most generic first (loose matching) → most specific.
KNOWN_FORMATS: Final[dict[str, list[str]]] = {
    "generic_prefixed": [
        r"^flag\{[^}]{2,}\}$",
        r"^FLAG\{[^}]{2,}\}$",
        r"^ctf\{[^}]{2,}\}$",
        r"^CTF\{[^}]{2,}\}$",
    ],
    "platform_specific": {
        "picoCTF": r"^picoCTF\{[^}]{2,}\}$",
        "HackTheBox": r"^HTB\{[^}]{2,}\}$",
        "TryHackMe": r"^THM\{[^}]{2,}\}$",
        "DASCTF": r"^DASCTF\{[^}]{2,}\}$",
        "TUCTF": r"^TUCTF\{[^}]{2,}\}$",
        "0ops": r"^0ops\{[^}]{2,}\}$",
        "n1ctf": r"^n1ctf\{[^}]{2,}\}$",
        "SUCTF": r"^SUCTF\{[^}]{2,}\}$",
        "RCTF": r"^RCTF\{[^}]{2,}\}$",
        "BJDCTF": r"^BJDCTF\{[^}]{2,}\}$",
        "H&NCTF": r"^H&NCTF\{[^}]{2,}\}$",
        "LitCTF": r"^LitCTF\{[^}]{2,}\}$",
        "NewStarCTF": r"^NewStarCTF\{[^}]{2,}\}$",
        "HFCTF": r"^HFCTF\{[^}]{2,}\}$",
        "D3CTF": r"^D3CTF\{[^}]{2,}\}$",
        "GYCTF": r"^GYCTF\{[^}]{2,}\}$",
        "GKCTF": r"^GKCTF\{[^}]{2,}\}$",
        "BaseCTF": r"^BaseCTF\{[^}]{2,}\}$",
        "CCTF": r"^CCTF\{[^}]{2,}\}$",
        "VNCTF": r"^VNCTF\{[^}]{2,}\}$",
        "DuckyCTF": r"^DuckyCTF\{[^}]{2,}\}$",
        "dice": r"^dice\{[^}]{2,}\}$",
        "buckeye": r"^buckeye\{[^}]{2,}\}$",
        "pwn.college": r"^pwn\.college\{[^}]{2,}\}$",
        "SEKAI": r"^SEKAI\{[^}]{2,}\}$",
        "idek": r"^idek\{[^}]{2,}\}$",
        "crew": r"^crew\{[^}]{2,}\}$",
        "grey": r"^grey\{[^}]{2,}\}$",
        "wargames": r"^wgmy\{[^}]{2,}\}$",
    },
    "exotic_no_braces": [
        r"^flag_[A-Za-z0-9_\-]{8,}$",
        r"^FLAG_[A-Za-z0-9_\-]{8,}$",
        r"^FLAG: ?[A-Za-z0-9_\-]{8,}$",
        r"^flag is: ?[A-Za-z0-9_\-]{8,}$",
        r"^The flag is: ?[A-Za-z0-9_\-]{8,}$",
    ],
    "exotic_url": [
        r"^https?://[^\s]+/flag/[A-Za-z0-9_\-]+$",
        r"^https?://[^\s]+/[A-Za-z0-9_\-]{16,}$",
    ],
    "exotic_uuid": [
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        r"^[0-9a-f]{32}$",
    ],
    "exotic_base64": [
        r"^[A-Za-z0-9+/]{16,}={0,2}$",
    ],
    "loose_substring": [
        r"[A-Za-z0-9_]+\{[A-Za-z0-9_!@#$%^&*()\-+=.,;:/'\"\\? ]{4,}\}",
    ],
}


_COMPILED_PATTERNS: list[tuple[str, re.Pattern[str]]] = []


def _ensure_compiled() -> list[tuple[str, re.Pattern[str]]]:
    global _COMPILED_PATTERNS
    if _COMPILED_PATTERNS:
        return _COMPILED_PATTERNS
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for group, pat in KNOWN_FORMATS.items():
        if isinstance(pat, dict):
            for platform, platform_pat in pat.items():
                patterns.append((f"{group}:{platform}", re.compile(platform_pat)))
        else:
            for p in pat:
                patterns.append((group, re.compile(p)))
    _COMPILED_PATTERNS = patterns
    return patterns


def looks_like_flag(  # noqa: PLR0911 - one branch per format family
    text: str,
    *,
    expected_format: str | None = None,
    require_full_match: bool = True,
) -> bool:
    """Return True if ``text`` looks like a CTF flag.

    Args:
        text: Candidate string.
        expected_format: Optional regex (Python re syntax) the agent
            extracted from the challenge description, e.g. ``r"^flag\\{.+\\}$"``
            or ``r"^CTF\\{[A-Z0-9]+\\}$"``. If supplied, it overrides the
            built-in library.
        require_full_match: When True, the pattern must match the
            entire string. When False, the pattern can match any
            substring (useful for finding a flag embedded in a longer
            response).

    Returns:
        True if any pattern matches.
    """
    if not text:
        return False
    if expected_format:
        try:
            pattern = re.compile(expected_format)
        except re.error:
            return False
        if require_full_match:
            return bool(pattern.fullmatch(text))
        return bool(pattern.search(text))

    for _name, pattern in _ensure_compiled():
        if "loose_substring" in _name:
            if pattern.search(text):
                return True
        elif require_full_match:
            if pattern.fullmatch(text):
                return True
        elif pattern.search(text):
            return True
    return False


def detect_format(text: str) -> str | None:
    """Return the first matched format name, or None.

    Useful for reporting which flag family a candidate belongs to
    (e.g. ``platform_specific:picoCTF``).
    """
    if not text:
        return None
    for name, pattern in _ensure_compiled():
        if "loose_substring" in name:
            continue
        if pattern.fullmatch(text):
            return name
    for name, pattern in _ensure_compiled():
        if "loose_substring" in name and pattern.search(text):
            return name
    return None


def example_formats() -> list[str]:
    """Return a small set of example flag strings (for tests / prompts)."""
    return [
        "flag{abc123}",
        "CTF{plain_text_here}",
        "picoCTF{custom_prefix_42}",
        "HTB{leet_h4x0r}",
        "DASCTF{hex_or_l33t}",
        "flag_custom_no_braces_xyz123",
        "https://ctf.example.com/flag/abc123def",
        "123e4567-e89b-12d3-a456-426614174000",
    ]
