"""String extraction tool for IOC discovery."""

from __future__ import annotations

import asyncio
import base64
import json
import re
from typing import Any

from agents.tool import function_tool

from ._path_resolver import ensure_host_path


# IOC regex patterns
URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](?::[0-9]+)?(?:/[^\s]*)?", re.IGNORECASE
)

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

IPV6_PATTERN = re.compile(
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}",
    re.IGNORECASE,
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

FILE_PATH_PATTERN = re.compile(r'(?:[A-Z]:\\|/)[^\s<>"|?*]+', re.IGNORECASE)

REGISTRY_KEY_PATTERN = re.compile(
    r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s<>"|]+', re.IGNORECASE
)

MUTEX_PATTERN = re.compile(r"(?:Global|Local)\\[a-zA-Z0-9_\-]+", re.IGNORECASE)

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")


def extract_ascii_strings(data: bytes, min_length: int = 4) -> list[dict[str, Any]]:
    """Extract ASCII strings from binary data."""
    ascii_pattern = re.compile(rb"[ -~]{" + str(min_length).encode() + rb",}")
    strings = []

    for match in ascii_pattern.finditer(data):
        offset = match.start()
        value = match.group(0).decode("ascii")
        strings.append(
            {
                "offset": f"0x{offset:X}",
                "value": value,
                "context": "",  # Context will be added later if needed
            }
        )

    return strings


def extract_unicode_strings(data: bytes, min_length: int = 4) -> list[dict[str, Any]]:
    """Extract UTF-16LE strings from binary data."""
    # Look for null-interleaved ASCII (UTF-16LE)
    unicode_pattern = re.compile(rb"(?:[ -~]\x00){" + str(min_length).encode() + rb",}")
    strings = []

    for match in unicode_pattern.finditer(data):
        offset = match.start()
        try:
            value = match.group(0).decode("utf-16le").rstrip("\x00")
            strings.append({"offset": f"0x{offset:X}", "value": value, "context": ""})
        except Exception:
            pass

    return strings


def extract_base64_strings(strings: list[dict[str, Any]], data: bytes) -> list[dict[str, Any]]:
    """Detect and decode base64-encoded strings."""
    decoded = []

    for string_info in strings:
        value = string_info["value"]

        # Check if it looks like base64
        if len(value) >= 20 and BASE64_PATTERN.match(value):
            try:
                # Try to decode
                decoded_bytes = base64.b64decode(value, validate=True)

                # Check if decoded data is printable
                if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded_bytes):
                    decoded_str = decoded_bytes.decode("ascii")
                    decoded.append(
                        {
                            "offset": string_info["offset"],
                            "encoded": value[:50] + ("..." if len(value) > 50 else ""),
                            "decoded": decoded_str,
                        }
                    )
            except Exception:
                pass

    return decoded


def extract_iocs(all_strings: list[str]) -> dict[str, list[str]]:
    """Extract IOCs from strings."""
    iocs: dict[str, list[str]] = {
        "urls": [],
        "ips": [],
        "domains": [],
        "file_paths": [],
        "registry_keys": [],
        "mutexes": [],
        "emails": [],
    }

    combined_text = "\n".join(all_strings)

    # Extract URLs
    for match in URL_PATTERN.finditer(combined_text):
        url = match.group(0)
        if url not in iocs["urls"]:
            iocs["urls"].append(url)

    # Extract IPs (v4 and v6)
    for match in IPV4_PATTERN.finditer(combined_text):
        ip = match.group(0)
        # Filter out common non-IP patterns
        if not ip.startswith(("0.", "127.", "255.")):
            if ip not in iocs["ips"]:
                iocs["ips"].append(ip)

    for match in IPV6_PATTERN.finditer(combined_text):
        ip = match.group(0)
        if ip not in iocs["ips"]:
            iocs["ips"].append(ip)

    # Extract domains
    for match in DOMAIN_PATTERN.finditer(combined_text):
        domain = match.group(0).lower()
        # Filter out common false positives
        if not domain.endswith((".dll", ".exe", ".sys", ".txt", ".log")):
            if domain not in iocs["domains"] and domain not in iocs["urls"]:
                iocs["domains"].append(domain)

    # Extract file paths
    for match in FILE_PATH_PATTERN.finditer(combined_text):
        path = match.group(0)
        if path not in iocs["file_paths"]:
            iocs["file_paths"].append(path)

    # Extract registry keys
    for match in REGISTRY_KEY_PATTERN.finditer(combined_text):
        key = match.group(0)
        if key not in iocs["registry_keys"]:
            iocs["registry_keys"].append(key)

    # Extract mutexes
    for match in MUTEX_PATTERN.finditer(combined_text):
        mutex = match.group(0)
        if mutex not in iocs["mutexes"]:
            iocs["mutexes"].append(mutex)

    # Extract emails
    for match in EMAIL_PATTERN.finditer(combined_text):
        email = match.group(0).lower()
        if email not in iocs["emails"]:
            iocs["emails"].append(email)

    return iocs


def extract_strings_sync(
    sample_path: str,
    min_length: int = 4,
    extract_base64: bool = True,
    extract_hex: bool = True,
) -> str:
    """Synchronous string extraction implementation."""
    try:
        # Resolve container path to host path
        success, resolved_path, error = ensure_host_path(sample_path)
        if not success:
            return json.dumps(
                {
                    "success": False,
                    "error": error,
                    "original_path": sample_path,
                }
            )

        with open(resolved_path, "rb") as f:
            data = f.read()

        # Extract ASCII strings
        ascii_strings = extract_ascii_strings(data, min_length)

        # Extract Unicode strings
        unicode_strings = extract_unicode_strings(data, min_length)

        # Extract base64-encoded strings
        base64_decoded = []
        if extract_base64:
            base64_decoded = extract_base64_strings(ascii_strings, data)

        # Combine all string values for IOC extraction
        all_string_values = [s["value"] for s in ascii_strings]
        all_string_values.extend([s["value"] for s in unicode_strings])
        all_string_values.extend([s["decoded"] for s in base64_decoded])

        # Extract IOCs
        iocs = extract_iocs(all_string_values)

        # Look for crypto artifacts
        crypto_artifacts = {"keys": [], "constants": []}

        # Check for common crypto constants
        # AES S-box first bytes
        aes_sbox_start = bytes(
            [
                0x63,
                0x7C,
                0x77,
                0x7B,
                0xF2,
                0x6B,
                0x6F,
                0xC5,
                0x30,
                0x01,
                0x67,
                0x2B,
                0xFE,
                0xD7,
                0xAB,
                0x76,
            ]
        )
        if aes_sbox_start in data:
            offset = data.find(aes_sbox_start)
            crypto_artifacts["constants"].append(f"Possible AES S-box at 0x{offset:X}")

        # Base64 standard table
        base64_table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        if base64_table in data:
            offset = data.find(base64_table)
            crypto_artifacts["constants"].append(f"Base64 table at 0x{offset:X}")

        # Limit output to reasonable size
        max_strings = 1000

        result = {
            "success": True,
            "strings": {
                "ascii": ascii_strings[:max_strings],
                "unicode": unicode_strings[:max_strings],
                "base64_decoded": base64_decoded[:100],
            },
            "iocs": iocs,
            "crypto_artifacts": crypto_artifacts,
            "string_count": {
                "total": len(ascii_strings) + len(unicode_strings),
                "suspicious": len(base64_decoded) + len(crypto_artifacts["constants"]),
            },
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@function_tool(timeout=60)
async def extract_strings(
    sample_path: str,
    min_length: int = 4,
    extract_base64: bool = True,
    extract_hex: bool = True,
) -> str:
    """Extract and categorize strings from a binary file.

    Extracts ASCII, Unicode, and base64-encoded strings, then categorizes
    them into IOC types (URLs, IPs, domains, file paths, registry keys, etc.).

    Args:
        sample_path: Path to the sample file
        min_length: Minimum string length to extract
        extract_base64: Whether to detect and decode base64 strings
        extract_hex: Whether to extract hex-encoded strings

    Returns:
        JSON string with extracted strings and IOCs:
        - ASCII strings with offsets
        - Unicode (UTF-16LE) strings with offsets
        - Base64-decoded strings
        - Categorized IOCs (URLs, IPs, domains, paths, registry keys, mutexes, emails)
        - Crypto artifacts (potential keys, algorithm constants)
    """
    return await asyncio.to_thread(
        extract_strings_sync,
        sample_path,
        min_length,
        extract_base64,
        extract_hex,
    )
