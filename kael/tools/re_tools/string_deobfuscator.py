"""String deobfuscator for malware analysis.

Reconstructs stack strings, detects multi-byte XOR encryption, and identifies
custom encoding schemes commonly used in malware to hide strings.
"""

from __future__ import annotations

import asyncio
import json
import re
import string
from collections import Counter

from agents.tool import function_tool

from ._path_resolver import ensure_host_path


# English letter frequency (for frequency analysis)
ENGLISH_FREQ = {
    "a": 0.08167,
    "b": 0.01492,
    "c": 0.02782,
    "d": 0.04253,
    "e": 0.12702,
    "f": 0.02228,
    "g": 0.02015,
    "h": 0.06094,
    "i": 0.06966,
    "j": 0.00153,
    "k": 0.00772,
    "l": 0.04025,
    "m": 0.02406,
    "n": 0.06749,
    "o": 0.07507,
    "p": 0.01929,
    "q": 0.00095,
    "r": 0.05987,
    "s": 0.06327,
    "t": 0.09056,
    "u": 0.02758,
    "v": 0.00978,
    "w": 0.02360,
    "x": 0.00150,
    "y": 0.01974,
    "z": 0.00074,
    " ": 0.13000,
}


def calculate_chi_squared(text: str) -> float:
    """Calculate chi-squared statistic to detect English-like text."""
    text = text.lower()
    if not text:
        return float("inf")

    # Count characters
    char_counts = Counter(c for c in text if c in string.printable and c != "\n")
    total = sum(char_counts.values())

    if total == 0:
        return float("inf")

    chi_sq = 0.0
    for char, expected_freq in ENGLISH_FREQ.items():
        observed = char_counts.get(char, 0)
        expected = expected_freq * total
        if expected > 0:
            chi_sq += ((observed - expected) ** 2) / expected

    # Normalize for input length so the score is comparable across samples.
    return (chi_sq / total) * 10


def try_xor_single_byte(data: bytes, min_length: int = 6) -> list[dict]:
    """Try all 256 single-byte XOR keys and return promising results."""
    results = []

    for key in range(256):
        xored = bytes(b ^ key for b in data)

        # Check if result is mostly printable ASCII
        if not xored:
            continue

        printable_count = sum(1 for b in xored if 32 <= b < 127 or b in (9, 10, 13))
        printable_ratio = printable_count / len(xored)

        if printable_ratio >= 0.85 and len(xored) >= min_length:
            try:
                text = xored.decode("ascii", errors="ignore")

                # Check if it looks like English/ASCII text
                chi_sq = calculate_chi_squared(text)

                results.append(
                    {
                        "key": f"0x{key:02X}",
                        "decoded": text[:200],  # Limit length
                        "full_length": len(xored),
                        "printable_ratio": round(printable_ratio, 3),
                        "chi_squared": round(chi_sq, 2),
                        "score": printable_ratio - (chi_sq / 100),  # Higher is better
                    }
                )
            except Exception:
                pass

    # Sort by score (best first)
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:10]  # Return top 10 candidates


def try_xor_multi_byte(data: bytes, key_length: int = 4) -> list[dict]:
    """Try multi-byte XOR keys (Kasiski examination + frequency analysis)."""
    if len(data) < key_length * 2:
        return []

    results = []

    # Try common key lengths
    for key_len in [2, 3, 4, 5, 6, 7, 8]:
        # Split data into columns
        columns = [[] for _ in range(key_len)]
        for i, byte in enumerate(data):
            columns[i % key_len].append(byte)

        # Find best key byte for each column
        key = []
        for col in columns:
            best_key = 0
            best_score = float("-inf")

            for k in range(256):
                xored = bytes(b ^ k for b in col)
                if not xored:
                    continue

                printable_count = sum(1 for b in xored if 32 <= b < 127 or b in (9, 10, 13))
                printable_ratio = printable_count / len(xored) if xored else 0

                if printable_ratio > 0.7:
                    try:
                        text = xored.decode("ascii", errors="ignore")
                        chi_sq = calculate_chi_squared(text)
                        language_ratio = sum(
                            1 for char in text if char.isalnum() or char in " .,;:_-/"
                        ) / len(text)
                        score = printable_ratio * 3 + language_ratio - min(chi_sq, 1_000) / 1_000
                        if score > best_score:
                            best_score = score
                            best_key = k
                    except Exception:
                        pass

            key.append(best_key)

        # Decrypt with found key
        try:
            key_bytes = bytes(key)
            xored = bytes(data[i] ^ key_bytes[i % key_len] for i in range(len(data)))
            text = xored.decode("ascii", errors="ignore")

            printable_count = sum(1 for b in xored if 32 <= b < 127)
            printable_ratio = printable_count / len(xored) if xored else 0

            if printable_ratio >= 0.8:
                results.append(
                    {
                        "key_length": key_len,
                        "key": key_bytes.hex(),
                        "decoded": text[:200],
                        "full_length": len(xored),
                        "printable_ratio": round(printable_ratio, 3),
                    }
                )
        except Exception:
            pass

    return results


def try_rot13(data: bytes) -> dict | None:
    """Check if data is ROT13 encoded."""
    try:
        text = data.decode("ascii", errors="ignore")
        # ROT13 is a Caesar cipher with shift 13
        decoded = text.translate(
            str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            )
        )

        # Check if decoded text looks more like English
        original_chi = calculate_chi_squared(text)
        decoded_chi = calculate_chi_squared(decoded)

        if decoded_chi < original_chi and decoded_chi < 200:
            return {
                "encoding": "ROT13",
                "decoded": decoded[:200],
                "full_length": len(decoded),
                "confidence": round((original_chi - decoded_chi) / max(original_chi, 1), 3),
            }
    except Exception:
        pass

    return None


def detect_stack_strings(file_path: str) -> list[dict]:
    """Detect stack strings (push/mov sequences that build strings on stack)."""
    stack_strings = []

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Pattern 1: Look for sequences of push instructions with ASCII values
        # x86 push imm32 = 0x68 + 4 bytes (little-endian)
        # x86 push imm8 = 0x6A + 1 byte

        # Find all push imm32 sequences
        push_pattern = re.compile(rb"\x68(.{4})", re.DOTALL)
        pushes = []
        for match in push_pattern.finditer(data):
            try:
                value = int.from_bytes(match.group(1), "little")
                # Check if it's ASCII (4 chars)
                if all(32 <= (value >> (i * 8)) & 0xFF < 127 for i in range(4)):
                    char_bytes = bytes([(value >> (i * 8)) & 0xFF for i in range(4)])
                    pushes.append((match.start(), char_bytes.decode("ascii")))
            except Exception:
                pass

        # Look for sequences of 3+ consecutive pushes (forming a string)
        if len(pushes) >= 3:
            for i in range(len(pushes) - 2):
                if (
                    pushes[i + 1][0] - pushes[i][0] <= 6
                    and pushes[i + 2][0] - pushes[i + 1][0] <= 6
                ):
                    # Consecutive pushes found
                    offset1, str1 = pushes[i]
                    offset2, str2 = pushes[i + 1]
                    offset3, str3 = pushes[i + 2]

                    # Reverse order (stack grows down, last push is first char)
                    combined = str3 + str2 + str1

                    if len(combined) >= 6 and all(c in string.printable for c in combined):
                        stack_strings.append(
                            {
                                "type": "push_sequence",
                                "offset": f"0x{offset1:X}",
                                "decoded": combined,
                            }
                        )

        # Pattern 2: Look for mov [esp+offset], imm32 sequences
        # This is more complex and architecture-specific, skip for now

    except Exception:
        pass

    return stack_strings[:20]  # Limit results


def detect_api_hashing(data: bytes) -> list[dict]:
    """Detect API name hashing patterns (common in malware)."""
    hash_patterns = []

    try:
        # Look for common hash constants
        # CRC32 polynomial: 0xEDB88320
        if b"\x20\x83\xb8\xed" in data:
            hash_patterns.append(
                {
                    "type": "CRC32_polynomial",
                    "constant": "0xEDB88320",
                    "note": "Common in API hashing",
                }
            )

        # DJB2 hash: hash * 33 + c
        # Look for multiplication by 33 (0x21)
        if b"\x69\x21" in data or b"\x83\xc0\x41" in data:  # imul eax, eax, 0x21 patterns
            hash_patterns.append(
                {
                    "type": "DJB2_hash",
                    "note": "Multiplication by 33 suggests DJB2 hash",
                }
            )

        # FNV hash: FNV_offset_basis = 0x811C9DC5
        if b"\xc5\x9d\x1c\x81" in data:
            hash_patterns.append(
                {
                    "type": "FNV1_hash",
                    "constant": "0x811C9DC5",
                    "note": "FNV-1 hash initialization",
                }
            )

        # ROR13 (used in shellcode/Metasploit)
        # Look for ROR instruction (rotate right) patterns
        if b"\xd1\xc8" in data or b"\xc1\xc8\x0d" in data:  # ror eax, 1 or ror eax, 13
            hash_patterns.append(
                {
                    "type": "ROR13_hash",
                    "note": "Rotate right 13 suggests Metasploit-style API hash",
                }
            )

    except Exception:
        pass

    return hash_patterns


def string_deobfuscation_sync(
    sample_path: str,
    try_xor: bool = True,
    try_rot13: bool = True,
    detect_stack: bool = True,
) -> str:
    """Synchronous string deobfuscation implementation."""
    try:
        success, resolved_path, error = ensure_host_path(sample_path)
        if not success:
            return json.dumps(
                {
                    "success": False,
                    "error": error,
                    "original_path": sample_path,
                }
            )

        sample_path = resolved_path

        with open(sample_path, "rb") as f:
            data = f.read()

        result = {
            "success": True,
            "sample_path": sample_path,
            "file_size": len(data),
            "xor_single_byte": [],
            "xor_multi_byte": [],
            "rot13": None,
            "stack_strings": [],
            "api_hashing": [],
        }

        # Try single-byte XOR on the first 4KB (most strings are near the start)
        if try_xor:
            sample = data[:4096]
            result["xor_single_byte"] = try_xor_single_byte(sample)
            result["xor_multi_byte"] = try_xor_multi_byte(sample)

        # Try ROT13
        if try_rot13:
            result["rot13"] = try_rot13(data[:4096])

        # Detect stack strings
        if detect_stack:
            result["stack_strings"] = detect_stack_strings(sample_path)

        # Detect API hashing
        result["api_hashing"] = detect_api_hashing(data)

        # Summary
        result["obfuscation_detected"] = (
            len(result["xor_single_byte"]) > 0
            or len(result["xor_multi_byte"]) > 0
            or result["rot13"] is not None
            or len(result["stack_strings"]) > 0
            or len(result["api_hashing"]) > 0
        )

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps(
            {
                "success": False,
                "error": f"String deobfuscation failed: {e!s}",
            }
        )


@function_tool(timeout=90)
async def string_deobfuscator(
    sample_path: str,
    try_xor: bool = True,
    try_rot13: bool = True,
    detect_stack: bool = True,
) -> str:
    """Deobfuscate strings using multiple techniques.

    Attempts single-byte XOR brute force, multi-byte XOR with frequency analysis,
    ROT13 detection, stack string reconstruction, and API name hashing detection.

    Args:
        sample_path: Path to the sample file
        try_xor: Whether to attempt XOR decryption (default: True)
        try_rot13: Whether to check for ROT13 encoding (default: True)
        detect_stack: Whether to detect stack string construction (default: True)

    Returns:
        JSON string with deobfuscation results including:
        - Single-byte XOR candidates (top 10 by score)
        - Multi-byte XOR results (key length 2-8)
        - ROT13 decoded text (if detected)
        - Stack strings (push/mov sequences)
        - API hashing patterns (CRC32, DJB2, FNV, ROR13)
    """
    return await asyncio.to_thread(
        string_deobfuscation_sync,
        sample_path,
        try_xor,
        try_rot13,
        detect_stack,
    )
