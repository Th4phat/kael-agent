"""File triage tool for initial sample classification."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import subprocess
from collections import Counter
from typing import Any

from agents.tool import function_tool

from ._path_resolver import ensure_host_path


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_pe_file(file_path: str) -> dict[str, Any]:
    """Analyze PE file structure."""
    try:
        import pefile
    except ImportError:
        return {"error": "pefile library not available"}

    try:
        pe = pefile.PE(file_path)

        format_info = {
            "type": "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32",
            "arch": "x86_64" if pe.FILE_HEADER.Machine == 0x8664 else "x86",
            "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, ["Unknown"])[0],
        }

        # Analyze sections
        sections = []
        packer_hints = []
        suspicious_indicators = []

        for section in pe.sections:
            section_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            section_data = section.get_data()
            section_entropy = calculate_entropy(section_data)

            section_info = {
                "name": section_name,
                "entropy": round(section_entropy, 2),
                "size": section.SizeOfRawData,
                "suspicious": False,
            }

            # Detect suspicious characteristics
            if section_entropy > 7.0:
                section_info["suspicious"] = True
                packer_hints.append(f"High entropy in {section_name} section")

            if section_entropy < 1.0 and section.SizeOfRawData > 1000:
                section_info["suspicious"] = True
                packer_hints.append(f"Low entropy in {section_name} section (packed/encrypted)")

            # Common packer section names
            if section_name.upper() in ["UPX0", "UPX1", "UPX2", "MPRESS1", "MPRESS2"]:
                packer_hints.append(f"Packer section detected: {section_name}")

            sections.append(section_info)

        # Check for suspicious indicators
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint >= pe.OPTIONAL_HEADER.SizeOfImage:
            suspicious_indicators.append("Entry point outside image")

        # Check if entry point is in last section
        if pe.sections:
            last_section = pe.sections[-1]
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if (
                last_section.VirtualAddress
                <= ep_rva
                < last_section.VirtualAddress + last_section.Misc_VirtualSize
            ):
                suspicious_indicators.append("Entry point in last section")

        # Check for TLS callbacks
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
            suspicious_indicators.append("TLS callback present")

        # Calculate overall entropy
        with open(file_path, "rb") as f:
            file_data = f.read()
        overall_entropy = calculate_entropy(file_data)

        # Check authenticode signature
        signatures = []
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
                signatures.append("Authenticode signature present")
        except Exception:
            pass

        pe.close()

        return {
            "format": format_info,
            "entropy": {
                "overall": round(overall_entropy, 2),
                "sections": sections,
            },
            "packer_hints": packer_hints,
            "signatures": signatures if signatures else ["No signature"],
            "suspicious_indicators": suspicious_indicators,
        }

    except Exception as e:
        return {"error": f"PE analysis failed: {e!s}"}


def analyze_elf_file(file_path: str) -> dict[str, Any]:
    """Analyze ELF file structure."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"error": "pyelftools library not available"}

    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)

            format_info = {
                "type": "ELF",
                "arch": elf.get_machine_arch(),
                "subsystem": "Linux/Unix",
            }

            # Analyze sections
            sections = []
            packer_hints = []
            suspicious_indicators = []

            for section in elf.iter_sections():
                section_data = section.data()
                section_entropy = calculate_entropy(section_data)

                section_info = {
                    "name": section.name,
                    "entropy": round(section_entropy, 2),
                    "size": section["sh_size"],
                    "suspicious": False,
                }

                if section_entropy > 7.0:
                    section_info["suspicious"] = True
                    packer_hints.append(f"High entropy in {section.name} section")

                sections.append(section_info)

            # Calculate overall entropy
            f.seek(0)
            file_data = f.read()
            overall_entropy = calculate_entropy(file_data)

            return {
                "format": format_info,
                "entropy": {
                    "overall": round(overall_entropy, 2),
                    "sections": sections,
                },
                "packer_hints": packer_hints,
                "signatures": ["N/A for ELF"],
                "suspicious_indicators": suspicious_indicators,
            }

    except Exception as e:
        return {"error": f"ELF analysis failed: {e!s}"}


def triage_file_sync(
    sample_path: str,
    calculate_ssdeep: bool = True,
    check_signatures: bool = True,
) -> str:
    """Synchronous file triage implementation."""
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

        # Use resolved host path for all file operations
        sample_path = resolved_path

        # Get file size
        file_size = os.path.getsize(sample_path)

        # Calculate hashes
        hashes = {}
        hash_algos = {
            "md5": hashlib.md5(usedforsecurity=False),
            "sha1": hashlib.sha1(usedforsecurity=False),
            "sha256": hashlib.sha256(),
        }

        with open(sample_path, "rb") as f:
            data = f.read()
            for name, hasher in hash_algos.items():
                hasher.update(data)
                hashes[name] = hasher.hexdigest()

        # Calculate ssdeep if requested
        if calculate_ssdeep:
            try:
                import ssdeep

                hashes["ssdeep"] = ssdeep.hash(data)
            except Exception:
                hashes["ssdeep"] = "N/A (ssdeep not available)"

        # Calculate TLSH
        try:
            import tlsh

            hashes["tlsh"] = tlsh.hash(data)
        except Exception:
            hashes["tlsh"] = "N/A (tlsh not available)"

        # Detect file type using magic
        try:
            result = subprocess.run(
                ["file", "-b", sample_path], capture_output=True, text=True, timeout=5
            )
            file_type = result.stdout.strip()
        except Exception:
            file_type = "Unknown"

        # Perform format-specific analysis
        format_analysis = {}

        if file_type.startswith("PE32"):
            format_analysis = analyze_pe_file(sample_path)
        elif file_type.startswith("ELF"):
            format_analysis = analyze_elf_file(sample_path)
        else:
            # Generic analysis for other file types
            overall_entropy = calculate_entropy(data)
            format_analysis = {
                "format": {
                    "type": file_type,
                    "arch": "Unknown",
                    "subsystem": "Unknown",
                },
                "entropy": {
                    "overall": round(overall_entropy, 2),
                    "sections": [],
                },
                "packer_hints": [],
                "signatures": [],
                "suspicious_indicators": [],
            }

        # Build result
        result = {
            "success": True,
            "hashes": hashes,
            "size": file_size,
        }
        result.update(format_analysis)

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@function_tool(timeout=60)
async def file_triage(
    sample_path: str,
    calculate_ssdeep: bool = True,
    check_signatures: bool = True,
) -> str:
    """Perform initial triage on a malware sample.

    Analyzes file format, calculates hashes, measures entropy, and detects
    packing/obfuscation indicators.

    Args:
        sample_path: Path to the sample file
        calculate_ssdeep: Whether to calculate fuzzy hash (ssdeep)
        check_signatures: Whether to check authenticode signatures (PE only)

    Returns:
        JSON string with triage results including:
        - File hashes (MD5, SHA1, SHA256, ssdeep, TLSH)
        - File format and architecture
        - Entropy analysis (overall and per-section)
        - Packer detection hints
        - Suspicious indicators
    """
    return await asyncio.to_thread(
        triage_file_sync,
        sample_path,
        calculate_ssdeep,
        check_signatures,
    )
