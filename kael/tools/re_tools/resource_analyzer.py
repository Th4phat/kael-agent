"""PE resource analyzer for embedded payload detection.

Extracts PE resources (icons, bitmaps, dialogs, version info, manifests), detects
steganography, analyzes RCDATA sections, and identifies embedded executables.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

from agents.tool import function_tool

from ._path_resolver import ensure_host_path


# Common PE resource types
RESOURCE_TYPES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLG_INCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
    26: "MUI",
}


def extract_pe_resources(file_path: str) -> dict:
    """Extract and analyze all PE resources."""
    try:
        import pefile
    except ImportError:
        return {"error": "pefile library not available"}

    result = {
        "resources": [],
        "version_info": {},
        "manifest": "",
        "embedded_executables": [],
        "suspicious_resources": [],
    }

    try:
        pe = pefile.PE(file_path)

        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return result

        def parse_resource_directory(entry, depth=0):
            """Recursively parse resource directory."""
            resources = []

            for resource_entry in entry.directory.entries:
                resource_info = {
                    "type": None,
                    "name": None,
                    "language": None,
                    "size": 0,
                    "offset": None,
                    "data": None,
                }

                # Get type
                if resource_entry.name is not None:
                    resource_info["type"] = f"NAME: {resource_entry.name}"
                else:
                    type_id = resource_entry.id
                    resource_info["type"] = RESOURCE_TYPES.get(type_id, f"TYPE_{type_id}")

                # If this entry has a subdirectory, recurse
                if resource_entry.directory:
                    sub_resources = parse_resource_directory(resource_entry.directory, depth + 1)
                    resources.extend(sub_resources)
                else:
                    # This is a leaf - get data
                    data_entry = resource_entry.data
                    resource_info["offset"] = data_entry.struct.OffsetToData
                    resource_info["size"] = data_entry.struct.Size
                    resource_info["language"] = data_entry.lang

                    # Get RVA and extract data
                    rva = data_entry.struct.OffsetToData
                    try:
                        data = pe.get_data(rva, data_entry.struct.Size)
                        resource_info["data"] = data
                        resource_info["hash"] = hashlib.sha256(data).hexdigest()
                    except Exception:
                        resource_info["data"] = None

                    resources.append(resource_info)

            return resources

        # Parse all resources
        all_resources = parse_resource_directory(pe.DIRECTORY_ENTRY_RESOURCE)

        # Analyze each resource
        for res in all_resources:
            res_type = res["type"]
            res_data = res.get("data")
            res_size = res["size"]

            res_summary = {
                "type": res_type,
                "size": res_size,
                "hash": res.get("hash"),
                "language": res.get("language"),
            }

            # Extract version info
            if res_type == "VERSION" and res_data:
                res_summary["version_info"] = parse_version_info(res_data)
                result["version_info"] = res_summary["version_info"]

            # Extract manifest
            elif res_type == "MANIFEST" and res_data:
                try:
                    manifest_text = res_data.decode("utf-8", errors="ignore")
                    res_summary["manifest"] = manifest_text[:1000]
                    result["manifest"] = manifest_text
                except Exception:
                    pass

            # Detect embedded executables (MZ, ELF, ZIP, PDF magic)
            elif res_data:
                if res_data[:2] == b"MZ":
                    res_summary["embedded_executable"] = "PE"
                    result["embedded_executables"].append(
                        {
                            "type": "PE",
                            "size": res_size,
                            "hash": res.get("hash"),
                        }
                    )
                elif res_data[:4] == b"\x7fELF":
                    res_summary["embedded_executable"] = "ELF"
                    result["embedded_executables"].append(
                        {
                            "type": "ELF",
                            "size": res_size,
                            "hash": res.get("hash"),
                        }
                    )
                elif res_data[:4] == b"PK\x03\x04":
                    res_summary["embedded_executable"] = "ZIP"
                    result["embedded_executables"].append(
                        {
                            "type": "ZIP",
                            "size": res_size,
                            "hash": res.get("hash"),
                        }
                    )
                elif res_data[:5] == b"%PDF-":
                    res_summary["embedded_executable"] = "PDF"
                    result["embedded_executables"].append(
                        {
                            "type": "PDF",
                            "size": res_size,
                            "hash": res.get("hash"),
                        }
                    )

            # Check for suspicious resources
            if res_type == "RCDATA" and res_size > 1000:
                result["suspicious_resources"].append(
                    {
                        "type": "RCDATA",
                        "size": res_size,
                        "reason": "Large RCDATA section (possible embedded payload)",
                    }
                )
            elif res_type in ("BITMAP", "ICON", "GROUP_ICON") and res_size > 100000:
                result["suspicious_resources"].append(
                    {
                        "type": res_type,
                        "size": res_size,
                        "reason": f"Unusually large {res_type} (possible steganography or embedded data)",
                    }
                )

            result["resources"].append(res_summary)

        # Check version info for suspicious indicators
        version_info = result.get("version_info", {})
        if version_info:
            company = version_info.get("CompanyName", "")
            description = version_info.get("FileDescription", "")

            # Check for fake/missing version info
            if not company or company in ("Microsoft Corporation", "Microsoft"):
                if "System32" not in str(version_info):
                    result["suspicious_resources"].append(
                        {
                            "type": "VERSION",
                            "reason": f"Fake Microsoft company name: {company}",
                        }
                    )

            if not description or description == "":
                result["suspicious_resources"].append(
                    {
                        "type": "VERSION",
                        "reason": "Missing file description (suspicious for legitimate software)",
                    }
                )

        pe.close()

    except Exception as e:
        result["error"] = f"Resource extraction failed: {e!s}"

    return result


def parse_version_info(data: bytes) -> dict:
    """Parse VS_VERSIONINFO structure."""
    version_info = {}

    try:
        # Simple parsing - extract ASCII strings from version info
        # Real parsing would use VS_FIXEDFILEINFO structure

        # Look for common version info keys
        data.decode("utf-16le", errors="ignore")

        keys = [
            "CompanyName",
            "FileDescription",
            "FileVersion",
            "InternalName",
            "LegalCopyright",
            "OriginalFilename",
            "ProductName",
            "ProductVersion",
            "Comments",
            "LegalTrademarks",
            "PrivateBuild",
            "SpecialBuild",
        ]

        for key in keys:
            # Search for key in UTF-16LE
            pattern = key.encode("utf-16le") + b"\x00\x00"
            if pattern in data:
                # Try to extract the value (simplified)
                idx = data.find(pattern)
                # Value starts after a null terminator, ends with null
                value_start = idx + len(pattern) + 2
                value_end = data.find(b"\x00\x00", value_start)
                if value_end > value_start:
                    value = data[value_start:value_end].decode("utf-16le", errors="ignore")
                    version_info[key] = value

    except Exception:
        pass

    return version_info


def detect_steganography(file_path: str) -> dict:
    """Detect steganography in image resources (simple LSB analysis)."""
    result = {
        "suspicious": False,
        "indicators": [],
    }

    try:
        import pefile

        pe = pefile.PE(file_path)

        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return result

        # Check bitmap resources for anomalies
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id == 2:  # BITMAP
                for lang_entry in entry.directory.entries:
                    for resource in lang_entry.directory.entries:
                        data = pe.get_data(
                            resource.data.struct.OffsetToData, resource.data.struct.Size
                        )

                        # Simple LSB analysis
                        lsb_count = 0
                        total_bytes = min(len(data), 1000)
                        for byte in data[:total_bytes]:
                            if byte & 1:
                                lsb_count += 1

                        lsb_ratio = lsb_count / total_bytes if total_bytes > 0 else 0

                        # High LSB ratio suggests steganography
                        if lsb_ratio > 0.45 and lsb_ratio < 0.55:
                            result["suspicious"] = True
                            result["indicators"].append(
                                {
                                    "type": "LSB_anomaly",
                                    "resource_size": resource.data.struct.Size,
                                    "lsb_ratio": round(lsb_ratio, 3),
                                }
                            )

        pe.close()
    except Exception:
        pass

    return result


def resource_analysis_sync(
    sample_path: str,
    detect_stego: bool = True,
) -> str:
    """Synchronous resource analysis implementation."""
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

        # Detect file type
        with open(sample_path, "rb") as f:
            magic = f.read(2)

        if magic != b"MZ":
            return json.dumps(
                {
                    "success": False,
                    "error": "Not a PE file (resources only supported for PE)",
                }
            )

        result = {
            "success": True,
            "sample_path": sample_path,
            "resource_analysis": extract_pe_resources(sample_path),
        }

        if detect_stego:
            result["steganography_check"] = detect_steganography(sample_path)

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps(
            {
                "success": False,
                "error": f"Resource analysis failed: {e!s}",
            }
        )


@function_tool(timeout=60)
async def resource_analyzer(
    sample_path: str,
    detect_stego: bool = True,
) -> str:
    """Analyze PE resources for embedded payloads and steganography.

    Extracts icons, bitmaps, dialogs, version info, and manifests. Detects
    embedded executables (PE/ELF/ZIP/PDF), analyzes RCDATA sections, and
    performs LSB steganography detection on bitmap resources.

    Args:
        sample_path: Path to the PE sample
        detect_stego: Whether to perform steganography detection (default: True)

    Returns:
        JSON string with resource analysis including:
        - All extracted resources with types, sizes, and hashes
        - Version info (CompanyName, FileDescription, etc.)
        - Manifest XML
        - Embedded executable detection (PE/ELF/ZIP/PDF)
        - Suspicious resources (large RCDATA, fake version info)
        - Steganography indicators
    """
    return await asyncio.to_thread(
        resource_analysis_sync,
        sample_path,
        detect_stego,
    )
