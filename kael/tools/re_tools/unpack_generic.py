"""Generic unpacking tool."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess

from agents.tool import function_tool

from ._path_resolver import ensure_host_path


def detect_packer(sample_path: str) -> list[str]:
    """Detect known packers."""
    detected = []

    try:
        with open(sample_path, "rb") as f:
            data = f.read()

        # Check for UPX
        if b"UPX0" in data or b"UPX1" in data or b"UPX!" in data:
            detected.append("upx")

        # Check for MPRESS
        if b".MPRESS1" in data or b".MPRESS2" in data:
            detected.append("mpress")

        # Check for Themida/WinLicense
        if b".themida" in data or b"Themida" in data or b"WinLicense" in data:
            detected.append("themida")

        # Check for VMProtect
        if b".vmp0" in data or b".vmp1" in data:
            detected.append("vmprotect")

        # Check for ASPack
        if b".aspack" in data or b".adata" in data:
            detected.append("aspack")

        # Check for PECompact
        if b"PECompact" in data:
            detected.append("pecompact")

    except Exception:
        pass

    return detected


def try_upx_unpack(sample_path: str, output_path: str) -> tuple[bool, str]:
    """Try to unpack with UPX."""
    try:
        result = subprocess.run(
            ["upx", "-d", sample_path, "-o", output_path],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode == 0 and os.path.exists(output_path):
            return True, "UPX unpacking successful"

        return False, result.stderr

    except subprocess.TimeoutExpired:
        return False, "UPX unpacking timed out"
    except Exception as e:
        return False, str(e)


def try_xor_brute(sample_path: str, output_dir: str) -> list[dict]:
    """Try XOR brute force on common single-byte keys."""
    unpacked = []

    try:
        with open(sample_path, "rb") as f:
            data = f.read()

        # Try common XOR keys
        for key in [0x00, 0xFF, 0x42, 0x55, 0xAA, 0x01, 0x02, 0x10, 0x20, 0x40, 0x80]:
            xored = bytes([b ^ key for b in data])

            # Check if result looks like PE or ELF
            if xored.startswith(b"MZ") or xored.startswith(b"\x7fELF"):
                output_path = os.path.join(output_dir, f"xor_{key:02x}.bin")

                with open(output_path, "wb") as f:
                    f.write(xored)

                unpacked.append(
                    {
                        "method": f"xor_brute_key_{key:02x}",
                        "output_path": output_path,
                        "size": len(xored),
                    }
                )

    except Exception:
        pass

    return unpacked


def extract_overlay(sample_path: str, output_dir: str) -> dict | None:
    """Extract PE overlay data."""
    try:
        import pefile

        pe = pefile.PE(sample_path)
        overlay_offset = pe.get_overlay_data_start_offset()

        if overlay_offset:
            with open(sample_path, "rb") as f:
                f.seek(overlay_offset)
                overlay_data = f.read()

            if len(overlay_data) > 100:  # Only extract if substantial
                output_path = os.path.join(output_dir, "overlay.bin")

                with open(output_path, "wb") as f:
                    f.write(overlay_data)

                return {
                    "method": "pe_overlay_extract",
                    "output_path": output_path,
                    "size": len(overlay_data),
                    "offset": overlay_offset,
                }

    except ImportError:
        pass
    except Exception:
        pass

    return None


def try_binwalk_extract(sample_path: str, output_dir: str) -> list[dict]:
    """Try to extract embedded files with binwalk."""
    extracted = []

    try:
        # Create temp directory for binwalk output
        temp_dir = os.path.join(output_dir, "binwalk_temp")
        os.makedirs(temp_dir, exist_ok=True)

        subprocess.run(
            ["binwalk", "-e", "-C", temp_dir, sample_path],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Check for extracted files
        if os.path.exists(temp_dir):
            for root, _dirs, files in os.walk(temp_dir):
                for file in files:
                    filepath = os.path.join(root, file)
                    filesize = os.path.getsize(filepath)

                    if filesize > 100:  # Only include substantial files
                        extracted.append(
                            {"method": "binwalk_extract", "output_path": filepath, "size": filesize}
                        )

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return extracted


def unpack_generic_sync(
    sample_path: str,
    method: str = "auto",
    output_dir: str | None = None,
) -> str:
    """Synchronous unpacking implementation."""

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

    sample_path = resolved_path

    # Handle output directory
    if output_dir is None:
        output_dir = os.path.join(os.getcwd(), "kael-artifacts")
    elif output_dir.startswith("/workspace/"):
        # Container path - use temp directory
        import tempfile

        output_dir = os.path.join(tempfile.gettempdir(), "kael-artifacts")

    # Create output directory
    try:
        os.makedirs(output_dir, exist_ok=True)
    except PermissionError:
        import tempfile

        output_dir = os.path.join(tempfile.gettempdir(), "kael-artifacts")
        os.makedirs(output_dir, exist_ok=True)

    result = {
        "success": True,
        "sample_path": sample_path,
        "output_dir": output_dir,
        "detected_packers": [],
        "unpacked_files": [],
    }

    try:
        # Detect packers
        packers = detect_packer(sample_path)
        result["detected_packers"] = packers

        # Try unpacking based on method
        if method == "auto":
            # Try all methods

            # 1. Try UPX if detected
            if "upx" in packers:
                upx_output = os.path.join(output_dir, "unpacked_upx.bin")
                success, msg = try_upx_unpack(sample_path, upx_output)
                if success:
                    result["unpacked_files"].append(
                        {
                            "method": "upx",
                            "output_path": upx_output,
                            "size": os.path.getsize(upx_output),
                        }
                    )

            # 2. Try XOR brute force
            xor_results = try_xor_brute(sample_path, output_dir)
            result["unpacked_files"].extend(xor_results)

            # 3. Try overlay extraction
            overlay_result = extract_overlay(sample_path, output_dir)
            if overlay_result:
                result["unpacked_files"].append(overlay_result)

            # 4. Try binwalk
            binwalk_results = try_binwalk_extract(sample_path, output_dir)
            result["unpacked_files"].extend(binwalk_results[:5])  # Limit to 5

        elif method == "upx":
            upx_output = os.path.join(output_dir, "unpacked_upx.bin")
            success, msg = try_upx_unpack(sample_path, upx_output)
            if success:
                result["unpacked_files"].append(
                    {
                        "method": "upx",
                        "output_path": upx_output,
                        "size": os.path.getsize(upx_output),
                    }
                )
            else:
                result["error"] = msg
                result["success"] = False

        elif method == "xor":
            xor_results = try_xor_brute(sample_path, output_dir)
            result["unpacked_files"].extend(xor_results)

        elif method == "overlay":
            overlay_result = extract_overlay(sample_path, output_dir)
            if overlay_result:
                result["unpacked_files"].append(overlay_result)

        elif method == "binwalk":
            binwalk_results = try_binwalk_extract(sample_path, output_dir)
            result["unpacked_files"].extend(binwalk_results)

        result["total_unpacked"] = len(result["unpacked_files"])

        if result["total_unpacked"] == 0 and result["success"]:
            result["message"] = (
                "No unpacked files extracted (sample may not be packed or uses unknown packer)"
            )

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"success": False, "error": f"Unpacking failed: {e!s}"})


@function_tool(timeout=120)
async def unpack_generic(
    sample_path: str,
    method: str = "auto",
    output_dir: str | None = None,
) -> str:
    """Unpack packed/encrypted samples using multiple methods.

    Args:
        sample_path: Path to the packed sample
        method: Unpacking method - "auto", "upx", "xor", "overlay", "binwalk" (default: "auto")
        output_dir: Directory to save unpacked files (default: ./kael-artifacts/ in current directory)

    Returns:
        JSON string with detected packers and unpacked files
    """
    return await asyncio.to_thread(
        unpack_generic_sync,
        sample_path,
        method,
        output_dir,
    )
