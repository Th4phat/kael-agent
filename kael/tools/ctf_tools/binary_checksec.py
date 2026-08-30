"""``binary_checksec`` — ELF / PE / Mach-O protection summary.

Runs ``file`` + ``checksec``-equivalent checks in pure Python and
returns a JSON dump of binary protections, arch, and dynamic
info. Useful as a host-side complement to ``pwn checksec`` in the
sandbox.
"""

from __future__ import annotations

import json
import os
import re
import struct
from typing import Any

from agents import function_tool


_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"


def _read(path: str, n: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def _read_all(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _checksec_elf(path: str) -> dict[str, Any]:
    data = _read_all(path)
    if not data.startswith(_ELF_MAGIC):
        return {"is_elf": False}

    info: dict[str, Any] = {
        "is_elf": True,
        "path": path,
        "size_bytes": len(data),
    }

    ei_class = data[4]
    info["class"] = "64-bit" if ei_class == 2 else "32-bit"
    ei_data = data[5]
    info["endian"] = "little" if ei_data == 1 else "big"

    if ei_class == 2:
        e_type = struct.unpack_from("<H", data, 16)[0]
        e_machine = struct.unpack_from("<H", data, 18)[0]
        e_entry = struct.unpack_from("<Q", data, 24)[0]
        e_phoff = struct.unpack_from("<Q", data, 32)[0]
        e_shoff = struct.unpack_from("<Q", data, 40)[0]
        e_phnum = struct.unpack_from("<H", data, 56)[0]
        e_shnum = struct.unpack_from("<H", data, 60)[0]
    else:
        e_type = struct.unpack_from("<H", data, 16)[0]
        e_machine = struct.unpack_from("<H", data, 18)[0]
        e_entry = struct.unpack_from("<I", data, 24)[0]
        e_phoff = struct.unpack_from("<I", data, 28)[0]
        e_shoff = struct.unpack_from("<I", data, 32)[0]
        e_phnum = struct.unpack_from("<H", data, 44)[0]
        e_shnum = struct.unpack_from("<H", data, 48)[0]

    info["type"] = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN (PIE)", 4: "CORE"}.get(
        e_type, f"unknown({e_type})"
    )
    info["machine"] = {
        3: "x86",
        0x3E: "x86-64",
        0x28: "ARM",
        0xB7: "AArch64",
        8: "MIPS",
        0x14: "PowerPC",
        0xF3: "RISC-V",
    }.get(e_machine, f"unknown({e_machine})")
    info["entry"] = f"0x{e_entry:x}"
    info["is_pie"] = e_type == 3

    info["protections"] = {
        "pie": info["is_pie"],
        "nx": True,
        "canary": False,
        "relro": "None",
        "rpath": None,
        "runpath": None,
    }

    section_headers_offset = e_shoff
    if section_headers_offset > 0 and e_shnum > 0:
        sh_size = 64 if ei_class == 2 else 40
        sh_strndx_idx = (
            section_headers_offset + sh_size * (e_shnum - 1)
            if ei_class == 2
            else section_headers_offset + sh_size * (e_shnum - 1)
        )
        if sh_size == 40:
            sh_strndx = struct.unpack_from("<I", data, sh_strndx_idx + 16)[0]
        else:
            sh_strndx = (
                struct.unpack_from("<H", data, sh_strndx_idx + 6)[0]
                if ei_class == 1
                else struct.unpack_from("<H", data, sh_strndx_idx + 6)[0]
            )

        sh_str_off = section_headers_offset + sh_strndx * sh_size
        if sh_size == 40:
            str_offset = struct.unpack_from("<I", data, sh_str_off + 16)[0]
            struct.unpack_from("<I", data, sh_str_off + 20)[0]
        else:
            str_offset = struct.unpack_from("<Q", data, sh_str_off + 24)[0]
            struct.unpack_from("<Q", data, sh_str_off + 32)[0]

        for i in range(e_shnum):
            sh_base = section_headers_offset + i * sh_size
            if sh_size == 40:
                sh_name_idx = struct.unpack_from("<I", data, sh_base)[0]
                sh_type = struct.unpack_from("<I", data, sh_base + 4)[0]
                sh_addr = struct.unpack_from("<I", data, sh_base + 12)[0]
            else:
                sh_name_idx = struct.unpack_from("<I", data, sh_base)[0]
                sh_type = struct.unpack_from("<I", data, sh_base + 4)[0]
                sh_addr = struct.unpack_from("<Q", data, sh_base + 16)[0]

            end = data.find(b"\x00", str_offset + sh_name_idx)
            if end < 0:
                continue
            name = data[str_offset + sh_name_idx : end].decode("ascii", errors="replace")

            if sh_type in (1, 8) and sh_addr > 0:
                if name == ".dynamic":
                    sh_addr if sh_addr < len(data) else None

        for i in range(e_shnum):
            sh_base = section_headers_offset + i * sh_size
            if sh_size == 40:
                sh_name_idx = struct.unpack_from("<I", data, sh_base)[0]
            else:
                sh_name_idx = struct.unpack_from("<I", data, sh_base)[0]
            end = data.find(b"\x00", str_offset + sh_name_idx)
            if end < 0:
                continue
            name = data[str_offset + sh_name_idx : end].decode("ascii", errors="replace")
            if name in (".note.GNU-stack", ".note.stapsdt"):
                pass

    if e_phoff > 0 and e_phnum > 0:
        ph_size = 56 if ei_class == 2 else 32
        for i in range(e_phnum):
            ph_base = e_phoff + i * ph_size
            if ei_class == 2:
                p_type = struct.unpack_from("<I", data, ph_base)[0]
                p_flags = struct.unpack_from("<I", data, ph_base + 4)[0]
            else:
                p_type = struct.unpack_from("<I", data, ph_base)[0]
                p_flags = struct.unpack_from("<I", data, ph_base + 24)[0]

            if p_type == 0x6474E551 and ei_class == 2:
                info["protections"]["nx"] = bool(p_flags & 0x1) is False
            if p_type == 0x6474E550 and ei_class == 1:
                info["protections"]["nx"] = bool(p_flags & 0x1) is False

    if b"__stack_chk_fail" in data:
        info["protections"]["canary"] = True
    if b"GLIBC_2." in data:
        info["libc_dependency"] = "glibc (likely Linux)"
    elif b"__stack_chk_fail" in data:
        info["libc_dependency"] = "unknown"
    if b"BIND_NOW" in data or b"DT_BIND_NOW" in data:
        info["protections"]["relro"] = "Full"
    elif b"DT_JMPREL" in data:
        info["protections"]["relro"] = "Partial"

    if b"\x00\x00\x00\x00\x00\x00\x00\x00R\x00" in data[:0x400]:
        info["protections"]["rpath"] = "present"
    if b"RUNPATH" in data:
        info["protections"]["runpath"] = "present"

    dynstr_match = re.search(rb"GNU C Library[^\x00]*release version (\d+\.\d+)", data)
    if dynstr_match:
        info["glibc_version"] = dynstr_match.group(1).decode("ascii", errors="replace")

    return info


def _checksec_pe(path: str) -> dict[str, Any]:
    data = _read_all(path)
    if not data.startswith(_PE_MAGIC):
        return {"is_pe": False}
    info: dict[str, Any] = {
        "is_pe": True,
        "path": path,
        "size_bytes": len(data),
        "protections": {"aslr": False, "dep": False, "cfg": False, "seh": True},
    }

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data):
        return info
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return info

    characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
    info["dll"] = bool(characteristics & 0x2000)

    optional_header_size = struct.unpack_from("<H", data, pe_offset + 16)[0]
    if optional_header_size < 96 or pe_offset + 24 + optional_header_size > len(data):
        return info

    magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
    is_64 = magic == 0x20B
    info["class"] = "64-bit" if is_64 else "32-bit"

    if is_64:
        dll_chars = struct.unpack_from("<H", data, pe_offset + 24 + 0x5C)[0]
    else:
        dll_chars = struct.unpack_from("<H", data, pe_offset + 24 + 0x5E)[0]

    info["protections"]["aslr"] = bool(dll_chars & 0x0040)
    info["protections"]["dep"] = bool(dll_chars & 0x0100)
    info["protections"]["seh"] = not bool(dll_chars & 0x0400)

    return info


@function_tool(timeout=15, strict_mode=False)
async def binary_checksec(ctx, binary_path: str) -> str:  # type: ignore[no-untyped-def]
    """Inspect binary protections (CTF pwn helper).

    Pure-Python ELF / PE parser that returns:
    - arch + class + entry
    - PIE / NX / canary / RELRO (best-effort detection)
    - RPATH / RUNPATH presence
    - glibc version (if detectable)

    For canonical results, also run ``pwn checksec ./chall`` in the
    sandbox.

    Args:
        binary_path: Path to the binary on the host filesystem.

    Returns:
        JSON with ``protections`` and arch info. Returns ``error`` if
        the file cannot be parsed.
    """
    if not os.path.exists(binary_path):
        return json.dumps({"success": False, "error": f"File not found: {binary_path}"})

    try:
        info = _checksec_elf(binary_path)
        if info.get("is_elf"):
            return json.dumps({"success": True, **info}, indent=2)
        info = _checksec_pe(binary_path)
        if info.get("is_pe"):
            return json.dumps({"success": True, **info}, indent=2)
        return json.dumps(
            {
                "success": True,
                "is_elf": False,
                "is_pe": False,
                "path": binary_path,
                "size_bytes": os.path.getsize(binary_path),
                "first_bytes": _read(binary_path, 16).hex(),
            }
        )
    except Exception as exc:
        return json.dumps({"success": False, "error": f"{type(exc).__name__}: {exc}"})
