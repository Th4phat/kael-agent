"""Import table analyzer for malware family identification.

Extracts and analyzes PE/ELF import tables, calculates imphash for family
clustering, detects suspicious API patterns, and identifies evasion techniques.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

from agents.tool import function_tool

from ._path_resolver import ensure_host_path


# Windows APIs commonly used in malware, categorized by technique
SUSPICIOUS_API_CATEGORIES = {
    "process_injection": [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "SetWindowsHookEx",
        "NtMapViewOfSection",
        "OpenProcess",
        "DuplicateHandle",
    ],
    "keylogging": [
        "GetAsyncKeyState",
        "GetKeyState",
        "GetKeyboardState",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "GetForegroundWindow",
        "GetWindowTextA",
        "GetWindowTextW",
    ],
    "persistence": [
        "RegSetValueExA",
        "RegSetValueExW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "CreateServiceA",
        "CreateServiceW",
        "OpenSCManagerA",
        "OpenSCManagerW",
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
    ],
    "network": [
        "WSAStartup",
        "socket",
        "connect",
        "send",
        "recv",
        "InternetOpenA",
        "InternetOpenW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WNetOpenEnumA",
        "WNetOpenEnumW",
        "gethostbyname",
        "getaddrinfo",
    ],
    "anti_debug": [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "QueryPerformanceCounter",
        "GetTickCount",
        "GetTickCount64",
        "NtSetInformationThread",
        "NtQuerySystemInformation",
    ],
    "crypto": [
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptCreateHash",
        "CryptHashData",
        "CryptDeriveKey",
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptGenRandom",
        "BCryptEncrypt",
        "BCryptDecrypt",
        "BCryptOpenAlgorithmProvider",
    ],
    "privilege_escalation": [
        "AdjustTokenPrivileges",
        "OpenProcessToken",
        "LookupPrivilegeValueA",
        "LookupPrivilegeValueW",
        "ImpersonateLoggedOnUser",
        "DuplicateTokenEx",
    ],
    "evasion": [
        "VirtualProtect",
        "VirtualProtectEx",
        "NtAllocateVirtualMemory",
        "CreateProcessA",
        "CreateProcessW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateProcessInternalA",
        "CreateProcessInternalW",
    ],
    "registry_modification": [
        "RegSetValueExA",
        "RegSetValueExW",
        "RegDeleteKeyA",
        "RegDeleteKeyW",
        "RegDeleteValueA",
        "RegDeleteValueW",
        "RegEnumKeyExA",
        "RegEnumKeyExW",
    ],
    "file_operation": [
        "CreateFileA",
        "CreateFileW",
        "WriteFile",
        "ReadFile",
        "DeleteFileA",
        "DeleteFileW",
        "MoveFileA",
        "MoveFileW",
        "CopyFileA",
        "CopyFileW",
    ],
}


def calculate_pe_imphash(imports: list[dict]) -> str:
    """Calculate PE imphash (import hash) for malware family identification.

    Algorithm: lowercase(DLL_name).lower() + '.' + lowercase(API_name) for all imports
    """
    import_data = []
    for imp in imports:
        dll = imp.get("dll", "").lower()
        if dll:
            for api in imp.get("functions", []):
                if api and api.lower() not in ("", "ordinal_only"):
                    import_data.append(f"{dll}.{api.lower()}")

    import_data.sort()
    return hashlib.md5(",".join(import_data).encode(), usedforsecurity=False).hexdigest()


def analyze_pe_imports(file_path: str) -> dict:
    """Analyze PE import table with imphash and suspicious API detection."""
    try:
        import pefile
    except ImportError:
        return {"error": "pefile library not available"}

    result = {
        "imports": [],
        "delay_imports": [],
        "suspicious_apis": [],
        "categories_detected": [],
        "total_imports": 0,
    }

    try:
        pe = pefile.PE(file_path)

        # Parse imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                functions = []

                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode("utf-8", errors="ignore"))
                    else:
                        functions.append(f"ordinal_{imp.ordinal}")

                result["imports"].append(
                    {
                        "dll": dll_name,
                        "functions": functions,
                        "count": len(functions),
                    }
                )

        # Parse delay imports (often used for evasion)
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                functions = []

                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode("utf-8", errors="ignore"))
                    else:
                        functions.append(f"ordinal_{imp.ordinal}")

                result["delay_imports"].append(
                    {
                        "dll": dll_name,
                        "functions": functions,
                        "count": len(functions),
                    }
                )

        # Calculate imphash
        all_imports_for_hash = []
        for imp in result["imports"]:
            all_imports_for_hash.append({"dll": imp["dll"], "functions": imp["functions"]})
        for imp in result["delay_imports"]:
            all_imports_for_hash.append({"dll": imp["dll"], "functions": imp["functions"]})

        if all_imports_for_hash:
            result["imphash"] = calculate_pe_imphash(all_imports_for_hash)

        # Count total imports
        result["total_imports"] = sum(imp["count"] for imp in result["imports"])
        result["total_delay_imports"] = sum(imp["count"] for imp in result["delay_imports"])

        # Detect suspicious APIs
        all_functions = set()
        for imp in result["imports"]:
            all_functions.update(imp["functions"])
        for imp in result["delay_imports"]:
            all_functions.update(imp["functions"])

        for category, apis in SUSPICIOUS_API_CATEGORIES.items():
            found = [api for api in apis if api in all_functions]
            if found:
                result["categories_detected"].append(
                    {
                        "category": category,
                        "apis": found,
                    }
                )
                result["suspicious_apis"].extend(
                    [
                        {
                            "api": api,
                            "category": category,
                        }
                        for api in found
                    ]
                )

        # Check for ordinal-only imports (evasion technique)
        ordinal_only_count = sum(1 for f in all_functions if f.startswith("ordinal_"))
        if ordinal_only_count > 0:
            result["evasion_indicators"] = result.get("evasion_indicators", [])
            result["evasion_indicators"].append(
                f"{ordinal_only_count} ordinal-only imports (possible API name hiding)"
            )

        # Check for dynamic API resolution (LoadLibrary + GetProcAddress)
        if "LoadLibraryA" in all_functions or "LoadLibraryW" in all_functions:
            result["evasion_indicators"] = result.get("evasion_indicators", [])
            result["evasion_indicators"].append(
                "LoadLibrary detected - possible dynamic API resolution"
            )
        if "GetProcAddress" in all_functions:
            result["evasion_indicators"] = result.get("evasion_indicators", [])
            result["evasion_indicators"].append(
                "GetProcAddress detected - possible dynamic API resolution"
            )

        # Check for unusually low import count (possible packed/encrypted imports)
        if result["total_imports"] < 10:
            result["evasion_indicators"] = result.get("evasion_indicators", [])
            result["evasion_indicators"].append(
                f"Very low import count ({result['total_imports']}) - possible packing/encryption"
            )

        pe.close()

    except Exception as e:
        result["error"] = f"PE import analysis failed: {e!s}"

    return result


def analyze_elf_imports(file_path: str) -> dict:
    """Analyze ELF dynamic symbols and library dependencies."""
    try:
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"error": "pyelftools library not available"}

    result = {
        "dynamic_libraries": [],
        "imported_functions": [],
        "exported_functions": [],
        "suspicious_apis": [],
        "categories_detected": [],
    }

    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)

            # Get dynamic libraries
            for section in elf.iter_sections():
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            result["dynamic_libraries"].append(tag.needed)

            # Get imported/exported functions from .dynsym
            if elf.has_section(".dynsym"):
                dynsym = elf.get_section(".dynsym")
                for sym in dynsym.iter_symbols():
                    if sym.name:
                        # Determine import vs export
                        st_info = sym["st_info"]
                        if st_info["type"] == "STT_FUNC":
                            if sym["st_shndx"] == "SHN_UNDEF":
                                result["imported_functions"].append(
                                    {
                                        "name": sym.name,
                                        "library": "unknown",  # Would need relocations to map
                                    }
                                )
                            else:
                                result["exported_functions"].append(sym.name)

            # Detect suspicious APIs
            all_func_names = {f["name"] for f in result["imported_functions"]}

            linux_suspicious_apis = {
                "process_injection": ["ptrace", "execve", "execvp", "system"],
                "network": ["socket", "connect", "sendto", "recvfrom", "gethostbyname", "fork"],
                "anti_debug": ["ptrace", "getppid", "getuid"],
                "persistence": ["chmod", "chown", "systemd", "daemon"],
                "file_operation": ["open", "write", "unlink", "rename"],
                "privilege_escalation": ["setuid", "setgid", "seteuid", "setegid"],
            }

            for category, apis in linux_suspicious_apis.items():
                found = [api for api in apis if api in all_func_names]
                if found:
                    result["categories_detected"].append(
                        {
                            "category": category,
                            "apis": found,
                        }
                    )
                    result["suspicious_apis"].extend(
                        [
                            {
                                "api": api,
                                "category": category,
                            }
                            for api in found
                        ]
                    )

    except Exception as e:
        result["error"] = f"ELF import analysis failed: {e!s}"

    return result


def import_analysis_sync(
    sample_path: str,
    analyze_pe: bool = True,
    analyze_elf: bool = True,
) -> str:
    """Synchronous import analysis implementation."""
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
        try:
            with open(sample_path, "rb") as f:
                magic = f.read(4)
        except Exception as e:
            return json.dumps(
                {
                    "success": False,
                    "error": f"Failed to read file: {e!s}",
                }
            )

        result = {
            "success": True,
            "sample_path": sample_path,
            "file_type": None,
            "analysis": {},
        }

        # PE file
        if magic[:2] == b"MZ" and analyze_pe:
            result["file_type"] = "PE"
            result["analysis"] = analyze_pe_imports(sample_path)

        # ELF file
        elif magic[:4] == b"\x7fELF" and analyze_elf:
            result["file_type"] = "ELF"
            result["analysis"] = analyze_elf_imports(sample_path)

        else:
            return json.dumps(
                {
                    "success": False,
                    "error": "Unsupported file type (only PE/ELF supported)",
                }
            )

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps(
            {
                "success": False,
                "error": f"Import analysis failed: {e!s}",
            }
        )


@function_tool(timeout=60)
async def import_analyzer(
    sample_path: str,
    analyze_pe: bool = True,
    analyze_elf: bool = True,
) -> str:
    """Analyze import table for malware family identification and behavioral indicators.

    Extracts PE/ELF imports, calculates imphash for family clustering, and detects
    suspicious API patterns (process injection, keylogging, anti-debug, etc.).

    Args:
        sample_path: Path to the sample file
        analyze_pe: Whether to analyze PE imports (default: True)
        analyze_elf: Whether to analyze ELF imports (default: True)

    Returns:
        JSON string with import analysis including:
        - imphash (PE import hash for family clustering)
        - Import list organized by DLL
        - Delay imports (often used for evasion)
        - Suspicious API categories detected
        - Evasion indicators (ordinal-only, low import count, dynamic resolution)
    """
    return await asyncio.to_thread(
        import_analysis_sync,
        sample_path,
        analyze_pe,
        analyze_elf,
    )
