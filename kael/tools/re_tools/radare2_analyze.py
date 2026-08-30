"""Radare2 analysis tool."""

from __future__ import annotations

import asyncio
import json
from collections import Counter

from agents.tool import function_tool

from ._path_resolver import ensure_host_path


def generate_cfg(sample_path: str, function_address: str) -> dict:
    """Generate control flow graph for a specific function.

    Args:
        sample_path: Path to the binary
        function_address: Address of function (hex string like "0x401000")
    """
    try:
        import r2pipe
    except ImportError:
        return {"error": "r2pipe not installed"}

    try:
        r2 = r2pipe.open(sample_path, flags=["-2"])
        r2.cmd("aaa")

        # Seek to function
        r2.cmd(f"s {function_address}")

        # Generate CFG
        cfg_data = r2.cmdj("afij")

        if not cfg_data:
            r2.quit()
            return {"error": "Function not found"}

        func_info = cfg_data[0] if isinstance(cfg_data, list) else cfg_data

        # Get basic blocks
        blocks = []
        for bb in func_info.get("bbs", []):
            blocks.append(
                {
                    "address": f"0x{bb.get('addr', 0):x}",
                    "size": bb.get("size", 0),
                    "jump": f"0x{bb.get('jump', 0):x}" if bb.get("jump") else None,
                    "fail": f"0x{bb.get('fail', 0):x}" if bb.get("fail") else None,
                    "conditional": bb.get("jump") and bb.get("fail"),
                }
            )

        # Calculate cyclomatic complexity
        # M = E - N + 2 (edges - nodes + 2)
        edges = len([b for b in blocks if b.get("jump")]) + len(
            [b for b in blocks if b.get("fail")]
        )
        nodes = len(blocks)
        cyclomatic_complexity = edges - nodes + 2 if nodes > 0 else 0

        result = {
            "function_address": function_address,
            "basic_blocks": blocks,
            "total_blocks": len(blocks),
            "edges": edges,
            "cyclomatic_complexity": cyclomatic_complexity,
            "obfuscation_indicators": [],
        }

        # High cyclomatic complexity suggests obfuscation
        if cyclomatic_complexity > 20:
            result["obfuscation_indicators"].append(
                f"High cyclomatic complexity ({cyclomatic_complexity}) suggests obfuscation"
            )

        # Single-block functions (possible dead code)
        if len(blocks) == 1:
            result["obfuscation_indicators"].append("Single basic block - possible dummy function")

        r2.quit()
        return result
    except Exception as e:
        return {"error": f"CFG generation failed: {e!s}"}


def generate_call_graph(sample_path: str) -> dict:
    """Generate function call graph for entire binary.

    Args:
        sample_path: Path to the binary
    """
    try:
        import r2pipe
    except ImportError:
        return {"error": "r2pipe not installed"}

    try:
        r2 = r2pipe.open(sample_path, flags=["-2"])
        r2.cmd("aaa")

        # Get all functions
        functions = r2.cmdj("aflj")

        call_graph = {
            "nodes": [],
            "edges": [],
            "stats": {
                "total_functions": len(functions) if functions else 0,
                "total_calls": 0,
                "recursive_functions": 0,
            },
        }

        if not functions:
            r2.quit()
            return call_graph

        # Build nodes
        func_set = set()
        for func in functions[:500]:  # Limit
            addr = func.get("offset", 0)
            name = func.get("name", "unknown")
            call_graph["nodes"].append(
                {
                    "address": f"0x{addr:x}",
                    "name": name,
                    "size": func.get("size", 0),
                }
            )
            func_set.add(addr)

        # Build edges (function calls)
        for func in functions[:500]:
            caller_addr = func.get("offset", 0)
            caller_name = func.get("name", "unknown")

            # Get calls from this function
            calls = r2.cmdj(f"axtj {caller_addr:x}")

            if calls:
                for call in calls:
                    call_addr = call.get("from", 0)
                    if call_addr in func_set:
                        call_graph["edges"].append(
                            {
                                "from": f"0x{caller_addr:x}",
                                "from_name": caller_name,
                                "to": f"0x{call_addr:x}",
                                "to_name": call.get("fcn_name", "unknown"),
                            }
                        )
                        call_graph["stats"]["total_calls"] += 1

        # Detect recursive functions (self-referencing)
        edge_counts = Counter(e["from"] for e in call_graph["edges"])
        for _addr, count in edge_counts.items():
            if count > 3:  # Function calls itself many times
                call_graph["stats"]["recursive_functions"] += 1

        r2.quit()
        return call_graph
    except Exception as e:
        return {"error": f"Call graph generation failed: {e!s}"}


def radare2_analyze_sync(
    sample_path: str,
    analysis_depth: str = "deep",
    extract_functions: bool = True,
    detect_crypto: bool = True,
    generate_cfg: bool = False,
    generate_callgraph: bool = False,
) -> str:
    """Synchronous radare2 analysis implementation."""

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

    try:
        import r2pipe
    except ImportError:
        return json.dumps({"success": False, "error": "r2pipe not installed"})

    try:
        # Open binary with radare2
        r2 = r2pipe.open(sample_path, flags=["-2"])

        # Run analysis based on depth
        if analysis_depth == "deep":
            r2.cmd("aaa")  # Analyze all
        elif analysis_depth == "standard":
            r2.cmd("aa")  # Analyze functions
        else:  # quick
            r2.cmd("af")  # Analyze function at entry

        result = {"success": True, "sample_path": sample_path}

        # Get entry point
        entry_info = r2.cmdj("iej")
        if entry_info and len(entry_info) > 0:
            result["entry_point"] = f"0x{entry_info[0].get('vaddr', 0):x}"
        else:
            result["entry_point"] = None

        # Extract functions
        if extract_functions:
            functions_raw = r2.cmdj("aflj")
            functions = []

            if functions_raw:
                for func in functions_raw[:100]:  # Limit to first 100 functions
                    func_info = {
                        "address": f"0x{func.get('offset', 0):x}",
                        "name": func.get("name", "unknown"),
                        "size": func.get("size", 0),
                        "calls": [],
                    }

                    # Check for suspicious characteristics
                    name = func.get("name", "").lower()
                    if any(
                        keyword in name
                        for keyword in ["decrypt", "decode", "unpack", "inject", "shellcode"]
                    ):
                        func_info["suspicious"] = True
                        func_info["reason"] = f"Suspicious function name: {func.get('name')}"

                    functions.append(func_info)

            result["functions"] = functions
            result["total_functions"] = len(functions_raw) if functions_raw else 0

        # Get imports
        imports_raw = r2.cmdj("iij")
        imports = []
        suspicious_apis = {
            "VirtualAllocEx": "Memory allocation (injection)",
            "WriteProcessMemory": "Process injection",
            "CreateRemoteThread": "Remote thread creation",
            "NtCreateThreadEx": "Remote thread creation",
            "SetWindowsHookEx": "Keylogger technique",
            "GetAsyncKeyState": "Keylogger technique",
            "IsDebuggerPresent": "Anti-debugging",
            "CheckRemoteDebuggerPresent": "Anti-debugging",
            "NtQueryInformationProcess": "Anti-debugging",
            "OutputDebugString": "Anti-debugging",
            "RegSetValueEx": "Registry modification",
            "URLDownloadToFile": "Download capability",
            "InternetOpen": "Network capability",
            "WSAStartup": "Network capability",
            "socket": "Network capability",
            "connect": "Network capability",
        }

        suspicious_api_list = []

        if imports_raw:
            for imp in imports_raw[:200]:  # Limit imports
                func_name = imp.get("name", "")
                import_info = {"name": func_name, "type": imp.get("type", "unknown")}

                # Check if API is suspicious
                for api, reason in suspicious_apis.items():
                    if api in func_name:
                        import_info["suspicious"] = True
                        import_info["reason"] = reason
                        suspicious_api_list.append({"api": func_name, "reason": reason})
                        break

                imports.append(import_info)

        result["imports"] = imports[:50]  # Limit to first 50 in output
        result["total_imports"] = len(imports)
        result["suspicious_apis"] = suspicious_api_list

        # Get strings and their cross-references
        strings_raw = r2.cmdj("izj")
        strings_xrefs = []

        if strings_raw:
            for string_info in strings_raw[:100]:  # Limit strings
                string_val = string_info.get("string", "")

                # Look for interesting strings
                if any(
                    keyword in string_val.lower()
                    for keyword in [
                        "http://",
                        "https://",
                        "ftp://",
                        ".exe",
                        ".dll",
                        "cmd.exe",
                        "powershell",
                    ]
                ):
                    strings_xrefs.append(
                        {
                            "string": string_val[:100],
                            "address": f"0x{string_info.get('vaddr', 0):x}",
                        }
                    )

        result["strings_xrefs"] = strings_xrefs

        # Detect crypto constants
        crypto_constants = []
        if detect_crypto:
            # Search for AES S-box
            aes_results = r2.cmd("/x 637c777bf26b6fc5")
            if aes_results and "0x" in aes_results:
                crypto_constants.append("AES S-box detected")

            # Search for common base64 tables
            b64_results = r2.cmd("/x 4142434445464748494a4b4c4d4e4f50")
            if b64_results and "0x" in b64_results:
                crypto_constants.append("Base64 table detected")

        result["crypto_constants"] = crypto_constants

        # Detect anti-analysis techniques
        anti_analysis = []

        # Search for anti-debug API calls
        if imports_raw:
            for imp in imports_raw:
                func_name = imp.get("name", "")
                if "IsDebuggerPresent" in func_name:
                    anti_analysis.append("IsDebuggerPresent import detected")
                elif "CheckRemoteDebuggerPresent" in func_name:
                    anti_analysis.append("CheckRemoteDebuggerPresent import detected")
                elif "NtQueryInformationProcess" in func_name:
                    anti_analysis.append("NtQueryInformationProcess import detected")
                elif "OutputDebugString" in func_name:
                    anti_analysis.append("OutputDebugString import detected")

        # Check for CPUID instruction (anti-VM)
        cpuid_results = r2.cmd("/x 0fa2")
        if cpuid_results and "0x" in cpuid_results:
            anti_analysis.append("CPUID instruction detected (possible VM detection)")

        # Check for RDTSC instruction (timing checks)
        rdtsc_results = r2.cmd("/x 0f31")
        if rdtsc_results and "0x" in rdtsc_results:
            anti_analysis.append("RDTSC instruction detected (timing checks)")

        result["anti_analysis"] = anti_analysis

        # Generate CFG if requested
        if generate_cfg and functions_raw:
            cfg_results = []
            for func in functions_raw[:5]:  # Limit to first 5 functions
                func_addr = f"0x{func.get('offset', 0):x}"
                cfg = generate_cfg(sample_path, func_addr)
                if "error" not in cfg:
                    cfg["function_name"] = func.get("name", "unknown")
                    cfg_results.append(cfg)
            result["control_flow_graphs"] = cfg_results

        # Generate call graph if requested
        if generate_callgraph:
            call_graph = generate_call_graph(sample_path)
            result["call_graph"] = call_graph

        # Close radare2
        r2.quit()

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"success": False, "error": f"Radare2 analysis failed: {e!s}"})


@function_tool(timeout=120)
async def radare2_analyze(
    sample_path: str,
    analysis_depth: str = "deep",
    extract_functions: bool = True,
    detect_crypto: bool = True,
    generate_cfg: bool = False,
    generate_callgraph: bool = False,
) -> str:
    """Analyze binary with radare2 for disassembly and behavioral patterns.

    Args:
        sample_path: Path to the binary to analyze
        analysis_depth: Analysis level - "quick", "standard", or "deep" (default: "deep")
        extract_functions: Whether to extract function information (default: True)
        detect_crypto: Whether to search for crypto constants (default: True)
        generate_cfg: Whether to generate control flow graphs (default: False)
        generate_callgraph: Whether to generate function call graph (default: False)

    Returns:
        JSON string with analysis results including functions, imports, strings,
        suspicious indicators, optional CFGs, and call graph
    """
    return await asyncio.to_thread(
        radare2_analyze_sync,
        sample_path,
        analysis_depth,
        extract_functions,
        detect_crypto,
        generate_cfg,
        generate_callgraph,
    )
