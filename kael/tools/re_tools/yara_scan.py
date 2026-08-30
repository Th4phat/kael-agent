"""YARA scanning tool."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from agents.tool import function_tool

from kael.utils.resource_paths import get_kael_resource_path

from ._path_resolver import ensure_host_path


def yara_scan_sync(
    sample_path: str,
    rules_inline: str | None = None,
    rules_dir: str | None = None,
    use_bundled_rules: bool = True,
) -> str:
    """Synchronous YARA scan implementation."""
    try:
        import yara
    except ImportError:
        return json.dumps({"success": False, "error": "yara-python not installed"})

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
        rules_to_compile: list[tuple[str, str]] = []

        # Compile bundled rules
        if use_bundled_rules:
            bundled_dirs = [Path("/opt/yara-rules")]
            source_rules = get_kael_resource_path("tools", "re_sandbox", "yara_rules")
            if source_rules not in bundled_dirs:
                bundled_dirs.append(source_rules)
            for bundled_dir in bundled_dirs:
                if not bundled_dir.is_dir():
                    continue
                for root, _dirs, files in os.walk(str(bundled_dir)):
                    for file in files:
                        if file.endswith(".yar") or file.endswith(".yara"):
                            rule_path = os.path.join(root, file)
                            try:
                                with open(rule_path) as f:
                                    rule_content = f.read()
                                # Use relative path as identifier
                                rule_id = os.path.relpath(rule_path, str(bundled_dir))
                                rules_to_compile.append((rule_id, rule_content))
                            except Exception:
                                # Skip broken rules
                                continue

        # Compile inline rules
        if rules_inline:
            rules_to_compile.append(("inline", rules_inline))

        # Compile rules from directory
        if rules_dir and os.path.exists(rules_dir):
            for root, _dirs, files in os.walk(rules_dir):
                for file in files:
                    if file.endswith(".yar") or file.endswith(".yara"):
                        rule_path = os.path.join(root, file)
                        try:
                            with open(rule_path) as f:
                                rule_content = f.read()
                            rule_id = os.path.relpath(rule_path, rules_dir)
                            rules_to_compile.append((rule_id, rule_content))
                        except Exception:
                            continue

        if not rules_to_compile:
            return json.dumps({"success": False, "error": "No YARA rules to compile"})

        # Compile all rules into a single ruleset
        sources_dict = {rule_id: rule_content for rule_id, rule_content in rules_to_compile}

        try:
            compiled_rules = yara.compile(sources=sources_dict)
        except Exception as e:
            return json.dumps({"success": False, "error": f"Failed to compile YARA rules: {e!s}"})

        # Scan the sample
        start_time = time.time()
        matches = compiled_rules.match(sample_path)
        scan_time_ms = int((time.time() - start_time) * 1000)

        # Process matches
        all_matches = []
        for match in matches:
            match_info = {
                "rule_name": match.rule,
                "namespace": match.namespace or "default",
                "tags": list(match.tags),
                "meta": dict(match.meta) if match.meta else {},
                "strings": [],
            }

            # Add string matches (limit to first 10 to avoid huge output)
            for idx, string_match in enumerate(match.strings):
                if idx >= 10:
                    match_info["strings"].append(
                        {"note": f"... and {len(match.strings) - 10} more string matches"}
                    )
                    break

                # string_match is a tuple: (offset, identifier, data)
                try:
                    data_hex = (
                        string_match[2][:50].hex()
                        if len(string_match[2]) > 50
                        else string_match[2].hex()
                    )
                    match_info["strings"].append(
                        {
                            "offset": f"0x{string_match[0]:X}",
                            "identifier": string_match[1],
                            "data": data_hex,
                        }
                    )
                except Exception:
                    # If hex conversion fails, skip this string
                    continue

            all_matches.append(match_info)

        return json.dumps(
            {
                "success": True,
                "sample_path": sample_path,
                "matches": all_matches,
                "total_matches": len(all_matches),
                "scan_time_ms": scan_time_ms,
                "rules_loaded": len(rules_to_compile),
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"success": False, "error": f"YARA scan failed: {e!s}"})


@function_tool(timeout=60)
async def yara_scan(
    sample_path: str,
    rules_inline: str | None = None,
    rules_dir: str | None = None,
    use_bundled_rules: bool = True,
) -> str:
    """Scan a sample with YARA rules.

    Args:
        sample_path: Path to the file to scan
        rules_inline: Optional inline YARA rule(s) as string
        rules_dir: Optional directory containing .yar/.yara files
        use_bundled_rules: Whether to use bundled Kael rules (default: True)

    Returns:
        JSON string with scan results including matches, metadata, and string offsets
    """
    return await asyncio.to_thread(
        yara_scan_sync,
        sample_path,
        rules_inline,
        rules_dir,
        use_bundled_rules,
    )
