"""SARIF 2.1.0 output for Kael vulnerability findings.

SARIF (Static Analysis Results Interchange Format) is the OASIS standard
for security-tool output, ingestable by GitHub Security tab, VS Code,
SonarQube, and most enterprise triage platforms.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from kael.report.writer import _atomic_write_text


logger = logging.getLogger(__name__)


_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_CWE_RE = re.compile(r"CWE-(\d+)")


def _get_kael_version() -> str:
    try:
        return version("kael-agent")
    except PackageNotFoundError:
        return "1.0.3"


def _vuln_to_sarif_result(report: dict[str, Any], index: int) -> dict[str, Any]:
    """Map one Kael vulnerability record to one SARIF ``result``."""
    severity = str(report.get("severity", "info")).lower()
    level = _SEVERITY_TO_SARIF_LEVEL.get(severity, "note")
    title = str(report.get("title", "Untitled vulnerability"))
    rule_id = f"kael/vuln/{index + 1:04d}"
    rid = str(report.get("id", ""))

    message_text = str(report.get("description", "")).strip() or title

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message_text},
        "properties": {
            "kael_id": rid,
            "kael_severity": severity,
            "kael_title": title,
            "kael_timestamp": str(report.get("timestamp", "")),
        },
    }

    cvss = report.get("cvss")
    if cvss is not None:
        result["properties"]["kael_cvss_score"] = cvss
    cve = report.get("cve")
    if isinstance(cve, str):
        match = _CVE_RE.search(cve)
        if match:
            result["properties"]["cve"] = match.group(0)
    cwe = report.get("cwe")
    if isinstance(cwe, str):
        match = _CWE_RE.search(cwe)
        if match:
            result["properties"]["cwe_id"] = int(match.group(1))
            result["properties"]["cwe"] = match.group(0)

    location = _build_location(report)
    if location is not None:
        result["locations"] = [location]
    return result


def _build_location(report: dict[str, Any]) -> dict[str, Any] | None:
    code_locs = report.get("code_locations") or []
    endpoint = report.get("endpoint")
    if not code_locs and not endpoint:
        return None
    if code_locs:
        first = code_locs[0] if isinstance(code_locs[0], dict) else {}
        file_path = first.get("file")
        start_line = first.get("start_line")
        if file_path and isinstance(start_line, int):
            phys_loc: dict[str, Any] = {
                "artifactLocation": {"uri": str(file_path)},
                "region": {"startLine": start_line},
            }
            end_line = first.get("end_line")
            if isinstance(end_line, int) and end_line >= start_line:
                phys_loc["region"]["endLine"] = end_line
            return {"physicalLocation": phys_loc}
    if endpoint:
        return {
            "logicalLocation": {
                "name": "endpoint",
                "kind": "url",
            },
            "properties": {"endpoint": str(endpoint), "method": report.get("method", "")},
        }
    return None


def write_sarif(
    run_dir: Path | str,
    vulnerability_reports: list[dict[str, Any]],
) -> Path:
    """Write a SARIF 2.1.0 report of all findings into ``run_dir``.

    Output path: ``<run_dir>/results.sarif``
    """
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Kael",
                        "version": _get_kael_version(),
                        "informationUri": "https://github.com/Th4phat/kael-agent",
                        "rules": [
                            {
                                "id": f"kael/vuln/{i + 1:04d}",
                                "name": str(r.get("title", "vulnerability"))[:128],
                                "shortDescription": {
                                    "text": str(r.get("title", "vulnerability"))[:1024]
                                },
                                "defaultConfiguration": {
                                    "level": _SEVERITY_TO_SARIF_LEVEL.get(
                                        str(r.get("severity", "info")).lower(), "note"
                                    )
                                },
                                "properties": {"security-severity": str(r.get("cvss", ""))},
                            }
                            for i, r in enumerate(vulnerability_reports)
                        ],
                    }
                },
                "results": [
                    _vuln_to_sarif_result(r, i) for i, r in enumerate(vulnerability_reports)
                ],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": _utcnow_iso(),
                    }
                ],
            }
        ],
    }

    out_path = run_path / "results.sarif"
    _atomic_write_text(out_path, json.dumps(sarif, ensure_ascii=False, indent=2))
    logger.info("Wrote SARIF report to: %s", out_path)
    return out_path


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
