"""Tests for SARIF output."""

from __future__ import annotations

import json
from pathlib import Path

from kael.report.sarif import write_sarif


class TestSARIF:
    def test_basic_sarif_shape(self, tmp_path: Path) -> None:
        reports = [
            {
                "id": "vuln-0001",
                "title": "SQLi in /api/users",
                "severity": "critical",
                "description": "Unsanitized user input in id parameter",
                "impact": "Full DB compromise",
                "technical_analysis": "concat() of user input into SQL",
                "cvss": 9.8,
                "cve": "CVE-2024-1234",
                "cwe": "CWE-89",
                "endpoint": "/api/users",
                "method": "GET",
                "code_locations": [{"file": "src/api/users.py", "start_line": 42, "end_line": 45}],
            }
        ]
        out_path = write_sarif(tmp_path, reports)
        assert out_path.exists()
        data = json.loads(out_path.read_text(encoding="utf-8"))

        assert data["version"] == "2.1.0"
        assert data["$schema"].endswith("sarif-schema-2.1.0.json")
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "Kael"
        assert run["tool"]["driver"]["version"]
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 1

        result = run["results"][0]
        assert result["level"] == "error"
        assert result["ruleId"] == "kael/vuln/0001"
        assert result["properties"]["cve"] == "CVE-2024-1234"
        assert result["properties"]["cwe"] == "CWE-89"
        assert result["properties"]["cwe_id"] == 89
        assert result["properties"]["kael_cvss_score"] == 9.8
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/api/users.py"
        assert loc["region"]["startLine"] == 42
        assert loc["region"]["endLine"] == 45

    def test_severity_mapping(self, tmp_path: Path) -> None:
        reports = [
            {"id": "v1", "title": "c", "severity": "critical"},
            {"id": "v2", "title": "h", "severity": "high"},
            {"id": "v3", "title": "m", "severity": "medium"},
            {"id": "v4", "title": "l", "severity": "low"},
            {"id": "v5", "title": "i", "severity": "info"},
        ]
        out_path = write_sarif(tmp_path, reports)
        data = json.loads(out_path.read_text(encoding="utf-8"))
        levels = [r["level"] for r in data["runs"][0]["results"]]
        assert levels == ["error", "error", "warning", "note", "note"]

    def test_no_vulnerabilities(self, tmp_path: Path) -> None:
        out_path = write_sarif(tmp_path, [])
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []

    def test_endpoint_only_location(self, tmp_path: Path) -> None:
        reports = [
            {"id": "v1", "title": "X", "severity": "low", "endpoint": "/login", "method": "POST"}
        ]
        out_path = write_sarif(tmp_path, reports)
        data = json.loads(out_path.read_text(encoding="utf-8"))
        result = data["runs"][0]["results"][0]
        assert "locations" in result
        loc = result["locations"][0]
        assert loc["logicalLocation"]["name"] == "endpoint"
        assert loc["properties"]["endpoint"] == "/login"
        assert loc["properties"]["method"] == "POST"

    def test_invalid_cve_cwe_are_dropped(self, tmp_path: Path) -> None:
        reports = [
            {"id": "v1", "title": "X", "severity": "low", "cve": "not-a-cve", "cwe": "invalid"}
        ]
        out_path = write_sarif(tmp_path, reports)
        data = json.loads(out_path.read_text(encoding="utf-8"))
        props = data["runs"][0]["results"][0]["properties"]
        assert "cve" not in props
        assert "cwe" not in props
        assert "cwe_id" not in props

    def test_atomic_write_no_partial_files(self, tmp_path: Path) -> None:
        write_sarif(tmp_path, [{"id": "v1", "title": "X", "severity": "low"}])
        assert [p for p in tmp_path.iterdir() if p.name.startswith(".results.sarif.")] == []
