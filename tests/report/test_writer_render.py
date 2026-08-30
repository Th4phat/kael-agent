"""Edge case tests for the report writer."""

from __future__ import annotations

from pathlib import Path

from kael.report.writer import render_vulnerability_md


class TestRenderVulnerabilityMd:
    def test_minimal_required_fields(self) -> None:
        """The report dict needs at least id/title/severity/timestamp."""
        md = render_vulnerability_md(
            {
                "id": "v1",
                "title": "Test Vuln",
                "severity": "high",
                "timestamp": "2024-01-01 00:00:00 UTC",
            }
        )
        assert "# Test Vuln" in md
        assert "**ID:** v1" in md
        assert "**Severity:** HIGH" in md

    def test_default_title_for_missing(self) -> None:
        md = render_vulnerability_md({})
        assert "Untitled Vulnerability" in md

    def test_optional_metadata_fields(self) -> None:
        md = render_vulnerability_md(
            {
                "id": "v1",
                "title": "x",
                "severity": "critical",
                "timestamp": "2024-01-01 00:00:00 UTC",
                "target": "https://target.com",
                "endpoint": "/api/users",
                "method": "POST",
                "cve": "CVE-2024-1234",
                "cwe": "CWE-89",
                "cvss": 9.8,
            }
        )
        assert "https://target.com" in md
        assert "/api/users" in md
        assert "POST" in md
        assert "CVE-2024-1234" in md
        assert "CWE-89" in md
        assert "9.8" in md

    def test_description_uses_default_when_missing(self) -> None:
        md = render_vulnerability_md(
            {
                "id": "v1",
                "title": "x",
                "severity": "low",
                "timestamp": "2024-01-01 00:00:00 UTC",
            }
        )
        assert "No description provided." in md

    def test_impact_section(self) -> None:
        md = render_vulnerability_md(
            {
                "id": "v1",
                "title": "x",
                "severity": "low",
                "timestamp": "2024-01-01 00:00:00 UTC",
                "impact": "Full database compromise",
            }
        )
        assert "## Impact" in md
        assert "Full database compromise" in md

    def test_technical_analysis_section(self) -> None:
        md = render_vulnerability_md(
            {
                "id": "v1",
                "title": "x",
                "severity": "low",
                "timestamp": "2024-01-01 00:00:00 UTC",
                "technical_analysis": "String concat into SQL",
            }
        )
        assert "## Technical Analysis" in md
        assert "String concat into SQL" in md

    def test_poc_with_code_block(self) -> None:
        md = render_vulnerability_md(
            {
                "id": "v1",
                "title": "x",
                "severity": "low",
                "timestamp": "2024-01-01 00:00:00 UTC",
                "poc_description": "Step 1: do X",
                "poc_script_code": "import os\nos.system('id')",
            }
        )
        assert "## Proof of Concept" in md
        assert "Step 1: do X" in md
        assert "```" in md
        assert "os.system" in md

    def test_code_locations_rendered(self) -> None:
        md = render_vulnerability_md(
            {
                "id": "v1",
                "title": "x",
                "severity": "low",
                "timestamp": "2024-01-01 00:00:00 UTC",
                "code_locations": [
                    {
                        "file": "src/api.py",
                        "start_line": 42,
                        "end_line": 45,
                        "snippet": "query = f'SELECT * FROM users WHERE id={id}'",
                        "label": "Vulnerable query",
                    }
                ],
            }
        )
        assert "## Code Analysis" in md
        assert "src/api.py" in md
        assert "lines 42-45" in md
        assert "Vulnerable query" in md
        assert "SELECT" in md

    def test_code_locations_single_line(self) -> None:
        md = render_vulnerability_md(
            {
                "id": "v1",
                "title": "x",
                "severity": "low",
                "timestamp": "2024-01-01 00:00:00 UTC",
                "code_locations": [{"file": "src/api.py", "start_line": 42, "end_line": 42}],
            }
        )
        assert "line 42" in md
        assert "lines 42-42" not in md

    def test_code_locations_with_diff_fix(self) -> None:
        md = render_vulnerability_md(
            {
                "id": "v1",
                "title": "x",
                "severity": "low",
                "timestamp": "2024-01-01 00:00:00 UTC",
                "code_locations": [
                    {
                        "file": "src/api.py",
                        "start_line": 10,
                        "end_line": 12,
                        "fix_before": "old code\nthat spans\nthree lines",
                        "fix_after": "new code",
                    }
                ],
            }
        )
        assert "Suggested Fix" in md
        assert "```diff" in md
        assert "- old code" in md
        assert "- that spans" in md
        assert "- three lines" in md
        assert "+ new code" in md

    def test_remediation_section(self) -> None:
        md = render_vulnerability_md(
            {
                "id": "v1",
                "title": "x",
                "severity": "low",
                "timestamp": "2024-01-01 00:00:00 UTC",
                "remediation_steps": "Use parameterized queries",
            }
        )
        assert "## Remediation" in md
        assert "Use parameterized queries" in md
