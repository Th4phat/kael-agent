"""Tests for the CVEDB (Shodan) lookup tool."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from kael.tools.cvedb.tool import (
    _do_cve_lookup,
    _is_cve_id,
    _normalize_cve_record,
    _normalize_list_record,
)


class TestIsCveId:
    def test_uppercase_cve(self) -> None:
        assert _is_cve_id("CVE-2021-40352") is True

    def test_lowercase_cve(self) -> None:
        assert _is_cve_id("cve-2021-40352") is True

    def test_mixed_case_cve(self) -> None:
        assert _is_cve_id("Cve-2021-40352") is True

    def test_product_is_not_cve(self) -> None:
        assert _is_cve_id("log4j") is False

    def test_empty_is_not_cve(self) -> None:
        assert _is_cve_id("") is False

    def test_whitespace_is_not_cve(self) -> None:
        assert _is_cve_id("   ") is False

    def test_malformed_cve_rejected(self) -> None:
        # Too many digits
        assert _is_cve_id("CVE-2021-403521234") is False
        # Missing year
        assert _is_cve_id("CVE-40352") is False
        # Non-numeric
        assert _is_cve_id("CVE-2021-abcde") is False


class TestNormalizeCveRecord:
    def test_basic_shape(self) -> None:
        record = {
            "cve_id": "CVE-2021-40352",
            "summary": "OpenEMR pnotes_print IDOR",
            "cvss": 6.5,
            "cvss_version": 3.0,
            "cvss_v2": 4.0,
            "cvss_v3": 6.5,
            "cvss_v4": None,
            "epss": 0.04642,
            "ranking_epss": 0.89525,
            "kev": False,
            "ransomware_campaign": None,
            "propose_action": None,
            "cpes": ["cpe:2.3:a:open-emr:openemr:6.0.0"],
            "references": [
                "https://example.com/advisory",
                "https://github.com/foo/CVE-2021-40352",
            ],
            "published_time": "2021-09-01T13:15:08",
            "euvd": {
                "id": "EUVD-2021-27530",
                "description": "OpenEMR IDOR",
                "published_time": "2021-09-01T12:20:41",
                "assigner": "mitre",
            },
        }
        result = _normalize_cve_record(record)
        assert result["cve_id"] == "CVE-2021-40352"
        assert result["cvss"] == 6.5
        assert result["kev"] is False
        assert result["cpes"] == ["cpe:2.3:a:open-emr:openemr:6.0.0"]
        assert result["euvd"]["id"] == "EUVD-2021-27530"
        assert len(result["references"]) == 2

    def test_kev_true_is_boolean(self) -> None:
        # Shodan sometimes returns int 1 instead of bool
        record = {
            "cve_id": "CVE-2021-44228",
            "kev": 1,
            "summary": "Log4Shell",
        }
        result = _normalize_cve_record(record)
        assert result["kev"] is True

    def test_summary_truncated(self) -> None:
        record = {"cve_id": "X", "summary": "x" * 5_000}
        result = _normalize_cve_record(record)
        assert len(result["summary"]) == 2_000

    def test_references_capped(self) -> None:
        refs = [f"https://example.com/{i}" for i in range(100)]
        record = {"cve_id": "X", "references": refs}
        result = _normalize_cve_record(record)
        assert len(result["references"]) == 25

    def test_non_list_cpes_normalized_empty(self) -> None:
        record = {"cve_id": "X", "cpes": "not-a-list"}
        result = _normalize_cve_record(record)
        assert result["cpes"] == []

    def test_non_dict_euvd_handled(self) -> None:
        record = {"cve_id": "X", "euvd": "not-a-dict"}
        result = _normalize_cve_record(record)
        assert result["euvd"] is None


class TestNormalizeListRecord:
    def test_list_shape(self) -> None:
        record = {
            "cve_id": "CVE-2021-44228",
            "summary": "Log4Shell",
            "cvss": 10.0,
            "epss": 0.94,
            "kev": True,
            "ransomware_campaign": "Known",
            "vendor": "apache",
            "product": "log4j",
            "version": "2.14.1",
            "published_time": "2021-12-10T00:00:00",
            "references": ["https://logging.apache.org/log4j/2.x/security.html"],
        }
        result = _normalize_list_record(record)
        assert result["cve_id"] == "CVE-2021-44228"
        assert result["kev"] is True
        assert result["vendor"] == "apache"
        assert result["product"] == "log4j"
        assert result["version"] == "2.14.1"


class TestDoCveLookup:
    def test_empty_query_returns_error(self) -> None:
        result = _do_cve_lookup("")
        assert result["success"] is False
        assert "empty" in result["error"].lower()

    def test_whitespace_query_returns_error(self) -> None:
        result = _do_cve_lookup("   ")
        assert result["success"] is False

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_successful_cve_lookup(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        response = MagicMock()
        response.json.return_value = {
            "cve_id": "CVE-2021-40352",
            "summary": "OpenEMR IDOR",
            "cvss": 6.5,
            "cvss_version": 3.0,
            "epss": 0.04642,
            "kev": False,
            "cpes": ["cpe:2.3:a:open-emr:openemr:6.0.0"],
            "references": ["https://example.com"],
        }
        response.raise_for_status.return_value = None
        session.get.return_value = response

        result = _do_cve_lookup("CVE-2021-40352")

        assert result["success"] is True
        assert result["lookup_type"] == "cve"
        assert result["query"] == "CVE-2021-40352"
        assert result["result"]["cve_id"] == "CVE-2021-40352"
        assert result["result"]["cvss"] == 6.5
        # Single-CVE endpoint hit, not list
        called_url = session.get.call_args.args[0]
        assert called_url.endswith("/cve/CVE-2021-40352")

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_lowercase_cve_normalized_to_uppercase_in_url(
        self, mock_session_cls: MagicMock
    ) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        response = MagicMock()
        response.json.return_value = {
            "cve_id": "CVE-2021-40352",
            "summary": "x",
        }
        response.raise_for_status.return_value = None
        session.get.return_value = response

        result = _do_cve_lookup("cve-2021-40352")
        called_url = session.get.call_args.args[0]
        assert called_url.endswith("/cve/CVE-2021-40352")
        assert result["success"] is True

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_successful_list_lookup(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        response = MagicMock()
        response.json.return_value = {
            "cves": [
                {
                    "cve_id": "CVE-2021-44228",
                    "summary": "Log4Shell",
                    "cvss": 10.0,
                    "epss": 0.94,
                    "kev": True,
                    "vendor": "apache",
                    "product": "log4j",
                    "version": "2.14.1",
                },
                {
                    "cve_id": "CVE-2021-45046",
                    "summary": "Log4j follow-up",
                    "cvss": 9.0,
                    "kev": True,
                    "vendor": "apache",
                    "product": "log4j",
                },
            ]
        }
        response.raise_for_status.return_value = None
        session.get.return_value = response

        result = _do_cve_lookup("log4j", product="log4j", is_kev=True, sort_by_epss=True)

        assert result["success"] is True
        assert result["lookup_type"] == "list"
        assert result["result_count"] == 2
        assert result["results"][0]["cve_id"] == "CVE-2021-44228"
        assert result["results"][0]["kev"] is True
        # Product list endpoint hit, not single-CVE
        called_url = session.get.call_args.args[0]
        assert called_url.endswith("/cves")
        called_params = session.get.call_args.kwargs.get("params", [])
        params_dict = dict(called_params)
        assert params_dict.get("product") == "log4j"
        assert params_dict.get("is_kev") == "true"
        assert params_dict.get("sort_by_epss") == "true"

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_cpe23_takes_precedence_over_product(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        response = MagicMock()
        response.json.return_value = {"cves": []}
        response.raise_for_status.return_value = None
        session.get.return_value = response

        _do_cve_lookup(
            "CVE-2021-40352",
            product="should-be-ignored",
            cpe23="cpe:2.3:a:apache:log4j:2.14.1",
        )
        called_params = dict(session.get.call_args.kwargs.get("params", []))
        assert called_params.get("cpe23") == "cpe:2.3:a:apache:log4j:2.14.1"
        assert "product" not in called_params

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_cve_with_filter_routes_to_list_endpoint(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        response = MagicMock()
        response.json.return_value = {"cves": []}
        response.raise_for_status.return_value = None
        session.get.return_value = response

        # CVE ID + filter → list endpoint
        _do_cve_lookup("CVE-2021-40352", is_kev=True)
        called_url = session.get.call_args.args[0]
        assert called_url.endswith("/cves")
        called_params = dict(session.get.call_args.kwargs.get("params", []))
        assert called_params.get("is_kev") == "true"

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_cve_not_found(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        response = MagicMock()
        response.json.return_value = {"detail": "No information available"}
        response.raise_for_status.return_value = None
        session.get.return_value = response

        result = _do_cve_lookup("CVE-9999-99999")
        assert result["success"] is False
        assert "no cvedb record" in result["error"].lower()

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_timeout_returns_error(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        session.get.side_effect = requests.exceptions.Timeout()

        result = _do_cve_lookup("CVE-2021-40352")
        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_http_error_returns_error(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        fake_response = MagicMock()
        fake_response.status_code = 500
        http_error = requests.exceptions.HTTPError(response=fake_response)
        session.get.side_effect = http_error

        result = _do_cve_lookup("CVE-2021-40352")
        assert result["success"] is False
        assert "500" in result["error"]

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_invalid_json_returns_error(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        response = MagicMock()
        response.json.side_effect = ValueError("not json")
        response.raise_for_status.return_value = None
        session.get.return_value = response

        result = _do_cve_lookup("CVE-2021-40352")
        assert result["success"] is False
        assert "unexpected" in result["error"].lower()

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_network_error_returns_error(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        session.get.side_effect = requests.exceptions.ConnectionError()

        result = _do_cve_lookup("CVE-2021-40352")
        assert result["success"] is False
        assert "network" in result["error"].lower()

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_unexpected_exception_caught(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        session.get.side_effect = RuntimeError("boom")

        result = _do_cve_lookup("CVE-2021-40352")
        assert result["success"] is False

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_list_with_unexpected_response_shape(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        response = MagicMock()
        response.json.return_value = "not a dict"
        response.raise_for_status.return_value = None
        session.get.return_value = response

        result = _do_cve_lookup("log4j", product="log4j")
        assert result["success"] is False

    @patch("kael.tools.cvedb.tool.requests.Session")
    def test_date_filters_passed(self, mock_session_cls: MagicMock) -> None:
        session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = session
        response = MagicMock()
        response.json.return_value = {"cves": []}
        response.raise_for_status.return_value = None
        session.get.return_value = response

        _do_cve_lookup(
            "log4j",
            product="log4j",
            start_date="2024-01-01",
            end_date="2024-12-31",
        )
        params = dict(session.get.call_args.kwargs.get("params", []))
        assert params.get("start_date") == "2024-01-01"
        assert params.get("end_date") == "2024-12-31"
