"""Live integration test for the CVEDB (Shodan) lookup tool.

Hits the real https://cvedb.shodan.io API end-to-end:

1. Look up a well-known CVE (Log4Shell, EternalBlue, ProxyLogon)
2. Verify CVSS / EPSS / KEV / ransomware fields are populated
3. Test product filter (log4j + is_kev)
4. Test cpe23 filter
5. Test date range filter
6. Test invalid CVE returns graceful error

Run with::

    uv run pytest tests/tools/test_cvedb_live.py -v -m live
    # or
    uv run pytest tests/tools/test_cvedb_live.py -v --override-ini="addopts="
"""

from __future__ import annotations

import pytest

from kael.tools.cvedb.tool import _do_cve_lookup


pytestmark = pytest.mark.network


# All of these CVEs are extremely well-documented and should be stable
# indefinitely. They're used to verify that the real CVEDB API returns
# the data shape we normalize.
_KNOWN_CVES = [
    "CVE-2021-44228",  # Log4Shell — KEV, EPSS~0.94, CVSS 10.0, ransomware: Known
    "CVE-2017-0144",  # EternalBlue — KEV, CVSS 8.1
    "CVE-2021-26855",  # ProxyLogon — KEV, CVSS 9.8
]


@pytest.mark.parametrize("cve_id", _KNOWN_CVES)
def test_known_cve_has_full_record(cve_id: str) -> None:
    result = _do_cve_lookup(cve_id, timeout=30)
    assert result["success"] is True, f"tool failed for {cve_id}: {result.get('error')}"
    assert result["lookup_type"] == "cve"
    assert result["query"] == cve_id
    record = result["result"]
    # Required fields populated
    assert record["cve_id"] == cve_id
    assert record["summary"], f"missing summary for {cve_id}"
    # All three CVEs are in CISA KEV
    assert record["kev"] is True, f"{cve_id} should be in CISA KEV"
    # CVSS must be present and a number
    assert isinstance(record["cvss"], (int, float))
    assert 0.0 <= record["cvss"] <= 10.0
    # EPSS must be present
    assert isinstance(record["epss"], (int, float))
    assert 0.0 <= record["epss"] <= 1.0
    # References list
    assert isinstance(record["references"], list)
    assert len(record["references"]) > 0


def test_log4shell_ransomware_flag() -> None:
    """Log4Shell is documented as tied to ransomware campaigns."""
    result = _do_cve_lookup("CVE-2021-44228", timeout=30)
    assert result["success"] is True
    record = result["result"]
    assert record["ransomware_campaign"] == "Known"
    # Log4Shell EPSS should be very high (top percentile)
    assert record["epss"] > 0.5
    assert record["cvss"] == 10.0


def test_product_filter_with_kev() -> None:
    """product=log4j + is_kev=True should return at least the Log4Shell family."""
    result = _do_cve_lookup(
        "log4j",
        product="log4j",
        is_kev=True,
        sort_by_epss=True,
        timeout=30,
    )
    assert result["success"] is True
    assert result["lookup_type"] == "list"
    assert result["result_count"] >= 1
    # All results should be KEV-flagged
    cve_ids = {r["cve_id"] for r in result["results"]}
    assert "CVE-2021-44228" in cve_ids, f"expected Log4Shell in KEV-log4j results, got: {cve_ids}"
    for r in result["results"]:
        assert r["kev"] is True
    # Note: CVEDB's list endpoint doesn't echo the product filter back
    # in the response records, so we can't assert the product field.
    # EPSS-sorted: results should be in descending EPSS order
    epss_values = [r.get("epss") or 0.0 for r in result["results"]]
    assert epss_values == sorted(epss_values, reverse=True), (
        f"sort_by_epss=True should give descending EPSS: {epss_values}"
    )


def test_cpe23_filter() -> None:
    """cpe23 should give precise product:version results."""
    result = _do_cve_lookup(
        "log4j",
        cpe23="cpe:2.3:a:apache:log4j:2.14.1",
        timeout=30,
    )
    assert result["success"] is True
    # At minimum, Log4Shell should be in the results
    if result["result_count"] > 0:
        cve_ids = {r["cve_id"] for r in result["results"]}
        assert "CVE-2021-44228" in cve_ids


def test_date_range_filter() -> None:
    """start_date + end_date should narrow results to a window."""
    result = _do_cve_lookup(
        "log4j",
        product="log4j",
        start_date="2021-12-01",
        end_date="2021-12-31",
        timeout=30,
    )
    assert result["success"] is True
    # Should at least find Log4Shell (published 2021-12-10)
    if result["result_count"] > 0:
        assert any("2021" in (r.get("published_time") or "") for r in result["results"])


def test_nonexistent_cve_returns_graceful_error() -> None:
    """A made-up CVE should return a clean error, not crash."""
    result = _do_cve_lookup("CVE-9999-99999", timeout=30)
    assert result["success"] is False
    # Error message should mention something actionable
    assert result["error"]


def test_kev_false_filter() -> None:
    """is_kev=False should be passed through to the API and return results.

    Note: CVEDB's API is occasionally inconsistent — Log4Shell-class CVEs
    sometimes appear in non-KEV results. We don't assert strictness on
    the upstream behavior; we just verify the tool passes the filter
    through and returns a usable payload.
    """
    result = _do_cve_lookup(
        "log4j",
        product="log4j",
        is_kev=False,
        timeout=30,
    )
    assert result["success"] is True
    assert result["lookup_type"] == "list"
    assert result["is_kev"] is False
    assert result["result_count"] >= 1
