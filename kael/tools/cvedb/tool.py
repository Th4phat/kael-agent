"""``cve_lookup`` — Shodan CVEDB-backed CVE / EPSS / KEV intelligence.

CVEDB (https://cvedb.shodan.io) is Shodan's free, no-auth, no-rate-limit
vulnerability database. Unlike NVD it returns four fields that matter
most for **practical exploitation triage**:

- ``cvss`` — authoritative score, multiple versions (v2/v3/v4)
- ``epss`` — Exploit Prediction Scoring System probability (0-1) that
  this CVE will be exploited in the next 30 days
- ``kev`` — whether the CVE is in CISA's Known Exploited Vulnerabilities
  catalog
- ``ransomware_campaign`` — whether known ransomware groups have used it

For a pentest agent this is the single highest-value lookup: it answers
"Is this CVE dangerous enough to spend an iteration on?" in one call.

Two operations are exposed:

1. **Look up a CVE by ID** — ``cve_lookup(query="CVE-2021-40352")`` —
   returns the full normalized record (CVSS, EPSS, KEV, affected CPEs,
   references, ransomware flag, EUVD alias).

2. **Search CVEs by filter** — ``cve_lookup(query="log4j", is_kev=True,
   sort_by_epss=True)`` — returns the matching list. Filter args
   (``product``, ``cpe23``, ``is_kev``, ``start_date``, ``end_date``,
   ``sort_by_epss``) map directly to CVEDB's query string.

This complements ``exploit_db_search`` (which returns the PoC code)
and ``exploit_search`` (which returns web artifacts) by giving the
agent the *severity and exploit-likelihood* layer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any
from urllib.parse import quote

import requests
from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


_CVEDB_BASE = "https://cvedb.shodan.io"
_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_MAX_SUMMARY_CHARS = 2_000
_MAX_REFERENCES = 25
_MAX_LIST_RESULTS = 50


def _is_cve_id(query: str) -> bool:
    return bool(_CVE_RE.match(query.strip()))


def _normalize_cve_record(record: dict[str, Any]) -> dict[str, Any]:
    """Flatten a CVEDB single-CVE payload into a stable shape."""
    summary = str(record.get("summary") or "")[:_MAX_SUMMARY_CHARS]

    refs = record.get("references") or []
    if not isinstance(refs, list):
        refs = []
    references = [str(r) for r in refs if r][:_MAX_REFERENCES]

    cpes = record.get("cpes") or []
    if not isinstance(cpes, list):
        cpes = []
    cpes_clean = [str(c) for c in cpes if c]

    euvd = record.get("euvd")
    euvd_clean: dict[str, Any] | None = None
    if isinstance(euvd, dict):
        euvd_clean = {
            "id": euvd.get("id"),
            "description": (str(euvd.get("description") or "")[:_MAX_SUMMARY_CHARS] or None),
            "published_time": euvd.get("published_time"),
            "assigner": euvd.get("assigner"),
        }

    return {
        "cve_id": record.get("cve_id"),
        "summary": summary,
        "cvss": record.get("cvss"),
        "cvss_version": record.get("cvss_version"),
        "cvss_v2": record.get("cvss_v2"),
        "cvss_v3": record.get("cvss_v3"),
        "cvss_v4": record.get("cvss_v4"),
        "epss": record.get("epss"),
        "ranking_epss": record.get("ranking_epss"),
        "kev": bool(record.get("kev")),
        "ransomware_campaign": record.get("ransomware_campaign"),
        "propose_action": record.get("propose_action"),
        "vendor": record.get("vendor"),
        "product": record.get("product"),
        "version": record.get("version"),
        "cpes": cpes_clean,
        "published_time": record.get("published_time"),
        "references": references,
        "euvd": euvd_clean,
    }


def _normalize_list_record(record: dict[str, Any]) -> dict[str, Any]:
    """List-endpoint variant: includes vendor/product/version, no cpes/references trim."""
    refs = record.get("references") or []
    if not isinstance(refs, list):
        refs = []
    references = [str(r) for r in refs if r][:_MAX_REFERENCES]
    summary = str(record.get("summary") or "")[:_MAX_SUMMARY_CHARS]
    return {
        "cve_id": record.get("cve_id"),
        "summary": summary,
        "cvss": record.get("cvss"),
        "cvss_version": record.get("cvss_version"),
        "cvss_v3": record.get("cvss_v3"),
        "epss": record.get("epss"),
        "ranking_epss": record.get("ranking_epss"),
        "kev": bool(record.get("kev")),
        "ransomware_campaign": record.get("ransomware_campaign"),
        "vendor": record.get("vendor"),
        "product": record.get("product"),
        "version": record.get("version"),
        "published_time": record.get("published_time"),
        "references": references,
    }


def _do_cve_lookup(  # noqa: PLR0911, PLR0912, PLR0915 - distinct error paths + filter/route branches
    query: str,
    *,
    product: str | None = None,
    cpe23: str | None = None,
    is_kev: bool | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    sort_by_epss: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    """Synchronous CVEDB call. Returns a structured dict — never raises.

    All failure modes return ``{"success": False, "error": ...}`` so the
    SDK can surface the message to the model without an exception.

    Routing logic:

    - If ``query`` matches ``CVE-YYYY-NNNN`` exactly (case-insensitive),
      hit ``/cve/<CVE>`` and return the full single-CVE record.
    - Otherwise treat ``query`` as a product name (only useful when
      ``product`` is also passed or no other filter is given) and
      delegate to the list endpoint.
    - If ``product`` or ``cpe23`` is given, prefer the list endpoint
      even if ``query`` looks like a CVE — the filter is the source of
      truth.
    """
    if not query or not query.strip():
        return {"success": False, "error": "Query cannot be empty"}

    cleaned_query = query.strip()
    has_filter = bool(product or cpe23 or is_kev is not None or start_date or end_date)
    cve_match = _is_cve_id(cleaned_query)
    prefer_list = has_filter and not (cve_match and not has_filter)

    try:
        with requests.Session() as session:
            session.headers.update(
                {
                    "User-Agent": _DEFAULT_USER_AGENT,
                    "Accept": "application/json",
                }
            )

            if cve_match and not prefer_list:
                url = f"{_CVEDB_BASE}/cve/{quote(cleaned_query.upper())}"
                logger.info("cve_lookup single cve=%s", cleaned_query.upper())
                response = session.get(url, timeout=timeout)
            else:
                params: list[tuple[str, str]] = []
                if cpe23:
                    params.append(("cpe23", cpe23))
                elif product:
                    params.append(("product", product))
                else:
                    params.append(("product", cleaned_query))
                if is_kev is not None:
                    params.append(("is_kev", "true" if is_kev else "false"))
                if start_date:
                    params.append(("start_date", start_date))
                if end_date:
                    params.append(("end_date", end_date))
                if sort_by_epss:
                    params.append(("sort_by_epss", "true"))
                params.append(("limit", str(_MAX_LIST_RESULTS)))
                url = f"{_CVEDB_BASE}/cves"
                logger.info("cve_lookup list params=%s", params)
                response = session.get(url, params=params, timeout=timeout)

            response.raise_for_status()
            data = response.json()
    except requests.exceptions.Timeout:
        logger.warning("cve_lookup timed out")
        return {"success": False, "error": "CVE lookup timed out. Try a simpler query"}
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        logger.exception("cve_lookup HTTP error status=%s", status)
        return {
            "success": False,
            "error": f"CVE lookup service returned HTTP {status}. Try again later",
        }
    except requests.exceptions.RequestException:
        logger.exception("cve_lookup network error")
        return {"success": False, "error": "CVE lookup network error. Try again later"}
    except (ValueError, TypeError):
        logger.exception("cve_lookup response shape unexpected")
        return {"success": False, "error": "CVE lookup returned an unexpected response. Try again"}
    except Exception:
        logger.exception("cve_lookup failed unexpectedly")
        return {"success": False, "error": "CVE lookup failed unexpectedly"}

    if cve_match and not prefer_list:
        if not isinstance(data, dict) or "cve_id" not in data:
            return {
                "success": False,
                "error": (
                    f"No CVEDB record for {cleaned_query.upper()}. "
                    "Double-check the CVE ID or try web_search."
                ),
            }
        return {
            "success": True,
            "lookup_type": "cve",
            "query": cleaned_query.upper(),
            "result": _normalize_cve_record(data),
        }

    if not isinstance(data, dict):
        return {"success": False, "error": "CVE lookup returned an unexpected response"}
    raw_cves = data.get("cves")
    if not isinstance(raw_cves, list):
        return {"success": False, "error": "CVE lookup returned an unexpected response"}

    results = [_normalize_list_record(r) for r in raw_cves if isinstance(r, dict)]
    return {
        "success": True,
        "lookup_type": "list",
        "query": cleaned_query,
        "product": product,
        "cpe23": cpe23,
        "is_kev": is_kev,
        "start_date": start_date,
        "end_date": end_date,
        "sort_by_epss": sort_by_epss,
        "result_count": len(results),
        "results": results,
    }


@function_tool(timeout=60, strict_mode=False)
async def cve_lookup(
    ctx: RunContextWrapper,
    query: str,
    product: str | None = None,
    cpe23: str | None = None,
    is_kev: bool | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    sort_by_epss: bool = False,
) -> str:
    """Look up a single CVE or search CVEs by product / KEV / date range.

    Backed by Shodan's CVEDB — no API key required. Returns CVSS scores
    (v2/v3/v4), EPSS exploitation-likelihood probability, KEV (CISA
    Known Exploited) flag, ransomware-campaign flag, affected CPEs,
    vendor/product/version, references, and the EUVD alias record.

    Use this when you need to answer any of:

    - "How dangerous is CVE-XXXX-XXXX?" → full record
    - "Is this CVE being exploited in the wild?" → ``kev`` field
    - "What's the chance someone has a working exploit?" → ``epss``
    - "Show me Log4j CVEs that are known-exploited" → ``product="log4j"`` + ``is_kev=True``
    - "Newest CVEs for apache struts sorted by exploit-likelihood" →
      ``product="apache struts"`` + ``sort_by_epss=True``
    - "All CVEs in CISA KEV from 2025" → ``is_kev=True`` +
      ``start_date="2025-01-01"`` + ``end_date="2025-12-31"``

    **Quick decision rules for prioritization:**

    - ``kev == True`` → CISA-confirmed exploited, must be on the test list
    - ``epss >= 0.5`` → high probability of in-the-wild exploitation
    - ``ransomware_campaign`` not null → tied to ransomware groups
    - ``cvss >= 7.0`` and any of the above → top priority

    When ``query`` is a ``CVE-YYYY-NNNN`` ID, returns a single full
    record. Otherwise treats it as a product name (or uses the explicit
    ``product`` / ``cpe23`` filter) and returns a list.

    Args:
        query: Either a CVE ID (``CVE-2021-40352``) or a product name
            (``log4j``). If a CVE ID is given, the other filter args are
            ignored unless they are also set.
        product: Product name filter, e.g. ``"log4j"``, ``"apache struts"``,
            ``"openssl"``. Use this to disambiguate ``query`` (e.g. when
            ``query="apache"`` but you mean ``"apache httpd"``).
        cpe23: CPE 2.3 string, e.g. ``"cpe:2.3:a:apache:log4j:2.14.1"``.
            Most precise filter — use it when you know the exact
            product:version. Takes precedence over ``product``.
        is_kev: If True, only return CISA Known Exploited Vulnerabilities.
            If False, only return non-KEV. If None, return both.
        start_date: ISO date ``YYYY-MM-DD``. Filter CVEs published on/after
            this date. Useful for "newest CVEs" queries.
        end_date: ISO date ``YYYY-MM-DD``. Filter CVEs published on/before
            this date.
        sort_by_epss: If True, sort results by EPSS descending. The
            single-CVE endpoint is unaffected.
    """
    result = await asyncio.to_thread(
        _do_cve_lookup,
        query,
        product=product,
        cpe23=cpe23,
        is_kev=is_kev,
        start_date=start_date,
        end_date=end_date,
        sort_by_epss=sort_by_epss,
        timeout=30,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
