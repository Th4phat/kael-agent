"""mitmproxy host-side @function_tool wrappers around mitm_control.py.

These are the agent-facing proxy tools. Their *names* and result shapes
are kept stable (``list_requests``, ``view_request``, ``repeat_request``,
``list_sitemap``, ``view_sitemap_entry``, ``scope_rules``), backed by the
in-container mitmproxy addon's control plane.

The session bundle stores a ``mitm_client`` handle (see
:mod:`kael.runtime.mitm_bootstrap`); we pull its ``host_url`` out of the
run context and hand it to :mod:`kael.tools.proxy.mitm_control` as the
``base_url`` for every call.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from typing import TYPE_CHECKING, Any, Literal

from agents import RunContextWrapper, function_tool

from kael.tools.proxy import mitm_control


logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from kael.tools.proxy.mitm_control import (
        RequestPart,
        SitemapDepth,
        SortBy,
        SortOrder,
    )
else:
    from kael.tools.proxy.mitm_control import (  # noqa: TC001
        RequestPart,
        SitemapDepth,
        SortBy,
        SortOrder,
    )


ScopeAction = Literal["get", "list", "create", "update", "delete"]


def _ctx_base_url(ctx: RunContextWrapper) -> str | None:
    """Return the mitm control ``base_url`` for this run, or ``None``.

    The session manager stashes a ``MitmControl`` handle under
    ``mitm_client``; its ``host_url`` is the exposed-port URL the host
    can reach the in-container control server on.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    handle = inner.get("mitm_client")
    if handle is None:
        return None
    return getattr(handle, "host_url", None)


def _no_client() -> str:
    return json.dumps(
        {"success": False, "error": "mitmproxy control client not available in run context"},
        ensure_ascii=False,
        default=str,
    )


def _err(name: str, exc: Exception) -> str:
    logger.exception("%s failed", name)
    return json.dumps(
        {"success": False, "error": f"{name} failed: {exc}"},
        ensure_ascii=False,
        default=str,
    )


def _decode_b64(value: str | None) -> bytes:
    if not value:
        return b""
    try:
        return base64.b64decode(value)
    except (ValueError, TypeError):
        return b""


def _raw_request_text(flow: dict[str, Any]) -> str:
    """Reconstruct a raw HTTP request string from a serialized flow."""
    req = flow.get("request") or {}
    method = req.get("method", "GET")
    path = req.get("path", "/")
    lines = [f"{method} {path} HTTP/1.1"]
    for pair in req.get("headers") or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            lines.append(f"{pair[0]}: {pair[1]}")
    body = _decode_b64(req.get("content_b64")).decode("utf-8", errors="replace")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def _raw_response_text(flow: dict[str, Any]) -> str | None:
    """Reconstruct a raw HTTP response string, or ``None`` if no response."""
    resp = flow.get("response")
    if not resp:
        return None
    status = resp.get("status_code", "")
    reason = resp.get("reason", "")
    lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
    for pair in resp.get("headers") or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            lines.append(f"{pair[0]}: {pair[1]}")
    body = _decode_b64(resp.get("content_b64")).decode("utf-8", errors="replace")
    return "\r\n".join(lines) + "\r\n\r\n" + body


@function_tool(timeout=120)
async def list_requests(
    ctx: RunContextWrapper,
    mitm_filter: str | None = None,
    first: int = 50,
    after: str | None = None,
    sort_by: SortBy = "timestamp",
    sort_order: SortOrder = "desc",
    scope_id: str | None = None,
) -> str:
    """List captured HTTP requests from the proxy with mitmproxy filtering.

    ``mitm_filter`` accepts mitmproxy filter expressions. The most useful
    operators are:

    - ``~m <regex>`` — request method (``~m POST``).
    - ``~u <regex>`` — full URL (``~u /api/``, ``~u \\.example\\.com``).
    - ``~d <regex>`` — domain/host (``~d api\\.example\\.com``).
    - ``~q`` — request has no response yet; ``~s`` — has a response.
    - ``~c <code>`` — response status code (``~c 500``, ``~c 40.``).
    - ``~h <regex>`` — header line (req or resp); ``~hq`` request-only,
      ``~hs`` response-only (``~hs Set-Cookie``).
    - ``~b <regex>`` — body (req or resp); ``~bq`` / ``~bs`` to scope it.
    - ``~t <regex>`` — Content-Type.
    - Combine with ``&`` (and), ``|`` (or), ``!`` (not), and parentheses:
      ``~m POST & ~c 40.`` , ``~u /admin & !~c 200`` ,
      ``(~d a.com | ~d b.com) & ~bs password`` .

    Values are regular expressions and do not require quoting. mitmproxy
    supports ``!`` as its negation operator.

    Pagination is cursor-based: pass ``page_info.end_cursor`` from one
    response as ``after`` to the next.

    Args:
        mitm_filter: mitmproxy filter expression (optional).
        first: Number of entries to return (default 50).
        after: Cursor from a previous ``page_info.end_cursor``.
        sort_by: ``timestamp`` / ``host`` / ``method`` / ``path`` /
            ``status_code`` / ``response_time`` / ``response_size`` /
            ``source``.
        sort_order: ``asc`` or ``desc``.
        scope_id: Restrict to a soft scope (managed via ``scope_rules``).
    """
    base_url = _ctx_base_url(ctx)
    if base_url is None:
        return _no_client()
    try:
        result = await mitm_control.list_flows(
            mitm_filter=mitm_filter,
            first=first,
            after=after,
            sort_by=sort_by,
            sort_order=sort_order,
            scope_id=scope_id,
            base_url=base_url,
        )
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception as exc:  # noqa: BLE001
        return _err("list_requests", exc)


@function_tool(timeout=60)
async def view_request(
    ctx: RunContextWrapper,
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> str:
    """View a captured request or its response, optionally regex-searched.

    Two modes:

    - **With** ``search_pattern`` (compact regex hits) — returns up to 20
      matches with ``before`` / ``after`` context and position. Useful
      for hunting reflected input, leaked URLs, hidden parameters.
    - **Without** ``search_pattern`` (full content with line pagination)
      — returns the page of raw content plus ``has_more`` flag.

    Common search patterns:

    - API endpoints: ``/api/[a-zA-Z0-9._/-]+``
    - URLs: ``https?://[^\\s<>"']+``
    - Query parameters: ``[?&][a-zA-Z0-9_]+=([^&\\s<>"']+)``
    - Specific input reflection: search for the value you submitted.

    Args:
        request_id: Flow ID from ``list_requests``.
        part: ``"request"`` or ``"response"``.
        search_pattern: Optional regex; switches the response shape to
            compact hits.
        page: 1-indexed page number (only when no ``search_pattern``).
        page_size: Lines per page.
    """
    base_url = _ctx_base_url(ctx)
    if base_url is None:
        return _no_client()

    try:
        flow = await mitm_control.view_flow(request_id, part=part, base_url=base_url)
        if not flow or flow.get("success") is False:
            return json.dumps(
                {"success": False, "error": f"Request {request_id} not found"},
                ensure_ascii=False,
                default=str,
            )

        if part == "request":
            content = _raw_request_text(flow)
        else:
            content = _raw_response_text(flow)  # type: ignore[assignment]
            if content is None:
                return json.dumps(
                    {"success": False, "error": f"No {part} for {request_id}"},
                    ensure_ascii=False,
                    default=str,
                )

        if search_pattern:
            return json.dumps(
                _format_search_hits(content, search_pattern),
                ensure_ascii=False,
                default=str,
            )

        return json.dumps(
            _format_text_page(content, page=page, page_size=page_size),
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:  # noqa: BLE001
        return _err("view_request", exc)


def _format_search_hits(content: str, pattern: str) -> dict[str, Any]:
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return {"success": False, "error": f"Invalid regex: {exc}"}

    hits = []
    for match in regex.finditer(content):
        start, end = match.span()
        before = content[max(0, start - 40) : start]
        after = content[end : end + 40]
        hits.append(
            {
                "match": match.group(0),
                "position": start,
                "before": before,
                "after": after,
            },
        )
        if len(hits) >= 20:
            break

    return {"success": True, "hits": hits, "total_hits": len(hits)}


def _format_text_page(content: str, *, page: int, page_size: int) -> dict[str, Any]:
    lines = content.splitlines()
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    return {
        "success": True,
        "content": "\n".join(lines[start:end]),
        "page": page,
        "page_size": page_size,
        "total_lines": len(lines),
        "has_more": end < len(lines),
    }


@function_tool(timeout=120, strict_mode=False)
async def repeat_request(
    ctx: RunContextWrapper,
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> str:
    """Repeat a captured request, optionally patching individual fields.

    The standard pentesting workflow with this tool:

    1. ``agent-browser`` (via ``exec_command``) or live target traffic
       → request gets captured by the proxy.
    2. ``list_requests`` → find the request ID you want to manipulate.
    3. ``repeat_request`` → send a modified version (auth-bypass test,
       payload injection, parameter tampering).

    Inherits everything from the original request (headers, cookies,
    auth, method, URL) and overlays only the fields you specify in
    ``modifications``.

    Args:
        request_id: ID of the original request (from ``list_requests``).
        modifications: Patch dict. Recognized keys:

            - ``url`` — replace the URL.
            - ``params`` — dict of query-string keys to add/update.
            - ``headers`` — dict of headers to add/update.
            - ``body`` — replace the body string entirely.
            - ``cookies`` — dict of cookies to add/update.
    """
    base_url = _ctx_base_url(ctx)
    if base_url is None:
        return _no_client()

    try:
        replay = await mitm_control.replay_flow(
            request_id,
            modifications=modifications or {},
            base_url=base_url,
        )
        return _format_replay_tool_result(replay)
    except Exception as exc:  # noqa: BLE001
        return _err("repeat_request", exc)


def _format_replay_tool_result(replay: dict[str, Any]) -> str:
    flow = replay.get("flow") or {}
    resp = flow.get("response") or {}
    body_bytes = _decode_b64(resp.get("content_b64"))
    body = body_bytes.decode("utf-8", errors="replace")
    body_truncated = False
    max_chars = 8192
    if len(body) > max_chars:
        body = body[:max_chars]
        body_truncated = True
    response_payload: dict[str, Any] | None = None
    if flow.get("response"):
        response_payload = {
            "status_code": resp.get("status_code"),
            "reason": resp.get("reason"),
            "headers": resp.get("headers"),
            "body": body,
            "body_truncated": body_truncated,
        }
    payload: dict[str, Any] = {
        "success": bool(replay.get("success")),
        "elapsed_ms": resp.get("roundtrip_ms"),
        "response": response_payload,
    }
    if replay.get("error"):
        payload["error"] = replay["error"]
    return json.dumps(payload, ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def list_sitemap(
    ctx: RunContextWrapper,
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: SitemapDepth = "DIRECT",
    page: int = 1,
) -> str:
    """Browse the hierarchical sitemap of proxied traffic.

    The proxy aggregates every captured request into a tree:
    ``DOMAIN`` → ``DIRECTORY`` (path segments) → ``REQUEST``.
    Use this to understand the discovered attack surface, locate
    promising directories, and pick endpoints worth deeper testing.

    Workflow:
    - Start with no ``parent_id`` to list root domains (scoped by
      ``scope_id`` if you only care about in-scope hosts).
    - Pick an entry where ``has_descendants=true`` and pass its ``id``
      as ``parent_id`` to drill in. ``depth="DIRECT"`` returns only
      immediate children; ``"ALL"`` flattens the full subtree.
    - Hand any ``id`` to ``view_sitemap_entry`` for the full record
      and recent matching requests.

    Args:
        scope_id: Limit roots to a soft scope (only used when
            ``parent_id`` is omitted). Manage scopes via ``scope_rules``.
        parent_id: Entry ID to expand; omit for root domains.
        depth: ``"DIRECT"`` (immediate children) or ``"ALL"``
            (recursive subtree). Only meaningful with ``parent_id``.
        page: 1-indexed page (30 entries per page).
    """
    base_url = _ctx_base_url(ctx)
    if base_url is None:
        return _no_client()
    try:
        result = await mitm_control.list_sitemap(
            scope_id=scope_id,
            parent_id=parent_id,
            depth=depth,
            page=page,
            base_url=base_url,
        )
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception as exc:  # noqa: BLE001
        return _err("list_sitemap", exc)


@function_tool(timeout=60)
async def view_sitemap_entry(
    ctx: RunContextWrapper,
    entry_id: str,
) -> str:
    """Get full detail for a sitemap entry plus its recent requests.

    Returns the entry's metadata, the primary request shape
    (method/path/response if any), and the most recent related
    requests that fall under this entry. Pair with ``list_sitemap`` to
    pick the ``entry_id``.

    Args:
        entry_id: ID from ``list_sitemap`` (or any nested entry).
    """
    base_url = _ctx_base_url(ctx)
    if base_url is None:
        return _no_client()
    try:
        result = await mitm_control.view_sitemap_entry(entry_id, base_url=base_url)
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception as exc:  # noqa: BLE001
        return _err("view_sitemap_entry", exc)


@function_tool(timeout=60)
async def scope_rules(
    ctx: RunContextWrapper,
    action: ScopeAction,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> str:
    """CRUD on soft scope rules (allow/deny patterns).

    Scopes tag and filter which traffic the proxy tools surface. Use
    them to focus on a target, exclude noisy assets (CDNs, static
    files), or define a bug-bounty allowlist.

    Pattern semantics:

    - Glob wildcards: ``*`` (any), ``?`` (single), ``[abc]`` (one of),
      ``[a-z]`` (range), ``[^abc]`` (none of).
    - **Empty allowlist = allow all domains.**
    - **Denylist always overrides allowlist.**

    Common denylist for noisy static assets:
    ``["*.gif", "*.jpg", "*.png", "*.css", "*.js", "*.ico", "*.svg",
    "*woff*", "*.ttf"]``.

    Each scope has a unique id usable as ``scope_id`` in
    ``list_requests`` and ``list_sitemap``.

    Args:
        action:

            - ``list`` — return all scopes.
            - ``get`` — single scope by ``scope_id``.
            - ``create`` — needs ``scope_name``, optionally
              ``allowlist`` / ``denylist``.
            - ``update`` — needs ``scope_id`` + ``scope_name``;
              allowlist / denylist replace the previous values.
            - ``delete`` — needs ``scope_id``.

        allowlist: Domain patterns to include (e.g.
            ``["*.example.com", "api.test.com"]``).
        denylist: Patterns to exclude.
        scope_id: Required for ``get`` / ``update`` / ``delete``.
        scope_name: Required for ``create`` / ``update``.
    """
    base_url = _ctx_base_url(ctx)
    if base_url is None:
        return _no_client()

    try:
        result = await mitm_control.scope_rules(
            action,
            allowlist=allowlist,
            denylist=denylist,
            scope_id=scope_id,
            scope_name=scope_name,
            base_url=base_url,
        )
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception as exc:  # noqa: BLE001
        return _err("scope_rules", exc)
