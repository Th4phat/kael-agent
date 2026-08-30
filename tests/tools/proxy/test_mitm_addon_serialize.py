"""Regression tests for the addon's flow-serialization helpers.

These guard the bugs that surfaced when the addon finally started and
captured real traffic in PR 1:

1. ``f.request.query`` is a ``MultiDictView``, not JSON-serializable.
   The control endpoints must emit it as a list of ``[key, value]``
   pairs (preserving duplicate query keys).
2. ``HTTPFlow`` has no ``timestamp_end`` attribute — end timestamps
   live on ``flow.response`` / ``flow.request``. Roundtrip math that
   reads ``flow.timestamp_end`` raises ``AttributeError`` at runtime.
3. Header serialization must use ``items(multi=True)`` (current mitmproxy
   releases have no ``true_all`` kwarg) and must round-trip duplicate headers.
4. Flow filtering must use mitmproxy's public ``flowfilter`` API; current
   ``HTTPFlow`` objects no longer expose ``matches``.

The helpers are exercised here directly with ``mitmproxy.test.tflow``
so we don't need to stand up a full ``DumpMaster``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mitmproxy.test import tflow, tutils

from kael.tools.proxy import mitm_addon


def _make_flow() -> object:
    req = tutils.treq(
        method=b"GET",
        host="example.com",
        port=443,
        path=b"/search?q=hello&q=world&lang=en",
    )
    resp = tutils.tresp(status_code=200, content=b"ok")
    f = tflow.tflow(req=req, resp=resp)
    # Duplicate request + response headers to prove multi=True round-trips.
    f.request.headers.add("X-Dup", "a")
    f.request.headers.add("X-Dup", "b")
    f.response.headers.add("Set-Cookie", "one=1")
    f.response.headers.add("Set-Cookie", "two=2")
    return f


def test_serialize_flow_is_json_serializable() -> None:
    f = _make_flow()
    record = mitm_addon._serialize_flow(f, scope_id="scope-1")
    # The whole record must survive a JSON round-trip.
    blob = json.dumps(record)
    back = json.loads(blob)
    assert back["id"] == f.id
    assert back["tags"] == ["scope:scope-1"]
    assert back["request"]["method"] == "GET"
    assert ["X-Dup", "a"] in back["request"]["headers"]
    assert ["X-Dup", "b"] in back["request"]["headers"]
    assert ["Set-Cookie", "one=1"] in back["response"]["headers"]
    assert ["Set-Cookie", "two=2"] in back["response"]["headers"]


def test_serialize_flow_roundtrip_ms_uses_response_timestamp() -> None:
    f = _make_flow()
    f.request.timestamp_start = 1000.0
    f.response.timestamp_end = 1002.5
    record = mitm_addon._serialize_flow(f, scope_id=None)
    # 2.5s -> 2500ms; this would raise AttributeError if the code read
    # flow.timestamp_end instead of response.timestamp_end.
    assert record["response"]["roundtrip_ms"] == 2500


def test_serialize_flow_no_response() -> None:
    req = tutils.treq(method=b"GET", host="example.com", port=443, path=b"/")
    f = tflow.tflow(req=req, resp=False)
    record = mitm_addon._serialize_flow(f, scope_id=None)
    assert "response" not in record
    # Still JSON-serializable.
    json.dumps(record)


def test_filter_flows_uses_current_mitmproxy_api() -> None:
    matching = _make_flow()
    other = _make_flow()
    other.request.path = "/different"

    result = mitm_addon._filter_flows(
        [matching, other],
        "~u /search",
    )

    assert result == [matching]


def test_filter_flows_rejects_invalid_expression() -> None:
    with pytest.raises(ValueError):
        mitm_addon._filter_flows([_make_flow()], "~definitely-not-a-filter")


def test_install_ca_cert_skips_quietly_when_not_writable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The addon runs as the unprivileged ``pentester`` user and cannot
    write to the root-only ``/usr/local/share/ca-certificates`` dir. A
    ``PermissionError`` there must never escape (it previously logged a
    traceback). The privileged install is done by the entrypoint.
    """
    # Point the addon's CA source dir at a temp dir holding a fake CA.
    fake_conf = tmp_path / "conf"
    fake_conf.mkdir()
    (fake_conf / "mitmproxy-ca-cert.pem").write_bytes(b"-----FAKE CA-----")
    monkeypatch.setattr(mitm_addon, "DEFAULT_CA_DIR", fake_conf)

    # Force the writability check to report "not writable" regardless of
    # the real environment (CI may run as root).
    monkeypatch.setattr(mitm_addon.os, "access", lambda *_a, **_k: False)

    addon = mitm_addon.KaelAddon()
    # Must not raise, must not attempt the copy.
    addon._install_ca_cert()
