"""mitmproxy addon for kael.

Runs inside ``mitmdump`` (or any mitmproxy frontend). It:

- Tags every captured request with its matching soft-scope id
  (see :mod:`kael.tools.proxy.scope_store`).
- Persists flows to a JSONL log under ``/workspace/.mitm/flows.jsonl``
  so the host SDK can read them without going through mitmproxy's
  process boundary.
- Exposes a small HTTP control plane on a configurable address so the
  host SDK can list, fetch, and replay flows. The container entrypoint
  binds it to all container interfaces, while the runtime publishes it
  only on the host loopback interface.
- Writes the host's CA cert into the system trust store on first
  start so HTTPS-intercepted traffic validates.

This file is also importable from the host side (the addon runs in
mitmdump's Python, but the same file is shipped via
``COPY kael/tools/proxy/mitm_addon.py /opt/kael-python/``).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import socket
import subprocess
import threading
import time
from collections.abc import Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import mitmproxy.addonmanager
import mitmproxy.connection
import mitmproxy.exceptions
import mitmproxy.http
import mitmproxy.io
from mitmproxy import command, ctx, flow, flowfilter, http


try:
    from kael.tools.proxy.scope_store import ScopeStore
except ModuleNotFoundError:
    # Running as a flat script under mitmdump; scope_store.py is a
    # sibling file at /opt/kael-python/scope_store.py.
    from scope_store import ScopeStore  # type: ignore[no-redef, import-not-found]

try:
    from kael.tools.proxy import sitemap as sitemap_mod
except ModuleNotFoundError:
    # Flat-script context under mitmdump; sitemap.py is a sibling file.
    import sitemap as sitemap_mod  # type: ignore[no-redef, import-not-found]


# IMPORTANT: do NOT use @dataclass anywhere in this file.
# mitmproxy's script loader (mitmproxy/addons/script.py) does
# ``module_from_spec`` + ``loader.exec_module(m)`` but does NOT
# register the module in ``sys.modules``. The @dataclass decorator
# then crashes with ``AttributeError: 'NoneType' object has no
# attribute '__dict__'`` when it tries to look up the class's module
# namespace. A plain class with an explicit __init__ avoids the
# decorator and works in both the host (package) and in-container
# (flat-script) contexts.
class _PendingReplay:
    __slots__ = ("created_at", "flow_id", "future")

    def __init__(self, flow_id: str, future: asyncio.Future[Any], created_at: float) -> None:
        self.flow_id = flow_id
        self.future = future
        self.created_at = created_at


logger = logging.getLogger(__name__)


DEFAULT_FLOWS_PATH = Path("/workspace/.mitm/flows.jsonl")
DEFAULT_SCOPES_PATH = Path("/workspace/.mitm/scopes.json")
DEFAULT_CA_DIR = Path("/home/pentester/.mitmproxy")
DEFAULT_CONTROL_HOST = "127.0.0.1"
DEFAULT_CONTROL_PORT = 8081
RESPONSE_BODY_MAX_CHARS = 8192
REPLAY_TIMEOUT_SECONDS = 30.0


def _b64(data: bytes | None) -> str:
    if not data:
        return ""
    return base64.b64encode(data).decode("ascii")


def _serialize_flow(flow: http.HTTPFlow, *, scope_id: str | None) -> dict[str, Any]:
    req = flow.request
    resp = flow.response
    record: dict[str, Any] = {
        "id": flow.id,
        "timestamp": flow.timestamp_start or time.time(),
        "request": {
            "method": req.method,
            "scheme": req.scheme,
            "host": req.host,
            "port": req.port,
            "path": req.path,
            "headers": [[k, v] for k, v in req.headers.items(multi=True)],
            "content_b64": _b64(req.raw_content),
        },
    }
    if scope_id is not None:
        record["tags"] = [f"scope:{scope_id}"]
    if resp is not None:
        rt_ms = 0
        if resp.timestamp_end and req.timestamp_start:
            rt_ms = int((resp.timestamp_end - req.timestamp_start) * 1000)
        record["response"] = {
            "status_code": resp.status_code,
            "reason": resp.reason,
            "headers": [[k, v] for k, v in resp.headers.items(multi=True)],
            "content_b64": _b64(resp.raw_content),
            "roundtrip_ms": rt_ms,
        }
    return record


def _filter_flows(flows: list[http.HTTPFlow], expression: str) -> list[http.HTTPFlow]:
    """Return flows matching a mitmproxy filter expression.

    ``HTTPFlow.matches`` was removed from current mitmproxy releases. The
    public ``flowfilter`` API is stable and compiling once avoids reparsing
    the same expression for every captured flow.
    """
    compiled = flowfilter.parse(expression)
    return [captured_flow for captured_flow in flows if flowfilter.match(compiled, captured_flow)]


class KaelAddon:
    """The mitmproxy addon."""

    _instance: ClassVar[KaelAddon | None] = None

    def __init__(self) -> None:
        self.flows_path = Path(os.environ.get("KAEL_MITM_FLOWS_PATH", str(DEFAULT_FLOWS_PATH)))
        self.scopes_path = Path(os.environ.get("KAEL_MITM_SCOPES_PATH", str(DEFAULT_SCOPES_PATH)))
        self.control_host = os.environ.get("KAEL_MITM_CONTROL_HOST", DEFAULT_CONTROL_HOST)
        self.control_port = int(os.environ.get("KAEL_MITM_CONTROL_PORT", DEFAULT_CONTROL_PORT))
        self._flows: dict[str, http.HTTPFlow] = {}
        self._scope_tags: dict[str, str | None] = {}
        self._pending_replays: dict[str, _PendingReplay] = {}
        self._lock = threading.RLock()
        self._control_server: ThreadingHTTPServer | None = None
        self._control_thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        KaelAddon._instance = self

    @classmethod
    def get_instance(cls) -> KaelAddon | None:
        return cls._instance

    def load(self, loader: mitmproxy.addonmanager.Loader) -> None:
        loader.add_option(
            name="kael_flows_path",
            typespec=str,
            default=str(self.flows_path),
            help="Path to the JSONL flow log (per-flow JSON object per line).",
        )
        loader.add_option(
            name="kael_scopes_path",
            typespec=str,
            default=str(self.scopes_path),
            help="Path to the JSON scope store.",
        )
        loader.add_option(
            name="kael_control_host",
            typespec=str,
            default=self.control_host,
            help="Host for the addon control HTTP server.",
        )
        loader.add_option(
            name="kael_control_port",
            typespec=int,
            default=self.control_port,
            help="Port for the addon control HTTP server.",
        )

    def configure(self, updates: Any) -> None:
        for name in updates or ():
            value = getattr(ctx.options, name, None)
            if value is None:
                continue
            if name == "kael_flows_path":
                self.flows_path = Path(value)
            elif name == "kael_scopes_path":
                self.scopes_path = Path(value)
            elif name == "kael_control_host":
                self.control_host = str(value)
            elif name == "kael_control_port":
                self.control_port = int(value)

    def running(self) -> None:
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self.flows_path.parent.mkdir(parents=True, exist_ok=True)
        self.scopes_path.parent.mkdir(parents=True, exist_ok=True)
        self._install_ca_cert()
        self._start_control_server()

    def done(self) -> None:
        self._stop_control_server()
        KaelAddon._instance = None

    def request(self, flow: http.HTTPFlow) -> None:
        scope_store = ScopeStore(self.scopes_path)
        scope_id = scope_store.matching_scope_id(flow.request.host)
        with self._lock:
            self._flows[flow.id] = flow
            self._scope_tags[flow.id] = scope_id

    def response(self, flow: http.HTTPFlow) -> None:
        scope_id: str | None
        with self._lock:
            self._flows[flow.id] = flow
            scope_id = self._scope_tags.get(flow.id)
        record = _serialize_flow(flow, scope_id=scope_id)
        try:
            with self.flows_path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(record, separators=(",", ":")))
                fp.write("\n")
        except OSError:
            logger.warning("failed to persist flow %s", flow.id, exc_info=True)

        self._maybe_complete_replay(flow)

    def error(self, flow: flow.Flow) -> None:
        if isinstance(flow, http.HTTPFlow):
            self._maybe_complete_replay(flow)

    def _maybe_complete_replay(self, flow: http.HTTPFlow) -> None:
        with self._lock:
            pending = self._pending_replays.pop(flow.id, None)
        if pending is None:
            return
        if not pending.future.done():
            payload = _serialize_flow(flow, scope_id=None)
            if self._loop is not None:
                self._loop.call_soon_threadsafe(pending.future.set_result, payload)
            else:
                pending.future.get_loop().call_soon_threadsafe(pending.future.set_result, payload)

    @command.command("kael.replay")
    def replay_command(self, flows: Sequence[flow.Flow]) -> None:
        """Replay one or more flows (mirrors ``replay.client`` semantics)."""
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                ctx.master.commands.call("replay.client", [f])

    def _start_control_server(self) -> None:
        if self._control_server is not None:
            return
        addon = self
        captured: dict[str, Any] = {"flows": addon._flows, "pending": addon._pending_replays}

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                logger.debug("control: " + format, *args)

            def do_GET(self) -> None:
                if self.path == "/health":
                    self._json(HTTPStatus.OK, {"status": "ok"})
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

            def do_POST(self) -> None:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                raw = self.rfile.read(length) if length > 0 else b""
                try:
                    body = json.loads(raw or b"{}")
                except json.JSONDecodeError:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                    return
                try:
                    self._dispatch(self.path, body)
                except Exception as exc:
                    logger.exception("control dispatch failed")
                    self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

            def _dispatch(self, path: str, body: dict[str, Any]) -> None:
                if path == "/flows/search":
                    self._flows_search(body)
                elif path == "/sitemap":
                    self._sitemap(body)
                elif path == "/sitemap/entry":
                    self._sitemap_entry(body)
                elif path.startswith("/flows/") and path.endswith("/replay"):
                    flow_id = path[len("/flows/") : -len("/replay")]
                    self._flow_replay(flow_id, body)
                elif path.startswith("/flows/"):
                    flow_id = path[len("/flows/") :]
                    self._flow_get(flow_id, body)
                elif path == "/scopes":
                    self._scope_action(body)
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

            def _flows_search(self, body: dict[str, Any]) -> None:
                flows_map = captured["flows"]
                scope_tags_map = addon._scope_tags
                with addon._lock:
                    snapshot = list(flows_map.values())
                snapshot.sort(
                    key=lambda f: f.timestamp_start or 0.0,
                    reverse=body.get("sort_order", "desc") != "asc",
                )
                scope_id_filter = body.get("scope_id")
                first = int(body.get("first") or 50)
                if scope_id_filter:
                    snapshot = [f for f in snapshot if scope_tags_map.get(f.id) == scope_id_filter]
                mitm_filter = body.get("filter")
                if mitm_filter:
                    try:
                        snapshot = _filter_flows(snapshot, str(mitm_filter))
                    except ValueError as exc:
                        self._json(HTTPStatus.BAD_REQUEST, {"error": f"invalid filter: {exc}"})
                        return
                total = len(snapshot)
                snapshot = snapshot[: max(1, first)]
                entries = [
                    {
                        "id": f.id,
                        "request": {
                            "id": f.id,
                            "method": f.request.method,
                            "host": f.request.host,
                            "port": f.request.port,
                            "path": f.request.path,
                            "query": [[k, v] for k, v in f.request.query.items(multi=True)],
                            "scheme": f.request.scheme,
                        },
                        "response": (
                            {
                                "status_code": f.response.status_code,
                                "length": len(f.response.raw_content or b""),
                                "roundtrip_ms": (
                                    int(
                                        (
                                            (f.response.timestamp_end or 0.0)
                                            - (f.request.timestamp_start or 0.0)
                                        )
                                        * 1000
                                    )
                                    if f.response is not None
                                    and f.response.timestamp_end
                                    and f.request.timestamp_start
                                    else 0
                                ),
                            }
                            if f.response is not None
                            else None
                        ),
                    }
                    for f in snapshot
                ]
                self._json(
                    HTTPStatus.OK,
                    {
                        "success": True,
                        "entries": entries,
                        "page_info": {
                            "has_next_page": total > len(entries),
                            "end_cursor": entries[-1]["id"] if entries else None,
                        },
                        "total": total,
                    },
                )

            def _sitemap(self, body: dict[str, Any]) -> None:
                result = sitemap_mod.build_sitemap(
                    addon.flows_path,
                    scope_id=body.get("scope_id"),
                    parent_id=body.get("parent_id"),
                    depth=str(body.get("depth") or "DIRECT"),
                    page=int(body.get("page") or 1),
                )
                self._json(HTTPStatus.OK, result)

            def _sitemap_entry(self, body: dict[str, Any]) -> None:
                entry_id = body.get("entry_id")
                if not entry_id:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "entry_id required"})
                    return
                result = sitemap_mod.build_entry_view(addon.flows_path, str(entry_id))
                self._json(HTTPStatus.OK, result)

            def _flow_get(self, flow_id: str, body: dict[str, Any]) -> None:
                with addon._lock:
                    f = captured["flows"].get(flow_id)
                if f is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": f"flow {flow_id} not found"})
                    return
                self._json(HTTPStatus.OK, _serialize_flow(f, scope_id=None))

            def _flow_replay(self, flow_id: str, body: dict[str, Any]) -> None:
                with addon._lock:
                    f = captured["flows"].get(flow_id)
                if f is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": f"flow {flow_id} not found"})
                    return
                modifications = body.get("modifications") or {}
                replayed = self._build_replay_flow(f, modifications)
                new_flow = http.HTTPFlow(
                    client_conn=mitmproxy.connection.Client(
                        peername=("127.0.0.1", 0),
                        sockname=("127.0.0.1", 0),
                    ),
                    server_conn=mitmproxy.connection.Server(
                        address=(replayed["host"], replayed["port"])
                    ),
                )
                self._populate_request(new_flow, replayed)
                loop = asyncio.new_event_loop()
                future: asyncio.Future[Any] = loop.create_future()
                pending = _PendingReplay(flow_id=new_flow.id, future=future, created_at=time.time())
                with addon._lock:
                    captured["pending"][new_flow.id] = pending
                try:
                    ctx.master.commands.call("replay.client", [new_flow])
                except mitmproxy.exceptions.CommandError as exc:
                    self._json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {"error": f"replay dispatch failed: {exc}"},
                    )
                    return
                try:
                    result = loop.run_until_complete(
                        asyncio.wait_for(future, timeout=REPLAY_TIMEOUT_SECONDS)
                    )
                except TimeoutError:
                    self._json(
                        HTTPStatus.GATEWAY_TIMEOUT,
                        {
                            "error": (
                                f"replay did not complete within "
                                f"{REPLAY_TIMEOUT_SECONDS:.0f}s — target may be "
                                "unreachable from the sandbox"
                            )
                        },
                    )
                    return
                finally:
                    loop.close()
                self._json(HTTPStatus.OK, {"success": True, "flow": result})

            @staticmethod
            def _build_replay_flow(
                f: http.HTTPFlow, modifications: dict[str, Any]
            ) -> dict[str, Any]:
                req = f.request.copy()
                url = modifications.get("url")
                if url:
                    req.url = str(url)
                if "params" in modifications and isinstance(modifications["params"], dict):
                    for k, v in modifications["params"].items():
                        req.query[str(k)] = str(v)
                if "headers" in modifications and isinstance(modifications["headers"], dict):
                    for k, v in modifications["headers"].items():
                        req.headers[str(k)] = str(v)
                if "body" in modifications:
                    body = modifications["body"]
                    if isinstance(body, str):
                        req.text = body
                    elif isinstance(body, (bytes, bytearray)):
                        req.raw_content = bytes(body)
                    else:
                        # dict / list / number / bool: serialize as JSON
                        req.text = json.dumps(body)
                        req.headers["Content-Type"] = "application/json"
                if "cookies" in modifications and isinstance(modifications["cookies"], dict):
                    cookie_str = "; ".join(f"{k}={v}" for k, v in modifications["cookies"].items())
                    if req.headers.get("Cookie"):
                        existing = req.headers["Cookie"].split("; ")
                        merged = {
                            kv.split("=", 1)[0]: kv.split("=", 1)[1] for kv in existing if "=" in kv
                        }
                        merged.update(modifications["cookies"])
                        cookie_str = "; ".join(f"{k}={v}" for k, v in merged.items())
                    req.headers["Cookie"] = cookie_str
                return {
                    "url": req.url,
                    "host": req.host,
                    "port": req.port,
                    "method": req.method,
                    "headers": [[k, v] for k, v in req.headers.items(multi=True)],
                    "content": req.raw_content or b"",
                }

            @staticmethod
            def _populate_request(new_flow: http.HTTPFlow, payload: dict[str, Any]) -> None:
                new_flow.request.method = payload["method"]
                new_flow.request.scheme = "https" if payload["port"] == 443 else "http"
                new_flow.request.host = payload["host"]
                new_flow.request.port = payload["port"]
                new_flow.request.headers.clear()
                for k, v in payload["headers"]:
                    new_flow.request.headers[k] = v
                new_flow.request.raw_content = payload["content"]

            def _scope_action(self, body: dict[str, Any]) -> None:
                action = body.get("action")
                store = ScopeStore(addon.scopes_path)
                if action == "list":
                    self._json(
                        HTTPStatus.OK,
                        {
                            "success": True,
                            "scopes": [s.to_dict() for s in store.list()],
                        },
                    )
                elif action == "get":
                    scope_id = body.get("scope_id")
                    if not scope_id:
                        self._json(HTTPStatus.BAD_REQUEST, {"error": "scope_id required"})
                        return
                    scope = store.get(scope_id)
                    if scope is None:
                        self._json(
                            HTTPStatus.NOT_FOUND,
                            {"error": f"scope {scope_id} not found"},
                        )
                        return
                    self._json(HTTPStatus.OK, {"success": True, "scope": scope.to_dict()})
                elif action == "create":
                    name = body.get("scope_name")
                    if not name:
                        self._json(HTTPStatus.BAD_REQUEST, {"error": "scope_name required"})
                        return
                    scope = store.create(
                        name=name,
                        allowlist=body.get("allowlist") or [],
                        denylist=body.get("denylist") or [],
                    )
                    self._json(HTTPStatus.OK, {"success": True, "scope": scope.to_dict()})
                elif action == "update":
                    scope_id = body.get("scope_id")
                    name = body.get("scope_name")
                    if not scope_id or not name:
                        self._json(
                            HTTPStatus.BAD_REQUEST,
                            {"error": "scope_id and scope_name required"},
                        )
                        return
                    scope = store.update(
                        scope_id,
                        name=name,
                        allowlist=body.get("allowlist"),
                        denylist=body.get("denylist"),
                    )
                    self._json(HTTPStatus.OK, {"success": True, "scope": scope.to_dict()})
                elif action == "delete":
                    scope_id = body.get("scope_id")
                    if not scope_id:
                        self._json(HTTPStatus.BAD_REQUEST, {"error": "scope_id required"})
                        return
                    store.delete(scope_id)
                    self._json(HTTPStatus.OK, {"success": True, "deleted": scope_id})
                else:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": f"unknown action: {action!r}"})

            def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
                body_bytes = json.dumps(payload, default=str).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)

        try:
            server = ThreadingHTTPServer((self.control_host, self.control_port), _Handler)
        except OSError as exc:
            logger.warning(
                "control server failed to bind %s:%s: %s", self.control_host, self.control_port, exc
            )
            return
        thread = threading.Thread(
            target=server.serve_forever, name="kael-mitm-control", daemon=True
        )
        thread.start()
        self._control_server = server
        self._control_thread = thread
        logger.info(
            "kael mitmaddon control server listening on %s:%s", self.control_host, self.control_port
        )

    def _stop_control_server(self) -> None:
        if self._control_server is not None:
            self._control_server.shutdown()
            self._control_server.server_close()
            self._control_server = None
        self._control_thread = None

    def _install_ca_cert(self) -> None:
        # The system trust store under /usr/local/share/ca-certificates/
        # is root-only, but the addon runs as the unprivileged
        # ``pentester`` user. Installing the CA into the system store is
        # therefore done by the container entrypoint (which runs as root,
        # after mitmproxy has generated its CA into confdir). Here we only
        # attempt the copy if the target is actually writable, and we skip
        # quietly otherwise — a failed copy must never take the addon down.
        ca_dir = DEFAULT_CA_DIR
        ca_cert = ca_dir / "mitmproxy-ca-cert.pem"
        if not ca_cert.exists():
            ca_cert = ca_dir / "mitmproxy-ca-cert.crt"
        if not ca_cert.exists():
            return
        target_dir = Path("/usr/local/share/ca-certificates")
        if not os.access(target_dir, os.W_OK):
            logger.debug(
                "CA trust store %s not writable by this user; "
                "leaving system-store install to the entrypoint",
                target_dir,
            )
            return
        try:
            target = target_dir / "mitmproxy-ca.crt"
            target.write_bytes(ca_cert.read_bytes())
            subprocess.run(  # noqa: S603
                ["update-ca-certificates"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            logger.warning("failed to install mitmproxy CA cert", exc_info=True)


addons: list[Any] = [KaelAddon()]


def health_check(
    host: str = "127.0.0.1", port: int = DEFAULT_CONTROL_PORT, timeout: float = 2.0
) -> bool:
    """Synchronous helper: ``True`` when the addon's control server is up.

    Used by the host-side bootstrap and by entrypoint readiness checks.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
