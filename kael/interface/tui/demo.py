"""``kael demo``: the real TUI fed by a scripted scan stream.

No Docker, no LLM. A background thread plays reasoning, streamed markdown,
tool calls, a child agent and findings through the same ``post_message``
path the scan thread uses, so the interface can be tried end to end.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import threading
import time
from types import SimpleNamespace
from typing import Any

from kael.interface.tui.app import GraphChanged, KaelTUIApp, ScanFinished, SdkEvent


ROOT, RECON = "a1root", "b2recon"

REPORT = """\
## Reconnaissance summary

I enumerated the target and found **3 open services**. The web tier runs \
`nginx/1.24` in front of a Flask app.

### Findings so far

1. The `/api/v1/users/{id}` endpoint returns other users' records (IDOR).
2. `X-Frame-Options` is missing on every response.
3. Session cookies lack the `Secure` flag.

```python
import requests
for uid in range(1, 5):
    r = requests.get(f"https://target/api/v1/users/{uid}", cookies=SESSION)
    print(uid, r.status_code, r.json()["email"])
```

> Next: confirm the IDOR against a second account and check the admin panel.

| Port | Service | Version |
|------|---------|---------|
| 22   | ssh     | OpenSSH 9.6 |
| 80   | http    | nginx 1.24 |
| 443  | https   | nginx 1.24 |
"""

RECON_TEXT = "Crawling the sitemap and fingerprinting every endpoint. " * 8


def _delta(text: str, kind: str = "response.output_text.delta") -> Any:
    return SimpleNamespace(type="raw_response_event", data=SimpleNamespace(type=kind, delta=text))


def _run_item(**fields: Any) -> Any:
    return SimpleNamespace(type="run_item_stream_event", item=SimpleNamespace(**fields))


def _final(text: str) -> Any:
    return _run_item(type="message_output_item", raw_item={"content": [{"text": text}]})


def _tool_call(call_id: str, tool: str, **args: Any) -> Any:
    raw = {"call_id": call_id, "name": tool, "arguments": json.dumps(args)}
    return _run_item(type="tool_call_item", raw_item=raw)


def _tool_output(call_id: str, output: str) -> Any:
    return _run_item(type="tool_call_output_item", raw_item={"call_id": call_id}, output=output)


def _chunks(text: str, n: int = 2) -> list[str]:
    parts = text.split(" ")
    return [
        " ".join(parts[i : i + n]) + (" " if i + n < len(parts) else "")
        for i in range(0, len(parts), n)
    ]


class DemoApp(KaelTUIApp):
    """KaelTUIApp with the scan thread replaced by a scripted producer."""

    def __init__(self, args: argparse.Namespace, tokens_per_sec: float) -> None:
        super().__init__(args)
        self._tokens_per_sec = tokens_per_sec

    def _start_scan_thread(self) -> None:
        threading.Thread(target=self._producer, daemon=True).start()

    def _stream(self, agent: str, text: str, kind: str = "response.output_text.delta") -> None:
        for chunk in _chunks(text):
            self._post_threadsafe(SdkEvent(agent, _delta(chunk, kind)))
            time.sleep(2 / self._tokens_per_sec)

    def _graph(self, root_status: str, recon_status: str | None = None) -> None:
        statuses = {ROOT: root_status}
        parent_of: dict[str, str | None] = {ROOT: None}
        names = {ROOT: "kael"}
        if recon_status is not None:
            statuses[RECON] = recon_status
            parent_of[RECON] = ROOT
            names[RECON] = "recon"
        self._post_threadsafe(GraphChanged(parent_of, statuses, names))

    def _recon_agent(self) -> None:
        self._stream(RECON, RECON_TEXT)
        self._post_threadsafe(SdkEvent(RECON, _final(RECON_TEXT)))
        self._graph("running", "completed")

    def _producer(self) -> None:
        post = self._post_threadsafe
        time.sleep(0.5)
        self._graph("running")
        time.sleep(0.5)

        thinking = (
            "The user wants a web assessment. I should start with service discovery, "
            "then look at the API for access-control issues. "
        ) * 2
        self._stream(ROOT, thinking, "response.reasoning_summary_text.delta")
        post(SdkEvent(ROOT, _run_item(type="reasoning_item")))
        answer = (
            "Starting reconnaissance against the target. "
            "I'll map open ports first, then crawl the web tier."
        )
        self._stream(ROOT, answer)
        post(SdkEvent(ROOT, _final(answer)))

        commands = [
            "nmap -sV -p- 10.0.0.5",
            "curl -sI https://target/",
            "ffuf -u https://target/FUZZ -w common.txt",
        ]
        for i, cmd in enumerate(commands):
            call_id = f"c{i}"
            post(SdkEvent(ROOT, _tool_call(call_id, "exec_command", cmd=cmd, workdir="/workspace")))
            time.sleep(1.5)
            out = "\n".join(f"{80 + j}/tcp open  http   nginx 1.24.0" for j in range(6 + i * 12))
            post(
                SdkEvent(ROOT, _tool_output(call_id, f"Process exited with code 0\nOutput:\n{out}"))
            )
            time.sleep(0.4)

        # A child agent that streams in parallel with the root.
        self._graph("running", "running")
        post(
            SdkEvent(
                ROOT, _tool_call("spawn", "create_agent", name="recon", task="crawl the web tier")
            )
        )
        post(
            SdkEvent(ROOT, _tool_output("spawn", json.dumps({"success": True, "agent_id": RECON})))
        )
        child = threading.Thread(target=self._recon_agent, daemon=True)
        child.start()

        post(
            SdkEvent(
                ROOT,
                _tool_call("think1", "think", thought="The API is the most promising surface."),
            )
        )
        post(SdkEvent(ROOT, _tool_output("think1", "ok")))
        self._stream(ROOT, REPORT)
        post(SdkEvent(ROOT, _final(REPORT)))

        self.report_state.add_vulnerability_report(
            title="IDOR in /api/v1/users/{id}",
            severity="high",
            agent_id=ROOT,
            cvss=7.5,
            description="Any authenticated user can read other users' records by changing the id.",
            poc_script_code=(
                "import requests\n"
                "print(requests.get('https://target/api/v1/users/2', cookies=SESSION).text)"
            ),
            remediation_steps="Authorize object access against the session user on every request.",
        )
        time.sleep(1)
        self.report_state.add_vulnerability_report(
            title="Missing X-Frame-Options header",
            severity="low",
            agent_id=RECON,
            description="Responses can be framed by third-party origins.",
        )
        child.join()
        post(
            SdkEvent(
                ROOT,
                _tool_call(
                    "fin",
                    "finish_scan",
                    executive_summary="One high and one low severity finding.",
                    methodology="Recon, API testing.",
                    technical_analysis="IDOR confirmed with two accounts.",
                    recommendations="Fix authorization first.",
                ),
            )
        )
        post(SdkEvent(ROOT, _tool_output("fin", json.dumps({"success": True}))))
        self._graph("completed", "completed")
        post(ScanFinished(None))


def run_demo(rest: list[str]) -> int:
    """``kael demo [TOKENS_PER_SEC]`` — runs until the user quits."""
    if rest and rest[0] in {"-h", "--help"}:
        print("Usage: kael demo [TOKENS_PER_SEC]   (default 40)")
        return 0
    try:
        tokens_per_sec = float(rest[0]) if rest else 40.0
    except ValueError:
        print(f"kael: error: invalid rate '{rest[0]}' (expected a number)")
        return 2

    args = argparse.Namespace(
        run_name="demo",
        targets_info=[
            {"type": "web_application", "details": {}, "original": "https://target.example"}
        ],
        instruction="",
        diff_scope={"active": False},
        scan_mode="deep",
        non_interactive=False,
        local_sources=[],
        scope_mode="auto",
        diff_base=None,
        user_explicit_instruction=None,
    )
    # Run dirs are created relative to the cwd; keep the demo out of kael_runs/.
    previous_cwd = os.getcwd()
    os.chdir(tempfile.mkdtemp(prefix="kael-demo-"))
    try:
        DemoApp(args, tokens_per_sec).run()
    finally:
        os.chdir(previous_cwd)
    return 0
