---
name: python
description: Run Python through exec_command in the SDK sandbox; use the image-baked mitm_control module when scripts need captured proxy traffic or replay.
---

# Python In The Sandbox

Use `exec_command` for Python. There is no separate Kael Python executor.

Prefer writing reusable scripts to `/workspace/scratch/<name>.py` and running
them with `python3 /workspace/scratch/<name>.py`. For a short transformation,
`python3 -c` or a small here-document is fine.

The `shell` parameter on `exec_command` selects a POSIX shell
(`bash`/`zsh`/`sh`); it does not select an interpreter. Put `python3` in the
command itself.

## Proxy Automation From Python

Prefer Kael's first-class proxy tools for ordinary capture, inspection, and
replay. For batch logic inside a sandbox script, import the image-baked
`mitm_control` module. Its helpers are async and return dictionaries:

```python
import asyncio

from mitm_control import list_flows, view_flow


async def main():
    result = await list_flows(mitm_filter="~m POST & ~u /api/", first=50)
    candidates = []
    for entry in result["entries"]:
        flow_id = entry["id"]
        flow = await view_flow(flow_id, part="request")
        body = flow["request"].get("content_b64", "")
        if body:
            candidates.append(flow_id)

    print(f"{len(candidates)} POST requests with bodies")
    print(candidates[:10])


asyncio.run(main())
```

Available helpers:

- `list_flows(mitm_filter=, first=50, after=, sort_by=, sort_order=, scope_id=)`
- `view_flow(flow_id, part="request")`
- `replay_flow(flow_id, modifications={...})`
- `list_sitemap(scope_id=, parent_id=, depth="DIRECT", page=1)`
- `view_sitemap_entry(entry_id)`
- `scope_rules(action, allowlist=, denylist=, scope_id=, scope_name=)`

The sandbox sets `HTTP_PROXY` and `HTTPS_PROXY`, so requests from `curl`,
Python HTTP clients, and most security tools are captured automatically.

## Workflow

1. Create or edit `/workspace/scratch/exploit.py` with `apply_patch`.
2. Run it with `exec_command`: `python3 /workspace/scratch/exploit.py`.
3. Edit and rerun until the proof of concept is reliable.

## Installing Extra Packages

The sandbox's Python lives in `/app/.venv`. Install a one-off dependency with:

```bash
uv pip install --python /app/.venv/bin/python <package>
```
