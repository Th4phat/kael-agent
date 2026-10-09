---
name: wsrx
description: WebSocketReflectorX (wsrx) — tunnel a raw TCP challenge that is only reachable over a WebSocket (ws:// / wss://) gateway down to a local 127.0.0.1:PORT you can hit with nc, pwntools remote(), sqlmap, or any TCP tool
---

# wsrx (WebSocketReflectorX) Playbook

Official repo: https://github.com/XDSEC/WebSocketReflectorX

Many CTF platforms don't expose the challenge's raw TCP port directly — they put
it behind a **WebSocket gateway** so it survives HTTP-only ingress (Cloudflare,
k8s ingress, ctfd + wsrx, XDSEC/D³CTF-style instancers). You get a `ws://` or
`wss://` URL (or an http link whose page connects to one) instead of a
`host:port`. `wsrx` bridges that WebSocket back into a normal TCP socket on
localhost, so every TCP tool you already use works unchanged.

`wsrx` is preinstalled at `/usr/local/bin/wsrx` (x86_64 sandbox).

## When to use

- The challenge address is `ws://…` or `wss://…`.
- The challenge page says "connect via wsrx / WebSocketReflectorX" or ships a web
  terminal instead of a `nc host port` line.
- `nc`/pwntools to the given host:port is refused/times out, but there is a
  WebSocket endpoint in the page (check the challenge HTML / DevTools Network tab
  for the `ws(s)://` URL).

## Core workflow (pin the port — do this)

```bash
# Bridge the WebSocket to a fixed local TCP port, in the background.
wsrx connect --host 127.0.0.1 --port 13337 "wss://chall.example.com/instance/abc" &

# Now the challenge is a normal TCP service at 127.0.0.1:13337 — use anything:
nc 127.0.0.1 13337
```

pwntools:
```python
from pwn import *
io = remote("127.0.0.1", 13337)   # instead of remote("chall.example.com", 1337)
io.sendline(b"payload")
print(io.recvall(timeout=5))
```

**Pin the port with `--host 127.0.0.1 --port <PORT>`.** Without it, wsrx picks a
random port and only tells you via the log line:

```
Hi, I am not RX, RX is here -> 127.0.0.1:37967
                                         ^^^^^ the local TCP port to connect to
```

Grab that programmatically if you didn't pin it:
```bash
wsrx connect --log-json true "$WS_URL" 2>wsrx.log &
sleep 1
PORT=$(grep -oE 'RX is here -> 127.0.0.1:[0-9]+' wsrx.log | grep -oE '[0-9]+$')
echo "challenge at 127.0.0.1:$PORT"
```

## How it behaves (matters for exploits)

- **Lazy upstream dial.** The local listener opens immediately; wsrx only opens
  the upstream WebSocket when a TCP client connects to the local port. Each new
  local connection = one fresh challenge connection. So pwntools reconnects,
  brute-force loops, and `nc` after `nc` all work against the same tunnel — no
  restart needed. Keep the `wsrx connect` process alive for the whole exploit.
- **One tunnel, many connections.** You don't need a new `wsrx connect` per
  attempt; the single backgrounded process multiplexes.
- **Direct egress, bypasses mitmproxy.** wsrx ignores `HTTP(S)_PROXY`/`ALL_PROXY`
  and validates `wss://` TLS against its own roots, so it connects straight out —
  correct for a raw pwn socket (no HTTP proxy mangling your bytes). Consequence:
  this traffic will **not** show up in the mitmproxy flow log; that's expected.
- **Local side is plain TCP on 127.0.0.1** (in `NO_PROXY`), so nc/pwntools/sqlmap
  to `127.0.0.1:PORT` are clean.

## URL tips

- Accepts `ws://host[:port]/path` and `wss://host[:port]/path`. Keep the full
  path — instancer URLs usually carry an id in the path/query.
- Given only an `http(s)://` link? Open it (curl / agent-browser) and pull the
  real `ws(s)://` endpoint from the page or its WebSocket connection, then feed
  that to `wsrx connect`.
- `wss://` (TLS) vs `ws://` (plain) must match what the gateway serves.

## Other subcommands (rarely needed)

- `wsrx serve --port <P>` — the challenge-host side; exposes local TCP over WS.
  You'd only use this to *host* a service, not to solve a challenge.
- `wsrx daemon` — long-running local HTTP admin API for managing many tunnels
  (what the GUI drives). For solving, plain `wsrx connect` is simpler.

## Failure recovery

- **`nc` connects but gets nothing / instant EOF** → wrong scheme (`ws` vs `wss`)
  or wrong path. Re-check the endpoint; watch `wsrx connect` logs for a
  `CREATE remote` line on connect (that confirms the upstream dial fired).
- **No `CREATE remote` on connect** → wsrx couldn't reach the gateway. Verify the
  URL with `curl -I` on its http(s) form; the instance may have expired (spin a
  new one on the platform).
- **Connection drops mid-exploit** → the platform instance timed out; request a
  fresh URL and restart `wsrx connect`. Add reconnect logic in pwntools.
- **Need to debug** → `RUST_LOG=wsrx=debug wsrx connect --log-json true "$WS_URL"`.
- **Port already in use** → pick another `--port`.
