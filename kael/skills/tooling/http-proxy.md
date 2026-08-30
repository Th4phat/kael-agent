---
name: http-proxy
description: Intercepting-proxy workflow playbook — capture, inspect, filter, and replay HTTP traffic with list_requests, view_request, repeat_request, list_sitemap, view_sitemap_entry, and scope_rules (mitmproxy filtering, attack-surface mapping, request tampering).
---

# Proxy Workflow Playbook

An intercepting HTTP/HTTPS proxy runs as an in-container sidecar. Every
process you launch via `exec_command` (curl, the agent-browser, ffuf,
sqlmap, your own scripts) routes through it automatically — `http_proxy`
/ `https_proxy` are pre-set and the proxy CA is already trusted, so HTTPS
is decrypted and captured without extra setup. You do not start or
configure the proxy; you read and manipulate what it captures.

You have six proxy tools. Treat them as your manual-testing surface:
browse/trigger traffic, find the request, inspect it, modify and replay,
observe the difference.

- `list_requests` — search captured traffic (mitmproxy filter + pagination)
- `view_request` — read one request or its response (full or regex-search)
- `repeat_request` — resend a captured request with field overrides
- `list_sitemap` — browse the host→directory→endpoint tree
- `view_sitemap_entry` — full detail for one sitemap node
- `scope_rules` — allow/deny patterns to focus or de-noise capture

## Core Loop

The canonical pentest cycle with these tools:

1. **Generate traffic** — drive the target so the proxy captures it.
   Use `exec_command` with curl, or the agent-browser to click through
   the app, or any scanner. Anything that makes requests gets captured.
2. **Find it** — `list_requests` with a mitmproxy filter to locate the
   exact request by host/path/method/status.
3. **Inspect it** — `view_request` to read the raw request and response,
   or regex-search for reflected input, tokens, hidden params.
4. **Tamper + replay** — `repeat_request` with `modifications` to test
   auth bypass, IDOR, parameter tampering, injection.
5. **Compare** — diff the replayed response against the baseline. Status
   change, length change, leaked data, error reflection — that is your
   signal.

This mirrors the manual "browse → capture → modify → test" flow. Prefer
it over blind one-off curls: capturing first means you inherit the real
headers, cookies, and auth the app actually sent.

## list_requests — mitmproxy Filtering

`list_requests(mitm_filter=None, first=50, after=None, sort_by="timestamp", sort_order="desc", scope_id=None)`

The `mitm_filter` parameter accepts mitmproxy filter expressions. The most
useful operators are:

**Basic matchers:**
- `~m <regex>` — request method (`~m POST`, `~m "GET|HEAD"`)
- `~u <regex>` — full URL (`~u /api/`, `~u \.example\.com`)
- `~d <regex>` — domain/host only (`~d api\.example\.com`)
- `~q` — request has no response yet; `~s` — has a response
- `~c <code>` — response status code (`~c 500`, `~c 40.` for 40x)

**Header and body matchers:**
- `~h <regex>` — any header line (req or resp)
- `~hq <regex>` — request headers only (`~hq Authorization`)
- `~hs <regex>` — response headers only (`~hs Set-Cookie`)
- `~b <regex>` — any body (req or resp)
- `~bq <regex>` — request body only
- `~bs <regex>` — response body only (`~bs password`)
- `~t <regex>` — Content-Type header (`~t json`)

**Combinators:**
- `&` — AND (both must match)
- `|` — OR (either matches)
- `!` — NOT (negation)
- `(...)` — grouping for precedence

**Syntax rules:**
- **`!` is the not operator.** Use it freely:
  `~u /admin & !~c 200` (admin paths that didn't return 200).
- **No quoting required for values** — the value is interpreted as a
  regex, so special chars must be escaped: `~d api\.example\.com` not
  `~d api.example.com` (which would match `api-example-com`).
- **No field.operator:value syntax** — it's always `~operator value`.

Common filters:

- Failed POSTs (logic/validation probes):
  `~m POST & ~c 40.`
- One host's API surface:
  `~d api\.example\.com & ~u /v1/`
- Anything that set a cookie:
  `~hs Set-Cookie`
- JSON endpoints only:
  `~u /api/ & !~m OPTIONS`
- Sensitive-data sweep across response bodies:
  `~bs "authorization|token|secret|BEGIN RSA"`
- Server errors worth investigating:
  `~c 5..`
- Exclude static noise:
  `!~u "\.(css|js|png|jpg|gif|svg|woff|ttf|ico)"`
- Complex logic (admin paths that require auth but returned 200 without it):
  `~u /admin & ~c 200 & !~hq Authorization`
- Requests with responses vs pending:
  `~s` (has response) or `~q` (no response yet)

**Pagination is cursor-based.** Pass `page_info.end_cursor` from one
response as `after` to the next. Do not assume offset paging.

## view_request — Inspect and Search

`view_request(request_id, part="request", search_pattern=None, page=1, page_size=50)`

Two modes:

- **No `search_pattern`** → paginated raw content. Read the full request
  or response line by line; `has_more` tells you to bump `page`.
- **With `search_pattern`** → up to 20 regex hits with `before`/`after`
  context and byte position. Use this to hunt for needles without
  paging through everything.

`part` is `"request"` or `"response"`. Inspect the response (`part="response"`)
to confirm reflected input, leaked data, or stack traces.

High-value search patterns:

- API endpoints: `/api/[a-zA-Z0-9._/-]+`
- Absolute URLs (SSRF/redirect candidates): `https?://[^\s<>"']+`
- Query params: `[?&][a-zA-Z0-9_]+=([^&\s<>"']+)`
- JWTs: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- Reflected input: search the **exact value you submitted** in the
  response to confirm reflection before calling it XSS/injection.

## repeat_request — Tamper and Replay

`repeat_request(request_id, modifications=None)`

Resends a captured request, inheriting everything (method, URL, headers,
cookies, auth, body) and overlaying only what you put in `modifications`.
Recognized keys:

- `url` — replace the full URL
- `params` — dict of query keys to add/update
- `headers` — dict of headers to add/update
- `body` — replace the body string entirely
- `cookies` — dict of cookies to add/update

The result includes the replayed response and `elapsed_ms`. Always
compare against the original captured response.

Attack patterns:

- **IDOR / BOLA** — capture a request for *your* object, then replay
  changing the id: `modifications={"url": ".../api/orders/1002"}` or
  `{"params": {"user_id": "1002"}}`. A 200 with another user's data is
  the finding.
- **Auth bypass** — replay a privileged request with the auth header
  removed or swapped: `{"headers": {"Authorization": ""}}` or a
  low-priv token. Still 200? Broken access control.
- **Method tampering** — re-send a `GET`-protected action as `POST`, or
  try `PUT`/`DELETE`/`PATCH` on a REST resource via the captured raw.
- **Parameter tampering / mass assignment** — add fields the UI never
  sends: `{"body": "{\"role\":\"admin\",\"price\":0}"}`.
- **Injection probes** — overlay payloads into a single param:
  `{"params": {"q": "' OR '1'='1"}}`, then read the response for
  errors/reflection. For systematic injection, hand the captured request
  off to sqlmap/ffuf instead of hand-replaying.
- **Header-based access control** — toggle `X-Forwarded-For`,
  `X-Original-URL`, `X-Forwarded-Host` to probe trust-boundary bugs.

Replay one variable at a time so the response delta is attributable.

## list_sitemap / view_sitemap_entry — Map the Attack Surface

`list_sitemap(scope_id=None, parent_id=None, depth="DIRECT", page=1)`
`view_sitemap_entry(entry_id)`

The sitemap aggregates captured traffic into a tree:
`DOMAIN` → `DIRECTORY` (path segments) → `REQUEST` → request body/query
variants. Use it to understand discovered surface and pick promising
endpoints.

Workflow:

- Start with **no `parent_id`** to list root domains (pass `scope_id` to
  restrict to in-scope hosts).
- Pick an entry where `has_descendants` is true and pass its `id` as
  `parent_id` to drill in. `depth="DIRECT"` returns immediate children;
  `depth="ALL"` flattens the whole subtree.
- Hand any node `id` to `view_sitemap_entry` for full detail plus the
  recent matching requests under it.

Use the sitemap to spot interesting directories (`/admin`, `/api`,
`/internal`, `/.git`), then switch to `list_requests` with a path filter
to pull the concrete requests for testing.

## scope_rules — Focus and De-Noise

`scope_rules(action, allowlist=None, denylist=None, scope_id=None, scope_name=None)`

Scopes filter which traffic the proxy tools surface. Set one early to
keep capture focused on the target and out of unrelated hosts.

- `action`: `list` | `get` | `create` | `update` | `delete`
  - `create` needs `scope_name` (+ optional `allowlist`/`denylist`)
  - `update` needs `scope_id` + `scope_name` (lists replace prior values)
  - `get` / `delete` need `scope_id`
- Pattern semantics (glob): `*` any, `?` single char, `[abc]` one-of,
  `[a-z]` range, `[^abc]` none-of.
- **Empty allowlist = allow all domains.**
- **Denylist always overrides allowlist.**

Each created scope returns an `id` you can pass as `scope_id` to
`list_requests` and `list_sitemap`.

Recommended de-noise denylist (static assets that bury real traffic):
`["*.gif", "*.jpg", "*.png", "*.css", "*.js", "*.ico", "*.svg", "*woff*", "*.ttf"]`

Typical target allowlist for a bug-bounty engagement:
`["*.target.com", "target.com"]`

## Driving Traffic Into the Proxy

The proxy only shows what it captured, so capture first:

- One-off request: `exec_command` →
  `curl -s https://target/api/users/1` (proxy + CA are pre-configured;
  no `-x` flag needed).
- Full app walkthrough: use the agent-browser to log in and click
  through flows — authenticated traffic (cookies, tokens) gets captured
  with valid session state, which is what makes replay tampering work.
- Scanners (ffuf, sqlmap, nuclei) also route through the proxy, so their
  traffic lands in `list_requests` too.

If a scanner needs a raw request file, `view_request(part="request")`
gives you the raw bytes to save and pass to `sqlmap -r` / `ffuf`.

## Failure Recovery and Gotchas

- **Filter parse error** — almost always a regex escaping issue. Remember
  that dots `.` match any character in regex; escape them for literals:
  `~d api\.example\.com` not `~d api.example.com`. Use parentheses for
  grouping: `(~d a.com | ~d b.com) & ~c 200`.
- **Empty `list_requests`** — traffic may be out of scope (check
  `scope_rules action="list"`), or you have not generated it yet, or
  your filter is too tight. Run with no filter first to confirm capture
  is happening, then narrow.
- **Replay returns a 50x HTML error page from the proxy itself** — this
  is a proxy-level error, not the app's response. Usually a wrong
  host/port or a TLS issue in your `modifications`. Re-check the `url`
  you overrode; do not report it as a target vulnerability.
- **`roundtrip_ms` missing on an entry** — it is only surfaced when the
  proxy actually measured it; absence is not an error.
- **Don't loop** — if two replay variations behave identically, step
  back and change the variable that actually matters (auth, identifier,
  method) rather than re-sending near-duplicates.

## When to Script Instead

For repetitive replay (sweeping 500 object ids for IDOR, fuzzing a
param), don't hand-call `repeat_request` in a loop. Either:

- Pull the raw request with `view_request` and feed it to a purpose-built
  tool (`ffuf -request`, `sqlmap -r`), or
- Write a short script in `exec_command` that loops with the proxy env
  already set, so every iteration is still captured and inspectable.

Reserve the proxy tools for targeted inspection and confirmation; reserve
scanners for breadth.
