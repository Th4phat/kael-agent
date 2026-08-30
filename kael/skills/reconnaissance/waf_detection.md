---
name: waf-detection
description: WAF fingerprinting, bypass strategies per vendor, evasion patterns, tools: wafw00f
---

# WAF Detection & Evasion

Web Application Firewalls inspect HTTP traffic and block malicious payloads. Modern WAFs (Cloudflare, Akamai, AWS WAF, F5, Azure Front Door) use ML and behavioral signals, not just regex. Knowing which WAF you're up against and what its rules look like determines which bypasses work.

## Detection Phase

### Active fingerprinting

- **wafw00f** (`wafw00f https://target.com`) — sends benign requests + WAF-specific probes; very reliable
- **nuclei** with `waf-detect` template (`nuclei -u target.com -t technologies/waf/`)
- **whatwaf** (Python, ~50+ WAFs, ML-based detection)
- **identYwaf** — Yara-based, handles obfuscated responses

### Passive fingerprinting (no probes)

Inspect response headers, cookies, and behavior:
- `Server:` header (e.g. `cloudflare`, `awselb`, `Varnish`)
- `Set-Cookie:` patterns (e.g. `__cfduid`, `AWSALB`, `incap_ses_*`, `_akamai*`)
- Response body fingerprints (Cloudflare's "Attention Required!" page, Akamai's reference ID format)
- HTTP/2 + HTTP/3 negotiation patterns
- Response timing (some WAFs add consistent delay)
- Behavior on benign but suspicious requests (e.g. add `?` or extra path)

### Custom WAFs

Many targets run a custom (often NGINX/HAProxy + ModSecurity/OpenResty) rule set. Clues:
- Generic block pages with `Request ID: 0a1b2c3d`
- 403 with empty body
- `Retry-After` header on block (rate limiting)
- Connection drop / reset
- Slow response time on suspicious input

## WAF-by-WAF Evasion

### Cloudflare

- **Cache abuse** — WAF only inspects cache misses; cache poisoning tricky but real
- **Origin IP discovery** — bypass entirely: cert transparency, censys, shodan, leaked rDNS, MX records, internal status pages
- **Rate limits** — distributed testing from many IPs (proxy rotation, cloud workers)
- **Bypass techniques**:
  - Chunked transfer encoding
  - HTTP/2 multiplexing tricks (rapid-fire on different streams)
  - Mixed-case + Unicode normalization
  - JSON over multipart/form-data
  - Long bodies (Cloudflare often has 100MB+ but inspects up to ~1MB)
  - Header pollution
  - Path traversal in normalization layer (e.g. `../`, URL-encoded variants, double-encoding)
- `exploit_search "Cloudflare WAF bypass 2025"` for current techniques

### Akamai

- **Strongest** commercial WAF — ML-based, very aggressive
- **Origin discovery** — Akamai's biggest weakness; many old configs leak origin
- Bypass patterns:
  - Slow drip attacks (1 req/sec) below rate threshold
  - IP rotation across geographies (Akamai's bot manager does device fingerprinting)
  - Bot manager bypass requires real browser fingerprints (use `undetected-chromedriver`, `playwright-extra`)
  - Body part-on-curl (inspect only certain content types)
  - WAF-BOOM (multipart with conflicting boundaries)
- Many bypasses surface on bug bounty writeups; use `web_search "Akamai WAF bypass"` to find current ones

### AWS WAF / Shield

- **IP-based** rate limits (Shield Standard)
- **WAF rules** — managed + custom
- Bypass:
  - Use CloudFront's behavior-switching (origin requests without WAF inspection)
  - Origin = ALB; WAF on CloudFront but not on ALB → bypass with direct ALB origin
  - IP allow-listing on origin (often includes internal AWS CIDR)
  - `X-Forwarded-For` manipulation if origin trusts it
- Shield Advanced requires business support; rate limits are negotiated

### F5 BIG-IP ASM / Advanced WAF

- Detected via: `Set-Cookie: BIGipServer*`, `Server: BigIP`, response to illegal method, etc.
- Bypass:
  - Header injection (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL — old F5 bypass)
  - HTTP/0.9 downgrade
  - HTTP parameter pollution (F5 sometimes picks last)
  - Slow POST with chunked encoding
  - Method override (`X-HTTP-Method-Override: PUT`)
  - Cookie poisoning (F5 ASM sometimes permits if the cookie name starts with allowed prefix)
  - Long URI truncation (F5 has length limits, sometimes different from origin)

### ModSecurity (OWASP CRS)

- **Open source** — most common in self-hosted setups
- Default CRS rules: SQLi, XSS, LFI, RCE patterns
- Bypass:
  - HPP (HTTP Parameter Pollution): `?id=1&id=1' OR 1=1--` — each parser sees different thing
  - Encoding: double URL, Unicode escapes, UTF-8 BOM
  - Comment injection: `/*!...*/` (MySQL), `/*!...*/` (Postgres)
  - Line breaks inside keywords: `UN%0aION SE%0bLECT`
  - Whitespace substitution: `%09`, `%0a`, `%0b`, `%0c`, `%0d`, `%a0`
  - Null bytes: `%00`
  - Polyglot payloads that look benign to one parser but malicious to another
  - `exploit_search "ModSecurity CRS bypass"` — bypasses are public

### Azure Front Door / WAF

- Similar to Cloudflare in detection
- Bypass:
  - Origin discovery (Azure IP ranges, NS lookup)
  - `X-Azure-*` headers
  - Bot manager requires JS challenges
  - Bot manager bypasses via real browser fingerprinting

### Imperva / Incapsula

- Detected via: `Set-Cookie: incap_ses_*, visid_incap_*`, `X-Iinfo` header
- Bypass:
  - Long delays between requests (Imperva is aggressive on rate)
  - IP rotation across regions
  - Cookie/session manipulation (Imperva issues `_Incapsula_Resource` cookie for legitimate users)

## Generic Evasion Techniques

### Encoding

- URL encoding (single + double)
- HTML entity encoding
- Unicode normalization (NFKC, NFKD)
- Base64 (when target decodes)
- Hex escape sequences
- Mixed case (where parser is case-sensitive)
- Overlong UTF-8 (theoretical — most parsers are fixed)

### HTTP-level tricks

- **HTTP method confusion** — `GET` with body, `POST` masquerading as `GET`
- **Content-Type switching** — multipart vs. JSON vs. URL-encoded
- **Chunked transfer** — split payload across chunks
- **Parameter pollution** — `?a=1&a=2` (which value does the app use?)
- **Header injection** — `X-Original-URL`, `X-Rewrite-URL`, `Content-Type: text/plain` overrides
- **Path tricks** — `../`, `..%2f`, `..%252f`, `..;/`, `..\`, semicolon path parameters
- **Case mismatch** — `GET /Api/Users` vs. `GET /api/users` (WAF may not check both)
- **HTTP version** — HTTP/0.9, HTTP/1.0, HTTP/2, HTTP/3 — each parser may differ

### Payload-level tricks

- **Comment-based** — `/*! ... */` (MySQL), `--[rand]`, `<!--[rand]-->`
- **Whitespace** — tab, newline, vertical tab, form feed, non-breaking space, zero-width space
- **String concat** — `CONCAT()`, `||` (Postgres), `+` (MSSQL)
- **Alternative keywords** — `INFORMATION_SCHEMA.PLUGIN` (MySQL), `sysobjects` (MSSQL), `pg_class` (Postgres)
- **Time/boolean gating** — wrap in `IF((SELECT 1)=1,SLEEP(5),0)` to delay signal
- **Out-of-band** — DNS, HTTP, SMB callbacks (use OAST like interactsh)

### Layered

- WAF + IDS + rate limiter + captcha — defeat each layer separately
- Some WAFs only inspect first N bytes; truncation attacks on POST body
- Some WAFs only inspect Content-Type they expect; switch Content-Type to bypass

## Detection During Testing

The WAF is watching you — and you should watch it back:

1. **Detection delay** — most WAFs don't block on first suspicious request; they learn
2. **Score accumulation** — score-based WAFs (Cloudflare, Akamai) trigger only above threshold
3. **Geo / IP reputation** — VPN/proxy traffic gets more scrutiny
4. **Header consistency** — mismatched User-Agent vs. Accept-Language vs. Accept-Encoding raise flags
5. **Timing** — attacks during business hours may be more aggressively blocked
6. **TLS fingerprinting** — JA3/JA4 fingerprint of your HTTP client can mark you as `curl/python` (often blocked)

## Tooling (Kali-preinstalled)

| Tool | Use |
|---|---|
| `wafw00f` | WAF detection |
| `identYwaf` | Yara-based WAF detection |
| `whatwaf` | ML-based detection + bypass suggestions |
| `nuclei` | WAF-specific templates + detection |
| `sqlmap --tamper=` | Tamper scripts for SQLi evasion |
| `burp suite` | Manual testing, intruder with custom payloads |
| `mitmproxy` | Proxied testing with replay/automation |
| `curl` + `python-requests` | Custom evasion |
| `interactsh` | Out-of-band detection |

## When NOT to Bypass

- WAF is part of the defense-in-depth and the customer wants it tested
- Bypass would cause production impact (rate-limit triggers, alert fatigue)
- The target is out of scope
- The finding is the WAF misconfiguration, not a payload bypass

Always document WAFs in your recon report and note any successful evasions as findings. WAF bypass alone is rarely a high-severity issue — but it amplifies every other vulnerability you find.

## Common Pitfalls

- Spending hours on bypasses when the origin IP is exposed (often simpler)
- Assuming a single bypass works for all WAF rules (per-rule, per-vendor)
- Triggering rate limits early and getting your IP banned globally
- Forgetting the WAF logs everything — your payload is captured
- Not testing the bypass against the WAF's analytics/learning layer
- Comparing WAF to origin directly (origin may have weaker validation = bigger issue)
- Not reporting WAF as a defense layer so the customer knows to add WAF where missing
