---
name: dns-enumeration
description: Zone transfers, DNS brute-force, certificate transparency, cache snooping, wildcard detection
---

# DNS Enumeration

DNS recon reveals the full attack surface before any port scan. Modern DNS is the canonical source for subdomain discovery, mail infrastructure, and split-horizon exposure. Always start with passive sources (CT logs, public resolvers) before active brute-forcing.

## Resolution Basics

- **Authoritative vs. recursive** — only the authoritative server has the truth. Recursive resolvers (8.8.8.8, 1.1.1.1) cache answers.
- **Forward (`A`/`AAAA`/`CNAME`) vs. reverse (`PTR`)** — both directions matter. Missing reverse DNS often signals a dynamic/cloud asset.
- **EDNS0 + DNSSEC** — modern resolvers use these; respect them with `dig +dnssec`.

## Record Types Worth Knowing

| Type | Purpose | Pentest use |
|---|---|---|
| `A`/`AAAA` | IPv4/IPv6 addresses | Asset discovery |
| `CNAME` | Alias (often to CDN/SaaS) | Detect vendor usage (e.g. `heroku`, `azurewebsites`) |
| `NS` | Authoritative nameservers | Identify DNS provider (route53, cloudflare, etc.) |
| `MX` | Mail servers | Mail security, SPF/DKIM/DMARC testing |
| `TXT` | Arbitrary text records | SPF, DKIM, DMARC, domain verification, MS=ms... (Microsoft), google-site-verification |
| `SOA` | Start of authority | Admin email, serial numbers, refresh intervals |
| `HINFO` / `LOC` | Rare | Historical data leaks |
| `SRV` | Service records (`_sip._tcp`, `_xmpp-client._tcp`) | VoIP, XMPP, Matrix, federation services |
| `CAA` | Certification Authority Authorization | Allowed CAs; reveals cert strategy |
| `TLSA` (DANE) | TLS pinning via DNS | Often absent — opportunity for downgrade |

## Subdomain Enumeration (Passive)

### Certificate Transparency

- `curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u`
- `crt.sh` returns every cert ever issued for the zone. Look for:
  - `*` (wildcard) — apex wildcard
  - Internal hostnames leaked in CN (`jumphost-01.corp.local`, `dc01.internal.target.com`)
  - Test/staging subdomains (`uat.`, `dev.`, `qa.`, `stg.`)
  - Email addresses in `subject:emailAddress` (older certs)
- **Censys** + **Facebook CT** + **Google CT** log search supplement `crt.sh`

### Public DNS datasets

- **Amass** — aggregates many sources (CT, HackerTarget, ThreatCrowd, VirusTotal, etc.)
- **subfinder** — 30+ passive sources
- **Rapid7's Project Sonar** — `https://opendata.rapid7.com/sonar.fdns_v2/` (massive historical dataset, ~3TB)
- **SecurityTrails**, **DNSlytics**, **PassiveTotal** — paid but extensive

### Search engines (Google dorks for subdomains)

- `site:*.target.com -site:www.target.com`
- `site:target.com -inurl:www`
- Bing: `site:target.com` then filter by URL

## Subdomain Enumeration (Active)

### DNS brute-force

- **dnsx** (`dnsx -d target.com -w wordlist.txt`) — fast, modern, supports wildcard detection
- **massdns** — high-perf, requires custom resolver list
- **gobuster dns** (`gobuster dns -d target.com -w subdomains.txt`)
- **ffuf** with FUZZ + DNS modules
- **wfuzz** (`wfuzz -c -f sub-fuzz.txt -Z -w wordlist.txt -u "https://FUZZ.target.com" --hc 400,404`)

Good wordlists:
- `seclists/Discovery/DNS/subdomains-top1million-*.txt`
- `seclists/Discovery/DNS/dns-Jhaddix.txt` (best all-around)
- `assetnote/wordlists/data/manual/best-dns-wordlist.txt`
- Custom: combine top-N + permutations (`api-v2`, `auth-prod-eu`, etc.)

### Permutation scanning

When basic brute hits a ceiling, generate permutations:

- `altdns` (`altdns -i subs.txt -o data_altdns.txt -w permutations.txt`)
- `gotator` (Go-based, faster)
- `dnsgen` + `massdns` (Python-based, very effective)
- Permutations to add: `dev`, `stg`, `uat`, `prod`, `v1`/`v2`/`v3`, region codes (`-us`, `-eu`, `-ap`), `admin`, `internal`, `intranet`, `corp`, `webmail`, `mail2`, env prefixes (`test-`, `pre-`, `nonprod-`)

## Zone Transfers (AXFR)

Always check first — sometimes the entire zone is downloadable:

```bash
dig axfr @ns1.target.com target.com
dig axfr @ns2.target.com target.com
host -t axfr target.com ns1.target.com
```

If it works, you have every host in the zone in one query. Even on failure, the SOA / NS / serial number leak useful information.

`dnsrecon -d target.com -t axfr` — automated.

## DNS Cache Snooping

Check whether a recursive resolver has recently resolved a name for a client:

- `dig @resolver target.com +norecurse` — if answer is non-authoritative, resolver has cached it
- Useful for: detecting whether a target is using a specific resolver
- `lbd` (load balancing detector) — checks DNS-based and HTTP-based load balancing

## DNS Rebinding

For attacking internal services from outside (SSRF-adjacent):

- **rbndr** (rebind domain generator)
- **whonow** — DNS rebinding toolkit
- **singularity** — full rebinding attack framework
- Vector: a public hostname resolves first to attacker IP (passes ACL), then rebinds to `127.0.0.1` or `169.254.169.254` (cloud metadata)
- Combine with `exploit_search "DNS rebinding CVE"` for current toolchains

## Mail Security Records

Always check:

```bash
# SPF (TXT)
dig target.com TXT | grep spf
# DMARC
dig _dmarc.target.com TXT
# DKIM (try common selectors)
dig google._domainkey.target.com TXT
dig selector1._domainkey.target.com TXT
dig selector2._domainkey.target.com TXT
# MX
dig target.com MX
# MTA-STS
dig _mta-sts.target.com TXT
# TLSRPT
dig _smtp._tls.target.com TXT
# BIMI
dig default._bimi.target.com TXT
```

Common findings:
- Missing DMARC → spoofing possible
- SPF `+all` or `?all` → no enforcement
- DKIM `p=` empty → verification disabled
- `v=spf1 include:_spf.google.com ~all` → only Google senders; 3rd-party mailers may fail alignment
- DMARC `p=none` → monitor only; upgrade to `p=quarantine` or `p=reject` after warmup

## DNSSEC

```bash
dig target.com +dnssec +multi
delv @1.1.1.1 target.com +rtrace
```

- Validates chain of trust
- Missing DNSSEC = no integrity protection
- Walk the chain: `dig +trace` to see delegation, NSEC/NSEC3 records can enumerate names (zone walking)

## Tooling (Kali-preinstalled)

| Tool | Use |
|---|---|
| `dig` / `drill` | Manual lookups |
| `host` | Quick lookups |
| `nslookup` | Quick lookups (Windows-friendly) |
| `dnsx` | Modern DNS brute + resolve |
| `dnsenum` | All-in-one enum |
| `dnsrecon` | Recon with many checks |
| `massdns` | High-perf bulk resolve |
| `amass` | Subdomain enum (active+passive) |
| `subfinder` | Fast passive enum |
| `fierce` | Brute force + zone transfer |
| `dnsmap` | Brute force |
| `dnsgen` / `altdns` / `gotator` | Permutation generation |
| `ldns-walk` | Zone walking via NSEC |
| `crt.sh` (web) | CT log search |

## Output / Documentation

For each target domain, produce:

1. **Full list of subdomains** with last-seen date, source (CT/passive/brute), and resolution status
2. **IP → hostname mapping** — note any 4-tuple sharing (multiple subdomains → same IP = likely shared infrastructure)
3. **Mail flow diagram** — MX, SPF, DKIM, DMARC; identify all senders (esp. 3rd-party SaaS that can be phished)
4. **Nameserver analysis** — provider (Cloudflare, Route53, etc.), DNSSEC status
5. **Takeovers** — CNAMEs pointing to unclaimed external services (see S3/heroku/Azure sub-takeover skills)
6. **Takeover vectors** — dangling DNS records pointing to deprovisioned resources
7. **Stealth** — what records reveal internal structure (e.g. corp.int.target.com, dc01.target.local)

## Subdomain Takeover Detection

After enumerating, scan CNAMEs for takeover-prone services:

- AWS S3: `*.s3.amazonaws.com` — bucket not registered
- CloudFront: `*.cloudfront.net` — distribution deleted
- Heroku: `*.herokuapp.com` — app removed
- GitHub Pages: `*.github.io` — repo not found
- Azure: `*.azurewebsites.net`, `*.cloudapp.net`, `*.azure-api.net`
- Pantheon: `*.pantheonsite.io`
- Tumblr: `*.tumblr.com`
- Shopify: `*.myshopify.com`
- Fastly: `*.fastly.net`
- Pantheon, Fly, Render, Vercel, Netlify

`subjack -w subs.txt -t 100 -timeout 30 -ssl -v` or `nuclei -l subs.txt -t takeovers/`

## Common Pitfalls

- Forgetting IPv6 (AAAA) — many targets are IPv6-only or have different content
- Skipping CT — most subdomain discovery lives in CT logs
- Not respecting wildcard (`*`) — false positives flood the results; detect with `dig nonexistent.target.com` and treat any answer as wildcard
- Probing subdomains outside authorized scope (CT often returns 3rd-party domains in CN/SAN)
- Forgetting about `null` MX records and mail flow edge cases
- Not testing DNSSEC validation path (validates at resolver, not at the zone)
- Missing zone walking via NSEC3 (less common now, but still appears)
