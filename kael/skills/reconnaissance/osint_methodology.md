---
name: osint-methodology
description: Passive reconnaissance, search engine dorking, social media enumeration, email harvesting, metadata extraction
---

# OSINT Methodology

Open-Source Intelligence (OSINT) is the foundation of every pentest. Modern recon is dominated by commercial intelligence surfaces, certificate transparency, leaked credential corpora, and supply-chain metadata. Prefer passive techniques first — every active probe is a signal in the target's logs.

## Engagement Selection

For every recon task, ask:

1. **Black-box vs. white-box** — white-box gets you source, container images, and CI artifacts; black-box only sees what the target exposes externally.
2. **Authorized scope** — every tool/lookup/connection must map to an explicitly authorized target. Never probe assets outside scope (use `web_search`/`exploit_search` to validate when uncertain).
3. **Stealth requirements** — passive OSINT first; active scanning only when authorized and necessary.

## Passive Recon (no direct contact with target)

### Search engine dorking

| Engine | Operators worth knowing |
|---|---|
| Google | `site:`, `inurl:`, `intitle:`, `intext:`, `filetype:`, `cache:`, `-` (exclude), `OR`, `"..."` (exact), `*` (wildcard) |
| Bing | `site:`, `ip:`, `contains:`, `inbody:`, `language:`, `location:` |
| DuckDuckGo | `site:`, `filetype:`; less aggressive bot detection |
| Yandex | strong for Russian/European targets; `host:`, `mime:` |

Useful patterns:
- `site:target.com filetype:pdf` — internal docs, manuals, whitepapers
- `site:target.com inurl:admin|login|portal` — auth surface
- `site:target.com (inurl:api | inurl:v1 | inurl:graphql)` — API endpoints
- `site:github.com "target.com" "password" OR "api_key"` — accidental commits
- `site:pastebin.com "target.com"` — paste leaks
- `site:trello.com OR site:notion.so OR site:atlassian.net "target.com"` — workspace exposure
- `inurl:"/server-status" | inurl:"/server-info"` — Apache status pages

### Certificate transparency

- **crt.sh** — `https://crt.sh/?q=%25.target.com` — every cert ever issued
- **Censys** (search.censys.io) — full cert DB + service banners
- **Facebook CT monitor** (developers.facebook.com/tools/ct) — real-time CT monitoring
- Parse subject CN + SAN to enumerate subdomains. Look for `*` (wildcard) and internal hostnames leaked in CN.

### DNS / subdomain enumeration (passive)

- **Amass** (`amass enum -passive -d target.com`) — combines many sources
- **subfinder** (`subfinder -d target.com -silent`) — fast, multiple sources
- **assetfinder**, **sublist3r** — additional sources
- **waybackurls** (from `httpx` author) — historical URLs from Wayback Machine
- **github-subdomains** — scrape GitHub code search for `*.target.com`

### Email / credential harvesting (defensive checks only)

When authorized, check whether corporate emails have appeared in:
- **HaveIBeenPwned** (api.haveibeenpwned.com) — domain-wide check
- **Dehashed** — historical breach DB
- **IntelligenceX** — paste/leak search
- **LeakCheck / GhostProject** — credential leak search

For pentest reports, treat any leaked credential as a critical finding requiring immediate rotation. Do not exfiltrate or use leaked credentials for further actions without explicit authorization.

### Metadata extraction

- **ExifTool** — `exiftool -r -all documents/` for PDF/Office metadata (authors, software, internal paths, printers, GPS for images)
- **FOCA** (Windows) — automated doc metadata from URLs
- Look for internal usernames → feed into username enumeration / password spraying

### Social media / people recon

- **LinkedIn** — employee names → username formats
- **GitHub** — repos, gists, commit history, leaked secrets
- **Twitter/X** — operational tweets (status, "we're hiring"), infrastructure leaks
- **Glassdoor, job boards** — tech stack hints, internal tooling, org structure
- **Shodan/Censys** — exposed services, banners, default credentials

### Shodan / Censys queries

Useful filters:
- `org:"Target Inc"` — all known assets
- `ssl.cert.subject.CN:"*.target.com"` — cert-based discovery
- `"X-Powered-By: Express"` — tech fingerprinting at scale
- `product:"Kubernetes" version:"1.27"` — version-specific searches
- `http.title:"Jenkins" http.status:200` — exposed Jenkins instances
- `vuln:CVE-2024-XXXX` — internet-wide CVE exposure

## Active Recon (when authorized)

### Port scanning

- **naabu** (`naabu -host target.com -p -`) — fast SYN scan
- **nmap** — full feature scan; `nmap -sV -sC -O -A -p- target.com`
- **rustscan** — fast initial scan, then nmap service detection
- **masscan** — internet-scale scanning, very fast

### Service enumeration

- **httpx** (`httpx -l hosts.txt -title -tech-detect -status-code`) — probe HTTP services, get tech stack
- **nuclei** (`nuclei -l hosts.txt -t technologies/`) — template-based tech/version detection
- **whatweb** (`whatweb -a3 target.com`) — Ruby-based tech fingerprint
- **wappalyzer** CLI (`wappalyzer target.com`) — alternative tech detection
- **curl + manual** — when scripts misbehave

### Web crawling

- **katana** (`katana -u target.com -d 3 -jc -jsl`) — modern crawler with JS rendering
- **gospider** (`gospider -s target.com -d 3 --js`) — Go-based, JS-aware
- **hakrawler** — lightweight
- **mitmproxy** — captured and scripted HTTP testing
- **waybackurls** — historical URLs from Wayback

## Output / Documentation

Produce a recon dossier with:

1. **Asset inventory** — domains, subdomains, IPs, ASNs, services
2. **Tech stack map** — frontend, backend, infra, third-party SaaS
3. **User accounts / usernames** — format patterns from harvested accounts
4. **Leaked credentials** — with severity context (which service, which account)
5. **Attack surface** — endpoints, parameters, auth mechanisms, file uploads, etc.
6. **Interesting findings** — exposed admin panels, default creds, version-specific CVEs
7. **Stealth observations** — WAF/IDS signals, rate limits, IP reputation

## Stealth / OPSEC

- Run active scans from a throwaway VPS or VPN with rotating IPs
- Throttle: `-rate 10` to nuclei, `--delay 1s` to nmap
- Use passive sources first to avoid detection
- Don't poke prod services outside scope even if Shodan shows them
- Randomize user-agents (`-random-agent` in many tools)
- Respect `robots.txt` when crawling (it's not security, but its violation is logged)

## Tooling Stack (Kali-preinstalled)

| Tool | Use case |
|---|---|
| `amass` | Subdomain enum, ASN mapping |
| `subfinder` | Fast passive subdomain enum |
| `httpx` | HTTP probing, tech detection |
| `naabu` | Fast port scan |
| `nmap` | Full port/service scan |
| `nuclei` | Template-based vuln + tech detection |
| `katana` | Web crawling |
| `waybackurls` | Historical URLs |
| `curl` | Manual probing |
| `dnsx` | DNS resolution + brute |
| `gitleaks` | Git secret scanning (whitebox) |
| `trufflehog` | Deeper secret scanning (whitebox) |
| `whatweb` | Tech fingerprinting |

## Recon Workflow Example

```
# 1. Passive subdomain enum
subfinder -d target.com -silent -o subs.txt
amass enum -passive -d target.com -o subs_amass.txt
cat subs*.txt | sort -u > all_subs.txt

# 2. Probe live hosts
httpx -l all_subs.txt -title -tech-detect -status-code -o live.txt

# 3. Crawl for endpoints
katana -list live.txt -d 3 -jc -o endpoints.txt

# 4. Tech detection
nuclei -l live.txt -t technologies/ -o tech.txt

# 5. Port scan interesting hosts
naabu -host live.txt -p 1-65535 -o ports.txt

# 6. Service detection
nmap -sV -sC -iL live_hosts.txt -oA nmap_full
```

## Common Pitfalls

- Skipping CT logs — these are gold for subdomain discovery
- Not running the same queries from multiple sources (different DBs, different vantage points)
- Treating Shodan output as a complete asset list (it's only what scanners see)
- Forgetting historical data (wayback, GitHub history, deleted tweets)
- Missing supply-chain: vendor SaaS, code dependencies, container registries
- Not correlating username patterns across platforms (samaccountname, email prefix, internal Slack handles)
- Probing out-of-scope assets flagged by CT or Shodan
