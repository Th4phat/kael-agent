---
name: technology-fingerprinting
description: HTTP header analysis, cookie patterns, JS library detection, CMS identification
---

# Technology Fingerprinting

Knowing the exact stack — web server, framework, language, version, third-party libs — is the difference between spraying payloads blind and targeting known-vulnerable components. Use fingerprinting to drive vulnerability selection, version-specific CVEs, and exploit search.

## Why Fingerprint First

- **Version-specific CVEs** — many CVEs are scoped to a version range
- **Default credentials** — install defaults vary by stack
- **Default paths/files** — `/.env`, `/wp-admin/`, `/actuator/env`, `/server-status`
- **Tech-specific vulns** — Struts OGNL injection, Django ORM, Spring SpEL, etc.
- **Payload syntax** — different parsers accept different SQL/XSS/path-traversal syntax
- **Stack-aware payloads** — bypass WAF rules that target generic patterns

## Passive Fingerprinting (no direct contact with target)

- **Shodan** (`https://www.shodan.io`) — full banners, SSL certs, default creds
- **Censys** (`https://search.censys.io`) — similar, academic origins
- **Netlas** — newer, more features
- **FOFA** — Chinese alternative, very thorough
- **BinaryEdge** — covers things other scanners miss
- **Onyphe** — focus on attack surface
- **FullHunt** — exposure monitoring

## Active Fingerprinting

### Web Server

**Headers + behavior:**

- `Server:` — usually `Apache/2.4.57 (Ubuntu)`, `nginx/1.25.1`, `Microsoft-IIS/10.0`, `cloudflare`
- `X-Powered-By:` — `PHP/8.2.10`, `ASP.NET`, `Express`
- `Via:` — proxies in the chain
- `X-AspNet-Version: 4.0.30319` — old .NET leaks
- `X-AspNetMvc-Version: 5.2`
- 404 page style — Apache default vs. nginx vs. custom
- `ETag:` format — Apache uses inode-size-mtime, nginx uses mtime-size, IIS uses FileTimestamp+ChangeNumber
- HTTP/1.1 vs. HTTP/2 vs. HTTP/3 support
- Method handling — `OPTIONS *` returns supported methods

**Tools:**

- `httpx -tech-detect` — single-shot tech + version
- `whatweb -a3` — comprehensive, multiple plugins
- `wappalyzer` CLI — modern
- `nmap -sV` — banner grabbing for many services
- `curl -I` + manual review
- `webanalyze` (Go, fast)

### Programming Language

| Signal | Language |
|---|---|
| `PHPSESSID`, `Set-Cookie: PHPSESSID=...` | PHP |
| `JSESSIONID` | Java |
| `ASP.NET_SessionId`, `__RequestVerificationToken` | .NET |
| `connect.sid` (Express), `csrf_token` | Node.js |
| `_csrf`, `_session` (Rails) | Ruby on Rails |
| `csrftoken`, `sessionid` (Django) | Python/Django |
| `laravel_session` | Laravel/PHP |
| `JSESSIONID`, `.do` URLs | Java/Spring |
| `wp-settings-*` | WordPress |
| Specific error pages: `Powered by Flask`, `Gunicorn` | Python |
| `Server: gunicorn/x.x.x` | Python/Gunicorn |
| `Server: uvicorn` | Python/uvicorn (FastAPI) |
| `.php` extensions | PHP |
| `.aspx`, `.ashx`, `.asmx` | ASP.NET |
| `.jsp` | Java |
| `.do` | Java/Struts |
| `.cfm` | ColdFusion |
| `.go` | Go (sometimes) |
| `.py` (rare in URL) | Python (Flask/Django dev) |
| `.rb` | Ruby (Rails) |

### Web Framework

**JavaScript bundles:**

- Read `<script src="...">` and look at bundle filenames
- `/_next/static/chunks/...` — Next.js
- `/nuxt/` or `@nuxt/` — Nuxt
- `/build/static/js/main.*.js` — CRA / Webpack
- `/assets/index-*.js` — Vite
- `/_astro/` — Astro
- `/app/chunks/manifest-*.js` — Remix
- `/q-data.json` — Quasar
- `/uploads/.../runtime.*.js` — Angular CLI

**Meta tags + globals:**

- `<meta name="generator" content="WordPress 6.4.2" />`
- `<meta name="csrf-param" content="authenticity_token" />` — Rails
- `<meta name="csrf-token" content="..." />` — Laravel/Express
- `window.__NEXT_DATA__` — Next.js
- `window.NUXT` — Nuxt
- `window.angular` — AngularJS
- `__webpack_require__` / `__webpack_modules__` — Webpack
- `__remixContext` — Remix
- `__SAPPER__` — Sapper
- `data-reactroot`, `data-react-helmet` — React

**Error page signatures:**

- PHP: `on line 45` in fatal errors
- ASP.NET: yellow page of death with stack trace
- Java: stack trace with `com.example.Class.method(File.java:123)`
- Django: `You're seeing this error because you have DEBUG = True`
- Rails: `We're sorry, but something went wrong`
- Flask: `Traceback (most recent call last):`
- Symfony: `An error occurred` with debug toolbar
- Express: `Cannot GET /unknown`
- Spring: `Whitelabel Error Page`
- Laravel: `Whoops\Handler\PrettyPageHandler` or debug bar

### CMS / Application

- **WordPress** — `/wp-admin/`, `/wp-content/`, `/wp-includes/`, `/wp-json/`, generator meta, `/feed/`, `/xmlrpc.php`
- **Drupal** — `/sites/default/`, `/node/`, `X-Drupal-Cache`, `X-Generator: Drupal X`, `/misc/`, `/modules/`
- **Joomla** — `/administrator/`, `option=com_content`, generator meta
- **Magento** — `/skin/frontend/`, `/js/mage/`, `X-Magento-*` headers
- **Shopify** — `cdn.shopify.com`, `shopify-features`, `X-ShopId`
- **Squarespace** — `static.squarespace.com`, `X-ServedBy`
- **Wix** — `static.wixstatic.com`, `X-Wix-*` headers
- **Ghost** — `/ghost/`, `X-Ghost-...`
- **Strapi** — `/admin/`, `/api/`, response shape, JWT auth
- **Contentful** — `cdn.contentful.com`, `Contentful-*` headers
- **Webflow** — `webflow.com`, `X-Webflow-*`
- **Concrete5** — `/concrete5/`
- **Plone** — `X-Plone-*`
- **Blogger** — `blogspot.com`, `blogger.com`

**Tools:**

- **CMSeek** (`cmseek -u target.com`) — fast CMS detection
- **Droopescan** — Drupal/WordPress/Joomla specific
- **WPScan** — WordPress with vuln lookup
- **droopescan** — multi-CMS
- **nuclei** — `nuclei -u target.com -t technologies/cms/`

### JavaScript Libraries

Read the main JS bundle (or all `<script>` tags) and grep for version comments:

- `/* jQuery v3.6.4` — jQuery version
- `/*! Bootstrap v5.3.2` — Bootstrap
- `/* @preserve Lodash 4.17.21` — Lodash
- `/* AngularJS v1.8.3 */` — AngularJS
- `* @version 4.17.21` — Lodash
- Source map files (`*.js.map`) — full source + version
- Bundle filename patterns — `vue.runtime.global.prod.js`, `react-dom.production.min.js`

**Tools:**

- ** Retire.js** (`retire --jspath /path/to/js`) — CVE lookup for outdated JS libs
- ** snyk** — `snyk test` for JS dep vulns (whitebox)
- ** Retire4j**, **nodejsscan** — alternative scanners

### CDN / Edge

- `Server: cloudflare`, `cf-ray:`, `cf-cache-status:` — Cloudflare
- `x-akamai-*` headers — Akamai
- `x-amz-cf-id:` — CloudFront
- `x-azure-ref:` — Azure Front Door
- `x-sucuri-id:` — Sucuri
- `x-cdn: Incapsula`, `incap_ses_*` — Imperva/Incapsula
- `x-fastly-request-id:` — Fastly
- `x-vercel-id:` — Vercel
- `x-nf-request-id:` — Netlify
- `x-bunny-cache:` — BunnyCDN
- `x-keycdn-cache-status:` — KeyCDN
- `server: BunnyCDN-*` — BunnyCDN

### WAF

See `waf-detection` skill.

## Version-Specific Exploit Search

Once you have a version string, search intelligently:

```bash
# In search queries, be specific:
"Apache 2.4.49 CVE"  # 2021 path traversal
"Struts 2.5.30 RCE"  # OGNL injection history
"OpenSSH 7.4 CVE"    # User enumeration + several auth bypasses
"PHP 8.1.0 bug"      # Early 8.1 had type juggling issues
"Drupal 7.58 CVE"    # Drupalgeddon
"jQuery 1.4.2 XSS"   # Old XSS in $.html
```

Always run `exploit_search "<product> <version> CVE"` for any fingerprint you find. Even unmaintained libraries often have public exploits.

## Tooling Stack (Kali-preinstalled)

| Tool | Use |
|---|---|
| `httpx` | Tech detection with `-tech-detect` |
| `whatweb` | Comprehensive web tech fingerprint |
| `wappalyzer` CLI | Alternative tech detection |
| `webanalyze` | Go-based, fast batch |
| `nmap -sV` | Service/version detection |
| `nuclei` | Template-based tech + vuln detection |
| `curl` | Manual probing |
| `wafw00f` | WAF detection (see WAF skill) |
| `wpscan` | WordPress deep scan |
| `retire` | Outdated JS lib detection |
| `nikto` | Server misconfig + default file scan |
| `droopescan` | Drupal/Joomla/WordPress |

## Output / Documentation

For each target, record:

1. **Web server** + version
2. **Reverse proxy** (if any) + version
3. **Application framework** + version
4. **Programming language** + runtime version
5. **CMS / SaaS** (if detected)
6. **Frontend framework** + version (React, Vue, Angular, etc.)
7. **JS libraries** + versions (jQuery, Lodash, etc.)
8. **CDN / WAF** + provider
9. **Database** (when detectable — response timing, error messages, admin paths)
10. **OS** + version (when detectable — nmap `-O`)
11. **Container / Cloud** (when detectable — headers, response patterns)
12. **Third-party SaaS integrations** (auth, payment, analytics, etc.)

## Common Pitfalls

- Trusting `Server:` header (often stripped, spoofed, or hidden behind CDN)
- Missing version behind a CDN (CDN's `Server:` ≠ origin's `Server:`)
- Stopping at one fingerprinting tool (use 2-3 to cross-check)
- Forgetting mobile vs. desktop differences (different subdomains, different stacks)
- Forgetting API domains (often different stack, e.g. REST on Go, webapp on PHP)
- Missing SPA vs. server-rendered distinction (SPA may have no obvious server framework)
- Forgetting admin/staging/dev environments (often older versions, different stack)
- Not testing the `/.well-known/` paths (security.txt, change-password, openid-configuration)
- Missing version hints in CSS bundles, image filenames, font URLs
