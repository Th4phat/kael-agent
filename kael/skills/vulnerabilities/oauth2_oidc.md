---
name: oauth2-oidc
description: OAuth 2.0 / OpenID Connect testing covering authorization code flow abuse, token theft, implicit flow, PKCE bypass, redirect URI validation, JWT in ID tokens, and client secret leaks
---

# OAuth 2.0 / OpenID Connect

OAuth 2.0 is an authorization framework, not an authentication protocol — and getting confused about that is the source of most implementation bugs. OIDC layers identity on top of OAuth. Both are battle-tested in spec but routinely broken in implementation. The most common failures are: missing or weak `state`/`nonce`, lax redirect URI validation, leaked client secrets, and using ID tokens as access tokens.

## Attack Surface

**Flows (use cases matter, not just names)**
- Authorization Code (with/without PKCE) — server-side web apps, SPAs, native apps
- Authorization Code + PKCE — modern best practice for all public clients
- Implicit (deprecated in OAuth 2.1) — legacy SPAs
- Client Credentials — machine-to-machine
- Resource Owner Password Credentials (deprecated) — first-party legacy
- Device Authorization — input-constrained devices (TVs, CLI tools)
- Token Exchange / JWT Bearer — service-to-service delegation

**Endpoints**
- `authorization_endpoint` — where the user is sent to grant consent
- `token_endpoint` — where codes are exchanged for tokens (client-authenticated)
- `userinfo_endpoint` — OIDC, returns claims about the authenticated user
- `introspection_endpoint` — RFC 7662, validate opaque tokens
- `revocation_endpoint` — RFC 7009, invalidate tokens
- `jwks_uri` — public keys for verifying JWT signatures
- `discovery` — `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`

**Tokens**
- `access_token` — sent to resource server
- `refresh_token` — used to get new access tokens
- `id_token` (OIDC) — JWT asserting the user's identity, NEVER sent to a resource server
- `authorization_code` — short-lived (≤10 min), single-use

**Client Types**
- Confidential — can hold a `client_secret` (web apps with backend)
- Public — cannot hold a secret (SPAs, mobile, native)
- First-party — owned by the same entity as the authorization server
- Third-party — external IdP integration

## Reconnaissance

**Discovery**
```bash
# OIDC
curl https://target.com/.well-known/openid-configuration
# OAuth 2.0
curl https://target.com/.well-known/oauth-authorization-server
# Look for: endpoints, grant_types_supported, response_types_supported, code_challenge_methods_supported, scopes_supported
```

**Endpoint fingerprinting**
```bash
# Check the auth endpoint for prompt/parameter handling
curl -I 'https://auth.target.com/authorize?response_type=code&client_id=test&redirect_uri=https://attacker.com&scope=openid&state=xyz'

# Token endpoint: try the public-client PKCE flow
curl -X POST https://auth.target.com/token \
  -d 'grant_type=authorization_code&code=X&redirect_uri=Y&client_id=Z&code_verifier=VVVVV'
```

**JWKS inspection**
```bash
curl https://auth.target.com/.well-known/jwks.json | jq .
# Look for: weak algs (HS256 with public key as secret), missing kid, alg=none support, multiple keys (key confusion)
```

**Token fingerprinting**
- Decode the JWT (use `jwt_tool` skill or `john --format=HMAC-SHA256 --wordlist=rockyou.txt token.jwt`)
- Identify signing algorithm: `alg`, `kid`, `jku`, `x5u`, `x5c`
- Check `iss` (issuer), `aud` (audience), `exp` (expiry), `nbf`, `iat`
- Identify custom claims: `scope`, `scp`, `roles`, `permissions`, `tenant_id`

**Open redirects in the auth chain**
- `redirect_uri` validation is the most common OAuth bug
- `post_logout_redirect_uri` and `return_url` after login
- `state` parameter handling — does it persist across sessions?

## Key Vulnerabilities

### Open Redirect via redirect_uri

The classic bug: the authorization server only validates that `redirect_uri` starts with the registered prefix.

**Test variations:**
```
redirect_uri=https://attacker.com          # exact
redirect_uri=https://target.com.attacker.com  # subdomain
redirect_uri=https://target.com@attacker.com  # userinfo
redirect_uri=https://attacker.com/target.com  # path
redirect_uri=https://target.com/../attacker.com  # path traversal
redirect_uri=https://target.com%2F@attacker.com  # encoded slash
redirect_uri=https://target.com\\@attacker.com  # backslash
redirect_uri=https://target.com#@attacker.com    # fragment
redirect_uri=https://target.com:80@attacker.com:443  # port
redirect_uri=https://attacker.com?target.com     # query
redirect_uri=https://target.com.attacker.com     # suffix (TLD confusion: target.com.attacker.com)
redirect_uri=ATTACKER.COM                        # case
redirect_uri=https://target.com:/\attacker.com   # mixed slashes
```

**Vulnerable validation patterns:**
- `startsWith("https://target.com/")` — matches `https://target.com.evil.com/`
- `URL.parse(redirect_uri).host === "target.com"` — can be tricked with `https://target.com@evil.com`
- Regex with `^https://target\\.com` — case-sensitive, may miss Unicode equivalents
- Whitelisting scheme only — `javascript:` URI in some cases
- Path-based redirect after login: `?next=/foo` does not validate `foo` properly

### State / Nonce / PKCE Missing

**Missing `state`**
- Attacker initiates a flow, victim completes it, code is bound to attacker's session
- Attacker now has an authorization code that exchanges for a token in the attacker's session
- Result: account takeover via session-fixation-style attack

**Missing `nonce` (OIDC)**
- ID token replay — attacker steals a valid ID token, replays it against the relying party
- `nonce` binds the ID token to the specific auth request, preventing replay

**Missing PKCE on public client**
- Authorization code interception (mobile, native, embedded webviews)
- Attacker steals the code (e.g., via custom-scheme handler hijack), exchanges without verifier

### JWT in Authorization Header + CORS

When the API uses `Authorization: Bearer <jwt>` instead of cookies:
- CORS preflight can pass (no cookies = no `credentials: include`)
- If the access token leaks to attacker origin (XSS, CORS, postMessage), full API access
- This is why OIDC recommends short-lived access tokens + refresh token rotation

### Implicit Flow / response_type=token (deprecated)

**Test:**
```
GET /authorize?response_type=token&client_id=X&redirect_uri=https://target.com/cb&state=Y
```
If the response returns `access_token` in the URL fragment:
- Token leaks via Referer, browser history, server logs
- No refresh token possible (token theft = full compromise)
- OAuth 2.1 deprecates this entirely

### ID Token as Access Token

**Bug:** the client sends the OIDC `id_token` (which contains user identity claims) to the resource server as `Authorization: Bearer <id_token>`.

**Why it's wrong:**
- `id_token` is meant to verify the user's identity to the **relying party** (RP), not to authorize API calls
- The `aud` claim is the RP, not the API
- APIs that don't validate `aud` will accept it
- Compromise: an `id_token` for RP-A may be accepted by RP-B if both don't validate `aud` properly

### Audience Confusion / Cross-Tenant Token Reuse

**Bug:** an access token issued for tenant A is accepted by tenant B.

Causes:
- `aud` claim validation missing or generic ("api", "resource-server")
- Multi-tenant API uses the same `client_id` and trusts tenant selection from request body/header
- Federation chain: token from IdP-A trusted by IdP-B, then IdP-B issues its own token with `act` claim

**Test:** obtain a token for tenant A, then send it to tenant B's resource server. If accepted → bug.

### Token Leakage Paths

**URL fragments (implicit flow)**
- `https://app.com/cb#access_token=...&token_type=bearer&...`
- Logs, browser history, Referer headers all expose it

**Authorization header in logs**
- Web server access logs, application logs, debug tools
- Search logs: `grep "Bearer " /var/log/nginx/access.log`

**Token in HTML / localStorage**
- XSS reads `localStorage.getItem('access_token')`
- Should use `HttpOnly` cookies or in-memory storage

**Refresh token in cookies**
- XSS-readable if not `HttpOnly`
- ROTATE refresh tokens on use — RFC 6749 + draft-ietf-oauth-security-topics

**Token in URL params for backend**
- Often used for callback URLs and password reset links
- Server logs, browser history, Referer leak

**Client secret leak**
- GitHub repo: `grep -r "client_secret" --include="*.js" --include="*.json" .`
- Source maps: `app.js.map` exposes the original source
- Mobile app: `strings target.apk | grep secret`
- CI logs, .npmrc, .env

### Account Takeover via Account Linking

OAuth account linking is a frequent ATO vector:
1. Attacker signs up with `attacker@evil.com` via "Sign in with Google"
2. Attacker initiates Google flow with the **target's** Google account somehow
3. The provider links the wrong account
4. Attacker now logs into target's account

**Common bug:** the link step does not verify that the OIDC `email_verified=true` and that the `sub` from Google matches the same identity.

### SSRF via OpenID Connect Discovery

**Bug:** the client library follows `/.well-known/openid-configuration` to find `jwks_uri` or `userinfo_endpoint`:
1. Attacker registers a malicious IdP pointing `jwks_uri` to `http://169.254.169.254/...` (AWS metadata)
2. App fetches JWKS, secrets leak

Or: target app uses user-supplied `iss` parameter to find the IdP. Attacker controls IdP, can return arbitrary `userinfo_endpoint`, target app makes requests to attacker URL (SSRF).

### JWT Validation Bugs

**`alg: none`**
```
{ "alg": "none", "typ": "JWT" }
. { "sub": "admin" }
. <empty signature>
```
If the library trusts `alg` from the token header → token forgery.

**`alg` confusion (RS256 ↔ HS256)**
- Server signs with RS256 (private key, public key published)
- Attacker takes the **public key** from JWKS, signs a token with **HS256** using the public key as the HMAC secret
- Library uses `alg` from token header → verifies with public key as HMAC key → succeeds

**`kid` injection**
- `kid` in JWT header is used as a file path: `kid = "../../../../etc/passwd"` or `kid = "https://attacker.com/key.pem"`
- SQLi via `kid`: `kid = "1' UNION SELECT..."`

**Missing `exp` / `nbf` validation**
- Tokens never expire
- `nbf` (not before) not checked
- `iat` not checked against clock skew

**Missing `iss` / `aud` validation**
- Token from one IdP accepted by another
- Token for one RP accepted by another

**Weak HMAC secret**
- Symmetric (HS256) signed JWTs with brute-forceable secrets
- Use `jwt_tool` / `hashcat -m 16500` to crack

**Key rotation race**
- Server publishes new JWKS, attackers can still use old keys during the rotation window
- Server may not check `kid` and just trust the first matching key

### Pushed Authorization Request (PAR) Abuse

PAR (RFC 9126) moves the auth request to a server-to-server call:
- Push request via `POST /par` (client-authenticated)
- Authorization request is referenced by `request_uri`
- If the `request_uri` is not unguessable (sequential, UUIDv1, short), attackers can hijack in-flight auth requests

### Device Flow Abuse

**User code phishing:**
- Attacker starts a device flow, gets a `user_code` + `verification_uri`
- Phishes victim to enter the code on the verification URL
- After victim authorizes, attacker polls and gets the token

**Code prediction:** if the `user_code` is short/predictable, attacker can guess codes from active flows.

### JWT-in-Cookie Authorization

Common bug: API uses a JWT in a cookie (`Set-Cookie: token=eyJ...; HttpOnly; SameSite=Lax`)
- XSS reads `document.cookie` (no, it's HttpOnly) — but session fixation possible if `state` is missing
- CORS reflective + `credentials: include` + non-HttpOnly → exfil

## Bypass Techniques

**Strict `redirect_uri` validation bypasses:**
- Path traversal: `https://target.com/../../attacker.com`
- Subdomain trick: `https://target.com.evil.com` (if matching suffix `target.com.`)
- Whitespace: `https:// target.com`
- Mixed case: `https://Target.com`
- Unicode normalization: `https://tаrget.com` (Cyrillic 'a')
- Encoded chars: `https%3A%2F%2Fattacker.com`
- HTTP/HTTPS mismatch in dev environments
- Wildcard subdomain: `https://*.target.com` registered but app trusts any subdomain
- `redirect_uri` array: some servers accept `redirect_uri` as `?redirect_uri=A&redirect_uri=B`

**State validation bypasses:**
- State stored in cookie + `state` parameter — cookie not bound to flow
- State not bound to PKCE code_verifier
- State generated from `session_id` that attacker can predict

**CSRF on OAuth callback (missing state):**
- Attacker initiates OAuth flow with their own account
- Captures callback URL
- Sends victim a link: `https://target.com/oauth/callback?code=ATTACKERS_CODE&state=ANY`
- If target binds the code to victim's session, attacker is now logged into their own account — useful for confused-deputy attacks

**PKCE downgrade:**
- Some servers accept PKCE *or* plain — attacker can omit code_verifier
- Verify: `code_challenge_methods_supported` in discovery; try with and without PKCE

**Refresh token rotation bypass:**
- New refresh token issued, old one invalidated — test whether old one still works (RFC violation, common bug)
- If old + new both work → token theft without detection

**Token replay across services:**
- Same IdP, multiple relying parties — `aud` claim not checked
- Token in URL param: navigate from app A to app B with token in URL → leak via Referer

## Testing Methodology

1. **Discovery** — `/.well-known/openid-configuration`, look for endpoints and `code_challenge_methods_supported`
2. **Identify the flow** — Authorization Code, PKCE, Implicit, Device, Client Credentials
3. **Test the auth endpoint** — fuzz `redirect_uri` with the bypass patterns above
4. **Test the token endpoint** — replay code, missing PKCE, client secret leak
5. **Test JWT validation** — `alg: none`, `alg` confusion, weak HMAC, missing `aud`/`iss`/`exp`
6. **Test state/nonce/PKCE** — omit, replay across sessions
7. **Test for client-side leaks** — localStorage, URL fragments, postMessage
8. **Test for SSRF** — IdP discovery points to attacker URL
9. **Test for token leakage** — Referer, browser history, server logs, error messages
10. **Account linking** — verify `email_verified`, `sub` binding
11. **Multi-tenant isolation** — token from tenant A to tenant B

## Validation Requirements

- Demonstrate ATO chain: attacker obtains a valid session/tokens for the victim's account via a documented OAuth/OIDC bug
- Show the **specific** bypass (e.g., `redirect_uri=https://target.com.attacker.com` with screenshot of accepted redirect)
- Prove JWT validation is missing with two tokens: a forged one with `alg: none` and a normal one
- For PKCE bypass: complete the auth code exchange with `code_verifier` omitted and document the response
- For CORS+token leak: real browser PoC that reads the token from a cross-origin response
- For IDOR via token: obtain a token for user A, hit an API endpoint for user B's resources, document the response

## False Positives

- `redirect_uri` accepts `https://attacker.com` but the `client_id` is confidential and `state` is properly bound to the user's session (CSRF token) → not exploitable without `state` bypass
- Missing PKCE but `code` is short-lived (10s) and bound to specific `client_id` via TLS mutual auth
- `alg: none` is rejected by the library despite the header being present
- Audience confusion: `aud` is checked server-side even if you can present a token for the wrong service
- `state` parameter absent but the framework stores the flow in a server-side session keyed by the user's CSRF token
- Refresh token replay test: new refresh token invalidates old one (correct behavior, not a bug)
- `email_verified` claim not required by relying party when IdP is trusted AND issuer is verified

## Impact

- **Critical**: Account takeover via `redirect_uri` bypass + `state` missing — single-click ATO on every user
- **Critical**: JWT validation gap (alg confusion, alg=none) — full API impersonation
- **High**: ID token as access token / cross-tenant token reuse — cross-customer data access
- **High**: Refresh token theft (XSS) + no rotation — persistent account access
- **Medium**: Information disclosure (user info from `/userinfo` after expired session)
- **Chain**: IDP discovery SSRF + cloud metadata = cloud credential exfil
- **Chain**: `state` missing + login CSRF + sensitive data endpoint = mass data theft

## OAuth-Specific Tools

- **jwt_tool** (`/opt/jwt_tool` or via pip) — JWT attack toolkit
- **Burp OAuth plugin** — automatic OAuth flow testing
- **oauth2-proxy** misconfig scanner
- **OpenID-Connect-Fingerprint** — IdP version detection
- **hashcat -m 16500** — crack HS256 JWTs
- **oasdiff** — OpenAPI spec diff for OAuth changes
- **Proxy tools** for capturing auth flows and replaying with mutated parameters

## Quick Reference Decision Tree

| Symptom | First thing to test |
|---|---|
| `redirect_uri` reflected back to attacker | Exact-match `redirect_uri` validation? Subdomain suffix? Path traversal? |
| Token in URL fragment | Implicit flow — `response_type=token` — push to migrate to PKCE |
| `alg: none` accepted | Library version — upgrade to a current `python-jose` / `go-jose` / `jose4j` |
| `alg: HS256` with public key as secret | Key confusion — switch to RS256 + key library that ignores `alg` in token header |
| Token accepted across services | `aud` validation — should be specific service identifier |
| `state` parameter missing | CSRF on OAuth callback — add `state` bound to session |
| Refresh tokens don't rotate | Implement RFC 6749 Section 10.4 + detection |
| `code_verifier` not required | Server accepts both PKCE and non-PKCE — force PKCE-only |
| `email_verified` not checked at linking | Account takeover via linking flow |
| `client_secret` in JS bundle / mobile app | Revoke and reissue — use confidential client on backend only |
