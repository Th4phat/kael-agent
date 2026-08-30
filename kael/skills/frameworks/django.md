---
name: django
description: Django security testing covering ORM injection, debug mode exposure, ALLOWED_HOSTS bypass, SECRET_KEY abuse, CSRF token validation, session hijacking, and Django REST Framework authorization gaps
---

# Django

Django is "batteries-included" Python web framework with strong built-in protections — but every escape hatch is a potential vuln. Most Django bugs are not framework bugs but misconfigurations, custom views that bypass the ORM safely, debug pages leaked in production, or DRF (Django REST Framework) endpoints that don't enforce the same auth as the underlying models.

## Attack Surface

**Core Surfaces**
- URL routing (`urls.py`) and middleware chain
- Views: function-based vs class-based
- Django ORM (raw SQL escape hatches: `raw()`, `extra()`)
- Django Admin (`/admin/`) — separate auth from main site
- Django REST Framework (DRF) — ViewSets, permissions, throttling
- Templates: `render()`, `render_to_string()`, template injection
- Form processing: `ModelForm`, `Form.clean()`, CSRF
- Sessions: DB-backed, cookie-backed, cache-backed
- Auth: `django.contrib.auth`, custom user models, `AUTHENTICATION_BACKENDS`
- Signals: pre_save, post_save — can leak data
- Management commands: custom commands can run as `manage.py`
- File storage: `MEDIA_ROOT` serving, `FileField` upload paths

**Configuration**
- `settings.py` keys: `DEBUG`, `ALLOWED_HOSTS`, `SECRET_KEY`, `DATABASES`, `CORS_*`, `CSRF_*`, `SESSION_*`, `AUTH_PASSWORD_VALIDATORS`
- Middleware order: `SecurityMiddleware`, `SessionMiddleware`, `CsrfViewMiddleware`, `AuthenticationMiddleware`
- `MIDDLEWARE` list order matters — adding custom middleware can disable protection

**DRF-Specific**
- `APIView` vs `ViewSet` vs `GenericAPIView`
- `permission_classes`, `authentication_classes`, `throttle_classes`
- `serializer.save()` bypasses `Model.clean()`
- `queryset.filter()` vs `get_queryset()` — overrides
- Pagination classes
- `lookup_field` and URL routing
- `renderer_classes` (JSON, BrowsableAPIRenderer, XML)
- Throttling: `AnonRateThrottle`, `UserRateThrottle`, custom

**High-Value Recon**
- `/admin/` — Django admin
- `/api/v1/` or `/api/` — DRF
- `/swagger/`, `/redoc/`, `/openapi.json` — schema exposure
- `/__debug__/` — django-debug-toolbar
- `/static/` and `/media/` — file serving config
- `/health/`, `/ready/`, `/metrics/` — operations endpoints
- `/_status/` — `django-health-check`
- `/.env`, `/settings.py`, `/manage.py` — debug config files

## Reconnaissance

**Server identification**
- `X-Frame-Options: DENY` (Django default)
- `Set-Cookie: csrftoken=...; SameSite=Lax` (Django default CSRF)
- `Set-Cookie: sessionid=...` (Django session)
- 404 page: `Page not found (404)` vs custom (Django wording varies)
- `Server: WSGIServer/0.2 CPython/3.x` (Django dev server)
- `X-Content-Type-Options: nosniff` (Django default)
- `/admin/login/` exists and shows Django admin

**Version detection**
- `python -c "import django; print(django.get_version())"`
- `pip show django` (in source)
- `requirements.txt` (in source)
- `DEBUG=True` 404 page includes Django version + Python version + path

**Hidden endpoints**
- Fuzz `/admin/`, `/api/`, `/api/v1/`, `/api/v2/`, `/api/docs/`
- Crawl `robots.txt`, `sitemap.xml`
- Source `urls.py` for all URL patterns
- DRF's `BrowsableAPIRenderer` exposes the full API at `/api/`

## Key Vulnerabilities

### DEBUG=True in Production (CRITICAL)

Django's debug mode is a self-contained information disclosure primitive.

**Triggers:**
- Trigger a 500 error: `curl https://target.com/aaa/bbb/ccc`
- Trigger a 404: `curl https://target.com/this-does-not-exist`
- Trigger a template error: visit a URL with bad template data

**Information leaked:**
- Full Python traceback with file paths
- Local variable values in each frame
- `SECRET_KEY` if it's in any variable
- `DATABASES` settings (host, port, user)
- Django version, Python version, installed packages
- Source code snippets of the failing code
- `request.META` (all headers, including `Authorization`, `Cookie`)
- `request.POST` (form data, including passwords)

**Exploitation:**
- `SECRET_KEY` leak → forge session cookies, forge CSRF tokens, forge password reset tokens
- `DATABASES` leak → direct DB connection if reachable
- Source code leak → vulnerability hunting in custom views

### SECRET_KEY Leak

Django uses `SECRET_KEY` for:
- Session signing (cookie-based sessions)
- CSRF token generation
- Password reset token signing
- `signing` module (`django.core.signing`)
- Any framework feature using `crypto`

**Test for it:**
```bash
# Get a session cookie
COOKIE=$(curl -c - https://target.com/ | grep sessionid | awk '{print $7}')
# Try to crack or forge with known SECRET_KEY from leaks/debug
python3 -c "from django.core.signing import dumps; print(dumps({'user_id': 1, '_auth_user_backend': 'django.contrib.auth.backends.ModelBackend', '_auth_user_hash': '...'}, key='<SECRET_KEY>'))"
```

**Sources of SECRET_KEY leak:**
- `DEBUG=True` 500 page (see above)
- GitHub commit history
- `git diff HEAD~1 settings.py` (one-line commit)
- `.env` files in webroot
- Environment dump in error pages
- Container environment (`/proc/1/environ` if LFI/path traversal)
- `ps aux` output via SSRF
- Cloud metadata service

### ALLOWED_HOSTS Bypass

When `ALLOWED_HOSTS` is misconfigured:

**Wildcard `ALLOWED_HOSTS = ['*']` in production:**
- Combined with `DEBUG=True`, allows Host header attacks
- `Host: target.com.attacker.com` → cache poisoning
- `Host: attacker.com` → password reset email contains attacker link

**Missing ALLOWED_HOSTS (empty list in prod):**
- Django returns 400 Bad Request — but if behind a proxy, headers may be mis-rewritten
- `X-Forwarded-Host` may be used by middleware
- `USE_X_FORWARDED_HOST = True` without strict proxy validation

**Cache poisoning via Host header:**
- `curl -H "Host: attacker.com" https://target.com/`
- If the response is cached and served to a victim, the victim sees `attacker.com` in all URLs

### CSRF Token Issues

Django's CSRF protection has a few subtle failure modes:

**CSRF cookie + token mismatch:**
- `csrftoken` cookie set with `Secure=False` (some configs)
- `csrfmiddlewaretoken` form field set correctly but never verified
- Custom CSRF check: `csrf_exempt` decorator on sensitive views
- API-only endpoints: `CsrfViewMiddleware` doesn't apply to DRF's `APIView` by default — DRF has its own CSRF, but it's often disabled for `SessionAuthentication`

**Logout CSRF:**
- Django's logout view historically was CSRF-exempt (fixed in 4.1+)
- If on older Django, `GET /admin/logout/` works → forced logout DoS
- POST /admin/logout/ without CSRF → same

**Login CSRF:**
- Older Django: login view didn't enforce CSRF (fixed in 1.10+)

**CSRF in AJAX:**
- `X-CSRFToken` header must be set in AJAX requests
- Custom JS that doesn't read `csrftoken` cookie → fails CSRF
- Frontend using CORS with credentials → CSRF cookie sent, but X-CSRFToken not sent → 403

### ORM SQL Injection

Django's ORM is parameterized, but escape hatches leak SQL:

**`.raw()` and `.extra()` — dangerous:**
```python
# VULNERABLE
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{user_input}'")
# VULNERABLE
User.objects.extra(where=[f"username = '{user_input}'"])
```

**`__raw` lookup (newer, also dangerous):**
```python
# VULNERABLE
User.objects.filter(**{f"username__{user_input}": "x"})
# → username LIKE '%x' (injection via __raw)
```

**`cursor.execute()` with f-strings:**
```python
# VULNERABLE
with connection.cursor() as cursor:
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

**Search vector lookup (varies by DB):**
```python
# SearchVectorField with raw config
Article.objects.filter(search=SearchQuery(user_input, config='public'))
# 'config' is the column, not the value — but other args may interpolate
```

**`JSONField` queries:**
```python
# VULNERABLE to NoSQL-style injection in some DBs
User.objects.filter(data__path=user_input)
# data__path is a lookup; user_input can be `__contains`, `__startswith`, etc.
```

**`Q()` and `F()` with user input:**
```python
# VULNERABLE
qs = Q()
for key in user_input_dict:
    qs |= Q(**{key: user_input_dict[key]})
# key can be "__or__" or other internal symbols
```

**Detection:**
```bash
grep -rn "\.raw(\|\.extra(\|cursor\.execute(\|\.filter(\*\*" --include="*.py" --include="*.py" .
```

### Mass Assignment

Django doesn't have a built-in mass-assignment guard like Rails' `strong_parameters`. Django Forms protect against this for `ModelForm`, but `serializer.save()` in DRF (without `extra_kwargs`) doesn't.

**Vulnerable DRF pattern:**
```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
        # VULNERABLE: User.is_admin is settable via serializer.save(**request.data)
```

**Test:**
```bash
curl -X POST https://target.com/api/users/ \
  -H "Content-Type: application/json" \
  -d '{"username": "attacker", "email": "a@b.c", "is_staff": true, "is_superuser": true}'
# If the user is created with staff/superuser, mass assignment confirmed
```

**Read-only check:**
- All writable fields must be explicitly listed in `fields`
- `read_only_fields = ['is_staff', 'is_superuser', 'is_active', ...]` on serializer

### IDOR in DRF

DRF's `ViewSet.get_object()` uses `lookup_field` (default `pk`). Authorization is via `permission_classes` on the view, but custom `get_queryset()` can leak across users.

**Test pattern:**
```bash
# Get your own object
curl -H "Authorization: Bearer <my_token>" https://target.com/api/users/me/
# Try to access another user's object
curl -H "Authorization: Bearer <my_token>" https://target.com/api/users/123/
# If 200 → IDOR (the lookup didn't check ownership)
```

**Common missing checks:**
- `get_queryset()` returns `Model.objects.all()` instead of `Model.objects.filter(owner=self.request.user)`
- `permission_classes = [IsAuthenticated]` but no `IsOwner` permission
- `lookup_field` set to a global identifier (e.g., `email`) without owner scoping
- `IsAdminUser` allows reading all rows (intentional but can be over-permissive)

### Authentication Backend Abuse

Django's auth backends (`AUTHENTICATION_BACKENDS`) are a config surface:

**Default `ModelBackend`:**
- Uses `User.check_password()` (PBKDF2 by default)
- Vulnerable to timing attacks on username (constant-time compare not always used)
- Vulnerable to user enumeration via login error messages

**Custom backends:**
- May have weaker password handling
- May not rate-limit
- May accept multiple password formats (legacy hashes: MD5, SHA1)

**`django-axes`** or `django-ratelimit` should be installed for brute-force protection
- Test: 100 rapid login attempts — does it lock?

**`AUTHENTICATION_BACKENDS` order matters:**
- First backend that returns a user wins
- If you have a `LDAPBackend` and a `ModelBackend`, LDAP errors may leak LDAP info

### Session Issues

Django's default session backend stores in `django_session` table. Some apps use cookie-based sessions (`SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'`).

**Cookie-based sessions:**
- Session data is in the cookie, signed but not encrypted
- SESSION_COOKIE_AGE default 2 weeks
- Read `sessionid` cookie, base64-decode, see session contents
- Forge session if you have `SECRET_KEY`

**Session fixation:**
- Django rotates session ID on login — but only if `SESSION_SAVE_EVERY_REQUEST = True` or login view uses `login()` correctly
- Old session remains valid in some custom auth flows

**Session prediction:**
- `SECRET_KEY` is used for session signing HMAC
- If `SECRET_KEY` is weak, session is forgeable

### File Upload Vulnerabilities

Django `FileField` and `ImageField` handle file storage:

**Path traversal in filename:**
```python
# VULNERABLE: doesn't sanitize filename
file.save(user_provided_filename, content)
# → /var/www/media/../../etc/cron.d/backdoor
```

**Content-type spoofing:**
- `ImageField` validates file content (Pillow)
- `FileField` does NOT — any extension allowed
- `ALLOWED_CONTENT_TYPES` (Django 5.1+) helps

**SVG file XSS:**
- `ImageField` may not validate SVG (Pillow doesn't read SVG as image)
- Upload `.svg` with `<script>` tag → XSS when served
- `Content-Security-Policy: default-src 'self'` mitigates
- `X-Content-Type-Options: nosniff` + SVG served as `image/svg+xml` → still XSS via inline SVG

**Storage backends:**
- `FileSystemStorage` (local disk)
- `S3Boto3Storage` (boto3 — check ACLs, bucket policies)
- `AzureStorage`, `GCSStorage` — similar
- Misconfigured S3 buckets leak uploaded files publicly

### Template Injection

Django templates auto-escape by default — but custom template tags, `{% include %}`, or `Template().from_string()` are sinks.

**`{% include user_input %}`:**
```python
# VULNERABLE if user_input is attacker-controlled
return render(request, f"pages/{user_input}.html")
# Or
return render(request, "page.html", {"page": user_input})
# Template: {% include page %}
```

**`{% ssi %}` server-side include:**
```html
{% ssi user_input %}
# → SSRF / file read
```

**Custom template tags that return render:**
```python
@register.simple_tag
def render_user_string(value):
    return Template(value).render(Context())
# VULNERABLE: attacker-supplied templates → SSTI
```

**Jinja2 mixed in:**
- Some apps use Jinja2 for templates (faster, more flexible)
- Jinja2 is SSTI-prone if user input reaches `from_string()` / `Template(value)`
- `{{ ''.__class__.__mro__[1].__subclasses__() }}` → RCE chain

### Middleware Bypass

Django's middleware order matters. A custom middleware can disable protections.

**`CsrfViewMiddleware` ordering:**
- Must come AFTER `SessionMiddleware`
- If `MIDDLEWARE` list reorders, CSRF may not get session

**`SecurityMiddleware`:**
- `SECURE_SSL_REDIRECT = True` (HSTS, HTTPS redirect)
- `SECURE_HSTS_SECONDS = 31536000`
- `SECURE_CONTENT_TYPE_NOSNIFF = True`
- `SECURE_BROWSER_XSS_FILTER = True`
- `SESSION_COOKIE_SECURE = True`
- `CSRF_COOKIE_SECURE = True`
- `X_FRAME_OPTIONS = 'DENY'`
- `SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')` — only with trusted proxy

**Common misconfig:**
- `SECURE_PROXY_SSL_HEADER` enabled but no reverse proxy validating the header
- Attacker sends `X-Forwarded-Proto: https` → bypasses `SECURE_SSL_REDIRECT`
- `USE_X_FORWARDED_HOST = True` with untrusted proxy → Host header injection

### Custom Management Commands

`python manage.py <custom_command>` — often runs as the web server user (with high privileges).

**RCE via management command:**
- Some apps expose management commands via HTTP (admin-only)
- Some commands accept filenames that get passed to `os.system()`
- Some commands load YAML/JSON that trigger deserialization

### Source Code Leak

Common Django file exposure:
- `static/admin/` paths
- `static/` and `media/` in webroot
- `requirements.txt` in repository
- `settings.py` accessible via LFI
- `__pycache__/` directories serving `.pyc` files
- `.git/` directory in webroot
- `manage.py` accessible in webroot
- `local_settings.py`, `prod_settings.py` patterns

**Test for `__pycache__` exposure:**
```bash
curl -I https://target.com/__pycache__/views.cpython-311.pyc
```

**Test for `.env` exposure:**
```bash
curl -I https://target.com/.env
```

## Common Django CVEs (2024-2025)

Always check `cve_lookup` for the latest:
- **CVE-2024-53907, CVE-2024-53908** — SQL injection in `JSONField` lookups (Django 4.2.x, 5.0.x) — `__isnull`, `__has_key` lookups
- **CVE-2024-41991** — `django.utils.html.urlize()` XSS via invalid HTML — affects 4.2.x, 5.0.x
- **CVE-2024-42005** — `URLField`/`IntegerField` validation bypass with very large values
- **CVE-2025-XXXXX** — check Shodan CVEDB / NVD for current
- **CVE-2024-38875** — `django-mptt` (third-party) authorization bypass

Run: `cve_lookup(query="django", product="django", is_kev=True, sort_by_epss=True)` to get current CVEs.

## Common Bypass Techniques

**`ALLOWED_HOSTS` strict bypass:**
- DNS rebinding: domain that resolves to your IP first, then target's IP
- HTTP/2 `:authority` vs `Host` header mismatch
- Trailing dot: `Host: target.com.` (DNS parsing)
- Case: `Host: TARGET.com` (HTTP/2 lowercases)

**CSRF in API endpoints:**
- Find a way to leak `csrftoken` cookie value (CORS, image fetch, etc.)
- Inject it as `X-CSRFToken` header
- Or use a CORS+form post combo (if `SameSite=Lax`)

**Session cookie theft:**
- XSS reads `document.cookie` (if `HttpOnly` not set — Django sets it by default)
- Server logs / log injection
- Network sniff (no TLS)

**`SECRET_KEY` brute force:**
- Short / dictionary-word SECRET_KEY
- Use `django-secret-key` cracker or `hashcat`
- If found → forge session, CSRF, password reset tokens

**Debug toolbar leak:**
- `django-debug-toolbar` exposes SQL queries, request data, settings
- Often enabled in production by mistake
- Test: `curl -H "X-Requested-With: XMLHttpRequest" https://target.com/__debug__/`

**Cache poisoning:**
- `USE_ETAGS = True` may allow Vary header bypass
- `CACHE_MIDDLEWARE_KEY_PREFIX` not set → cache key collision
- Backend cache (`Memcached`/`Redis`) accessible from outside

**`/admin/` brute force:**
- Default Django admin has no rate limit
- `/admin/login/?next=/admin/` → no CSRF
- User enumeration via login error: "User does not exist" vs "Password incorrect"

## Testing Methodology

1. **Fingerprint** — Django version, DEBUG mode, ALLOWED_HOSTS, installed middleware
2. **Trigger 500 error** — extract DEBUG data, SECRET_KEY, DATABASES, source paths
3. **Enumerate URLs** — `/admin/`, `/api/`, `/api/v1/`, debug toolbar, static/media
4. **Source review** — ORM raw queries, serializer fields, custom views, management commands
5. **Test ORM injection** — f-strings, `.raw()`, `.extra()`, `__raw` lookups
6. **Test mass assignment** — POST with extra fields (`is_staff`, `is_superuser`, `user_type`)
7. **Test IDOR** — get own object, try other IDs
8. **Test CSRF** — POST without CSRF token, POST with wrong token, GET-based state change
9. **Test sessions** — cookie entropy, SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY
10. **Test file upload** — path traversal in filename, content-type spoofing, SVG XSS
11. **Test middleware** — `X-Forwarded-Proto`, `X-Forwarded-Host` injection
12. **Test DRF** — schema exposure, permission_classes, authentication_classes
13. **Test settings exposure** — `__pycache__/`, `local_settings.py`, `.env`

## Validation Requirements

- **DEBUG leak**: trigger 500 error, show SECRET_KEY, DATABASES, or `request.META` in response
- **SECRET_KEY forge**: forge a session cookie, log in as admin without password
- **ALLOWED_HOSTS bypass**: send `Host: target.com.attacker.com`, get 200
- **ORM SQLi**: prove with `UNION SELECT` or time-based blind
- **Mass assignment**: create a user with `is_staff=true`, show admin access
- **IDOR**: read another user's resource with own auth, show 200 + foreign data
- **CSRF bypass**: state-changing GET or POST without token succeeds
- **File upload RCE**: upload `.svg` with XSS, render in headless browser, see JS execute
- **Settings leak**: read `local_settings.py` via path traversal, show contents

## False Positives

- `DEBUG=True` is set but the server is internal-only (still a finding, but lower impact)
- `ALLOWED_HOSTS = ['*']` but a reverse proxy strips/overrides the Host header
- `SECRET_KEY` is public (e.g., in a settings file accessible to all developers) and the deployment uses a different key from env var
- ORM uses `.raw()` with hardcoded SQL, no user input
- Mass assignment blocked by `read_only_fields` on the serializer
- IDOR attempt blocked by custom `get_queryset()` filtering on `request.user`
- CSRF missing on `/api/` because it's an OAuth bearer-token API (no cookies = no CSRF)
- File upload with `Content-Type` validation that does check magic bytes
- Debug toolbar exposed but only for authenticated staff users

## Impact

- **Critical**: DEBUG=True + SECRET_KEY leak → full admin takeover
- **Critical**: ORM SQLi → full DB compromise, auth bypass
- **High**: Mass assignment → privilege escalation to admin
- **High**: IDOR in DRF → mass user data exfiltration
- **High**: ALLOWED_HOSTS bypass + password reset → ATO via email link
- **Medium**: File upload XSS / path traversal
- **Medium**: Session forgery if SECRET_KEY weak
- **Chain**: DEBUG leak + ORM SQLi + admin exposed = full RCE

## Cross-References

- **`sql_injection` skill** — ORM raw queries
- **`xss` skill** — template injection, SVG upload
- **`cors_misconfiguration` skill** — DRF CORS misconfig
- **`deserialization` skill** — pickle in `__init__` / signal handlers
- **`oauth2_oidc` skill** — Django OAuth integrations (django-allauth, django-oauth-toolkit)
- **`rce` skill** — management commands, template injection
- **`path_traversal_lfi_rfi` skill** — Django media file serving
- **`cve_lookup` tool** — current Django CVEs

## Tooling Checklist

- **bandit** — Python static analysis
- **semgrep** with `p/python` and `p/django` rules
- **trufflehog / gitleaks** — secret scanning
- **debug-toolbar** introspection (if exposed)
- **Nuclei** — Django template-based CVEs
- **djangodebugtoolbar** as recon target
- **Proxy tools** for replaying with `Host: target.com.attacker.com` etc.
- **wpscan** if WordPress (not Django, but common confusion)
- **interactsh** for OOB ORM SQLi
