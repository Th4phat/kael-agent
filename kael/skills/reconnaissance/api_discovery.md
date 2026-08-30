---
name: api-discovery
description: Swagger/OpenAPI discovery, GraphQL introspection, common endpoint patterns
---

# API Discovery

Modern apps live or die by their APIs. Missing endpoints = missing vulns. API discovery is the first step after tech fingerprinting — and it's often the most impactful recon step for finding attack surface.

## Why API Discovery Matters

- **Authentication bypasses** — APIs often have weaker auth than web UI
- **Hidden endpoints** — internal/admin/debug APIs exposed unintentionally
- **Schema disclosure** — Swagger/GraphQL introspection reveals the full data model
- **Parameter pollution** — APIs accept more parameters than the web UI
- **Direct object access** — APIs often lack the UI's authorization wrapper
- **Mass assignment** — fields the UI hides are accepted by the API

## Common API Styles

| Style | Signals |
|---|---|
| REST | `/api/v1/users`, `/api/users/123`, JSON/XML, OpenAPI/Swagger |
| GraphQL | `/graphql`, `/api/graphql`, `/gql`, POST with `{query, variables}` |
| gRPC | HTTP/2 + protobuf, `application/grpc` content type, `.proto` definitions |
| WebSocket | `wss://`, upgrade headers, often in chat/realtime apps |
| SOAP | `?wsdl`, XML envelopes, `Content-Type: text/xml` |
| JSON-RPC | `/rpc`, `{"jsonrpc": "2.0", "method": "..."}` |
| XML-RPC | `POST /xmlrpc.php` (WordPress) |

## REST API Discovery

### Path patterns to probe

- `/api`, `/api/v1`, `/api/v2`, `/api/v3` — versioned
- `/v1/`, `/v2/`
- `/api/rest/`, `/api/json/`, `/api/xml/`
- `/api/public/`, `/api/internal/`, `/api/admin/`
- `/api/users/`, `/api/orders/`, `/api/products/`
- `/api/`, `/api-docs/`, `/swagger/`, `/openapi/`
- `/api/health`, `/api/status`, `/api/ping` — health checks
- `/api/me`, `/api/profile` — current user
- `/api/`, `/api/__schema` — GraphQL-style introspection in REST
- `/api/search`, `/api/query` — search/query endpoints
- `/api/upload`, `/api/files` — file upload
- `/api/auth/login`, `/api/auth/refresh` — auth endpoints
- `/api/admin/`, `/api/internal/`, `/api/debug/`, `/api/dev/`
- `/api/users/1`, `/api/users/me` — IDOR candidates

### Wordlists

- **SecLists** — `Discovery/Web-Content/api/`
- **Assetnote** — `data/automated/`
- **fuzz.txt** — `danielmiessler/SecLists`
- **raft** wordlists — `Discovery/Web-Content/raft-`
- **API-specific** — `SecLists/Discovery/Web-Content/api/*`

### Tools

- **feroxbuster** — recursive, fast, with extensions filter
- **ffuf** — fast fuzzer, JSON output
- **gobuster** — multi-mode (dir, dns, vhost)
- **dirsearch** — feature-rich dir buster
- **katana** — modern crawler with API discovery
- **arjun** — parameter discovery specifically for APIs (`arjun -u https://target.com/api/users`)
- **x8** — hidden parameter discovery
- **paramspider** — parameter mining from web archives

## OpenAPI / Swagger Discovery

### Common paths

- `/swagger.json`
- `/swagger.yaml`
- `/openapi.json`
- `/openapi.yaml`
- `/api/swagger.json`
- `/api-docs`
- `/api-docs/swagger.json`
- `/api/v1/swagger.json`
- `/api/v1/openapi.json`
- `/api/spec.json`
- `/api/spec.yaml`
- `/v1/api-docs`
- `/v2/api-docs`
- `/v3/api-docs`
- `/swagger-resources`
- `/swagger-ui.html`
- `/swagger-ui/`
- `/swagger/index.html`
- `/api/swagger-ui.html`
- `/api-docs-ui/`
- `/redoc`
- `/docs/`
- `/_doc/`
- `/api/documentation`

### Tools

- **SwaggerSpy** — finds swagger URLs and parses them
- **nuclei** with `exposures/configs/` and `technologies/` templates
- **dirsearch** with API wordlists
- **Manual curl** — `curl https://target.com/openapi.json | jq`
- **stepped parsing** — load swagger UI, click around, harvest the JSON spec URL

### Exploitation

When you find a swagger spec:

1. **List every endpoint** — `/users`, `/users/{id}`, `/admin/users`, etc.
2. **Note auth requirements** — Bearer token? Cookie? API key? Public?
3. **Identify sensitive data** — `/users/{id}` returns PII? `/admin/*` requires admin?
4. **Check for IDOR** — try `/users/1` with your token, then `/users/2` (different user)
5. **Check for BOLA** — Broken Object Level Authorization (OWASP API #1)
6. **Check for BFLA** — Broken Function Level Authorization (OWASP API #5)
7. **Hidden parameters** — feed the spec to `arjun` to find undocumented fields
8. **Schema validation bypasses** — send types different from spec (e.g. array where scalar is expected)

## GraphQL Discovery

### Detection

- Common endpoints: `/graphql`, `/api/graphql`, `/gql`, `/graphql/v1`, `/api/gql`
- Send a POST with empty body or `{"query": "{__schema{types{name}}}"}` to see if it responds
- HEAD on the path
- `nuclei -t technologies/graphql/`
- **GraphQL Voyager** — `https://graphql-kit.com/graphql-voyager/` for schema visualization

### Introspection (if enabled)

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind ofType { name kind } } }
      }
    }
  }
}
```

Most apps ship with introspection enabled in dev/staging. Often leaked to prod.

### Tools

- **graphql-cop** — security audit (introspection, batching, depth limits, etc.)
- **GraphQLmap** — automation
- **clairvoyance** — schema discovery via field sampling (when introspection is disabled)
- **crackQL** — JWT/cookie cracking for GraphQL
- **BatchQL** — batch query attacks
- **InQL** (Burp extension) — schema visualization, attack helpers

### Common GraphQL vulns

- **Introspection in prod** — full schema exposed
- **No depth limit** — DoS via deeply nested queries
- **No batching limit** — brute force via batched login mutation
- **Field suggestions** — type name leaks when querying wrong field
- **No auth on mutations** — anyone can call `deleteUser`
- **IDOR on nodes** — same as REST
- **Subscription abuse** — WebSocket-based DoS
- **N+1 query DoS** — `users { posts { comments { author { posts { ... } } } } }`

## gRPC Discovery

### Detection

- HTTP/2 with `content-type: application/grpc`
- Often on `:50051`, `:443` with `application/grpc+proto`
- `grpcurl` (the `curl` of gRPC) — `grpcurl -plaintext target.com:443 list`
- Server reflection (often enabled): `grpcurl target.com:443 list` then `grpcurl target.com:443 describe <service>`
- `grpc-tools` — `grpc_cli ls target.com:443`

### Web reflection API

- `/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo`
- Often accessible unauthenticated

### Tools

- **grpcurl** — like curl for gRPC
- **grpcui** — web UI for gRPC servers (introspection)
- **ghz** — gRPC benchmarking (DoS)
- **protoc** + proto files — generate clients

### Common gRPC vulns

- **Reflection enabled in prod** — full schema exposed
- **No auth** — gRPC services often skip auth "because they're internal"
- **TLS termination at LB** — gRPC traffic unencrypted inside
- **HTTP/2 vulnerabilities** — Rapid Reset (CVE-2023-44487), HPACK bombs
- **gRPC-Web** — sometimes exposed with different auth, leading to bypass

## SOAP / WSDL Discovery

### Detection

- `?wsdl` parameter on common paths
- `.asmx`, `.svc` (WCF)
- `?op=` (operation) parameter
- Look for `<soapenv:` in HTML output
- Burp Scanner does this well

### Tools

- **WSDLer** — automated WSDL discovery
- **SoapUI** — full-featured testing
- **WSDigger** — security audit
- **nmap** — `nmap --script http-soap-discover`

## JSON-RPC / XML-RPC

- **WordPress XML-RPC** — `/xmlrpc.php` is often a quick bruteforce target
- **JSON-RPC** — `/rpc`, `/json-rpc`, `/api/json-rpc`
- Methods often discoverable via `{"jsonrpc": "2.0", "method": "system.listMethods", "id": 1}`

## WebSocket Discovery

- `wss://target.com/ws`, `/socket.io/`, `/realtime/`
- Often discoverable via main page JavaScript
- Burp Suite has WebSocket interception
- `websocat` — CLI for WebSocket testing

### Common WebSocket vulns

- **No auth on connect** — `wss://target.com/ws` accepts anyone
- **CSWSH** — Cross-Site WebSocket Hijacking (no Origin check)
- **Auth bypass via header injection** — `Sec-WebSocket-Protocol` for auth tokens
- **Message injection** — server trusts client-controlled fields
- **DoS** — large messages, rapid messages, no rate limit

## API Security Headers

Always check:

```bash
# CORS
curl -I -H "Origin: https://attacker.com" https://target.com/api/users
# Should NOT return Access-Control-Allow-Origin: https://attacker.com with credentials

# CORS preflight
curl -X OPTIONS -H "Origin: https://attacker.com" -H "Access-Control-Request-Method: POST" https://target.com/api/users

# Authentication required
curl https://target.com/api/users  # should be 401/403, not 200

# Rate limiting
for i in {1..100}; do curl https://target.com/api/login -d "..."; done
# Look for 429, Retry-After, IP ban

# Content-Type validation
curl -X POST https://target.com/api/users -H "Content-Type: text/plain" -d '{...}'
# Some APIs accept JSON regardless of declared Content-Type

# HTTP methods
curl -X OPTIONS https://target.com/api/users -I  # check Allow header
```

## Versioning and Deprecation

- Look for `X-API-Version`, `API-Version`, `X-Rate-Limit-*` headers
- Check `/api/v1/`, `/api/v2/` — v1 often has worse security
- Sometimes old versions are unmaintained but still live (find via Wayback)

## Tooling Summary

| Tool | Use |
|---|---|
| `ffuf` / `feroxbuster` / `gobuster` | Path brute |
| `arjun` / `x8` | Parameter discovery |
| `nuclei` | Template-based API detection |
| `katana` | Modern crawler with API discovery |
| `graphql-cop` / `crackQL` / `BatchQL` | GraphQL attacks |
| `grpcurl` / `grpcui` | gRPC discovery |
| `SoapUI` / `WSDLer` | SOAP discovery |
| `mitmproxy` | Captured and scripted API testing |
| `postman` / `insomnia` | API client |
| `swagger-codegen` | Generate client from spec |
| `Wayback Machine` / `waybackurls` | Historical endpoints |
| `paramspider` | Param mining from archives |

## Output / Documentation

For each API discovered, record:

1. **Base URL** + version
2. **Authentication** — type, where to get tokens, refresh flow
3. **Authorization** — role model, ACL, scope
4. **All endpoints** — method, path, params, response shape
5. **Sensitive endpoints** — admin, internal, debug, PII
6. **File upload endpoints** — where, what types, what size
7. **WebSocket endpoints** — auth model
8. **Rate limits** — by IP, by user, by endpoint
9. **OpenAPI/GraphQL/gRPC schema** if accessible — keep versioned
10. **CORS** — allowed origins, credentials
11. **CSP** — content security policy on the API origin
12. **TLS** — cert chain, HSTS, ALPN, cipher suites

## Common Pitfalls

- Stopping at the public API — internal/admin/dev APIs are usually less secure
- Forgetting versioning — `/api/v1/` may have more vulns than current `/api/v3/`
- Not testing CORS — frequently the #1 finding on production APIs
- Missing GraphQL introspection — one query reveals the entire data model
- Probing GraphQL mutations without proper auth (often missing on dev)
- Not testing API keys vs. session cookies (different attack surface)
- Missing file upload endpoints (often allow dangerous types)
- Assuming JSON-only — some APIs accept XML/Protobuf, leading to parser confusion
- Missing rate limits (often absent on internal APIs)
- Missing health/info endpoints that leak stack info
- Not checking for default API keys (`x-api-key: demo`, `Authorization: Bearer demo`)
- Skipping API documentation sites (often linked from the UI, full of examples)
