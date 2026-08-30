"""Tests for the skill loader."""

from __future__ import annotations

from kael.skills import (
    get_all_skill_names,
    get_available_skills,
    load_skills,
    validate_requested_skills,
)


class TestSkillLoader:
    def test_get_all_skill_names_returns_set(self) -> None:
        names = get_all_skill_names()
        assert isinstance(names, set)
        assert len(names) > 0
        assert "sql_injection" in names

    def test_get_available_skills_grouped(self) -> None:
        grouped = get_available_skills()
        assert isinstance(grouped, dict)
        assert "vulnerabilities" in grouped
        assert "sql_injection" in grouped["vulnerabilities"]

    def test_load_skills_strips_frontmatter(self) -> None:
        content = load_skills(["vulnerabilities/sql_injection"])
        assert "sql_injection" in content
        body = content["sql_injection"]
        assert not body.startswith("---"), "frontmatter should be stripped"
        assert "SQL Injection" in body or "injection" in body.lower()

    def test_load_skills_missing_logs_and_skips(self) -> None:
        content = load_skills(["nonexistent_skill_xyz"])
        assert content == {}

    def test_load_skills_by_bare_name(self) -> None:
        content = load_skills(["sql_injection"])
        assert "sql_injection" in content

    def test_validate_requested_skills_too_many(self) -> None:
        names = list(get_all_skill_names())[:10]
        err = validate_requested_skills(names)
        assert err is not None
        assert "more than" in err.lower()

    def test_validate_requested_skills_unknown(self) -> None:
        err = validate_requested_skills(["not_a_real_skill"])
        assert err is not None
        assert "invalid" in err.lower()

    def test_validate_requested_skills_valid(self) -> None:
        err = validate_requested_skills(["sql_injection", "xss"])
        assert err is None


class TestWordpressAndPhpSkills:
    """The WordPress and PHP skills are tightly coupled (WordPress is
    written in PHP) and frequently loaded together for WP pentests. Lock
    in their existence, structure, and key content so regressions are
    caught at test time rather than at scan time.
    """

    def test_php_skill_exists_and_loads(self) -> None:
        content = load_skills(["technologies/php"])
        assert "php" in content
        body = content["php"]
        assert not body.startswith("---"), "frontmatter should be stripped"
        # The skill must cover the high-impact primitives that are unique
        # to PHP — if any of these go missing, the skill is no longer
        # doing its job.
        for marker in [
            "unserialize",  # POI
            "phpggc",  # gadget chains
            "php://filter",  # LFI wrappers
            "type juggling",  # loose comparison
            "0e",  # magic hash example
            "allow_url_include",  # RFI config
        ]:
            assert marker in body, f"php skill missing {marker!r}"

    def test_wordpress_skill_exists_and_loads(self) -> None:
        content = load_skills(["technologies/wordpress"])
        assert "wordpress" in content
        body = content["wordpress"]
        assert not body.startswith("---"), "frontmatter should be stripped"
        for marker in [
            "wp-json",  # REST API surface
            "xmlrpc",  # XML-RPC brute force
            "wp-config.php",  # config disclosure
            "unserialize",  # POI in plugins
            "permission_callback",  # common REST auth-bypass pattern
            "CVE-2025",  # recent CVEs as examples
            "WPScan",  # primary recon tool
        ]:
            assert marker in body, f"wordpress skill missing {marker!r}"

    def test_php_and_wordpress_in_technologies_category(self) -> None:
        grouped = get_available_skills()
        assert "technologies" in grouped
        assert "php" in grouped["technologies"]
        assert "wordpress" in grouped["technologies"]

    def test_php_and_wordpress_usable_in_agent(self) -> None:
        """Both must be user-selectable (not internal) and pass
        validation alongside other skills."""
        err = validate_requested_skills(["wordpress", "php", "sql_injection", "xss", "ssrf"])
        assert err is None

    def test_php_skill_covers_framework_gadget_chains(self) -> None:
        """The PHP skill should call out the major framework POP chains
        that phpggc supports — these are the highest-impact POI payloads
        in the wild."""
        body = load_skills(["technologies/php"])["php"]
        for framework in ["Laravel", "Monolog", "Symfony", "Guzzle"]:
            assert framework in body, f"php skill missing framework chain {framework!r}"

    def test_wordpress_skill_covers_account_switching_pattern(self) -> None:
        """The most consistent critical-bug pattern in WP plugins 2024-2025
        is unauthenticated account switching via missing capability checks.
        If the skill drops this, agents will miss a whole vuln class."""
        body = load_skills(["technologies/wordpress"])["wordpress"]
        for marker in [
            "account-switching",  # pattern name
            "wp_set_auth_cookie",  # the dangerous sink
            "JWT",  # JWT signing key leak class
            "user meta",  # privilege escalation via meta
        ]:
            assert marker.lower() in body.lower(), (
                f"wordpress skill missing account-switching pattern marker {marker!r}"
            )


class TestCorsMisconfigurationSkill:
    """CORS misconfig is the kill combo of reflective ACAO + credentials=true.
    The skill must cover the exploitation chain AND the false-positive cases."""

    def test_loads(self) -> None:
        content = load_skills(["vulnerabilities/cors_misconfiguration"])
        assert "cors_misconfiguration" in content
        body = content["cors_misconfiguration"]
        assert not body.startswith("---")

    def test_covers_kill_combo(self) -> None:
        body = load_skills(["vulnerabilities/cors_misconfiguration"])["cors_misconfiguration"]
        for marker in [
            "Access-Control-Allow-Origin",  # the header
            "Access-Control-Allow-Credentials",  # the kill combo flag
            "credentials: 'include'",  # the fetch option that triggers it
            "null",  # null origin attack
            "SameSite",  # cookie protection
            "Vary: Origin",  # cache defense
        ]:
            assert marker in body, f"cors skill missing {marker!r}"

    def test_covers_bypass_techniques(self) -> None:
        body = load_skills(["vulnerabilities/cors_misconfiguration"])["cors_misconfiguration"]
        # Each must be covered for the agent to handle real-world apps
        for bypass in [
            "subdomain",
            "userinfo",
            "trailing",
            "case",
            "cache",
        ]:
            assert bypass in body.lower(), f"cors skill missing bypass category {bypass!r}"


class TestOauth2OidcSkill:
    """OAuth 2.0 / OIDC bugs are high-impact. The skill must cover
    redirect_uri bypass, JWT validation, and state/nonce/PKCE absence."""

    def test_loads(self) -> None:
        content = load_skills(["vulnerabilities/oauth2_oidc"])
        assert "oauth2_oidc" in content
        body = content["oauth2_oidc"]
        assert not body.startswith("---")

    def test_covers_redirect_uri_bypass(self) -> None:
        body = load_skills(["vulnerabilities/oauth2_oidc"])["oauth2_oidc"]
        for marker in [
            "redirect_uri",
            "attacker.com",
            "subdomain",
            "userinfo",
            "startsWith",
        ]:
            assert marker in body, f"oauth skill missing redirect_uri bypass {marker!r}"

    def test_covers_jwt_validation_bugs(self) -> None:
        body = load_skills(["vulnerabilities/oauth2_oidc"])["oauth2_oidc"]
        for marker in [
            "alg: none",  # the classic
            "HS256",  # algorithm confusion
            "RS256",  # the other side
            "kid",  # kid injection
            "iss",  # issuer validation
            "aud",  # audience validation
        ]:
            assert marker in body, f"oauth skill missing JWT validation bug {marker!r}"

    def test_covers_pkce_state_nonce(self) -> None:
        body = load_skills(["vulnerabilities/oauth2_oidc"])["oauth2_oidc"]
        for marker in [
            "PKCE",
            "code_verifier",
            "state",  # CSRF protection
            "nonce",  # OIDC ID token binding
        ]:
            assert marker in body, f"oauth skill missing {marker!r}"


class TestDeserializationSkill:
    """Insecure deserialization covers Java, .NET, Python, Node.js, Ruby.
    Each language has its own gadget chains — the skill must name them."""

    def test_loads(self) -> None:
        content = load_skills(["vulnerabilities/deserialization"])
        assert "deserialization" in content
        body = content["deserialization"]
        assert not body.startswith("---")

    def test_covers_java_chains(self) -> None:
        body = load_skills(["vulnerabilities/deserialization"])["deserialization"]
        for marker in [
            "ysoserial",
            "CommonsCollections",
            "ObjectInputStream",
            "Jackson",
            "FastJson",
            "SnakeYAML",
            "XStream",
        ]:
            assert marker in body, f"deserialization skill missing Java chain {marker!r}"

    def test_covers_dotnet_chains(self) -> None:
        body = load_skills(["vulnerabilities/deserialization"])["deserialization"]
        for marker in [
            "BinaryFormatter",
            "ysoserial.net",
            "WindowsIdentity",
            "Newtonsoft",
        ]:
            assert marker in body, f"deserialization skill missing .NET chain {marker!r}"

    def test_covers_python_node_ruby(self) -> None:
        body = load_skills(["vulnerabilities/deserialization"])["deserialization"]
        for marker in [
            "pickle",
            "yaml.load",
            "node-serialize",
            "js-yaml",
            "Marshal",
        ]:
            assert marker in body, f"deserialization skill missing {marker!r}"

    def test_covers_oob_detection(self) -> None:
        """URLDNS chain + OOB detection is the safest way to confirm
        blind deserialization — the skill must mention it."""
        body = load_skills(["vulnerabilities/deserialization"])["deserialization"]
        assert "URLDNS" in body
        assert "interactsh" in body.lower() or "oob" in body.lower()


class TestPrototypePollutionSkill:
    """Prototype pollution is a JS/Node.js-specific vuln class with
    multiple chains to RCE / XSS / auth bypass. The skill must cover
    both the basic __proto__ path AND the downstream gadget chains."""

    def test_loads(self) -> None:
        content = load_skills(["vulnerabilities/prototype_pollution"])
        assert "prototype_pollution" in content
        body = content["prototype_pollution"]
        assert not body.startswith("---")

    def test_covers_pollution_sinks(self) -> None:
        body = load_skills(["vulnerabilities/prototype_pollution"])["prototype_pollution"]
        for marker in [
            "__proto__",
            "constructor.prototype",
            "_.merge",  # lodash
            "jQuery.extend",  # jQuery
            "deep-extend",  # npm deep-extend
        ]:
            assert marker in body, f"prototype_pollution skill missing {marker!r}"

    def test_covers_rce_chains(self) -> None:
        body = load_skills(["vulnerabilities/prototype_pollution"])["prototype_pollution"]
        for marker in [
            "ejs",
            "pug",
            "handlebars",
            "child_process",
            "exec",
        ]:
            assert marker in body, f"prototype_pollution skill missing RCE chain {marker!r}"


class TestToolingSkills:
    """The three high-impact tooling skills (sqlmap, jwt_tool, interactsh)
    must each cover the exact CLI flags the agent will use."""

    def test_sqlmap_loads_and_covers_core_flags(self) -> None:
        content = load_skills(["tooling/sqlmap"])
        assert "sqlmap" in content
        body = content["sqlmap"]
        for marker in [
            "--batch",  # non-interactive
            "--tamper",  # WAF bypass
            "--technique",  # technique selection
            "--dbms",  # DBMS-specific
            "--level",  # thoroughness
            "--risk",  # risk level
            "--dump",  # extraction
            "--os-shell",  # RCE
            "--file-read",  # file read
            "--oob",  # out-of-band
        ]:
            assert marker in body, f"sqlmap skill missing flag {marker!r}"

    def test_sqlmap_covers_dbms_specifics(self) -> None:
        body = load_skills(["tooling/sqlmap"])["sqlmap"]
        for dbms in ["MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite"]:
            assert dbms in body, f"sqlmap skill missing DBMS {dbms!r}"

    def test_jwt_tool_loads_and_cores_attack_modes(self) -> None:
        content = load_skills(["tooling/jwt_tool"])
        assert "jwt_tool" in content
        body = content["jwt_tool"]
        for marker in [
            "-X",  # exploit mode selector
            "alg: none",  # classic
            "key confusion",  # RS256 -> HS256
            "kid",  # kid injection
            "jku",  # jku injection
            "rockyou",  # wordlist reference
            "weak HMAC",
        ]:
            assert marker.lower() in body.lower(), f"jwt_tool skill missing {marker!r}"

    def test_interactsh_loads_and_covers_oob_workflow(self) -> None:
        content = load_skills(["tooling/interactsh"])
        assert "interactsh" in content
        body = content["interactsh"]
        for marker in [
            "-payload-only",  # generate payload
            "oast.pro",  # default server
            "SSRF",
            "RCE",
            "XXE",
            "webhook",
            "DNS",
            "HTTP",
        ]:
            assert marker in body, f"interactsh skill missing {marker!r}"


class TestProxySkill:
    """The proxy skill teaches the capture → inspect → replay loop. It must
    reference the exact agent-facing tool names (so the agent calls real
    tools) and cover mitmproxy filtering rules."""

    def test_loads_and_in_tooling_category(self) -> None:
        grouped = get_available_skills()
        assert "http-proxy" in grouped["tooling"]
        content = load_skills(["tooling/http-proxy"])
        assert "http-proxy" in content
        body = content["http-proxy"]
        assert not body.startswith("---"), "frontmatter should be stripped"

    def test_references_real_tool_names(self) -> None:
        """The agent only has these six tools. If the skill drifts to
        names that aren't registered (e.g. list_flows/replay_flow), the
        agent will call tools that don't exist."""
        body = load_skills(["tooling/http-proxy"])["http-proxy"]
        for tool in [
            "list_requests",
            "view_request",
            "repeat_request",
            "list_sitemap",
            "view_sitemap_entry",
            "scope_rules",
        ]:
            assert tool in body, f"proxy skill missing tool {tool!r}"

    def test_covers_mitmproxy_filter_rules(self) -> None:
        body = load_skills(["tooling/http-proxy"])["http-proxy"]
        for marker in [
            "~m POST",  # request method
            "~c 5..",  # response status regex
            "~hq Authorization",  # request header
            "~bs",  # response body
            "!~u",  # negated URL matcher
            "end_cursor",  # cursor-based pagination
        ]:
            assert marker in body, f"proxy skill missing mitmproxy marker {marker!r}"

    def test_covers_replay_modifications_and_attacks(self) -> None:
        body = load_skills(["tooling/http-proxy"])["http-proxy"]
        for marker in [
            "modifications",  # the repeat_request patch dict
            "IDOR",
            "auth bypass",
            "mass assignment",
            "X-Forwarded-For",  # header-based access control
        ]:
            assert marker.lower() in body.lower(), f"proxy skill missing {marker!r}"

    def test_usable_in_agent(self) -> None:
        err = validate_requested_skills(["http-proxy", "idor", "sql_injection"])
        assert err is None


class TestFrameworkSkills:
    """All five new framework skills must load, be in the frameworks category,
    and cover the framework-specific critical-bug patterns."""

    def test_all_frameworks_listed(self) -> None:
        grouped = get_available_skills()
        assert "frameworks" in grouped
        for name in ["django", "laravel", "express", "spring", "rails"]:
            assert name in grouped["frameworks"], (
                f"{name} not in frameworks category: {grouped['frameworks']}"
            )

    def test_all_frameworks_loadable(self) -> None:
        names = ["django", "laravel", "express", "spring", "rails"]
        content = load_skills([f"frameworks/{n}" for n in names])
        for name in names:
            assert name in content, f"{name} did not load"
            body = content[name]
            assert not body.startswith("---"), f"{name} frontmatter not stripped"

    def test_django_covers_debug_and_secret(self) -> None:
        body = load_skills(["frameworks/django"])["django"]
        for marker in [
            "DEBUG=True",
            "SECRET_KEY",
            "ALLOWED_HOSTS",
            ".raw()",  # ORM raw sink
            ".extra()",  # ORM extra sink
            "DRF",
            "permission_classes",
        ]:
            assert marker in body, f"django skill missing {marker!r}"

    def test_laravel_covers_app_key_and_phpggc(self) -> None:
        body = load_skills(["frameworks/laravel"])["laravel"]
        for marker in [
            "APP_KEY",
            "phpggc",
            "Mass assignment",  # in some form
            "Telescope",
            "Eloquent",
            "whereRaw",
        ]:
            assert marker in body, f"laravel skill missing {marker!r}"

    def test_express_covers_prototype_and_nosql(self) -> None:
        body = load_skills(["frameworks/express"])["express"]
        for marker in [
            "prototype",  # pollution
            "NoSQL",  # injection
            "$ne",  # the canonical Mongo injection
            "middleware",
            "helmet",
            "res.redirect",
        ]:
            assert marker in body, f"express skill missing {marker!r}"

    def test_spring_covers_actuator_and_spel(self) -> None:
        body = load_skills(["frameworks/spring"])["spring"]
        for marker in [
            "Actuator",  # /actuator/env, /actuator/heapdump
            "heapdump",
            "SpEL",  # Spring Expression Language
            "Spring4Shell",  # CVE-2022-22965
            "Spring Cloud Gateway",  # CVE-2022-22947
            "@PreAuthorize",
            "mass assignment",
        ]:
            assert marker in body, f"spring skill missing {marker!r}"

    def test_rails_covers_secret_and_marshal(self) -> None:
        body = load_skills(["frameworks/rails"])["rails"]
        for marker in [
            "secret_key_base",  # Rails 4.1+
            "master.key",  # the master key file
            "Marshal",  # cookie deserialization
            "mass assignment",  # strong_parameters bypass
            "strong_parameters",
            "Devise",  # common auth gem
        ]:
            assert marker in body, f"rails skill missing {marker!r}"
