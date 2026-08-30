# Security Policy

## Supported versions

| Version | Status |
|---|---|
| 0.1.x | Supported |
| Other versions and upstream Strix releases | Not supported by Kael |

## Report a vulnerability privately

Do not open a public issue for a vulnerability in Kael.

Use [GitHub private vulnerability reporting](https://github.com/Th4phat/kael-agent/security/advisories/new)
and include:

- A description and impact assessment
- Reproduction steps or a minimal proof of concept
- The affected version or commit
- Suggested mitigations, if known

Maintainers aim to acknowledge reports within seven days and provide an initial
triage within fourteen days. Remediation and disclosure timing are coordinated
with the reporter according to severity. These are best-effort targets.

Kael does not currently operate a paid bug bounty.

## Scope

In scope:

- The Kael source, CLI, TUI, reports, and configuration handling
- The locally built sandbox and its Kael-owned integration code
- Unsafe privilege, filesystem, network, or secret-handling behavior introduced
  by Kael

Out of scope:

- Third-party LLM providers, Docker, and tools bundled in the sandbox
- Vulnerabilities found by Kael in an assessed target
- Upstream Strix releases

## Safe operation

Kael generates real attack traffic and can execute untrusted samples.

1. Test only assets you own or are explicitly authorized to assess.
2. Use an isolated host or VM, especially for malware reverse engineering.
3. Do not run Kael as root unless your container runtime requires it.
4. Keep credentials out of source control and rotate exposed secrets.
5. Review reports before sharing; they may contain sensitive target data.
6. Restrict sandbox egress to the authorized scope where practical.
7. Rebuild the versioned sandbox after security updates.
8. Supervise high-stakes scans and review agent decisions.
