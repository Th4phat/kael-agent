# Contributing to Kael

Issues, discussions, documentation, skills, tests, and code contributions are
welcome.

## Before you start

- Search existing issues and discussions.
- Use an issue for substantial behavior or interface changes.
- Never include real credentials, private target data, or unauthorized scan
  output.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Maintainers aim to triage new issues and pull requests within 14 days. This is a
best-effort target, not a service-level agreement.

## Development setup

```bash
git clone https://github.com/Th4phat/kael-agent.git
cd kael-agent
make setup-dev
uv run kael sandbox build
```

Linux with Docker or Podman and Python 3.12 or 3.13 is the supported contributor
baseline. Docker is the CI runtime.

## Pull requests

1. Branch from `main`.
2. Keep the change focused and explain its user impact.
3. Add or update tests and documentation.
4. Run `make check`.
5. Link the relevant issue and call out security, dependency, CLI, container, or
   compatibility risks.

Do not run formatters over unrelated code. Do not add network access to the unit
suite; use the registered `network` marker for real external services and
`integration` for container-runtime-dependent tests.

The strict mypy gate covers the core package. The inherited TUI, proxy, CTF,
and malware-analysis modules are tracked as an explicit incremental boundary in
`pyproject.toml`; changes there still require focused tests and should reduce
the excluded type surface where practical.

## Skills

Skill contributions live under `kael/skills/`. Include a focused description,
practical usage, validation guidance, and tests for discovery/registration where
appropriate.

## Reporting bugs and security issues

Use [GitHub Issues](https://github.com/Th4phat/kael-agent/issues) for ordinary bugs and
[GitHub Discussions](https://github.com/Th4phat/kael-agent/discussions) for questions.

Do not open a public issue for a vulnerability in Kael. Follow
[SECURITY.md](SECURITY.md) and use private vulnerability reporting.
