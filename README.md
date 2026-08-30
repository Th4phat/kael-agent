# Kael

Open-source, multi-agent security testing from your own machine.

[![CI](https://github.com/Th4phat/kael-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/Th4phat/kael-agent/actions/workflows/ci.yml)
[![Python 3.12–3.13](https://img.shields.io/badge/python-3.12%E2%80%933.13-blue)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> [!WARNING]
> Kael generates real attack traffic. Only test systems you own or have explicit
> permission to assess. You are responsible for using it safely and legally.

Kael coordinates AI agents inside an isolated security-tool sandbox. It supports
source-aware application testing, web assessment, CTF workflows, and malware
reverse engineering, and writes its findings to local reports.

## Release status

Kael v0.1 is distributed as source from this repository. There is currently no
official PyPI package, pre-built executable, hosted service, or published
container image. The sandbox is built locally from the checked-out source.

Official v0.1 support is Linux with Python 3.12 or 3.13. Docker is exercised in
CI; rootless and rootful Podman are supported through its Docker-compatible API
socket and are validated manually. macOS and Windows are not release-gated.

## Quick start

Prerequisites:

- Git
- [uv](https://docs.astral.sh/uv/)
- Python 3.12 or 3.13
- Docker with a running daemon, or Podman with an active API socket
- An API key for a supported LLM provider

```bash
git clone https://github.com/Th4phat/kael-agent.git
cd kael-agent
uv sync --frozen

export KAEL_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

uv run kael ./app-directory
```

For rootless Podman, configure the runtime before building or scanning:

```bash
systemctl --user start podman.socket
export KAEL_RUNTIME_BACKEND=podman
export KAEL_CONTAINER_SOCKET="/run/user/$(id -u)/podman/podman.sock"
```

On first use, Kael asks before building the versioned local sandbox image. The
build downloads a Kali base image and security tools, so it can take a while and
consume several gigabytes.

Build or rebuild it explicitly with:

```bash
uv run kael sandbox build
uv run kael sandbox build --force
```

Non-interactive jobs never start a large build without an explicit opt-in:

```bash
uv run kael ./app-directory non-interactive --build-sandbox
# or
KAEL_AUTO_BUILD_SANDBOX=1 uv run kael ./app-directory non-interactive
```

## Common commands

```bash
# Launch the TUI and choose a target interactively
uv run kael

# Scan local source or a web application
uv run kael ./my-project
uv run kael https://staging.example.com

# Explicit scan mode and instructions
uv run kael scan ./my-project mode quick
uv run kael example.com instruction "Focus on authorization boundaries"

# Prompt-only or malware reverse-engineering workflows
uv run kael prompt "Review the manifests in ./deploy"
uv run kael ./sample.exe mode malware_re

# Inspect and resume local runs
uv run kael list
uv run kael show
uv run kael report
uv run kael resume

# Runtime help
uv run kael help
uv run kael sandbox --help
```

Run data is stored under `kael_runs/`. The exact report set depends on the scan,
and can include Markdown, CSV, JSON, and SARIF output.

## Configuration

Configuration precedence is:

1. Environment variables
2. `.env` in the working directory
3. `~/.kael/cli-config.json`

Common settings:

| Variable | Purpose |
|---|---|
| `KAEL_LLM` | Provider/model identifier |
| `LLM_API_KEY` | LLM provider credential |
| `LLM_API_BASE` | Optional custom provider endpoint |
| `KAEL_IMAGE` | Custom sandbox image; defaults to `kael-sandbox:0.1.0` |
| `KAEL_RUNTIME_BACKEND` | Runtime backend: `docker` (default) or `podman` |
| `KAEL_CONTAINER_SOCKET` | Optional path to a Docker-compatible API socket |
| `KAEL_AUTO_BUILD_SANDBOX` | Allow missing-image builds in non-interactive runs |

Never commit credentials. See [BUILDING.md](BUILDING.md) for development and
sandbox details and [docs/](docs/) for the longer usage guides.

## Contributing and security

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), follow the
[Code of Conduct](CODE_OF_CONDUCT.md), and use
[GitHub Discussions](https://github.com/Th4phat/kael-agent/discussions) for questions.

Do not report vulnerabilities in Kael publicly. Follow
[SECURITY.md](SECURITY.md) and use the repository's private vulnerability
reporting form.

## Lineage and license

Kael began as a fork of [usestrix/strix](https://github.com/usestrix/strix).
The upstream Git history is intentionally preserved, while Kael starts a new
release line at v0.1.0 and does not provide compatibility aliases for Strix
commands or configuration.

Licensed under the [Apache License 2.0](LICENSE).
