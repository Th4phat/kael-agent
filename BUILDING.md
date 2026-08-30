# Building Kael from Source

Kael v0.1 is a source-only release. The supported development and runtime
environment is Linux, Python 3.12 or 3.13, uv, and Docker or Podman.

## Set up a checkout

```bash
git clone https://github.com/Th4phat/kael-agent.git
cd kael-agent
uv sync --frozen
uv run kael version
```

Install contributor hooks with:

```bash
make setup-dev
```

Kael reads provider settings from environment variables, a local `.env`, or
`~/.kael/cli-config.json`. Never commit credentials.

## Build the sandbox

The sandbox is built from `containers/Dockerfile` and tagged with the Kael
version:

```bash
uv run kael sandbox build
# equivalent contributor shortcut
make sandbox-build
```

Use `--force` to rebuild an existing tag. A normal interactive scan offers to
build a missing default image. Non-interactive scans require either
`--build-sandbox` or `KAEL_AUTO_BUILD_SANDBOX=1`.

A custom image can be selected with `KAEL_IMAGE`. Custom images are pulled when
missing; Kael only source-builds its own default image.

For rootless Podman, start its API socket and select it explicitly:

```bash
systemctl --user start podman.socket
export KAEL_RUNTIME_BACKEND=podman
export KAEL_CONTAINER_SOCKET="/run/user/$(id -u)/podman/podman.sock"
uv run kael sandbox build
```

The build command uses host networking for Podman builds to avoid rootless
build-network DNS failures. Docker is exercised in CI; Podman is covered by the
same runtime integration test during manual release validation.

## Development commands

```bash
make check             # release checks; writes ignored artifacts under dist/
make test-unit         # no container runtime or network
make test-integration  # built sandbox + Docker-compatible API required
make test-network      # real external services; opt-in
make format            # rewrite formatting
make fix               # apply safe lint fixes
```

## Source layout

- `kael/`: host application, CLI/TUI, tools, skills, and reports
- `containers/`: locally built security sandbox
- `tests/`: hermetic unit tests plus explicitly marked integration/network tests
- `docs/`: repository documentation sources

Sandbox-only Python packages belong in the pinned container requirements, not in
the host runtime dependency set.

## Release checks

A source release requires:

1. A clean dependency lock and Python 3.12/3.13 unit matrix.
2. Green formatting, lint, typing, security, and package resource checks.
3. A clean sandbox build and runtime smoke test (Docker in CI; Podman manually).
4. No unmarked network tests, credentials, generated analysis artifacts, or
   unexplained large files.
5. Matching versions in `pyproject.toml`, `CHANGELOG.md`, the local image tag,
   and the Git tag.

The release workflow creates GitHub release notes and source archives only. It
does not upload to PyPI, GHCR, or a binary registry.
