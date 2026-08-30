# Pull Request

Thanks for contributing to **Kael** (pronounced *ka-el*). Please fill out the sections below — it helps reviewers get context fast.

## What

A 1–3 sentence summary of the change.

## Why

What problem does this solve? Link the issue with `Fixes #NNN` or `Refs #NNN` if applicable.

## How

- High-level approach (one or two bullets).
- Notable trade-offs or alternatives considered.

## Risk

- [ ] Touches the agent core (`kael/core`, `kael/agents`)
- [ ] Touches the sandbox / container (`containers/`, `kael/runtime/`)
- [ ] Touches proxy / network capture (`kael/tools/proxy/`)
- [ ] Touches the LLM config / model surface (`kael/config/`, `kael/agents/prompt.py`)
- [ ] New external dependency
- [ ] Changes public CLI surface
- [ ] Other: ___

## Validation

- [ ] `make check` passes locally
- [ ] Added or updated unit tests for the change
- [ ] Ran a real scan against a non-production target if behavior changed
- [ ] Updated docs (README / `docs/` / `CHANGELOG.md`) if user-visible

## Screenshots / Output

If the change is user-visible (CLI, TUI, report format), paste the relevant output.

## Checklist

- [ ] My branch is up to date with `main`
- [ ] I followed the existing code style (ruff format + line length 100)
- [ ] I added type hints and docstrings to new public functions
- [ ] I did not commit secrets, API keys, or real target URLs
