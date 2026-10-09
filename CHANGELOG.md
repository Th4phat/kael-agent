# Changelog

Kael uses [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- TUI: command palette (`ctrl+p`) with agent switching, folding, copy and
  theme selection; native header/footer with visible key bindings; model
  reasoning shown as a folded "thinking" block; per-agent unread badges;
  "new messages" indicator when scrolled up; `ctrl+j` newline (works in
  every terminal); `ctrl+o` fold/unfold tool output; `ctrl+↑/↓` agent cycling.
- TUI: `kael` Textual theme; every built-in Textual theme can be selected.
- `KAEL_REASONING_EFFORT` now applies to custom OpenAI-compatible endpoints.

### Changed

- TUI rendering is push-based (one widget per event, real Markdown) instead of
  re-rendering the whole transcript on a timer; streaming no longer stutters
  and the scan thread never blocks on the UI.
- Vulnerability detail and agent messages render with Textual's Markdown
  widget (tables, code blocks, links).
- `ctrl+c` copies the selection when there is one, otherwise asks to quit.

## [0.1.0] - 2026-08-29

### Added

- Source-only Kael release with local Docker sandbox builds.
- Application-security, CTF, malware reverse-engineering, proxy, reporting,
  session-management, and multi-agent workflows.
- SARIF output, tool selection/telemetry, session compaction, and provider
  configuration.
- Linux CI for Python 3.12 and 3.13, public contribution templates, and private
  vulnerability reporting.

### Changed

- Forked and fully renamed from Strix to Kael with a clean CLI/config break.
- Default sandbox is a versioned local image instead of a hosted registry image.
- Documentation and support use GitHub as the only canonical destination.

### Security

- Added explicit authorized-use guidance and isolated malware-analysis defaults.
- Added dependency, secret, static-analysis, and container checks to the release
  gate.

Kael preserves the upstream history of
[usestrix/strix](https://github.com/usestrix/strix) through commit
`f7e3af49bd5cbd23353db70d645bbc6e858ded8d`, while starting an independent
release line at v0.1.0.

[Unreleased]: https://github.com/Th4phat/kael-agent/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Th4phat/kael-agent/releases/tag/v0.1.0
