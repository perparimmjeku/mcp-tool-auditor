# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-06-23

### Added
- **Behavioral / ATPA detection** — a runtime analyzer (`behavior` command) that
  calls tools and inspects their responses to catch Advanced Tool Poisoning
  Attacks: benign-then-malicious "time-bomb" output (`BEHAV_ATPA_TRANSITION`),
  output injection, response divergence, and call errors. Works live
  (`behavior stdio` / `behavior url`) or offline (`behavior import`).
- **SARIF 2.1.0 output** (`--format sarif`) for GitHub code-scanning / GitLab,
  with severity mapping, security-severity scores, OWASP tags, and remediation
  in rule help text.
- **`--fail-on SEVERITY` CI gate** — exits non-zero (code 2) when a finding meets
  the threshold, so pipelines can fail builds on poisoning findings.
- **`explain <rule>` command** and per-rule remediation guidance.
- **`scan local`** — auto-discovers and scans MCP configs for Claude Desktop,
  Cursor, VS Code (Continue), Windsurf, and Zed, plus project-local `mcp.json`.
- **SSE / streamable-HTTP transport** for URL scanning and probing, so `scan url`
  and `behavior url` work against real-world MCP servers, not just simple servers.
- **GitHub Action** (`action.yml`) for one-step CI integration.

### Changed
- Consolidated packaging into `pyproject.toml` (removed `setup.py`); version is
  single-sourced from `mcp_tool_auditor.__version__`.
- Shared injection patterns extracted into `analyzers/patterns.py`.

### Fixed
- Restored the MIT `LICENSE`; stopped tracking `egg-info` build artifacts.
- Corrected README OWASP/architecture/test-command documentation to match the code.

## [1.0.0] - 2026

### Added
- Initial release: static signature, heuristic, schema/FSP, and rug-pull analyzers
  mapped to the OWASP MCP Top 10, plus offensive ATPA/rug-pull simulators.

[1.1.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.1.0
[1.0.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.0.0
