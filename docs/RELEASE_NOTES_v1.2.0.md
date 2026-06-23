# v1.2.0 — Pentest-ready

Paste this into the GitHub Release for tag `v1.2.0`.

---

MCP Tool Auditor goes beyond static scanning: it now authenticates, completes the MCP
Streamable HTTP handshake, scores findings by confidence, and ships a reusable CI action.

## Highlights

- **Authenticated scanning & proxy** — `--header "Authorization: Bearer ..."` and `--proxy`
  on URL scan/behavior, so it works against real auth-protected servers and routes through
  Burp for interception.
- **Full MCP Streamable HTTP** — captures `Mcp-Session-Id` and sends it plus
  `MCP-Protocol-Version` on post-initialize requests.
- **Confidence scoring + suppressions** — every finding carries HIGH/MEDIUM/LOW confidence;
  `--min-confidence` cuts heuristic noise and `--suppress` / `--suppressions` silence
  accepted false positives.
- **Behavioral / ATPA detection** — `behavior` command calls tools and catches
  benign-then-malicious time-bomb output that definition-only scanners miss.
- **`source-scan`** — flags Prompt-In-Shell-Out shell-injection in MCP server source (Python AST + JS/TS).
- **`scan local`** — auto-discovers configs for Claude Desktop, Cursor, VS Code, Windsurf, Zed.
- **SARIF + `--fail-on` + GitHub Action** — upload findings to code-scanning and gate merges.
- **Quality** — mypy in CI (clean), 102 tests, ruff + black enforced.

## Install

```bash
pip install mcp-tool-auditor
```

See the [CHANGELOG](../CHANGELOG.md) for the full list and [docs/RULES.md](RULES.md) for the
detection rule catalog.
