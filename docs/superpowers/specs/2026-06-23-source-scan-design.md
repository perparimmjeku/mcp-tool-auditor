# Source-Scan (Prompt-In-Shell-Out) — Design

**Date:** 2026-06-23
**Status:** Approved

## Problem

Every analyzer so far inspects MCP tool *definitions* or *behavior*. None looks at the
MCP server's own *source code*. A server author can introduce a classic
**Prompt-In-Shell-Out** bug: an LLM-controlled tool argument flows into a shell-spawning
API without sanitization, letting an attacker who controls the LLM input inject shell
metacharacters and run arbitrary code on the host.

## Goal

`mcp-tool-auditor source-scan <path>` reads MCP server source (Python + JS/TS) and flags
shell-injection sinks fed by interpolated/variable arguments.

## Non-Goals

- General-purpose SAST. We only open files that import an MCP SDK.
- Full inter-procedural taint analysis. v1 uses local argument-shape heuristics.

## Architecture

New `mcp_tool_auditor/auditor/source/` package:

- `python_analyzer.py` — uses stdlib `ast` (robust): `is_mcp_source(src) -> bool` and
  `analyze(src, path) -> list[Finding]`.
- `js_analyzer.py` — regex heuristics (no stdlib JS parser): same two functions.
- `scanner.py` — `SourceScanner.scan(path) -> dict[str, ScanResult]`: walk a file or
  directory, pick `.py/.js/.ts/.mjs/.cjs`, keep only MCP-importing files, dispatch to
  the language analyzer, aggregate findings.

### File selection
- Python MCP markers: top-level import of `mcp` or `fastmcp`.
- JS/TS MCP markers: source references `@modelcontextprotocol/sdk` (or `modelcontextprotocol`).

### Sinks
- Python: `os.system`, `os.popen`, `subprocess.getoutput`, and
  `subprocess.run/Popen/call/check_output/check_call` **with `shell=True`**.
- JS/TS: `child_process.exec`/`execSync`, `util.promisify(exec)`, `execAsync(`,
  and `spawn(..., { shell: true })`.

### Taint heuristic (v1) → severity
For the sink's command argument:
- interpolation (f-string / template literal `${}`) or concatenation (`+`, `.format`, `%`)
  → **CRITICAL** (clear injection vector).
- bare variable / non-literal expression → **HIGH**.
- pure constant string literal → **not reported** (not injectable).

## Findings & reuse

Extend `Finding` with optional `file: str | None` and `line: int | None` (added to
`to_dict`). Source findings use:
- `rule = "SRC_SHELL_INJECTION"`, `owasp_id = "MCP05"`, `attack_type = "command_injection"`.

This reuses the JSON/Markdown/SARIF reporters and the `--fail-on` gate unchanged. The
SARIF reporter emits a real `physicalLocation` (artifact + region startLine) when
`file`/`line` are present, so findings land in GitHub code-scanning at the right line.
`remediation.py` gains an `SRC` prefix entry.

## CLI

`source-scan <path>` with `--format {markdown,json,sarif}`, `--severity`, `--output`,
`--fail-on SEVERITY`. After `scan`, the summary nudges users to run `source-scan`
against in-house servers (out of scope for this pass; optional follow-up).

## Testing

Fixtures under `tests/fixtures/source/`:
- `vuln_server.py` — `subprocess.run(f"...{arg}", shell=True)` → CRITICAL.
- `safe_server.py` — `subprocess.run(["ls", arg])` (no shell) and a constant
  `os.system("ls")` → no finding.
- `vuln_server.js` — `exec(\`git \${arg}\`)` → CRITICAL.
- `not_mcp.py` — `os.system(var)` but no MCP import → skipped (no findings).
Plus unit tests for the analyzers and a CLI test asserting SARIF + `--fail-on`.
