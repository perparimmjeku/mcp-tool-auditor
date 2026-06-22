# Behavioral ATPA Detector — Design

**Date:** 2026-06-23
**Status:** Approved

## Problem

Every analyzer in `mcp-tool-auditor` is *static* — it inspects tool **definitions**
(name / description / `inputSchema`) and never observes what a tool actually
**does**. The project ships an ATPA *attack* simulator (`offensive/atpa_server.py`)
where tools act benign and then return malicious instructions after a call
threshold, but there is **no detector** for that behavior. This design adds
runtime/behavioral detection, closing the loop with the existing simulator.

ATPA = "Advanced Tool Poisoning Attack": the poison lives in tool **responses**,
revealed only after the tool has been called enough times to earn trust.

## Goals

- Detect injection/exfil/credential-harvesting content in tool **responses**.
- Detect the ATPA time-bomb signature: responses benign for the first *k* calls,
  then turning malicious.
- Be fully testable offline (pure detection core) and verifiable live against the
  bundled ATPA simulator.

## Non-Goals

- A MITM proxy / passive interceptor (out of scope, large surface).
- Guaranteeing the target's tools are side-effect-free. Live probing executes real
  tool calls and is therefore opt-in and authorization-gated.

## Architecture

Pure detection core, two front-ends (live + offline).

### 1. `analyzers/patterns.py` (new, shared)
Extract the injection / exfil / authority / imperative regexes (currently inline in
`HeuristicAnalyzer`) into a shared module. Consumed by both `HeuristicAnalyzer`
(over definitions) and `BehavioralAnalyzer` (over responses). Targeted refactor
justified by reuse; existing heuristic behavior must remain unchanged.

### 2. `analyzers/behavioral.py` (new) — `BehavioralAnalyzer`
Pure logic, **no I/O**.

```
analyze(tool: dict, responses: list[CallResult]) -> list[Finding]
```

where `CallResult` carries: call index, extracted response text, and an
error flag/message. The analyzer:

- Classifies each response as benign vs injection-bearing using `patterns.py`.
- Emits findings (see Detection Rules).

### 3. Argument synthesis — `synthesize_arguments(input_schema: dict) -> dict`
Minimal valid dummy arguments per JSON-schema property type (string→`"test"`,
number→`1`, boolean→`true`, array→`[]`, object→`{}`, respects `enum`/`default`).
Used by live mode only. Best-effort; only `required` props need values, but
synthesizing all declared props is acceptable.

### 4. Transport — extend `MCPScanner`
Add `call_tool(name, arguments)` issuing JSON-RPC `tools/call` over the existing
stdio and URL plumbing, plus `collect_responses(tool, calls)` returning the ordered
`CallResult` list. The analyzer never touches the network — it is handed responses.
Response text is extracted from MCP `content` blocks (`type: "text"`).

### 5. CLI — `behavior` subcommand
- `behavior stdio -- <command> [args...]`
- `behavior url <url>`
- `behavior import <file>` — offline: a JSON file mapping tool name → list of
  response strings (or `{tools: [...], transcripts: {...}}`); runs the same core.
- `--calls N` (default **6**, to clear the typical switch-after-5 threshold).
- Findings flow through the existing JSON / Markdown reporters and severity filter.

### 6. Safety gate
Live modes (`stdio`, `url`) execute real tool calls, so they are opt-in (never part
of `scan`) and require authorization acknowledgement via `security.require_ack`,
bypassable with `--yes` / `MCP_TOOL_AUDITOR_ASSUME_AUTHORIZED`, mirroring the
offensive tooling. The `import` mode performs no calls and needs no ack.

## Detection Rules

| Rule | Severity | attack_type | OWASP | Trigger |
|---|---|---|---|---|
| `BEHAV_OUTPUT_INJECTION` | HIGH | `behavioral_injection` | MCP03 | Any response text matches injection/exfil/credential patterns |
| `BEHAV_ATPA_TRANSITION` | CRITICAL | `atpa` | MCP03 | First *k≥1* responses benign, a later response injection-bearing; report the flip index |
| `BEHAV_RESPONSE_DIVERGENCE` | LOW | `behavioral_nondeterminism` | MCP03 | Identical-input responses differ across calls, no injection content |
| `BEHAV_CALL_ERROR` | INFO | `behavioral_error` | N/A | A tool call errored (informational, not a vuln) |

`BEHAV_ATPA_TRANSITION` is the headline. When it fires, the plain
`BEHAV_OUTPUT_INJECTION` for the same tool is suppressed to avoid double-reporting.

## Error Handling

- Per-tool isolation: a failure calling one tool yields a `BEHAV_CALL_ERROR`
  finding and continues to the next tool; it never aborts the run.
- Transport/connection failures raise `RuntimeError` with actionable messages,
  consistent with the existing scanner.
- Malformed `import` files raise a `ValidationError`-based message.

## Testing

- **Unit (pure core):** canned response sequences — all-benign (no finding),
  all-injection (`BEHAV_OUTPUT_INJECTION`), benign→malicious transition
  (`BEHAV_ATPA_TRANSITION` with correct flip index, injection suppressed),
  divergent-benign (`BEHAV_RESPONSE_DIVERGENCE`), error responses
  (`BEHAV_CALL_ERROR`).
- **Unit:** `synthesize_arguments` across schema types incl. `enum`/`required`.
- **Unit:** `patterns.py` matchers; assert `HeuristicAnalyzer` output unchanged.
- **Integration:** run the live path against the bundled ATPA simulator and assert
  `BEHAV_ATPA_TRANSITION` is reported.
- **CLI:** `behavior import` over a fixture transcript produces expected findings
  and respects the severity filter.

## Backwards Compatibility

Purely additive. No existing analyzer, CLI command, model, or reporter changes
behavior. `patterns.py` is a pure extraction; `HeuristicAnalyzer` results are
unchanged and asserted so by tests.
