# MCP Tool Auditor

**Scan MCP server tool definitions for poisoning, injection, and OWASP MCP Top 10 vulnerabilities.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP03%20Tool%20Poisoning-red)](https://owasp.org/www-project-mcp-top-10/)

`mcp-tool-auditor` is a comprehensive security scanner for Model Context Protocol (MCP) servers. It detects tool poisoning, full-schema poisoning (FSP), rug-pull attacks, tool shadowing, and ATPA (Advanced Tool Poisoning Attacks), while mapping findings to the OWASP MCP Top 10 framework.

The project also includes authorized offensive tooling for penetration testers and security researchers to simulate realistic MCP attack scenarios in controlled environments.

---

## Features

### Defensive Scanner

| Feature | What It Detects |
|---|---|
| Static Signatures | 40+ patterns such as "ignore security", "always use this tool", "send full conversation", and "authoritative source" |
| Heuristic Analysis | Imperative language scoring, authority spoofing, Unicode hidden characters, and excessive agency claims |
| Schema Anomaly Detection | Full-Schema Poisoning (FSP), sidenote parameter injection, enum injection, poisoned defaults, and required-array abuse |
| Rug-Pull Detection | SHA-256 schema fingerprinting to detect unexpected tool definition changes |
| Behavioral / ATPA Detection | Calls tools and inspects responses for the benign→malicious time-bomb signature, output injection, and exfil instructions |
| OWASP Mapping | Maps findings to MCP01–MCP10 classifications |

### Offensive Tooling

| Tool | What It Simulates |
|---|---|
| Description Injection Server | Classic Tool Poisoning Attacks using malicious tool descriptions |
| FSP Generator | CyberArk-style schema poisoning variants |
| ATPA Server | Behavioral poisoning that becomes malicious after a configurable threshold |
| Rug-Pull Server | Serves clean tools initially, then swaps to malicious definitions |
| Tool Shadowing Server | Mimics trusted tool names while embedding injected payloads |

---

## Installation

### Install from GitHub

```bash
git clone https://github.com/perparimmjeku/mcp-tool-auditor.git
cd mcp-tool-auditor
pip install -e .
```

### Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

---

## Quick Start

### Scan an MCP Server

```bash
mcp-tool-auditor scan url http://localhost:8080/mcp
```

### Generate a Markdown Report

```bash
mcp-tool-auditor scan url http://localhost:8080/mcp \
  --format markdown \
  -o report.md
```

### Scan MCP Servers from a Configuration File

```bash
mcp-tool-auditor scan config \
  ~/.config/Claude/claude_desktop_config.json
```

### Register a Baseline Fingerprint

```bash
mcp-tool-auditor register url http://localhost:8080/mcp
```

### Check for Rug-Pull Changes

```bash
mcp-tool-auditor check url http://localhost:8080/mcp
```

### Behavioral / ATPA Detection

Static scans read tool *definitions*; behavioral probing actually calls tools and
inspects their *responses* to catch Advanced Tool Poisoning Attacks (ATPA) — tools
that act benign, then return poisoned output after a few calls.

```bash
# Live probe (executes real tool calls — authorized testing only)
mcp-tool-auditor behavior url http://localhost:8080/mcp --calls 6 --yes
mcp-tool-auditor behavior stdio --calls 6 -- npx @modelcontextprotocol/server-everything

# Offline: analyze a recorded transcript (tool name -> list of response strings)
mcp-tool-auditor behavior import responses.json --format json
```

Findings: `BEHAV_ATPA_TRANSITION` (benign→malicious time-bomb), `BEHAV_OUTPUT_INJECTION`,
`BEHAV_RESPONSE_DIVERGENCE`, and `BEHAV_CALL_ERROR`. Live modes require an
authorization acknowledgement (`--yes` or `MCP_TOOL_AUDITOR_ASSUME_AUTHORIZED=1`).

### Generate Offensive Test Servers

```bash
mcp-tool-auditor generate all --output-dir ./pentest_servers
```

### Verbose Output, Logs, and Metrics

```bash
mcp-tool-auditor -v scan import tests/fixtures/poisoned_tools.json
```

By default, structured logs are written under `~/.mcp-tool-auditor/logs` and scan
metrics are appended to `~/.mcp-tool-auditor/metrics.jsonl`. Use `--no-log-file`
or `--no-metrics` to disable those side effects for a run.

### Configuration

```bash
mcp-tool-auditor --config ./config.yaml scan url http://localhost:8080/mcp
```

The CLI accepts JSON or YAML config files. CLI flags still take precedence for
scan output format and minimum severity.

### Offensive Simulation Acknowledgement

```bash
mcp-tool-auditor attack --yes atpa --port 8080 --threshold 3
```

Offensive simulation servers show an authorization warning before they start.
Use `--yes` only for non-interactive, authorized lab runs.

---

## OWASP MCP Top 10 Mapping

| OWASP ID | Issue | Detection |
|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | `ST_IGNORE_PREVIOUS`, `ST_BYPASS`, `ST_IGNORE_SECURITY` |
| MCP02 | Privilege Escalation via Scope Creep | `HEUR_AGENCY`, credential-related signatures |
| MCP03 | Tool Poisoning | Signatures, heuristics, FSP, rug-pull, and behavioral/ATPA detection |
| MCP04 | Software Supply Chain Attacks | Rug-pull fingerprint mismatches and unexpected tool changes |
| MCP05 | Command Injection & Execution | `ST_EXECUTE`, `ST_CODE_EXEC`, command-related schema findings |

---

## Offensive Testing Examples

```bash
# Start an ATPA simulation server
mcp-tool-auditor attack atpa --port 8080 --threshold 3

# Start a rug-pull simulation server
mcp-tool-auditor attack rugpull --port 8081 --switch-after 5

# Generate standalone attack servers
mcp-tool-auditor generate all --output-dir ./test_servers

python ./test_servers/server_description_injection.py
```

---

## Architecture

```text
mcp-tool-auditor/
├── mcp_tool_auditor/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── logging_config.py
│   ├── metrics.py
│   ├── security.py
│   ├── validation.py
│   ├── auditor/
│   │   ├── __init__.py
│   │   ├── scanner.py
│   │   ├── models.py
│   │   ├── analyzers/
│   │   │   ├── __init__.py
│   │   │   ├── static.py
│   │   │   ├── heuristic.py
│   │   │   ├── schema.py
│   │   │   ├── rugpull.py
│   │   │   ├── behavioral.py
│   │   │   └── patterns.py
│   │   ├── signatures/
│   │   │   ├── __init__.py
│   │   │   ├── descriptions.yaml
│   │   │   └── parameters.yaml
│   │   └── reporters/
│   │       ├── __init__.py
│   │       ├── json_reporter.py
│   │       └── markdown_reporter.py
│   └── offensive/
│       ├── __init__.py
│       ├── poisoner.py
│       ├── atpa_server.py
│       └── rugpull_sim.py
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_patterns.py
│   ├── test_behavioral.py
│   ├── test_cli_behavior.py
│   ├── test_behavior_integration.py
│   └── fixtures/
│       ├── __init__.py
│       └── poisoned_tools.json
├── config.yaml
├── pyproject.toml
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── README.md
```

---

## Configuration

See `config.yaml` for example scanner settings. Pass a config file with `--config`
(JSON or YAML); CLI flags override the file for output format and minimum severity.

### Default Configuration

```yaml
auditor:
  severity_threshold: MEDIUM

  heuristic_analysis:
    description_length_threshold: 500
    imperative_threshold: 2

  schema_analysis:
    check_fsp_params: true
    check_required_array: true
    check_enum_values: true
```

---

## Contributing

Pull requests are welcome.

Please see `CONTRIBUTING.md` for development guidelines, coding standards, and testing procedures.

Security issues should follow `SECURITY.md`.

---

## License

MIT License — see the `LICENSE` file for details.

---

## Legal Disclaimer

This tool is intended strictly for:

- Authorized penetration testing
- Defensive security research
- Educational and lab environments
- Controlled validation of MCP security controls

Users must have explicit permission before testing any target systems.

The authors assume no liability for misuse, unauthorized testing, or damages caused by improper use of this software.

---

## Package Metadata

### `mcp_tool_auditor/__init__.py`

```python
"""MCP Tool Auditor package."""

__version__ = "1.0.0"
__author__ = "Përparim Mjeku"
__license__ = "MIT"
```
