# MCP Tool Auditor

**Scan MCP server tool definitions for poisoning, injection, and OWASP MCP Top 10 vulnerabilities.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP03%20Tool%20Poisoning-red)](https://owasp.org/www-project-mcp-top-10/)

`mcp-tool-auditor` is a comprehensive security scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. It detects **tool poisoning**, **full-schema poisoning (FSP)**, **rug-pull attacks**, **tool shadowing**, and **ATPA (Advanced Tool Poisoning Attacks)** — mapping all findings to the **OWASP MCP Top 10** framework.

Includes **authorized offensive tooling** for penetration testers to simulate real-world MCP attacks.

---

## 🔍 Features

### Defensive Scanner
| Feature | What It Detects |
|---------|----------------|
| **Static Signatures** | 40+ patterns: "ignore security", "always use this tool", "send full conversation", "authoritative source", etc. |
| **Heuristic Analysis** | Imperative language scoring, authority spoofing, Unicode hidden chars, excessive agency claims |
| **Schema Anomaly Detection** | Full-Schema Poisoning (sidenote params, enum injection, default poisoning, required array injection) |
| **Rug-Pull Detection** | HMAC-based fingerprinting — flags tool definition changes since baseline registration |
| **OWASP Mapping** | Every finding mapped to MCP01–MCP10 with attack type classification |

### Offensive Tooling (Authorized Tests)
| Tool | What It Simulates |
|------|-------------------|
| **Description Injection Server** | Classic TPA — hidden instructions in tool descriptions |
| **FSP Generator** | CyberArk-style schema poisoning (sidenote, enum, default, required array variants) |
| **ATPA Server** | Behavioral poisoning — benign for N calls, then returns poisoned errors that instruct the agent to exfiltrate data |
| **Rug-Pull Server** | Serves clean tools initially, swaps to malicious definitions post-approval |
| **Tool Shadowing Server** | Mimics legitimate tool names with injected payloads |

---

## Quick Start

```bash
# Install
pip install mcp-tool-auditor

# Scan a URL-based MCP server
mcp-tool-auditor scan url http://localhost:8080/mcp

# Scan CLI output as markdown report
mcp-tool-auditor scan url http://localhost:8080/mcp --format markdown -o report.md

# Scan all servers in your config
mcp-tool-auditor scan config ~/.config/Claude/claude_desktop_config.json

# Register a baseline fingerprint (rug-pull prevention)
mcp-tool-auditor register url http://localhost:8080/mcp

# Check for rug pulls
mcp-tool-auditor check url http://localhost:8080/mcp

# Generate offensive test servers
mcp-tool-auditor generate all --output-dir ./pentest_servers

**OWASP MCP Top 10 Mapping**
OWASP ID	Issue	Detection
MCP01	Token Mismanagement & Secret Exposure	ST_IGNORE_PREVIOUS, ST_BYPASS, ST_IGNORE_SECURITY
MCP02	Privilege Escalation via Scope Creep	HEUR_AGENCY, credential-related signatures
MCP03	Tool Poisoning	Core focus — all signatures, heuristics, FSP, rug-pull, shadowing
MCP04	Software Supply Chain Attacks	Rug-pull fingerprint mismatch, new tool detection
MCP05	Command Injection & Execution	ST_EXECUTE, ST_SUBPROCESS, ST_EVAL, ST_CURL

**Offensive Testing Examples**

# Start an ATPA simulation server (behavioral poisoning)
mcp-tool-auditor attack atpa --port 8080 --threshold 3

# Start a rug-pull simulation server
mcp-tool-auditor attack rugpull --port 8081 --switch-after 5

# Generate all attack variants as standalone Python servers
mcp-tool-auditor generate all --output-dir ./test_servers
python ./test_servers/server_description_injection.py


