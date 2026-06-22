"""Remediation guidance for findings, matched by rule prefix with OWASP fallback."""

DEFAULT_REMEDIATION = (
    "Review this tool against your MCP security policy. Confirm the tool comes from a "
    "trusted, pinned source and that its definition and behavior match expectations."
)

# Ordered most-specific prefix first; the first match wins.
_PREFIX_REMEDIATION: list[tuple[str, str]] = [
    (
        "BEHAV_ATPA_TRANSITION",
        "The tool returned benign output on early calls, then poisoned output later — the "
        "ATPA time-bomb pattern. Quarantine the server, pin/revert to a trusted version, and "
        "do not let agents act on tool responses that request reading credentials or files.",
    ),
    (
        "BEHAV_OUTPUT_INJECTION",
        "A tool response contained injection/exfiltration instructions. Treat tool output as "
        "untrusted data, never as instructions; strip or sandbox responses before the agent acts.",
    ),
    (
        "BEHAV_RESPONSE_DIVERGENCE",
        "Identical inputs produced different responses. Confirm the non-determinism is expected "
        "(e.g. live data) and not a server quietly changing behavior between calls.",
    ),
    (
        "BEHAV_CALL_ERROR",
        "One or more tool calls errored during probing. Investigate the server logs; errors can "
        "hide poisoned error messages used by ATPA attacks.",
    ),
    (
        "RUGPULL",
        "Tool definitions changed since the registered baseline. Re-review the server, then "
        "re-register the baseline only after confirming the change is legitimate "
        "(mcp-tool-auditor register).",
    ),
    (
        "FSP",
        "A schema field (parameter name, description, enum, default, or required entry) carries "
        "hidden instructions (Full-Schema Poisoning). Reject the tool and report it to the server "
        "author; do not expose the parameter to the agent.",
    ),
    (
        "SCHEMA",
        "The parameter schema is overly permissive or untyped. Require explicit, constrained types "
        "so the agent cannot be coerced into passing arbitrary values.",
    ),
    (
        "HEUR_UNICODE",
        "Invisible/zero-width Unicode characters were found — a stealth channel for hidden "
        "instructions. Reject the tool; legitimate tools do not need invisible characters.",
    ),
    (
        "HEUR_AUTHORITY_SPOOF",
        "The description claims system/admin authority to coerce the agent. Tool descriptions must "
        "not assert authority; treat this as an attempted authority-spoofing attack.",
    ),
    (
        "HEUR",
        "The description uses imperative/agency language that issues commands to the agent. Tool "
        "descriptions should describe function, not instruct the agent; review and reject if poisoned.",
    ),
    (
        "ST_",
        "A known tool-poisoning signature matched the tool text (e.g. 'ignore previous', 'bypass'). "
        "Reject the tool and report it to the server author.",
    ),
    (
        "CUSTOM",
        "A custom signature matched. Review the configured signature and the matching tool text.",
    ),
]

_OWASP_FALLBACK: dict[str, str] = {
    "MCP01": "Tighten secret handling: never let tool text reference or request credentials/tokens.",
    "MCP02": "Constrain tool scope; isolate high-privilege tools in a separate agent context.",
    "MCP03": "Treat the tool as poisoned: reject it, pin trusted versions, and re-scan before approval.",
    "MCP05": "Block command/code-execution vectors; require server-side allowlists, not prompt rules.",
}


def get_remediation(rule: str, owasp_id: str | None = None, attack_type: str | None = None) -> str:
    """Return remediation guidance for a finding rule."""
    for prefix, text in _PREFIX_REMEDIATION:
        if rule.startswith(prefix):
            return text
    if owasp_id and owasp_id in _OWASP_FALLBACK:
        return _OWASP_FALLBACK[owasp_id]
    return DEFAULT_REMEDIATION


def list_families() -> list[str]:
    """Return the known rule-prefix families that have specific remediation."""
    return [prefix for prefix, _ in _PREFIX_REMEDIATION]
