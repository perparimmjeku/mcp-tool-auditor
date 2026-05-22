import re
from typing import List, Dict, Any, Tuple
from ..models import Finding, Severity


class StaticAnalyzer:
    """Signature-based static analysis of MCP tool definitions."""

    # Built-in high-severity signature patterns
    HIGH_SIGNATURES: List[Tuple[str, str, str, str]] = [
        (r"always\s+use\s+this\s+tool", "ST_ALWAYS_USE",
         "Tool description contains 'always use this tool' — overriding agent tool selection.",
         "authority_spoofing"),
        (r"send\s+full\s+conversation", "ST_SEND_FULL",
         "Tool description requests complete conversation exfiltration.",
         "data_exfiltration"),
        (r"ignore\s+(previous|all|prior)", "ST_IGNORE_PREVIOUS",
         "Attempt to override prior instructions or security controls.",
         "prompt_injection"),
        (r"ignore\s+security", "ST_IGNORE_SECURITY",
         "Attempt to disable safety guardrails.",
         "security_bypass"),
        (r"authoritative\s+source", "ST_AUTHORITATIVE",
         "False authority claim to manipulate tool selection.",
         "authority_spoofing"),
        (r"\bmust\b", "ST_MUST",
         "Imperative/coercive language forcing agent action.",
         "tool_poisoning"),
        (r"do\s+not\s+(question|tell|inform|notify|ask)", "ST_DO_NOT",
         "Suppressing agent reasoning or user notification.",
         "stealth"),
        (r"you\s+(must|shall|will\s+always|need\s+to|have\s+to)", "ST_YOU_MUST",
         "Imperative instruction directed at the agent.",
         "tool_poisoning"),
        (r"always\s+call", "ST_ALWAYS_CALL",
         "Forcing specific tool invocation.",
         "tool_poisoning"),
        (r"\bbypass\b", "ST_BYPASS",
         "Attempt to circumvent controls.",
         "security_bypass"),
        (r"this\s+is\s+a\s+system\s+(instruction|directive|command)", "ST_SYSTEM_CLAIM",
         "Falsely claiming system-level authority.",
         "authority_spoofing"),
        (r"\boverride\b", "ST_OVERRIDE",
         "Attempting to supersede agent configuration.",
         "tool_poisoning"),
    ]

    # Medium-severity signatures (suspicious capabilities)
    MEDIUM_SIGNATURES: List[Tuple[str, str, str, str]] = [
        (r"read_file|read\s+.*file", "ST_READ_FILE",
         "File read capability mentioned — potential sensitive data access.",
         "sensitive_access"),
        (r"\b(password|secret|token|api_key|ssh|aws)\b", "ST_CREDENTIAL",
         "Credential-related terminology — potential exposure risk.",
         "credential_exposure"),
        (r"send\s+.*http|post\s+.*data|curl", "ST_DATA_EXFIL",
         "Data exfiltration via HTTP.",
         "data_exfiltration"),
        (r"\bexecute|subprocess|os\.system|run\b", "ST_EXECUTE",
         "Command execution indicator.",
         "command_injection"),
        (r"\beval|exec\s*\(", "ST_CODE_EXEC",
         "Dynamic code execution.",
         "code_injection"),
        (r"write_file|delete_file|chmod|sudo", "ST_FILESYSTEM",
         "Filesystem modification capability.",
         "filesystem_access"),
    ]

    # Low-severity signatures (context harvesting / data handling)
    LOW_SIGNATURES: List[Tuple[str, str, str, str]] = [
        (r"full\s+context|entire\s+conversation|all\s+messages", "ST_CONTEXT_HARVEST",
         "Requesting broad context access.",
         "context_harvesting"),
        (r"\b(complete|entire|full)\b", "ST_COMPLETE",
         "May request complete data scope.",
         "context_harvesting"),
        (r"\bsensitive|confidential|private\b", "ST_SENSITIVE",
         "Sensitive/confidential data handling.",
         "data_handling"),
    ]

    def __init__(self, custom_signatures: List[Dict[str, Any]] = None):
        self._custom = custom_signatures or []

    def analyze(self, tool: Dict[str, Any]) -> List[Finding]:
        """Run static analysis on a single tool definition."""
        findings: List[Finding] = []
        tool_name = tool.get("name", "unknown")
        text = self._get_text(tool)

        # Built-in high signatures
        for pattern, rule, msg, atype in self.HIGH_SIGNATURES:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    rule=rule,
                    message=f"Tool '{tool_name}': {msg}",
                    owasp_id="MCP03",
                    attack_type=atype,
                    tool_name=tool_name,
                ))

        # Built-in medium signatures
        for pattern, rule, msg, atype in self.MEDIUM_SIGNATURES:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    rule=rule,
                    message=f"Tool '{tool_name}': {msg}",
                    owasp_id="MCP03",
                    attack_type=atype,
                    tool_name=tool_name,
                ))

        # Built-in low signatures
        for pattern, rule, msg, atype in self.LOW_SIGNATURES:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.LOW,
                    rule=rule,
                    message=f"Tool '{tool_name}': {msg}",
                    owasp_id="MCP03",
                    attack_type=atype,
                    tool_name=tool_name,
                ))

        # Custom signatures
        for cs in self._custom:
            pattern = cs.get("pattern", "")
            rule = cs.get("rule", "CUSTOM")
            msg = cs.get("message", "Custom signature match")
            atype = cs.get("attack_type", "custom")
            severity = Severity(cs.get("severity", "MEDIUM"))
            owasp = cs.get("owasp_id", "MCP03")
            if pattern and re.search(pattern, text, re.IGNORECASE):
                findings.append(Finding(
                    severity=severity,
                    rule=f"CUSTOM_{rule}",
                    message=f"Tool '{tool_name}': {msg}",
                    owasp_id=owasp,
                    attack_type=atype,
                    tool_name=tool_name,
                ))

        return findings

    @staticmethod
    def _get_text(tool: Dict[str, Any]) -> str:
        """Concatenate all text fields from a tool definition."""
        parts = [
            tool.get("name", ""),
            tool.get("title", ""),
            tool.get("description", ""),
        ]
        schema = tool.get("inputSchema", {})
        for prop_name, prop in schema.get("properties", {}).items():
            parts.append(prop_name)
            parts.append(prop.get("description", ""))
        return " ".join(parts)