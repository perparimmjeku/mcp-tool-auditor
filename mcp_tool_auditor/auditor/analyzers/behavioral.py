"""Behavioral/runtime analysis of MCP tool responses (ATPA detection)."""

from dataclasses import dataclass
from typing import Any

from ..models import Finding, Severity
from . import patterns


@dataclass
class CallResult:
    """One invocation of a tool: its 0-based index, response text, and error."""

    index: int
    text: str
    error: str | None = None


_DUMMY_BY_TYPE: dict[str, Any] = {
    "string": "test",
    "integer": 1,
    "number": 1,
    "boolean": True,
    "array": [],
    "object": {},
    "null": None,
}


def synthesize_arguments(input_schema: Any) -> dict[str, Any]:
    """Build minimal valid dummy arguments from a JSON-Schema inputSchema."""
    if not isinstance(input_schema, dict):
        return {}
    props = input_schema.get("properties", {})
    if not isinstance(props, dict):
        return {}
    args: dict[str, Any] = {}
    for pname, spec in props.items():
        if not isinstance(spec, dict):
            args[pname] = "test"
        elif "default" in spec:
            args[pname] = spec["default"]
        elif spec.get("enum"):
            args[pname] = spec["enum"][0]
        else:
            args[pname] = _DUMMY_BY_TYPE.get(spec.get("type", "string"), "test")
    return args


class BehavioralAnalyzer:
    """Detects ATPA time-bomb behavior and injection content in tool responses."""

    def analyze(self, tool: dict[str, Any], responses: list[CallResult]) -> list[Finding]:
        name = tool.get("name", "unknown")
        findings: list[Finding] = []

        successful = [r for r in responses if r.error is None]
        errored = [r for r in responses if r.error is not None]

        injections = [(r.index, patterns.scan_response(r.text)) for r in successful]
        injections = [(idx, labels) for idx, labels in injections if labels]

        if injections:
            injection_indices = {idx for idx, _ in injections}
            first_idx, first_labels = min(injections, key=lambda x: x[0])
            prior_benign = [
                r for r in successful if r.index < first_idx and r.index not in injection_indices
            ]
            if prior_benign:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        rule="BEHAV_ATPA_TRANSITION",
                        message=(
                            f"Tool '{name}': benign for {len(prior_benign)} call(s), then call "
                            f"#{first_idx + 1} returned poisoned content "
                            f"({', '.join(first_labels)}) — ATPA time-bomb behavior."
                        ),
                        owasp_id="MCP03",
                        attack_type="atpa",
                        tool_name=name,
                    )
                )
            else:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        rule="BEHAV_OUTPUT_INJECTION",
                        message=(
                            f"Tool '{name}': response contains injection/exfil indicators "
                            f"({', '.join(first_labels)})."
                        ),
                        owasp_id="MCP03",
                        attack_type="behavioral_injection",
                        tool_name=name,
                    )
                )
        else:
            texts = {r.text for r in successful}
            if len(successful) > 1 and len(texts) > 1:
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        rule="BEHAV_RESPONSE_DIVERGENCE",
                        message=(
                            f"Tool '{name}': identical inputs produced {len(texts)} different "
                            f"responses across {len(successful)} calls — non-deterministic behavior."
                        ),
                        owasp_id="MCP03",
                        attack_type="behavioral_nondeterminism",
                        tool_name=name,
                    )
                )

        if errored:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    rule="BEHAV_CALL_ERROR",
                    message=(
                        f"Tool '{name}': {len(errored)} of {len(responses)} call(s) errored "
                        f"(e.g. {errored[0].error})."
                    ),
                    owasp_id="N/A",
                    attack_type="behavioral_error",
                    tool_name=name,
                )
            )

        return findings
