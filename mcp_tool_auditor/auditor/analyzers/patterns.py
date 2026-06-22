"""Shared regex pattern libraries for poisoning detection.

Definition-text heuristics are consumed by HeuristicAnalyzer (over tool
definitions); scan_response is consumed by BehavioralAnalyzer (over tool
responses).
"""

import re

# --- Definition-text heuristics (moved verbatim from HeuristicAnalyzer) ---
IMPERATIVE_PATTERNS = [
    r"\b(must|always|never|required|mandatory)\b",
    r"\b(you (shall|will|need to|have to))\b",
    r"\b(do not|don't|should not)\b",
]

AGENCY_PATTERNS = [
    r"\b(send|post|upload|exfiltrate)\b",
    r"\b(read|write|delete|modify)\b",
    r"\b(access|retrieve|fetch|download)\b",
]

AUTHORITY_PATTERNS = [
    r"\b(system|admin|root|supervisor|compliance|audit)\b",
    r"\b(official|authoritative|certified|approved)\b",
]

UNICODE_SUSPECT = re.compile(r"[​‌‍⁠⁡⁢⁣⁤﻿]")

# --- Response/behavioral injection indicators: (label, compiled regex) ---
_RESPONSE_INJECTION: list[tuple[str, re.Pattern]] = [
    (
        "instruction_override",
        re.compile(
            r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "agent_directive",
        re.compile(
            r"\b(you must|you should|please (read|provide|append|send)|in order to)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "credential_reference",
        re.compile(
            r"(\.ssh/|id_rsa|id_ed25519|\.aws/credentials|aws_access_key|"
            r"\b(api[_-]?key|secret|token|password|credential)s?\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "exfiltration",
        re.compile(
            r"\b(send|upload|post|exfiltrate|forward|email)\b[^.\n]{0,40}"
            r"(https?://|@|to the|to this|endpoint|server)",
            re.IGNORECASE,
        ),
    ),
    (
        "file_read_directive",
        re.compile(r"\b(read_file|read the .{0,20}file|append the content)\b", re.IGNORECASE),
    ),
]


def scan_response(text: str) -> list[str]:
    """Return labels of injection/exfil indicators present in a tool response."""
    if not text:
        return []
    return [label for label, rx in _RESPONSE_INJECTION if rx.search(text)]
