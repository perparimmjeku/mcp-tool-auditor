import hashlib
import json
import logging
import os
from typing import Any

from ..models import Finding, Severity

logger = logging.getLogger(__name__)


class RugPullDetector:
    """Detects MCP rug-pull attacks by comparing tool schema fingerprints."""

    FINGERPRINT_DIR = os.path.expanduser("~/.mcp-tool-auditor/fingerprints/")

    def __init__(self, fingerprint_dir: str | None = None):
        self._fp_dir = fingerprint_dir or self.FINGERPRINT_DIR

    def _server_id(self, server_url: str) -> str:
        return hashlib.sha256(server_url.encode()).hexdigest()

    def _fingerprint_tool(self, tool: dict[str, Any]) -> str:
        """Create a deterministic hash of a tool definition."""

        def deep_sort(obj):
            if isinstance(obj, dict):
                return {k: deep_sort(v) for k, v in sorted(obj.items())}
            if isinstance(obj, list):
                return [deep_sort(item) for item in obj]
            return obj

        normalized = {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "title": tool.get("title", ""),
            "inputSchema": tool.get("inputSchema", {}),
            "outputSchema": tool.get("outputSchema", {}),
        }
        normalized = deep_sort(normalized)
        return hashlib.sha256(json.dumps(normalized, separators=(",", ":")).encode()).hexdigest()

    def register(self, server_url: str, tools: list[dict[str, Any]]) -> str:
        """Register current tool fingerprints as the approved baseline."""
        registry: dict[str, str] = {}
        for tool in tools:
            registry[tool.get("name", "unknown")] = self._fingerprint_tool(tool)

        os.makedirs(self._fp_dir, exist_ok=True)
        fp_path = os.path.join(self._fp_dir, f"{self._server_id(server_url)}.json")

        temp_path = f"{fp_path}.tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(registry, f, indent=2, sort_keys=True)
            os.replace(temp_path, fp_path)
        except OSError:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise

        logger.info("Registered %d tool fingerprints for %s", len(registry), server_url)
        return fp_path

    def check(self, server_url: str, tools: list[dict[str, Any]]) -> list[Finding]:
        """Compare current tool fingerprints against registered baseline."""
        findings: list[Finding] = []
        fp_path = os.path.join(self._fp_dir, f"{self._server_id(server_url)}.json")

        if not os.path.exists(fp_path):
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    rule="RUGPULL_NO_BASELINE",
                    message=f"Server '{server_url}': No baseline registered — run register() first.",
                    owasp_id="MCP03",
                    attack_type="rug_pull",
                )
            )
            return findings

        try:
            with open(fp_path, encoding="utf-8") as f:
                baseline: dict[str, str] = json.load(f)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Corrupted baseline fingerprint at {fp_path}: {e}. "
                "Run 'mcp-tool-auditor register' to reset it."
            ) from e
        except OSError as e:
            raise RuntimeError(f"Cannot read baseline fingerprint at {fp_path}: {e}") from e

        current_fps = {t.get("name", "unknown"): self._fingerprint_tool(t) for t in tools}

        # New tools (potential shadowing)
        new_tools = set(current_fps.keys()) - set(baseline.keys())
        for name in sorted(new_tools):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    rule="RUGPULL_NEW_TOOL",
                    message=f"Server '{server_url}': New tool '{name}' appeared — possible tool shadowing.",
                    owasp_id="MCP03",
                    attack_type="tool_shadowing",
                )
            )

        # Removed tools
        removed_tools = set(baseline.keys()) - set(current_fps.keys())
        for name in sorted(removed_tools):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    rule="RUGPULL_REMOVED_TOOL",
                    message=f"Server '{server_url}': Tool '{name}' has been removed since baseline registration.",
                    owasp_id="MCP03",
                    attack_type="rug_pull",
                )
            )

        # Changed fingerprints (rug pull!)
        for name, current_fp in current_fps.items():
            if name in baseline:
                if current_fp != baseline[name]:
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            rule="RUGPULL_FINGERPRINT_MISMATCH",
                            message=f"Server '{server_url}': Tool '{name}' schema has CHANGED since baseline — POSSIBLE RUG PULL ATTACK.",
                            owasp_id="MCP03",
                            attack_type="rug_pull",
                        )
                    )

        return findings

    def list_registrations(self) -> dict[str, str]:
        """List all registered server baselines."""
        registrations = {}
        if not os.path.isdir(self._fp_dir):
            return registrations
        for fname in os.listdir(self._fp_dir):
            if fname.endswith(".json"):
                fpath = os.path.join(self._fp_dir, fname)
                with open(fpath) as f:
                    data = json.load(f)
                registrations[fname.replace(".json", "")] = f"{len(data)} tools | {fpath}"
        return registrations
