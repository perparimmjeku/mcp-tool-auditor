"""Metrics and statistics collection."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ScanMetrics:
    """Metrics from a single scanner run."""

    timestamp: str
    duration_seconds: float
    tools_scanned: int
    findings_total: int
    findings_by_severity: dict[str, int]
    findings_by_owasp: dict[str, int]
    server_count: int
    success: bool
    error_message: str | None = None

    @classmethod
    def now(
        cls,
        duration_seconds: float,
        tools_scanned: int,
        findings_total: int,
        findings_by_severity: dict[str, int],
        findings_by_owasp: dict[str, int],
        server_count: int,
        success: bool,
        error_message: str | None = None,
    ) -> ScanMetrics:
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_seconds=duration_seconds,
            tools_scanned=tools_scanned,
            findings_total=findings_total,
            findings_by_severity=findings_by_severity,
            findings_by_owasp=findings_by_owasp,
            server_count=server_count,
            success=success,
            error_message=error_message,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary."""
        return asdict(self)


class MetricsCollector:
    """Collects scan metrics in JSONL format."""

    def __init__(self, metrics_file: str | None = None, enabled: bool = True):
        self.enabled = enabled
        self.metrics_file = Path(metrics_file or "~/.mcp-tool-auditor/metrics.jsonl").expanduser()

        if not self.enabled:
            return
        try:
            self.metrics_file.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("Metrics disabled: cannot create %s: %s", self.metrics_file, exc)
            self.enabled = False

    def record(self, metrics: ScanMetrics) -> None:
        """Append scan metrics."""
        if not self.enabled:
            return
        try:
            with self.metrics_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(metrics.to_dict(), sort_keys=True) + "\n")
        except OSError as exc:
            logger.warning("Failed to write metrics to %s: %s", self.metrics_file, exc)

    def get_stats(self, last_n: int = 100) -> dict[str, Any]:
        """Return aggregate statistics from recent scans."""
        if not self.metrics_file.exists():
            return {}

        entries: list[dict[str, Any]] = []
        try:
            with self.metrics_file.open(encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.debug("Skipping malformed metrics line")
        except OSError:
            return {}

        entries = entries[-last_n:]
        if not entries:
            return {}

        return {
            "total_scans": len(entries),
            "successful_scans": sum(1 for entry in entries if entry.get("success")),
            "failed_scans": sum(1 for entry in entries if not entry.get("success")),
            "avg_duration": sum(entry.get("duration_seconds", 0.0) for entry in entries)
            / len(entries),
            "total_tools_scanned": sum(entry.get("tools_scanned", 0) for entry in entries),
            "total_findings": sum(entry.get("findings_total", 0) for entry in entries),
            "last_scan": entries[-1].get("timestamp"),
        }
