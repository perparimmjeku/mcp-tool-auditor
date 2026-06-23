"""Configuration management for mcp-tool-auditor."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a package dependency
    yaml = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@dataclass
class AuditConfig:
    """Runtime options for scanner behavior."""

    timeout_stdio: int = 10
    timeout_url: int = 15

    desc_length_threshold: int = 500
    param_desc_length_threshold: int = 300
    imperative_count_threshold: int = 2
    agency_count_threshold: int = 3
    authority_count_threshold: int = 2

    fsp_check_enabled: bool = True
    required_check_enabled: bool = True
    enum_check_enabled: bool = True
    default_check_enabled: bool = True

    min_severity: str = "INFO"
    output_format: str = "markdown"
    fingerprint_dir: str | None = None

    def __post_init__(self) -> None:
        if self.fingerprint_dir is None:
            self.fingerprint_dir = os.path.expanduser("~/.mcp-tool-auditor/fingerprints")
        else:
            self.fingerprint_dir = os.path.expanduser(self.fingerprint_dir)
        self.min_severity = str(self.min_severity).upper()
        self.output_format = str(self.output_format).lower()

    @classmethod
    def from_file(cls, path: str) -> AuditConfig:
        """Load config from JSON or YAML."""
        config_path = Path(path).expanduser()
        if not config_path.is_file():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with config_path.open(encoding="utf-8") as fh:
            if config_path.suffix.lower() in {".yaml", ".yml"}:
                text = fh.read()
                raw = yaml.safe_load(text) if yaml is not None else _parse_simple_yaml(text)
                raw = raw or {}
            else:
                raw = json.load(fh)

        if not isinstance(raw, dict):
            raise ValueError("Config root must be a JSON/YAML object")
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> AuditConfig:
        """Create config from flat fields or the repo's nested config.yaml shape."""
        flattened: dict[str, Any] = {}

        auditor = data.get("auditor")
        if isinstance(auditor, dict):
            flattened["min_severity"] = auditor.get("severity_threshold")
            flattened["output_format"] = auditor.get("output_format")

            timeouts = auditor.get("timeouts")
            if isinstance(timeouts, dict):
                flattened["timeout_stdio"] = timeouts.get("stdio")
                flattened["timeout_url"] = timeouts.get("url")

            heuristic = auditor.get("heuristic_analysis")
            if isinstance(heuristic, dict):
                flattened["desc_length_threshold"] = heuristic.get("description_length_threshold")
                flattened["param_desc_length_threshold"] = heuristic.get(
                    "parameter_description_length_threshold"
                )
                flattened["imperative_count_threshold"] = heuristic.get("imperative_threshold")
                flattened["agency_count_threshold"] = heuristic.get("agency_threshold")
                flattened["authority_count_threshold"] = heuristic.get("authority_threshold")

            schema = auditor.get("schema_analysis")
            if isinstance(schema, dict):
                flattened["fsp_check_enabled"] = schema.get("check_fsp_params")
                flattened["required_check_enabled"] = schema.get("check_required_array")
                flattened["enum_check_enabled"] = schema.get("check_enum_values")
                flattened["default_check_enabled"] = schema.get("check_default_values")

            rugpull = auditor.get("rug_pull_detection")
            if isinstance(rugpull, dict):
                flattened["fingerprint_dir"] = rugpull.get("fingerprint_dir")

        known_fields = set(cls.__dataclass_fields__)
        for key, value in data.items():
            if key in known_fields:
                flattened[key] = value

        sanitized = {
            key: value
            for key, value in flattened.items()
            if key in known_fields and value is not None
        }
        return cls(**sanitized)

    def to_file(self, path: str) -> None:
        """Save config as JSON."""
        config_path = Path(path).expanduser()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with config_path.open("w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2, sort_keys=True)


def load_config(config_path: str | None = None) -> AuditConfig:
    """Load configuration from an explicit path, env var, user config, or defaults."""
    candidates: list[str] = []
    if config_path:
        candidates.append(config_path)
    else:
        for env_name in ("MCP_TOOL_AUDITOR_CONFIG", "MCP_AUDITOR_CONFIG"):
            if os.environ.get(env_name):
                candidates.append(os.environ[env_name])
        candidates.extend(
            [
                "~/.mcp-tool-auditor/config.yaml",
                "~/.mcp-tool-auditor/config.json",
            ]
        )

    for candidate in candidates:
        path = Path(candidate).expanduser()
        if not path.is_file():
            if config_path:
                raise FileNotFoundError(f"Config file not found: {path}")
            continue
        try:
            return AuditConfig.from_file(str(path))
        except Exception as exc:
            if config_path:
                raise
            logger.warning("Failed to load config from %s: %s", path, exc)
            return AuditConfig()

    return AuditConfig()


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the repo's simple nested YAML config when PyYAML is unavailable."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip() or ":" not in line:
            continue

        indent = len(line) - len(line.lstrip(" "))
        key, value = line.strip().split(":", 1)
        key = key.strip()
        value = value.strip()

        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if value == "":
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _parse_simple_scalar(value)

    return root


def _parse_simple_scalar(value: str) -> Any:
    value = value.strip().strip('"').strip("'")
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        return int(value)
    except ValueError:
        return value


_global_config: AuditConfig | None = None


def get_config() -> AuditConfig:
    """Return the cached global config."""
    global _global_config
    if _global_config is None:
        _global_config = load_config()
    return _global_config


def set_config(config: AuditConfig) -> None:
    """Override the cached global config."""
    global _global_config
    _global_config = config
