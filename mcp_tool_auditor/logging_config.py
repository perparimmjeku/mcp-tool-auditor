"""Centralized logging configuration for mcp-tool-auditor."""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


class LoggerFactory:
    """Factory for consistent process-wide logging."""

    _configured = False
    _log_dir: Path | None = None

    @classmethod
    def setup(
        cls,
        level: int = logging.INFO,
        log_file: bool = True,
        log_dir: str | None = None,
    ) -> logging.Logger:
        """Configure the root logger once per process."""
        if cls._configured:
            root = logging.getLogger()
            root.setLevel(level)
            for handler in root.handlers:
                handler.setLevel(level)
            return root

        root = logging.getLogger()
        root.setLevel(level)
        root.handlers.clear()

        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)
        console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        root.addHandler(console_handler)

        if log_file:
            cls._configure_file_handlers(root, level, log_dir)

        cls._configured = True
        return root

    @classmethod
    def _configure_file_handlers(
        cls,
        root: logging.Logger,
        level: int,
        log_dir: str | None,
    ) -> None:
        if log_dir is None:
            log_dir = os.path.expanduser("~/.mcp-tool-auditor/logs")

        cls._log_dir = Path(log_dir)
        try:
            cls._log_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            root.warning("File logging disabled: cannot create %s: %s", cls._log_dir, exc)
            return

        formatter = logging.Formatter(
            fmt="%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        file_handler = logging.handlers.RotatingFileHandler(
            cls._log_dir / "mcp-tool-auditor.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

        json_handler = _JsonLoggingHandler(cls._log_dir / "mcp-tool-auditor.jsonl")
        json_handler.setLevel(level)
        root.addHandler(json_handler)

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """Return a module logger, configuring logging with defaults if needed."""
        if not cls._configured:
            cls.setup()
        return logging.getLogger(name)


class _JsonLoggingHandler(logging.FileHandler):
    """Write structured JSON log records."""

    def __init__(self, filename: Path):
        super().__init__(filename, encoding="utf-8")

    def emit(self, record: logging.LogRecord) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exception"] = self.format(record)

        try:
            self.stream.write(json.dumps(payload, sort_keys=True) + "\n")
            self.flush()
        except Exception:
            self.handleError(record)


def get_logger(name: str) -> logging.Logger:
    """Return a logger for the calling module."""
    return LoggerFactory.get_logger(name)
