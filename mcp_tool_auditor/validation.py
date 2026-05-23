"""Input validation utilities."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path
from urllib.parse import urlparse


class ValidationError(Exception):
    """Raised when user input fails validation."""


def validate_command_exists(command: str) -> str:
    """Validate that a command exists in PATH or at the provided absolute path."""
    if not command:
        raise ValidationError("Command cannot be empty")
    if shutil.which(command) is None:
        raise ValidationError(f"Command '{command}' not found in PATH")
    return command


def validate_file_exists(path: str) -> str:
    """Validate that a file exists and is readable."""
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise ValidationError(f"File not found: {file_path}")
    if not os.access(file_path, os.R_OK):
        raise ValidationError(f"File not readable: {file_path}")
    return str(file_path)


def validate_dir_exists(path: str) -> str:
    """Validate that a directory exists and is readable."""
    dir_path = Path(path).expanduser()
    if not dir_path.is_dir():
        raise ValidationError(f"Directory not found: {dir_path}")
    if not os.access(dir_path, os.R_OK):
        raise ValidationError(f"Directory not readable: {dir_path}")
    return str(dir_path)


def validate_url(url: str) -> str:
    """Validate that a URL is an HTTP or HTTPS URL."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValidationError(f"Invalid URL '{url}': missing scheme or host")
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError(f"Invalid URL '{url}': unsupported scheme '{parsed.scheme}'")
    return url


def validate_json_file(path: str) -> object:
    """Validate and parse a JSON file."""
    file_path = validate_file_exists(path)
    try:
        with open(file_path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"Invalid JSON in {file_path}: {exc.msg} (line {exc.lineno})"
        ) from exc
    except OSError as exc:
        raise ValidationError(f"Cannot read {file_path}: {exc}") from exc


def validate_output_path(path: str, create_dir: bool = True) -> Path:
    """Validate a writable output file path."""
    output_path = Path(path).expanduser()
    parent = output_path.parent
    try:
        if create_dir:
            parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValidationError(f"Cannot create directory {parent}: {exc}") from exc

    if not parent.exists():
        raise ValidationError(f"Parent directory does not exist: {parent}")
    if not os.access(parent, os.W_OK):
        raise ValidationError(f"Parent directory not writable: {parent}")
    return output_path


class ArgparseValidation:
    """Argparse type adapters for validation helpers."""

    @staticmethod
    def command(command: str) -> str:
        try:
            return validate_command_exists(command)
        except ValidationError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc

    @staticmethod
    def file(path: str) -> str:
        try:
            return validate_file_exists(path)
        except ValidationError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc

    @staticmethod
    def directory(path: str) -> str:
        try:
            return validate_dir_exists(path)
        except ValidationError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc

    @staticmethod
    def url(url: str) -> str:
        try:
            return validate_url(url)
        except ValidationError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc
