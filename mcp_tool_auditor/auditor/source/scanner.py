"""Walk a path, pick MCP server source files, and run the language analyzers."""

import os

from ..models import ScanResult
from . import js_analyzer, python_analyzer

_PY_EXT = {".py"}
_JS_EXT = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}


class SourceScanner:
    """Scans MCP server source code for Prompt-In-Shell-Out shell injection."""

    def scan(self, path: str) -> dict[str, ScanResult]:
        findings = []
        scanned = 0
        for fpath in self._collect_files(path):
            ext = os.path.splitext(fpath)[1].lower()
            analyzer = (
                python_analyzer if ext in _PY_EXT else js_analyzer if ext in _JS_EXT else None
            )
            if analyzer is None:
                continue
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    source = fh.read()
            except OSError:
                continue
            if not analyzer.is_mcp_source(source):
                continue
            scanned += 1
            findings.extend(analyzer.analyze(source, fpath))
        return {path: ScanResult(tools_scanned=scanned, findings=findings)}

    @staticmethod
    def _collect_files(path: str) -> list[str]:
        if os.path.isfile(path):
            return [path]
        collected: list[str] = []
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in names:
                if os.path.splitext(name)[1].lower() in (_PY_EXT | _JS_EXT):
                    collected.append(os.path.join(root, name))
        return collected
