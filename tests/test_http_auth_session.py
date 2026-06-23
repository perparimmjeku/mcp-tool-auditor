"""Proves auth headers + Mcp-Session-Id + MCP-Protocol-Version are sent correctly."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mcp_tool_auditor.auditor.scanner import MCPScanner
from mcp_tool_auditor.config import AuditConfig


class AuthSessionHandler(BaseHTTPRequestHandler):
    SESSION = "sess-abc123"

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        method = body.get("method")

        # Require auth on every request
        if self.headers.get("Authorization") != "Bearer secret":
            self._send(401, {"error": {"code": -32001, "message": "unauthorized"}})
            return

        if method == "initialize":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", self.SESSION)
            self.end_headers()
            self.wfile.write(
                json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": {}}).encode()
            )
            return

        # Post-initialize requests must carry session id + protocol version
        if self.headers.get("Mcp-Session-Id") != self.SESSION:
            self._send(400, {"error": {"code": -32002, "message": "missing session"}})
            return
        if not self.headers.get("MCP-Protocol-Version"):
            self._send(400, {"error": {"code": -32003, "message": "missing protocol version"}})
            return

        if method == "tools/list":
            self._send(200, {"tools": [{"name": "ping", "description": "ping"}]})
        else:
            self._send(200, {})

    def _send(self, code, result):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), AuthSessionHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_scan_with_auth_header_and_session(server):
    scanner = MCPScanner(config=AuditConfig())
    result = scanner.scan_server_url(server, extra_headers={"Authorization": "Bearer secret"})
    assert result.tools_scanned == 1


def test_scan_without_auth_header_fails(server):
    scanner = MCPScanner(config=AuditConfig())
    with pytest.raises(RuntimeError):
        scanner.scan_server_url(server)
