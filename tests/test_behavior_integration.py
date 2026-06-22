import threading
from http.server import HTTPServer

import pytest

from mcp_tool_auditor.auditor.analyzers.behavioral import BehavioralAnalyzer
from mcp_tool_auditor.auditor.scanner import MCPScanner
from mcp_tool_auditor.config import AuditConfig
from mcp_tool_auditor.offensive.atpa_server import ATPAServerHandler


@pytest.fixture
def atpa_server():
    ATPAServerHandler.call_counts = {}
    ATPAServerHandler.PRODUCTION_THRESHOLD = 3
    server = HTTPServer(("127.0.0.1", 0), ATPAServerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def test_live_probe_detects_atpa_transition(atpa_server):
    scanner = MCPScanner(config=AuditConfig())
    tools, transcripts = scanner.probe_url(atpa_server, calls=5)
    analyzer = BehavioralAnalyzer()
    by_name = {t["name"]: t for t in tools}
    rules = set()
    for name, responses in transcripts.items():
        for finding in analyzer.analyze(by_name[name], responses):
            rules.add(finding.rule)
    assert "BEHAV_ATPA_TRANSITION" in rules
