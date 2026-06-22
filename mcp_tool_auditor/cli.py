#!/usr/bin/env python3
"""
mcp-tool-auditor - MCP Tool Poisoning Scanner
OWASP MCP Top 10 Compliant | Defensive + Offensive tooling
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time

from .auditor.analyzers.behavioral import BehavioralAnalyzer, CallResult
from .auditor.analyzers.rugpull import RugPullDetector
from .auditor.models import ScanResult, Severity
from .auditor.reporters.json_reporter import JSONReporter
from .auditor.reporters.markdown_reporter import MarkdownReporter
from .auditor.scanner import MCPScanner
from .config import load_config, set_config
from .logging_config import LoggerFactory
from .metrics import MetricsCollector, ScanMetrics
from .offensive.poisoner import PoisonedServerGenerator
from .security import print_security_warning, require_ack
from .validation import (
    ArgparseValidation,
    ValidationError,
    validate_json_file,
    validate_output_path,
)

logger = logging.getLogger(__name__)


def _init_logging(debug: bool = False, log_file: bool = True) -> None:
    level = logging.DEBUG if debug else logging.INFO
    LoggerFactory.setup(level=level, log_file=log_file)


def _get_tools_from_result(result):
    """Return raw tool definitions captured during scanning."""
    return getattr(result, "tools", [])


def _print_rugpull_findings(findings) -> None:
    if not findings:
        print("[+] No rug pull detected. Tool fingerprints match baseline.")
        return
    for finding in findings:
        severity = (
            finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        )
        print(f"  [{severity}] {finding.message}")


def _add_scan_options(parser, include_rugpull: bool = False) -> None:
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default=None,
        help="Output format (default: config value or markdown)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Minimum severity to report (default: config value or INFO)",
    )
    if include_rugpull:
        parser.add_argument(
            "--check-rugpull",
            action="store_true",
            help="Also compare URL results against a registered rug-pull baseline",
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-tool-auditor",
        description="MCP Tool Poisoning Scanner - Defensive scanning + offensive pentest tooling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a stdio-based MCP server
  mcp-tool-auditor scan stdio -- npx @modelcontextprotocol/server-filesystem /tmp

  # Scan a URL-based MCP server
  mcp-tool-auditor scan url http://localhost:8080/mcp

  # Scan all servers in a config file (Claude Desktop, Cursor, Windsurf)
  mcp-tool-auditor scan config ~/.config/Claude/claude_desktop_config.json

  # Import a JSON array of tool definitions
  mcp-tool-auditor scan import tools.json

  # Register current tool fingerprints (rug-pull baseline)
  mcp-tool-auditor register url http://localhost:8080/mcp

  # Check for rug pulls against baseline
  mcp-tool-auditor check url http://localhost:8080/mcp

  # Generate offensive pentest servers
  mcp-tool-auditor generate all --output-dir ./poisoned_servers

  # Start an ATPA simulation server
  mcp-tool-auditor attack atpa --port 8080 --threshold 3

  # Start a rug-pull simulation server
  mcp-tool-auditor attack rugpull --port 8081 --switch-after 5
        """,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--config",
        help="Path to mcp-tool-auditor JSON/YAML config",
    )
    parser.add_argument(
        "--no-log-file",
        action="store_true",
        help="Disable log files under ~/.mcp-tool-auditor/logs",
    )
    parser.add_argument(
        "--metrics-file",
        help="Write scan metrics to this JSONL file",
    )
    parser.add_argument(
        "--no-metrics",
        action="store_true",
        help="Disable scan metrics collection",
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan MCP servers for tool poisoning")
    scan_sub = scan_parser.add_subparsers(dest="scan_type")

    stdio_p = scan_sub.add_parser("stdio", help="Scan a stdio-based MCP server")
    stdio_p.add_argument(
        "server_command",
        type=ArgparseValidation.command,
        help="Command to run the server",
    )
    stdio_p.add_argument("args", nargs=argparse.REMAINDER, help="Arguments")

    url_p = scan_sub.add_parser("url", help="Scan a URL-based MCP server")
    url_p.add_argument("url", type=ArgparseValidation.url, help="Server URL")

    config_p = scan_sub.add_parser("config", help="Scan all MCP servers in a config file")
    config_p.add_argument(
        "path",
        type=ArgparseValidation.file,
        help="Path to MCP config file (JSON)",
    )

    import_p = scan_sub.add_parser("import", help="Scan tool definitions from a JSON file")
    import_p.add_argument(
        "path",
        type=ArgparseValidation.file,
        help="Path to JSON file with tool definitions",
    )

    for parser_with_scan_options in (stdio_p, config_p, import_p):
        _add_scan_options(parser_with_scan_options)
    _add_scan_options(url_p, include_rugpull=True)

    reg_parser = subparsers.add_parser(
        "register",
        help="Register tool fingerprints for rug-pull detection",
    )
    reg_sub = reg_parser.add_subparsers(dest="register_type")
    reg_url = reg_sub.add_parser("url", help="Register a URL-based server")
    reg_url.add_argument("url", type=ArgparseValidation.url)
    reg_stdio = reg_sub.add_parser("stdio", help="Register a stdio-based server")
    reg_stdio.add_argument("server_command", type=ArgparseValidation.command)
    reg_stdio.add_argument("args", nargs=argparse.REMAINDER)

    chk_parser = subparsers.add_parser(
        "check",
        help="Check for rug pulls against registered baseline",
    )
    chk_sub = chk_parser.add_subparsers(dest="check_type")
    chk_url = chk_sub.add_parser("url")
    chk_url.add_argument("url", type=ArgparseValidation.url)
    chk_stdio = chk_sub.add_parser("stdio")
    chk_stdio.add_argument("server_command", type=ArgparseValidation.command)
    chk_stdio.add_argument("args", nargs=argparse.REMAINDER)

    gen_parser = subparsers.add_parser(
        "generate",
        help="Generate poisoned MCP servers for authorized testing",
    )
    gen_parser.add_argument(
        "type",
        nargs="?",
        default="all",
        choices=[
            "all",
            "description_injection",
            "full_schema_poisoning",
            "tool_shadowing",
            "rug_pull_prep",
            "atpa_error_based",
        ],
        help="Attack type to generate (default: all)",
    )
    gen_parser.add_argument(
        "--output-dir",
        default="./poisoned_servers",
        help="Output directory for generated servers",
    )
    gen_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for generated server",
    )

    atk_parser = subparsers.add_parser(
        "attack",
        help="Start offensive simulation servers",
    )
    atk_parser.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge authorization warning non-interactively",
    )
    atk_sub = atk_parser.add_subparsers(dest="attack_type")

    atpa_p = atk_sub.add_parser("atpa", help="Start ATPA simulation server")
    atpa_p.add_argument("--port", type=int, default=8080)
    atpa_p.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge authorization warning non-interactively",
    )
    atpa_p.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Number of benign calls before poison triggers",
    )

    rugpull_p = atk_sub.add_parser("rugpull", help="Start rug-pull simulation server")
    rugpull_p.add_argument("--port", type=int, default=8081)
    rugpull_p.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge authorization warning non-interactively",
    )
    rugpull_p.add_argument(
        "--switch-after",
        type=int,
        default=5,
        help="Number of requests before swapping to poisoned tools",
    )

    # --- behavior ---
    beh_parser = subparsers.add_parser(
        "behavior", help="Behavioral/runtime probing for ATPA & response injection"
    )
    beh_sub = beh_parser.add_subparsers(dest="behavior_type")

    beh_stdio = beh_sub.add_parser("stdio", help="Probe a stdio-based MCP server")
    beh_stdio.add_argument("server_command", type=ArgparseValidation.command)
    beh_stdio.add_argument("args", nargs=argparse.REMAINDER)
    beh_url = beh_sub.add_parser("url", help="Probe a URL-based MCP server")
    beh_url.add_argument("url", type=ArgparseValidation.url)
    beh_import = beh_sub.add_parser("import", help="Analyze a recorded response transcript")
    beh_import.add_argument("path", type=ArgparseValidation.file)

    for sub in (beh_stdio, beh_url, beh_import):
        sub.add_argument("--calls", type=int, default=6, help="Calls per tool (default 6)")
        sub.add_argument("--format", choices=["json", "markdown"], default=None)
        sub.add_argument("--severity", default=None)
        sub.add_argument("--output", default=None)
    for sub in (beh_stdio, beh_url):
        sub.add_argument("--yes", action="store_true", help="Assume authorization (skip ack)")

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    _init_logging(debug=args.verbose, log_file=not args.no_log_file)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        config = load_config(args.config)
        set_config(config)
    except Exception as exc:
        logger.error("Failed to load config: %s", exc)
        sys.exit(1)

    metrics_collector = MetricsCollector(
        metrics_file=args.metrics_file,
        enabled=not args.no_metrics,
    )
    scanner = MCPScanner(config=config)

    try:
        if args.command == "scan":
            _handle_scan(args, scanner, config, metrics_collector)
        elif args.command == "register":
            _handle_register(args, scanner)
        elif args.command == "check":
            _handle_check(args, scanner)
        elif args.command == "generate":
            _handle_generate(args)
        elif args.command == "attack":
            _handle_attack(args)
        elif args.command == "behavior":
            _handle_behavior(args, scanner, config)
        else:
            parser.print_help()
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(130)
    except Exception as exc:
        logger.error("%s", exc, exc_info=args.verbose)
        sys.exit(1)


def _handle_scan(args, scanner: MCPScanner, config, metrics_collector: MetricsCollector) -> None:
    start = time.time()
    try:
        results = _run_scan(args, scanner)
        severity = args.severity or config.min_severity
        results = _filter_results(results, severity)

        output_format = args.format or config.output_format
        output = (
            JSONReporter.generate(results)
            if output_format == "json"
            else MarkdownReporter.generate(results)
        )

        if args.output:
            output_path = validate_output_path(args.output)
            output_path.write_text(output, encoding="utf-8")
            print(f"[+] Report written to {output_path}")
        else:
            print(output)

        metrics_collector.record(_metrics_from_results(results, time.time() - start, True))
        logger.info("Scan completed in %.2fs", time.time() - start)
    except Exception as exc:
        metrics_collector.record(
            ScanMetrics.now(
                duration_seconds=time.time() - start,
                tools_scanned=0,
                findings_total=0,
                findings_by_severity={},
                findings_by_owasp={},
                server_count=0,
                success=False,
                error_message=str(exc),
            )
        )
        raise


def _run_scan(args, scanner: MCPScanner):
    if args.scan_type == "stdio":
        result = scanner.scan_server_stdio(args.server_command, args.args)
        return {f"stdio:{args.server_command}": result}
    if args.scan_type == "url":
        result = scanner.scan_server_url(
            args.url,
            check_rugpull=args.check_rugpull,
        )
        return {args.url: result}
    if args.scan_type == "config":
        return scanner.scan_config_file(args.path)
    if args.scan_type == "import":
        data = validate_json_file(args.path)
        if isinstance(data, list):
            tools = data
        elif isinstance(data, dict):
            tools = data.get("tools", data.get("result", {}).get("tools", []))
        else:
            raise ValidationError("Imported JSON must be an object or an array")
        if not isinstance(tools, list):
            raise ValidationError("Imported JSON must contain a tools array")
        return {args.path: scanner.scan_tool_list(tools)}
    raise ValidationError("Specify 'stdio', 'url', 'config', or 'import'")


def _filter_results(results, min_severity: str):
    sev_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }
    severity = sev_map.get(str(min_severity).upper())
    if severity is None:
        raise ValidationError(f"Unknown severity: {min_severity}")
    return {
        name: (
            result.filter_by_severity(severity) if hasattr(result, "filter_by_severity") else result
        )
        for name, result in results.items()
    }


def _metrics_from_results(results, duration: float, success: bool) -> ScanMetrics:
    severity_counts = {}
    owasp_counts = {}
    findings_total = 0
    tools_scanned = 0

    for result in results.values():
        tools_scanned += result.tools_scanned
        findings_total += len(result.findings)
        for severity, count in result.severity_counts.items():
            severity_counts[severity] = severity_counts.get(severity, 0) + count
        for finding in result.findings:
            owasp_counts[finding.owasp_id] = owasp_counts.get(finding.owasp_id, 0) + 1

    return ScanMetrics.now(
        duration_seconds=duration,
        tools_scanned=tools_scanned,
        findings_total=findings_total,
        findings_by_severity=severity_counts,
        findings_by_owasp=owasp_counts,
        server_count=len(results),
        success=success,
    )


def _responses_from_transcript(value) -> list[CallResult]:
    results: list[CallResult] = []
    for i, item in enumerate(value):
        if isinstance(item, str):
            results.append(CallResult(index=i, text=item))
        elif isinstance(item, dict):
            results.append(
                CallResult(index=i, text=str(item.get("text", "")), error=item.get("error"))
            )
        else:
            results.append(CallResult(index=i, text=str(item)))
    return results


def _behavior_result(tools, transcripts, server_url=None) -> ScanResult:
    analyzer = BehavioralAnalyzer()
    by_name = {t.get("name", "unknown"): t for t in tools}
    findings = []
    for name, responses in transcripts.items():
        findings.extend(analyzer.analyze(by_name.get(name, {"name": name}), responses))
    return ScanResult(
        tools_scanned=len(transcripts),
        findings=findings,
        server_url=server_url,
        tools=list(by_name.values()),
    )


def _handle_behavior(args, scanner: MCPScanner, config) -> None:
    if args.behavior_type == "import":
        data = validate_json_file(args.path)
        if not isinstance(data, dict):
            raise ValidationError(
                "Transcript file must be a JSON object mapping tool name to responses"
            )
        transcripts = {name: _responses_from_transcript(v) for name, v in data.items()}
        tools = [{"name": name} for name in transcripts]
        results = {args.path: _behavior_result(tools, transcripts)}
    elif args.behavior_type in {"stdio", "url"}:
        print_security_warning()
        if not require_ack(auto_ack=getattr(args, "yes", False)):
            print("[*] Operation cancelled")
            sys.exit(1)
        if args.behavior_type == "url":
            tools, transcripts = scanner.probe_url(args.url, calls=args.calls)
            results = {args.url: _behavior_result(tools, transcripts, server_url=args.url)}
        else:
            tools, transcripts = scanner.probe_stdio(
                args.server_command, args.args, calls=args.calls
            )
            results = {f"stdio:{args.server_command}": _behavior_result(tools, transcripts)}
    else:
        raise ValidationError("Specify 'stdio', 'url', or 'import'")

    severity = args.severity or config.min_severity
    results = _filter_results(results, severity)
    output_format = args.format or config.output_format
    output = (
        JSONReporter.generate(results)
        if output_format == "json"
        else MarkdownReporter.generate(results)
    )
    if args.output:
        output_path = validate_output_path(args.output)
        output_path.write_text(output, encoding="utf-8")
        print(f"[+] Report written to {output_path}")
    else:
        print(output)


def _handle_register(args, scanner: MCPScanner) -> None:
    detector = RugPullDetector(fingerprint_dir=scanner.config.fingerprint_dir)
    if args.register_type == "url":
        result = scanner.scan_server_url(args.url)
        server_id = args.url
    elif args.register_type == "stdio":
        result = scanner.scan_server_stdio(args.server_command, args.args)
        server_id = f"stdio:{args.server_command} {' '.join(args.args)}"
    else:
        raise ValidationError("Specify 'url' or 'stdio'")

    fingerprint_path = detector.register(server_id, _get_tools_from_result(result))
    print(f"[+] Registered {result.tools_scanned} tools from {server_id}")
    print(f"[+] Fingerprint stored at: {fingerprint_path}")


def _handle_check(args, scanner: MCPScanner) -> None:
    detector = RugPullDetector(fingerprint_dir=scanner.config.fingerprint_dir)
    if args.check_type == "url":
        result = scanner.scan_server_url(args.url)
        findings = detector.check(args.url, _get_tools_from_result(result))
    elif args.check_type == "stdio":
        result = scanner.scan_server_stdio(args.server_command, args.args)
        server_id = f"stdio:{args.server_command} {' '.join(args.args)}"
        findings = detector.check(server_id, _get_tools_from_result(result))
    else:
        raise ValidationError("Specify 'url' or 'stdio'")
    _print_rugpull_findings(findings)


def _handle_generate(args) -> None:
    if args.type == "all":
        output_dir = PoisonedServerGenerator.generate_all_variants(args.output_dir)
        print(f"[+] All attack variants generated in {output_dir}")
        return

    code = PoisonedServerGenerator.generate_server(
        attack_type=args.type,
        port=args.port,
    )
    os.makedirs(args.output_dir, exist_ok=True)
    path = os.path.join(args.output_dir, f"server_{args.type}.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(code)
    print(f"[+] Generated: {path}")
    print(f"\n  To test: python {path}")
    print(f"  Connect any MCP client to: http://localhost:{args.port}")


def _handle_attack(args) -> None:
    if args.yes:
        os.environ["MCP_TOOL_AUDITOR_ASSUME_AUTHORIZED"] = "1"

    if args.attack_type == "atpa":
        from .offensive.atpa_server import main as atpa_main

        sys.argv = [sys.argv[0], str(args.port), str(args.threshold)]
        atpa_main()
    elif args.attack_type == "rugpull":
        from .offensive.rugpull_sim import main as rugpull_main

        sys.argv = [sys.argv[0], str(args.port), str(args.switch_after)]
        rugpull_main()
    else:
        raise ValidationError("Specify 'atpa' or 'rugpull'")


if __name__ == "__main__":
    main()
