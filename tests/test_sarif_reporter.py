import json

from mcp_tool_auditor.auditor.models import Finding, ScanResult, Severity
from mcp_tool_auditor.auditor.reporters.sarif_reporter import SarifReporter


def _results():
    findings = [
        Finding(
            severity=Severity.CRITICAL,
            rule="FSP_DESC_INJECTION",
            message="Tool 'x': injection payload.",
            owasp_id="MCP03",
            attack_type="full_schema_poisoning",
            tool_name="x",
            field="inputSchema.properties.note.description",
        ),
        Finding(
            severity=Severity.MEDIUM,
            rule="HEUR_IMPERATIVE",
            message="Tool 'x': imperative language.",
            owasp_id="MCP03",
            tool_name="x",
        ),
    ]
    return {"server-a": ScanResult(tools_scanned=1, findings=findings)}


def test_sarif_has_valid_top_level_structure():
    doc = json.loads(SarifReporter.generate(_results()))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].startswith("https://")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-tool-auditor"


def test_sarif_dedupes_rules_and_maps_levels():
    run = json.loads(SarifReporter.generate(_results()))["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert sorted(rule_ids) == ["FSP_DESC_INJECTION", "HEUR_IMPERATIVE"]

    by_rule = {res["ruleId"]: res for res in run["results"]}
    assert by_rule["FSP_DESC_INJECTION"]["level"] == "error"  # CRITICAL
    assert by_rule["HEUR_IMPERATIVE"]["level"] == "warning"  # MEDIUM


def test_sarif_includes_owasp_and_location():
    run = json.loads(SarifReporter.generate(_results()))["runs"][0]
    res = next(r for r in run["results"] if r["ruleId"] == "FSP_DESC_INJECTION")
    assert res["properties"]["owasp_id"] == "MCP03"
    loc = res["locations"][0]["logicalLocations"][0]
    assert loc["name"] == "x"


def test_sarif_empty_results_is_valid():
    doc = json.loads(SarifReporter.generate({}))
    assert doc["runs"][0]["results"] == []


def test_sarif_rule_includes_remediation_help():
    run = json.loads(SarifReporter.generate(_results()))["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "FSP_DESC_INJECTION")
    assert "help" in rule and rule["help"]["text"]
