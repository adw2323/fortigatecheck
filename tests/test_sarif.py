"""Tests for SARIF output format."""

from __future__ import annotations

import json

from fgcheck.model import Evidence
from fgcheck.rules import Finding
from fgcheck.sarif import findings_to_sarif


def _make_finding(
    rule_id: str = "FGT-TEST-RULE",
    title: str = "Test finding",
    severity: str = "medium",
    confidence: str = "certain",
    vdom: str = "root",
    message: str = "Test message",
    line_start: int = 10,
) -> Finding:
    ev = [Evidence(file_id="test.conf", line_range=(line_start, line_start), path=(), raw_lines=[])]
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        vdom=vdom,
        message=message,
        evidence=ev,
    )


class TestSARIF:
    def test_valid_json(self):
        findings = [_make_finding()]
        sarif_str = findings_to_sarif(findings)
        data = json.loads(sarif_str)
        assert isinstance(data, dict)

    def test_schema_and_version(self):
        findings = [_make_finding()]
        data = json.loads(findings_to_sarif(findings))
        assert data["$schema"].startswith("https://")
        assert data["version"] == "2.1.0"

    def test_tool_info(self):
        findings = [_make_finding()]
        data = json.loads(findings_to_sarif(findings))
        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "fgcheck"
        assert "version" in tool
        assert "informationUri" in tool

    def test_rules_array(self):
        findings = [_make_finding(rule_id="FGT-A"), _make_finding(rule_id="FGT-B")]
        data = json.loads(findings_to_sarif(findings))
        rule_ids = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
        assert "FGT-A" in rule_ids
        assert "FGT-B" in rule_ids

    def test_results_have_rule_id(self):
        findings = [_make_finding(rule_id="FGT-TEST")]
        data = json.loads(findings_to_sarif(findings))
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "FGT-TEST"

    def test_severity_mapping(self):
        for sev, expected_level in [("critical", "error"), ("high", "error"), ("medium", "warning"), ("low", "note")]:
            findings = [_make_finding(severity=sev)]
            data = json.loads(findings_to_sarif(findings))
            level = data["runs"][0]["results"][0]["level"]
            assert level == expected_level, f"Severity {sev} should map to {expected_level}, got {level}"

    def test_locations_have_line(self):
        findings = [_make_finding(line_start=42)]
        data = json.loads(findings_to_sarif(findings))
        loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 42

    def test_empty_findings(self):
        data = json.loads(findings_to_sarif([]))
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []

    def test_message_text(self):
        findings = [_make_finding(message="This is a security issue")]
        data = json.loads(findings_to_sarif(findings))
        assert data["runs"][0]["results"][0]["message"]["text"] == "This is a security issue"
