from fgcheck.model import Evidence
from fgcheck.report import findings_to_html, findings_to_human, scan_to_html, scan_to_human
from fgcheck.rules import Finding


def test_findings_to_human_renders_summary_and_explanation():
    findings = [
        Finding(
            rule_id="FGT-ADMIN-EDGE-SSH",
            title="SSH admin on edge",
            severity="high",
            confidence="certain",
            vdom="root",
            message="allowaccess includes ssh on edge interface port1",
            evidence=[
                Evidence(
                    file_id="sample.conf",
                    line_range=(12, 13),
                    path=("vdom", "root", "system", "interface", "port1"),
                    raw_lines=["set allowaccess ping https ssh"],
                )
            ],
        )
    ]

    out = findings_to_human(findings, title="Readable Report", suppressed=2)

    assert "Readable Report" in out
    assert "Summary" in out
    assert "Findings: 1" in out
    assert "FGT-ADMIN-EDGE-SSH" in out
    assert "What it means:" in out
    assert "Why flagged:" in out
    assert "sample.conf lines 12-13" in out
    assert "Suppressed by baseline: 2" in out
    assert "Top Risks First" in out
    assert "[HIGH] FGT-ADMIN-EDGE-SSH: 1 finding(s)" in out


def test_findings_to_human_handles_empty():
    out = findings_to_human([], title="Empty Report", suppressed=3)
    assert "Empty Report" in out
    assert "Suppressed by baseline: 3" in out
    assert "No findings were detected." in out


def test_scan_to_human_renders_folder_summary():
    files = [
        {
            "file": "a.conf",
            "parse_warnings": [],
            "findings": [
                {
                    "rule_id": "FGT-ADMIN-EDGE-SSH",
                    "severity": "high",
                    "confidence": "certain",
                    "message": "allowaccess includes ssh on edge interface port1",
                    "evidence": [{"file_id": "a.conf", "line_range": [33, 33]}],
                }
            ],
        },
        {
            "file": "b.conf",
            "parse_warnings": [{"code": "parse_warning"}],
            "findings": [],
        },
    ]
    summary = {
        "files": 2,
        "findings_total": 3,
        "findings": 1,
        "parse_warnings": 1,
        "highest_severity": "high",
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    out = scan_to_human(files, summary)

    assert "FortiGate Folder Scan" in out
    assert "Files scanned: 2" in out
    assert "Findings: 1" in out
    assert "Findings before suppression: 3" in out
    assert "Highest severity: high" in out
    assert "Parse warnings: 1" in out
    assert "a.conf: findings=1, parse_warnings=0" in out
    assert "b.conf: findings=0, parse_warnings=1" in out
    assert "[HIGH] FGT-ADMIN-EDGE-SSH (certain)" in out
    assert "What it means:" in out
    assert "Evidence: a.conf lines 33-33" in out
    assert "Top Risks First" in out
    assert "[HIGH] FGT-ADMIN-EDGE-SSH: 1 finding(s), files=1" in out


def test_scan_to_human_empty_top_risks():
    out = scan_to_human(
        [{"file": "a.conf", "parse_warnings": [], "findings": []}],
        {
            "files": 1,
            "findings": 0,
            "parse_warnings": 0,
            "suppressed": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
    )
    assert "Top Risks First" in out
    assert "- none" in out


def test_findings_to_html_contains_embedded_document():
    findings = [
        Finding(
            rule_id="FGT-ADMIN-EDGE-SSH",
            title="SSH admin on edge",
            severity="high",
            confidence="certain",
            vdom="root",
            message="allowaccess includes ssh on edge interface port1",
            evidence=[Evidence(file_id="sample.conf", line_range=(12, 12), path=("x",), raw_lines=[])],
        )
    ]
    out = findings_to_html(findings, title="HTML Report", suppressed=1)
    assert "<!doctype html>" in out.lower()
    assert "HTML Report" in out
    assert "Top Risks First" in out
    assert "Suppressed" in out
    assert "FGT-ADMIN-EDGE-SSH" in out


def test_scan_to_html_contains_summary_and_files():
    out = scan_to_html(
        [
            {
                "file": "a.conf",
                "parse_warnings": [],
                "findings": [
                    {
                        "rule_id": "FGT-ADMIN-EDGE-SSH",
                        "severity": "high",
                        "confidence": "certain",
                        "message": "m",
                        "evidence": [{"file_id": "a.conf", "line_range": [1, 1]}],
                    }
                ],
            }
        ],
        {
            "files": 1,
            "findings_total": 1,
            "findings": 1,
            "parse_warnings": 0,
            "suppressed": 0,
            "highest_severity": "high",
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
    )
    assert "<!doctype html>" in out.lower()
    assert "FortiGate Folder Scan" in out
    assert "a.conf" in out
    assert "Top Risks First" in out
