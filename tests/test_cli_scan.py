import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fgcheck.cli import main


def test_cli_can_scan_folder_and_emit_summary_json(tmp_path, monkeypatch, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy("tests/fixtures/bad_edge_admin_on.conf", scan_dir / "bad.conf")
    (scan_dir / "good.conf").write_text(
        """
config system interface
    edit "port1"
        set ip 192.0.2.10 255.255.255.0
    next
end
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            str(scan_dir),
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
        ],
    )
    main()
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["summary"]["files"] == 2
    assert payload["summary"]["findings_total"] >= payload["summary"]["findings"]
    assert payload["summary"]["findings"] >= 1
    assert len(payload["files"]) == 2
    assert {Path(f["file"]).name for f in payload["files"]} == {"bad.conf", "good.conf"}


def test_cli_default_rule_pack_loads_without_explicit_rules(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
        ],
    )
    main()
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)
    for finding in payload:
        assert finding.get("evidence")


def test_cli_single_file_human_output(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "human",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
        ],
    )
    main()
    out = capsys.readouterr().out
    assert "FortiGate Findings: bad_edge_admin_on.conf" in out
    assert "Summary" in out
    assert "Findings" in out
    assert "FGT-ADMIN-EDGE-SSH" in out


def test_cli_single_file_html_output(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "html",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
        ],
    )
    main()
    out = capsys.readouterr().out
    assert "<!doctype html>" in out.lower()
    assert "FortiGate Findings: bad_edge_admin_on.conf" in out
    assert "Top Risks First" in out


def test_cli_single_file_human_custom_report_title(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "human",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--report-title",
            "Executive Snapshot",
        ],
    )
    main()
    out = capsys.readouterr().out
    assert "Executive Snapshot" in out


def test_cli_folder_human_output(tmp_path, monkeypatch, capsys):
    scan_dir = tmp_path / "scan_human"
    scan_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy("tests/fixtures/bad_edge_admin_on.conf", scan_dir / "bad.conf")
    (scan_dir / "good.conf").write_text(
        """
config system interface
    edit "port1"
        set ip 192.0.2.10 255.255.255.0
    next
end
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            str(scan_dir),
            "--format",
            "human",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
        ],
    )
    main()
    out = capsys.readouterr().out
    assert "FortiGate Folder Scan" in out
    assert "Files scanned: 2" in out
    assert "bad.conf: findings=" in out
    assert "good.conf: findings=" in out
    assert "FGT-ADMIN-EDGE-SSH" in out
    assert "What it means:" in out


def test_cli_folder_html_output(tmp_path, monkeypatch, capsys):
    scan_dir = tmp_path / "scan_html"
    scan_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy("tests/fixtures/bad_edge_admin_on.conf", scan_dir / "bad.conf")
    (scan_dir / "good.conf").write_text(
        """
config system interface
    edit "port1"
        set ip 192.0.2.10 255.255.255.0
    next
end
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            str(scan_dir),
            "--format",
            "html",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
        ],
    )
    main()
    out = capsys.readouterr().out
    assert "<!doctype html>" in out.lower()
    assert "FortiGate Folder Scan" in out
    assert "bad.conf" in out


def test_cli_folder_html_custom_report_title(tmp_path, monkeypatch, capsys):
    scan_dir = tmp_path / "scan_html_custom"
    scan_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy("tests/fixtures/bad_edge_admin_on.conf", scan_dir / "bad.conf")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            str(scan_dir),
            "--format",
            "html",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--report-title",
            "Client Security Report",
        ],
    )
    main()
    out = capsys.readouterr().out
    assert "Client Security Report" in out


def test_cli_writes_output_file_for_human(tmp_path, monkeypatch):
    out_file = tmp_path / "report.txt"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "human",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--output",
            str(out_file),
        ],
    )
    main()
    text = out_file.read_text(encoding="utf-8")
    assert "FortiGate Findings: bad_edge_admin_on.conf" in text
    assert "Top Risks First" in text


def test_cli_pdf_output_requires_html(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--pdf-output",
            "out.pdf",
        ],
    )
    with pytest.raises(SystemExit):
        main()


def test_cli_quiet_writes_output_without_stdout(tmp_path, monkeypatch, capsys):
    out_file = tmp_path / "quiet_report.txt"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "human",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--output",
            str(out_file),
            "--quiet",
        ],
    )
    main()
    assert capsys.readouterr().out == ""
    text = out_file.read_text(encoding="utf-8")
    assert "FortiGate Findings: bad_edge_admin_on.conf" in text


def test_cli_baseline_suppresses_findings_json(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text('[{"rule_id":"FGT-ADMIN-EDGE-SSH"}]', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--baseline",
            str(baseline),
        ],
    )
    main()
    payload = json.loads(capsys.readouterr().out)
    assert payload == []


def test_cli_single_file_human_shows_suppressed_count(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text('[{"rule_id":"FGT-ADMIN-EDGE-SSH"}]', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "human",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--baseline",
            str(baseline),
        ],
    )
    main()
    out = capsys.readouterr().out
    assert "Suppressed by baseline: 1" in out


def test_cli_can_write_baseline_file(tmp_path, monkeypatch):
    out_file = tmp_path / "baseline_out.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--write-baseline",
            str(out_file),
        ],
    )
    main()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert payload
    assert payload[0]["rule_id"] == "FGT-ADMIN-EDGE-SSH"


def test_cli_baseline_strict_fails_on_unsuppressed_findings(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    baseline.write_text('[{"rule_id":"SOME-OTHER-RULE"}]', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--baseline",
            str(baseline),
            "--baseline-strict",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2


def test_cli_baseline_strict_passes_when_all_suppressed(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    baseline.write_text('[{"rule_id":"FGT-ADMIN-EDGE-SSH"}]', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--baseline",
            str(baseline),
            "--baseline-strict",
        ],
    )
    main()


def test_cli_fail_on_severity_fails_when_threshold_met(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--fail-on-severity",
            "high",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 3


def test_cli_fail_on_severity_passes_when_threshold_not_met(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    baseline.write_text('[{"rule_id":"FGT-ADMIN-EDGE-SSH"}]', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--baseline",
            str(baseline),
            "--fail-on-severity",
            "critical",
        ],
    )
    main()


def test_cli_baseline_update_merges_findings(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    baseline.write_text('[{"rule_id":"FGT-ADMIN-EDGE-HTTPS"}]', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--baseline",
            str(baseline),
            "--baseline-update",
        ],
    )
    main()
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    rule_ids = {p.get("rule_id") for p in payload}
    assert "FGT-ADMIN-EDGE-HTTPS" in rule_ids
    assert "FGT-ADMIN-EDGE-SSH" in rule_ids


def test_cli_baseline_update_requires_baseline(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--baseline-update",
        ],
    )
    with pytest.raises(SystemExit):
        main()


def test_cli_writes_new_findings_output_without_baseline(tmp_path, monkeypatch):
    out_file = tmp_path / "new_findings.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--new-findings-output",
            str(out_file),
        ],
    )
    main()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert payload
    assert payload[0]["rule_id"] == "FGT-ADMIN-EDGE-SSH"


def test_cli_writes_new_findings_output_with_baseline(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    out_file = tmp_path / "new_findings.json"
    baseline.write_text('[{"rule_id":"FGT-ADMIN-EDGE-SSH"}]', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--baseline",
            str(baseline),
            "--new-findings-output",
            str(out_file),
        ],
    )
    main()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload == []


def test_cli_writes_summary_output_single_file(tmp_path, monkeypatch):
    summary_file = tmp_path / "summary.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--summary-output",
            str(summary_file),
        ],
    )
    main()
    payload = json.loads(summary_file.read_text(encoding="utf-8"))
    assert payload["summary"]["files"] == 1
    assert payload["summary"]["findings"] >= 1
    assert payload["summary"]["findings_total"] >= payload["summary"]["findings"]
    assert payload["summary"]["highest_severity"] in {"critical", "high", "medium", "low", "info", "none"}


def test_cli_writes_summary_output_folder(tmp_path, monkeypatch):
    scan_dir = tmp_path / "scan_summary"
    summary_file = tmp_path / "summary_folder.json"
    scan_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy("tests/fixtures/bad_edge_admin_on.conf", scan_dir / "bad.conf")
    (scan_dir / "good.conf").write_text(
        """
config system interface
    edit "port1"
        set ip 192.0.2.10 255.255.255.0
    next
end
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            str(scan_dir),
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--summary-output",
            str(summary_file),
        ],
    )
    main()
    payload = json.loads(summary_file.read_text(encoding="utf-8"))
    assert payload["summary"]["files"] == 2
    assert payload["summary"]["findings_total"] >= payload["summary"]["findings"]
    assert payload["summary"]["highest_severity"] in {"critical", "high", "medium", "low", "info", "none"}


def test_cli_writes_findings_csv_output_single_file(tmp_path, monkeypatch):
    csv_file = tmp_path / "findings.csv"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--findings-csv-output",
            str(csv_file),
        ],
    )
    main()
    text = csv_file.read_text(encoding="utf-8")
    assert "rule_id,severity,confidence,vdom,message,file_id,line_start,line_end" in text
    assert "FGT-ADMIN-EDGE-SSH" in text


def test_cli_writes_findings_csv_output_with_baseline_empty(tmp_path, monkeypatch):
    csv_file = tmp_path / "findings_empty.csv"
    baseline = tmp_path / "baseline.json"
    baseline.write_text('[{"rule_id":"FGT-ADMIN-EDGE-SSH"}]', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--baseline",
            str(baseline),
            "--findings-csv-output",
            str(csv_file),
        ],
    )
    main()
    lines = csv_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert lines[0] == "rule_id,severity,confidence,vdom,message,file_id,line_start,line_end"


def test_cli_folder_markdown_includes_suppression_summary(tmp_path, monkeypatch, capsys):
    scan_dir = tmp_path / "scan_md"
    scan_dir.mkdir(parents=True, exist_ok=True)
    baseline = tmp_path / "baseline.json"
    shutil.copy("tests/fixtures/bad_edge_admin_on.conf", scan_dir / "bad.conf")
    (scan_dir / "good.conf").write_text(
        """
config system interface
    edit "port1"
        set ip 192.0.2.10 255.255.255.0
    next
end
""".strip(),
        encoding="utf-8",
    )
    baseline.write_text('[{"rule_id":"FGT-ADMIN-EDGE-SSH"}]', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            str(scan_dir),
            "--format",
            "md",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
            "--baseline",
            str(baseline),
        ],
    )
    main()
    out = capsys.readouterr().out
    assert "findings_total=1" in out
    assert "suppressed=1" in out
    assert "findings=0" in out


def test_python_module_entrypoint_executes():
    env = dict(**os.environ)
    env["PYTHONPATH"] = "src"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "fgcheck.cli",
            "tests/fixtures/bad_edge_admin_on.conf",
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
        ],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list)
    assert payload
