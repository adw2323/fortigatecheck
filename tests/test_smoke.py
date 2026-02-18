from pathlib import Path
from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run

def test_edge_admin_ssh_triggers():
    conf = Path("tests/fixtures/bad_edge_admin_on.conf").read_text()
    model, warnings = parse_fortios_text(conf, file_id="bad_edge_admin_on.conf")
    findings = run(model, rule_files=["rules/builtin/FGT-ADMIN-EDGE-SSH.yaml"])
    assert any(f.rule_id == "FGT-ADMIN-EDGE-SSH" for f in findings)
