import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


def test_policy_any_any_all_skips_when_schema_loaded_without_required_fields(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "firewall policy": {
                    "fields": {
                        "action": {"allowed_values": ["accept", "deny"]},
                    }
                }
            }
        },
    )
    conf = """
config firewall policy
    edit 1
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-POLICY-ANY-ANY-ALL.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


def test_requested_rules_degrade_under_partial_schema(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "coverage": "table_only",
            "tables": {
                "system interface": {"fields": {}},
                "system admin": {"fields": {}},
                "firewall local-in-policy": {"fields": {}},
                "firewall policy": {"fields": {}},
                "vpn ipsec phase1-interface": {"fields": {}},
                "log syslogd setting": {"fields": {}},
            },
        },
    )
    conf = """
config system interface
    edit "wan1"
        set allowaccess "http" "https" "ssh" "telnet"
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set device "wan1"
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
end
config firewall local-in-policy
    edit 1
        set action accept
    next
end
config firewall policy
    edit 1
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
config vpn ipsec phase1-interface
    edit "p1"
        set dhgrp 2 14
    next
end
config log syslogd setting
    set status disable
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=[
            "rules/builtin/FGT-ADMIN-EDGE-ALLACCESS.yaml",
            "rules/builtin/FGT-ADMIN-NO-TRUSTED-HOSTS.yaml",
            "rules/builtin/FGT-LOCALIN-NO-PROTECTION.yaml",
            "rules/builtin/FGT-POLICY-ANY-ANY-ALL.yaml",
            "rules/builtin/FGT-IPSEC-WEAK-DH.yaml",
            "rules/builtin/FGT-NO-REMOTE-LOGGING.yaml",
        ],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert all(f.confidence == "heuristic" for f in findings)
    assert all(f.message.startswith("[schema_unknown]") for f in findings)


def test_no_remote_logging_skips_when_schema_has_neither_remote_target(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {"tables": {"system interface": {"fields": {"allowaccess": {"allowed_values": []}}}}},
    )
    conf = """
config log syslogd setting
    set status disable
end
config log fortianalyzer setting
    set status disable
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-NO-REMOTE-LOGGING.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


def test_no_remote_logging_skips_without_explicit_disable_evidence(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "log syslogd setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
                "log fortianalyzer setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
            }
        },
    )
    conf = """
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-NO-REMOTE-LOGGING.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


def test_admin_no_trusted_hosts_skips_without_explicit_admin_evidence(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {"tables": {"system admin": {"fields": {"trusthost1": {"allowed_values": []}}}}},
    )
    conf = """
config system admin
    edit "admin"
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-NO-TRUSTED-HOSTS.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


def test_localin_no_protection_skips_without_explicit_action_or_status_evidence(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "firewall local-in-policy": {
                    "fields": {
                        "action": {"allowed_values": ["accept", "deny"]},
                        "status": {"allowed_values": ["enable", "disable"]},
                    }
                }
            }
        },
    )
    conf = """
config firewall local-in-policy
    edit 1
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-LOCALIN-NO-PROTECTION.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


def test_policy_accept_no_log_includes_evidence_when_logtraffic_unset(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "firewall policy": {
                    "fields": {
                        "action": {"allowed_values": ["accept", "deny"]},
                        "logtraffic": {"allowed_values": ["all", "utm", "disable"]},
                    }
                }
            }
        },
    )
    conf = """
config firewall policy
    edit 1
        set action accept
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-POLICY-LOG-001.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-POLICY-LOG-001"
    assert findings[0].evidence
