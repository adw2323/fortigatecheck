import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


def test_admin_edge_allaccess_triggers(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system interface": {
                    "fields": {"allowaccess": {"allowed_values": ["ping", "http", "https", "ssh", "telnet"]}}
                }
            }
        },
    )
    conf = """
config system interface
    edit "wan1"
        set allowaccess "ping" "http" "https" "ssh" "telnet"
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set device "wan1"
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-EDGE-ALLACCESS.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-ADMIN-EDGE-ALLACCESS"
    assert findings[0].confidence == "certain"
    assert findings[0].evidence


def test_admin_edge_allaccess_not_triggered_for_limited_access(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {"tables": {"system interface": {"fields": {"allowaccess": {"allowed_values": ["ping", "https"]}}}}},
    )
    conf = """
config system interface
    edit "wan1"
        set allowaccess "https"
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set device "wan1"
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-EDGE-ALLACCESS.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


def test_admin_no_trusted_hosts_triggers(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {"tables": {"system admin": {"fields": {"trusthost1": {"allowed_values": []}}}}},
    )
    conf = """
config system admin
    edit "admin"
        set accprofile "super_admin"
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
    assert findings
    assert findings[0].rule_id == "FGT-ADMIN-NO-TRUSTED-HOSTS"
    assert findings[0].confidence == "certain"
    assert findings[0].evidence


def test_admin_no_trusted_hosts_not_triggered_when_trusthost_is_restricted(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {"tables": {"system admin": {"fields": {"trusthost1": {"allowed_values": []}}}}},
    )
    conf = """
config system admin
    edit "admin"
        set trusthost1 192.0.2.10 255.255.255.255
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


def test_admin_no_trusted_hosts_not_triggered_when_trusthost2_is_set(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system admin": {"fields": {"trusthost1": {"allowed_values": []}, "trusthost2": {"allowed_values": []}}}
            }
        },
    )
    conf = """
config system admin
    edit "admin"
        set trusthost2 192.0.2.10 255.255.255.255
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


def test_localin_no_protection_triggers(tmp_path: Path):
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
        set action accept
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
    assert findings
    assert findings[0].rule_id == "FGT-LOCALIN-NO-PROTECTION"
    assert findings[0].confidence == "certain"
    assert findings[0].evidence


def test_localin_no_protection_not_triggered_when_deny_exists(tmp_path: Path):
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
        set action deny
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


def test_policy_any_any_all_triggers(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "firewall policy": {
                    "fields": {
                        "action": {"allowed_values": ["accept", "deny"]},
                        "srcaddr": {"allowed_values": []},
                        "dstaddr": {"allowed_values": []},
                        "service": {"allowed_values": []},
                        "status": {"allowed_values": ["enable", "disable"]},
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
    assert findings
    assert findings[0].rule_id == "FGT-POLICY-ANY-ANY-ALL"
    assert findings[0].confidence == "certain"
    assert findings[0].evidence


def test_policy_any_any_all_not_triggered_when_service_restricted(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "firewall policy": {
                    "fields": {
                        "action": {"allowed_values": ["accept", "deny"]},
                        "srcaddr": {"allowed_values": []},
                        "dstaddr": {"allowed_values": []},
                        "service": {"allowed_values": []},
                        "status": {"allowed_values": ["enable", "disable"]},
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
        set service "HTTPS"
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


def test_ipsec_weak_dh_triggers(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "vpn ipsec phase1-interface": {
                    "fields": {
                        "dhgrp": {"allowed_values": ["1", "2", "5", "14"]},
                        "status": {"allowed_values": ["enable", "disable"]},
                    }
                }
            }
        },
    )
    conf = """
config vpn ipsec phase1-interface
    edit "p1"
        set dhgrp 5 14
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-IPSEC-WEAK-DH.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-IPSEC-WEAK-DH"
    assert findings[0].confidence == "certain"
    assert findings[0].evidence


def test_ipsec_weak_dh_not_triggered_for_strong_group_only(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "vpn ipsec phase1-interface": {
                    "fields": {
                        "dhgrp": {"allowed_values": ["14", "15"]},
                        "status": {"allowed_values": ["enable", "disable"]},
                    }
                }
            }
        },
    )
    conf = """
config vpn ipsec phase1-interface
    edit "p1"
        set dhgrp 14 15
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-IPSEC-WEAK-DH.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


def test_ipsec_weak_dh_ignores_disabled_phase1(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "vpn ipsec phase1-interface": {
                    "fields": {
                        "dhgrp": {"allowed_values": ["2", "14"]},
                        "status": {"allowed_values": ["enable", "disable"]},
                    }
                }
            }
        },
    )
    conf = """
config vpn ipsec phase1-interface
    edit "p1"
        set dhgrp 2 14
        set status disable
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-IPSEC-WEAK-DH.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


def test_ipsec_weak_dh_supports_legacy_phase1_table_path(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "vpn ipsec phase1": {
                    "fields": {
                        "dhgrp": {"allowed_values": ["2", "14"]},
                        "status": {"allowed_values": ["enable", "disable"]},
                    }
                }
            }
        },
    )
    conf = """
config vpn ipsec phase1
    edit "p1"
        set dhgrp 2 14
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-IPSEC-WEAK-DH.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-IPSEC-WEAK-DH"


def test_ipsec_weak_dh_deduplicates_same_phase1_name_across_tables(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "vpn ipsec phase1-interface": {"fields": {"dhgrp": {"allowed_values": ["2", "14"]}}},
                "vpn ipsec phase1": {"fields": {"dhgrp": {"allowed_values": ["2", "14"]}}},
            }
        },
    )
    conf = """
config vpn ipsec phase1-interface
    edit "p1"
        set dhgrp 2 14
    next
end
config vpn ipsec phase1
    edit "p1"
        set dhgrp 2 14
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-IPSEC-WEAK-DH.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert len(findings) == 1


def test_no_remote_logging_triggers_and_clears_when_enabled(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "log syslogd setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
                "log syslogd2 setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
                "log fortianalyzer setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
                "log fortianalyzer2 setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
                "log fortianalyzer-cloud setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
            }
        },
    )
    bad_conf = """
config log syslogd setting
    set status disable
end
config log fortianalyzer setting
    set status disable
end
""".strip()
    model, warnings = parse_fortios_text(bad_conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-NO-REMOTE-LOGGING.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-NO-REMOTE-LOGGING"
    assert findings[0].confidence == "certain"
    assert findings[0].evidence

    good_conf = """
config log syslogd setting
    set status enable
end
""".strip()
    model, warnings = parse_fortios_text(good_conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-NO-REMOTE-LOGGING.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []

    fortigate_cloud_conf = """
config log fortianalyzer-cloud setting
    set status enable
end
""".strip()
    model, warnings = parse_fortios_text(fortigate_cloud_conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-NO-REMOTE-LOGGING.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []

    secondary_target_conf = """
config log syslogd2 setting
    set status enable
end
""".strip()
    model, warnings = parse_fortios_text(secondary_target_conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-NO-REMOTE-LOGGING.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []
