import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


def test_sslvpn_min_tls_triggers_when_legacy_protocol_configured(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {"tables": {"vpn ssl settings": {"fields": {"ssl-min-proto-ver": {"allowed_values": ["tls1-0", "tls1-1", "tls1-2", "tls1-3"]}}}}},
    )
    conf = """
config vpn ssl settings
    set ssl-min-proto-ver tls1-0
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-SSLVPN-MIN-TLS.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-SSLVPN-MIN-TLS"
    assert findings[0].confidence == "certain"


def test_local_in_policy_permissive_triggers(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "firewall local-in-policy": {
                    "fields": {
                        "action": {"allowed_values": ["accept", "deny"]},
                        "intf": {"allowed_values": []},
                        "srcaddr": {"allowed_values": []},
                        "service": {"allowed_values": []},
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
        set intf "any"
        set srcaddr "all"
        set service "ALL"
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-LOCAL-IN-PERMISSIVE.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-LOCAL-IN-PERMISSIVE"
    assert findings[0].confidence == "likely"


def test_admin_trusthost_unrestricted_triggers_for_super_admin(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {"tables": {"system admin": {"fields": {"accprofile": {"allowed_values": []}, "trusthost1": {"allowed_values": []}}}}},
    )
    conf = """
config system admin
    edit "admin"
        set accprofile "super_admin"
        set trusthost1 0.0.0.0 0.0.0.0
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-TRUSTHOST-UNRESTRICTED.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-ADMIN-TRUSTHOST-UNRESTRICTED"
    assert findings[0].confidence == "likely"


def test_admin_trusthost_unrestricted_triggers_for_trusthost2(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system admin": {
                    "fields": {
                        "accprofile": {"allowed_values": []},
                        "trusthost1": {"allowed_values": []},
                        "trusthost2": {"allowed_values": []},
                    }
                }
            }
        },
    )
    conf = """
config system admin
    edit "admin"
        set accprofile "super_admin"
        set trusthost2 0.0.0.0 0.0.0.0
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-TRUSTHOST-UNRESTRICTED.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-ADMIN-TRUSTHOST-UNRESTRICTED"
    assert findings[0].confidence == "likely"


def test_new_rules_degrade_when_schema_is_partial(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "coverage": "table_only",
            "tables": {
                "vpn ssl settings": {"fields": {}},
                "firewall local-in-policy": {"fields": {}},
                "system admin": {"fields": {}},
            },
        },
    )
    conf = """
config vpn ssl settings
    set ssl-min-proto-ver tls1-1
end
config firewall local-in-policy
    edit 1
        set action accept
        set intf "any"
        set srcaddr "all"
        set service "ALL"
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set trusthost1 0.0.0.0 0.0.0.0
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=[
            "rules/builtin/FGT-SSLVPN-MIN-TLS.yaml",
            "rules/builtin/FGT-LOCAL-IN-PERMISSIVE.yaml",
            "rules/builtin/FGT-ADMIN-TRUSTHOST-UNRESTRICTED.yaml",
        ],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    ids = {f.rule_id: f for f in findings}
    assert "FGT-SSLVPN-MIN-TLS" in ids
    assert "FGT-LOCAL-IN-PERMISSIVE" in ids
    assert "FGT-ADMIN-TRUSTHOST-UNRESTRICTED" in ids
    assert all(f.confidence == "heuristic" for f in ids.values())


def test_sslvpn_source_interface_any_triggers(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "vpn ssl settings": {
                    "fields": {
                        "status": {"allowed_values": ["enable", "disable"]},
                        "source-interface": {"allowed_values": []},
                    }
                }
            }
        },
    )
    conf = """
config vpn ssl settings
    set status enable
    set source-interface "any"
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-SSLVPN-SRCINTF-ANY.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-SSLVPN-SRCINTF-ANY"
    assert findings[0].confidence == "likely"


def test_sslvpn_source_address_all_triggers(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "vpn ssl settings": {
                    "fields": {
                        "status": {"allowed_values": ["enable", "disable"]},
                        "source-address": {"allowed_values": []},
                        "source-address-negate": {"allowed_values": ["enable", "disable"]},
                    }
                }
            }
        },
    )
    conf = """
config vpn ssl settings
    set status enable
    set source-address "all"
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-SSLVPN-SRCADDR-ALL.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-SSLVPN-SRCADDR-ALL"
    assert findings[0].confidence == "likely"


def test_sslvpn_scope_rules_degrade_when_schema_is_partial(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "coverage": "table_only",
            "tables": {
                "vpn ssl settings": {
                    "fields": {},
                }
            },
        },
    )
    conf = """
config vpn ssl settings
    set status enable
    set source-interface "any"
    set source-address "all"
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=[
            "rules/builtin/FGT-SSLVPN-SRCINTF-ANY.yaml",
            "rules/builtin/FGT-SSLVPN-SRCADDR-ALL.yaml",
        ],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    ids = {f.rule_id: f for f in findings}
    assert "FGT-SSLVPN-SRCINTF-ANY" in ids
    assert "FGT-SSLVPN-SRCADDR-ALL" in ids
    assert all(f.confidence == "heuristic" for f in ids.values())


def test_super_admin_without_two_factor_triggers(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system admin": {
                    "fields": {
                        "accprofile": {"allowed_values": []},
                        "two-factor": {"allowed_values": ["enable", "disable"]},
                    }
                }
            }
        },
    )
    conf = """
config system admin
    edit "admin"
        set accprofile "super_admin"
        set two-factor disable
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-SUPER-NO-2FA.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-ADMIN-SUPER-NO-2FA"
    assert findings[0].confidence == "likely"


def test_super_admin_with_two_factor_enabled_is_not_flagged(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system admin": {
                    "fields": {
                        "accprofile": {"allowed_values": []},
                        "two-factor": {"allowed_values": ["enable", "disable"]},
                    }
                }
            }
        },
    )
    conf = """
config system admin
    edit "admin"
        set accprofile "super_admin"
        set two-factor enable
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-SUPER-NO-2FA.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


def test_admin_edge_telnet_triggers(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {"tables": {"system interface": {"fields": {"allowaccess": {"allowed_values": ["https", "telnet"]}}}}},
    )
    conf = """
config system interface
    edit "wan1"
        set allowaccess "telnet"
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
        rule_files=["rules/builtin/FGT-ADMIN-EDGE-TELNET.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-ADMIN-EDGE-TELNET"
    assert findings[0].confidence == "certain"


def test_admin_edge_http_triggers(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {"tables": {"system interface": {"fields": {"allowaccess": {"allowed_values": ["http", "https"]}}}}},
    )
    conf = """
config system interface
    edit "wan1"
        set allowaccess "http"
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
        rule_files=["rules/builtin/FGT-ADMIN-EDGE-HTTP.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == "FGT-ADMIN-EDGE-HTTP"
    assert findings[0].confidence == "certain"
