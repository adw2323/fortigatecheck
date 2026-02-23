import json
from pathlib import Path

import pytest

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


SCENARIOS = [
    {
        "rule_file": "rules/builtin/FGT-ADMIN-EDGE-ALLACCESS.yaml",
        "rule_id": "FGT-ADMIN-EDGE-ALLACCESS",
        "schema_tables": {
            "system interface": {"fields": {"allowaccess": {"allowed_values": ["http", "https", "ssh", "telnet"]}}},
        },
        "conf": """
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
""".strip(),
    },
    {
        "rule_file": "rules/builtin/FGT-ADMIN-NO-TRUSTED-HOSTS.yaml",
        "rule_id": "FGT-ADMIN-NO-TRUSTED-HOSTS",
        "schema_tables": {
            "system admin": {"fields": {"trusthost1": {"allowed_values": []}}},
        },
        "conf": """
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
end
""".strip(),
    },
    {
        "rule_file": "rules/builtin/FGT-LOCALIN-NO-PROTECTION.yaml",
        "rule_id": "FGT-LOCALIN-NO-PROTECTION",
        "schema_tables": {
            "firewall local-in-policy": {"fields": {"action": {"allowed_values": ["accept", "deny"]}, "status": {"allowed_values": ["enable", "disable"]}}},
        },
        "conf": """
config firewall local-in-policy
    edit 1
        set action accept
        set status enable
    next
end
""".strip(),
    },
    {
        "rule_file": "rules/builtin/FGT-POLICY-ANY-ANY-ALL.yaml",
        "rule_id": "FGT-POLICY-ANY-ANY-ALL",
        "schema_tables": {
            "firewall policy": {
                "fields": {
                    "action": {"allowed_values": ["accept", "deny"]},
                    "srcaddr": {"allowed_values": []},
                    "dstaddr": {"allowed_values": []},
                    "service": {"allowed_values": []},
                    "status": {"allowed_values": ["enable", "disable"]},
                }
            },
        },
        "conf": """
config firewall policy
    edit 1
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
""".strip(),
    },
    {
        "rule_file": "rules/builtin/FGT-IPSEC-WEAK-DH.yaml",
        "rule_id": "FGT-IPSEC-WEAK-DH",
        "schema_tables": {
            "vpn ipsec phase1-interface": {"fields": {"dhgrp": {"allowed_values": ["2", "14"]}}},
        },
        "conf": """
config vpn ipsec phase1-interface
    edit "p1"
        set dhgrp 2 14
    next
end
""".strip(),
    },
    {
        "rule_file": "rules/builtin/FGT-NO-REMOTE-LOGGING.yaml",
        "rule_id": "FGT-NO-REMOTE-LOGGING",
        "schema_tables": {
            "log syslogd setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
            "log fortianalyzer-cloud setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
        },
        "conf": """
config log syslogd setting
    set status disable
end
config log fortianalyzer-cloud setting
    set status disable
end
""".strip(),
    },
]

SAFE_SCENARIOS = [
    {
        "rule_file": "rules/builtin/FGT-ADMIN-EDGE-ALLACCESS.yaml",
        "schema_tables": {
            "system interface": {"fields": {"allowaccess": {"allowed_values": ["https"]}}},
        },
        "conf": """
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
""".strip(),
    },
    {
        "rule_file": "rules/builtin/FGT-ADMIN-NO-TRUSTED-HOSTS.yaml",
        "schema_tables": {
            "system admin": {"fields": {"trusthost1": {"allowed_values": []}}},
        },
        "conf": """
config system admin
    edit "admin"
        set trusthost1 192.0.2.10 255.255.255.255
    next
end
""".strip(),
    },
    {
        "rule_file": "rules/builtin/FGT-LOCALIN-NO-PROTECTION.yaml",
        "schema_tables": {
            "firewall local-in-policy": {"fields": {"action": {"allowed_values": ["accept", "deny"]}, "status": {"allowed_values": ["enable", "disable"]}}},
        },
        "conf": """
config firewall local-in-policy
    edit 1
        set action deny
        set status enable
    next
end
""".strip(),
    },
    {
        "rule_file": "rules/builtin/FGT-POLICY-ANY-ANY-ALL.yaml",
        "schema_tables": {
            "firewall policy": {
                "fields": {
                    "action": {"allowed_values": ["accept", "deny"]},
                    "srcaddr": {"allowed_values": []},
                    "dstaddr": {"allowed_values": []},
                    "service": {"allowed_values": []},
                    "status": {"allowed_values": ["enable", "disable"]},
                }
            },
        },
        "conf": """
config firewall policy
    edit 1
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
    next
end
""".strip(),
    },
    {
        "rule_file": "rules/builtin/FGT-IPSEC-WEAK-DH.yaml",
        "schema_tables": {
            "vpn ipsec phase1-interface": {"fields": {"dhgrp": {"allowed_values": ["14", "15"]}}},
        },
        "conf": """
config vpn ipsec phase1-interface
    edit "p1"
        set dhgrp 14 15
    next
end
""".strip(),
    },
    {
        "rule_file": "rules/builtin/FGT-NO-REMOTE-LOGGING.yaml",
        "schema_tables": {
            "log syslogd setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
            "log fortianalyzer-cloud setting": {"fields": {"status": {"allowed_values": ["enable", "disable"]}}},
        },
        "conf": """
config log fortianalyzer-cloud setting
    set status enable
end
""".strip(),
    },
]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["rule_id"] for s in SCENARIOS])
def test_requested_rule_matrix_triggers_with_full_schema(tmp_path: Path, scenario: dict):
    _write_schema(tmp_path, "7.4", {"tables": scenario["schema_tables"]})
    model, warnings = parse_fortios_text(scenario["conf"], file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=[scenario["rule_file"]],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].rule_id == scenario["rule_id"]
    assert findings[0].evidence


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["rule_id"] for s in SCENARIOS])
def test_requested_rule_matrix_degrades_under_partial_schema(tmp_path: Path, scenario: dict):
    tables = {k: {"fields": {}} for k in scenario["schema_tables"].keys()}
    _write_schema(
        tmp_path,
        "7.4",
        {
            "coverage": "table_only",
            "tables": tables,
        },
    )
    model, warnings = parse_fortios_text(scenario["conf"], file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=[scenario["rule_file"]],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].confidence == "heuristic"
    assert findings[0].message.startswith("[schema_unknown]")


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["rule_id"] for s in SCENARIOS])
def test_requested_rule_matrix_skips_when_schema_missing_required_support(tmp_path: Path, scenario: dict):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system global": {
                    "fields": {
                        "hostname": {"allowed_values": []},
                    }
                }
            },
        },
    )
    model, warnings = parse_fortios_text(scenario["conf"], file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=[scenario["rule_file"]],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


@pytest.mark.parametrize("scenario", SAFE_SCENARIOS, ids=[s["rule_file"].split("/")[-1] for s in SAFE_SCENARIOS])
def test_requested_rule_matrix_safe_scenarios_do_not_trigger(tmp_path: Path, scenario: dict):
    _write_schema(tmp_path, "7.4", {"tables": scenario["schema_tables"]})
    model, warnings = parse_fortios_text(scenario["conf"], file_id="inline.conf")
    assert warnings == []
    findings = run(
        model,
        rule_files=[scenario["rule_file"]],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []
