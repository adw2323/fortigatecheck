import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


def test_policy_any_any_all_is_reported_per_vdom(tmp_path: Path):
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
config vdom
    edit root
        config firewall policy
            edit 1
                set action accept
                set srcaddr "all"
                set dstaddr "all"
                set service "ALL"
            next
        end
    next
    edit app
        config firewall policy
            edit 2
                set action accept
                set srcaddr "all"
                set dstaddr "all"
                set service "ALL"
            next
        end
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
    assert len(findings) == 2
    assert {f.vdom for f in findings} == {"root", "app"}
    assert all(f.rule_id == "FGT-POLICY-ANY-ANY-ALL" for f in findings)


def test_admin_edge_allaccess_respects_explicit_vdom_filter(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system interface": {"fields": {"allowaccess": {"allowed_values": ["http", "https", "ssh", "telnet"]}}}
            }
        },
    )
    conf = """
config vdom
    edit root
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
    next
    edit app
        config system interface
            edit "wan2"
                set allowaccess "http" "https" "ssh" "telnet"
            next
        end
        config router static
            edit 1
                set dst 0.0.0.0 0.0.0.0
                set device "wan2"
            next
        end
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []

    findings = run(
        model,
        vdoms=["app"],
        rule_files=["rules/builtin/FGT-ADMIN-EDGE-ALLACCESS.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert len(findings) == 1
    assert findings[0].vdom == "app"
    assert findings[0].rule_id == "FGT-ADMIN-EDGE-ALLACCESS"
