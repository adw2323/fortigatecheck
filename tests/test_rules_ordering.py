import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


def test_findings_are_returned_in_stable_sorted_order(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system interface": {"fields": {"allowaccess": {"allowed_values": ["ssh", "https", "http", "telnet"]}}},
                "firewall policy": {
                    "fields": {
                        "action": {"allowed_values": ["accept", "deny"]},
                        "srcaddr": {"allowed_values": []},
                        "dstaddr": {"allowed_values": []},
                        "service": {"allowed_values": []},
                        "status": {"allowed_values": ["enable", "disable"]},
                    }
                },
            }
        },
    )
    conf = """
config vdom
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
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []

    findings = run(
        model,
        rule_files=[
            "rules/builtin/FGT-ADMIN-EDGE-ALLACCESS.yaml",
            "rules/builtin/FGT-POLICY-ANY-ANY-ALL.yaml",
        ],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert len(findings) == 2
    assert [(f.vdom, f.rule_id) for f in findings] == [
        ("app", "FGT-POLICY-ANY-ANY-ALL"),
        ("root", "FGT-ADMIN-EDGE-ALLACCESS"),
    ]
