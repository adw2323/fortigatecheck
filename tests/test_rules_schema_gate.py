import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


def test_admin_edge_ssh_degrades_to_heuristic_when_schema_missing(tmp_path: Path):
    conf = Path("tests/fixtures/bad_edge_admin_on.conf").read_text(encoding="utf-8")
    model, warnings = parse_fortios_text(conf, file_id="bad_edge_admin_on.conf")
    assert warnings == []

    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-EDGE-SSH.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].confidence == "heuristic"
    assert findings[0].message.startswith("[schema_unknown]")


def test_admin_edge_ssh_stays_certain_when_schema_confirms_fields(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system interface": {
                    "fields": {
                        "allowaccess": {"allowed_values": ["ssh", "https", "ping"]},
                    }
                }
            }
        },
    )
    conf = Path("tests/fixtures/bad_edge_admin_on.conf").read_text(encoding="utf-8")
    model, warnings = parse_fortios_text(conf, file_id="bad_edge_admin_on.conf")
    assert warnings == []

    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-EDGE-SSH.yaml"],
        fortios_version="7.4.11",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].confidence == "certain"
    assert not findings[0].message.startswith("[schema_unknown]")


def test_admin_edge_ssh_skips_when_schema_loaded_but_field_not_supported(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system interface": {
                    "fields": {
                        "ip": {"allowed_values": []},
                    }
                }
            }
        },
    )
    conf = Path("tests/fixtures/bad_edge_admin_on.conf").read_text(encoding="utf-8")
    model, warnings = parse_fortios_text(conf, file_id="bad_edge_admin_on.conf")
    assert warnings == []

    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-EDGE-SSH.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings == []


def test_admin_edge_ssh_degrades_when_schema_is_table_only_partial(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "coverage": "table_only",
            "tables": {
                "system interface": {
                    "fields": {},
                }
            },
        },
    )
    conf = Path("tests/fixtures/bad_edge_admin_on.conf").read_text(encoding="utf-8")
    model, warnings = parse_fortios_text(conf, file_id="bad_edge_admin_on.conf")
    assert warnings == []

    findings = run(
        model,
        rule_files=["rules/builtin/FGT-ADMIN-EDGE-SSH.yaml"],
        fortios_version="7.4",
        schema_base_dir=tmp_path,
    )
    assert findings
    assert findings[0].confidence == "heuristic"
    assert findings[0].message.startswith("[schema_unknown]")
