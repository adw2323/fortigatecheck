"""Tests for FGT-DNS-DEFAULT-ONLY rule."""
import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


_SCHEMA_WITH_FIELDS = {
    "tables": {
        "system dns": {
            "fields": {
                "primary": {},
                "secondary": {},
                "protocol": {},
            }
        }
    }
}


class TestDnsDefaultOnly:
    """Test detection when DNS uses only default public resolvers with cleartext."""

    def test_google_default_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system dns
    set primary 8.8.8.8
    set secondary 8.8.4.4
    set protocol cleartext
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "FGT-DNS-DEFAULT-ONLY"
        assert f.severity == "medium"
        assert f.confidence == "likely"
        assert "8.8.8.8" in f.message
        assert "8.8.4.4" in f.message
        assert "cleartext" in f.message.lower()
        assert f.evidence  # must have evidence with line references

    def test_cloudflare_default_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system dns
    set primary 1.1.1.1
    set secondary 1.0.0.1
    set protocol cleartext
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "1.1.1.1" in findings[0].message

    def test_quad9_default_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system dns
    set primary 9.9.9.9
    set secondary 149.112.112.112
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "9.9.9.9" in findings[0].message

    def test_single_default_primary_only(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system dns
    set primary 8.8.8.8
    set protocol cleartext
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "8.8.8.8" in findings[0].message

    def test_no_protocol_default_triggers(self, tmp_path: Path):
        """When protocol is not set (defaults to cleartext), should still trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system dns
    set primary 8.8.8.8
    set secondary 1.1.1.1
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "cleartext" in findings[0].message.lower()

    def test_encrypted_protocol_still_triggers(self, tmp_path: Path):
        """When protocol is dns-over-tls but servers are default, still triggers."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system dns
    set primary 8.8.8.8
    set secondary 1.1.1.1
    set protocol dns-over-tls
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "dns-over-tls" in findings[0].message
        assert "unreviewed" in findings[0].message.lower()


class TestDnsCustomServer:
    """Test no finding when DNS uses custom/internal resolvers."""

    def test_custom_primary_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system dns
    set primary 10.0.0.53
    set secondary 10.0.1.53
    set protocol cleartext
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_mixed_custom_and_default_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system dns
    set primary 10.0.0.53
    set secondary 8.8.8.8
    set protocol cleartext
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_no_dns_config_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system interface
    edit "wan1"
        set allowaccess https
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_empty_dns_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system dns
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


class TestDnsInGlobalScope:
    """Test detection when DNS config is inside config global block."""

    def test_dns_in_global_scope_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config global
    config system dns
        set primary 8.8.8.8
        set secondary 1.1.1.1
        set protocol cleartext
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-DNS-DEFAULT-ONLY"


class TestDnsSchemaUnknown:
    """Test behavior when schema does not have the table/field."""

    def test_empty_tables_schema_not_loaded(self, tmp_path: Path):
        """When tables dict is empty, schema loads but has no tables → schema unknown."""
        _write_schema(tmp_path, "7.4", {"tables": {}})
        conf = """\
config system dns
    set primary 8.8.8.8
    set secondary 1.1.1.1
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Empty tables dict → schema.loaded = False → treated as schema unknown
        # Rule still runs as heuristic
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert "[schema_unknown]" in findings[0].message

    def test_no_schema_file_uses_heuristic(self, tmp_path: Path):
        """When no schema file exists at all, the rule should still run as heuristic."""
        conf = """\
config system dns
    set primary 8.8.8.8
    set secondary 1.1.1.1
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # load_schema returns SchemaView(loaded=False) when file is missing
        # _schema_supports_field returns (True, True) when schema is None or not loaded
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert "[schema_unknown]" in findings[0].message

    def test_full_coverage_field_missing_skips(self, tmp_path: Path):
        """When schema has full field extraction but field is missing, rule should skip."""
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system dns": {
                    "fields": {"protocol": {}}
                }
            }
        })
        conf = """\
config system dns
    set primary 8.8.8.8
    set secondary 1.1.1.1
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Full coverage schema (not partial/table_only) — field not listed → rule skips
        assert findings == []

    def test_partial_schema_field_missing_runs_heuristic(self, tmp_path: Path):
        """When schema has partial coverage and field is missing, rule runs as heuristic."""
        _write_schema(tmp_path, "7.4", {
            "coverage": "table_only",
            "tables": {
                "system dns": {
                    "fields": {"protocol": {}}
                }
            }
        })
        conf = """\
config system dns
    set primary 8.8.8.8
    set secondary 1.1.1.1
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-DEFAULT-ONLY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Partial schema, field not listed → schema_unknown, rule runs as heuristic
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert "[schema_unknown]" in findings[0].message
