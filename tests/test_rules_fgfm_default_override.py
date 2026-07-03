"""Tests for FGT-FGFM-DEFAULT-OVERRIDE rule."""
import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


_SCHEMA_WITH_TABLE = {
    "tables": {
        "system fortimanager": {
            "fields": {
                "default-override": {},
                "status": {},
                "server": {},
            }
        }
    }
}

_SCHEMA_TABLE_ONLY = {
    "coverage": "table_only",
    "tables": {
        "system fortimanager": {"fields": {}},
    },
}

_SCHEMA_NO_TABLE = {
    "tables": {}
}


# ---------------------------------------------------------------------------
# Signal: default-override enabled
# ---------------------------------------------------------------------------
class TestFGFMDefaultOverrideEnabled:
    """Test detection of FortiManager default-override being enabled."""

    def test_override_enable_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system fortimanager
    set status enable
    set server "10.0.0.100"
    set serial "FMGVM0000000000"
    set default-override enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-FGFM-DEFAULT-OVERRIDE"
        assert findings[0].severity == "medium"
        assert findings[0].confidence == "likely"
        assert "10.0.0.100" in findings[0].message
        assert "default-override" in findings[0].message
        assert findings[0].evidence

    def test_override_enable_with_status_active(self, tmp_path: Path):
        """When both status and default-override are enabled, message mentions active connection."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system fortimanager
    set status enable
    set server "10.0.0.100"
    set default-override enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "connection is active" in findings[0].message

    def test_override_enable_with_status_absent(self, tmp_path: Path):
        """default-override enabled but status not set — still triggers."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system fortimanager
    set server "10.0.0.100"
    set default-override enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        # Status not enabled -> no "connection is active" in message
        assert "connection is active" not in findings[0].message

    def test_override_enable_with_server_unknown(self, tmp_path: Path):
        """default-override enabled without server field — uses 'unknown'."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system fortimanager
    set default-override enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "unknown" in findings[0].message

    def test_override_enable_with_serial(self, tmp_path: Path):
        """default-override enabled with serial number — triggers."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system fortimanager
    set status enable
    set server "10.0.0.100"
    set serial "FMGVM0000000000"
    set default-override enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# No findings: default-override disabled or absent
# ---------------------------------------------------------------------------
class TestFGFMDefaultOverrideDisabled:
    """Test that disabled or absent default-override produces no findings."""

    def test_override_disable_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system fortimanager
    set status enable
    set server "10.0.0.100"
    set default-override disable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_override_absent_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system fortimanager
    set status enable
    set server "10.0.0.100"
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_no_fortimanager_config_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_empty_fortimanager_no_finding(self, tmp_path: Path):
        """FortiManager config section exists but is completely empty."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system fortimanager
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestFGFMDefaultOverrideSchema:
    """Test schema fallback and degradation behavior."""

    def test_schema_unknown_downgrades_confidence(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_TABLE_ONLY)
        conf = """\
config system fortimanager
    set status enable
    set server "10.0.0.100"
    set default-override enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_no_schema_version_uses_heuristic(self, tmp_path: Path):
        conf = """\
config system fortimanager
    set status enable
    set server "10.0.0.100"
    set default-override enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_schema_field_not_supported_skips(self, tmp_path: Path):
        """When the table exists but default-override field is not in the schema and schema is loaded, skip."""
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system fortimanager": {"fields": {"status": {}, "server": {}}}
            },
        })
        conf = """\
config system fortimanager
    set status enable
    set server "10.0.0.100"
    set default-override enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# VDOM scope
# ---------------------------------------------------------------------------
class TestFGFMDefaultOverrideVDOM:
    """Test FGT-FGFM-DEFAULT-OVERRIDE across VDOMs."""

    def test_per_vdom_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config vdom
    edit "root"
        config system fortimanager
            set status enable
            set server "10.0.0.100"
            set default-override enable
        end
    next
    edit "vdom1"
        config system fortimanager
            set status enable
            set server "10.0.0.200"
            set default-override disable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        root_findings = [f for f in findings if f.vdom == "root"]
        vdom1_findings = [f for f in findings if f.vdom == "vdom1"]
        assert len(root_findings) == 1
        assert "10.0.0.100" in root_findings[0].message
        assert vdom1_findings == []

    def test_both_vdoms_flagged(self, tmp_path: Path):
        """Both VDOMs have override enabled — both flagged."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config vdom
    edit "root"
        config system fortimanager
            set status enable
            set default-override enable
        end
    next
    edit "vdom1"
        config system fortimanager
            set status enable
            set default-override enable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 2
        vdoms = {f.vdom for f in findings}
        assert vdoms == {"root", "vdom1"}
