"""Tests for FGT-ADMIN-NO-IDLE-TIMEOUT rule."""

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
        "system global": {
            "fields": {
                "admin-idle-timeout": {},
                "hostname": {},
            }
        }
    }
}


class TestIdleTimeoutDisabled:
    """Test detection when admin-idle-timeout is set to 0 (disabled)."""

    def test_timeout_zero_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config global
    config system global
        set admin-idle-timeout 0
        set hostname fw01
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "FGT-ADMIN-NO-IDLE-TIMEOUT"
        assert f.severity == "high"
        assert f.confidence == "likely"
        assert "disabled" in f.message.lower()
        assert f.evidence  # must have evidence with line references

    def test_timeout_zero_in_vdom_scope(self, tmp_path: Path):
        """Test detection when system global is in vdom scope (exported config)."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system global
    set admin-idle-timeout 0
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].severity == "high"


class TestIdleTimeoutExcessive:
    """Test detection when admin-idle-timeout exceeds recommended maximum."""

    def test_timeout_30_minutes_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config global
    config system global
        set admin-idle-timeout 30
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "FGT-ADMIN-NO-IDLE-TIMEOUT"
        assert f.severity == "medium"
        assert "30" in f.message
        assert "15" in f.message  # mentions recommended maximum
        assert f.evidence

    def test_timeout_60_minutes_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config global
    config system global
        set admin-idle-timeout 60
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "60" in findings[0].message


class TestIdleTimeoutAcceptable:
    """Test no finding when admin-idle-timeout is within acceptable range."""

    def test_timeout_5_minutes_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config global
    config system global
        set admin-idle-timeout 5
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_timeout_15_minutes_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config global
    config system global
        set admin-idle-timeout 15
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


class TestIdleTimeoutMissing:
    """Test no finding when admin-idle-timeout is not configured."""

    def test_no_global_block_no_finding(self, tmp_path: Path):
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
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_global_block_without_idle_timeout_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config global
    config system global
        set hostname fw01
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


class TestIdleTimeoutSchemaUnknown:
    """Test behavior when schema does not have the table/field."""

    def test_empty_tables_schema_not_loaded(self, tmp_path: Path):
        """When tables dict is empty, schema loads but has no tables → schema unknown."""
        _write_schema(tmp_path, "7.4", {"tables": {}})
        conf = """\
config global
    config system global
        set admin-idle-timeout 0
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Empty tables dict → schema.loaded = False → treated as schema unknown
        # Rule still runs as heuristic
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert "[schema_unknown]" in findings[0].message

    def test_schema_unknown_field_missing_with_partial(self, tmp_path: Path):
        """When table exists but field is missing and schema is table_only, should run as heuristic."""
        _write_schema(
            tmp_path, "7.4", {"coverage": "table_only", "tables": {"system global": {"fields": {"hostname": {}}}}}
        )
        conf = """\
config global
    config system global
        set admin-idle-timeout 0
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # With partial schema, the field check returns (True, True) — schema_unknown
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert "[schema_unknown]" in findings[0].message

    def test_no_schema_file_uses_heuristic(self, tmp_path: Path):
        """When no schema file exists at all, the rule should still run as heuristic."""
        # Don't write any schema file
        conf = """\
config global
    config system global
        set admin-idle-timeout 0
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
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
        _write_schema(tmp_path, "7.4", {"tables": {"system global": {"fields": {"hostname": {}}}}})
        conf = """\
config global
    config system global
        set admin-idle-timeout 0
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-NO-IDLE-TIMEOUT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Full coverage schema (not partial/table_only) — field not listed → rule skips
        assert findings == []
