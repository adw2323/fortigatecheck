"""Tests for FGT-DLP-NO-SENSOR rule."""
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
        "dlp sensor": {
            "fields": {},
            "source_url": "https://example.com",
        }
    }
}

_SCHEMA_TABLE_ONLY = {
    "coverage": "table_only",
    "tables": {
        "dlp sensor": {"fields": {}},
    },
}


# ---------------------------------------------------------------------------
# Basic detection — sensors without rules
# ---------------------------------------------------------------------------
class TestDlpNoSensor:
    """Test detection of DLP sensors without filter rules."""

    def test_single_sensor_no_rules_triggers(self, tmp_path: Path):
        """A single sensor with no rules should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config dlpsensor sensor
    edit "dlp-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-DLP-NO-SENSOR"
        assert findings[0].severity == "medium"
        assert "dlp-default" in findings[0].message
        assert "none contain filter rules" in findings[0].message

    def test_multiple_sensors_no_rules_triggers(self, tmp_path: Path):
        """Multiple sensors without rules should trigger with all names."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config dlpsensor sensor
    edit "dlp-sensor-a"
    next
    edit "dlp-sensor-b"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "dlp-sensor-a" in findings[0].message
        assert "dlp-sensor-b" in findings[0].message
        assert "2 sensor(s)" in findings[0].message

    def test_sensor_with_set_comment_no_rules_triggers(self, tmp_path: Path):
        """A sensor with set comment but no rules should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config dlpsensor sensor
    edit "dlp-default"
        set comment 'default sensor'
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "dlp-default" in findings[0].message


# ---------------------------------------------------------------------------
# No finding when sensor has rules configured
# ---------------------------------------------------------------------------
class TestDlpNoSensorWithRules:
    """Test that sensors with rules configured produce no findings."""

    def test_sensor_with_rules_no_finding(self, tmp_path: Path):
        """A sensor with rules set should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config dlpsensor sensor
    edit "dlp-custom"
        set rules "dlp-rules" enable
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_sensor_with_profile_protocol_options_no_finding(self, tmp_path: Path):
        """A sensor with profile-protocol-options should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config dlpsensor sensor
    edit "dlp-proto"
        set profile-protocol-options "dlp-protocol-profile"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_sensor_with_both_rules_and_profile_no_finding(self, tmp_path: Path):
        """A sensor with both rules and profile-protocol-options should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config dlpsensor sensor
    edit "dlp-full"
        set rules "dlp-rules" enable
        set profile-protocol-options "dlp-proto"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_one_sensor_with_rules_clears_others(self, tmp_path: Path):
        """If at least one sensor has rules, no finding is raised."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config dlpsensor sensor
    edit "dlp-empty"
    next
    edit "dlp-configured"
        set rules "dlp-rules" enable
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# No DLP sensor table = no finding
# ---------------------------------------------------------------------------
class TestDlpNoSensorNoTable:
    """Test that configs without DLP sensors produce no findings."""

    def test_no_dlp_sensor_block(self, tmp_path: Path):
        """No config dlpsensor sensor at all should produce no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_dlp_settings_only_no_finding(self, tmp_path: Path):
        """DLP settings without sensors should produce no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config dlpsensor settings
    set deep-inspection-options enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestDlpNoSensorSchemaHandling:
    """Test schema fallback and degradation."""

    def test_schema_unknown_downgrades_confidence(self, tmp_path: Path):
        """Table-only schema should produce heuristic confidence."""
        _write_schema(tmp_path, "7.4", _SCHEMA_TABLE_ONLY)
        conf = """\
config dlpsensor sensor
    edit "dlp-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_no_schema_version_uses_heuristic(self, tmp_path: Path):
        """Non-existent schema version -> heuristic."""
        conf = """\
config dlpsensor sensor
    edit "dlp-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) >= 1
        assert findings[0].confidence == "heuristic"

    def test_no_dlp_sensor_in_schema_skips(self, tmp_path: Path):
        """Schema without dlp sensor table should skip the rule entirely."""
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system interface": {"fields": {"name": {}}}
            },
        })
        conf = """\
config dlpsensor sensor
    edit "dlp-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # dlp sensor table not in schema -> skip
        assert findings == []


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
class TestDlpNoSensorEvidence:
    """Test that evidence is properly attached to findings."""

    def test_finding_has_evidence_with_set_line(self, tmp_path: Path):
        """Finding should include evidence when sensor has set lines."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config dlpsensor sensor
    edit "dlp-default"
        set comment 'default sensor'
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        # Evidence should be present from the set:comment line
        assert len(findings[0].evidence) >= 1

    def test_finding_message_format(self, tmp_path: Path):
        """Finding message should be clear and actionable."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config dlpsensor sensor
    edit "dlp-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        msg = findings[0].message
        # Should mention the sensor name
        assert "dlp-default" in msg
        # Should mention no filter rules
        assert "none contain filter rules" in msg
        # Should mention exfiltration
        assert "exfiltration" in msg
        # Should recommend action
        assert "Configure DLP sensors with rules" in msg


# ---------------------------------------------------------------------------
# Integration with firewall policies
# ---------------------------------------------------------------------------
class TestDlpNoSensorIntegration:
    """Test DLP sensor check in context of firewall policies."""

    def test_policy_referencing_dlp_profile(self, tmp_path: Path):
        """Firewall policy with DLP sensor reference, sensor has rules."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config firewall policy
    edit 1
        set name "dlp-inspect"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set dlp-sensor "dlp-active"
    next
end
config dlpsensor sensor
    edit "dlp-active"
        set rules "dlp-rule-group" enable
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Sensor has rules — no finding
        assert findings == []

    def test_policy_with_empty_dlp_sensor(self, tmp_path: Path):
        """Firewall policy with DLP reference but empty sensor should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config firewall policy
    edit 1
        set name "dlp-inspect"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set dlp-sensor "dlp-empty"
    next
end
config dlpsensor sensor
    edit "dlp-empty"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-DLP-NO-SENSOR"
