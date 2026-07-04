"""Tests for FGT-IPS-DEFAULT-SIGNATURE rule."""

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
        "ips sensor": {
            "fields": {},
            "source_url": "https://example.com",
        }
    }
}

_SCHEMA_TABLE_ONLY = {
    "coverage": "table_only",
    "tables": {
        "ips sensor": {"fields": {}},
    },
}


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------
class TestIpsDefaultSignature:
    """Test detection of IPS sensors without custom entries."""

    def test_single_sensor_no_entries_triggers(self, tmp_path: Path):
        """A single sensor with no config entries should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config ips sensor
    edit "default-signature"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-IPS-DEFAULT-SIGNATURE"
        assert findings[0].severity == "medium"
        assert findings[0].confidence == "heuristic"
        assert "default-signature" in findings[0].message
        assert "none contain custom signature entries" in findings[0].message

    def test_multiple_sensors_no_entries_triggers(self, tmp_path: Path):
        """Multiple sensors with no entries should trigger with all names."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config ips sensor
    edit "sensor-a"
    next
    edit "sensor-b"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "sensor-a" in findings[0].message
        assert "sensor-b" in findings[0].message
        assert "2 sensor(s)" in findings[0].message

    def test_sensor_with_set_lines_no_entries_triggers(self, tmp_path: Path):
        """A sensor with set lines but no entries should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config ips sensor
    edit "default-signature"
        set comment 'default sensor'
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "default-signature" in findings[0].message


# ---------------------------------------------------------------------------
# No finding when entries exist
# ---------------------------------------------------------------------------
class TestIpsDefaultSignatureWithEntries:
    """Test that sensors with custom entries produce no findings."""

    def test_sensor_with_entries_no_finding(self, tmp_path: Path):
        """A sensor with config entries should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config ips sensor
    edit "custom-sensor"
        config entries
            edit 1
                set action block
                set log-packet enable
            next
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_one_sensor_with_entries_all_pass(self, tmp_path: Path):
        """Even if one sensor is empty, if any sensor has entries, no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config ips sensor
    edit "empty-sensor"
    next
    edit "custom-sensor"
        config entries
            edit 1
                set action block
            next
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# No IPS sensor table = no finding
# ---------------------------------------------------------------------------
class TestIpsDefaultSignatureNoSensor:
    """Test that configs without IPS sensors produce no findings."""

    def test_no_ips_sensor_block(self, tmp_path: Path):
        """No config ips sensor at all should produce no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_ips_enabled_but_no_sensors(self, tmp_path: Path):
        """IPS global enabled but no sensors defined should produce no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system ips
    set status enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestIpsDefaultSignatureSchemaHandling:
    """Test schema fallback and degradation."""

    def test_schema_unknown_downgrades_confidence(self, tmp_path: Path):
        """Table-only schema should produce heuristic confidence."""
        _write_schema(tmp_path, "7.4", _SCHEMA_TABLE_ONLY)
        conf = """\
config ips sensor
    edit "default-signature"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_no_schema_version_uses_heuristic(self, tmp_path: Path):
        """Non-existent schema version -> heuristic."""
        conf = """\
config ips sensor
    edit "default-signature"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) >= 1
        assert findings[0].confidence == "heuristic"

    def test_no_ips_sensor_in_schema_skips(self, tmp_path: Path):
        """Schema without ips sensor table should skip the rule entirely."""
        _write_schema(
            tmp_path,
            "7.4",
            {
                "tables": {"system interface": {"fields": {"name": {}}}},
            },
        )
        conf = """\
config ips sensor
    edit "default-signature"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # ips sensor table not in schema -> skip
        assert findings == []


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
class TestIpsDefaultSignatureEvidence:
    """Test that evidence is properly attached to findings."""

    def test_finding_has_evidence_with_set_line(self, tmp_path: Path):
        """Finding should include evidence when sensor has set lines."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config ips sensor
    edit "default-signature"
        set comment 'default sensor'
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        # Evidence may be empty if sensor has no set: lines,
        # but with set:comment it should have evidence
        assert len(findings[0].evidence) >= 1

    def test_finding_message_format(self, tmp_path: Path):
        """Finding message should be clear and actionable."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config ips sensor
    edit "default-signature"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        msg = findings[0].message
        # Should mention the sensor name
        assert "default-signature" in msg
        # Should mention "no custom signature entries"
        assert "none contain custom signature entries" in msg
        # Should mention factory defaults
        assert "factory-default" in msg
        # Should recommend action
        assert "Create dedicated IPS sensors" in msg


# ---------------------------------------------------------------------------
# Integration with firewall policies
# ---------------------------------------------------------------------------
class TestIpsDefaultSignatureIntegration:
    """Test IPS sensor check in context of firewall policies."""

    def test_policy_referencing_empty_sensor(self, tmp_path: Path):
        """Firewall policy references IPS sensor that has no entries."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config firewall policy
    edit 1
        set name "allow-web"
        set srcintf "wan1"
        set dstintf "lan"
        set action accept
        set ips-sensor "default-signature"
    next
end
config ips sensor
    edit "default-signature"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Should still trigger — the sensor itself has no entries
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-IPS-DEFAULT-SIGNATURE"
