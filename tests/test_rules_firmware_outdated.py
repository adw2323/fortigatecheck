"""Tests for FGT-FIRMWARE-OUTDATED rule."""
import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


_SCHEMA_EMPTY = {"tables": {}}


class TestFirmwareOutdatedDetected:
    """Test that outdated firmware is flagged correctly."""

    def test_7_4_3_triggers(self, tmp_path: Path):
        """7.4.3 is 9 patch versions behind 7.4.12 -> high."""
        _write_schema(tmp_path, "7.4", _SCHEMA_EMPTY)
        conf = """\
#config-version=FGT60F-7.4.3-FORTIGATE 7.4.3
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "FGT-FIRMWARE-OUTDATED"
        assert f.severity == "high"
        assert f.confidence == "likely"
        assert "7.4.3" in f.message
        assert "7.4.12" in f.message
        assert f.evidence  # must have evidence with line references

    def test_7_4_0_triggers(self, tmp_path: Path):
        """7.4.0 is very old -> high."""
        _write_schema(tmp_path, "7.4", _SCHEMA_EMPTY)
        conf = """\
#config-version=FGT60F-7.4.0-FORTIGATE 7.4.0
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "7.4.0" in findings[0].message

    def test_7_4_10_triggers_medium(self, tmp_path: Path):
        """7.4.10 is 2 patches behind 7.4.12 -> medium."""
        _write_schema(tmp_path, "7.4", _SCHEMA_EMPTY)
        conf = """\
#config-version=FGT60F-7.4.10-FORTIGATE 7.4.10
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_7_6_1_triggers(self, tmp_path: Path):
        """7.6.1 is 6 patches behind 7.6.7 -> high."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = """\
#config-version=FGT60F-7.6.1-FORTIGATE 7.6.1
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "7.6.1" in findings[0].message
        assert "7.6.7" in findings[0].message


class TestFirmwareUpToDate:
    """Test that up-to-date firmware produces no findings."""

    def test_7_4_12_no_finding(self, tmp_path: Path):
        """7.4.12 is the latest 7.4.x -> no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_EMPTY)
        conf = """\
#config-version=FGT60F-7.4.12-FORTIGATE 7.4.12
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_7_6_7_no_finding(self, tmp_path: Path):
        """7.6.7 is the latest 7.6.x -> no finding."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = """\
#config-version=FGT60F-7.6.7-FORTIGATE 7.6.7
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_8_0_0_no_finding(self, tmp_path: Path):
        """8.0.0 is the latest 8.0.x -> no finding."""
        _write_schema(tmp_path, "8.0", _SCHEMA_EMPTY)
        conf = """\
#config-version=FGT60F-8.0.0-FORTIGATE 8.0.0
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="8.0",
            schema_base_dir=tmp_path,
        )
        assert findings == []


class TestFirmwareNoHeader:
    """Test behavior when no version header is present."""

    def test_family_only_fallback_no_finding(self, tmp_path: Path):
        """Without a header, only the family (e.g. 7.4) is available.
        The rule requires a full 3-component version to compare, so
        it should not fire."""
        _write_schema(tmp_path, "7.4", _SCHEMA_EMPTY)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_no_version_header_and_no_flag_no_finding(self, tmp_path: Path):
        """No header and no --fortios flag -> no version -> no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_EMPTY)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


class TestFirmwareUnknownFamily:
    """Test behavior for unsupported FortiOS version families."""

    def test_7_2_unknown_family_no_finding(self, tmp_path: Path):
        """7.2.x is not in the latest-known table -> skip gracefully."""
        _write_schema(tmp_path, "7.2", _SCHEMA_EMPTY)
        conf = """\
#config-version=FGT60F-7.2.5-FORTIGATE 7.2.5
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="7.2",
            schema_base_dir=tmp_path,
        )
        assert findings == []


class TestFirmwareEvidence:
    """Test that evidence is correctly captured."""

    def test_evidence_contains_header_line(self, tmp_path: Path):
        """Evidence should include the config header line with line number."""
        _write_schema(tmp_path, "7.4", _SCHEMA_EMPTY)
        conf = """\
#config-version=FGT60F-7.4.3-FORTIGATE 7.4.3
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FIRMWARE-OUTDATED.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        ev = findings[0].evidence
        assert len(ev) == 1
        assert ev[0].line_range == (1, 1)
        assert "7.4.3" in ev[0].raw_lines[0]
        assert ev[0].file_id == "inline.conf"
