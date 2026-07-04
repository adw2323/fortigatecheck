"""Tests for FGT-DHCP-SNOOP rule."""

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
        "system interface": {
            "fields": {
                "switch-controller-feature": {},
                "switch-controller-dhcp-snooping": {},
            }
        }
    }
}

_SCHEMA_TABLE_ONLY = {
    "coverage": "table_only",
    "tables": {
        "system interface": {"fields": {}},
    },
}

_SCHEMA_EMPTY = {
    "tables": {
        "system interface": {"fields": {}},
    }
}


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------
class TestDhcpSnoop:
    """Test detection of switch controller interfaces without DHCP snooping."""

    def test_no_dhcp_snooping_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system interface
    edit "port1"
        set switch-controller-feature lan
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DHCP-SNOOP.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-DHCP-SNOOP"
        assert findings[0].severity == "medium"
        assert findings[0].confidence == "likely"
        assert "port1" in findings[0].message
        assert "dhcp snooping" in findings[0].message.lower()

    def test_dhcp_snooping_disabled_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system interface
    edit "port2"
        set switch-controller-feature lan
        set switch-controller-dhcp-snooping disable
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DHCP-SNOOP.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "port2" in findings[0].message


# ---------------------------------------------------------------------------
# No finding when DHCP snooping is enabled
# ---------------------------------------------------------------------------
class TestDhcpSnoopEnabled:
    """Test that interfaces with DHCP snooping enabled produce no findings."""

    def test_dhcp_snooping_enabled_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system interface
    edit "port1"
        set switch-controller-feature lan
        set switch-controller-dhcp-snooping enable
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DHCP-SNOOP.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Non-switch-controller interfaces are ignored
# ---------------------------------------------------------------------------
class TestDhcpSnoopNotSwitchController:
    """Test that non-switch-controller interfaces are not flagged."""

    def test_regular_interface_ignored(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system interface
    edit "wan1"
        set role wan
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DHCP-SNOOP.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Multiple interfaces: only switch-controller ones flagged
# ---------------------------------------------------------------------------
class TestDhcpSnoopMultiple:
    """Multiple interfaces: only switch-controller ones without DHCP snooping are flagged."""

    def test_mixed_interfaces(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system interface
    edit "wan1"
        set role wan
    next
    edit "port1"
        set switch-controller-feature lan
    next
    edit "port2"
        set switch-controller-feature lan
        set switch-controller-dhcp-snooping enable
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DHCP-SNOOP.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Only port1 should be flagged (port2 has snooping enabled, wan1 is not switch-controller)
        assert len(findings) == 1
        assert "port1" in findings[0].message


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestDhcpSnoopSchemaHandling:
    """Test schema fallback and degradation."""

    def test_no_interface_block_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DHCP-SNOOP.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_schema_unknown_downgrades_confidence(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_TABLE_ONLY)
        conf = """\
config system interface
    edit "port1"
        set switch-controller-feature lan
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DHCP-SNOOP.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_no_schema_version_uses_heuristic(self, tmp_path: Path):
        """Non-existent schema version -> heuristic."""
        conf = """\
config system interface
    edit "port1"
        set switch-controller-feature lan
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DHCP-SNOOP.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) >= 1
        assert findings[0].confidence == "heuristic"

    def test_schema_field_not_supported_skips(self, tmp_path: Path):
        """When switch-controller-dhcp-snooping is not in schema and schema is loaded, skip."""
        _write_schema(
            tmp_path,
            "7.4",
            {
                "tables": {"system interface": {"fields": {"switch-controller-feature": {}}}},
            },
        )
        conf = """\
config system interface
    edit "port1"
        set switch-controller-feature lan
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DHCP-SNOOP.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # switch-controller-dhcp-snooping NOT in schema -> skip
        assert findings == []
