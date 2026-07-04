"""Tests for FGT-IFACE-NO-VLAN-SECURITY rule."""

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
                "switch-controller-access-vlan": {},
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
class TestIfaceNoVlanSecurity:
    """Test detection of switch controller interfaces without access VLAN security."""

    def test_no_access_vlan_triggers(self, tmp_path: Path):
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
            rule_files=["rules/builtin/FGT-IFACE-NO-VLAN-SECURITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-IFACE-NO-VLAN-SECURITY"
        assert findings[0].severity == "medium"
        assert findings[0].confidence == "likely"
        assert "port1" in findings[0].message
        assert "access vlan" in findings[0].message.lower()

    def test_access_vlan_disabled_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system interface
    edit "port2"
        set switch-controller-feature lan
        set switch-controller-access-vlan disable
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IFACE-NO-VLAN-SECURITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "port2" in findings[0].message


# ---------------------------------------------------------------------------
# No finding when access VLAN is enabled
# ---------------------------------------------------------------------------
class TestIfaceVlanSecurityEnabled:
    """Test that interfaces with access VLAN enabled produce no findings."""

    def test_access_vlan_enabled_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system interface
    edit "port1"
        set switch-controller-feature lan
        set switch-controller-access-vlan enable
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IFACE-NO-VLAN-SECURITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Non-switch-controller interfaces are ignored
# ---------------------------------------------------------------------------
class TestIfaceNotSwitchController:
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
            rule_files=["rules/builtin/FGT-IFACE-NO-VLAN-SECURITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Multiple interfaces: only switch-controller ones flagged
# ---------------------------------------------------------------------------
class TestIfaceMultiple:
    """Multiple interfaces: only switch-controller ones without VLAN security are flagged."""

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
        set switch-controller-access-vlan enable
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IFACE-NO-VLAN-SECURITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Only port1 should be flagged (port2 has access-vlan enabled, wan1 is not switch-controller)
        assert len(findings) == 1
        assert "port1" in findings[0].message


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestIfaceVlanSchemaHandling:
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
            rule_files=["rules/builtin/FGT-IFACE-NO-VLAN-SECURITY.yaml"],
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
            rule_files=["rules/builtin/FGT-IFACE-NO-VLAN-SECURITY.yaml"],
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
            rule_files=["rules/builtin/FGT-IFACE-NO-VLAN-SECURITY.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) >= 1
        assert findings[0].confidence == "heuristic"

    def test_schema_field_not_supported_skips(self, tmp_path: Path):
        """When switch-controller-access-vlan is not in schema and schema is loaded, skip."""
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
            rule_files=["rules/builtin/FGT-IFACE-NO-VLAN-SECURITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # switch-controller-access-vlan NOT in schema -> skip
        assert findings == []
