"""Tests for FGT-SNMP-NO-ACL rule."""

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
        "system snmp community": {
            "fields": {
                "name": {},
                "hosts": {},
            }
        }
    }
}

_SCHEMA_TABLE_ONLY = {
    "coverage": "table_only",
    "tables": {
        "system snmp community": {"fields": {}},
    },
}


# ---------------------------------------------------------------------------
# Signal 1: hosts field set to 0.0.0.0/0 (unrestricted)
# ---------------------------------------------------------------------------
class TestSNMPNoACLUnrestricted:
    """Test detection of SNMP communities with 0.0.0.0/0 hosts ACL."""

    def test_hosts_0000_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system snmp community
    edit 1
        set name "wide-open"
        set hosts 0.0.0.0 0.0.0.0
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-SNMP-NO-ACL"
        assert findings[0].severity == "medium"
        assert findings[0].confidence == "likely"
        assert "wide-open" in findings[0].message
        assert "0.0.0.0/0" in findings[0].message
        assert findings[0].evidence

    def test_hosts_wildcard_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system snmp community
    edit 1
        set name "open"
        set hosts 0.0.0.0 255.255.255.255
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # 0.0.0.0 with wildcard mask = unrestricted
        assert len(findings) == 1
        assert "open" in findings[0].message


# ---------------------------------------------------------------------------
# Specific hosts ACL - no findings
# ---------------------------------------------------------------------------
class TestSNMPNoACLSpecific:
    """Test that communities with specific hosts ACL produce no findings."""

    def test_specific_host_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system snmp community
    edit 1
        set name "restricted"
        set hosts 10.0.0.1 255.255.255.255
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_specific_subnet_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system snmp community
    edit 1
        set name "mgmt-only"
        set hosts 10.0.0.0 255.255.255.0
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Signal 2: no hosts field AND no hosts sub-table - all communities flagged
# ---------------------------------------------------------------------------
class TestSNMPNoACLNoHostsAtAll:
    """Test detection when communities have no hosts configured anywhere."""

    def test_no_hosts_anywhere_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system snmp community
    edit 1
        set name "open-community"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "open-community" in findings[0].message
        assert "no host ACL" in findings[0].message

    def test_multiple_no_hosts_all_flagged(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system snmp community
    edit 1
        set name "comm1"
    next
    edit 2
        set name "comm2"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 2
        names = {f.message.split('"')[1] for f in findings}
        assert names == {"comm1", "comm2"}


# ---------------------------------------------------------------------------
# Mixed: sub-table hosts exist - skip Signal 2 to avoid false positives
# ---------------------------------------------------------------------------
class TestSNMPNoACLSubTableExist:
    """When hosts sub-table exists, we skip no-field communities (parser flattening)."""

    def test_hosts_sub_table_skips_no_field_community(self, tmp_path: Path):
        """Community without hosts field but hosts sub-table exists -> no finding
        (cant tell which community owns the hosts entries)."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system snmp community
    edit 1
        set name "unknown-acl"
        config hosts
            edit 1
                set ip 10.0.0.1 255.255.255.255
            next
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # hosts sub-table exists -> we skip Signal 2 to avoid false positives
        assert findings == []


# ---------------------------------------------------------------------------
# No SNMP communities - no findings
# ---------------------------------------------------------------------------
class TestSNMPNoACLNoCommunity:
    """No SNMP community config should produce no findings."""

    def test_no_communities_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestSNMPNoACLSchemaHandling:
    """Test schema fallback and degradation."""

    def test_schema_unknown_downgrades_confidence(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_TABLE_ONLY)
        conf = """\
config system snmp community
    edit 1
        set name "open"
        set hosts 0.0.0.0 0.0.0.0
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_no_schema_version_uses_heuristic(self, tmp_path: Path):
        conf = """\
config system snmp community
    edit 1
        set name "open"
        set hosts 0.0.0.0 0.0.0.0
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) >= 1
        assert findings[0].confidence == "heuristic"

    def test_schema_field_not_supported_skips(self, tmp_path: Path):
        """When the name field is not in the schema and schema is loaded, skip."""
        _write_schema(
            tmp_path,
            "7.4",
            {
                "tables": {"system snmp community": {"fields": {"hosts": {}}}},
            },
        )
        conf = """\
config system snmp community
    edit 1
        set name "open"
        set hosts 0.0.0.0 0.0.0.0
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# VDOM scope
# ---------------------------------------------------------------------------
class TestSNMPNoACLVDOM:
    """Test SNMP no-ACL check across VDOMs."""

    def test_per_vdom_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vdom
    edit "root"
        config system snmp community
            edit 1
                set name "open-root"
            next
        end
    next
    edit "vdom1"
        config system snmp community
            edit 1
                set name "restricted-vdom1"
                set hosts 10.0.0.1 255.255.255.255
            next
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        root_findings = [f for f in findings if f.vdom == "root"]
        vdom1_findings = [f for f in findings if f.vdom == "vdom1"]
        assert len(root_findings) == 1
        assert "open-root" in root_findings[0].message
        assert vdom1_findings == []
