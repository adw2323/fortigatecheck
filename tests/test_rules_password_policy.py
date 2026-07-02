"""Tests for FGT-ADMIN-WEAK-PASSWORD-POLICY rule."""
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
        "system password-policy": {
            "fields": {
                "status": {"allowed_values": ["enable", "disable"]},
                "minimum-length": {},
                "min-lower-case-letter": {},
                "min-upper-case-letter": {},
                "min-non-alphanumeric": {},
                "min-number": {},
                "min-change-characters": {},
                "expire-status": {"allowed_values": ["enable", "disable"]},
                "reuse-password": {"allowed_values": ["enable", "disable"]},
            }
        }
    }
}


class TestPasswordPolicyDisabled:
    """Test detection of explicitly disabled password policy."""

    def test_policy_disabled_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system password-policy
    set status disable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-WEAK-PASSWORD-POLICY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-ADMIN-WEAK-PASSWORD-POLICY"
        assert findings[0].severity == "high"
        assert findings[0].confidence == "likely"
        assert "disabled" in findings[0].message.lower()
        assert findings[0].evidence  # must have evidence

    def test_policy_enabled_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system password-policy
    set status enable
    set minimum-length 12
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-WEAK-PASSWORD-POLICY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_no_password_policy_block_no_finding(self, tmp_path: Path):
        """Empty config should not trigger — absence means factory default."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-WEAK-PASSWORD-POLICY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


class TestPasswordPolicyWeakLength:
    """Test detection of minimum-length below threshold."""

    def test_min_length_6_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system password-policy
    set status enable
    set minimum-length 6
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-WEAK-PASSWORD-POLICY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-ADMIN-WEAK-PASSWORD-POLICY"
        assert "6" in findings[0].message
        assert "below" in findings[0].message.lower()

    def test_min_length_1_no_finding(self, tmp_path: Path):
        """min-length 1 (likely zero or garbage) — no int parsing crash."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system password-policy
    set status enable
    set minimum-length 1
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-WEAK-PASSWORD-POLICY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "1" in findings[0].message

    def test_min_length_8_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system password-policy
    set status enable
    set minimum-length 8
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-WEAK-PASSWORD-POLICY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_min_length_12_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system password-policy
    set status enable
    set minimum-length 12
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-WEAK-PASSWORD-POLICY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


class TestPasswordPolicySchemaUnknown:
    """Test behaviour when schema is missing (table_only)."""

    def test_schema_unknown_downgrades_confidence(self, tmp_path: Path):
        """When schema has table but no fields (table_only coverage), confidence is heuristic."""
        _write_schema(tmp_path, "7.4", {"coverage": "table_only", "tables": {"system password-policy": {"fields": {}}}})
        conf = """\
config system password-policy
    set status disable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-WEAK-PASSWORD-POLICY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_no_schema_version_uses_heuristic(self, tmp_path: Path):
        """Non-existent schema version -> heuristic."""
        conf = """\
config system password-policy
    set status disable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-WEAK-PASSWORD-POLICY.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        # Without schema, table support is assumed but unknown
        assert len(findings) >= 1
        assert findings[0].confidence == "heuristic"


class TestPasswordPolicyVDOM:
    """Test password policy check across VDOMs."""

    def test_per_vdom_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vdom
    edit "root"
        config system password-policy
            set status disable
        end
    next
    edit "vdom1"
        config system password-policy
            set status enable
            set minimum-length 12
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-ADMIN-WEAK-PASSWORD-POLICY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Only root vdom should trigger
        root_findings = [f for f in findings if f.vdom == "root"]
        vdom1_findings = [f for f in findings if f.vdom == "vdom1"]
        assert len(root_findings) == 1
        assert root_findings[0].message == "Administrator password policy is explicitly disabled."
        assert vdom1_findings == []
