"""Tests for FGT-EMAILFILTER-NO-DNSBL rule."""

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
        "emailfilter profile": {
            "fields": {},
            "source_url": "https://docs.fortinet.com/document/fortigate/7.4.12/cli-reference/268788570/config-emailfilter-profile",
        }
    }
}

_SCHEMA_TABLE_ONLY = {
    "coverage": "table_only",
    "tables": {
        "emailfilter profile": {"fields": {}},
    },
}

_SCHEMA_EMPTY = {
    "tables": {
        "emailfilter profile": {"fields": {}},
    },
}


# ---------------------------------------------------------------------------
# Basic detection — profiles without DNSBL
# ---------------------------------------------------------------------------
class TestEmailFilterNoDnsbl:
    """Test detection of email filter profiles without DNSBL configured."""

    def test_single_profile_no_dnsbl_triggers(self, tmp_path: Path):
        """A single profile with no dnsbl should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config emailfilter profile
    edit "default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-EMAILFILTER-NO-DNSBL"
        assert findings[0].severity == "low"
        assert "default" in findings[0].message
        assert "DNSBL" in findings[0].message

    def test_multiple_profiles_no_dnsbl_triggers(self, tmp_path: Path):
        """Multiple profiles without DNSBL should trigger with all names."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config emailfilter profile
    edit "profile-a"
    next
    edit "profile-b"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "profile-a" in findings[0].message
        assert "profile-b" in findings[0].message
        assert "2 email filter profile(s)" in findings[0].message

    def test_profile_with_other_set_lines_no_dnsbl_triggers(self, tmp_path: Path):
        """A profile with set lines but no dnsbl should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config emailfilter profile
    edit "default"
        set comment 'default profile'
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "default" in findings[0].message


# ---------------------------------------------------------------------------
# No finding when DNSBL is configured
# ---------------------------------------------------------------------------
class TestEmailFilterWithDnsbl:
    """Test that email filter profiles with DNSBL configured produce no findings."""

    def test_profile_with_dnsbl_no_finding(self, tmp_path: Path):
        """A profile with dnsbl set should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config emailfilter profile
    edit "default"
        set dnsbl default-dnsbl
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_all_profiles_with_dnsbl_no_finding(self, tmp_path: Path):
        """All profiles having DNSBL should produce no findings."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config emailfilter profile
    edit "profile-a"
        set dnsbl dnsbl-a
    next
    edit "profile-b"
        set dnsbl dnsbl-b
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# No email filter profile table = no finding
# ---------------------------------------------------------------------------
class TestEmailFilterNoProfile:
    """Test that configs without email filter profiles produce no findings."""

    def test_no_emailfilter_profile_block(self, tmp_path: Path):
        """No config emailfilter profile at all should produce no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_emailfilter_dnsbl_only_no_finding(self, tmp_path: Path):
        """DNSBL table defined but no profiles should produce no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config emailfilter dnsbl
    edit "zen-dnsbl"
        set server "zen.spamhaus.org"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestEmailFilterNoDnsblSchemaHandling:
    """Test schema fallback and degradation."""

    def test_schema_unknown_downgrades_confidence(self, tmp_path: Path):
        """Table-only schema should produce heuristic confidence."""
        _write_schema(tmp_path, "7.4", _SCHEMA_TABLE_ONLY)
        conf = """\
config emailfilter profile
    edit "default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_no_schema_version_uses_heuristic(self, tmp_path: Path):
        """Non-existent schema version -> heuristic."""
        conf = """\
config emailfilter profile
    edit "default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) >= 1
        assert findings[0].confidence == "heuristic"

    def test_no_emailfilter_profile_in_schema_skips(self, tmp_path: Path):
        """Schema without emailfilter profile table should skip the rule."""
        _write_schema(
            tmp_path,
            "7.4",
            {
                "tables": {"system interface": {"fields": {"name": {}}}},
            },
        )
        conf = """\
config emailfilter profile
    edit "default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # emailfilter profile table not in schema -> skip
        assert findings == []


# ---------------------------------------------------------------------------
# Evidence verification
# ---------------------------------------------------------------------------
class TestEmailFilterNoDnsblEvidence:
    """Verify evidence is captured correctly."""

    def test_evidence_from_profile(self, tmp_path: Path):
        """Finding should include evidence from the profile node."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config emailfilter profile
    edit "default"
        set comment 'test profile'
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert len(findings[0].evidence) >= 1

    def test_finding_message_format(self, tmp_path: Path):
        """Finding message should be clear and actionable."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config emailfilter profile
    edit "default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-EMAILFILTER-NO-DNSBL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        msg = findings[0].message
        assert "default" in msg
        assert "DNSBL" in msg
        assert "Enable DNSBL" in msg
