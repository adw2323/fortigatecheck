"""Tests for FGT-AV-NO-HEURISTIC rule."""

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
        "antivirus profile": {
            "fields": {},
            "source_url": "https://example.com",
        }
    }
}

_SCHEMA_TABLE_ONLY = {
    "coverage": "table_only",
    "tables": {
        "antivirus profile": {"fields": {}},
    },
}


# ---------------------------------------------------------------------------
# Basic detection — profiles without heuristic
# ---------------------------------------------------------------------------
class TestAvNoHeuristic:
    """Test detection of antivirus profiles without heuristic scanning."""

    def test_single_profile_no_heuristic_triggers(self, tmp_path: Path):
        """A single profile with no protocol sections should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-AV-NO-HEURISTIC"
        assert findings[0].severity == "medium"
        assert "av-default" in findings[0].message
        assert "heuristic scanning is not enabled" in findings[0].message

    def test_multiple_profiles_no_heuristic_triggers(self, tmp_path: Path):
        """Multiple profiles without heuristic should trigger with all names."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-profile-a"
    next
    edit "av-profile-b"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "av-profile-a" in findings[0].message
        assert "av-profile-b" in findings[0].message
        assert "2 profile(s)" in findings[0].message

    def test_profile_with_set_lines_no_heuristic_triggers(self, tmp_path: Path):
        """A profile with set lines but no heuristic should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-default"
        set comment 'default profile'
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "av-default" in findings[0].message

    def test_profile_with_protocol_but_no_heuristic_triggers(self, tmp_path: Path):
        """A profile with protocol sections but no heuristic enable should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        # When parser flattens config http inside the edit block,
        # it creates a root-level "http" table with a singleton node.
        conf = """\
config antivirus profile
    edit "av-default"
        config http
            set action reset
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-AV-NO-HEURISTIC"


# ---------------------------------------------------------------------------
# No finding when heuristic is enabled
# ---------------------------------------------------------------------------
class TestAvNoHeuristicWithHeuristic:
    """Test that profiles with heuristic enabled produce no findings."""

    def test_profile_with_http_heuristic_no_finding(self, tmp_path: Path):
        """A profile with http heuristic enabled should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-custom"
        config http
            set action reset
            set heuristic enable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_profile_with_ftp_heuristic_no_finding(self, tmp_path: Path):
        """A profile with ftp heuristic enabled should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-ftp"
        config ftp
            set action quarantine
            set heuristic enable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_profile_with_smtp_heuristic_no_finding(self, tmp_path: Path):
        """A profile with smtp heuristic enabled should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-mail"
        config smtp
            set action pass
            set heuristic enable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_profile_with_imap_heuristic_no_finding(self, tmp_path: Path):
        """A profile with imap heuristic enabled should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-imap"
        config imap
            set action reset
            set heuristic enable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_profile_with_pop3_heuristic_no_finding(self, tmp_path: Path):
        """A profile with pop3 heuristic enabled should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-pop3"
        config pop3
            set action quarantine
            set heuristic enable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_profile_with_smb_heuristic_no_finding(self, tmp_path: Path):
        """A profile with smb heuristic enabled should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-smb"
        config smb
            set action reset
            set heuristic enable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_profile_with_nntp_heuristic_no_finding(self, tmp_path: Path):
        """A profile with nntp heuristic enabled should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-nntp"
        config nntp
            set action pass
            set heuristic enable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_heuristic_disable_triggers(self, tmp_path: Path):
        """A profile with heuristic explicitly disabled should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-no-heur"
        config http
            set action reset
            set heuristic disable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-AV-NO-HEURISTIC"


# ---------------------------------------------------------------------------
# No antivirus profile table = no finding
# ---------------------------------------------------------------------------
class TestAvNoHeuristicNoProfile:
    """Test that configs without antivirus profiles produce no findings."""

    def test_no_antivirus_profile_block(self, tmp_path: Path):
        """No config antivirus profile at all should produce no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_antivirus_settings_only_no_finding(self, tmp_path: Path):
        """Antivirus settings without profiles should produce no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus settings
    set default-decryption-action pass
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestAvNoHeuristicSchemaHandling:
    """Test schema fallback and degradation."""

    def test_schema_unknown_downgrades_confidence(self, tmp_path: Path):
        """Table-only schema should produce heuristic confidence."""
        _write_schema(tmp_path, "7.4", _SCHEMA_TABLE_ONLY)
        conf = """\
config antivirus profile
    edit "av-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_no_schema_version_uses_heuristic(self, tmp_path: Path):
        """Non-existent schema version -> heuristic."""
        conf = """\
config antivirus profile
    edit "av-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) >= 1
        assert findings[0].confidence == "heuristic"

    def test_no_av_profile_in_schema_skips(self, tmp_path: Path):
        """Schema without antivirus profile table should skip the rule entirely."""
        _write_schema(
            tmp_path,
            "7.4",
            {
                "tables": {"system interface": {"fields": {"name": {}}}},
            },
        )
        conf = """\
config antivirus profile
    edit "av-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # antivirus profile table not in schema -> skip
        assert findings == []


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
class TestAvNoHeuristicEvidence:
    """Test that evidence is properly attached to findings."""

    def test_finding_has_evidence_with_set_line(self, tmp_path: Path):
        """Finding should include evidence when profile has set lines."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config antivirus profile
    edit "av-default"
        set comment 'default profile'
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
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
config antivirus profile
    edit "av-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        msg = findings[0].message
        # Should mention the profile name
        assert "av-default" in msg
        # Should mention heuristic scanning not enabled
        assert "heuristic scanning is not enabled" in msg
        # Should mention zero-day detection
        assert "zero-day" in msg
        # Should recommend action
        assert "Enable heuristic scanning" in msg


# ---------------------------------------------------------------------------
# Integration with firewall policies
# ---------------------------------------------------------------------------
class TestAvNoHeuristicIntegration:
    """Test AV heuristic check in context of firewall policies."""

    def test_policy_referencing_profile_without_heuristic(self, tmp_path: Path):
        """Firewall policy references antivirus profile that has no heuristic."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config firewall policy
    edit 1
        set name "allow-web"
        set srcintf "wan1"
        set dstintf "lan"
        set action accept
        set profile-protocol-options "av-default"
    next
end
config antivirus profile
    edit "av-default"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Should still trigger — the profile itself has no heuristic
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-AV-NO-HEURISTIC"

    def test_policy_with_profile_heuristic_enabled(self, tmp_path: Path):
        """Firewall policy with antivirus profile that has heuristic enabled."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config firewall policy
    edit 1
        set name "allow-web"
        set srcintf "wan1"
        set dstintf "lan"
        set action accept
        set profile-protocol-options "av-custom"
    next
end
config antivirus profile
    edit "av-custom"
        config http
            set action reset
            set heuristic enable
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Should NOT trigger — heuristic is enabled
        assert findings == []
