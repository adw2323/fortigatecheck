"""Tests for FGT-WAF-NO-PROFILE rule."""

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
        "waf profile": {
            "fields": {},
            "source_url": "https://example.com",
        }
    }
}

_SCHEMA_TABLE_ONLY = {
    "coverage": "table_only",
    "tables": {
        "waf profile": {"fields": {}},
    },
}


# ---------------------------------------------------------------------------
# Basic detection — profiles without criteria
# ---------------------------------------------------------------------------
class TestWafNoProfile:
    """Test detection of WAF profiles without filter criteria."""

    def test_single_profile_no_criteria_triggers(self, tmp_path: Path):
        """A single profile with no criteria should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config waf profile
    edit "default-waf"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-WAF-NO-PROFILE"
        assert findings[0].severity == "medium"
        assert "default-waf" in findings[0].message
        assert "none contain filter criteria" in findings[0].message

    def test_multiple_profiles_no_criteria_triggers(self, tmp_path: Path):
        """Multiple profiles without criteria should trigger with all names."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config waf profile
    edit "waf-profile-a"
    next
    edit "waf-profile-b"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "waf-profile-a" in findings[0].message
        assert "waf-profile-b" in findings[0].message
        assert "2 profile(s)" in findings[0].message

    def test_profile_with_set_comment_no_criteria_triggers(self, tmp_path: Path):
        """A profile with set comment but no criteria should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config waf profile
    edit "default-waf"
        set comment 'default profile'
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "default-waf" in findings[0].message


# ---------------------------------------------------------------------------
# No finding when profile has criteria configured
# ---------------------------------------------------------------------------
class TestWafNoProfileWithCriteria:
    """Test that profiles with criteria configured produce no findings."""

    def test_profile_with_main_criteria_no_finding(self, tmp_path: Path):
        """A profile with main-criteria entries should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config waf profile
    edit "custom-waf"
        config main-criteria
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
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_profile_with_custom_criteria_no_finding(self, tmp_path: Path):
        """A profile with custom-criteria entries should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config waf profile
    edit "custom-waf"
        config custom-criteria
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
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_profile_with_both_criteria_no_finding(self, tmp_path: Path):
        """A profile with both main and custom criteria should NOT trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config waf profile
    edit "full-waf"
        config main-criteria
            edit 1
                set action block
            next
        end
        config custom-criteria
            edit 1
                set action exempt
            next
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_one_profile_with_criteria_clears_others(self, tmp_path: Path):
        """If at least one profile has criteria, no finding is raised."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config waf profile
    edit "empty-waf"
    next
    edit "active-waf"
        config main-criteria
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
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# No WAF profile table = no finding
# ---------------------------------------------------------------------------
class TestWafNoProfileNoTable:
    """Test that configs without WAF profiles produce no findings."""

    def test_no_waf_profile_block(self, tmp_path: Path):
        """No config waf profile at all should produce no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_waf_settings_only_no_finding(self, tmp_path: Path):
        """WAF settings without profiles should produce no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config waf global
    set status enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestWafNoProfileSchemaHandling:
    """Test schema fallback and degradation."""

    def test_schema_unknown_downgrades_confidence(self, tmp_path: Path):
        """Table-only schema should produce heuristic confidence."""
        _write_schema(tmp_path, "7.4", _SCHEMA_TABLE_ONLY)
        conf = """\
config waf profile
    edit "default-waf"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_no_schema_version_uses_heuristic(self, tmp_path: Path):
        """Non-existent schema version -> heuristic."""
        conf = """\
config waf profile
    edit "default-waf"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) >= 1
        assert findings[0].confidence == "heuristic"

    def test_no_waf_profile_in_schema_skips(self, tmp_path: Path):
        """Schema without waf profile table should skip the rule entirely."""
        _write_schema(
            tmp_path,
            "7.4",
            {
                "tables": {"system interface": {"fields": {"name": {}}}},
            },
        )
        conf = """\
config waf profile
    edit "default-waf"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # waf profile table not in schema -> skip
        assert findings == []


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
class TestWafNoProfileEvidence:
    """Test that evidence is properly attached to findings."""

    def test_finding_has_evidence_with_set_line(self, tmp_path: Path):
        """Finding should include evidence when profile has set lines."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config waf profile
    edit "default-waf"
        set comment 'default profile'
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
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
config waf profile
    edit "default-waf"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        msg = findings[0].message
        # Should mention the profile name
        assert "default-waf" in msg
        # Should mention no filter criteria
        assert "none contain filter criteria" in msg
        # Should mention web application protection
        assert "web application protection" in msg
        # Should recommend action
        assert "Configure WAF profile criteria" in msg


# ---------------------------------------------------------------------------
# Integration with firewall policies
# ---------------------------------------------------------------------------
class TestWafNoProfileIntegration:
    """Test WAF profile check in context of firewall policies."""

    def test_policy_referencing_waf_profile_with_criteria(self, tmp_path: Path):
        """Firewall policy with WAF profile that has criteria should not trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config firewall policy
    edit 1
        set name "web-policy"
        set srcintf "wan1"
        set dstintf "lan"
        set action accept
    next
end
config waf profile
    edit "active-waf"
        config main-criteria
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
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # Profile has criteria — no finding
        assert findings == []

    def test_policy_with_empty_waf_profile(self, tmp_path: Path):
        """Firewall policy with WAF reference but empty profile should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config firewall policy
    edit 1
        set name "web-policy"
        set srcintf "wan1"
        set dstintf "lan"
        set action accept
    next
end
config waf profile
    edit "empty-waf"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-WAF-NO-PROFILE"


# ---------------------------------------------------------------------------
# VDOM scope
# ---------------------------------------------------------------------------
class TestWafNoProfileVdom:
    """Test VDOM-scoped detection."""

    def test_vdom_scoped_profiles(self, tmp_path: Path):
        """WAF profile in a specific VDOM should trigger for that VDOM only."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config vdom
    edit "root"
        config waf profile
            edit "root-waf"
            next
        end
    next
    edit "dmz"
        config waf profile
            edit "dmz-waf"
                config main-criteria
                    edit 1
                        set action block
                    next
                end
            next
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WAF-NO-PROFILE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
            vdoms=["root"],
        )
        assert len(findings) == 1
        assert findings[0].vdom == "root"
        assert "root-waf" in findings[0].message
        assert "dmz-waf" not in findings[0].message
