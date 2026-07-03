"""Tests for FGT-WEBFILTER-DEFAULT-OVERRIDE rule."""
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
        "webfilter override": {
            "fields": {},
            "source_url": "https://example.com",
        }
    }
}

_SCHEMA_TABLE_ONLY = {
    "coverage": "table_only",
    "tables": {
        "webfilter override": {"fields": {}},
    },
}


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------
class TestWebfilterDefaultOverride:
    """Test detection of web filter override entries."""

    def test_single_override_triggers(self, tmp_path: Path):
        """A single override entry should trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config webfilter override
    edit "bypass-group"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-WEBFILTER-DEFAULT-OVERRIDE"
        assert findings[0].severity == "medium"
        assert findings[0].confidence == "heuristic"
        assert "bypass-group" in findings[0].message
        assert "1 bypass entry/entries" in findings[0].message

    def test_multiple_overrides_triggers(self, tmp_path: Path):
        """Multiple override entries should trigger with all names."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config webfilter override
    edit "bypass-group"
    next
    edit "vip-users"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "bypass-group" in findings[0].message
        assert "vip-users" in findings[0].message
        assert "2 bypass entry/entries" in findings[0].message

    def test_override_with_set_lines_triggers(self, tmp_path: Path):
        """An override with set lines should still trigger."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config webfilter override
    edit "bypass-group"
        set name "vip users"
        set type ip
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "bypass-group" in findings[0].message

    def test_no_overrides_no_finding(self, tmp_path: Path):
        """No webfilter override config means no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config system global
    set hostname "fgt01"
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 0

    def test_empty_override_no_finding(self, tmp_path: Path):
        """Empty override table (no entries) means no finding."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config webfilter override
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestWebfilterDefaultOverrideSchema:
    """Test schema-aware behavior."""

    def test_table_only_schema_heuristic_confidence(self, tmp_path: Path):
        """Table-only schema should produce heuristic confidence."""
        _write_schema(tmp_path, "7.4", _SCHEMA_TABLE_ONLY)
        conf = """\
config webfilter override
    edit "bypass-group"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_missing_table_skips(self, tmp_path: Path):
        """When schema has no webfilter override table, rule skips."""
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system interface": {"fields": {}, "source_url": "https://example.com"},
            }
        })
        conf = """\
config webfilter override
    edit "bypass-group"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 0

    def test_no_schema_file_heuristic(self, tmp_path: Path):
        """When no schema file exists, rule runs with heuristic confidence."""
        conf = """\
config webfilter override
    edit "bypass-group"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_full_schema_no_schema_unknown_prefix(self, tmp_path: Path):
        """Full schema (non-partial) should not add schema_unknown prefix."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config webfilter override
    edit "bypass-group"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        # Even though we mark heuristic for this rule (schema has no fields),
        # the schema_unknown prefix should NOT be present because the table
        # exists in the schema.
        assert not findings[0].message.startswith("[schema_unknown]")


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
class TestWebfilterDefaultOverrideEvidence:
    """Test evidence extraction."""

    def test_evidence_from_first_override(self, tmp_path: Path):
        """Evidence should come from the first override entry with set lines."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config webfilter override
    edit "first-override"
        set name "first"
    next
    edit "second-override"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert len(findings[0].evidence) >= 1
        # Evidence should reference the config file
        assert findings[0].evidence[0].file_id == "inline.conf"

    def test_evidence_line_range_present(self, tmp_path: Path):
        """Evidence should have valid line ranges."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config webfilter override
    edit "bypass-group"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        for ev in findings[0].evidence:
            assert len(ev.line_range) == 2
            assert ev.line_range[0] > 0
            assert ev.line_range[1] >= ev.line_range[0]


# ---------------------------------------------------------------------------
# VDOM scope
# ---------------------------------------------------------------------------
class TestWebfilterDefaultOverrideVdom:
    """Test VDOM-scoped detection."""

    def test_vdom_scoped_override(self, tmp_path: Path):
        """Override in a specific VDOM should trigger for that VDOM only."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config vdom
    edit "root"
        config webfilter override
            edit "root-bypass"
            next
        end
    next
    edit "dmz"
        config webfilter override
            edit "dmz-bypass"
            next
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
            vdoms=["root"],
        )
        assert len(findings) == 1
        assert findings[0].vdom == "root"
        assert "root-bypass" in findings[0].message
        assert "dmz-bypass" not in findings[0].message


# ---------------------------------------------------------------------------
# Message content
# ---------------------------------------------------------------------------
class TestWebfilterDefaultOverrideMessage:
    """Test that finding messages are informative."""

    def test_message_mentions_bypass(self, tmp_path: Path):
        """Message should mention bypass and override."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config webfilter override
    edit "corp-bypass"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        msg = findings[0].message
        assert "bypass" in msg.lower()
        assert "override" in msg.lower()
        assert "web filter" in msg.lower()

    def test_message_recommends_review(self, tmp_path: Path):
        """Message should recommend reviewing overrides."""
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_TABLE)
        conf = """\
config webfilter override
    edit "bypass"
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-WEBFILTER-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        msg = findings[0].message
        assert "review" in msg.lower() or "minimise" in msg.lower()
