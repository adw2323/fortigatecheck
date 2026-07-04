"""Tests for syntax validation rules."""

from __future__ import annotations

from fgcheck.facts import build_facts
from fgcheck.model import ConfigModel, Node
from fgcheck.rules import Rule
from fgcheck.rules_syntax import (
    rule_deprecated_syntax,
    rule_unknown_field,
    rule_unknown_table,
)
from fgcheck.schema import SchemaView


def _make_rule(rule_id: str, title: str, severity: str = "medium") -> Rule:
    return Rule(
        id=rule_id,
        title=title,
        severity=severity,
        confidence="heuristic",
        entrypoint="fgcheck.rules_syntax:rule_unknown_table",
    )


def test_rule_unknown_table_with_unknown():
    """Test that unknown tables are flagged."""
    model = ConfigModel()
    model.vdoms["root"] = {
        "firewall policy": {"edit 1": Node(fields={"action": "accept"})},
        "totally_fake_table": {"edit 1": Node(fields={"foo": "bar"})},
    }

    schema = SchemaView(requested_version="7.6", loaded=True, partial=False)
    schema._tables = {"firewall policy": {"fields": {"action": {"allowed_values": ["accept", "deny"]}}}}

    rule = _make_rule("FGT-SYNTAX-UNKNOWN-TABLE", "Unknown config table")
    facts = build_facts(model, vdom="root")

    findings = rule_unknown_table(model=model, facts=facts, vdom="root", rule=rule, schema=schema)
    assert len(findings) == 1
    assert "totally_fake_table" in findings[0].message


def test_rule_unknown_table_all_known():
    """Test that known tables produce no findings."""
    model = ConfigModel()
    model.vdoms["root"] = {
        "firewall policy": {"edit 1": Node(fields={"action": "accept"})},
        "system interface": {"edit wan1": Node(fields={"allowaccess": "ssh"})},
    }

    schema = SchemaView(requested_version="7.6", loaded=True, partial=False)
    schema._tables = {
        "firewall policy": {"fields": {}},
        "system interface": {"fields": {}},
    }

    rule = _make_rule("FGT-SYNTAX-UNKNOWN-TABLE", "Unknown config table")
    facts = build_facts(model, vdom="root")

    findings = rule_unknown_table(model=model, facts=facts, vdom="root", rule=rule, schema=schema)
    assert len(findings) == 0


def test_rule_unknown_table_no_schema():
    """Test that no findings when schema is not loaded."""
    model = ConfigModel()
    model.vdoms["root"] = {"fake_table": {"edit 1": Node(fields={})}}

    rule = _make_rule("FGT-SYNTAX-UNKNOWN-TABLE", "Unknown config table")
    facts = build_facts(model, vdom="root")

    findings = rule_unknown_table(model=model, facts=facts, vdom="root", rule=rule, schema=None)
    assert len(findings) == 0


def test_rule_unknown_field():
    """Test that unknown fields are flagged."""
    model = ConfigModel()
    model.vdoms["root"] = {"firewall policy": {"edit 1": Node(fields={"action": "accept", "fake_field": "value"})}}

    schema = SchemaView(requested_version="7.6", loaded=True, partial=False)
    schema._tables = {"firewall policy": {"fields": {"action": {"allowed_values": ["accept", "deny"]}}}}

    rule = _make_rule("FGT-SYNTAX-UNKNOWN-FIELD", "Unknown field")
    facts = build_facts(model, vdom="root")

    findings = rule_unknown_field(model=model, facts=facts, vdom="root", rule=rule, schema=schema)
    assert len(findings) == 1
    assert "fake_field" in findings[0].message


def test_rule_deprecated_syntax():
    """Test that deprecated syntax is flagged."""
    model = ConfigModel()
    model.vdoms["root"] = {"system interface": {"edit wan1": Node(fields={"access": "ssh"})}}

    rule = _make_rule("FGT-SYNTAX-DEPRECATED", "Deprecated syntax", severity="low")
    facts = build_facts(model, vdom="root")

    findings = rule_deprecated_syntax(model=model, facts=facts, vdom="root", rule=rule)
    assert len(findings) == 1
    assert "deprecated" in findings[0].message.lower()


def test_rule_deprecated_syntax_modern():
    """Test that modern syntax produces no findings."""
    model = ConfigModel()
    model.vdoms["root"] = {"system interface": {"edit wan1": Node(fields={"allowaccess": "ssh"})}}

    rule = _make_rule("FGT-SYNTAX-DEPRECATED", "Deprecated syntax", severity="low")
    facts = build_facts(model, vdom="root")

    findings = rule_deprecated_syntax(model=model, facts=facts, vdom="root", rule=rule)
    assert len(findings) == 0
