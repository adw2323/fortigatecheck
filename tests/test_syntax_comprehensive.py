"""Comprehensive tests for syntax validation rules."""
from __future__ import annotations

import pytest
from fgcheck.model import ConfigModel, Node, Evidence
from fgcheck.facts import build_facts
from fgcheck.rules import Finding, Rule
from fgcheck.parse import parse_fortios_text


def _make_rule(rule_id, title="Test", severity="medium", confidence="certain"):
    return Rule(id=rule_id, title=title, severity=severity, confidence=confidence,
                entrypoint="fgcheck.rules_syntax:rule_unknown_table")


class TestDuplicateEditBlocks:
    def test_no_duplicates(self):
        from fgcheck.rules_syntax import rule_duplicate_edit_blocks
        text = """config firewall policy
    edit 1
        set name "policy1"
    next
    edit 2
        set name "policy2"
    next
end"""
        model, _ = parse_fortios_text(text)
        facts = build_facts(model)
        findings = rule_duplicate_edit_blocks(model=model, facts=facts, vdom="root", rule=_make_rule("FGT-SYNTAX-DUPLICATE-EDIT"))
        assert len(findings) == 0


class TestMissingFields:
    def test_entry_no_fields(self):
        from fgcheck.rules_syntax import rule_missing_end
        text = """config firewall policy
    edit 1
    next
end"""
        model, _ = parse_fortios_text(text)
        facts = build_facts(model)
        findings = rule_missing_end(model=model, facts=facts, vdom="root", rule=_make_rule("FGT-SYNTAX-MISSING-FIELDS"))
        assert len(findings) >= 1
        assert "no fields" in findings[0].message.lower()


class TestIPAddressFormat:
    def test_valid_ip(self):
        from fgcheck.rules_syntax import rule_ip_address_format
        text = """config firewall address
    edit "server1"
        set subnet 192.168.1.0 255.255.255.0
    next
end"""
        model, _ = parse_fortios_text(text)
        facts = build_facts(model)
        findings = rule_ip_address_format(model=model, facts=facts, vdom="root", rule=_make_rule("FGT-SYNTAX-IP-FORMAT"))
        assert len(findings) == 0

    def test_invalid_ip(self):
        from fgcheck.rules_syntax import rule_ip_address_format
        text = """config firewall address
    edit "bad"
        set subnet 192.168.1.256 255.255.255.0
    next
end"""
        model, _ = parse_fortios_text(text)
        facts = build_facts(model)
        findings = rule_ip_address_format(model=model, facts=facts, vdom="root", rule=_make_rule("FGT-SYNTAX-IP-FORMAT"))
        assert len(findings) == 1
        assert "Malformed" in findings[0].message

    def test_valid_ip_in_list(self):
        from fgcheck.rules_syntax import rule_ip_address_format
        text = """config firewall address
    edit "good"
        set subnet 10.0.0.0 255.0.0.0
    next
end"""
        model, _ = parse_fortios_text(text)
        facts = build_facts(model)
        findings = rule_ip_address_format(model=model, facts=facts, vdom="root", rule=_make_rule("FGT-SYNTAX-IP-FORMAT"))
        assert len(findings) == 0


class TestPortRangeFormat:
    def test_valid_port(self):
        from fgcheck.rules_syntax import rule_port_range_format
        text = """config firewall service custom
    edit "https"
        set tcp-portrange 443
    next
end"""
        model, _ = parse_fortios_text(text)
        facts = build_facts(model)
        findings = rule_port_range_format(model=model, facts=facts, vdom="root", rule=_make_rule("FGT-SYNTAX-PORT-RANGE"))
        assert len(findings) == 0

    def test_invalid_port(self):
        from fgcheck.rules_syntax import rule_port_range_format
        text = """config firewall service custom
    edit "bad"
        set tcp-portrange 99999
    next
end"""
        model, _ = parse_fortios_text(text)
        facts = build_facts(model)
        findings = rule_port_range_format(model=model, facts=facts, vdom="root", rule=_make_rule("FGT-SYNTAX-PORT-RANGE"))
        assert len(findings) == 1
        assert "Invalid port" in findings[0].message


class TestDeprecatedSyntax:
    def test_deprecated_access(self):
        from fgcheck.rules_syntax import rule_deprecated_syntax
        text = """config system interface
    edit "port1"
        set access ssh
    next
end"""
        model, _ = parse_fortios_text(text)
        facts = build_facts(model)
        findings = rule_deprecated_syntax(model=model, facts=facts, vdom="root", rule=_make_rule("FGT-SYNTAX-DEPRECATED"))
        assert len(findings) == 1
        assert "Deprecated" in findings[0].message

    def test_no_deprecated(self):
        from fgcheck.rules_syntax import rule_deprecated_syntax
        text = """config system interface
    edit "port1"
        set allowaccess https ssh
    next
end"""
        model, _ = parse_fortios_text(text)
        facts = build_facts(model)
        findings = rule_deprecated_syntax(model=model, facts=facts, vdom="root", rule=_make_rule("FGT-SYNTAX-DEPRECATED"))
        assert len(findings) == 0


class TestSyntaxRulesIntegration:
    def test_real_config_syntax_check(self):
        """Test syntax rules against a real-ish config."""
        from fgcheck.rules_syntax import (
            rule_duplicate_edit_blocks, rule_empty_table,
            rule_missing_end, rule_ip_address_format, rule_port_range_format
        )

        text = """config system global
    set admin-port 8443
end
config firewall policy
    edit 1
        set name "allow-web"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTP" "HTTPS"
        set logtraffic enable
    next
end
config firewall address
    edit "server1"
        set subnet 192.168.1.100 255.255.255.255
    next
end"""
        model, _ = parse_fortios_text(text)
        facts = build_facts(model)

        rule = _make_rule("TEST")

        for fn in [rule_duplicate_edit_blocks, rule_empty_table,
                   rule_missing_end, rule_ip_address_format, rule_port_range_format]:
            findings = fn(model=model, facts=facts, vdom="root", rule=rule)
            assert isinstance(findings, list)
