"""Tests for FGT-ADMIN-LOCKOUT-NO-TRIES and FGT-HA-NO-HEARTBEAT rules."""

from __future__ import annotations

from fgcheck.facts import build_facts
from fgcheck.model import ConfigModel, Evidence, Node
from fgcheck.rules import Rule
from fgcheck.rules_impl import rule_admin_lockout_no_tries, rule_ha_no_heartbeat


def _make_rule(rule_id: str, title: str, severity: str = "medium") -> Rule:
    return Rule(
        id=rule_id,
        title=title,
        severity=severity,
        confidence="likely",
        entrypoint="fgcheck.rules_impl:rule_admin_lockout_no_tries",
    )


# ── FGT-ADMIN-LOCKOUT-NO-TRIES ──


class TestAdminLockoutNoTries:
    def test_no_lockout_config(self):
        """Factory default — no config system global block."""
        model = ConfigModel()
        model.vdoms["root"] = {}
        model.global_cfg = {}
        rule = _make_rule("FGT-ADMIN-LOCKOUT-NO-TRIES", "Admin lockout not configured")
        facts = build_facts(model, vdom="root")
        findings = rule_admin_lockout_no_tries(model=model, facts=facts, vdom="root", rule=rule)
        assert len(findings) == 1
        assert "factory default" in findings[0].message.lower()

    def test_lockout_threshold_zero(self):
        """Lockout explicitly disabled."""
        model = ConfigModel()
        model.global_cfg = {
            "system": {
                "global": {
                    "__singleton__": Node(
                        fields={"admin-lockout-threshold": "0"},
                        evidence={
                            "set:admin-lockout-threshold": Evidence(
                                "test", (1, 1), ("system", "global"), ["set admin-lockout-threshold 0"]
                            )
                        },
                    )
                }
            }
        }
        model.vdoms["root"] = {}
        rule = _make_rule("FGT-ADMIN-LOCKOUT-NO-TRIES", "Admin lockout not configured")
        facts = build_facts(model, vdom="root")
        findings = rule_admin_lockout_no_tries(model=model, facts=facts, vdom="root", rule=rule)
        assert len(findings) == 1
        assert "disabled" in findings[0].message.lower()

    def test_lockout_threshold_set(self):
        """Lockout properly configured."""
        model = ConfigModel()
        model.global_cfg = {
            "system": {
                "global": {
                    "__singleton__": Node(
                        fields={"admin-lockout-threshold": "3"},
                    )
                }
            }
        }
        model.vdoms["root"] = {}
        rule = _make_rule("FGT-ADMIN-LOCKOUT-NO-TRIES", "Admin lockout not configured")
        facts = build_facts(model, vdom="root")
        findings = rule_admin_lockout_no_tries(model=model, facts=facts, vdom="root", rule=rule)
        assert len(findings) == 0

    def test_lockout_field_missing(self):
        """Config exists but lockout field not set."""
        model = ConfigModel()
        model.global_cfg = {"system": {"global": {"__singleton__": Node(fields={"hostname": "fgt01"})}}}
        model.vdoms["root"] = {}
        rule = _make_rule("FGT-ADMIN-LOCKOUT-NO-TRIES", "Admin lockout not configured")
        facts = build_facts(model, vdom="root")
        findings = rule_admin_lockout_no_tries(model=model, facts=facts, vdom="root", rule=rule)
        assert len(findings) == 1
        assert "not set" in findings[0].message.lower()


# ── FGT-HA-NO-HEARTBEAT ──


class TestHANoHeartbeat:
    def test_no_ha_config(self):
        """No HA config — not in HA mode."""
        model = ConfigModel()
        model.vdoms["root"] = {}
        model.global_cfg = {}
        rule = _make_rule("FGT-HA-NO-HEARTBEAT", "HA heartbeat not configured")
        facts = build_facts(model, vdom="root")
        findings = rule_ha_no_heartbeat(model=model, facts=facts, vdom="root", rule=rule)
        assert len(findings) == 0

    def test_ha_no_hbdev(self):
        """HA configured but no heartbeat device."""
        model = ConfigModel()
        model.global_cfg = {"system": {"ha": {"__singleton__": Node(fields={"mode": "a-p"})}}}
        model.vdoms["root"] = {}
        rule = _make_rule("FGT-HA-NO-HEARTBEAT", "HA heartbeat not configured")
        facts = build_facts(model, vdom="root")
        findings = rule_ha_no_heartbeat(model=model, facts=facts, vdom="root", rule=rule)
        assert len(findings) == 1
        assert "heartbeat" in findings[0].message.lower()

    def test_ha_hbdev_no_cluster_key(self):
        """HA with heartbeat but no encryption."""
        model = ConfigModel()
        model.global_cfg = {"system": {"ha": {"__singleton__": Node(fields={"mode": "a-p", "hbdev": "port4"})}}}
        model.vdoms["root"] = {}
        rule = _make_rule("FGT-HA-NO-HEARTBEAT", "HA heartbeat not configured")
        facts = build_facts(model, vdom="root")
        findings = rule_ha_no_heartbeat(model=model, facts=facts, vdom="root", rule=rule)
        assert len(findings) == 1
        assert "unencrypted" in findings[0].message.lower()

    def test_ha_hbdev_with_cluster_key(self):
        """HA with heartbeat and encryption — good."""
        model = ConfigModel()
        model.global_cfg = {
            "system": {"ha": {"__singleton__": Node(fields={"mode": "a-p", "hbdev": "port4", "cluster-key": "s3cret"})}}
        }
        model.vdoms["root"] = {}
        rule = _make_rule("FGT-HA-NO-HEARTBEAT", "HA heartbeat not configured")
        facts = build_facts(model, vdom="root")
        findings = rule_ha_no_heartbeat(model=model, facts=facts, vdom="root", rule=rule)
        assert len(findings) == 0
