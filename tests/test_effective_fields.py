"""Tests that rules and facts respect Node.unsets via effective_fields()."""

from __future__ import annotations

from fgcheck.facts import build_facts
from fgcheck.model import ConfigModel, Evidence, Node
from fgcheck.rules import Rule
from fgcheck.rules_impl import (
    rule_admin_edge_https,
    rule_admin_edge_ssh,
    rule_policy_accept_no_log,
    rule_policy_any_any_all,
)


def _make_rule(rule_id: str = "TEST-001") -> Rule:
    return Rule(
        id=rule_id,
        title="Test Rule",
        severity="medium",
        confidence="high",
        entrypoint="fgcheck.rules_impl:rule_admin_edge_ssh",
    )


def _make_model_with_interface(ifname: str, allowaccess: list, unsets: set | None = None) -> ConfigModel:
    """Build a ConfigModel with one interface node."""
    node = Node(
        fields={"allowaccess": allowaccess},
        unsets=unsets or set(),
        evidence={"set:allowaccess": Evidence(file_id="test", line_range=(1, 1), path=("system", "interface", ifname))},
    )
    return ConfigModel(
        vdoms={"root": {"system": {"interface": {ifname: node}}}},
    )


class TestEffectiveFieldsInRules:
    """Verify that rules use effective_fields() so unsets suppress false positives."""

    def test_edge_ssh_unsets_allowaccess(self):
        """Interface with allowaccess set then unset should NOT trigger SSH finding."""
        model = _make_model_with_interface(
            "wan1",
            allowaccess=["ssh", "https"],
            unsets={"allowaccess"},
        )
        # Need a default route pointing to wan1 so it's an edge interface
        route_node = Node(
            fields={"dst": ["0.0.0.0", "0.0.0.0"], "device": "wan1"},
            evidence={},
        )
        model.vdoms["root"]["router"] = {"static": {"1": route_node}}

        rule = _make_rule("FGT-ADMIN-EDGE-SSH")
        findings = rule_admin_edge_ssh(model=model, facts=build_facts(model), vdom="root", rule=rule)
        assert findings == [], "Should not find SSH on interface with unset allowaccess"

    def test_edge_ssh_active_allowaccess(self):
        """Interface with allowaccess including ssh SHOULD trigger finding."""
        model = _make_model_with_interface(
            "wan1",
            allowaccess=["ssh", "https"],
            unsets=set(),
        )
        route_node = Node(
            fields={"dst": ["0.0.0.0", "0.0.0.0"], "device": "wan1"},
            evidence={},
        )
        model.vdoms["root"]["router"] = {"static": {"1": route_node}}

        rule = _make_rule("FGT-ADMIN-EDGE-SSH")
        findings = rule_admin_edge_ssh(model=model, facts=build_facts(model), vdom="root", rule=rule)
        assert len(findings) == 1, "Should find SSH on active edge interface"

    def test_edge_https_unsets_allowaccess(self):
        """Interface with allowaccess set then unset should NOT trigger HTTPS finding."""
        model = _make_model_with_interface(
            "wan1",
            allowaccess=["https"],
            unsets={"allowaccess"},
        )
        route_node = Node(
            fields={"dst": ["0.0.0.0", "0.0.0.0"], "device": "wan1"},
            evidence={},
        )
        model.vdoms["root"]["router"] = {"static": {"1": route_node}}

        rule = _make_rule("FGT-ADMIN-EDGE-HTTPS")
        findings = rule_admin_edge_https(model=model, facts=build_facts(model), vdom="root", rule=rule)
        assert findings == [], "Should not find HTTPS on interface with unset allowaccess"

    def test_policy_unsets_action(self):
        """Policy with action set then unset should NOT trigger accept-no-log."""
        pol_node = Node(
            fields={"action": "accept", "logtraffic": "disable"},
            unsets={"action"},
            evidence={"set:action": Evidence(file_id="test", line_range=(1, 1), path=())},
        )
        model = ConfigModel(vdoms={"root": {"firewall": {"policy": {"1": pol_node}}}})

        rule = _make_rule("FGT-POLICY-NO-LOG")
        findings = rule_policy_accept_no_log(model=model, facts=build_facts(model), vdom="root", rule=rule)
        assert findings == [], "Should not find accept policy when action is unset"

    def test_policy_unsets_logtraffic(self):
        """Policy with logtraffic set then unset should NOT trigger accept-no-log
        (unset logtraffic means default, not explicitly disabled)."""
        pol_node = Node(
            fields={"action": "accept", "logtraffic": "disable"},
            unsets={"logtraffic"},
            evidence={},
        )
        model = ConfigModel(vdoms={"root": {"firewall": {"policy": {"1": pol_node}}}})

        rule = _make_rule("FGT-POLICY-NO-LOG")
        findings = rule_policy_accept_no_log(model=model, facts=build_facts(model), vdom="root", rule=rule)
        assert findings == [], "Should not find accept-no-log when logtraffic is unset"

    def test_policy_any_any_all_unsets_srcaddr(self):
        """Policy with srcaddr set then unset should NOT trigger any-any-all."""
        pol_node = Node(
            fields={"action": "accept", "srcaddr": "all", "dstaddr": "all", "service": "ALL"},
            unsets={"srcaddr"},
            evidence={"set:srcaddr": Evidence(file_id="test", line_range=(1, 1), path=())},
        )
        model = ConfigModel(vdoms={"root": {"firewall": {"policy": {"1": pol_node}}}})

        rule = _make_rule("FGT-POLICY-ANY-ANY-ALL")
        findings = rule_policy_any_any_all(model=model, facts=build_facts(model), vdom="root", rule=rule)
        assert findings == [], "Should not find any-any-all when srcaddr is unset"


class TestEffectiveFieldsInFacts:
    """Verify that facts building uses effective_fields() so unsets are respected."""

    def test_static_route_unsets_dst_not_edge(self):
        """Static route with dst set then unset should NOT mark device as edge."""
        route_node = Node(
            fields={"dst": ["0.0.0.0", "0.0.0.0"], "device": "wan1"},
            unsets={"dst"},
        )
        model = ConfigModel(vdoms={"root": {"router": {"static": {"1": route_node}}}})
        facts = build_facts(model, vdom="root")
        assert "wan1" not in facts.edge_interfaces, "unset dst route should not create edge interface"

    def test_static_route_unsets_device_not_edge(self):
        """Static route with device set then unset should NOT mark device as edge."""
        route_node = Node(
            fields={"dst": ["0.0.0.0", "0.0.0.0"], "device": "wan1"},
            unsets={"device"},
        )
        model = ConfigModel(vdoms={"root": {"router": {"static": {"1": route_node}}}})
        facts = build_facts(model, vdom="root")
        assert "wan1" not in facts.edge_interfaces, "unset device route should not create edge interface"

    def test_interface_unsets_member_not_resolved(self):
        """Interface with member set then unset should NOT expand members."""
        iface_node = Node(
            fields={"member": ["port1", "port2"]},
            unsets={"member"},
        )
        model = ConfigModel(
            vdoms={"root": {"system": {"interface": {"agg0": iface_node}}}},
        )
        facts = build_facts(model, vdom="root")
        # The aggregate should exist but its members should not be resolved
        assert (
            "port1" not in facts.zone_to_interfaces.get("__unzoned__", set()) or "agg0" not in facts.interface_to_zone
        ), "unset member should not resolve interface members"
