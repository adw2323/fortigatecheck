from pathlib import Path

from fgcheck.facts import build_facts
from fgcheck.parse import parse_fortios_text


def _facts_from_fixture(path: str):
    conf = Path(path).read_text(encoding="utf-8")
    model, warnings = parse_fortios_text(conf, file_id=Path(path).name)
    assert warnings == []
    return build_facts(model, vdom="root")


def _facts_from_conf(conf: str):
    model, warnings = parse_fortios_text(conf.strip(), file_id="inline.conf")
    assert warnings == []
    return build_facts(model, vdom="root")


def test_default_route_resolves_direct_edge_interface():
    facts = _facts_from_fixture("tests/fixtures/facts_default_route_direct.conf")

    assert facts.edge_interfaces == {"wan1"}
    assert facts.edge_zones == {"WAN-ZONE"}


def test_default_route_via_sdwan_resolves_member_interfaces():
    facts = _facts_from_fixture("tests/fixtures/facts_sdwan_default.conf")

    assert facts.edge_interfaces == {"wan1", "wan2"}
    assert facts.edge_zones == {"INTERNET"}


def test_policy_routes_resolve_zone_members_and_ignore_disabled_entries():
    facts = _facts_from_fixture("tests/fixtures/facts_policy_route_zone.conf")

    assert facts.edge_interfaces == {"wan3"}
    assert facts.edge_zones == {"WAN-ZONE"}


def test_default_route_on_software_switch_projects_member_interfaces():
    conf = """
config system interface
    edit "wan-sw"
        set type switch
        set member "wan1" "wan2"
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set device "wan-sw"
    next
end
""".strip()
    facts = _facts_from_conf(conf)
    assert facts.edge_interfaces == {"wan1", "wan2"}


def test_default_route_on_vlan_projects_parent_interface():
    conf = """
config system interface
    edit "wan1.100"
        set interface "wan1"
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set device "wan1.100"
    next
end
""".strip()
    facts = _facts_from_conf(conf)
    assert facts.edge_interfaces == {"wan1"}
