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


def test_default_route_cidr_string_is_detected_and_non_default_ignored():
    conf = """
config router static
    edit 1
        set dst 0.0.0.0/0
        set device "wan1"
    next
    edit 2
        set dst 10.0.0.0 255.0.0.0
        set device "wan2"
    next
end
""".strip()
    facts = _facts_from_conf(conf)
    assert facts.edge_interfaces == {"wan1"}


def test_sdwan_keyword_sdwan_resolves_members_as_edge():
    conf = """
config system sdwan
    config members
        edit 1
            set interface "wan1"
        next
        edit 2
            set interface "wan2"
        next
    end
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set device "sdwan"
    next
end
""".strip()
    facts = _facts_from_conf(conf)
    assert facts.edge_interfaces == {"wan1", "wan2"}


def test_zone_membership_resolves_through_software_switch_hierarchy():
    conf = """
config system interface
    edit "wan-sw"
        set type switch
        set member "wan1" "wan2"
    next
end
config system zone
    edit "WAN-ZONE"
        set interface "wan-sw"
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set device "wan1"
    next
end
""".strip()
    facts = _facts_from_conf(conf)
    assert facts.edge_zones == {"WAN-ZONE"}
    assert facts.interface_to_zone["wan1"] == "WAN-ZONE"


def test_nested_software_switch_and_vlan_hierarchy_resolves_to_physical_member():
    conf = """
config system interface
    edit "wan-core"
        set type switch
        set member "wan-agg"
    next
    edit "wan-agg"
        set type switch
        set member "wan1.100"
    next
    edit "wan1.100"
        set interface "wan1"
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set device "wan-core"
    next
end
""".strip()
    facts = _facts_from_conf(conf)
    assert facts.edge_interfaces == {"wan1"}


def test_facts_are_scoped_per_vdom_for_default_route_edge_detection():
    conf = """
config vdom
    edit root
        config router static
            edit 1
                set dst 0.0.0.0 0.0.0.0
                set device "wan-root"
            next
        end
    next
    edit app
        config router static
            edit 1
                set dst 0.0.0.0 0.0.0.0
                set device "wan-app"
            next
        end
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    root_facts = build_facts(model, vdom="root")
    app_facts = build_facts(model, vdom="app")
    assert root_facts.edge_interfaces == {"wan-root"}
    assert app_facts.edge_interfaces == {"wan-app"}


def test_zone_membership_does_not_bleed_across_vdoms():
    conf = """
config vdom
    edit root
        config system zone
            edit "WAN-ZONE"
                set interface "wan1"
            next
        end
        config router static
            edit 1
                set dst 0.0.0.0 0.0.0.0
                set device "wan1"
            next
        end
    next
    edit app
        config system zone
            edit "APP-ZONE"
                set interface "wan2"
            next
        end
        config router static
            edit 1
                set dst 0.0.0.0 0.0.0.0
                set device "wan2"
            next
        end
    next
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline.conf")
    assert warnings == []
    root_facts = build_facts(model, vdom="root")
    app_facts = build_facts(model, vdom="app")
    assert root_facts.edge_zones == {"WAN-ZONE"}
    assert app_facts.edge_zones == {"APP-ZONE"}
