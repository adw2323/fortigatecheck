from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Set, Tuple

from .model import ConfigModel, Node
from .util import as_list

@dataclass
class Facts:
    edge_interfaces: Set[str] = field(default_factory=set)
    edge_zones: Set[str] = field(default_factory=set)
    interface_to_zone: Dict[str, str] = field(default_factory=dict)
    zone_to_interfaces: Dict[str, Set[str]] = field(default_factory=dict)

def get_table(scope_tables: Dict[str, Any], path: Tuple[str, ...]) -> Dict[str, Node]:
    node: Any = scope_tables
    for p in path:
        if not isinstance(node, dict) or p not in node:
            return {}
        node = node[p]
    if not isinstance(node, dict):
        return {}
    return node  # type: ignore


_SDWAN_LOGICAL_DEVICES = {"virtual-wan-link", "sdwan"}


def _is_default_route(dst: Any) -> bool:
    if isinstance(dst, list) and len(dst) >= 2 and dst[0] == "0.0.0.0" and dst[1] == "0.0.0.0":
        return True
    if isinstance(dst, str) and dst in ("0.0.0.0/0", "0.0.0.0"):
        return True
    return False


def _add_zone_membership(facts: Facts, zone_name: str, members: Any) -> None:
    for iface in as_list(members):
        facts.interface_to_zone[iface] = zone_name
        facts.zone_to_interfaces.setdefault(zone_name, set()).add(iface)

def build_facts(model: ConfigModel, *, vdom: str = "root") -> Facts:
    facts = Facts()
    tables = model.vdoms.get(vdom, {})
    interface_table = get_table(tables, ("system", "interface"))

    interface_members: Dict[str, Set[str]] = {}
    interface_parent: Dict[str, str] = {}
    for ifname, inode in interface_table.items():
        if not isinstance(inode, Node):
            continue
        name = str(ifname)
        members = set(as_list(inode.fields.get("member")))
        if members:
            interface_members[name] = members
        parents = as_list(inode.fields.get("interface"))
        if parents:
            interface_parent[name] = parents[0]

    resolved_interface_cache: Dict[str, Set[str]] = {}

    def resolve_interface_targets(ifname: str, trail: Set[str] | None = None) -> Set[str]:
        cached = resolved_interface_cache.get(ifname)
        if cached is not None:
            return set(cached)

        walk = trail or set()
        if ifname in walk:
            return {ifname}
        walk = set(walk)
        walk.add(ifname)

        out: Set[str] = set()
        for member in interface_members.get(ifname, set()):
            out.update(resolve_interface_targets(member, walk))

        parent = interface_parent.get(ifname)
        if parent:
            out.update(resolve_interface_targets(parent, walk))

        if not out:
            out.add(ifname)

        resolved_interface_cache[ifname] = set(out)
        return out

    zone_table = get_table(tables, ("system", "zone"))
    for zone_name, znode in zone_table.items():
        if not isinstance(znode, Node):
            continue
        _add_zone_membership(facts, str(zone_name), znode.fields.get("interface", []))

    sdwan_zone_table = get_table(tables, ("system", "sdwan", "zone"))
    for zone_name, znode in sdwan_zone_table.items():
        if not isinstance(znode, Node):
            continue
        _add_zone_membership(facts, str(zone_name), znode.fields.get("interface", []))

    sdwan_members: Set[str] = set()
    for path in (("system", "sdwan", "members"), ("members",)):
        sdwan_member_table = get_table(tables, path)
        for _, mnode in sdwan_member_table.items():
            if not isinstance(mnode, Node):
                continue
            sdwan_members.update(as_list(mnode.fields.get("interface")))

    # Expand zone membership through interface hierarchy so callers can
    # resolve both logical and concrete interfaces to their zone.
    for zone, members in list(facts.zone_to_interfaces.items()):
        expanded: Set[str] = set(members)
        for member in list(members):
            expanded.update(resolve_interface_targets(member))
        facts.zone_to_interfaces[zone] = expanded
        for iface in expanded:
            facts.interface_to_zone.setdefault(iface, zone)

    def resolve_device_targets(device_value: Any) -> Set[str]:
        out: Set[str] = set()
        for dev in as_list(device_value):
            if dev in _SDWAN_LOGICAL_DEVICES:
                for member in sdwan_members:
                    out.update(resolve_interface_targets(member))
                continue
            if dev in facts.zone_to_interfaces:
                for member in facts.zone_to_interfaces[dev]:
                    out.update(resolve_interface_targets(member))
                facts.edge_zones.add(dev)
                continue
            out.update(resolve_interface_targets(dev))
        return out

    static_table = get_table(tables, ("router", "static"))
    for _, snode in static_table.items():
        if not isinstance(snode, Node):
            continue
        dst = snode.fields.get("dst")
        dev = snode.fields.get("device")
        if dev is None:
            continue

        if _is_default_route(dst):
            facts.edge_interfaces.update(resolve_device_targets(dev))

    policy_table = get_table(tables, ("router", "policy"))
    for _, pnode in policy_table.items():
        if not isinstance(pnode, Node):
            continue
        if pnode.fields.get("status") == "disable":
            continue
        out_dev = pnode.fields.get("output-device")
        if out_dev is None:
            continue
        facts.edge_interfaces.update(resolve_device_targets(out_dev))

    for zone, members in facts.zone_to_interfaces.items():
        for member in members:
            resolved_members = resolve_interface_targets(member)
            if resolved_members.intersection(facts.edge_interfaces):
                facts.edge_zones.add(zone)
                break

    return facts
