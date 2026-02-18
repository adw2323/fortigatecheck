from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Set, Tuple

from .model import ConfigModel, Node

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

def build_facts(model: ConfigModel, *, vdom: str = "root") -> Facts:
    facts = Facts()
    tables = model.vdoms.get(vdom, {})

    zone_table = get_table(tables, ("system", "zone"))
    for zone_name, znode in zone_table.items():
        if not isinstance(znode, Node):
            continue
        members = znode.fields.get("interface", [])
        if isinstance(members, str):
            members = [members]
        if isinstance(members, list):
            for iface in members:
                iface = str(iface)
                facts.interface_to_zone[iface] = zone_name
                facts.zone_to_interfaces.setdefault(zone_name, set()).add(iface)

    static_table = get_table(tables, ("router", "static"))
    for _, snode in static_table.items():
        if not isinstance(snode, Node):
            continue
        dst = snode.fields.get("dst")
        dev = snode.fields.get("device")
        if dev is None:
            continue

        is_default = False
        if isinstance(dst, list) and len(dst) >= 2 and dst[0] == "0.0.0.0" and dst[1] == "0.0.0.0":
            is_default = True
        if isinstance(dst, str) and dst in ("0.0.0.0/0", "0.0.0.0"):
            is_default = True

        if is_default:
            facts.edge_interfaces.add(str(dev))

    for iface in list(facts.edge_interfaces):
        z = facts.interface_to_zone.get(iface)
        if z:
            facts.edge_zones.add(z)

    return facts
