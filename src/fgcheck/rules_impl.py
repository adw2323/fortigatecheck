from __future__ import annotations
from typing import List, Optional

from .facts import Facts, get_table
from .model import ConfigModel, Evidence, Node
from .rules import Finding, Rule
from .schema import SchemaView
from .util import as_list

def _schema_supports_field(schema: Optional[SchemaView], table: tuple[str, ...], field: str) -> tuple[bool, bool]:
    # returns: (supported, schema_unknown)
    if schema is None or not schema.loaded:
        return True, True
    if not schema.has_table(table):
        return False, False
    if not schema.has_field(table, field):
        return False, False
    return True, False


def rule_admin_edge_ssh(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: List[Finding] = []
    supported, schema_unknown = _schema_supports_field(schema, ("system", "interface"), "allowaccess")
    if not supported:
        return out

    for ifname, inode in intf_table.items():
        if not isinstance(inode, Node):
            continue
        if str(ifname) not in facts.edge_interfaces:
            continue
        allowaccess = as_list(inode.fields.get("allowaccess"))
        if "ssh" in allowaccess:
            ev = []
            if "set:allowaccess" in inode.evidence:
                ev.append(inode.evidence["set:allowaccess"])
            msg = f'Interface "{ifname}" is edge (via default route) and allows SSH management (allowaccess contains ssh).'
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            ))
    return out

def rule_admin_edge_https(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: List[Finding] = []
    supported, schema_unknown = _schema_supports_field(schema, ("system", "interface"), "allowaccess")
    if not supported:
        return out

    for ifname, inode in intf_table.items():
        if not isinstance(inode, Node):
            continue
        if str(ifname) not in facts.edge_interfaces:
            continue
        allowaccess = as_list(inode.fields.get("allowaccess"))
        if "https" in allowaccess:
            ev = []
            if "set:allowaccess" in inode.evidence:
                ev.append(inode.evidence["set:allowaccess"])
            msg = f'Interface "{ifname}" is edge (via default route) and allows HTTPS management (allowaccess contains https).'
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            ))
    return out

def rule_policy_accept_no_log(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    pol_table = get_table(tables, ("firewall", "policy"))
    out: List[Finding] = []
    action_supported, action_unknown = _schema_supports_field(schema, ("firewall", "policy"), "action")
    log_supported, log_unknown = _schema_supports_field(schema, ("firewall", "policy"), "logtraffic")
    if not action_supported or not log_supported:
        return out
    schema_unknown = action_unknown or log_unknown

    for pid, pnode in pol_table.items():
        if not isinstance(pnode, Node):
            continue
        if pnode.fields.get("action") != "accept":
            continue
        logtraffic = pnode.fields.get("logtraffic")
        if logtraffic in (None, "disable"):
            ev = []
            if "set:logtraffic" in pnode.evidence:
                ev.append(pnode.evidence["set:logtraffic"])
            msg = f'Policy "{pid}" accepts traffic but logging is disabled or unset.'
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            ))
    return out
