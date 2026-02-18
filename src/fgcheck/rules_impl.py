from __future__ import annotations
from typing import List

from .facts import Facts, get_table
from .model import ConfigModel, Evidence, Node
from .rules import Finding, Rule
from .util import as_list

def rule_admin_edge_ssh(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: List[Finding] = []

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
            out.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                vdom=vdom,
                message=f'Interface "{ifname}" is edge (via default route) and allows SSH management (allowaccess contains ssh).',
                evidence=ev,
            ))
    return out

def rule_admin_edge_https(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: List[Finding] = []

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
            out.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                vdom=vdom,
                message=f'Interface "{ifname}" is edge (via default route) and allows HTTPS management (allowaccess contains https).',
                evidence=ev,
            ))
    return out

def rule_policy_accept_no_log(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    pol_table = get_table(tables, ("firewall", "policy"))
    out: List[Finding] = []

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
            out.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                vdom=vdom,
                message=f'Policy "{pid}" accepts traffic but logging is disabled or unset.',
                evidence=ev,
            ))
    return out
