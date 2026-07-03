from __future__ import annotations
import base64
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .facts import Facts, get_table
from .model import ConfigModel, Evidence, Node
from .rules import Finding, Rule
from .schema import SchemaView
from .util import as_list

def _merged_scope_tables(
    vdom_tables: dict[str, Any], global_tables: dict[str, Any]
) -> dict[str, Any]:
    """Return a combined view of vdom and global scope tables.

    In multi-VDOM deployments many system-level configs (SNMP, IPS, NTP,
    etc.) live under ``config global`` rather than inside individual VDOMs.
    Rules that only inspect the per-VDOM scope miss these settings.  This
    helper merges both scopes so callers can check both with a single dict
    lookup.  Global entries take priority when the same key exists in both.
    """
    if not global_tables:
        return vdom_tables
    if not vdom_tables:
        return global_tables
    merged = dict(vdom_tables)
    for k, v in global_tables.items():
        if k != "__path__":
            merged[k] = v
    return merged

try:
    from cryptography import x509 as _x509
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

_TRUSTHOST_FIELDS = tuple(f"trusthost{i}" for i in range(1, 11))


def _schema_supports_field(schema: Optional[SchemaView], table: tuple[str, ...], field: str) -> tuple[bool, bool]:
    # returns: (supported, schema_unknown)
    if schema is None or not schema.loaded:
        return True, True
    if not schema.has_table(table):
        return False, False
    if not schema.has_field(table, field):
        if schema.partial:
            return True, True
        return False, False
    return True, False


def _schema_supported_fields(
    schema: Optional[SchemaView],
    table: tuple[str, ...],
    fields: tuple[str, ...],
) -> tuple[list[str], bool]:
    supported_fields: list[str] = []
    schema_unknown = False
    for field in fields:
        supported, unknown = _schema_supports_field(schema, table, field)
        if supported:
            supported_fields.append(field)
            schema_unknown = schema_unknown or unknown
    return supported_fields, schema_unknown


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
        allowaccess = as_list(inode.effective_fields().get("allowaccess"))
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
        allowaccess = as_list(inode.effective_fields().get("allowaccess"))
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

def rule_admin_edge_telnet(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
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
        allowaccess = as_list(inode.effective_fields().get("allowaccess"))
        if "telnet" in allowaccess:
            ev = []
            if "set:allowaccess" in inode.evidence:
                ev.append(inode.evidence["set:allowaccess"])
            msg = f'Interface "{ifname}" is edge (via default route) and allows Telnet management (allowaccess contains telnet).'
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

def rule_admin_edge_http(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
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
        allowaccess = as_list(inode.effective_fields().get("allowaccess"))
        if "http" in allowaccess:
            ev = []
            if "set:allowaccess" in inode.evidence:
                ev.append(inode.evidence["set:allowaccess"])
            msg = f'Interface "{ifname}" is edge (via default route) and allows HTTP management (allowaccess contains http).'
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
        if pnode.effective_fields().get("action") != "accept":
            continue
        logtraffic = pnode.effective_fields().get("logtraffic")
        if logtraffic in (None, "disable"):
            ev = []
            if "set:logtraffic" in pnode.evidence:
                ev.append(pnode.evidence["set:logtraffic"])
            if not ev and "set:action" in pnode.evidence:
                ev.append(pnode.evidence["set:action"])
            if not ev:
                continue
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


def rule_vpn_ssl_min_proto(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    ssl_table = get_table(tables, ("vpn", "ssl", "settings"))
    out: List[Finding] = []
    supported, schema_unknown = _schema_supports_field(schema, ("vpn", "ssl", "settings"), "ssl-min-proto-ver")
    if not supported:
        return out

    node = ssl_table.get("__singleton__")
    if not isinstance(node, Node):
        return out
    value = str(node.effective_fields().get("ssl-min-proto-ver", "")).strip().lower()
    if not value:
        return out
    if value not in {"tls1-0", "tls1-1"}:
        return out

    ev = []
    if "set:ssl-min-proto-ver" in node.evidence:
        ev.append(node.evidence["set:ssl-min-proto-ver"])
    msg = f'SSL-VPN minimum protocol is "{value}", which allows legacy TLS.'
    if schema_unknown:
        msg = f"[schema_unknown] {msg}"
    out.append(
        Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom,
            message=msg,
            evidence=ev,
        )
    )
    return out


def rule_local_in_policy_permissive(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    lip_table = get_table(tables, ("firewall", "local-in-policy"))
    out: List[Finding] = []
    support_checks = [
        _schema_supports_field(schema, ("firewall", "local-in-policy"), "action"),
        _schema_supports_field(schema, ("firewall", "local-in-policy"), "intf"),
        _schema_supports_field(schema, ("firewall", "local-in-policy"), "srcaddr"),
        _schema_supports_field(schema, ("firewall", "local-in-policy"), "service"),
        _schema_supports_field(schema, ("firewall", "local-in-policy"), "status"),
    ]
    if any(not s for s, _ in support_checks):
        return out
    schema_unknown = any(u for _, u in support_checks)

    for pid, pnode in lip_table.items():
        if not isinstance(pnode, Node):
            continue
        if str(pnode.effective_fields().get("status", "")).strip().lower() == "disable":
            continue
        action = str(pnode.effective_fields().get("action", "")).strip().lower()
        if action != "accept":
            continue
        intf_vals = {v.lower() for v in as_list(pnode.effective_fields().get("intf"))}
        src_vals = {v.lower() for v in as_list(pnode.effective_fields().get("srcaddr"))}
        svc_vals = {v.lower() for v in as_list(pnode.effective_fields().get("service"))}
        if "any" not in intf_vals:
            continue
        if "all" not in src_vals:
            continue
        if "all" not in svc_vals:
            continue

        ev = []
        for ek in ("set:action", "set:intf", "set:srcaddr", "set:service"):
            if ek in pnode.evidence:
                ev.append(pnode.evidence[ek])
        msg = f'Local-in policy "{pid}" accepts ALL services from ALL sources on interface "any".'
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            )
        )
    return out


def rule_admin_trusthost_unrestricted(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    admin_table = get_table(tables, ("system", "admin"))
    out: List[Finding] = []
    acc_supported, acc_unknown = _schema_supports_field(schema, ("system", "admin"), "accprofile")
    if not acc_supported:
        return out
    supported_trusthosts, schema_unknown = _schema_supported_fields(schema, ("system", "admin"), _TRUSTHOST_FIELDS)
    if not supported_trusthosts:
        return out
    schema_unknown = schema_unknown or acc_unknown

    for admin_name, anode in admin_table.items():
        if not isinstance(anode, Node):
            continue
        if str(anode.effective_fields().get("accprofile", "")).strip().lower() != "super_admin":
            continue
        ev = []
        if "set:accprofile" in anode.evidence:
            ev.append(anode.evidence["set:accprofile"])
        unrestricted = False
        for field in supported_trusthosts:
            vals = as_list(anode.effective_fields().get(field))
            if len(vals) >= 2 and vals[0] == "0.0.0.0" and vals[1] == "0.0.0.0":
                unrestricted = True
            if f"set:{field}" in anode.evidence:
                ev.append(anode.evidence[f"set:{field}"])
        if not unrestricted:
            continue
        msg = f'Admin "{admin_name}" has super_admin profile with unrestricted trusthost entry.'
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            )
        )
    return out


def rule_sslvpn_source_interface_any(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    ssl_table = get_table(tables, ("vpn", "ssl", "settings"))
    out: List[Finding] = []
    support_checks = [
        _schema_supports_field(schema, ("vpn", "ssl", "settings"), "status"),
        _schema_supports_field(schema, ("vpn", "ssl", "settings"), "source-interface"),
    ]
    if any(not s for s, _ in support_checks):
        return out
    schema_unknown = any(u for _, u in support_checks)

    node = ssl_table.get("__singleton__")
    if not isinstance(node, Node):
        return out
    if str(node.effective_fields().get("status", "enable")).strip().lower() == "disable":
        return out
    if "any" not in {v.lower() for v in as_list(node.effective_fields().get("source-interface"))}:
        return out

    ev = []
    for ek in ("set:status", "set:source-interface"):
        if ek in node.evidence:
            ev.append(node.evidence[ek])
    msg = 'SSL-VPN is enabled and bound to source-interface "any".'
    if schema_unknown:
        msg = f"[schema_unknown] {msg}"
    out.append(
        Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom,
            message=msg,
            evidence=ev,
        )
    )
    return out


def rule_sslvpn_source_address_all(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    ssl_table = get_table(tables, ("vpn", "ssl", "settings"))
    out: List[Finding] = []
    support_checks = [
        _schema_supports_field(schema, ("vpn", "ssl", "settings"), "status"),
        _schema_supports_field(schema, ("vpn", "ssl", "settings"), "source-address"),
        _schema_supports_field(schema, ("vpn", "ssl", "settings"), "source-address-negate"),
    ]
    if any(not s for s, _ in support_checks):
        return out
    schema_unknown = any(u for _, u in support_checks)

    node = ssl_table.get("__singleton__")
    if not isinstance(node, Node):
        return out
    if str(node.effective_fields().get("status", "enable")).strip().lower() == "disable":
        return out
    if str(node.effective_fields().get("source-address-negate", "")).strip().lower() == "enable":
        return out
    if "all" not in {v.lower() for v in as_list(node.effective_fields().get("source-address"))}:
        return out

    ev = []
    for ek in ("set:status", "set:source-address", "set:source-address-negate"):
        if ek in node.evidence:
            ev.append(node.evidence[ek])
    msg = 'SSL-VPN is enabled and permits source-address "all".'
    if schema_unknown:
        msg = f"[schema_unknown] {msg}"
    out.append(
        Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom,
            message=msg,
            evidence=ev,
        )
    )
    return out


def rule_admin_super_no_2fa(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    admin_table = get_table(tables, ("system", "admin"))
    out: List[Finding] = []
    acc_supported, acc_unknown = _schema_supports_field(schema, ("system", "admin"), "accprofile")
    tf_supported, tf_unknown = _schema_supports_field(schema, ("system", "admin"), "two-factor")
    tfa_supported, tfa_unknown = _schema_supports_field(schema, ("system", "admin"), "two-factor-authentication")
    if not acc_supported:
        return out
    if not tf_supported and not tfa_supported:
        return out
    schema_unknown = acc_unknown or tf_unknown or tfa_unknown

    for admin_name, anode in admin_table.items():
        if not isinstance(anode, Node):
            continue
        if str(anode.effective_fields().get("accprofile", "")).strip().lower() != "super_admin":
            continue
        tf = str(anode.effective_fields().get("two-factor", "")).strip().lower()
        tfa = str(anode.effective_fields().get("two-factor-authentication", "")).strip().lower()
        enabled = (tf == "enable") or (tfa == "enable")
        if enabled:
            continue

        ev = []
        for ek in ("set:accprofile", "set:two-factor", "set:two-factor-authentication"):
            if ek in anode.evidence:
                ev.append(anode.evidence[ek])
        if not ev:
            continue
        msg = f'Admin "{admin_name}" has super_admin profile without two-factor enabled.'
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            )
        )
    return out


def rule_admin_edge_allaccess(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: List[Finding] = []
    supported, schema_unknown = _schema_supports_field(schema, ("system", "interface"), "allowaccess")
    if not supported:
        return out

    broad_access = {"http", "https", "ssh", "telnet", "snmp", "fgfm", "fabric"}
    for ifname, inode in intf_table.items():
        if not isinstance(inode, Node):
            continue
        if str(ifname) not in facts.edge_interfaces:
            continue
        access_set = {v.lower() for v in as_list(inode.effective_fields().get("allowaccess"))}
        if len(access_set.intersection(broad_access)) < 4:
            continue
        ev = []
        if "set:allowaccess" in inode.evidence:
            ev.append(inode.evidence["set:allowaccess"])
        msg = f'Edge interface "{ifname}" exposes broad management access via allowaccess.'
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            )
        )
    return out


def rule_admin_no_trusted_hosts(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    admin_table = get_table(tables, ("system", "admin"))
    out: List[Finding] = []
    supported_trusthosts, schema_unknown = _schema_supported_fields(schema, ("system", "admin"), _TRUSTHOST_FIELDS)
    if not supported_trusthosts:
        return out

    for admin_name, anode in admin_table.items():
        if not isinstance(anode, Node):
            continue
        has_trusthost = False
        for field in supported_trusthosts:
            if as_list(anode.effective_fields().get(field)):
                has_trusthost = True
                break
        if has_trusthost:
            continue
        ev = []
        for field in supported_trusthosts:
            ek = f"set:{field}"
            if ek in anode.evidence:
                ev.append(anode.evidence[ek])
        if "set:accprofile" in anode.evidence:
            ev.append(anode.evidence["set:accprofile"])
        if not ev:
            continue
        msg = f'Admin "{admin_name}" has no trusted host restriction (no trusthost entries set).'
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            )
        )
    return out


def rule_localin_no_protection(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    lip_table = get_table(tables, ("firewall", "local-in-policy"))
    out: List[Finding] = []
    action_supported, action_unknown = _schema_supports_field(schema, ("firewall", "local-in-policy"), "action")
    status_supported, status_unknown = _schema_supports_field(schema, ("firewall", "local-in-policy"), "status")
    if not action_supported or not status_supported:
        return out
    schema_unknown = action_unknown or status_unknown

    enabled_entries: List[Node] = []
    has_deny = False
    for _, pnode in lip_table.items():
        if not isinstance(pnode, Node):
            continue
        if str(pnode.effective_fields().get("status", "")).strip().lower() == "disable":
            continue
        enabled_entries.append(pnode)
        if str(pnode.effective_fields().get("action", "")).strip().lower() == "deny":
            has_deny = True
    if not enabled_entries or has_deny:
        return out

    ev: List[Evidence] = []
    sample = enabled_entries[0]
    for ek in ("set:action", "set:status"):
        if ek in sample.evidence:
            ev.append(sample.evidence[ek])
    if not ev:
        return out
    msg = "No enabled local-in policy provides explicit deny protection."
    if schema_unknown:
        msg = f"[schema_unknown] {msg}"
    out.append(
        Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom,
            message=msg,
            evidence=ev,
        )
    )
    return out


def rule_policy_any_any_all(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    pol_table = get_table(tables, ("firewall", "policy"))
    out: List[Finding] = []
    support_checks = [
        _schema_supports_field(schema, ("firewall", "policy"), "action"),
        _schema_supports_field(schema, ("firewall", "policy"), "srcaddr"),
        _schema_supports_field(schema, ("firewall", "policy"), "dstaddr"),
        _schema_supports_field(schema, ("firewall", "policy"), "service"),
        _schema_supports_field(schema, ("firewall", "policy"), "status"),
    ]
    if any(not s for s, _ in support_checks):
        return out
    schema_unknown = any(u for _, u in support_checks)

    for pid, pnode in pol_table.items():
        if not isinstance(pnode, Node):
            continue
        if str(pnode.effective_fields().get("status", "")).strip().lower() == "disable":
            continue
        if str(pnode.effective_fields().get("action", "")).strip().lower() != "accept":
            continue
        src = {v.lower() for v in as_list(pnode.effective_fields().get("srcaddr"))}
        dst = {v.lower() for v in as_list(pnode.effective_fields().get("dstaddr"))}
        svc = {v.lower() for v in as_list(pnode.effective_fields().get("service"))}
        if "all" not in src or "all" not in dst or "all" not in svc:
            continue

        ev = []
        for ek in ("set:action", "set:srcaddr", "set:dstaddr", "set:service"):
            if ek in pnode.evidence:
                ev.append(pnode.evidence[ek])
        msg = f'Policy "{pid}" is accept with srcaddr=all, dstaddr=all, service=ALL.'
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            )
        )
    return out


def rule_ipsec_weak_dh(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []
    weak_groups = {"1", "2", "5"}
    phase1_paths = [("vpn", "ipsec", "phase1-interface"), ("vpn", "ipsec", "phase1")]

    any_supported = False
    any_schema_unknown = False
    phase_tables: List[dict[str, Node]] = []
    for path in phase1_paths:
        dh_supported, dh_unknown = _schema_supports_field(schema, path, "dhgrp")
        if not dh_supported:
            continue
        any_supported = True
        any_schema_unknown = any_schema_unknown or dh_unknown
        phase_tables.append(get_table(tables, path))
    if not any_supported:
        return out

    seen_keys: set[str] = set()
    for phase_table in phase_tables:
        for pname, pnode in phase_table.items():
            if not isinstance(pnode, Node):
                continue
            dedupe_key = str(pname).strip().lower()
            if dedupe_key in seen_keys:
                continue
            if str(pnode.effective_fields().get("status", "")).strip().lower() == "disable":
                continue
            groups = {v.strip() for v in as_list(pnode.effective_fields().get("dhgrp"))}
            if not groups.intersection(weak_groups):
                continue
            ev = []
            if "set:dhgrp" in pnode.evidence:
                ev.append(pnode.evidence["set:dhgrp"])
            msg = f'IPsec phase1 "{pname}" uses weak DH group(s): {", ".join(sorted(groups.intersection(weak_groups)))}.'
            if any_schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=("heuristic" if any_schema_unknown else rule.confidence),
                    vdom=vdom,
                    message=msg,
                    evidence=ev,
                )
            )
            seen_keys.add(dedupe_key)
    return out


def rule_no_remote_logging(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    remote_paths = [
        ("log", "syslogd", "setting"),
        ("log", "syslogd2", "setting"),
        ("log", "syslogd3", "setting"),
        ("log", "syslogd4", "setting"),
        ("log", "fortianalyzer", "setting"),
        ("log", "fortianalyzer2", "setting"),
        ("log", "fortianalyzer3", "setting"),
        ("log", "fortianalyzer-cloud", "setting"),
    ]

    supported_paths: List[tuple[str, ...]] = []
    schema_unknown = False
    for path in remote_paths:
        supported, unknown = _schema_supports_field(schema, path, "status")
        if supported:
            supported_paths.append(path)
            schema_unknown = schema_unknown or unknown
    if not supported_paths:
        return out

    ev: List[Evidence] = []
    for path in supported_paths:
        table = get_table(tables, path)
        node = table.get("__singleton__")
        if isinstance(node, Node):
            if str(node.effective_fields().get("status", "")).strip().lower() == "enable":
                return out
            if "set:status" in node.evidence:
                ev.append(node.evidence["set:status"])

    # Do not emit findings from implicit defaults; require explicit config evidence.
    if not ev:
        return out

    msg = "No remote logging target is enabled."
    if schema_unknown:
        msg = f"[schema_unknown] {msg}"
    out.append(
        Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom,
            message=msg,
            evidence=ev,
        )
    )
    return out


def rule_dns_zone_transfer(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    """Detect DNS server entries with zone-transfer enabled."""
    tables = model.vdoms.get(vdom, {})
    dns_table = get_table(tables, ("dns", "server"))
    out: List[Finding] = []
    supported, schema_unknown = _schema_supports_field(schema, ("dns", "server"), "zone-transfer")
    if not supported:
        return out

    for name, node in dns_table.items():
        if not isinstance(node, Node):
            continue
        zt_val = str(node.effective_fields().get("zone-transfer", "")).strip().lower()
        if zt_val != "enable":
            continue
        ev: List[Evidence] = []
        if "set:zone-transfer" in node.evidence:
            ev.append(node.evidence["set:zone-transfer"])
        if not ev:
            continue
        msg = f'DNS server entry "{name}" has zone-transfer enabled, allowing AXFR requests.'
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            )
        )
    return out


# ---------------------------------------------------------------------------
# FGT-DNS-DEFAULT-ONLY
# Detects when DNS resolution uses only well-known public/default resolvers
# (e.g. 8.8.8.8, 1.1.1.1) with cleartext protocol, indicating an unreviewed
# out-of-box configuration with unencrypted DNS queries.
# ---------------------------------------------------------------------------

_DEFAULT_DNS_SERVERS: frozenset[str] = frozenset({
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "208.67.222.222",
    "208.67.220.220",
    "9.9.9.9",
    "149.112.112.112",
    "64.6.64.6",
    "64.6.65.6",
})


def rule_dns_default_only(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect DNS configured with only default public resolvers and cleartext."""
    out: List[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "dns"), "primary"
    )
    if not supported:
        return out

    # DNS config lives in config global scope or in vdom scope
    global_tables = model.global_cfg
    vdom_tables = model.vdoms.get(vdom, {})

    dns_global = get_table(global_tables, ("system", "dns"))
    dns_vdom = get_table(vdom_tables, ("system", "dns"))

    node_global = dns_global.get("__singleton__")
    node_vdom = dns_vdom.get("__singleton__")
    node = node_global if isinstance(node_global, Node) else node_vdom
    if not isinstance(node, Node):
        return out

    primary = str(node.effective_fields().get("primary", "")).strip()
    secondary = str(node.effective_fields().get("secondary", "")).strip()
    protocol = str(node.effective_fields().get("protocol", "")).strip().lower()

    # Collect all configured DNS servers
    servers: list[str] = []
    if primary:
        servers.append(primary)
    if secondary:
        servers.append(secondary)

    # Also check for additional DNS entries (alt-*, etc.)
    for field_name in node.effective_fields():
        if field_name.startswith("alt"):
            val = str(node.effective_fields()[field_name]).strip()
            if val:
                servers.append(val)

    if not servers:
        return out

    # All servers must be default public resolvers
    all_default = all(s in _DEFAULT_DNS_SERVERS for s in servers)
    if not all_default:
        return out

    # Build evidence
    ev: List[Evidence] = []
    for field_name in ("set:primary", "set:secondary", "set:protocol"):
        if field_name in node.evidence:
            ev.append(node.evidence[field_name])
    # Also collect alt-* evidence
    for field_name in node.evidence:
        if field_name.startswith("set:alt"):
            ev.append(node.evidence[field_name])

    if not ev:
        return out

    # Determine message based on protocol
    if protocol == "cleartext" or protocol == "":
        msg = (
            f"DNS is configured with only default public resolvers "
            f"({', '.join(servers)}) using cleartext protocol. "
            f"DNS queries are unencrypted and may be intercepted or spoofed. "
            f"Consider using DNS-over-TLS, DNS-over-HTTPS, or internal resolvers."
        )
    else:
        msg = (
            f"DNS is configured with only default public resolvers "
            f"({', '.join(servers)}). While protocol is '{protocol}', "
            f"using default resolvers may indicate an unreviewed configuration. "
            f"Consider using internal resolvers."
        )

    if schema_unknown:
        msg = f"[schema_unknown] {msg}"

    out.append(
        Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom,
            message=msg,
            evidence=ev,
        )
    )
    return out


def rule_ntp_no_ntps(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    """Detect NTP configuration without NTPS (unencrypted time sync)."""
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    ntp_table = get_table(tables, ("system", "ntp"))
    out: List[Finding] = []
    ntps_supported, ntps_unknown = _schema_supports_field(schema, ("system", "ntp"), "ntps")
    type_supported, type_unknown = _schema_supports_field(schema, ("system", "ntp"), "type")
    if not ntps_supported:
        return out
    schema_unknown = ntps_unknown or type_unknown

    node = ntp_table.get("__singleton__")
    if not isinstance(node, Node):
        return out
    ntps_val = str(node.effective_fields().get("ntps", "")).strip().lower()
    if ntps_val == "enable":
        return out
    ev: List[Evidence] = []
    if "set:ntps" in node.evidence:
        ev.append(node.evidence["set:ntps"])
    if "set:type" in node.evidence:
        ev.append(node.evidence["set:type"])
    if not ev:
        return out
    msg = "NTP is configured without NTPS; time synchronization is unencrypted."
    if schema_unknown:
        msg = f"[schema_unknown] {msg}"
    out.append(
        Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom,
            message=msg,
            evidence=ev,
        )
    )
    return out


_WEAK_SNMP_COMMUNITIES: set[str] = {
    "public",
    "private",
    "community",
    "snmp",
    "monitoring",
    "default",
    "readonly",
    "readwrite",
    "read-only",
    "read-write",
}


def rule_snmp_weak_community(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    """Detect SNMP communities using default or well-known weak strings."""
    tables = model.vdoms.get(vdom, {})
    snmp_table = get_table(tables, ("system", "snmp", "community"))
    out: List[Finding] = []
    supported, schema_unknown = _schema_supports_field(schema, ("system", "snmp", "community"), "name")
    if not supported:
        return out

    for entry_name, node in snmp_table.items():
        if not isinstance(node, Node):
            continue
        community = str(node.effective_fields().get("name", "")).strip().lower()
        if community not in _WEAK_SNMP_COMMUNITIES:
            continue
        ev: List[Evidence] = []
        if "set:name" in node.evidence:
            ev.append(node.evidence["set:name"])
        if not ev:
            continue
        msg = f'SNMP community "{community}" is a default or well-known weak community string.'
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            )
        )
    return out


# ---------------------------------------------------------------------------
# FGT-ADMIN-WEAK-PASSWORD-POLICY
# Detects when the administrator password policy is disabled, uses a minimum
# length below 8, or lacks minimum character-class requirements.
# ---------------------------------------------------------------------------

_MIN_LENGTH_THRESHOLD = 8  # NIST SP 800-63B / CIS FortiGate benchmark


def rule_admin_weak_password_policy(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect weak or disabled administrator password policy."""
    tables = model.vdoms.get(vdom, {})
    pw_table = get_table(tables, ("system", "password-policy"))
    out: List[Finding] = []

    # Check schema support for the fields we need.
    status_supported, status_unknown = _schema_supports_field(
        schema, ("system", "password-policy"), "status"
    )
    minlen_supported, minlen_unknown = _schema_supports_field(
        schema, ("system", "password-policy"), "minimum-length"
    )
    schema_unknown = status_unknown or minlen_unknown

    if not status_supported and not minlen_supported:
        return out

    node = pw_table.get("__singleton__")
    if not isinstance(node, Node):
        # No password-policy block found — this means the policy is at
        # factory defaults (disabled).  We only flag when there is explicit
        # evidence that the policy was configured and then disabled.
        # A missing block means the default is active (disabled), but
        # without explicit evidence we should not emit a finding.
        return out

    findings: List[Finding] = []

    # --- Check 1: policy is explicitly disabled ---
    if status_supported:
        status_val = str(node.effective_fields().get("status", "")).strip().lower()
        if status_val == "disable":
            ev: List[Evidence] = []
            if "set:status" in node.evidence:
                ev.append(node.evidence["set:status"])
            if ev:
                msg = "Administrator password policy is explicitly disabled."
                if schema_unknown:
                    msg = f"[schema_unknown] {msg}"
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=("heuristic" if schema_unknown else rule.confidence),
                        vdom=vdom,
                        message=msg,
                        evidence=ev,
                    )
                )

    # --- Check 2: minimum-length below threshold ---
    if minlen_supported and not findings:
        minlen_raw = node.effective_fields().get("minimum-length")
        if minlen_raw is not None:
            try:
                minlen_val = int(minlen_raw)
            except (ValueError, TypeError):
                minlen_val = 0
            if 0 < minlen_val < _MIN_LENGTH_THRESHOLD:
                ev2: List[Evidence] = []
                if "set:minimum-length" in node.evidence:
                    ev2.append(node.evidence["set:minimum-length"])
                if ev2:
                    msg = (
                        f"Password policy minimum-length is {minlen_val}, "
                        f"below the recommended {_MIN_LENGTH_THRESHOLD} characters."
                    )
                    if schema_unknown:
                        msg = f"[schema_unknown] {msg}"
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            confidence=("heuristic" if schema_unknown else rule.confidence),
                            vdom=vdom,
                            message=msg,
                            evidence=ev2,
                        )
                    )

    out.extend(findings)
    return out


# ---------------------------------------------------------------------------
# FGT-ADMIN-NO-IDLE-TIMEOUT
# Detects when the administrator idle timeout is explicitly set to 0 (disabled,
# meaning sessions never expire) or exceeds the recommended maximum.
# The FortiGate default is 5 minutes; best practice recommends <= 15 minutes.
# ---------------------------------------------------------------------------

_IDLE_TIMEOUT_DISABLED = 0   # never timeout — high risk
_IDLE_TIMEOUT_MAX = 15       # recommended maximum in minutes


def rule_admin_no_idle_timeout(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect disabled or excessively long administrator idle timeout."""
    out: List[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "global"), "admin-idle-timeout"
    )
    if not supported:
        return out

    # config system global is stored in the global scope (config global block)
    # but may also appear directly in the vdom scope for exported configs.
    global_table = get_table(model.global_cfg, ("system", "global"))
    vdom_table = get_table(model.vdoms.get(vdom, {}), ("system", "global"))

    # Prefer the global scope; fall back to vdom scope.
    node_global = global_table.get("__singleton__")
    node_vdom = vdom_table.get("__singleton__")
    node = node_global if isinstance(node_global, Node) else node_vdom
    if not isinstance(node, Node):
        return out

    raw = node.effective_fields().get("admin-idle-timeout")
    if raw is None:
        return out

    try:
        timeout_val = int(raw)
    except (ValueError, TypeError):
        return out

    ev: List[Evidence] = []
    if "set:admin-idle-timeout" in node.evidence:
        ev.append(node.evidence["set:admin-idle-timeout"])

    if not ev:
        return out

    msg: str = ""
    severity = rule.severity

    if timeout_val == _IDLE_TIMEOUT_DISABLED:
        msg = (
            "Administrator idle timeout is set to 0 (disabled). "
            "Administrator sessions will never expire, allowing abandoned "
            "sessions to remain active indefinitely."
        )
        severity = "high"
    elif timeout_val > _IDLE_TIMEOUT_MAX:
        msg = (
            f"Administrator idle timeout is {timeout_val} minutes, "
            f"exceeding the recommended maximum of {_IDLE_TIMEOUT_MAX} "
            f"minutes. Long-lived abandoned sessions increase the risk "
            f"of unauthorized access."
        )
        severity = "medium"

    if msg:
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom,
                message=msg,
                evidence=ev,
            )
        )

    return out


# ---------------------------------------------------------------------------
# FGT-FIRMWARE-OUTDATED
# Detects when the FortiGate firmware version is not at the latest known
# patch level for its version family. Outdated firmware may contain known
# security vulnerabilities that have been patched in subsequent releases.
#
# The version is extracted from the config header line
# (#config-version=...) which the parser stores in model.meta["header_lines"].
# If no header is present, the rule falls back to the target_fortios value
# set by rules.run() (family only, e.g. "7.4"), which provides less
# granularity but still allows family-level freshness checks.
# ---------------------------------------------------------------------------

# Latest known stable patch release per version family.
# Updated when new FortiOS patch releases are validated against schema.
_LATEST_PER_FAMILY: dict[str, tuple[int, ...]] = {
    "7.4": (7, 4, 12),
    "7.6": (7, 6, 7),
    "8.0": (8, 0, 0),
}


def _parse_version_tuple(version_str: str) -> tuple[int, ...] | None:
    """Parse a dotted version string like '7.4.3' into (7, 4, 3)."""
    parts = version_str.strip().split(".")
    try:
        return tuple(int(p) for p in parts)
    except (ValueError, TypeError):
        return None


def _get_header_versions(meta: dict) -> list[str]:
    """Extract firmware version strings from config header lines."""
    from .versioning import _extract_header_fortios_version, _header_lines

    versions: list[str] = []
    for header in _header_lines(meta):
        v = _extract_header_fortios_version(header)
        if v:
            versions.append(v)
    return versions


def rule_firmware_outdated(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect outdated firmware version relative to latest known patch."""
    out: List[Finding] = []

    # Extract the exact version from the config header.
    header_versions = _get_header_versions(model.meta)

    # If no header present, fall back to target_fortios (family only).
    detected_version: str | None = None
    if header_versions:
        detected_version = header_versions[0]
    else:
        detected_version = model.meta.get("target_fortios")

    if detected_version is None:
        return out

    detected_tuple = _parse_version_tuple(detected_version)
    if detected_tuple is None or len(detected_tuple) < 3:
        # Need full 3-component version (e.g. 7.4.3) to compare against
        # patch-level latest. Family-only versions (e.g. 7.4) are not
        # specific enough to determine if firmware is outdated.
        return out

    # Determine the family from the first two components.
    family = f"{detected_tuple[0]}.{detected_tuple[1]}"
    latest = _LATEST_PER_FAMILY.get(family)
    if latest is None:
        # Unknown family - cannot compare; skip gracefully.
        return out

    # Compare: is the detected version older than the latest known?
    if detected_tuple >= latest:
        return out  # firmware is up to date (or newer than known)

    # Build evidence from the config header line.
    ev: List[Evidence] = []
    header_lines = model.meta.get("header_lines", [])
    for item in header_lines:
        if isinstance(item, tuple) and len(item) >= 2:
            line_no, raw = item[0], item[1]
            if detected_version in str(raw):
                ev.append(Evidence(
                    file_id=model.meta.get("file_id", ""),
                    line_range=(line_no, line_no),
                    path=(),
                    raw_lines=[str(raw)],
                ))
                break

    detected_str = ".".join(str(p) for p in detected_tuple)
    latest_str = ".".join(str(p) for p in latest)

    # Determine severity based on how far behind the detected version is.
    # For same-family versions, compare the full version tuple.
    # major+minor gap >= 2 -> critical; 1 minor behind -> high;
    # same minor but patch behind -> high if 5+ patches, else medium.
    version_gap = latest[1] - detected_tuple[1]
    patch_gap = latest[2] - detected_tuple[2] if len(detected_tuple) >= 3 else 0

    if version_gap >= 2:
        severity = "critical"
    elif version_gap >= 1:
        severity = "high"
    elif patch_gap >= 5:
        severity = "high"
    else:
        severity = "medium"

    msg = (
        f"FortiOS firmware version {detected_str} is outdated. "
        f"The latest known release for the {family}.x family is "
        f"{latest_str}. Running outdated firmware may expose the "
        f"device to known security vulnerabilities that have been "
        f"patched in later releases."
    )

    out.append(Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=severity,
        confidence=rule.confidence,
        vdom=vdom,
        message=msg,
        evidence=ev,
    ))

    return out


# ---------------------------------------------------------------------------
# FGT-SSH-WEAK-CIPHERS
# Detects SSH service configured with weak ciphers, weak key-exchange
# algorithms, or weak MAC algorithms on the FortiGate.
#
# The FortiGate SSH config lives in `config system ssh-config` and controls
# the SSH server (management access) and the SSH client (outgoing SSH).
# Weak ciphers/exchange algorithms reduce the security of management plane
# access and can be exploited by man-in-the-middle attackers.
#
# Schema status: system ssh-config is table_only in all versions.
# This rule therefore always runs at heuristic confidence.
# ---------------------------------------------------------------------------

_WEAK_SSH_CIPHERS: set[str] = {
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "blowfish-cbc",
    "arcfour",
    "arcfour-md5",
    "cast128-cbc",
}

_WEAK_SSH_KEX: set[str] = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}

_WEAK_SSH_MAC: set[str] = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1-96",
}


def _check_ssh_config_field(
    node: "Node",
    field: str,
    weak_set: set[str],
    label: str,
    rule: "Rule",
    vdom: str,
    schema_unknown: bool,
) -> list["Finding"]:
    """Check a single SSH config field for weak values."""
    findings: list["Finding"] = []
    raw = str(node.effective_fields().get(field, "")).strip().lower()
    if not raw:
        return findings

    # ssh-key-exchange may contain multiple space-separated algorithms
    values = [v.strip() for v in raw.split() if v.strip()]
    weak_found = [v for v in values if v in weak_set]
    if not weak_found:
        return findings

    ev: list["Evidence"] = []
    evidence_key = f"set:{field}"
    if evidence_key in node.evidence:
        ev.append(node.evidence[evidence_key])

    if not ev:
        return findings

    msg = (
        f"SSH config field '{field}' contains weak {label}: "
        f"{', '.join(weak_found)}. "
        f"Weak {label} can be exploited by man-in-the-middle attacks "
        f"to downgrade the security of management plane SSH connections. "
        f"Replace with strong alternatives (e.g. AES-CTR, "
        f"diffie-hellman-group14-sha256, hmac-sha2-256)."
    )
    if schema_unknown:
        msg = f"[schema_unknown] {msg}"

    findings.append(
        Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom,
            message=msg,
            evidence=ev,
        )
    )
    return findings


def rule_ssh_weak_ciphers(
    *,
    model: "ConfigModel",
    facts: "Facts",
    vdom: str,
    rule: "Rule",
    schema: Optional["SchemaView"] = None,
) -> list["Finding"]:
    """Detect SSH service configured with weak ciphers, key-exchange, or MAC."""
    out: list["Finding"] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "ssh-config"), "ssh-cipher-1"
    )
    if not supported:
        return out

    # ssh-config is a singleton — check both global and vdom scope
    global_table = get_table(model.global_cfg, ("system", "ssh-config"))
    vdom_table = get_table(model.vdoms.get(vdom, {}), ("system", "ssh-config"))

    node_global = global_table.get("__singleton__")
    node_vdom = vdom_table.get("__singleton__")
    node = node_global if isinstance(node_global, Node) else node_vdom
    if not isinstance(node, Node):
        return out

    # Check incoming SSH server ciphers (ssh-cipher-1, ssh-cipher-2, ssh-cipher-3)
    for field in ("ssh-cipher-1", "ssh-cipher-2", "ssh-cipher-3"):
        out.extend(
            _check_ssh_config_field(
                node, field, _WEAK_SSH_CIPHERS, "ciphers",
                rule, vdom, schema_unknown,
            )
        )

    # Check key-exchange algorithms
    out.extend(
        _check_ssh_config_field(
            node, "ssh-key-exchange", _WEAK_SSH_KEX,
            "key-exchange algorithms", rule, vdom, schema_unknown,
        )
    )

    # Check MAC algorithms
    for field in ("ssh-local-mac",):
        out.extend(
            _check_ssh_config_field(
                node, field, _WEAK_SSH_MAC, "MAC algorithms",
                rule, vdom, schema_unknown,
            )
        )

    # Check outgoing SSH client ciphers
    for field in ("ssh-local-cipher",):
        out.extend(
            _check_ssh_config_field(
                node, field, _WEAK_SSH_CIPHERS, "ciphers",
                rule, vdom, schema_unknown,
            )
        )

    # Check outgoing SSH client key exchange
    for field in ("ssh-local-kex",):
        out.extend(
            _check_ssh_config_field(
                node, field, _WEAK_SSH_KEX,
                "key-exchange algorithms", rule, vdom, schema_unknown,
            )
        )

    return out


# ---------------------------------------------------------------------------
# FGT-SNMP-NO-ACL
# Detects SNMP communities configured without host ACL restrictions.
#
# When a FortiGate SNMP community has no hosts ACL configured, any host on
# the network can query SNMP for system information. This information can be
# used to fingerprint the device, enumerate interfaces, and identify services.
#
# Detection strategy (two signals):
# 1. Community has a 'hosts' field set to 0.0.0.0 0.0.0.0 — unrestricted.
# 2. Community has no 'hosts' field at all and no hosts sub-table entries
#    exist in the model — no ACL whatsoever.
#
# The parser flattens nested 'config hosts' sub-tables to root level, losing
# the parent community association. We handle this by:
# - Checking each community node's own 'hosts' field (inline set syntax).
# - If no community has hosts AND no hosts sub-table exists, all communities
#   are flagged as unrestricted.
# ---------------------------------------------------------------------------


def _hosts_is_unrestricted(hosts_val: object) -> bool:
    """Return True if a community hosts field allows all hosts."""
    if isinstance(hosts_val, list):
        # Parser stores 'set hosts 0.0.0.0 0.0.0.0' as ['0.0.0.0', '0.0.0.0']
        if len(hosts_val) >= 2 and hosts_val[0] == "0.0.0.0":
            return True
    elif isinstance(hosts_val, str):
        if hosts_val.strip() in ("0.0.0.0/0", "0.0.0.0 0.0.0.0"):
            return True
    return False


def rule_snmp_no_acl(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect SNMP communities without host ACL restrictions."""
    out: List[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "snmp", "community"), "name"
    )
    if not supported:
        return out

    tables = model.vdoms.get(vdom, {})
    snmp_table = get_table(tables, ("system", "snmp", "community"))

    # Collect all community entries
    communities: list[dict] = []
    for entry_name, node in snmp_table.items():
        if not isinstance(node, Node):
            continue
        communities.append({
            "name": str(node.effective_fields().get("name", f"community-{entry_name}")).strip(),
            "entry": entry_name,
            "node": node,
            "has_hosts_field": "hosts" in node.effective_fields(),
            "hosts_field": node.effective_fields().get("hosts"),
        })

    if not communities:
        return out

    # Check if any hosts sub-table entries exist in the model
    hosts_table = get_table(tables, ("hosts",))
    has_any_host_entry = any(
        isinstance(v, Node) for k, v in hosts_table.items() if k != "__path__"
    )

    for comm in communities:
        name = comm["name"]
        node = comm["node"]

        # Signal 1: community has hosts field set to 0.0.0.0/0 (unrestricted)
        if comm["has_hosts_field"]:
            if _hosts_is_unrestricted(comm["hosts_field"]):
                ev: List[Evidence] = []
                if "set:name" in node.evidence:
                    ev.append(node.evidence["set:name"])
                if "set:hosts" in node.evidence:
                    ev.append(node.evidence["set:hosts"])
                if not ev:
                    continue
                msg = (
                    f'SNMP community "{name}" has a hosts ACL of 0.0.0.0/0, '
                    f"allowing any host to query SNMP. Restrict to authorized "
                    f"management stations only."
                )
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
            # Community has specific hosts — skip
            continue

        # Signal 2: community has no hosts field at all
        # Only flag if no hosts sub-table exists in the model either,
        # because the sub-table might contain its ACL (parser flattening
        # means we can't tell which community owns the sub-table entries).
        if has_any_host_entry:
            # Hosts sub-table exists — some community has ACL, we can't tell
            # which ones are restricted vs unrestricted due to parser flattening.
            # Skip rather than produce false positives.
            continue

        # No hosts field on community AND no hosts sub-table anywhere
        ev2: List[Evidence] = []
        if "set:name" in node.evidence:
            ev2.append(node.evidence["set:name"])
        if not ev2:
            continue

        msg = (
            f'SNMP community "{name}" has no host ACL configured. '
            f"Any host on the network can query SNMP for system "
            f"information, including interface addresses, routing tables, "
            f"and device version. Configure a hosts ACL to restrict "
            f"SNMP access to authorized management stations."
        )
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"

        out.append(Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom,
            message=msg,
            evidence=ev2,
        ))

    return out


# ---------------------------------------------------------------------------
# FGT-CERT-EXPIRING
# Detects local certificates that are expiring within a configurable threshold
# or have already expired.
#
# The FortiGate certificate config lives in `config certificate local` and
# contains the PEM-encoded certificate data. Expired or soon-to-expire certs
# can cause TLS/VPN failures, admin GUI lockouts, and IPSec tunnel drops.
#
# The rule extracts PEM blocks from the certificate field and parses them
# using the cryptography library if available. When the library is missing,
# the rule falls back to heuristic detection (looks for common expired-cert
# patterns) and marks findings with schema_unknown.
# ---------------------------------------------------------------------------

# Default threshold: flag certificates expiring within this many days.
_CERT_EXPIRY_THRESHOLD_DAYS: int = 30

# Patterns that indicate a certificate is likely expired or invalid
# (fallback when cryptography library is not available).
_CERT_REDACTED_PATTERNS: set[str] = {
    "REDACTED",
    "REMOVED",
    "PLACEHOLDER",
    "<REDACTED>",
    "***",
}


def _parse_pem_certificates(cert_field: object) -> list[str]:
    """Extract PEM certificate blocks from a certificate field value.

    The parser may store the certificate as:
    - A list of strings (multiline PEM split across lines)
    - A single string (inline PEM or redacted placeholder)
    """
    if cert_field is None:
        return []

    # Join list items into a single string if needed
    if isinstance(cert_field, list):
        raw = "\n".join(str(item) for item in cert_field)
    else:
        raw = str(cert_field)

    # Find all PEM certificate blocks
    pem_pattern = re.compile(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        re.DOTALL,
    )
    matches = pem_pattern.findall(raw)
    if matches:
        return matches

    return []


def _check_certificate_expiry(
    pem_data: str,
) -> tuple[bool, bool, str | None]:
    """Check if a PEM certificate is expired or expiring soon.

    Returns:
        (is_problematic, is_expired, expiry_info_str)
    """
    if not _HAS_CRYPTOGRAPHY:
        return False, False, None

    try:
        cert = _x509.load_pem_x509_certificate(pem_data.encode("utf-8"))
    except Exception:
        return False, False, None

    now = datetime.now(timezone.utc)

    # Check if already expired
    if cert.not_valid_after_utc < now:
        days_expired = (now - cert.not_valid_after_utc).days
        return True, True, f"expired {days_expired} days ago"

    # Check if expiring within threshold
    days_remaining = (cert.not_valid_after_utc - now).days
    if days_remaining <= _CERT_EXPIRY_THRESHOLD_DAYS:
        return True, False, f"expires in {days_remaining} days"

    return False, False, None


def rule_cert_expiring(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect local certificates that are expired or expiring soon."""
    out: List[Finding] = []

    tables = model.vdoms.get(vdom, {})
    cert_table = get_table(tables, ("certificate", "local"))

    if not cert_table:
        return out

    for cert_name, cert_node in cert_table.items():
        if not isinstance(cert_node, Node):
            continue

        cert_field = cert_node.effective_fields().get("certificate")
        if cert_field is None:
            continue

        # Extract PEM certificates
        pem_blocks = _parse_pem_certificates(cert_field)

        ev: List[Evidence] = []
        if "set:certificate" in cert_node.evidence:
            ev.append(cert_node.evidence["set:certificate"])

        if not pem_blocks:
            # No parseable certificate — check for redacted/placeholder values
            if isinstance(cert_field, str) and cert_field.strip() in _CERT_REDACTED_PATTERNS:
                msg = (
                    f'Certificate "{cert_name}" has a redacted or placeholder '
                    f"certificate value. This may indicate an expired or invalid "
                    f"certificate that was manually replaced. Verify the certificate "
                    f"is valid and not expired."
                )
                out.append(Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence="heuristic",
                    vdom=vdom,
                    message=msg,
                    evidence=ev,
                ))
            elif not _HAS_CRYPTOGRAPHY:
                # Cannot parse without cryptography library — skip silently
                pass
            continue

        # Check each PEM block
        for pem_data in pem_blocks:
            is_problematic, is_expired, expiry_info = _check_certificate_expiry(pem_data)

            if is_problematic:
                if is_expired:
                    msg = (
                        f'Certificate "{cert_name}" is {expiry_info}. '
                        f"An expired certificate can cause TLS/VPN failures, "
                        f"admin GUI lockouts, and IPSec tunnel drops. "
                        f"Renew the certificate immediately."
                    )
                else:
                    msg = (
                        f'Certificate "{cert_name}" {expiry_info}. '
                        f"Certificate expiry will cause TLS/VPN failures and "
                        f"service disruptions. Renew the certificate before it expires."
                    )

                out.append(Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity="high",
                    confidence=rule.confidence,
                    vdom=vdom,
                    message=msg,
                    evidence=ev,
                ))
                break  # One finding per cert is enough

    return out


# ---------------------------------------------------------------------------
# FGT-FGFM-DEFAULT-OVERRIDE
# Detects when FortiManager default-override is enabled on a FortiGate.
#
# When default-override is enabled, FortiManager can push configuration
# changes that override local security settings on the FortiGate device.
# This includes admin access rules, firewall policies, VPN settings, and
# other security-critical configuration. An attacker who compromises the
# FortiManager can silently weaken the FortiGate's security posture.
#
# The config lives in `config system fortimanager` and the field is
# `default-override` which accepts `enable`/`disable` values.
#
# Note: `system fortimanager` exists in the schema for all versions but
# has no field-level details, so findings are always heuristic.
# ---------------------------------------------------------------------------

def rule_fgfm_default_override(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect when FortiManager default-override is enabled."""
    out: List[Finding] = []

    # The system fortimanager table exists in schema but has no field-level
    # coverage for any version (7.4, 7.6, 8.0). We check if the table exists
    # in schema; if it doesn't, findings are still heuristic but we note it.
    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "fortimanager"), "default-override"
    )
    if not supported:
        return out

    tables = model.vdoms.get(vdom, {})
    fm_table = get_table(tables, ("system", "fortimanager"))

    if not fm_table:
        return out

    for entry_name, node in fm_table.items():
        if not isinstance(node, Node):
            continue

        # Only check if default-override is explicitly set to enable
        override_val = str(node.effective_fields().get("default-override", "")).lower().strip()
        if override_val not in ("enable", "on", "true", "1"):
            continue

        # Check if FortiManager is actually connected (status field)
        fm_status = str(node.effective_fields().get("status", "")).lower().strip()

        ev: List[Evidence] = []
        if "set:default-override" in node.evidence:
            ev.append(node.evidence["set:default-override"])
        if "set:status" in node.evidence:
            ev.append(node.evidence["set:status"])

        if not ev:
            continue

        server = str(node.effective_fields().get("server", "unknown"))
        serial = str(node.effective_fields().get("serial", ""))

        if fm_status == "enable":
            msg = (
                f"FortiManager default-override is enabled and FortiManager "
                f"connection is active (server: {server}). This allows the "
                f"FortiManager to push configuration changes that override "
                f"local security settings on this FortiGate, including admin "
                f"access rules, firewall policies, and VPN settings. An "
                f"attacker who compromises the FortiManager can silently "
                f"weaken this device's security posture. Disable "
                f"default-override unless FortiManager-managed overrides "
                f"are explicitly required."
            )
        else:
            msg = (
                f"FortiManager default-override is enabled (server: {server}). "
                f"When a FortiManager connects, it can push configuration "
                f"changes that override local security settings, including "
                f"admin access rules, firewall policies, and VPN settings. "
                f"Disable default-override unless FortiManager-managed "
                f"overrides are explicitly required."
            )

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


# ---------------------------------------------------------------------------
# Wave 2 — FGT-IFACE-NO-VLAN-SECURITY
# ---------------------------------------------------------------------------

def rule_iface_no_vlan_security(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    """Detect switch controller-managed interfaces without access VLAN security."""
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: List[Finding] = []
    supported, schema_unknown = _schema_supports_field(schema, ("system", "interface"), "switch-controller-access-vlan")
    if not supported:
        return out

    for ifname, inode in intf_table.items():
        if not isinstance(inode, Node):
            continue
        # Only check interfaces managed by the switch controller
        sc_feature = as_list(inode.effective_fields().get("switch-controller-feature"))
        if not sc_feature:
            continue
        access_vlan = str(inode.effective_fields().get("switch-controller-access-vlan", "")).strip()
        if access_vlan == "enable":
            continue
        ev = []
        if "set:switch-controller-access-vlan" in inode.evidence:
            ev.append(inode.evidence["set:switch-controller-access-vlan"])
        elif "set:switch-controller-feature" in inode.evidence:
            ev.append(inode.evidence["set:switch-controller-feature"])
        msg = (
            f'Interface "{ifname}" is managed by the switch controller '
            f'(feature: {", ".join(sc_feature)}) but access VLAN security '
            f"is not enabled. Without access VLAN filtering, the port may "
            f"allow traffic from unauthorized VLANs."
        )
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


# ---------------------------------------------------------------------------
# Wave 2 — FGT-DHCP-SNOOP
# ---------------------------------------------------------------------------

def rule_dhcp_snoop(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    """Detect switch controller-managed interfaces without DHCP snooping."""
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: List[Finding] = []
    supported, schema_unknown = _schema_supports_field(schema, ("system", "interface"), "switch-controller-dhcp-snooping")
    if not supported:
        return out

    for ifname, inode in intf_table.items():
        if not isinstance(inode, Node):
            continue
        # Only check interfaces managed by the switch controller
        sc_feature = as_list(inode.effective_fields().get("switch-controller-feature"))
        if not sc_feature:
            continue
        dhcp_snoop = str(inode.effective_fields().get("switch-controller-dhcp-snooping", "")).strip()
        if dhcp_snoop == "enable":
            continue
        ev = []
        if "set:switch-controller-dhcp-snooping" in inode.evidence:
            ev.append(inode.evidence["set:switch-controller-dhcp-snooping"])
        elif "set:switch-controller-feature" in inode.evidence:
            ev.append(inode.evidence["set:switch-controller-feature"])
        msg = (
            f'Interface "{ifname}" is managed by the switch controller '
            f'(feature: {", ".join(sc_feature)}) but DHCP snooping '
            f"is not enabled. Without DHCP snooping, rogue DHCP servers "
            f"on this network segment can assign malicious IP configurations."
        )
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


def rule_sslvpn_no_mfa(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: Optional[SchemaView] = None) -> List[Finding]:
    """Detect SSL VPN configurations that do not require two-factor authentication.

    FortiGate supports two-factor auth for SSL VPN via:
    - ``two-factor`` set to one of: ``fortitoken``, ``email``, ``sms``,
      ``fortitoken-cloud``, ``cert``

    When ``two-factor`` is missing or ``none``, users can authenticate with
    a password alone, which is a high-risk misconfiguration.
    """
    tables = model.vdoms.get(vdom, {})
    ssl_table = get_table(tables, ("vpn", "ssl", "settings"))
    out: List[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("vpn", "ssl", "settings"), "two-factor"
    )
    if not supported:
        return out

    node = ssl_table.get("__singleton__")
    if not isinstance(node, Node):
        return out

    # Check if SSL VPN is actually enabled
    status = str(node.effective_fields().get("status", "disable")).strip().lower()
    if status != "enable":
        return out

    # Check two-factor setting
    two_factor = str(node.effective_fields().get("two-factor", "none")).strip().lower()
    if two_factor in ("fortitoken", "email", "sms", "fortitoken-cloud", "cert"):
        return out  # MFA is configured

    ev: List[Evidence] = []
    if "set:two-factor" in node.evidence:
        ev.append(node.evidence["set:two-factor"])
    elif "set:status" in node.evidence:
        ev.append(node.evidence["set:status"])

    if two_factor in (None, "", "none"):
        detail = "two-factor authentication is not configured"
    else:
        detail = f"two-factor is set to \"{two_factor}\""

    msg = (
        f"SSL VPN is enabled but {detail}. "
        f"Users can authenticate with a password only, increasing the risk "
        f"of credential theft and unauthorized remote access."
    )
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


# ---------------------------------------------------------------------------
# FGT-IPS-DEFAULT-SIGNATURE
# ---------------------------------------------------------------------------

def rule_ips_default_signature(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect IPS sensors configured with no custom signature entries.

    FortiGate IPS works by defining *sensors* that contain signature
    entries (actions, matched signatures, logging settings).  When
    ``config ips sensor`` is present but none of the sensors have a
    ``config entries`` block, the IPS relies entirely on factory-default
    signatures and no organisation-specific tuning has been applied.

    This is flagged because:
    - Default signatures may be too broad (causing false-positive floods)
      or too narrow (missing relevant threats).
    - Without custom entries the IPS cannot enforce organisation-specific
      blocking or pass-through policies.
    - Best practice is to create dedicated IPS sensors with entries tuned
      to the network profile.
    """
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    # Schema check: ``ips sensor`` is a top-level table in the schema.
    # When the table exists but schema is partial (table_only), fields
    # are unknown so confidence degrades to heuristic.
    if schema is None or not schema.loaded:
        schema_unknown = True
    elif schema.has_table(("ips", "sensor")):
        schema_unknown = schema.partial
    else:
        return out  # table not in schema at all — skip

    sensor_table = get_table(tables, ("ips", "sensor"))
    if not sensor_table:
        return out

    # Collect sensor names (skip __singleton__ if present)
    sensor_names = [
        name for name in sensor_table
        if isinstance(sensor_table[name], Node)
    ]
    if not sensor_names:
        return out

    # The parser flattens nested ``config entries`` blocks into a
    # separate top-level ``entries`` table.  If that table has any
    # Node entries, at least one sensor has custom IPS rules.
    entries_table = get_table(tables, ("entries",))
    has_entries = any(isinstance(v, Node) for v in entries_table.values())

    if has_entries:
        return out  # at least one sensor has custom entries — OK

    # Build evidence — use first sensor's set: evidence if available,
    # otherwise create minimal evidence from the sensor name.
    ev: List[Evidence] = []
    for name in sensor_names:
        node = sensor_table[name]
        if node.evidence:
            for _, e in node.evidence.items():
                ev.append(e)
                break
            if ev:
                break
    # If no evidence from set: lines, create a synthetic one so the
    # finding is always anchored to a config line.
    if not ev and sensor_names:
        first_node = sensor_table[sensor_names[0]]
        # Walk sensor_table values to find any evidence
        for _, e in first_node.evidence.items():
            ev.append(e)
            break

    sensor_list = ", ".join(f'"{n}"' for n in sensor_names)
    msg = (
        f"IPS is configured with {len(sensor_names)} sensor(s) "
        f"({sensor_list}) but none contain custom signature entries. "
        f"The IPS is running with only factory-default signatures. "
        f"Create dedicated IPS sensors with entries tuned to your "
        f"network profile."
    )
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


def rule_webfilter_default_override(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect web filter override entries that may weaken default filtering.

    FortiGate ``config webfilter override`` allows administrators to create
    bypass rules that exempt specific users, groups, or IP addresses from
    web filtering policies.  When override entries exist, traffic matching
    those entries can bypass the normal web filter profile entirely.

    This is flagged because:
    - Overrides weaken the default web filtering posture.
    - Excessive or broad overrides may create security gaps.
    - Best practice is to minimise overrides and audit them regularly.
    """
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    # Schema check: ``webfilter override`` is a table in the schema.
    if schema is None or not schema.loaded:
        schema_unknown = True
    elif schema.has_table(("webfilter", "override")):
        schema_unknown = schema.partial
    else:
        return out  # table not in schema — skip

    override_table = get_table(tables, ("webfilter", "override"))
    if not override_table:
        return out

    # Collect override entries (skip __singleton__ if present)
    override_entries = [
        name for name in override_table
        if isinstance(override_table[name], Node)
    ]
    if not override_entries:
        return out

    # Build evidence from first entry
    ev: List[Evidence] = []
    for name in override_entries:
        node = override_table[name]
        if node.evidence:
            for _, e in node.evidence.items():
                ev.append(e)
                break
            if ev:
                break

    entry_list = ", ".join(f'"{n}"' for n in override_entries)
    msg = (
        f"Web filter override has {len(override_entries)} bypass entry/entries "
        f"({entry_list}). Overrides allow traffic to bypass the web filter "
        f"profile entirely. Review and minimise overrides to maintain the "
        f"intended web filtering posture."
    )
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


# FGT-AV-NO-HEURISTIC
# ---------------------------------------------------------------------------

# Protocol sub-table names that appear inside antivirus profile edit blocks.
# The parser flattens these to root-level tables (e.g. ``("http",)``).
_AV_PROTOCOL_TABLES = ("http", "ftp", "imap", "pop3", "smtp", "smb", "nntp")


def rule_av_no_heuristic(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect antivirus profiles configured without heuristic scanning.

    FortiGate antivirus profiles define per-protocol scanning behaviour
    inside ``config antivirus profile``.  Each protocol section (http,
    ftp, imap, pop3, smtp, smb, nntp) can enable heuristic analysis via
    ``set heuristic enable``.

    Heuristic ( behavioural ) analysis detects zero-day and polymorphic
    malware that signature-based scanning alone may miss.  When profiles
    exist but heuristic scanning is not enabled in any protocol section,
    the antivirus posture relies entirely on known signatures.

    This is flagged because:
    - Signature-only scanning cannot detect novel or obfuscated malware.
    - Heuristic scanning is a recommended best practice for all
      production FortiGate deployments.
    - Without heuristic, zero-day threats pass through undetected.
    """
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    # Schema check: ``antivirus profile`` is a table in the schema.
    if schema is None or not schema.loaded:
        schema_unknown = True
    elif schema.has_table(("antivirus", "profile")):
        schema_unknown = schema.partial
    else:
        return out  # table not in schema — skip

    av_table = get_table(tables, ("antivirus", "profile"))
    if not av_table:
        return out

    # Collect profile names (skip __singleton__ if present)
    profile_names = [
        name for name in av_table
        if isinstance(av_table[name], Node)
    ]
    if not profile_names:
        return out

    # Check for heuristic scanning evidence in flattened protocol tables.
    # The parser flattens ``config http`` (etc.) inside edit blocks to
    # root-level tables.  We look for any ``set heuristic enable`` in
    # those tables.
    has_heuristic = False
    heuristic_evidence: Optional[Evidence] = None
    for proto in _AV_PROTOCOL_TABLES:
        proto_table = get_table(tables, (proto,))
        if not proto_table:
            continue
        for _name, node in proto_table.items():
            if not isinstance(node, Node):
                continue
            if node.effective_fields().get("heuristic") == "enable":
                has_heuristic = True
                if "set:heuristic" in node.evidence:
                    heuristic_evidence = node.evidence["set:heuristic"]
                break
        if has_heuristic:
            break

    if has_heuristic:
        return out  # heuristic is enabled somewhere — OK

    # Build evidence from first profile
    ev: List[Evidence] = []
    for name in profile_names:
        node = av_table[name]
        if node.evidence:
            for _, e in node.evidence.items():
                ev.append(e)
                break
            if ev:
                break

    profile_list = ", ".join(f'"{n}"' for n in profile_names)
    msg = (
        f"Antivirus is configured with {len(profile_names)} profile(s) "
        f"({profile_list}) but heuristic scanning is not enabled in any "
        f"protocol section. Heuristic analysis detects zero-day and "
        f"unknown malware that signature-based scanning alone may miss. "
        f"Enable heuristic scanning in antivirus profile protocol sections."
    )
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


# FGT-DLP-NO-SENSOR
# ---------------------------------------------------------------------------

def rule_dlp_no_sensor(
    *,
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: Optional[SchemaView] = None,
) -> List[Finding]:
    """Detect DLP sensors configured without any filter rules.

    FortiGate Data Loss Prevention (DLP) works by defining *sensors* inside
    ``config dlpsensor sensor`` that reference rule groups and profile
    protocol options.  Each sensor can have:
    - ``set rules <group> enable``  — attach a rule group
    - ``set profile-protocol-options <profile>``  — attach a protocol profile

    When sensors exist but none of them have any ``rules`` or
    ``profile-protocol-options`` configured, the DLP engine has no detection
    criteria and is effectively non-functional — all traffic passes through
    without inspection for sensitive data.

    This is flagged because:
    - DLP without filter rules cannot detect sensitive data exfiltration.
    - Empty sensors suggest DLP was partially configured but never completed.
    - Best practice is to define DLP sensors with rules tuned to the
      organisation's data classification policy.
    """
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    # Schema check: ``dlp sensor`` is a top-level table in the schema.
    # Note: the parser treats ``dlpsensor`` as a single token, so the
    # config path is ("dlpsensor", "sensor") while the schema names it
    # "dlp sensor" -> ("dlp", "sensor").
    if schema is None or not schema.loaded:
        schema_unknown = True
    elif schema.has_table(("dlp", "sensor")):
        schema_unknown = schema.partial
    else:
        return out  # table not in schema — skip

    # The parser creates ``dlpsensor`` -> ``sensor`` as nested dicts.
    sensor_table = get_table(tables, ("dlpsensor", "sensor"))
    if not sensor_table:
        return out

    # Collect sensor names (skip __singleton__ if present)
    sensor_names = [
        name for name in sensor_table
        if isinstance(sensor_table[name], Node)
    ]
    if not sensor_names:
        return out

    # Check if any sensor has rules or profile-protocol-options configured.
    _DLP_RULE_FIELDS = ("rules", "profile-protocol-options")
    has_rules = False
    for name in sensor_names:
        node = sensor_table[name]
        for field in _DLP_RULE_FIELDS:
            val = node.effective_fields().get(field)
            if val and str(val).strip():
                has_rules = True
                break
        if has_rules:
            break

    if has_rules:
        return out  # at least one sensor has rules configured — OK

    # Build evidence from first sensor
    ev: List[Evidence] = []
    for name in sensor_names:
        node = sensor_table[name]
        if node.evidence:
            for _, e in node.evidence.items():
                ev.append(e)
                break
            if ev:
                break

    sensor_list = ", ".join(f'"{n}"' for n in sensor_names)
    msg = (
        f"DLP is configured with {len(sensor_names)} sensor(s) "
        f"({sensor_list}) but none contain filter rules. "
        f"The DLP engine has no detection criteria and cannot identify "
        f"sensitive data exfiltration. Configure DLP sensors with rules "
        f"tuned to your organisation's data classification policy."
    )
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
