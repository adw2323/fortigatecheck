from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

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


def _schema_supports_field(schema: SchemaView | None, table: tuple[str, ...], field: str) -> tuple[bool, bool]:
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
    schema: SchemaView | None,
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


def rule_admin_edge_ssh(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: list[Finding] = []
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

def rule_admin_edge_https(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: list[Finding] = []
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

def rule_admin_edge_telnet(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: list[Finding] = []
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

def rule_admin_edge_http(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: list[Finding] = []
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

def rule_policy_accept_no_log(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    pol_table = get_table(tables, ("firewall", "policy"))
    out: list[Finding] = []
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


def rule_vpn_ssl_min_proto(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    ssl_table = get_table(tables, ("vpn", "ssl", "settings"))
    out: list[Finding] = []
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


def rule_local_in_policy_permissive(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    lip_table = get_table(tables, ("firewall", "local-in-policy"))
    out: list[Finding] = []
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


def rule_admin_trusthost_unrestricted(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    admin_table = get_table(tables, ("system", "admin"))
    out: list[Finding] = []
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


def rule_sslvpn_source_interface_any(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    ssl_table = get_table(tables, ("vpn", "ssl", "settings"))
    out: list[Finding] = []
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


def rule_sslvpn_source_address_all(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    ssl_table = get_table(tables, ("vpn", "ssl", "settings"))
    out: list[Finding] = []
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


def rule_admin_super_no_2fa(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    admin_table = get_table(tables, ("system", "admin"))
    out: list[Finding] = []
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


def rule_admin_edge_allaccess(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: list[Finding] = []
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


def rule_admin_no_trusted_hosts(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    admin_table = get_table(tables, ("system", "admin"))
    out: list[Finding] = []
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


def rule_localin_no_protection(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    lip_table = get_table(tables, ("firewall", "local-in-policy"))
    out: list[Finding] = []
    action_supported, action_unknown = _schema_supports_field(schema, ("firewall", "local-in-policy"), "action")
    status_supported, status_unknown = _schema_supports_field(schema, ("firewall", "local-in-policy"), "status")
    if not action_supported or not status_supported:
        return out
    schema_unknown = action_unknown or status_unknown

    enabled_entries: list[Node] = []
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

    ev: list[Evidence] = []
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


def rule_policy_any_any_all(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    pol_table = get_table(tables, ("firewall", "policy"))
    out: list[Finding] = []
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


def rule_ipsec_weak_dh(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []
    weak_groups = {"1", "2", "5"}
    phase1_paths = [("vpn", "ipsec", "phase1-interface"), ("vpn", "ipsec", "phase1")]

    any_supported = False
    any_schema_unknown = False
    phase_tables: list[dict[str, Node]] = []
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


def rule_no_remote_logging(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

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

    supported_paths: list[tuple[str, ...]] = []
    schema_unknown = False
    for path in remote_paths:
        supported, unknown = _schema_supports_field(schema, path, "status")
        if supported:
            supported_paths.append(path)
            schema_unknown = schema_unknown or unknown
    if not supported_paths:
        return out

    ev: list[Evidence] = []
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


def rule_dns_zone_transfer(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    """Detect DNS server entries with zone-transfer enabled."""
    tables = model.vdoms.get(vdom, {})
    dns_table = get_table(tables, ("dns", "server"))
    out: list[Finding] = []
    supported, schema_unknown = _schema_supports_field(schema, ("dns", "server"), "zone-transfer")
    if not supported:
        return out

    for name, node in dns_table.items():
        if not isinstance(node, Node):
            continue
        zt_val = str(node.effective_fields().get("zone-transfer", "")).strip().lower()
        if zt_val != "enable":
            continue
        ev: list[Evidence] = []
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
    schema: SchemaView | None = None,
) -> list[Finding]:
    """Detect DNS configured with only default public resolvers and cleartext."""
    out: list[Finding] = []

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
    ev: list[Evidence] = []
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


def rule_ntp_no_ntps(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    """Detect NTP configuration without NTPS (unencrypted time sync)."""
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    ntp_table = get_table(tables, ("system", "ntp"))
    out: list[Finding] = []
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
    ev: list[Evidence] = []
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


def rule_snmp_weak_community(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    """Detect SNMP communities using default or well-known weak strings."""
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    snmp_table = get_table(tables, ("system", "snmp", "community"))
    out: list[Finding] = []
    supported, schema_unknown = _schema_supports_field(schema, ("system", "snmp", "community"), "name")
    if not supported:
        return out

    for _entry_name, node in snmp_table.items():
        if not isinstance(node, Node):
            continue
        community = str(node.effective_fields().get("name", "")).strip().lower()
        if community not in _WEAK_SNMP_COMMUNITIES:
            continue
        ev: list[Evidence] = []
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
    schema: SchemaView | None = None,
) -> list[Finding]:
    """Detect weak or disabled administrator password policy."""
    tables = model.vdoms.get(vdom, {})
    pw_table = get_table(tables, ("system", "password-policy"))
    out: list[Finding] = []

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

    findings: list[Finding] = []

    # --- Check 1: policy is explicitly disabled ---
    if status_supported:
        status_val = str(node.effective_fields().get("status", "")).strip().lower()
        if status_val == "disable":
            ev: list[Evidence] = []
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
                ev2: list[Evidence] = []
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
    schema: SchemaView | None = None,
) -> list[Finding]:
    """Detect disabled or excessively long administrator idle timeout."""
    out: list[Finding] = []

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

    ev: list[Evidence] = []
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
    schema: SchemaView | None = None,
) -> list[Finding]:
    """Detect outdated firmware version relative to latest known patch."""
    out: list[Finding] = []

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
    ev: list[Evidence] = []
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
    node: Node,
    field: str,
    weak_set: set[str],
    label: str,
    rule: Rule,
    vdom: str,
    schema_unknown: bool,
) -> list[Finding]:
    """Check a single SSH config field for weak values."""
    findings: list[Finding] = []
    raw = str(node.effective_fields().get(field, "")).strip().lower()
    if not raw:
        return findings

    # ssh-key-exchange may contain multiple space-separated algorithms
    values = [v.strip() for v in raw.split() if v.strip()]
    weak_found = [v for v in values if v in weak_set]
    if not weak_found:
        return findings

    ev: list[Evidence] = []
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
    model: ConfigModel,
    facts: Facts,
    vdom: str,
    rule: Rule,
    schema: SchemaView | None = None,
) -> list[Finding]:
    """Detect SSH service configured with weak ciphers, key-exchange, or MAC."""
    out: list[Finding] = []

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
    schema: SchemaView | None = None,
) -> list[Finding]:
    """Detect SNMP communities without host ACL restrictions."""
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "snmp", "community"), "name"
    )
    if not supported:
        return out

    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
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
                ev: list[Evidence] = []
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
        ev2: list[Evidence] = []
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

    now = datetime.now(UTC)

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
    schema: SchemaView | None = None,
) -> list[Finding]:
    """Detect local certificates that are expired or expiring soon."""
    out: list[Finding] = []

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

        ev: list[Evidence] = []
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
    schema: SchemaView | None = None,
) -> list[Finding]:
    """Detect when FortiManager default-override is enabled."""
    out: list[Finding] = []

    # The system fortimanager table exists in schema but has no field-level
    # coverage for any version (7.4, 7.6, 8.0). We check if the table exists
    # in schema; if it doesn't, findings are still heuristic but we note it.
    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "fortimanager"), "default-override"
    )
    if not supported:
        return out

    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    fm_table = get_table(tables, ("system", "fortimanager"))

    if not fm_table:
        return out

    for _entry_name, node in fm_table.items():
        if not isinstance(node, Node):
            continue

        # Only check if default-override is explicitly set to enable
        override_val = str(node.effective_fields().get("default-override", "")).lower().strip()
        if override_val not in ("enable", "on", "true", "1"):
            continue

        # Check if FortiManager is actually connected (status field)
        fm_status = str(node.effective_fields().get("status", "")).lower().strip()

        ev: list[Evidence] = []
        if "set:default-override" in node.evidence:
            ev.append(node.evidence["set:default-override"])
        if "set:status" in node.evidence:
            ev.append(node.evidence["set:status"])

        if not ev:
            continue

        server = str(node.effective_fields().get("server", "unknown"))
        str(node.effective_fields().get("serial", ""))

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

def rule_iface_no_vlan_security(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    """Detect switch controller-managed interfaces without access VLAN security."""
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: list[Finding] = []
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

def rule_dhcp_snoop(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    """Detect switch controller-managed interfaces without DHCP snooping."""
    tables = model.vdoms.get(vdom, {})
    intf_table = get_table(tables, ("system", "interface"))
    out: list[Finding] = []
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


def rule_sslvpn_no_mfa(*, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None) -> list[Finding]:
    """Detect SSL VPN configurations that do not require two-factor authentication.

    FortiGate supports two-factor auth for SSL VPN via:
    - ``two-factor`` set to one of: ``fortitoken``, ``email``, ``sms``,
      ``fortitoken-cloud``, ``cert``

    When ``two-factor`` is missing or ``none``, users can authenticate with
    a password alone, which is a high-risk misconfiguration.
    """
    tables = model.vdoms.get(vdom, {})
    ssl_table = get_table(tables, ("vpn", "ssl", "settings"))
    out: list[Finding] = []

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

    ev: list[Evidence] = []
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
    schema: SchemaView | None = None,
) -> list[Finding]:
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
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

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
    ev: list[Evidence] = []
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
    schema: SchemaView | None = None,
) -> list[Finding]:
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
    out: list[Finding] = []

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
    ev: list[Evidence] = []
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
    schema: SchemaView | None = None,
) -> list[Finding]:
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
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

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
                    node.evidence["set:heuristic"]
                break
        if has_heuristic:
            break

    if has_heuristic:
        return out  # heuristic is enabled somewhere — OK

    # Build evidence from first profile
    ev: list[Evidence] = []
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
    schema: SchemaView | None = None,
) -> list[Finding]:
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
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

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
    ev: list[Evidence] = []
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


def rule_admin_lockout_no_tries(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect administrator accounts without lockout threshold configured.

    Without lockout protection, brute-force password attacks against
    administrator accounts will never be blocked. Best practice is to
    set a lockout threshold (e.g. 3-5 attempts) and a lockout duration.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    # Check schema support
    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "global"), "admin-lockout-threshold"
    )
    if not supported:
        return out

    # config system global may be in global scope or vdom scope
    global_table = get_table(model.global_cfg, ("system", "global"))
    vdom_table = get_table(tables, ("system", "global"))
    node_global = global_table.get("__singleton__") if global_table else None
    node_vdom = vdom_table.get("__singleton__") if vdom_table else None
    node = node_global if isinstance(node_global, Node) else node_vdom

    if not isinstance(node, Node):
        # No admin config found — factory default = no lockout
        out.append(Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=rule.confidence,
            vdom=vdom,
            message=(
                "Administrator lockout is not configured (factory default). "
                "Without a lockout threshold, brute-force password attacks "
                "against admin accounts will never be blocked. Configure "
                "\"set admin-lockout-threshold\" in \"config system global\"."
            ),
            evidence=[],
        ))
        return out

    raw = node.effective_fields().get("admin-lockout-threshold")
    if raw is None:
        out.append(Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=rule.confidence,
            vdom=vdom,
            message=(
                "Administrator lockout threshold is not set. Without a "
                "lockout threshold, brute-force password attacks against "
                "admin accounts will never be blocked. Configure "
                "\"set admin-lockout-threshold\" in \"config system global\"."
            ),
            evidence=[],
        ))
        return out

    try:
        threshold = int(str(raw))
    except (ValueError, TypeError):
        return out

    if threshold == 0:
        out.append(Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=rule.confidence,
            vdom=vdom,
            message=(
                "Administrator lockout threshold is set to 0 (disabled). "
                "Brute-force password attacks against admin accounts will "
                "never be blocked. Set a non-zero threshold (recommended: 3-5)."
            ),
            evidence=[],
        ))

    return out


def rule_ha_no_heartbeat(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect HA configuration without heartbeat interface or with unencrypted heartbeat.

    HA heartbeat traffic is critical for failover. Without a dedicated
    heartbeat interface, heartbeat traffic shares the data plane, risking
    split-brain scenarios. Unencrypted heartbeat traffic can be intercepted
    and used to manipulate failover state.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    # Check schema support
    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "ha"), "hbdev"
    )
    if not supported:
        return out

    # config system ha may be in global scope or vdom scope
    global_table = get_table(model.global_cfg, ("system", "ha"))
    vdom_table = get_table(tables, ("system", "ha"))
    node_global = global_table.get("__singleton__") if global_table else None
    node_vdom = vdom_table.get("__singleton__") if vdom_table else None
    node = node_global if isinstance(node_global, Node) else node_vdom

    if not isinstance(node, Node):
        return out  # No HA config — not in HA mode

    fields = node.effective_fields()

    # Check heartbeat device
    hbdev = fields.get("hbdev")
    if hbdev is None or (isinstance(hbdev, str) and hbdev.strip() == ""):
        ev = []
        if "set:hbdev" in node.evidence:
            ev.append(node.evidence["set:hbdev"])
        msg = "HA configuration has no heartbeat interface (hbdev). Without a dedicated heartbeat interface, HA heartbeat traffic shares the data plane, risking split-brain scenarios."
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

    # Check for unencrypted heartbeat
    hbdev_val = str(hbdev).strip() if hbdev else ""
    if hbdev_val and "cluster-key" not in fields:
        ev = []
        if "set:hbdev" in node.evidence:
            ev.append(node.evidence["set:hbdev"])
        msg = (
            f"HA heartbeat interface \"{hbdev_val}\" is configured but "
            f"cluster encryption key (cluster-key) is not set. HA heartbeat "
            f"traffic is unencrypted and can be intercepted. Configure "
            f"\"set cluster-key\" to encrypt heartbeat traffic."
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


def rule_ssl_inspection_disabled(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect SSL deep inspection not enabled on web traffic policies.

    Without SSL inspection, encrypted malware and C2 traffic passes
    through the firewall undetected.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []
    policy_table = get_table(tables, ("firewall", "policy"))
    get_table(tables, ("firewall", "ssl-ssh-profile"))

    for policy_name, policy_node in policy_table.items():
        if not isinstance(policy_node, Node):
            continue
        fields = policy_node.effective_fields()
        action = str(fields.get("action", "")).lower()
        if action != "accept":
            continue
        services = as_list(fields.get("service"))
        has_https = any("https" in str(s).lower() or "http" in str(s).lower() for s in services)
        if not has_https:
            continue
        utm_status = str(fields.get("utm-status", "")).lower()
        if utm_status != "enable":
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=rule.confidence, vdom=vdom,
                message=f"Policy {policy_name}: accepts HTTPS but UTM/SSL inspection is disabled (utm-status={utm_status}).",
                evidence=[],
            ))
    return out


def rule_admin_no_2fa(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect administrator accounts without two-factor authentication."""
    tables = model.vdoms.get(vdom, {})
    global_tables = model.global_cfg
    out: list[Finding] = []
    admin_table = get_table(_merged_scope_tables(tables, global_tables), ("system", "admin"))
    for admin_name, admin_node in admin_table.items():
        if not isinstance(admin_node, Node):
            continue
        fields = admin_node.effective_fields()
        two_factor = str(fields.get("two-factor-auth", "")).lower()
        if two_factor in ("", "none", "disable"):
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=rule.confidence, vdom=vdom,
                message=f"Admin \"{admin_name}\" does not have two-factor authentication enabled.",
                evidence=[],
            ))
    return out


def rule_firewall_policy_any_any(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect overly permissive firewall policies with any-any source/destination."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []
    policy_table = get_table(tables, ("firewall", "policy"))
    for policy_name, policy_node in policy_table.items():
        if not isinstance(policy_node, Node):
            continue
        fields = policy_node.effective_fields()
        action = str(fields.get("action", "")).lower()
        if action != "accept":
            continue
        srcaddr = as_list(fields.get("srcaddr"))
        dstaddr = as_list(fields.get("dstaddr"))
        src_all = "all" in srcaddr or "ALL" in srcaddr
        dst_all = "all" in dstaddr or "ALL" in dstaddr
        if src_all and dst_all:
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=rule.confidence, vdom=vdom,
                message=f"Policy {policy_name}: accepts traffic from any source to any destination (any-any policy).",
                evidence=[],
            ))
    return out


def rule_dns_server_allow_tcp(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect DNS server with zone transfer enabled."""
    tables = model.vdoms.get(vdom, {})
    global_tables = _merged_scope_tables(tables, model.global_cfg)
    out: list[Finding] = []
    dns_table = get_table(global_tables, ("system", "dns"))
    for _name, node in dns_table.items():
        if not isinstance(node, Node):
            continue
        fields = node.effective_fields()
        if fields.get("allow-tcp") == "enable":
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=rule.confidence, vdom=vdom,
                message="DNS server has TCP allowed, which may enable zone transfer attacks.",
                evidence=[],
            ))
    return out


def rule_interface_open_port(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect edge interfaces with management protocols enabled."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []
    intf_table = get_table(tables, ("system", "interface"))
    mgmt_protos = {"ssh", "https", "http", "telnet", "ping", "snmp"}
    for ifname, inode in intf_table.items():
        if not isinstance(inode, Node):
            continue
        fields = inode.effective_fields()
        if ifname not in facts.edge_interfaces:
            continue
        allowaccess = as_list(fields.get("allowaccess"))
        enabled_mgmt = [p for p in allowaccess if p in mgmt_protos]
        if len(enabled_mgmt) >= 3:
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=rule.confidence, vdom=vdom,
                message=f"Edge interface \"{ifname}\" has {len(enabled_mgmt)} management protocols enabled: {', '.join(enabled_mgmt)}.",
                evidence=[],
            ))
    return out


def rule_vpn_phase1_unencrypted(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect IPsec VPN phase1 with weak or no encryption."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []
    phase1_table = get_table(tables, ("vpn", "ipsec", "phase1-interface"))
    weak_enc = {"des", "3des", "null"}
    for name, node in phase1_table.items():
        if not isinstance(node, Node):
            continue
        fields = node.effective_fields()
        proposal = str(fields.get("proposal", "")).lower()
        for weak in weak_enc:
            if weak in proposal:
                out.append(Finding(
                    rule_id=rule.id, title=rule.title, severity=rule.severity,
                    confidence=rule.confidence, vdom=vdom,
                    message=f"IPsec VPN \"{name}\" uses weak encryption: {weak} detected in proposal.",
                    evidence=[],
                ))
                break
    return out


def rule_switch_stp_no_root_guard(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect FortiSwitch with STP enabled but no root guard."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []
    switch_table = get_table(tables, ("switch-controller", "managed-switch"))
    for name, node in switch_table.items():
        if not isinstance(node, Node):
            continue
        fields = node.effective_fields()
        if fields.get("stp") == "enable" and "root-guard" not in fields:
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=rule.confidence, vdom=vdom,
                message=f"Switch \"{name}\" has STP enabled without root guard configured.",
                evidence=[],
            ))
    return out


def rule_log_no_local_traffic(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect local-in policy without logging."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []
    local_table = get_table(tables, ("firewall", "local-in-policy"))
    for name, node in local_table.items():
        if not isinstance(node, Node):
            continue
        fields = node.effective_fields()
        action = str(fields.get("action", "")).lower()
        if action == "accept" and fields.get("logtraffic") != "enable":
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=rule.confidence, vdom=vdom,
                message=f"Local-in policy \"{name}\" accepts traffic without logging enabled.",
                evidence=[],
            ))
    return out


def rule_system_global_no_admin_restricted(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect admin restrict-vdom not enabled on multi-VDOM systems."""
    if len(model.vdoms) <= 1:
        return []
    global_table = get_table(model.global_cfg, ("system", "global"))
    out: list[Finding] = []
    for _name, node in global_table.items():
        if not isinstance(node, Node):
            continue
        fields = node.effective_fields()
        restrict = fields.get("admin-restrict-vdom")
        if restrict is None or str(restrict).lower() != "enable":
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=rule.confidence, vdom=vdom,
                message="Multi-VDOM system does not have admin-restrict-vdom enabled. Admins may access all VDOMs.",
                evidence=[],
            ))
    return out


def rule_wireless_open_ssid(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect wireless SSID with open (no security) authentication."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []
    ssid_table = get_table(tables, ("wireless-controller", "ssid"))
    for name, node in ssid_table.items():
        if not isinstance(node, Node):
            continue
        fields = node.effective_fields()
        security = str(fields.get("security", "")).lower()
        if security in ("open", "none", ""):
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=rule.confidence, vdom=vdom,
                message=f"Wireless SSID \"{name}\" has no security (open network).",
                evidence=[],
            ))
    return out


def rule_router_static_default_route_insecure(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect default route via unencrypted/unauthenticated gateway."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []
    static_table = get_table(tables, ("router", "static"))
    for _name, node in static_table.items():
        if not isinstance(node, Node):
            continue
        fields = node.effective_fields()
        dst = str(fields.get("dst", "")).strip()
        if "0.0.0.0" in dst and "0.0.0.0" in dst:
            device = str(fields.get("device", "")).lower()
            if device.startswith("vpn") or "ipsec" in device:
                continue  # VPN tunnel — OK
            gateway = str(fields.get("gateway", "")).strip()
            if gateway and gateway != "0.0.0.0":
                out.append(Finding(
                    rule_id=rule.id, title=rule.title, severity=rule.severity,
                    confidence=rule.confidence, vdom=vdom,
                    message=f"Default route via gateway {gateway} on device {device}. Verify gateway is hardened.",
                    evidence=[],
                ))
    return out


# ---------------------------------------------------------------------------
# FGT-API-TOKEN-NO-EXPIRY
# ---------------------------------------------------------------------------

def rule_api_token_no_expiry(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect API user accounts configured without token expiry.

    API users without token expiry keep valid credentials indefinitely,
    increasing the window of exposure if the token is compromised.
    """
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "api-user"), "token-expiry"
    )
    if not supported:
        return out

    api_table = get_table(tables, ("system", "api-user"))
    if not api_table:
        return out

    for uname, unode in api_table.items():
        if not isinstance(unode, Node):
            continue
        fields = unode.effective_fields()
        if not fields.get("token-expiry"):
            ev: list[Evidence] = []
            if "set:token-expiry" in unode.evidence:
                ev.append(unode.evidence["set:token-expiry"])
            msg = (
                f'API user "{uname}" has no token expiry configured. '
                f"Without expiry, API tokens remain valid indefinitely "
                f"and cannot be rotated automatically."
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
# FGT-APP-CTRL-NO-POLICY
# ---------------------------------------------------------------------------

def rule_app_ctrl_no_policy(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect accept policies without application control profile.

    Application control identifies and controls traffic for thousands of
    applications.  Accept policies without an application-list leave the
    firewall blind to application-layer threats.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("firewall", "policy"), "application-list"
    )
    if not supported:
        return out

    pol_table = get_table(tables, ("firewall", "policy"))
    for pid, pnode in pol_table.items():
        if not isinstance(pnode, Node):
            continue
        fields = pnode.effective_fields()
        if fields.get("action") != "accept":
            continue
        if not fields.get("application-list"):
            ev: list[Evidence] = []
            if "set:application-list" in pnode.evidence:
                ev.append(pnode.evidence["set:application-list"])
            msg = f'Policy "{pid}" accepts traffic without application control.'
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-AUTOMATION-STITCH-NO-RESTRICT
# ---------------------------------------------------------------------------

def rule_automation_stitch_no_restrict(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect automation triggers configured without target restrictions.

    Automation triggers without target restrictions may execute with
    unrestricted privileges, potentially allowing compromise of the
    automation framework.
    """
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "automation-trigger"), "restrict-targets"
    )
    if not supported:
        return out

    table = get_table(tables, ("system", "automation-trigger"))
    if not table:
        return out

    for tname, tnode in table.items():
        if not isinstance(tnode, Node):
            continue
        fields = tnode.effective_fields()
        if not fields.get("restrict-targets"):
            ev: list[Evidence] = []
            if "set:restrict-targets" in tnode.evidence:
                ev.append(tnode.evidence["set:restrict-targets"])
            msg = (
                f'Automation trigger "{tname}" has no target restrictions. '
                f"Without restrictions, automations may execute with "
                f"unlimited scope."
            )
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-CAPTCHA-NO-ENABLE
# ---------------------------------------------------------------------------

def rule_captcha_no_enable(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect that CAPTCHA is not enabled globally.

    CAPTCHA helps prevent automated brute-force attacks against
    login portals.  When disabled, bots can attempt credentials
    at scale.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "global"), "captcha"
    )
    if not supported:
        return out

    global_table = _merged_scope_tables(tables, model.global_cfg)
    gtable = get_table(global_table, ("system", "global"))
    for _name, gnode in gtable.items():
        if not isinstance(gnode, Node):
            continue
        fields = gnode.effective_fields()
        if fields.get("captcha") != "enable":
            ev: list[Evidence] = []
            if "set:captcha" in gnode.evidence:
                ev.append(gnode.evidence["set:captcha"])
            msg = (
                "CAPTCHA is not enabled. Without CAPTCHA, login portals "
                "are vulnerable to automated brute-force and credential-"
                "stuffing attacks."
            )
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-DHCP-NO-RANGE-LIMIT
# ---------------------------------------------------------------------------

def rule_dhcp_no_range_limit(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect DHCP servers without explicit lease time or range limits.

    DHCP servers without configured lease times use the default, which
    may be inappropriate for the network segment.
    """
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "dhcp"), "lease"
    )
    if not supported:
        return out

    table = get_table(tables, ("system", "dhcp"))
    for name, dnode in table.items():
        if not isinstance(dnode, Node):
            continue
        fields = dnode.effective_fields()
        if not fields.get("lease"):
            ev: list[Evidence] = []
            if "set:lease" in dnode.evidence:
                ev.append(dnode.evidence["set:lease"])
            msg = (
                f'DHCP server "{name}" has no explicit lease time configured. '
                f"Without a defined lease time, the default may not suit the "
                f"network segment requirements."
            )
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-DNS-FILTER-NO-PROFILE
# ---------------------------------------------------------------------------

def rule_dns_filter_no_profile(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect that no DNS filter profiles are configured.

    Without DNS filter profiles, DNS-based threats such as C2 callbacks
    and phishing domains cannot be blocked.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("dnsfilter", "profile"), "name"
    )
    if not supported:
        return out

    profile_table = get_table(tables, ("dnsfilter", "profile"))
    if not profile_table or not any(isinstance(v, Node) for v in profile_table.values()):
        msg = (
            "No DNS filter profile configured. DNS-based threats such as "
            "command-and-control callbacks and phishing domains cannot be "
            "blocked without DNS filtering."
        )
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(Finding(
            rule_id=rule.id, title=rule.title, severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom, message=msg, evidence=[],
        ))
    return out


# ---------------------------------------------------------------------------
# FGT-FW-MULTICAST-NO-SECURE
# ---------------------------------------------------------------------------

def rule_fw_multicast_no_secure(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect multicast address objects without security controls.

    Multicast addresses without colour tags or associated security
    profiles may allow uncontrolled multicast traffic flows.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("firewall", "multicast-address"), "color"
    )
    if not supported:
        return out

    table = get_table(tables, ("firewall", "multicast-address"))
    for name, mnode in table.items():
        if not isinstance(mnode, Node):
            continue
        fields = mnode.effective_fields()
        if not fields.get("color"):
            ev: list[Evidence] = []
            if "set:color" in mnode.evidence:
                ev.append(mnode.evidence["set:color"])
            msg = (
                f'Multicast address "{name}" has no security controls '
                f"applied. Verify multicast traffic is properly secured."
            )
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-ICAP-NO-PROFILE
# ---------------------------------------------------------------------------

def rule_icap_no_profile(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect that no ICAP server profile is configured.

    ICAP allows offloading content inspection to external DLP/AV
    servers.  Without it, content inspection is limited to built-in
    profiles only.
    """
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("icap", "profile"), "name"
    )
    if not supported:
        return out

    table = get_table(tables, ("icap", "profile"))
    if not table or not any(isinstance(v, Node) for v in table.values()):
        msg = (
            "No ICAP profile configured. ICAP allows offloading content "
            "inspection to external servers for additional DLP/AV protection."
        )
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(Finding(
            rule_id=rule.id, title=rule.title, severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom, message=msg, evidence=[],
        ))
    return out


# ---------------------------------------------------------------------------
# FGT-IPSEC-NO-PFS
# ---------------------------------------------------------------------------

def rule_ipsec_no_pfs(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect IPsec phase2 tunnels without perfect forward secrecy.

    Without PFS, compromise of the long-term key allows decryption of
    all past captured traffic.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("vpn", "ipsec", "phase2-interface"), "pfs"
    )
    if not supported:
        return out

    table = get_table(tables, ("vpn", "ipsec", "phase2-interface"))
    seen_keys: set[str] = set()
    for pname, pnode in table.items():
        if not isinstance(pnode, Node):
            continue
        dedupe = str(pname).strip().lower()
        if dedupe in seen_keys:
            continue
        fields = pnode.effective_fields()
        if str(fields.get("status", "")).strip().lower() == "disable":
            continue
        pfs = fields.get("pfs")
        if pfs is None or str(pfs).strip().lower() in ("", "disable"):
            ev: list[Evidence] = []
            if "set:pfs" in pnode.evidence:
                ev.append(pnode.evidence["set:pfs"])
            msg = (
                f'IPsec phase2 "{pname}" does not have Perfect Forward '
                f"Secrecy (PFS) enabled. Without PFS, compromise of the "
                f"long-term key exposes past traffic."
            )
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
        seen_keys.add(dedupe)
    return out


# ---------------------------------------------------------------------------
# FGT-IPSEC-SHORT-LIFETIME
# ---------------------------------------------------------------------------

def rule_ipsec_short_lifetime(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect IPsec SA lifetime shorter than the recommended minimum.

    Short SA lifetimes (< 3600s) cause frequent rekeying, increasing
    CPU overhead and potential VPN instability.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("vpn", "ipsec", "phase2-interface"), "lifetime"
    )
    if not supported:
        return out

    table = get_table(tables, ("vpn", "ipsec", "phase2-interface"))
    for pname, pnode in table.items():
        if not isinstance(pnode, Node):
            continue
        fields = pnode.effective_fields()
        if str(fields.get("status", "")).strip().lower() == "disable":
            continue
        lt = fields.get("lifetime")
        if lt is not None:
            try:
                val = int(str(lt))
                if val < 3600:
                    ev: list[Evidence] = []
                    if "set:lifetime" in pnode.evidence:
                        ev.append(pnode.evidence["set:lifetime"])
                    msg = (
                        f'IPsec phase2 "{pname}" has short SA lifetime '
                        f"({val}s). Recommended minimum: >=3600s (1 hour)."
                    )
                    if schema_unknown:
                        msg = f"[schema_unknown] {msg}"
                    out.append(Finding(
                        rule_id=rule.id, title=rule.title, severity=rule.severity,
                        confidence=("heuristic" if schema_unknown else rule.confidence),
                        vdom=vdom, message=msg, evidence=ev,
                    ))
            except (ValueError, TypeError):
                pass
    return out


# ---------------------------------------------------------------------------
# FGT-LOG-REMOTE-UNENCRYPTED
# ---------------------------------------------------------------------------

def rule_log_remote_unencrypted(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect remote logging targets enabled without encryption.

    Sending logs over unencrypted channels exposes sensitive data
    (IPs, usernames, URLs) to network sniffing.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    global_tables = _merged_scope_tables(tables, model.global_cfg)
    syslog_paths = [
        ("log", "syslogd", "setting"),
        ("log", "syslogd2", "setting"),
        ("log", "syslogd3", "setting"),
    ]

    for prefix in syslog_paths:
        supported, schema_unknown = _schema_supports_field(schema, prefix, "mode")
        if not supported:
            continue
        table = get_table(global_tables, prefix)
        for _name, node in table.items():
            if not isinstance(node, Node):
                continue
            fields = node.effective_fields()
            mode = str(fields.get("mode", "")).strip().lower()
            if mode == "enable" and not fields.get("enc-algorithm"):
                ev: list[Evidence] = []
                if "set:enc-algorithm" in node.evidence:
                    ev.append(node.evidence["set:enc-algorithm"])
                msg = (
                    "Remote syslog is enabled without encryption. Log data "
                    "may be intercepted in transit. Configure TLS encryption "
                    "for secure log forwarding."
                )
                if schema_unknown:
                    msg = f"[schema_unknown] {msg}"
                out.append(Finding(
                    rule_id=rule.id, title=rule.title, severity=rule.severity,
                    confidence=("heuristic" if schema_unknown else rule.confidence),
                    vdom=vdom, message=msg, evidence=ev,
                ))
    return out


# ---------------------------------------------------------------------------
# FGT-NAC-NO-POLICY
# ---------------------------------------------------------------------------

def rule_nac_no_policy(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect that Network Access Control policies are not configured.

    Without NAC policies, devices connecting to the network are not
    authenticated or authorized, allowing any device access.
    """
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("switch-controller", "nac-policy"), "name"
    )
    if not supported:
        return out

    table = get_table(tables, ("switch-controller", "nac-policy"))
    if not table or not any(isinstance(v, Node) for v in table.values()):
        msg = (
            "No NAC policies configured. Without Network Access Control, "
            "devices connecting to the network are not authenticated or "
            "authorized."
        )
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(Finding(
            rule_id=rule.id, title=rule.title, severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom, message=msg, evidence=[],
        ))
    return out


# ---------------------------------------------------------------------------
# FGT-POLICY-NO-AV
# ---------------------------------------------------------------------------

def rule_policy_no_av(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect accept policies without antivirus profile configured."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("firewall", "policy"), "av-profile"
    )
    if not supported:
        return out

    pol_table = get_table(tables, ("firewall", "policy"))
    for pid, pnode in pol_table.items():
        if not isinstance(pnode, Node):
            continue
        fields = pnode.effective_fields()
        if fields.get("action") != "accept":
            continue
        if not fields.get("av-profile"):
            ev: list[Evidence] = []
            if "set:av-profile" in pnode.evidence:
                ev.append(pnode.evidence["set:av-profile"])
            msg = f'Policy "{pid}": accepts traffic without antivirus profile.'
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-POLICY-NO-DLP
# ---------------------------------------------------------------------------

def rule_policy_no_dlp(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect accept policies without DLP sensor configured."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("firewall", "policy"), "dlp-sensor"
    )
    if not supported:
        return out

    pol_table = get_table(tables, ("firewall", "policy"))
    for pid, pnode in pol_table.items():
        if not isinstance(pnode, Node):
            continue
        fields = pnode.effective_fields()
        if fields.get("action") != "accept":
            continue
        if not fields.get("dlp-sensor"):
            ev: list[Evidence] = []
            if "set:dlp-sensor" in pnode.evidence:
                ev.append(pnode.evidence["set:dlp-sensor"])
            msg = f'Policy "{pid}": accepts traffic without DLP sensor.'
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-POLICY-NO-IPS
# ---------------------------------------------------------------------------

def rule_policy_no_ips(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect accept policies without IPS sensor configured."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("firewall", "policy"), "ips-sensor"
    )
    if not supported:
        return out

    pol_table = get_table(tables, ("firewall", "policy"))
    for pid, pnode in pol_table.items():
        if not isinstance(pnode, Node):
            continue
        fields = pnode.effective_fields()
        if fields.get("action") != "accept":
            continue
        if not fields.get("ips-sensor"):
            ev: list[Evidence] = []
            if "set:ips-sensor" in pnode.evidence:
                ev.append(pnode.evidence["set:ips-sensor"])
            msg = f'Policy "{pid}": accepts traffic without IPS sensor.'
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-POLICY-NO-LOG
# ---------------------------------------------------------------------------

def rule_policy_no_log(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect accept policies without traffic logging."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("firewall", "policy"), "logtraffic"
    )
    if not supported:
        return out

    pol_table = get_table(tables, ("firewall", "policy"))
    for pid, pnode in pol_table.items():
        if not isinstance(pnode, Node):
            continue
        fields = pnode.effective_fields()
        if fields.get("action") != "accept":
            continue
        if fields.get("logtraffic") != "enable":
            ev: list[Evidence] = []
            if "set:logtraffic" in pnode.evidence:
                ev.append(pnode.evidence["set:logtraffic"])
            msg = f'Policy "{pid}": accepts traffic without logging enabled.'
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-POLICY-NO-WEBFILTER
# ---------------------------------------------------------------------------

def rule_policy_no_webfilter(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect accept policies without web filter profile configured."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("firewall", "policy"), "webfilter-profile"
    )
    if not supported:
        return out

    pol_table = get_table(tables, ("firewall", "policy"))
    for pid, pnode in pol_table.items():
        if not isinstance(pnode, Node):
            continue
        fields = pnode.effective_fields()
        if fields.get("action") != "accept":
            continue
        if not fields.get("webfilter-profile"):
            ev: list[Evidence] = []
            if "set:webfilter-profile" in pnode.evidence:
                ev.append(pnode.evidence["set:webfilter-profile"])
            msg = f'Policy "{pid}": accepts traffic without web filter profile.'
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-REPORT-NO-SCHEDULE
# ---------------------------------------------------------------------------

def rule_report_no_schedule(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect that no report schedules are configured.

    Reports without a schedule will never run automatically, rendering
    them useless for ongoing monitoring.
    """
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("report", "schedule"), "name"
    )
    if not supported:
        return out

    table = get_table(tables, ("report", "schedule"))
    if not table or not any(isinstance(v, Node) for v in table.values()):
        msg = (
            "No report schedule configured. Without a schedule, reports "
            "will never run automatically for ongoing monitoring."
        )
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(Finding(
            rule_id=rule.id, title=rule.title, severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom, message=msg, evidence=[],
        ))
    return out


# ---------------------------------------------------------------------------
# FGT-ROUTING-NO-FILTER
# ---------------------------------------------------------------------------

def rule_routing_no_filter(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect static routes configured without route filtering.

    Many static routes without prefix-list or route-map filtering may
    indicate routes were added without proper access control.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("router", "static"), "dst"
    )
    if not supported:
        return out

    table = get_table(tables, ("router", "static"))
    count = sum(1 for _, node in table.items() if isinstance(node, Node))
    if count > 10:
        msg = (
            f"Router has {count} static routes. Consider implementing route "
            f"filtering via prefix-lists or route-maps to control routing."
        )
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(Finding(
            rule_id=rule.id, title=rule.title, severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom, message=msg, evidence=[],
        ))
    return out


# ---------------------------------------------------------------------------
# FGT-SDWAN-NO-HEALTH-CHECK
# ---------------------------------------------------------------------------

def rule_sdwan_no_health_check(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect SD-WAN configured without health checks.

    Without health checks, SD-WAN cannot dynamically select the best
    path based on link quality metrics.
    """
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "sdwan"), "health-check"
    )
    if not supported:
        return out

    table = get_table(tables, ("system", "sdwan"))
    for _name, snode in table.items():
        if not isinstance(snode, Node):
            continue
        fields = snode.effective_fields()
        if not fields.get("health-check"):
            ev: list[Evidence] = []
            if "set:health-check" in snode.evidence:
                ev.append(snode.evidence["set:health-check"])
            msg = (
                "SD-WAN is configured without health checks. Without "
                "health checks, SD-WAN cannot perform dynamic path "
                "selection based on link quality."
            )
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-SSLVPN-PORT
# ---------------------------------------------------------------------------

def rule_sslvpn_port(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect SSL VPN listening on a non-standard port.

    Non-standard ports provide no real security benefit and complicate
    client configuration.
    """
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("vpn", "ssl", "settings"), "port"
    )
    if not supported:
        return out

    table = get_table(tables, ("vpn", "ssl", "settings"))
    for _name, node in table.items():
        if not isinstance(node, Node):
            continue
        fields = node.effective_fields()
        port = fields.get("port")
        if port:
            try:
                p = int(str(port))
                if p not in (443, 10443):
                    ev: list[Evidence] = []
                    if "set:port" in node.evidence:
                        ev.append(node.evidence["set:port"])
                    msg = (
                        f"SSL VPN is listening on non-standard port {p} "
                        f"instead of 443 or 10443."
                    )
                    if schema_unknown:
                        msg = f"[schema_unknown] {msg}"
                    out.append(Finding(
                        rule_id=rule.id, title=rule.title, severity=rule.severity,
                        confidence=("heuristic" if schema_unknown else rule.confidence),
                        vdom=vdom, message=msg, evidence=ev,
                    ))
            except (ValueError, TypeError):
                pass
    return out


# ---------------------------------------------------------------------------
# FGT-SSLVPN-WEAK-CIPHER
# ---------------------------------------------------------------------------

_SSLVPN_WEAK_CIPHERS = {"rc4", "des", "3des", "null", "md5"}


def rule_sslvpn_weak_cipher(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect SSL VPN configured with weak cipher suites."""
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("vpn", "ssl", "settings"), "cipher"
    )
    if not supported:
        return out

    table = get_table(tables, ("vpn", "ssl", "settings"))
    for _name, node in table.items():
        if not isinstance(node, Node):
            continue
        fields = node.effective_fields()
        cipher = str(fields.get("cipher", "")).lower()
        for w in _SSLVPN_WEAK_CIPHERS:
            if w in cipher:
                ev: list[Evidence] = []
                if "set:cipher" in node.evidence:
                    ev.append(node.evidence["set:cipher"])
                msg = f"SSL VPN uses weak cipher: {w}. Use AES-GCM ciphers only."
                if schema_unknown:
                    msg = f"[schema_unknown] {msg}"
                out.append(Finding(
                    rule_id=rule.id, title=rule.title, severity=rule.severity,
                    confidence=("heuristic" if schema_unknown else rule.confidence),
                    vdom=vdom, message=msg, evidence=ev,
                ))
                break
    return out


# ---------------------------------------------------------------------------
# FGT-SWITCH-NO-PORT-SECURITY
# ---------------------------------------------------------------------------

def rule_switch_no_port_security(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect that no switch port security policies are configured.

    Without port security, unauthorized devices can connect to switch
    ports and gain network access.
    """
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("switch-controller", "switch-port-security"), "name"
    )
    if not supported:
        return out

    table = get_table(tables, ("switch-controller", "switch-port-security"))
    if not table or not any(isinstance(v, Node) for v in table.values()):
        msg = (
            "No switch port security policies configured. Without port "
            "security, unauthorized devices can connect to switch ports "
            "and gain network access."
        )
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(Finding(
            rule_id=rule.id, title=rule.title, severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom, message=msg, evidence=[],
        ))
    return out


# ---------------------------------------------------------------------------
# FGT-SYSTEM-NO-MGMT-INTERFACE
# ---------------------------------------------------------------------------

def rule_system_no_mgmt_interface(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect no dedicated management interface configured.

    Using a shared data interface for management exposes the management
    plane to the same threats as the data plane.
    """
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("system", "interface"), "type"
    )
    if not supported:
        return out

    table = get_table(tables, ("system", "interface"))
    has_mgmt = any(
        "mgmt" in str(n).lower() or "management" in str(n).lower()
        for n, node in table.items()
        if isinstance(node, Node)
    )
    if not has_mgmt:
        msg = (
            "No dedicated management interface found. Management traffic "
            "shares the data plane, exposing administrative access to the "
            "same threats as production traffic."
        )
        if schema_unknown:
            msg = f"[schema_unknown] {msg}"
        out.append(Finding(
            rule_id=rule.id, title=rule.title, severity=rule.severity,
            confidence=("heuristic" if schema_unknown else rule.confidence),
            vdom=vdom, message=msg, evidence=[],
        ))
    return out


# ---------------------------------------------------------------------------
# FGT-USER-NO-EXPIRY
# ---------------------------------------------------------------------------

def rule_user_no_expiry(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect user accounts configured without password expiry."""
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("user", "local"), "expire"
    )
    if not supported:
        return out

    table = get_table(tables, ("user", "local"))
    for uname, unode in table.items():
        if not isinstance(unode, Node):
            continue
        fields = unode.effective_fields()
        if not fields.get("expire"):
            ev: list[Evidence] = []
            if "set:expire" in unode.evidence:
                ev.append(unode.evidence["set:expire"])
            msg = (
                f'User "{uname}" has no expiry date. Without password '
                f"expiry, credentials may remain valid indefinitely even "
                f"if compromised."
            )
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-WIFI-NO-RADIUS
# ---------------------------------------------------------------------------

def rule_wifi_no_radius(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect enterprise WiFi SSID without RADIUS server configured."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("wireless-controller", "ssid"), "security"
    )
    if not supported:
        return out

    table = get_table(tables, ("wireless-controller", "ssid"))
    for sname, snode in table.items():
        if not isinstance(snode, Node):
            continue
        fields = snode.effective_fields()
        security = str(fields.get("security", "")).lower()
        if "enterprise" in security and not fields.get("radius-server"):
            ev: list[Evidence] = []
            if "set:radius-server" in snode.evidence:
                ev.append(snode.evidence["set:radius-server"])
            msg = (
                f'Enterprise WiFi "{sname}" has no RADIUS server configured. '
                f"Without RADIUS, per-user authentication and accountability "
                f"are not possible."
            )
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-WIFI-WPA-TKIP
# ---------------------------------------------------------------------------

def rule_wifi_wpa_tkip(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect wireless SSID using TKIP encryption (weak)."""
    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("wireless-controller", "ssid"), "security"
    )
    if not supported:
        return out

    table = get_table(tables, ("wireless-controller", "ssid"))
    for sname, snode in table.items():
        if not isinstance(snode, Node):
            continue
        fields = snode.effective_fields()
        security = str(fields.get("security", "")).lower()
        if "tkip" in security and "ccmp" not in security:
            ev: list[Evidence] = []
            if "set:security" in snode.evidence:
                ev.append(snode.evidence["set:security"])
            msg = (
                f'WiFi "{sname}" uses TKIP encryption ({security}). '
                f"TKIP is deprecated and vulnerable to cryptographic "
                f"attacks. Use WPA2-CCMP (AES) or WPA3 instead."
            )
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ---------------------------------------------------------------------------
# FGT-ZTNA-NO-TRUST-CERT
# ---------------------------------------------------------------------------

def rule_ztna_no_trust_cert(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect ZTNA server without a trusted certificate configured.

    ZTNA connections without a trusted certificate are vulnerable to
    man-in-the-middle attacks.
    """
    tables = _merged_scope_tables(model.vdoms.get(vdom, {}), model.global_cfg)
    out: list[Finding] = []

    supported, schema_unknown = _schema_supports_field(
        schema, ("ztna", "server"), "certificate"
    )
    if not supported:
        return out

    table = get_table(tables, ("ztna", "server"))
    for name, znode in table.items():
        if not isinstance(znode, Node):
            continue
        fields = znode.effective_fields()
        if not fields.get("certificate"):
            ev: list[Evidence] = []
            if "set:certificate" in znode.evidence:
                ev.append(znode.evidence["set:certificate"])
            msg = (
                f'ZTNA server "{name}" has no trusted certificate configured. '
                f"Without a trusted certificate, ZTNA sessions are vulnerable "
                f"to man-in-the-middle attacks."
            )
            if schema_unknown:
                msg = f"[schema_unknown] {msg}"
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=("heuristic" if schema_unknown else rule.confidence),
                vdom=vdom, message=msg, evidence=ev,
            ))
    return out


# ── ZTNA Rules ──

def rule_ztna_server_no_cert(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("ztna", "server"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("certificate"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"ZTNA server \"{name}\" has no trusted certificate configured.", evidence=[]))
    return out


def rule_ztna_rule_no_users(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("ztna", "rule"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("users") and not fields.get("user-groups"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"ZTNA rule \"{name}\" has no user or group restrictions.", evidence=[]))
    return out


def rule_ztna_no_posture(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("ztna", "rule"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("device-posture"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"ZTNA rule \"{name}\" does not require device posture check.", evidence=[]))
    return out


def rule_ztna_default_action(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("ztna", "rule"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        action = str(fields.get("action", "")).lower()
        if action in ("", "allow", "accept"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"ZTNA rule \"{name}\" has default allow action. Use deny-by-default.", evidence=[]))
    return out


def rule_ztna_no_forticlient(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("ztna", "rule"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("forticlient-check") and not fields.get("ems-tag"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"ZTNA rule \"{name}\" does not require FortiClient endpoint compliance.", evidence=[]))
    return out


def rule_ztna_port_standard(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("ztna", "server"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        port = fields.get("port")
        if port:
            try:
                p = int(str(port))
                if p != 443 and p != 10443:
                    out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"ZTNA server \"{name}\" on non-standard port {p}.", evidence=[]))
            except (ValueError, TypeError):
                pass
    return out


def rule_ztna_no_reauth(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("ztna", "server"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("reauth-interval"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"ZTNA server \"{name}\" has no re-authentication interval configured.", evidence=[]))
    return out


def rule_ztna_no_logging(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("ztna", "rule"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("logtraffic") != "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"ZTNA rule \"{name}\" has logging disabled.", evidence=[]))
    return out


def rule_ztna_exposed_apps(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("ztna", "server"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("saml-service-provider") and not fields.get("client-cert"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"ZTNA server \"{name}\" has applications exposed without additional access controls.", evidence=[]))
    return out

# ── SIA Rules ──

def rule_sia_no_dns_filter(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    policy_table = get_table(tables, ("firewall", "policy"))
    for name, node in policy_table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if str(fields.get("action", "")).lower() == "accept" and not fields.get("dnsfilter-profile"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Policy {name}: accepts traffic without DNS filter.", evidence=[]))
    return out


def rule_sia_no_web_filter(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    policy_table = get_table(tables, ("firewall", "policy"))
    for name, node in policy_table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if str(fields.get("action", "")).lower() == "accept" and not fields.get("webfilter-profile"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Policy {name}: accepts traffic without web filter.", evidence=[]))
    return out


def rule_sia_no_ssl_inspect(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    policy_table = get_table(tables, ("firewall", "policy"))
    for name, node in policy_table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if str(fields.get("action", "")).lower() == "accept" and not fields.get("ssl-ssh-profile"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Policy {name}: accepts traffic without SSL inspection.", evidence=[]))
    return out


def rule_sia_no_app_control(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    policy_table = get_table(tables, ("firewall", "policy"))
    for name, node in policy_table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if str(fields.get("action", "")).lower() == "accept" and not fields.get("application-list"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Policy {name}: accepts traffic without application control.", evidence=[]))
    return out


def rule_sia_no_ips(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    policy_table = get_table(tables, ("firewall", "policy"))
    for name, node in policy_table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if str(fields.get("action", "")).lower() == "accept" and not fields.get("ips-sensor"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Policy {name}: accepts traffic without IPS sensor.", evidence=[]))
    return out


def rule_sia_no_captive_portal(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("user", "setting"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("auth-captive-portal") != "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Captive portal is not enabled for guest access.", evidence=[]))
    return out


def rule_sia_no_log(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    policy_table = get_table(tables, ("firewall", "policy"))
    for name, node in policy_table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if str(fields.get("action", "")).lower() == "accept" and fields.get("logtraffic") != "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Policy {name}: accepts traffic without logging.", evidence=[]))
    return out


def rule_sia_no_geo_ip(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    policy_table = get_table(tables, ("firewall", "policy"))
    for name, node in policy_table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        src = as_list(fields.get("srcaddr"))
        if "all" in src and not fields.get("geoip-match"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Policy {name}: accepts all sources without geo-IP filtering.", evidence=[]))
    return out


# ── VPN Hardening Rules ──

def rule_vpn_no_dpd(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("vpn", "ipsec", "phase1-interface"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("dpd") and not fields.get("auto-negotiate"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPsec phase1 \"{name}\" has no dead peer detection.", evidence=[]))
    return out


def rule_vpn_no_nat_t(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("vpn", "ipsec", "phase1-interface"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("nat-traversal") == "disable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPsec phase1 \"{name}\" has NAT traversal disabled.", evidence=[]))
    return out


def rule_vpn_short_ike(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("vpn", "ipsec", "phase1-interface"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        lt = fields.get("lifetime")
        if lt:
            try:
                val = int(str(lt))
                if val < 28800:
                    out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPsec phase1 \"{name}\" has short IKE lifetime ({val}s).", evidence=[]))
            except (ValueError, TypeError):
                pass
    return out


def rule_vpn_no_dh_group14(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    weak_groups = ["1", "2"]
    table = get_table(tables, ("vpn", "ipsec", "phase1-interface"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        dhgroup = as_list(fields.get("dhgrp"))
        for g in dhgroup:
            if str(g) in weak_groups:
                out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPsec phase1 \"{name}\" uses weak DH group {g}.", evidence=[]))
                break
    return out


def rule_vpn_no_auth_localid(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("vpn", "ipsec", "phase1-interface"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("localid"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPsec phase1 \"{name}\" has no local ID.", evidence=[]))
    return out


def rule_vpn_ssl_no_client_cert(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("vpn", "ssl", "settings"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("reqclientcert"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="SSL VPN does not require client certificate.", evidence=[]))
    return out


def rule_vpn_ssl_dns_split(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("vpn", "ssl", "settings"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("dns-split-tunnel") == "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="SSL VPN has DNS split tunneling enabled.", evidence=[]))
    return out


def rule_vpn_ipsec_no_replay(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("vpn", "ipsec", "phase2-interface"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("replay") == "disable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPsec phase2 \"{name}\" has anti-replay disabled.", evidence=[]))
    return out


def rule_vpn_ipsec_compression(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("vpn", "ipsec", "phase2-interface"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("compression") == "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPsec phase2 \"{name}\" has compression enabled.", evidence=[]))
    return out


# ── Routing Security Rules ──

def rule_routing_bgp_no_password(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("router", "bgp"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("password"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="BGP configured without MD5 authentication.", evidence=[]))
    return out


def rule_routing_bgp_no_prefix_filter(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("router", "prefix-list"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No prefix lists for BGP route filtering.", evidence=[]))
    return out


def rule_routing_bgp_no_max_prefix(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("router", "bgp"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("maximum-prefix"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="BGP has no maximum prefix limit.", evidence=[]))
    return out


def rule_routing_ospf_no_auth(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("router", "ospf"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("authentication"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="OSPF configured without authentication.", evidence=[]))
    return out


def rule_routing_ospf_no_passive(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("router", "ospf"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("passive-interface"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="OSPF has no passive interfaces.", evidence=[]))
    return out


def rule_routing_static_no_gw_check(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("router", "static"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("distance") and not fields.get("weight"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Static route {name} has no distance/weight.", evidence=[]))
    return out


def rule_routing_no_route_map(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("router", "route-map"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No route maps for route filtering.", evidence=[]))
    return out


def rule_routing_no_prefix_list(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("router", "prefix-list"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No prefix lists for route filtering.", evidence=[]))
    return out


def rule_routing_rip_no_auth(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("router", "rip"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("authentication"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="RIP configured without authentication.", evidence=[]))
    return out


# ── FortiSwitch Rules ──

def rule_switch_no_8021x(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("switch-controller", "switch-port-security"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No 802.1X port security on switches.", evidence=[]))
    return out


def rule_switch_no_vlan_seg(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("switch-controller", "managed-switch"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("vlan"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Switch \"{name}\" has no VLAN config.", evidence=[]))
    return out


def rule_switch_no_storm_control(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("switch-controller", "managed-switch"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("storm-control"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Switch \"{name}\" has no storm control.", evidence=[]))
    return out


def rule_switch_no_mac_limit(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("switch-controller", "switch-port-security"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("mac-limit"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Port security \"{name}\" has no MAC limit.", evidence=[]))
    return out


def rule_switch_no_bpdu_guard(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("switch-controller", "managed-switch"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("bpdu-guard"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Switch \"{name}\" has no BPDU guard.", evidence=[]))
    return out


def rule_switch_no_dhcp_snoop(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("switch-controller", "managed-switch"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("dhcp-snooping"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Switch \"{name}\" has no DHCP snooping.", evidence=[]))
    return out


def rule_switch_no_dynamic_arp(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("switch-controller", "managed-switch"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("arp-inspection"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Switch \"{name}\" has no dynamic ARP inspection.", evidence=[]))
    return out


# ── FortiAP Rules ──

def rule_ap_no_wpa3(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("wireless-controller", "ssid"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        security = str(fields.get("security", "")).lower()
        if "wpa3" not in security and "sae" not in security and "enterprise" not in security:
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"WiFi SSID \"{name}\" does not use WPA3.", evidence=[]))
    return out


def rule_ap_open_network(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("wireless-controller", "ssid"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        security = str(fields.get("security", "")).lower()
        if security in ("", "open", "none"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"WiFi SSID \"{name}\" has no encryption.", evidence=[]))
    return out


def rule_ap_no_client_isolation(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("wireless-controller", "ssid"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("client-isolation"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"WiFi SSID \"{name}\" has no client isolation.", evidence=[]))
    return out


def rule_ap_no_max_clients(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("wireless-controller", "ssid"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("max-clients"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"WiFi SSID \"{name}\" has no client limit.", evidence=[]))
    return out


def rule_ap_no_radius(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("wireless-controller", "ssid"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        security = str(fields.get("security", "")).lower()
        if "enterprise" in security and not fields.get("radius-server"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Enterprise WiFi \"{name}\" has no RADIUS.", evidence=[]))
    return out


def rule_ap_no_logging(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("wireless-controller", "ssid"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("log-client-event"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"WiFi SSID \"{name}\" has no client event logging.", evidence=[]))
    return out


# ── Additional Security Rules ──

def rule_firewall_no_dose(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("firewall", "DoS-policy"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No DoS protection policy configured.", evidence=[]))
    return out


def rule_firewall_no_antispoof(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("firewall", "DoS-policy"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("anomaly"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"DoS policy \"{name}\" has no anomaly detection.", evidence=[]))
    return out


def rule_log_no_fortianalyzer(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    global_tables = _merged_scope_tables(tables, model.global_cfg)
    faz_table = get_table(global_tables, ("log", "fortianalyzer", "setting"))
    if not faz_table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No FortiAnalyzer logging configured.", evidence=[]))
    return out


def rule_auth_no_radius(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("user", "radius"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No RADIUS server configured.", evidence=[]))
    return out


def rule_auth_no_ldap(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("user", "ldap"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No LDAP server configured.", evidence=[]))
    return out


def rule_system_no_ntps(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "ntp"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        ntp_type = str(fields.get("type", "")).lower()
        if ntp_type == "custom" and not fields.get("ntps"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="NTP configured without NTPS (TLS).", evidence=[]))
    return out


def rule_system_no_snmpv3(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "snmp"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("v2c-status") == "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="SNMPv2c enabled. Use SNMPv3.", evidence=[]))
    return out


def rule_system_no_fortiguard(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "fortiguard"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("update-server-location") == "disable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="FortiGuard update service disabled.", evidence=[]))
    return out


# ── Local-in Policy Rules ──

def rule_firewall_no_local_in(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("firewall", "local-in-policy"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No local-in policy configured. Management access is unprotected.", evidence=[]))
    return out


def rule_firewall_local_in_no_restrict(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("firewall", "local-in-policy"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        svc = str(fields.get("service", "")).lower()
        if svc in ("all", "all"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Local-in policy {name} allows ALL services. Restrict to specific management services.", evidence=[]))
    return out


# ── Security Fabric Rules ──

def rule_fabric_no_quarantine(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "security-fabric"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("compromised-host-quat-enable") != "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Security Fabric quarantine not enabled for compromised hosts.", evidence=[]))
    return out


def rule_fabric_no_root(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "security-fabric"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Security Fabric is not configured.", evidence=[]))
    return out


# ── Network Hardening Rules ──

def rule_network_no_tcp_seq(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("tcp-seq-picky") != "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="TCP sequence checking (tcp-seq-picky) is not enabled.", evidence=[]))
    return out


def rule_network_no_urpf(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("system", "interface"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        role = str(fields.get("role", "")).lower()
        if role in ("lan", "dmz", "wan") and not fields.get("urpf"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Interface \"{name}\" does not have reverse path forwarding.", evidence=[]))
    return out


def rule_network_no_unicast_route(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "setting"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("unicast-reverse-path"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Unicast reverse path forwarding not configured.", evidence=[]))
    return out


# ── System Hardening Rules ──

def rule_system_default_hostname(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        hostname = str(fields.get("hostname", "")).lower()
        if hostname in ("", "fortigate", "fgt", "fg"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Default hostname \"{hostname}\" not changed. Set a unique hostname.", evidence=[]))
    return out


def rule_system_no_password_policy(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "password"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("min-length") and not fields.get("min-lower-case") and not fields.get("min-upper-case"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Password policy has no minimum requirements configured.", evidence=[]))
    return out


def rule_system_no_firmware_check(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "fortiguard-service"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("update-check") or fields.get("update-check") == "disable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Firmware auto-check is not enabled.", evidence=[]))
    return out


def rule_system_ddns_enabled(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("system", "ddns"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("ddns-status") == "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="DDNS is enabled. Disable unless explicitly needed.", evidence=[]))
    return out


def rule_system_usb_auto_install(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "usb"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("auto-install") == "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="USB auto-install is enabled. Disable to prevent unauthorized config loading.", evidence=[]))
    return out


def rule_system_no_strong_crypto(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("strong-crypto") != "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Strong crypto is not enabled. Enable for secure communications.", evidence=[]))
    return out


def rule_system_gui_tls_weak(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        tls_min = fields.get("admin-https-ssl-min-tls")
        if tls_min and str(tls_min) in ("1.0", "1.1"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"GUI allows TLS {tls_min}. Minimum should be TLS 1.2.", evidence=[]))
    return out


def rule_system_no_banner(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("pre-login-banner") and not fields.get("post-login-banner"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No login banner configured. Required for legal compliance.", evidence=[]))
    return out


def rule_system_no_timezone(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        tz = fields.get("timezone")
        if not tz or str(tz) in ("", "00"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Timezone not configured. Affects log accuracy.", evidence=[]))
    return out


# ── HA Hardening Rules ──

def rule_ha_no_interface_monitor(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "ha"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("monitor"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="HA is configured without interface monitoring.", evidence=[]))
    return out


def rule_ha_no_mgmt_interface(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "ha"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("management-interface") and fields.get("mode"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="HA is configured without a reserved management interface.", evidence=[]))
    return out


def rule_ha_default_group_id(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "ha"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        group_id = fields.get("group-id")
        if group_id is not None:
            try:
                if int(str(group_id)) == 0:
                    out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="HA uses default group ID 0. Change to prevent conflicts.", evidence=[]))
            except (ValueError, TypeError):
                pass
    return out


# ── Logging Hardening Rules ──

def rule_log_no_encryption(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("log", "fortianalyzer", "setting"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("encryption") != "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="FortiAnalyzer logging without encryption enabled.", evidence=[]))
    return out


def rule_log_no_extended(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("log", "fortianalyzer", "setting"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("retention"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No extended log retention configured.", evidence=[]))
    return out


# ── Implicit Deny Rules ──

def rule_policy_implicit_deny_no_log(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("firewall", "policy"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        action = str(fields.get("action", "")).lower()
        if action in ("deny", "deny") and fields.get("logtraffic") != "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Deny policy {name} has logging disabled.", evidence=[]))
    return out

# ── System/BIOS Hardening Rules ──

def rule_sys_maintainer_enabled(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        maintainer = fields.get("maintainer")
        if maintainer is None or str(maintainer).lower() != "disable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Maintainer account is enabled. Disable to prevent password reset without credentials.", evidence=[]))
    return out


def rule_sys_secure_boot_disabled(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("secureboot-status") != "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Secure boot is not enabled. Enable for BIOS-level security.", evidence=[]))
    return out


# ── Admin Access (additional) ──

def rule_admin_https_redirect(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("admin-https-redirect") != "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="HTTPS redirect not enabled. HTTP admin access is possible.", evidence=[]))
    return out


def rule_admin_ssh_grace_long(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        grace = fields.get("admin-ssh-grace-time")
        if grace:
            try:
                val = int(str(grace))
                if val > 60:
                    out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"SSH grace time is {val}s. Recommended: 60s or less.", evidence=[]))
            except (ValueError, TypeError):
                pass
    return out


def rule_admin_scp_enabled(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("admin-scp") == "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="SCP access is enabled. Disable to restrict config access.", evidence=[]))
    return out


def rule_admin_forticloud_enabled(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("admin-forticloud-access") == "enable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="FortiCloud access is enabled. Disable unless actively used.", evidence=[]))
    return out


def rule_admin_hostkey_default(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("admin-ssh-hostkey"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="SSH host key not configured. Regenerate with strong key.", evidence=[]))
    return out


# ── Encryption/TLS Rules ──

def rule_tls_admin_cipher_weak(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    weak_ciphers = ["rc4", "des", "3des", "export", "null"]
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "global"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        ciphersuite = str(fields.get("admin-https-ssl-ciphersuite", "")).lower()
        for wc in weak_ciphers:
            if wc in ciphersuite:
                out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Weak admin cipher '{wc}' in HTTPS ciphersuite.", evidence=[]))
                break
    return out


def rule_ssh_weak_mac(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    weak_mac = ["hmac-md5", "hmac-sha1-96"]
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "ssh"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        allowed_mac = str(fields.get("strong-crypto", "")).lower()
        for wm in weak_mac:
            if wm in allowed_mac:
                out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Weak SSH MAC '{wm}' is allowed.", evidence=[]))
    return out


def rule_ssh_weak_kex(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "ssh"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        kex = str(fields.get("kex-algorithms", "")).lower()
        for wk in weak_kex:
            if wk in kex:
                out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Weak SSH key exchange '{wk}' is allowed.", evidence=[]))
    return out


# ── Network Security Rules ──

def rule_net_ipv6_unprotected(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    iface_table = get_table(tables, ("system", "interface"))
    policy6_table = get_table(tables, ("firewall", "policy6"))
    ipv6_ifaces = []
    for name, node in iface_table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("ipv6") == "enable" or fields.get("allowaccess-ipv6"):
            ipv6_ifaces.append(name)
    if ipv6_ifaces and not policy6_table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPv6 enabled on {len(ipv6_ifaces)} interfaces but no IPv6 firewall policies.", evidence=[]))
    return out


def rule_net_unused_iface_up(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("system", "interface"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        status = str(fields.get("status", "up")).lower()
        iface_type = str(fields.get("type", "")).lower()
        if status == "up" and iface_type in ("physical", ""):
            if not fields.get("allowaccess") and not fields.get("role"):
                out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Interface \"{name}\" is up but has no allowaccess or role.", evidence=[]))
    return out


# ── DoS/Flood Protection Rules ──

def rule_dos_no_synproxy(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("firewall", "DoS-policy"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("synproxy"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"DoS policy \"{name}\" has no SYN proxy configured.", evidence=[]))
    return out


def rule_flood_no_udp_limit(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("firewall", "DoS-policy"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("udp-flood-limit") and not fields.get("udp-flood-rate"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"DoS policy \"{name}\" has no UDP flood protection.", evidence=[]))
    return out


# ── Certificate Management Rules ──

def rule_cert_self_signed_admin(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "certificate"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        issuer = str(fields.get("issuer", "")).lower()
        subject = str(fields.get("subject", "")).lower()
        if issuer and subject and issuer == subject:
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Certificate \"{name}\" is self-signed.", evidence=[]))
    return out


def rule_cert_weak_keysize(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "certificate"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        key_type = str(fields.get("key-type", "")).lower()
        key_size = fields.get("key-size")
        if key_type == "rsa" and key_size:
            try:
                if int(str(key_size)) < 2048:
                    out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"Certificate \"{name}\" uses RSA {key_size}-bit key. Minimum: 2048.", evidence=[]))
            except (ValueError, TypeError):
                pass
    return out


# ── Central Management Rules ──

def rule_cfg_no_central_mgmt(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "central-management"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No central management configured.", evidence=[]))
    return out


def rule_cfg_encrypted_backup(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "backup"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if not fields.get("backup-password") and not fields.get("encrypt"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Configuration backup is not encrypted.", evidence=[]))
    return out


def rule_cfg_auto_backup(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "automation-trigger"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No automation triggers configured. Set up automated backups.", evidence=[]))
    return out


# ── Security Fabric Rules ──

def rule_csf_no_joined(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "csf"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("status") == "disable" or not fields.get("status"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="Security Fabric is disabled.", evidence=[]))
    return out


def rule_fg_update_disabled(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("system", "fortiguard-service"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        if fields.get("auto-update") == "disable":
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="FortiGuard auto-update is disabled.", evidence=[]))
    return out


# ── SSL VPN Additional Rules ──

def rule_vpn_ssl_idletimeout_high(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(_merged_scope_tables(tables, model.global_cfg), ("vpn", "ssl", "settings"))
    for _name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        timeout = fields.get("idle-timeout")
        if timeout:
            try:
                val = int(str(timeout))
                if val > 300:
                    out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"SSL VPN idle timeout is {val}s. Recommended: 300s or less.", evidence=[]))
            except (ValueError, TypeError):
                pass
    return out


def rule_vpn_ipsec_weak_cipher(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    weak_enc = ["des", "3des", "blowfish", "arc4"]
    for table_name in [("vpn", "ipsec", "phase1-interface"), ("vpn", "ipsec", "phase2-interface")]:
        table = get_table(tables, table_name)
        for name, node in table.items():
            if not isinstance(node, Node): continue
            fields = node.effective_fields()
            enc = str(fields.get("encryption", "")).lower()
            for we in weak_enc:
                if we in enc:
                    out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPsec \"{name}\" uses weak encryption '{we}'.", evidence=[]))
                    break
    return out


def rule_vpn_ipsec_weak_integrity(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    weak_int = ["md5", "sha1"]
    table = get_table(tables, ("vpn", "ipsec", "phase2-interface"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        integrity = str(fields.get("integrity", "")).lower()
        for wi in weak_int:
            if wi in integrity:
                out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPsec phase2 \"{name}\" uses weak integrity '{wi}'.", evidence=[]))
                break
    return out


# ── IPS/DLP Rules ──

def rule_ips_mode_monitor(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("ips", "sensor"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        action = str(fields.get("action", "")).lower()
        if action in ("monitor", "pass", "allow"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"IPS sensor \"{name}\" is in monitor-only mode. Switch to block.", evidence=[]))
    return out


def rule_av_mode_monitor(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("antivirus", "profile"))
    for name, node in table.items():
        if not isinstance(node, Node): continue
        fields = node.effective_fields()
        action = str(fields.get("av-action", "")).lower()
        if action in ("monitor", "pass", "allow"):
            out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message=f"AV profile \"{name}\" is in monitor-only mode.", evidence=[]))
    return out


def rule_email_no_filter(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []
    table = get_table(tables, ("emailfilter", "profile"))
    if not table:
        out.append(Finding(rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence, vdom=vdom, message="No email filter profile configured.", evidence=[]))
    return out
