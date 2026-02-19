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
        if schema.partial:
            return True, True
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
    value = str(node.fields.get("ssl-min-proto-ver", "")).strip().lower()
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
        if str(pnode.fields.get("status", "")).strip().lower() == "disable":
            continue
        action = str(pnode.fields.get("action", "")).strip().lower()
        if action != "accept":
            continue
        intf_vals = {v.lower() for v in as_list(pnode.fields.get("intf"))}
        src_vals = {v.lower() for v in as_list(pnode.fields.get("srcaddr"))}
        svc_vals = {v.lower() for v in as_list(pnode.fields.get("service"))}
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
    support_checks = [
        _schema_supports_field(schema, ("system", "admin"), "accprofile"),
        _schema_supports_field(schema, ("system", "admin"), "trusthost1"),
    ]
    if any(not s for s, _ in support_checks):
        return out
    schema_unknown = any(u for _, u in support_checks)

    for admin_name, anode in admin_table.items():
        if not isinstance(anode, Node):
            continue
        if str(anode.fields.get("accprofile", "")).strip().lower() != "super_admin":
            continue
        trusthost1 = as_list(anode.fields.get("trusthost1"))
        unrestricted = False
        if not trusthost1:
            unrestricted = True
        if len(trusthost1) >= 2 and trusthost1[0] == "0.0.0.0" and trusthost1[1] == "0.0.0.0":
            unrestricted = True
        if not unrestricted:
            continue

        ev = []
        if "set:accprofile" in anode.evidence:
            ev.append(anode.evidence["set:accprofile"])
        if "set:trusthost1" in anode.evidence:
            ev.append(anode.evidence["set:trusthost1"])
        msg = f'Admin "{admin_name}" has super_admin profile with unrestricted trusthost1.'
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
    if str(node.fields.get("status", "enable")).strip().lower() == "disable":
        return out
    if "any" not in {v.lower() for v in as_list(node.fields.get("source-interface"))}:
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
    if str(node.fields.get("status", "enable")).strip().lower() == "disable":
        return out
    if str(node.fields.get("source-address-negate", "")).strip().lower() == "enable":
        return out
    if "all" not in {v.lower() for v in as_list(node.fields.get("source-address"))}:
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
        if str(anode.fields.get("accprofile", "")).strip().lower() != "super_admin":
            continue
        tf = str(anode.fields.get("two-factor", "")).strip().lower()
        tfa = str(anode.fields.get("two-factor-authentication", "")).strip().lower()
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
        access_set = {v.lower() for v in as_list(inode.fields.get("allowaccess"))}
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
    supported, schema_unknown = _schema_supports_field(schema, ("system", "admin"), "trusthost1")
    if not supported:
        return out

    for admin_name, anode in admin_table.items():
        if not isinstance(anode, Node):
            continue
        trusthost1 = as_list(anode.fields.get("trusthost1"))
        unrestricted = not trusthost1
        if len(trusthost1) >= 2 and trusthost1[0] == "0.0.0.0" and trusthost1[1] == "0.0.0.0":
            unrestricted = True
        if not unrestricted:
            continue
        ev = []
        for ek in ("set:trusthost1", "set:accprofile"):
            if ek in anode.evidence:
                ev.append(anode.evidence[ek])
        if not ev:
            continue
        msg = f'Admin "{admin_name}" has no trusted host restriction (trusthost1 is unset or any-any).'
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
        if str(pnode.fields.get("status", "")).strip().lower() == "disable":
            continue
        enabled_entries.append(pnode)
        if str(pnode.fields.get("action", "")).strip().lower() == "deny":
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
        if str(pnode.fields.get("status", "")).strip().lower() == "disable":
            continue
        if str(pnode.fields.get("action", "")).strip().lower() != "accept":
            continue
        src = {v.lower() for v in as_list(pnode.fields.get("srcaddr"))}
        dst = {v.lower() for v in as_list(pnode.fields.get("dstaddr"))}
        svc = {v.lower() for v in as_list(pnode.fields.get("service"))}
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
            if str(pnode.fields.get("status", "")).strip().lower() == "disable":
                continue
            groups = {v.strip() for v in as_list(pnode.fields.get("dhgrp"))}
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
            if str(node.fields.get("status", "")).strip().lower() == "enable":
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
