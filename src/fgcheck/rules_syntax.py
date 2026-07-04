"""Syntax validation rules for FortiGate configurations.

These rules check config correctness, not just security posture.
They validate:
- Unknown commands/tables
- Invalid field values
- Type mismatches
- Missing required fields
- Deprecated syntax
- Duplicate entries
- IP address format
- Port number range
"""

from __future__ import annotations

from .facts import Facts
from .model import ConfigModel, Node
from .rules import Finding, Rule
from .schema import SchemaView


def _walk_tables(tables, callback, prefix=()):
    """Recursively walk the nested dict structure and call callback for each Node."""
    for key, value in tables.items():
        if key.startswith("__"):
            continue
        if isinstance(value, Node):
            callback(prefix, key, value)
        elif isinstance(value, dict):
            _walk_tables(value, callback, prefix + (key,))


def _walk_nodes(model, vdom, callback):
    """Walk all nodes in a vdom's nested config structure."""
    tables = model.vdoms.get(vdom, {})
    _walk_tables(tables, callback)


def rule_unknown_table(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect config tables that don't exist in the FortiOS schema."""
    if schema is None or not schema.loaded:
        return []

    tables = model.vdoms.get(vdom, {})
    out: list[Finding] = []

    for table_path, _table_data in tables.items():
        if table_path.startswith("__"):
            continue
        if isinstance(table_path, tuple):
            normalized = " ".join(str(p).strip().lower() for p in table_path if str(p).strip())
        else:
            normalized = str(table_path).strip().lower()

        if not schema.has_table(normalized):
            out.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    vdom=vdom,
                    message=f'Unknown table "{normalized}" not found in schema.',
                    evidence=[],
                )
            )

    return out


def rule_unknown_field(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect config fields that don't exist in the FortiOS schema."""
    if schema is None or not schema.loaded:
        return []

    model.vdoms.get(vdom, {})
    out: list[Finding] = []

    def _check(prefix, name, node):
        table_path = " ".join(prefix)
        for field_name in node.fields:
            if field_name.startswith("__"):
                continue
            if not schema.has_field(table_path, field_name):
                out.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        vdom=vdom,
                        message=f'Unknown field "{field_name}" on table "{table_path}".',
                        evidence=[],
                    )
                )

    _walk_nodes(model, vdom, _check)
    return out


def rule_deprecated_syntax(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect deprecated FortiOS syntax patterns."""
    out: list[Finding] = []

    deprecated_fields = {
        "access": ("allowaccess", 'Use "set allowaccess" instead of "set access"'),
    }

    def _check(prefix, name, node):
        fields = node.effective_fields()
        for field_name, (_new_field, message) in deprecated_fields.items():
            if field_name in fields:
                out.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        vdom=vdom,
                        message=f'Deprecated syntax: "set {field_name}" — {message}',
                        evidence=[],
                    )
                )

    _walk_nodes(model, vdom, _check)
    return out


def rule_duplicate_edit_blocks(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect duplicate edit blocks in the same table."""
    out: list[Finding] = []
    seen = set()

    def _check(prefix, name, node):
        path = " ".join(prefix)
        key = (vdom, path, name)
        if key in seen:
            out.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    vdom=vdom,
                    message=f'Duplicate entry "{name}" in table "{path}".',
                    evidence=[],
                )
            )
        else:
            seen.add(key)

    _walk_nodes(model, vdom, _check)
    return out


def rule_empty_table(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect tables that have no entries (only nested dicts)."""
    out: list[Finding] = []

    def _check_dict(tables, prefix=()):
        for key, value in tables.items():
            if key.startswith("__"):
                continue
            if isinstance(value, dict):
                has_children = any(isinstance(v, (Node, dict)) for k, v in value.items() if not k.startswith("__"))
                if not has_children and prefix + (key,) != ("system", "global"):
                    path = " ".join(prefix + (key,))
                    out.append(
                        Finding(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            vdom=vdom,
                            message=f'Table "{path}" is configured but has no entries.',
                            evidence=[],
                        )
                    )
                _check_dict(value, prefix + (key,))

    _check_dict(model.vdoms.get(vdom, {}))
    return out


def rule_missing_end(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect entries with no fields set."""
    out: list[Finding] = []

    def _check(prefix, name, node):
        fields = node.effective_fields()
        if len(fields) == 0:
            path = " ".join(prefix)
            out.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    vdom=vdom,
                    message=f'Entry "{name}" in "{path}" has no fields set.',
                    evidence=[],
                )
            )

    _walk_nodes(model, vdom, _check)
    return out


def rule_ip_address_format(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect malformed IP addresses in config fields."""
    import re

    out: list[Finding] = []
    ip_fields = {"dst", "src", "subnet", "gateway", "ip", "server", "remote-ip", "netmask"}
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

    def _check(prefix, name, node):
        fields = node.effective_fields()
        for field_name in ip_fields:
            if field_name in fields:
                val = fields[field_name]
                parts = val if isinstance(val, list) else str(val).split()
                for part in parts:
                    part = str(part).strip()
                    if ip_pattern.match(part):
                        for octet in part.split("."):
                            try:
                                if int(octet) > 255:
                                    out.append(
                                        Finding(
                                            rule_id=rule.id,
                                            title=rule.title,
                                            severity=rule.severity,
                                            confidence=rule.confidence,
                                            vdom=vdom,
                                            message=f'Malformed IP "{part}" in {field_name} (octet {octet} > 255).',
                                            evidence=[],
                                        )
                                    )
                                    break
                            except ValueError:
                                pass

    _walk_nodes(model, vdom, _check)
    return out


def rule_port_range_format(
    *, model: ConfigModel, facts: Facts, vdom: str, rule: Rule, schema: SchemaView | None = None
) -> list[Finding]:
    """Detect invalid port numbers in service/port fields."""
    out: list[Finding] = []
    port_fields = {"port", "dstport", "srcport", "start-port", "end-port", "tcp-portrange", "udp-portrange"}

    def _check(prefix, name, node):
        fields = node.effective_fields()
        for field_name in port_fields:
            if field_name in fields:
                val = str(fields[field_name]).strip()
                for part in val.replace(",", " ").replace("-", " ").split():
                    try:
                        port = int(part)
                        if port < 0 or port > 65535:
                            out.append(
                                Finding(
                                    rule_id=rule.id,
                                    title=rule.title,
                                    severity=rule.severity,
                                    confidence=rule.confidence,
                                    vdom=vdom,
                                    message=f"Invalid port {port} in {field_name} (must be 0-65535).",
                                    evidence=[],
                                )
                            )
                    except ValueError:
                        pass

    _walk_nodes(model, vdom, _check)
    return out
