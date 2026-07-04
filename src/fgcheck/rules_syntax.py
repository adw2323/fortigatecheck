"""Syntax validation rules for FortiGate configurations.

These rules check config correctness, not just security posture.
They validate:
- Unknown commands/tables
- Invalid field values
- Type mismatches
- Missing required fields
- Deprecated syntax
"""
from __future__ import annotations
from typing import List, Optional

from .facts import Facts, get_table
from .model import ConfigModel, Node
from .rules import Finding, Rule
from .schema import SchemaView


def rule_unknown_table(
    *, model: ConfigModel, facts: Facts, vdom: str,
    rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
    """Detect config tables that don't exist in the FortiOS schema.

    When a table is present in the config but not in the schema for the
    target FortiOS version, it may be:
    - A typo in the config
    - A deprecated table from an older version
    - A vendor-specific extension
    - A table from a newer version not yet in schema
    """
    if schema is None or not schema.loaded:
        return []  # Can't validate without schema

    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    for table_path, table_data in tables.items():
        if table_path.startswith("__"):
            continue  # Skip metadata keys

        # Normalize table path for schema lookup
        if isinstance(table_path, tuple):
            normalized = " ".join(str(p).strip().lower() for p in table_path if str(p).strip())
        else:
            normalized = str(table_path).strip().lower()

        if not schema.has_table(normalized):
            out.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                vdom=vdom,
                message=f'Unknown table "{normalized}" not found in FortiOS schema (version {schema.resolved_version}).',
                evidence=[],
            ))

    return out


def rule_unknown_field(
    *, model: ConfigModel, facts: Facts, vdom: str,
    rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
    """Detect config fields that don't exist in the FortiOS schema.

    When a field is set on a table but not in the schema for the target
    version, it may be:
    - A typo in the field name
    - A deprecated field
    - A field from a different FortiOS version
    """
    if schema is None or not schema.loaded:
        return []

    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    for table_path, table_data in tables.items():
        if table_path.startswith("__"):
            continue
        if not isinstance(table_data, dict):
            continue

        for entry_name, entry_data in table_data.items():
            if entry_name.startswith("__"):
                continue
            if not isinstance(entry_data, Node):
                continue

            for field_name in entry_data.fields:
                if field_name.startswith("__"):
                    continue
                if not schema.has_field(table_path, field_name):
                    out.append(Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        vdom=vdom,
                        message=f'Unknown field "{field_name}" on table "{table_path}" not found in schema.',
                        evidence=[],
                    ))

    return out


def rule_deprecated_syntax(
    *, model: ConfigModel, facts: Facts, vdom: str,
    rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
    """Detect deprecated FortiOS syntax patterns.

    Checks for common deprecated patterns:
    - set access ssh (should be set allowaccess ssh)
    - set trusted-host (should be set trusted-host-ip-mask)
    - Old-style logging commands
    """
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    # Deprecated patterns: (field_name, old_value, new_value, message)
    deprecated_patterns = [
        ("access", "ssh", "allowaccess", 'Use "set allowaccess" instead of "set access"'),
        ("access", "http", "allowaccess", 'Use "set allowaccess" instead of "set access"'),
        ("access", "https", "allowaccess", 'Use "set allowaccess" instead of "set access"'),
        ("access", "telnet", "allowaccess", 'Use "set allowaccess" instead of "set access"'),
    ]

    for table_path, table_data in tables.items():
        if table_path.startswith("__"):
            continue
        if not isinstance(table_data, dict):
            continue

        for entry_name, entry_data in table_data.items():
            if entry_name.startswith("__"):
                continue
            if not isinstance(entry_data, Node):
                continue

            for field_name, old_val, new_field, message in deprecated_patterns:
                if field_name in entry_data.fields:
                    field_val = str(entry_data.fields[field_name]).lower()
                    if field_val == old_val.lower():
                        out.append(Finding(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            vdom=vdom,
                            message=f'Deprecated syntax: "set {field_name} {old_val}" — {message}',
                            evidence=[],
                        ))

    return out


def rule_duplicate_edit_blocks(
    *, model: ConfigModel, facts: Facts, vdom: str,
    rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
    """Detect duplicate edit blocks in the same table.

    FortiOS allows multiple edit blocks with the same name in some tables
    but this is almost always a copy-paste error.
    """
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    for table_path, table_data in tables.items():
        if table_path.startswith("__"):
            continue
        if not isinstance(table_data, dict):
            continue

        seen_names = {}
        for entry_name, entry_data in table_data.items():
            if entry_name.startswith("__"):
                continue
            if not isinstance(entry_data, Node):
                continue

            if entry_name in seen_names:
                out.append(Finding(
                    rule_id=rule.id, title=rule.title, severity=rule.severity,
                    confidence=rule.confidence, vdom=vdom,
                    message=f'Duplicate edit block "{entry_name}" in table "{table_path}".',
                    evidence=[],
                ))
            else:
                seen_names[entry_name] = True

    return out


def rule_empty_table(
    *, model: ConfigModel, facts: Facts, vdom: str,
    rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
    """Detect tables with no entries.

    Empty tables are not errors but may indicate incomplete configuration.
    """
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    for table_path, table_data in tables.items():
        if table_path.startswith("__"):
            continue
        if not isinstance(table_data, dict):
            continue

        # Count non-metadata entries
        entries = [k for k in table_data.keys() if not k.startswith("__")]
        if len(entries) == 0 and table_path not in ("system global",):
            out.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity,
                confidence=rule.confidence, vdom=vdom,
                message=f'Table "{table_path}" is configured but has no entries.',
                evidence=[],
            ))

    return out


def rule_missing_end(
    *, model: ConfigModel, facts: Facts, vdom: str,
    rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
    """Detect config sections that may be missing 'end' markers.

    The parser handles this, but we can detect suspicious patterns
    where tables have entries but no fields set.
    """
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    for table_path, table_data in tables.items():
        if table_path.startswith("__"):
            continue
        if not isinstance(table_data, dict):
            continue

        for entry_name, entry_data in table_data.items():
            if entry_name.startswith("__"):
                continue
            if not isinstance(entry_data, Node):
                continue

            fields = entry_data.effective_fields()
            if len(fields) == 0:
                out.append(Finding(
                    rule_id=rule.id, title=rule.title, severity=rule.severity,
                    confidence=rule.confidence, vdom=vdom,
                    message=f'Entry "{entry_name}" in "{table_path}" has no fields set.',
                    evidence=[],
                ))

    return out


def rule_ip_address_format(
    *, model: ConfigModel, facts: Facts, vdom: str,
    rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
    """Detect malformed IP addresses in config fields.

    Common fields: dst, src, subnet, gateway, ip, server.
    """
    import re
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []
    ip_fields = {"dst", "src", "subnet", "gateway", "ip", "server", "remote-ip", "netmask"}
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

    for table_path, table_data in tables.items():
        if table_path.startswith("__"):
            continue
        if not isinstance(table_data, dict):
            continue

        for entry_name, entry_data in table_data.items():
            if entry_name.startswith("__"):
                continue
            if not isinstance(entry_data, Node):
                continue

            fields = entry_data.effective_fields()
            for field_name in ip_fields:
                if field_name in fields:
                    val = str(fields[field_name]).strip()
                    # Check for malformed IPs (like 192.168.1.256)
                    if ip_pattern.match(val):
                        parts = val.split(".")
                        for part in parts:
                            try:
                                if int(part) > 255:
                                    out.append(Finding(
                                        rule_id=rule.id, title=rule.title, severity=rule.severity,
                                        confidence=rule.confidence, vdom=vdom,
                                        message=f'Malformed IP address "{val}" in {field_name} (octet > 255).',
                                        evidence=[],
                                    ))
                                    break
                            except ValueError:
                                pass

    return out


def rule_port_range_format(
    *, model: ConfigModel, facts: Facts, vdom: str,
    rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
    """Detect invalid port numbers in service/port fields."""
    import re
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []
    port_fields = {"port", "dstport", "srcport", "start-port", "end-port"}

    for table_path, table_data in tables.items():
        if table_path.startswith("__"):
            continue
        if not isinstance(table_data, dict):
            continue

        for entry_name, entry_data in table_data.items():
            if entry_name.startswith("__"):
                continue
            if not isinstance(entry_data, Node):
                continue

            fields = entry_data.effective_fields()
            for field_name in port_fields:
                if field_name in fields:
                    val = str(fields[field_name]).strip()
                    try:
                        port = int(val)
                        if port < 0 or port > 65535:
                            out.append(Finding(
                                rule_id=rule.id, title=rule.title, severity=rule.severity,
                                confidence=rule.confidence, vdom=vdom,
                                message=f'Invalid port {port} in {field_name} (must be 0-65535).',
                                evidence=[],
                            ))
                    except ValueError:
                        pass

    return out
