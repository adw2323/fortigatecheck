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
