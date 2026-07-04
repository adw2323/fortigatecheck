"""Config diff utility for comparing two FortiGate configurations.

Compares two parsed configs and shows what changed, including:
- Added/removed tables
- Added/removed entries within tables
- Changed field values
- Security impact assessment
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import ConfigModel, Node


@dataclass
class DiffChange:
    """A single change between two configs."""
    change_type: str  # "added", "removed", "changed"
    path: str  # e.g., "firewall policy/edit 1/action"
    old_value: str | None = None
    new_value: str | None = None
    severity: str = "info"  # "critical", "high", "medium", "low", "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_type": self.change_type,
            "path": self.path,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "severity": self.severity,
        }


@dataclass
class ConfigDiff:
    """Result of comparing two configs."""
    changes: list[DiffChange] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "changes": [c.to_dict() for c in self.changes],
            "summary": self.summary,
            "total_changes": len(self.changes),
        }


# Security-sensitive fields that need attention
SECURITY_FIELDS = {
    "action", "allowaccess", "srcaddr", "dstaddr", "service",
    "utm-status", "ssl-ssh-profile", "ips-sensor", "av-profile",
    "webfilter-profile", "dlp-sensor", "admin-password", "cluster-key",
    "certificate", "private-key", "secret", "auth-passwd",
}


def _classify_severity(field_name: str, old_val: str, new_val: str) -> str:
    """Classify the security impact of a field change."""
    field_lower = field_name.lower()

    if field_lower in ("action", "utm-status", "allowaccess"):
        return "high"
    if field_lower in ("srcaddr", "dstaddr", "service") and new_val == "all":
        return "high"
    if field_lower in ("admin-password", "cluster-key", "secret", "auth-passwd"):
        return "critical"
    if field_lower in ("certificate", "private-key"):
        return "critical"
    if field_lower in SECURITY_FIELDS:
        return "medium"
    if "proto" in field_lower or "encrypt" in field_lower or "cipher" in field_lower:
        return "high"
    return "info"


def _diff_tables(
    old_tables: dict[str, Any],
    new_tables: dict[str, Any],
    prefix: str,
) -> list[DiffChange]:
    """Compare two sets of tables and return changes."""
    changes: list[DiffChange] = []

    all_keys = set(list(old_tables.keys()) + list(new_tables.keys()))
    for key in all_keys:
        if key.startswith("__"):
            continue
        path = f"{prefix}/{key}" if prefix else str(key)

        old_val = old_tables.get(key)
        new_val = new_tables.get(key)

        if old_val is None and new_val is not None:
            changes.append(DiffChange(
                change_type="added", path=path,
                new_value=str(type(new_val).__name__),
                severity="info",
            ))
        elif old_val is not None and new_val is None:
            changes.append(DiffChange(
                change_type="removed", path=path,
                old_value=str(type(old_val).__name__),
                severity="info",
            ))
        elif isinstance(old_val, dict) and isinstance(new_val, dict):
            changes.extend(_diff_tables(old_val, new_val, path))
        elif isinstance(old_val, Node) and isinstance(new_val, Node):
            changes.extend(_diff_nodes(old_val, new_val, path))
        elif old_val != new_val:
            severity = _classify_severity(key, str(old_val), str(new_val))
            changes.append(DiffChange(
                change_type="changed", path=path,
                old_value=str(old_val), new_value=str(new_val),
                severity=severity,
            ))

    return changes


def _diff_nodes(
    old_node: Node,
    new_node: Node,
    prefix: str,
) -> list[DiffChange]:
    """Compare two nodes and return field-level changes."""
    changes: list[DiffChange] = []

    all_fields = set(list(old_node.fields.keys()) + list(new_node.fields.keys()))
    for field_name in all_fields:
        if field_name.startswith("__"):
            continue
        path = f"{prefix}/{field_name}"

        old_val = old_node.fields.get(field_name)
        new_val = new_node.fields.get(field_name)

        if old_val is None and new_val is not None:
            changes.append(DiffChange(
                change_type="added", path=path,
                new_value=str(new_val),
                severity=_classify_severity(field_name, "", str(new_val)),
            ))
        elif old_val is not None and new_val is None:
            changes.append(DiffChange(
                change_type="removed", path=path,
                old_value=str(old_val),
                severity=_classify_severity(field_name, str(old_val), ""),
            ))
        elif str(old_val) != str(new_val):
            severity = _classify_severity(field_name, str(old_val), str(new_val))
            changes.append(DiffChange(
                change_type="changed", path=path,
                old_value=str(old_val), new_value=str(new_val),
                severity=severity,
            ))

    return changes


def diff_configs(
    old_config: ConfigModel,
    new_config: ConfigModel,
) -> ConfigDiff:
    """Compare two parsed FortiGate configurations.

    Returns a ConfigDiff with all changes and a summary by severity.
    """
    changes: list[DiffChange] = []

    # Compare global config
    changes.extend(_diff_tables(
        old_config.global_cfg, new_config.global_cfg, "global"
    ))

    # Compare VDOMs
    all_vdoms = set(list(old_config.vdoms.keys()) + list(new_config.vdoms.keys()))
    for vdom in all_vdoms:
        old_vdom = old_config.vdoms.get(vdom, {})
        new_vdom = new_config.vdoms.get(vdom, {})
        changes.extend(_diff_tables(old_vdom, new_vdom, f"vdom/{vdom}"))

    # Build summary
    summary: dict[str, int] = {}
    for change in changes:
        summary[change.severity] = summary.get(change.severity, 0) + 1

    return ConfigDiff(changes=changes, summary=summary)


def diff_configs_from_text(
    old_text: str,
    new_text: str,
) -> ConfigDiff:
    """Compare two raw config texts."""
    from .parse import parse_fortios_text

    old_model, _ = parse_fortios_text(old_text, file_id="old")
    new_model, _ = parse_fortios_text(new_text, file_id="new")

    return diff_configs(old_model, new_model)
