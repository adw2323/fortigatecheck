from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .schema import load_schema

VALIDATED = "VALIDATED"
PARTIALLY_VALIDATED = "PARTIALLY_VALIDATED"
UNKNOWN = "UNKNOWN"


def _normalize_query(value: str | Iterable[str]) -> str:
    if isinstance(value, str):
        parts = value.replace("/", " ").split()
    else:
        parts = [str(p) for p in value]
    if parts and parts[0].lower() == "config":
        parts = parts[1:]
    return " ".join(p.strip().lower() for p in parts if p.strip())


@dataclass
class AuthorityResult:
    query: str
    fortios_version: str
    resolved_version: str | None
    validation_result: str
    coverage_level: str
    confidence_level: str
    matched_table: str | None = None
    matched_command: str | None = None
    matched_field: str | None = None
    known_fields: list[str] | None = None
    allowed_values: list[str] | None = None
    source_url: str | None = None
    warnings: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "fortios_version": self.fortios_version,
            "resolved_version": self.resolved_version,
            "matched_table": self.matched_table,
            "matched_command": self.matched_command,
            "matched_field": self.matched_field,
            "known_fields": self.known_fields or [],
            "allowed_values": self.allowed_values or [],
            "source_url": self.source_url,
            "coverage_level": self.coverage_level,
            "confidence_level": self.confidence_level,
            "validation_result": self.validation_result,
            "warnings": self.warnings or [],
        }


def _table_result(query: str, fortios: str, schema: Any, table_name: str, table_obj: dict[str, Any]) -> AuthorityResult:
    fields = table_obj.get("fields", {}) if isinstance(table_obj, dict) else {}
    known_fields = sorted(str(k) for k in fields.keys()) if isinstance(fields, dict) else []
    source_url = table_obj.get("source_url") if isinstance(table_obj, dict) else None
    if known_fields:
        validation_result = VALIDATED
        coverage_level = "table_and_fields"
        confidence_level = "high"
    elif source_url:
        validation_result = PARTIALLY_VALIDATED
        coverage_level = "table_only"
        confidence_level = "medium"
    else:
        validation_result = PARTIALLY_VALIDATED
        coverage_level = "table_only_no_source"
        confidence_level = "low"
    return AuthorityResult(
        query=query,
        fortios_version=fortios,
        resolved_version=schema.resolved_version,
        validation_result=validation_result,
        coverage_level=coverage_level,
        confidence_level=confidence_level,
        matched_table=table_name,
        matched_command=f"config {table_name}",
        known_fields=known_fields,
        source_url=source_url,
        warnings=list(schema.warnings),
    )


def _field_result(
    query: str,
    fortios: str,
    schema: Any,
    table_name: str,
    table_obj: dict[str, Any],
    field_name: str,
    field_obj: dict[str, Any],
) -> AuthorityResult:
    allowed = field_obj.get("allowed_values") if isinstance(field_obj, dict) else None
    values = sorted(str(v) for v in allowed) if isinstance(allowed, list) else []
    source_url = table_obj.get("source_url") if isinstance(table_obj, dict) else None
    return AuthorityResult(
        query=query,
        fortios_version=fortios,
        resolved_version=schema.resolved_version,
        validation_result=VALIDATED,
        coverage_level="field" if not values else "field_and_allowed_values",
        confidence_level="high",
        matched_table=table_name,
        matched_command=f"config {table_name}",
        matched_field=field_name,
        known_fields=sorted(str(k) for k in table_obj.get("fields", {}).keys()),
        allowed_values=values,
        source_url=source_url,
        warnings=list(schema.warnings),
    )


def lookup_authority(query: str, *, fortios: str = "7.6", base_dir: str | Path = ".") -> AuthorityResult:
    schema = load_schema(fortios, base_dir=base_dir)
    normalized = _normalize_query(query)
    if not schema.loaded:
        return AuthorityResult(
            query=query,
            fortios_version=fortios,
            resolved_version=schema.resolved_version,
            validation_result=UNKNOWN,
            coverage_level="none",
            confidence_level="none",
            warnings=list(schema.warnings) + ["schema_not_loaded"],
        )

    tables: dict[str, Any] = getattr(schema, "_tables", {})
    if normalized in tables:
        return _table_result(query, fortios, schema, normalized, tables[normalized])

    field_matches: list[tuple[str, dict[str, Any], str, dict[str, Any]]] = []
    table_contains: list[tuple[str, dict[str, Any]]] = []
    for table_name, table_obj_any in tables.items():
        table_obj = table_obj_any if isinstance(table_obj_any, dict) else {}
        if normalized and normalized in table_name:
            table_contains.append((table_name, table_obj))
        fields = table_obj.get("fields", {})
        if not isinstance(fields, dict):
            continue
        if normalized in fields:
            field_obj = fields[normalized] if isinstance(fields[normalized], dict) else {}
            field_matches.append((table_name, table_obj, normalized, field_obj))

    if len(field_matches) == 1:
        table_name, table_obj, field_name, field_obj = field_matches[0]
        return _field_result(query, fortios, schema, table_name, table_obj, field_name, field_obj)

    if len(field_matches) > 1:
        table_name, table_obj, field_name, field_obj = field_matches[0]
        result = _field_result(query, fortios, schema, table_name, table_obj, field_name, field_obj)
        result.validation_result = PARTIALLY_VALIDATED
        result.confidence_level = "medium"
        result.warnings = (result.warnings or []) + [
            "ambiguous_field_match",
            "matching_tables=" + ",".join(t[0] for t in field_matches[:25]),
        ]
        return result

    if len(table_contains) == 1:
        table_name, table_obj = table_contains[0]
        result = _table_result(query, fortios, schema, table_name, table_obj)
        result.warnings = (result.warnings or []) + ["partial_table_name_match"]
        return result

    if len(table_contains) > 1:
        table_name, table_obj = table_contains[0]
        result = _table_result(query, fortios, schema, table_name, table_obj)
        result.validation_result = PARTIALLY_VALIDATED
        result.confidence_level = "medium"
        result.warnings = (result.warnings or []) + [
            "ambiguous_table_match",
            "matching_tables=" + ",".join(t[0] for t in table_contains[:25]),
        ]
        return result

    return AuthorityResult(
        query=query,
        fortios_version=fortios,
        resolved_version=schema.resolved_version,
        validation_result=UNKNOWN,
        coverage_level="none",
        confidence_level="none",
        warnings=list(schema.warnings) + ["no_schema_match"],
    )


def render_authority_json(result: AuthorityResult) -> str:
    return json.dumps(result.to_dict(), indent=2) + "\n"


def render_authority_human(result: AuthorityResult) -> str:
    data = result.to_dict()
    lines = [
        f"Query: {data['query']}",
        f"FortiOS: {data['fortios_version']} (resolved: {data['resolved_version'] or 'none'})",
        f"Validation: {data['validation_result']}",
        f"Coverage: {data['coverage_level']}",
        f"Confidence: {data['confidence_level']}",
    ]
    if data["matched_command"]:
        lines.append(f"Command: {data['matched_command']}")
    if data["matched_field"]:
        lines.append(f"Field: {data['matched_field']}")
    if data["allowed_values"]:
        lines.append("Allowed values: " + ", ".join(data["allowed_values"]))
    if data["source_url"]:
        lines.append(f"Source: {data['source_url']}")
    if data["warnings"]:
        lines.append("Warnings: " + "; ".join(data["warnings"]))
    return "\n".join(lines) + "\n"
