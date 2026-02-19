from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


def _normalize_table_key(path: str | Iterable[str]) -> str:
    if isinstance(path, str):
        if "/" in path:
            parts = [p.strip() for p in path.split("/") if p.strip()]
        else:
            parts = [p.strip() for p in path.split() if p.strip()]
    else:
        parts = [str(p).strip() for p in path if str(p).strip()]
    return " ".join(parts).lower()


def _version_candidates(version: str) -> list[str]:
    v = version.strip()
    if not v:
        return []
    parts = v.split(".")
    candidates = [v]
    if len(parts) >= 2:
        family = ".".join(parts[:2])
        if family not in candidates:
            candidates.append(family)
    return candidates


@dataclass
class SchemaView:
    requested_version: str
    resolved_version: str | None = None
    loaded: bool = False
    partial: bool = False
    warnings: list[str] = field(default_factory=list)
    _tables: dict[str, Any] = field(default_factory=dict)

    def has_table(self, path: str | Iterable[str]) -> bool:
        key = _normalize_table_key(path)
        return key in self._tables

    def has_field(self, table: str | Iterable[str], field: str) -> bool:
        tkey = _normalize_table_key(table)
        fkey = field.strip().lower()
        table_obj = self._tables.get(tkey, {})
        fields = table_obj.get("fields", {}) if isinstance(table_obj, dict) else {}
        return fkey in fields

    def allowed_values(self, table: str | Iterable[str], field: str) -> set[str] | None:
        tkey = _normalize_table_key(table)
        fkey = field.strip().lower()
        table_obj = self._tables.get(tkey, {})
        fields = table_obj.get("fields", {}) if isinstance(table_obj, dict) else {}
        field_obj = fields.get(fkey, {}) if isinstance(fields, dict) else {}
        if not isinstance(field_obj, dict):
            return None
        values = field_obj.get("allowed_values")
        if values is None:
            return None
        if not isinstance(values, list):
            return None
        return {str(v) for v in values}


def load_schema(version: str, *, base_dir: str | Path = ".") -> SchemaView:
    view = SchemaView(requested_version=version)
    root = Path(base_dir)
    schema_root = root / "docs" / "derived" / "schema"

    for candidate in _version_candidates(version):
        schema_file = schema_root / candidate / "schema.json"
        if not schema_file.exists():
            continue

        raw = json.loads(schema_file.read_text(encoding="utf-8"))
        tables = raw.get("tables", {}) if isinstance(raw, dict) else {}
        coverage = raw.get("coverage") if isinstance(raw, dict) else None
        normalized: dict[str, Any] = {}
        if isinstance(tables, dict):
            for table_name, table_obj in tables.items():
                normalized[_normalize_table_key(str(table_name))] = table_obj

        if not normalized:
            view.resolved_version = candidate
            view.loaded = False
            view.warnings.append("schema_unknown")
            return view

        view.resolved_version = candidate
        view.loaded = True
        view.partial = coverage == "table_only"
        view._tables = normalized
        return view

    view.warnings.append("schema_unknown")
    return view
