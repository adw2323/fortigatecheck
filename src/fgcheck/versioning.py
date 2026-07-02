from __future__ import annotations

import re
from typing import Any

from .model import ConfigModel

# Supported FortiOS version families.  The schema loader (schema.py) resolves
# point-release versions (e.g. "8.0.0") to family directories (e.g. "8.0") via
# ``_version_candidates``, but versioning lives here so other callers can
# validate user-supplied versions against the set we ship data for.
SUPPORTED_VERSION_FAMILIES: tuple[str, ...] = ("7.4", "7.6", "8.0")

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _extract_header_fortios_version(header_line: str) -> str | None:
    match = _VERSION_RE.search(header_line)
    if not match:
        return None
    return match.group(1)


def _header_lines(meta: dict[str, Any]) -> list[str]:
    lines = meta.get("header_lines", [])
    out: list[str] = []
    if isinstance(lines, list):
        for item in lines:
            if isinstance(item, tuple) and len(item) >= 2:
                out.append(str(item[1]))
            elif isinstance(item, str):
                out.append(item)
    return out


def resolve_target_fortios(model: ConfigModel, *, explicit_version: str | None) -> tuple[str, list[str]]:
    warnings: list[str] = []

    for header in _header_lines(model.meta):
        parsed = _extract_header_fortios_version(header)
        if parsed:
            return parsed, warnings

    if explicit_version:
        return explicit_version, warnings

    warnings.append("version_defaulted")
    return SUPPORTED_VERSION_FAMILIES[0], warnings
