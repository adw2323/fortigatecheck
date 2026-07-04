from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

Path = tuple[str | int, ...]
LineRange = tuple[int, int]

@dataclass(frozen=True)
class Evidence:
    file_id: str
    line_range: LineRange
    path: Path
    raw_lines: list[str] = field(default_factory=list)

@dataclass
class Node:
    fields: dict[str, Any] = field(default_factory=dict)
    unsets: set[str] = field(default_factory=set)
    evidence: dict[str, Evidence] = field(default_factory=dict)

    def effective_fields(self) -> dict[str, Any]:
        """Return fields minus any that were explicitly unset."""
        return {k: v for k, v in self.fields.items() if k not in self.unsets}

@dataclass
class ConfigModel:
    meta: dict[str, Any] = field(default_factory=dict)
    global_cfg: dict[str, Any] = field(default_factory=dict)
    vdoms: dict[str, dict[str, Any]] = field(default_factory=dict)

@dataclass(frozen=True)
class ParseWarning:
    code: str
    message: str
    line_no: int
