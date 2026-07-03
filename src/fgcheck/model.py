from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple, Union

Path = Tuple[Union[str, int], ...]
LineRange = Tuple[int, int]

@dataclass(frozen=True)
class Evidence:
    file_id: str
    line_range: LineRange
    path: Path
    raw_lines: List[str] = field(default_factory=list)

@dataclass
class Node:
    fields: Dict[str, Any] = field(default_factory=dict)
    unsets: set[str] = field(default_factory=set)
    evidence: Dict[str, Evidence] = field(default_factory=dict)

    def effective_fields(self) -> Dict[str, Any]:
        """Return fields minus any that were explicitly unset."""
        return {k: v for k, v in self.fields.items() if k not in self.unsets}

@dataclass
class ConfigModel:
    meta: Dict[str, Any] = field(default_factory=dict)
    global_cfg: Dict[str, Any] = field(default_factory=dict)
    vdoms: Dict[str, Dict[str, Any]] = field(default_factory=dict)

@dataclass(frozen=True)
class ParseWarning:
    code: str
    message: str
    line_no: int
