from __future__ import annotations
from typing import Any, List

def as_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, str):
        return [x]
    if isinstance(x, list):
        return [str(i) for i in x]
    return [str(x)]
