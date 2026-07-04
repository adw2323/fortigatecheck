from __future__ import annotations

from typing import Any


def as_list(x: Any) -> list[str]:
    if x is None:
        return []
    if isinstance(x, str):
        return [x]
    if isinstance(x, list):
        return [str(i) for i in x]
    return [str(x)]
