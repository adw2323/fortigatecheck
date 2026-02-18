from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .model import ConfigModel, Node, Evidence, ParseWarning

@dataclass
class _Ctx:
    kind: str  # "config" or "edit"
    path: Tuple[str, ...]
    start_line: int

def _strip_comment(line: str) -> str:
    s = line.rstrip("\n")
    if s.lstrip().startswith("#"):
        return ""
    return s

def _tokenize(line: str) -> List[str]:
    out: List[str] = []
    buf: List[str] = []
    in_q = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == '"':
            in_q = not in_q
            i += 1
            continue
        if not in_q and ch.isspace():
            if buf:
                out.append("".join(buf))
                buf = []
            i += 1
            continue
        if in_q and ch == "\\" and i + 1 < len(line) and line[i + 1] == '"':
            buf.append('"')
            i += 2
            continue
        buf.append(ch)
        i += 1
    if buf:
        out.append("".join(buf))
    return out

def _ensure_table(root: Dict[str, Any], path: Tuple[str, ...]) -> Dict[str, Any]:
    node: Any = root
    for p in path:
        node = node.setdefault(p, {})
    if not isinstance(node, dict):
        return {}
    return node

def parse_fortios_text(conf_text: str, *, file_id: str = "config") -> tuple[ConfigModel, list[ParseWarning]]:
    lines = conf_text.splitlines(True)
    warnings: List[ParseWarning] = []

    model = ConfigModel(meta={"file_id": file_id})
    model.vdoms.setdefault("root", {})

    scope = "root"  # "root" or vdom name or "global"
    stack: List[_Ctx] = []

    current_table_path: Optional[Tuple[str, ...]] = None
    current_table: Optional[Dict[str, Any]] = None
    current_obj_key: Optional[str] = None
    current_obj: Optional[Node] = None

    # support singleton tables like "config system global" that use set without edit
    singleton_node: Optional[Node] = None

    for ln, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if stripped.startswith("#config-version"):
            model.meta.setdefault("header_lines", []).append((ln, stripped))

    def scope_root() -> Dict[str, Any]:
        return model.global_cfg if scope == "global" else model.vdoms.setdefault(scope, {})

    for line_no, raw in enumerate(lines, start=1):
        line = _strip_comment(raw)
        if not line.strip():
            continue

        tokens = _tokenize(line.strip())
        if not tokens:
            continue

        head = tokens[0].lower()

        if head == "config":
            # special scopes
            if len(tokens) >= 2 and tokens[1].lower() == "global":
                scope = "global"
                stack.append(_Ctx("config", ("global",), line_no))
                current_table_path = None
                current_table = None
                current_obj = None
                singleton_node = None
                continue

            if len(tokens) >= 2 and tokens[1].lower() == "vdom":
                stack.append(_Ctx("config", ("vdom",), line_no))
                current_table_path = None
                current_table = None
                current_obj = None
                singleton_node = None
                continue

            path = tuple(tokens[1:])
            stack.append(_Ctx("config", path, line_no))
            current_table_path = path
            current_table = _ensure_table(scope_root(), path)
            current_obj = None
            current_obj_key = None

            # if this table has no edit blocks, we store under a synthetic singleton node key
            singleton_node = None
            continue

        if head == "edit":
            key = " ".join(tokens[1:]).strip()
            # inside config vdom: edit <vdomname> changes scope
            if stack and stack[-1].kind == "config" and stack[-1].path == ("vdom",):
                scope = key or scope
                model.vdoms.setdefault(scope, {})
                stack.append(_Ctx("edit", ("vdom", key), line_no))
                current_table_path = None
                current_table = None
                current_obj = None
                singleton_node = None
                continue

            if current_table is None:
                warnings.append(ParseWarning("EDIT_OUTSIDE_TABLE", "edit outside config table", line_no))
                continue
            current_obj_key = key
            obj = current_table.get(key)
            if not isinstance(obj, Node):
                obj = Node()
                current_table[key] = obj
            current_obj = obj
            stack.append(_Ctx("edit", (key,), line_no))
            singleton_node = None
            continue

        if head in ("set", "unset"):
            if current_obj is None:
                # try singleton table mode
                if current_table is not None:
                    if singleton_node is None:
                        singleton_node = current_table.get("__singleton__")
                        if not isinstance(singleton_node, Node):
                            singleton_node = Node()
                            current_table["__singleton__"] = singleton_node
                    current_obj = singleton_node
                    current_obj_key = "__singleton__"
                else:
                    warnings.append(ParseWarning("SET_OUTSIDE_EDIT", f"{head} outside edit block", line_no))
                    continue

            if head == "unset":
                if len(tokens) < 2:
                    warnings.append(ParseWarning("UNSET_NO_KEY", "unset missing key", line_no))
                    continue
                k = tokens[1]
                current_obj.unsets.add(k)
                current_obj.evidence[f"unset:{k}"] = Evidence(
                    file_id=file_id,
                    line_range=(line_no, line_no),
                    path=("scope", scope, *(current_table_path or ()), current_obj_key or "", "unset", k),
                    raw_lines=[raw.rstrip("\n")],
                )
                continue

            if len(tokens) < 3:
                warnings.append(ParseWarning("SET_SHORT", "set missing key/value", line_no))
                continue
            k = tokens[1]
            v = tokens[2:]
            value: Any = v[0] if len(v) == 1 else v
            current_obj.fields[k] = value
            current_obj.evidence[f"set:{k}"] = Evidence(
                file_id=file_id,
                line_range=(line_no, line_no),
                path=("scope", scope, *(current_table_path or ()), current_obj_key or "", "set", k),
                raw_lines=[raw.rstrip("\n")],
            )
            continue

        if head == "next":
            # close edit unless we're in singleton mode
            if stack and stack[-1].kind == "edit":
                stack.pop()
            current_obj = None
            current_obj_key = None
            singleton_node = None
            continue

        if head == "end":
            if stack:
                ctx = stack.pop()
                if ctx.kind == "config" and ctx.path == ("global",):
                    scope = "root"
                # leaving config table
            current_table_path = None
            current_table = None
            current_obj = None
            current_obj_key = None
            singleton_node = None
            continue

        # unknown directive
        warnings.append(ParseWarning("UNKNOWN_LINE", f"Unrecognized directive: {tokens[0]}", line_no))

    return model, warnings
