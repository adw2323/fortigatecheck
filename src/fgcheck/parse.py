from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .model import ConfigModel, Evidence, Node, ParseWarning


@dataclass
class _Ctx:
    kind: str  # "config" or "edit"
    path: tuple[str, ...]
    start_line: int
    prev_scope: str | None = None


@dataclass
class _PendingSet:
    key: str
    start_line: int
    table_path: tuple[str, ...] | None
    obj_key: str | None
    node: Node
    values: list[str]
    raw_lines: list[str]


def _strip_comment(line: str) -> str:
    """Strip full-line comments and inline comments (first unquoted ``#``)."""
    s = line.rstrip("\n")
    if s.lstrip().startswith("#"):
        return ""
    # Find the first unquoted '#' and truncate there
    in_quote = False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and in_quote and i + 1 < len(s) and s[i + 1] == '"':
            i += 2  # skip escaped quote inside a quoted string
            continue
        if ch == '"':
            in_quote = not in_quote
        elif ch == "#" and not in_quote:
            return s[:i].rstrip()
        i += 1
    return s


def _tokenize(line: str) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
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


def _count_unescaped_quotes(line: str) -> int:
    count = 0
    i = 0
    while i < len(line):
        if line[i] == "\\":
            i += 2
            continue
        if line[i] == '"':
            count += 1
        i += 1
    return count


def _has_unclosed_quote(line: str) -> bool:
    return _count_unescaped_quotes(line) % 2 == 1


def _first_unescaped_quote_index(line: str) -> int:
    i = 0
    while i < len(line):
        if line[i] == "\\":
            i += 2
            continue
        if line[i] == '"':
            return i
        i += 1
    return -1


def _ensure_table(root: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    node: Any = root
    for p in path:
        node = node.setdefault(p, {})
    if not isinstance(node, dict):
        return {}
    return node


def parse_fortios_text(conf_text: str, *, file_id: str = "config") -> tuple[ConfigModel, list[ParseWarning]]:
    lines = conf_text.splitlines(True)
    warnings: list[ParseWarning] = []

    model = ConfigModel(meta={"file_id": file_id})
    model.vdoms.setdefault("root", {})

    scope = "root"  # "root" or vdom name or "global"
    stack: list[_Ctx] = []

    current_table_path: tuple[str, ...] | None = None
    current_table: dict[str, Any] | None = None
    current_obj_key: str | None = None
    current_obj: Node | None = None

    # support singleton tables like "config system global" that use set without edit
    singleton_node: Node | None = None
    pending_set: _PendingSet | None = None

    for ln, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if stripped.startswith("#config-version"):
            model.meta.setdefault("header_lines", []).append((ln, stripped))
            # Detect FortiManager-managed configs by checking for FMGR
            # markers in the config-version header.
            if "FMGR" in stripped.upper() or "FORTIMANAGER" in stripped.upper():
                model.meta["fortimanager_config"] = True
                # Also detect workspace mode
                if "WORKSPACE" in stripped.upper():
                    model.meta["fmg_workspace_mode"] = True

    def scope_root() -> dict[str, Any]:
        return model.global_cfg if scope == "global" else model.vdoms.setdefault(scope, {})

    def top_config_table_path() -> tuple[str, ...] | None:
        for ctx in reversed(stack):
            if ctx.kind != "config":
                continue
            if ctx.path in (("global",), ("vdom",)):
                continue
            return ctx.path
        return None

    def refresh_table_context() -> None:
        nonlocal current_table_path, current_table
        path = top_config_table_path()
        if path is None:
            current_table_path = None
            current_table = None
            return
        current_table_path = path
        current_table = _ensure_table(scope_root(), path)

    for line_no, raw in enumerate(lines, start=1):
        line = _strip_comment(raw)
        if not line.strip():
            continue

        if pending_set is not None:
            pending_set.raw_lines.append(raw.rstrip("\n"))
            stripped_line = line.strip()
            quote_idx = _first_unescaped_quote_index(stripped_line)
            if quote_idx >= 0:
                pending_set.values.append(stripped_line[:quote_idx])
                pending_set.node.fields[pending_set.key] = pending_set.values
                pending_set.node.evidence[f"set:{pending_set.key}"] = Evidence(
                    file_id=file_id,
                    line_range=(pending_set.start_line, line_no),
                    path=(
                        "scope",
                        scope,
                        *(pending_set.table_path or ()),
                        pending_set.obj_key or "",
                        "set",
                        pending_set.key,
                    ),
                    raw_lines=pending_set.raw_lines,
                )
                pending_set = None
            else:
                pending_set.values.append(stripped_line)
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

            rel_path = tuple(tokens[1:])
            parent_path: tuple[str, ...] | None = None
            if stack and stack[-1].kind == "config" and stack[-1].path not in (("global",), ("vdom",)):
                parent_path = stack[-1].path

            full_path = (*parent_path, *rel_path) if parent_path is not None else rel_path
            stack.append(_Ctx("config", full_path, line_no))
            current_table_path = full_path
            current_table = _ensure_table(scope_root(), full_path)
            current_obj = None
            current_obj_key = None

            # if this table has no edit blocks, we store under a synthetic singleton node key
            singleton_node = None
            continue

        if head == "edit":
            key = " ".join(tokens[1:]).strip()
            # inside config vdom: edit <vdomname> changes scope
            if stack and stack[-1].kind == "config" and stack[-1].path == ("vdom",):
                prev_scope = scope
                scope = key or scope
                model.vdoms.setdefault(scope, {})
                stack.append(_Ctx("edit", ("vdom", key), line_no, prev_scope=prev_scope))
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
            if _has_unclosed_quote(line):
                pending_set = _PendingSet(
                    key=k,
                    start_line=line_no,
                    table_path=current_table_path,
                    obj_key=current_obj_key,
                    node=current_obj,
                    values=[" ".join(v)],
                    raw_lines=[raw.rstrip("\n")],
                )
                continue
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
                ctx = stack.pop()
                if ctx.path and ctx.path[0] == "vdom":
                    scope = ctx.prev_scope or "root"
            current_obj = None
            current_obj_key = None
            singleton_node = None
            continue

        if head == "end":
            if stack:
                ctx = stack.pop()
                if ctx.kind == "config" and ctx.path == ("global",):
                    scope = "root"
                if ctx.kind == "config" and ctx.path == ("vdom",):
                    scope = "root"
                # leaving config table
            refresh_table_context()
            current_obj = None
            current_obj_key = None
            singleton_node = None
            continue

        # unknown directive
        warnings.append(ParseWarning("UNKNOWN_LINE", f"Unrecognized directive: {tokens[0]}", line_no))

    return model, warnings
