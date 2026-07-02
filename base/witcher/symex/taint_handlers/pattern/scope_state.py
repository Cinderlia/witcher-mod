import re
from typing import List, Optional

from taint_handlers.llm.core.llm_response import _norm_llm_name


_GLOBAL_DECL_RE = re.compile(r"^\s*global\s+(.+?);\s*$", re.IGNORECASE)
_VAR_RE = re.compile(r"\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*")


def record_scope_observations(current: dict, scope_locs: list, scope_source_lines: List[dict], ctx: dict) -> None:
    _append_scope_locs(ctx, scope_locs)
    _record_global_declarations(scope_source_lines, ctx)


def is_declared_global_taint(item: dict, ctx: dict) -> bool:
    if not isinstance(item, dict) or not isinstance(ctx, dict):
        return False
    if (item.get("type") or "").strip() != "AST_VAR":
        return False
    global_names = ctx.setdefault("pattern_global_names", set())
    name = _norm_var_name(item.get("name") or "")
    return bool(name and name in global_names)


def defer_global_taint(item: dict, ctx: dict) -> bool:
    if not isinstance(item, dict) or not isinstance(ctx, dict):
        return False
    pending = ctx.setdefault("pattern_pending_globals", [])
    seen = ctx.setdefault("pattern_pending_global_seen", set())
    key = _taint_key(item)
    if key in seen:
        return False
    seen.add(key)
    pending.append(dict(item))
    return True


def pop_deferred_global_taints(ctx: dict) -> List[dict]:
    if not isinstance(ctx, dict):
        return []
    out = list(ctx.get("pattern_pending_globals") or [])
    ctx["pattern_pending_globals"] = []
    ctx["pattern_pending_global_seen"] = set()
    return out


def all_scope_locs(ctx: dict) -> list:
    if not isinstance(ctx, dict):
        return []
    return list(ctx.get("pattern_all_scope_locs") or [])


def _append_scope_locs(ctx: dict, scope_locs: list) -> None:
    all_locs = ctx.setdefault("pattern_all_scope_locs", [])
    seen = ctx.setdefault("pattern_all_scope_seen", set())
    for item in scope_locs or []:
        key = _loc_key(item)
        if not key or key in seen:
            continue
        seen.add(key)
        all_locs.append(item)
def _record_global_declarations(scope_source_lines: List[dict], ctx: dict) -> None:
    global_names = ctx.setdefault("pattern_global_names", set())
    for item in scope_source_lines or []:
        if not isinstance(item, dict):
            continue
        code = (item.get("code") or "").strip()
        m = _GLOBAL_DECL_RE.match(code)
        if not m:
            continue
        for name in _VAR_RE.findall(m.group(1) or ""):
            norm = _norm_var_name(name)
            if norm:
                global_names.add(norm)


def _norm_var_name(name: str) -> str:
    raw = (name or "").replace(".", "->").strip()
    if not raw:
        return ""
    return _norm_llm_name(raw)


def _loc_key(item) -> Optional[object]:
    if not item:
        return None
    if isinstance(item, dict):
        loc = (item.get("loc") or "").strip()
        path = (item.get("path") or "").strip()
        line = item.get("line")
        source_only = bool(item.get("source_only"))
        if not loc and path and line is not None:
            try:
                loc = f"{path}:{int(line)}"
            except Exception:
                loc = ""
        seq = item.get("seq")
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        return (loc, seq_i, source_only) if loc else None
    if isinstance(item, str):
        return item
    return None


def _taint_key(item: dict) -> tuple:
    try:
        return (
            int(item.get("id")) if item.get("id") is not None else None,
            int(item.get("seq")) if item.get("seq") is not None else None,
            (item.get("type") or "").strip(),
            _norm_var_name(item.get("name") or ""),
        )
    except Exception:
        return (
            item.get("id"),
            item.get("seq"),
            item.get("type"),
            item.get("name"),
        )
