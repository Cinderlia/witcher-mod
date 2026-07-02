import re
from typing import Dict, List, Optional, Set, Tuple


_FUNC_NAME_RE = re.compile(r"\bfunction\s+&?\s*([A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)", re.IGNORECASE)
_DECL_TYPES = {"AST_FUNC_DECL", "AST_METHOD", "AST_CLOSURE"}


def structure_mapped_context(mapped: list, nodes: dict, parent_of: dict, top_id_to_file: dict) -> List[dict]:
    items = []
    for idx, it in enumerate(mapped or []):
        if not isinstance(it, dict):
            continue
        items.append({"_idx": int(idx), **it})
    if not items:
        return list(mapped or [])

    loc_to_func = _build_loc_to_funcid(items, nodes, parent_of, top_id_to_file)
    for it in items:
        loc = _loc_key(it)
        it["_funcid"] = loc_to_func.get(loc)

    global_items = [it for it in items if it.get("_funcid") is None]
    func_groups = {}
    for it in items:
        fid = it.get("_funcid")
        if fid is None:
            continue
        func_groups.setdefault(int(fid), []).append(it)

    blocks = []
    global_remaining = list(global_items)
    global_used = set()
    for fid, group in func_groups.items():
        decl = _pick_decl_line(group)
        func_name = _func_name_from_code((decl.get("code") if isinstance(decl, dict) else "") or "")
        callsites = _pick_callsites(global_remaining, func_name, used=global_used) if func_name else []
        body = [it for it in group if it is not decl]
        body.sort(key=lambda x: (_sort_seq_key(x.get("seq")), x.get("_idx", 0)))
        decl_seq = _sort_seq_key(decl.get("seq")) if isinstance(decl, dict) else 10**9
        call_min = min((x.get("_idx", 10**9) for x in callsites), default=10**9)
        block_idx = min(call_min, int(decl.get("_idx", 10**9))) if isinstance(decl, dict) else call_min
        blocks.append(
            {
                "_idx": int(block_idx),
                "callsites": callsites,
                "decl": decl,
                "body": body,
                "func_name": func_name,
                "funcid": int(fid),
                "decl_seq_key": decl_seq,
            }
        )

    global_filtered = [it for it in global_remaining if it.get("_idx") not in global_used]
    global_filtered.sort(key=lambda x: int(x.get("_idx", 0)))
    blocks.sort(key=lambda b: int(b.get("_idx", 10**9)))

    out = []
    gi = 0
    bi = 0
    while gi < len(global_filtered) or bi < len(blocks):
        next_g = global_filtered[gi] if gi < len(global_filtered) else None
        next_b = blocks[bi] if bi < len(blocks) else None
        if next_b is not None and (next_g is None or int(next_b.get("_idx", 10**9)) <= int(next_g.get("_idx", 10**9))):
            out.extend(_emit_block(next_b))
            bi += 1
            continue
        if next_g is not None:
            out.append(_strip_meta(next_g))
            gi += 1
            continue
    out_keys = {_item_key(x) for x in out if isinstance(x, dict)}
    missing = []
    for it in items:
        k = _item_key(_strip_meta(it))
        if k not in out_keys:
            missing.append(_strip_meta(it))
            out_keys.add(k)
    if missing:
        out.extend(missing)
    if _has_decl(items) and not _has_decl(out):
        out = _fallback_function_block(items)
    return out


def _emit_block(block: dict) -> List[dict]:
    out = []
    for it in block.get("callsites") or []:
        out.append(_strip_meta(it))
    decl = block.get("decl")
    decl_is_func = isinstance(decl, dict) and ("function" in ((decl.get("code") or "").lower()))
    body_items = [it for it in (block.get("body") or []) if isinstance(it, dict)]
    if isinstance(decl, dict):
        out.append(_strip_meta(decl))
    if decl_is_func and body_items:
        out.append({"seq": None, "path": "", "line": None, "code": "{"})
        for it in body_items:
            out.append(_strip_meta(it))
        out.append({"seq": None, "path": "", "line": None, "code": "}"})
    else:
        for it in body_items:
            out.append(_strip_meta(it))
    return out


def _strip_meta(it: dict) -> dict:
    out = dict(it)
    out.pop("_idx", None)
    out.pop("_funcid", None)
    return out


def _item_key(it: dict) -> tuple:
    if not isinstance(it, dict):
        return (None,)
    return (
        it.get("seq"),
        (it.get("path") or "").strip(),
        it.get("line"),
        (it.get("code") or "").strip(),
    )


def _has_decl(buf: list) -> bool:
    for it in buf or []:
        if not isinstance(it, dict):
            continue
        if "function" in ((it.get("code") or "").lower()):
            return True
    return False


def _fallback_function_block(items: List[dict]) -> List[dict]:
    src = [_strip_meta(x) for x in items or []]
    call_lines = []
    decl_lines = []
    body = []
    for it in src:
        code = (it.get("code") or "").strip()
        if "function" in code.lower():
            decl_lines.append(it)
            continue
        if ("::" in code or "->" in code) and "(" in code:
            call_lines.append(it)
            continue
        body.append(it)
    out = []
    out.extend(call_lines)
    out.extend(decl_lines)
    out.append({"seq": None, "path": "", "line": None, "code": "{"})
    out.extend(body)
    out.append({"seq": None, "path": "", "line": None, "code": "}"})
    return out


def _pick_decl_line(group: List[dict]) -> dict:
    decls = []
    for it in group or []:
        code = (it.get("code") or "").strip()
        if "function" in code:
            decls.append(it)
    if decls:
        decls.sort(key=lambda x: (_sort_seq_key(x.get("seq")), int(x.get("_idx", 0))))
        return decls[0]
    group2 = list(group or [])
    group2.sort(key=lambda x: (_sort_seq_key(x.get("seq")), int(x.get("_idx", 0))))
    return group2[0] if group2 else {}


def _pick_callsites(global_items: List[dict], func_name: str, *, used: Set) -> List[dict]:
    hits = []
    if not func_name:
        return hits
    pat = re.compile(rf"(?i)(->|::)?{re.escape(func_name)}\s*\(")
    for it in global_items or []:
        idx = it.get("_idx")
        if idx in used:
            continue
        code = (it.get("code") or "")
        if pat.search(code):
            hits.append(it)
            used.add(idx)
    hits.sort(key=lambda x: int(x.get("_idx", 0)))
    return hits


def _func_name_from_code(code: str) -> str:
    m = _FUNC_NAME_RE.search(code or "")
    return (m.group(1) or "").strip() if m else ""


def _loc_key(it: dict) -> Optional[tuple]:
    path = (it.get("path") or "").strip()
    line = it.get("line")
    if not path or line is None:
        return None
    try:
        return (path, int(line))
    except Exception:
        return None


def _sort_seq_key(seq) -> int:
    try:
        return int(seq) if seq is not None else 10**9
    except Exception:
        return 10**9


def _build_loc_to_funcid(items: List[dict], nodes: dict, parent_of: dict, top_id_to_file: dict) -> Dict[tuple, int]:
    by_loc = {}
    for nid, nx in (nodes or {}).items():
        try:
            nid_i = int(nid)
        except Exception:
            continue
        line = nx.get("lineno")
        if line is None:
            continue
        try:
            line_i = int(line)
        except Exception:
            continue
        path = _node_path(nid_i, nodes, parent_of, top_id_to_file)
        if not path:
            continue
        by_loc.setdefault((path, line_i), []).append(nid_i)

    out = {}
    for it in items or []:
        lk = _loc_key(it)
        if lk is None:
            continue
        ids = by_loc.get(lk) or []
        fid = None
        for nid_i in ids:
            nx = nodes.get(nid_i) or {}
            nt = ((nx.get("type") or "")).strip()
            if nt in _DECL_TYPES:
                fid = int(nid_i)
                break
            cand = nx.get("funcid")
            if cand is None:
                continue
            try:
                fid = int(cand)
                break
            except Exception:
                continue
        if fid is not None and int(fid) > 0:
            out[lk] = int(fid)
    return out


def _node_path(node_id: int, nodes: dict, parent_of: dict, top_id_to_file: dict) -> str:
    try:
        from utils.extractors.if_extract import resolve_top_id
    except Exception:
        return ""
    top = resolve_top_id(int(node_id), parent_of, nodes, top_id_to_file)
    if top is None:
        return ""
    return (top_id_to_file.get(int(top)) or "").strip()
