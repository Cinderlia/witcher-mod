import json
import os
import re
from typing import Dict, List, Optional, Set, Tuple


_FUNC_NAME_RE = re.compile(r"\bfunction\s+&?\s*([A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)", re.IGNORECASE)
_DECL_TYPES = {"AST_FUNC_DECL", "AST_METHOD", "AST_CLOSURE"}


def _append_structured_context_debug(mapped: list, event: str, **fields) -> None:
    run_dir = ""
    for it in mapped or []:
        if not isinstance(it, dict):
            continue
        run_dir = str(it.get("__WITCHER_RUN_DIR__") or "").strip()
        if run_dir:
            break
    if not run_dir:
        return
    payload = {
        "event": str(event or ""),
        "pid": int(os.getpid()),
        "ppid": int(os.getppid()),
    }
    for k, v in (fields or {}).items():
        payload[str(k)] = v
    try:
        logs_dir = os.path.join(os.path.abspath(run_dir), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        with open(os.path.join(logs_dir, "stage_debug.ndjson"), "a", encoding="utf-8", errors="replace") as f:
            f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception:
        pass


def structure_mapped_context(mapped: list, nodes: dict, parent_of: dict, top_id_to_file: dict) -> List[dict]:
    _append_structured_context_debug(mapped, "sc_enter", mapped_count=len(mapped or []), node_count=len(nodes or {}), parent_count=len(parent_of or {}), top_file_count=len(top_id_to_file or {}))
    items = []
    for idx, it in enumerate(mapped or []):
        if not isinstance(it, dict):
            continue
        items.append({"_idx": int(idx), **it})
    _append_structured_context_debug(mapped, "sc_items_built", item_count=len(items))
    if not items:
        _append_structured_context_debug(mapped, "sc_empty_return")
        return list(mapped or [])

    _append_structured_context_debug(mapped, "sc_before_build_loc_to_funcid", item_count=len(items))
    loc_to_func = _build_loc_to_funcid(items, nodes, parent_of, top_id_to_file)
    _append_structured_context_debug(mapped, "sc_after_build_loc_to_funcid", loc_to_func_count=len(loc_to_func or {}))
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
    _append_structured_context_debug(mapped, "sc_groups_built", global_item_count=len(global_items), func_group_count=len(func_groups))

    blocks = []
    global_remaining = list(global_items)
    global_used = set()
    for fid, group in func_groups.items():
        _append_structured_context_debug(mapped, "sc_block_build_start", funcid=int(fid), group_count=len(group or []), global_remaining_count=len(global_remaining), global_used_count=len(global_used))
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
        _append_structured_context_debug(mapped, "sc_block_build_done", funcid=int(fid), callsite_count=len(callsites or []), body_count=len(body or []), block_idx=int(block_idx))

    global_filtered = [it for it in global_remaining if it.get("_idx") not in global_used]
    global_filtered.sort(key=lambda x: int(x.get("_idx", 0)))
    blocks.sort(key=lambda b: int(b.get("_idx", 10**9)))
    _append_structured_context_debug(mapped, "sc_merge_ready", global_filtered_count=len(global_filtered), block_count=len(blocks))

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
    _append_structured_context_debug(mapped, "sc_merge_done", out_count=len(out), gi=int(gi), bi=int(bi))
    out_keys = {_item_key(x) for x in out if isinstance(x, dict)}
    missing = []
    for it in items:
        k = _item_key(_strip_meta(it))
        if k not in out_keys:
            missing.append(_strip_meta(it))
            out_keys.add(k)
    if missing:
        out.extend(missing)
    _append_structured_context_debug(mapped, "sc_missing_appended", missing_count=len(missing), out_count=len(out))
    if _has_decl(items) and not _has_decl(out):
        _append_structured_context_debug(mapped, "sc_fallback_function_block")
        out = _fallback_function_block(items)
    _append_structured_context_debug(mapped, "sc_return", out_count=len(out))
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
    _append_structured_context_debug(items, "sc_loc_to_funcid_enter", item_count=len(items or []), node_count=len(nodes or {}))
    wanted_locs = set()
    for it in items or []:
        lk = _loc_key(it)
        if lk is not None:
            wanted_locs.add(lk)
    _append_structured_context_debug(items, "sc_loc_to_funcid_targets", target_loc_count=len(wanted_locs))
    if not wanted_locs:
        _append_structured_context_debug(items, "sc_loc_to_funcid_return", node_iter_count=0, item_iter_count=0, by_loc_count=0, out_count=0)
        return {}

    wanted_lines = {int(line) for _, line in wanted_locs}
    wanted_paths = {str(path) for path, _ in wanted_locs}
    by_loc = {}
    node_iter_count = 0
    matched_node_count = 0
    for nid, nx in (nodes or {}).items():
        node_iter_count += 1
        if node_iter_count <= 3 or (node_iter_count % 200000) == 0:
            _append_structured_context_debug(items, "sc_loc_to_funcid_node_progress", node_iter_count=int(node_iter_count), by_loc_count=len(by_loc), matched_node_count=int(matched_node_count))
        line = nx.get("lineno")
        if line is None:
            continue
        try:
            line_i = int(line)
        except Exception:
            continue
        if line_i not in wanted_lines:
            continue
        try:
            nid_i = int(nid)
        except Exception:
            continue
        path = _node_path(nid_i, nodes, parent_of, top_id_to_file)
        if not path or path not in wanted_paths:
            continue
        lk = (path, line_i)
        if lk not in wanted_locs:
            continue
        by_loc.setdefault(lk, []).append(nid_i)
        matched_node_count += 1
        if len(by_loc) == len(wanted_locs):
            done = True
            for target_lk in wanted_locs:
                if not by_loc.get(target_lk):
                    done = False
                    break
            if done:
                _append_structured_context_debug(items, "sc_loc_to_funcid_early_stop", node_iter_count=int(node_iter_count), matched_node_count=int(matched_node_count), covered_loc_count=len(by_loc))
                break

    out = {}
    item_iter_count = 0
    for it in items or []:
        item_iter_count += 1
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
    _append_structured_context_debug(items, "sc_loc_to_funcid_return", node_iter_count=int(node_iter_count), item_iter_count=int(item_iter_count), by_loc_count=len(by_loc), out_count=len(out), matched_node_count=int(matched_node_count))
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
