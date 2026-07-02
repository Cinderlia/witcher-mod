from taint_handlers.pattern.normalize import seq_for_node
from typing import List, Optional


def add_function_frame_locs(ctx: dict, call_param_arg_info: dict) -> None:
    if not isinstance(ctx, dict) or not isinstance(call_param_arg_info, dict):
        return
    call_seq = call_param_arg_info.get("call_seq")
    callee_id = call_param_arg_info.get("callee_id")
    try:
        call_seq_i = int(call_seq) if call_seq is not None else None
    except Exception:
        call_seq_i = None
    try:
        callee_id_i = int(callee_id) if callee_id is not None else None
    except Exception:
        callee_id_i = None
    locs = []
    if call_seq_i is not None:
        loc = _loc_for_seq(call_seq_i, ctx)
        if loc is not None:
            locs.append(loc)
    if callee_id_i is not None:
        loc = _loc_for_func_decl(callee_id_i, ctx, ref_seq=(call_seq_i or 0))
        if loc is not None:
            locs.append(loc)
    if locs:
        existing = list(ctx.get("pattern_source_locs") or [])
        ctx["pattern_source_locs"] = _dedup_locs(existing + locs)


def add_decl_locs_from_scope_lines(ctx: dict, scope_source_lines: List[dict]) -> None:
    if not isinstance(ctx, dict):
        return
    locs = []
    items = [it for it in (scope_source_lines or []) if isinstance(it, dict)]
    for idx, it in enumerate(items):
        if not isinstance(it, dict):
            continue
        code = (it.get("code") or "").strip()
        if "function" not in code:
            continue
        if not _has_body_code_after(items, start_index=idx + 1):
            continue
        seq = it.get("seq")
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        if seq_i is None:
            continue
        loc = _loc_for_seq(seq_i, ctx)
        if loc is not None:
            locs.append(loc)
    if locs:
        existing = list(ctx.get("pattern_source_locs") or [])
        ctx["pattern_source_locs"] = _dedup_locs(existing + locs)


def _has_body_code_after(items: List[dict], *, start_index: int) -> bool:
    for it in items[start_index:]:
        code = (it.get("code") or "").strip()
        if not code:
            continue
        if code.startswith("// FUNCTION_SCOPE_"):
            continue
        if "function" in code:
            continue
        return True
    return False


def _loc_for_seq(seq: int, ctx: dict) -> Optional[dict]:
    recs = ctx.get("trace_index_records") or []
    seq_to_idx = ctx.get("trace_seq_to_index") or {}
    idx = seq_to_idx.get(int(seq))
    rec = None
    if isinstance(idx, int) and 0 <= idx < len(recs):
        rec = recs[idx] or {}
    if rec is None:
        for r in recs:
            if int(seq) in {int(x) for x in (r.get("seqs") or []) if x is not None}:
                rec = r or {}
                break
    if not isinstance(rec, dict):
        return None
    p = (rec.get("path") or "").strip()
    ln = rec.get("line")
    if not p or ln is None:
        return None
    try:
        ln_i = int(ln)
    except Exception:
        return None
    return {"seq": int(seq), "path": p, "line": ln_i, "loc": f"{p}:{ln_i}"}


def _loc_for_func_decl(callee_id: int, ctx: dict, *, ref_seq: int) -> Optional[dict]:
    nodes = ctx.get("nodes") or {}
    top_id_to_file = ctx.get("top_id_to_file") or {}
    parent_of = ctx.get("parent_of") or {}
    try:
        from utils.extractors.if_extract import resolve_top_id
    except Exception:
        return None
    nx = nodes.get(int(callee_id)) or {}
    line = nx.get("lineno")
    if line is None:
        return None
    try:
        line_i = int(line)
    except Exception:
        return None
    top = resolve_top_id(int(callee_id), parent_of, nodes, top_id_to_file)
    path = top_id_to_file.get(top) if top is not None else None
    if not path:
        return None
    seq_i = seq_for_node(int(callee_id), ctx, ref_seq=int(ref_seq), prefer="forward")
    out = {"path": path, "line": line_i, "loc": f"{path}:{line_i}"}
    if seq_i is not None:
        out["seq"] = int(seq_i)
    else:
        out["source_only"] = True
    return out


def _dedup_locs(items: list) -> list:
    out = []
    seen = set()
    for it in items or []:
        if not isinstance(it, dict):
            continue
        loc = (it.get("loc") or "").strip()
        seq = it.get("seq")
        source_only = bool(it.get("source_only"))
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        key = (loc, seq_i, source_only) if loc else None
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out
