from taint_handlers.handlers.call import ast_method_call

import re
from typing import Optional

_FUNC_NAME_RE = re.compile(r"\\bfunction\\s+&?\\s*([A-Za-z_\\x80-\\xff][A-Za-z0-9_\\x80-\\xff]*)", re.IGNORECASE)
_CALL_TYPES = {"AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"}


def infer_call_param_arg_info_for_current(current: dict, ctx: dict) -> Optional[dict]:
    if not isinstance(current, dict) or not isinstance(ctx, dict):
        return None
    cur_id = current.get("id")
    cur_seq = current.get("seq")
    if cur_id is None or cur_seq is None:
        return None
    try:
        cur_id_i = int(cur_id)
        cur_seq_i = int(cur_seq)
    except Exception:
        return None
    nodes = ctx.get("nodes") or {}
    funcid = (nodes.get(cur_id_i) or {}).get("funcid")
    try:
        funcid_i = int(funcid) if funcid is not None else None
    except Exception:
        funcid_i = None
    if funcid_i is None:
        return None
    recs = ctx.get("trace_index_records") or []
    seq_to_idx = ctx.get("trace_seq_to_index") or {}
    stop_index = seq_to_idx.get(int(cur_seq_i))
    if not isinstance(stop_index, int) or stop_index <= 0:
        return None
    try:
        from taint_handlers.handlers.expr.ast_var import build_funcid_to_call_ids, find_nearest_callsite_record
    except Exception:
        return None
    calls_edges_union = ctx.get("calls_edges_union")
    if calls_edges_union is None:
        calls_edges_union = ast_method_call.read_calls_edges(".")
        ctx["calls_edges_union"] = calls_edges_union
    funcid_to_call_ids = ctx.get("_llm_funcid_to_call_ids")
    if funcid_to_call_ids is None:
        funcid_to_call_ids = build_funcid_to_call_ids(calls_edges_union)
        ctx["_llm_funcid_to_call_ids"] = funcid_to_call_ids
    call_ids = funcid_to_call_ids.get(int(funcid_i)) or set()
    if not call_ids:
        return _infer_by_name(int(funcid_i), stop_index=int(stop_index), ctx=ctx)
    hit = find_nearest_callsite_record(set(call_ids), recs, stop_index - 1)
    if not hit:
        return _infer_by_name(int(funcid_i), stop_index=int(stop_index), ctx=ctx)
    call_index, call_id, _ = hit
    call_seq = None
    try:
        call_id_i = int(call_id)
    except Exception:
        return None
    if isinstance(call_index, int) and 0 <= call_index < len(recs):
        try:
            seqs = (recs[int(call_index)] or {}).get("seqs") or []
            if seqs:
                call_seq = int(min(int(x) for x in seqs))
        except Exception:
            call_seq = None
    if call_seq is None:
        for rec in recs:
            node_ids = rec.get("node_ids") or []
            if not node_ids:
                continue
            try:
                if int(call_id_i) not in {int(x) for x in node_ids}:
                    continue
            except Exception:
                continue
            seqs = rec.get("seqs") or []
            if seqs:
                try:
                    call_seq = int(min(int(x) for x in seqs))
                except Exception:
                    call_seq = None
            break
    if call_seq is None:
        return None
    info = ast_method_call.build_call_param_arg_info(int(call_id_i), int(call_seq), int(funcid_i), ctx)
    return info if isinstance(info, dict) else None


def _infer_by_name(funcid: int, *, stop_index: int, ctx: dict) -> Optional[dict]:
    nodes = ctx.get("nodes") or {}
    recs = ctx.get("trace_index_records") or []
    nx = nodes.get(int(funcid)) or {}
    func_name = (nx.get("name") or "").strip()
    if not func_name:
        func_name = _parse_func_name((nx.get("code") or "") or "")
    if not func_name:
        return None
    pat = re.compile(r"(?i)(->|::)?%s\s*\(" % re.escape(func_name))
    i = int(stop_index) - 1
    steps = 0
    while i >= 0 and steps < 4000:
        rec = recs[i] or {}
        node_ids = rec.get("node_ids") or []
        call_id = None
        for nid in node_ids:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            t = ((nodes.get(nid_i) or {}).get("type") or "").strip()
            if t not in _CALL_TYPES:
                continue
            code = ((nodes.get(nid_i) or {}).get("code") or (nodes.get(nid_i) or {}).get("name") or "").strip()
            if code and pat.search(code):
                call_id = int(nid_i)
                break
        if call_id is not None:
            seqs = rec.get("seqs") or []
            call_seq = None
            if seqs:
                try:
                    call_seq = int(min(int(x) for x in seqs))
                except Exception:
                    call_seq = None
            if call_seq is None:
                return None
            info = ast_method_call.build_call_param_arg_info(int(call_id), int(call_seq), int(funcid), ctx)
            return info if isinstance(info, dict) else None
        i -= 1
        steps += 1
    return None


def _parse_func_name(code: str) -> str:
    m = _FUNC_NAME_RE.search(code or "")
    return (m.group(1) or "").strip() if m else ""
