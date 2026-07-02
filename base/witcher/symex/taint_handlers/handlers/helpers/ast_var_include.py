from typing import Dict, Iterable, List, Optional, Set, Tuple
import re


def _safe_int(x):
    try:
        return int(x)
    except Exception:
        return None


def _min_seq(rec: dict) -> Optional[int]:
    seqs = (rec or {}).get("seqs") or []
    if not seqs:
        return None
    try:
        return int(min(int(s) for s in seqs))
    except Exception:
        return None


def _log(ctx: Optional[dict], event: str, **fields) -> None:
    if not isinstance(ctx, dict):
        return
    if not ctx.get("llm_scope_debug"):
        return
    lg = ctx.get("logger")
    if lg is None:
        return
    try:
        lg.debug(f"ast_var_include_{(event or '').strip()}", **fields)
    except Exception:
        return


def _record_primary_node_id(rec: dict) -> Optional[int]:
    node_ids = (rec or {}).get("node_ids") or []
    if not node_ids:
        return None
    nid = node_ids[0]
    return _safe_int(nid)


def _record_primary_funcid(rec: dict, nodes: Dict[int, dict]) -> Optional[int]:
    nid = _record_primary_node_id(rec)
    if nid is None:
        return None
    v = (nodes.get(nid) or {}).get("funcid")
    return _safe_int(v)


def _node_type(nid: int, nodes: Dict[int, dict]) -> str:
    return ((nodes.get(int(nid)) or {}).get("type") or "").strip()


def _node_funcid(nid: int, nodes: Dict[int, dict]) -> Optional[int]:
    return _safe_int((nodes.get(int(nid)) or {}).get("funcid"))


def _is_func_def_record(rec: dict, nodes: Dict[int, dict]) -> bool:
    for nid in (rec or {}).get("node_ids") or []:
        nid_i = _safe_int(nid)
        if nid_i is None:
            continue
        if _node_type(nid_i, nodes) in ("AST_METHOD", "AST_FUNC_DECL"):
            return True
    return False


def _ensure_func_def_locs(trace_index_records: List[dict], nodes: Dict[int, dict], ctx: Optional[dict] = None) -> Set[str]:
    if isinstance(ctx, dict):
        cached = ctx.get("_ast_func_def_locs")
        if isinstance(cached, set):
            return cached
    out: Set[str] = set()
    for rec in trace_index_records or []:
        if not isinstance(rec, dict):
            continue
        if not _is_func_def_record(rec, nodes):
            continue
        p = (rec.get("path") or "").strip()
        ln = rec.get("line")
        if not p or ln is None:
            continue
        try:
            out.add(f"{p}:{int(ln)}")
        except Exception:
            continue
    if isinstance(ctx, dict):
        ctx["_ast_func_def_locs"] = out
    return out


def _filter_func_def_locs_from_include(locs: List[str], trace_index_records: List[dict], nodes: Dict[int, dict], ctx: Optional[dict] = None) -> List[str]:
    if not locs:
        return []
    func_def_locs = _ensure_func_def_locs(trace_index_records, nodes, ctx)
    if not func_def_locs:
        return list(locs)
    out: List[str] = []
    for loc in locs:
        if loc in func_def_locs:
            continue
        out.append(loc)
    return out


def _iter_descendants(root: int, children_of: Dict[int, List[int]]) -> List[int]:
    out = []
    q = [root]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
        for c in children_of.get(x, []) or []:
            try:
                q.append(int(c))
            except Exception:
                continue
    return out


def _normalize_var_name(name: str) -> str:
    v = (name or "").strip()
    if v.startswith("$"):
        v = v[1:]
    return v


def _split_var_name_parts(name: str) -> Set[str]:
    v = _normalize_var_name(name)
    if not v:
        return set()
    parts = set()
    v2 = v.replace("->", " ").replace(".", " ").replace("[", " ").replace("]", " ")
    for token in re.split(r"[^A-Za-z0-9_]+", v2):
        if not token:
            continue
        if len(token) >= 3:
            parts.add(token)
        if "_" in token:
            for sub in token.split("_"):
                if sub and len(sub) >= 3:
                    parts.add(sub)
    if len(v) >= 3:
        parts.add(v)
    if not parts and v:
        parts.add(v)
    return {p.lower() for p in parts if p}


def _collect_varlike_names_from_node(nid: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]], parent_of: Dict[int, int]) -> Set[str]:
    try:
        from utils.ast_utils.var_utils import extract_varlike_for_nodes
    except Exception:
        extract_varlike_for_nodes = None
    if extract_varlike_for_nodes is None:
        return set()
    desc = _iter_descendants(int(nid), children_of)
    items = extract_varlike_for_nodes(desc, children_of, parent_of, nodes) or []
    out = set()
    for it in items:
        nm = _normalize_var_name((it or {}).get("name") or "")
        if nm:
            out.add(nm)
    return out


def _collect_target_var_parts(ctx: Optional[dict], nodes: Dict[int, dict], children_of: Dict[int, List[int]], parent_of: Dict[int, int]) -> Set[str]:
    if not isinstance(ctx, dict):
        return set()
    cached = ctx.get("_ast_target_var_parts")
    if isinstance(cached, set):
        return cached
    names = set()
    for t in (ctx.get("initial_taints") or []):
        if not isinstance(t, dict):
            continue
        nid = t.get("id")
        if nid is not None:
            try:
                names |= _collect_varlike_names_from_node(int(nid), nodes, children_of, parent_of)
            except Exception:
                pass
        nm = _normalize_var_name((t.get("name") or "").strip())
        if nm:
            names.add(nm)
    if not names:
        for src in (ctx.get("taint_sources") or []):
            if not isinstance(src, dict):
                continue
            nm = _normalize_var_name((src.get("source") or "").strip())
            if nm:
                names.add(nm)
    parts = set()
    for nm in names:
        parts |= _split_var_name_parts(nm)
    ctx["_ast_target_var_parts"] = parts
    return parts


def _is_define_name_node(nid: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> bool:
    if _node_type(nid, nodes) != "AST_NAME":
        return False
    try:
        from utils.ast_utils.var_utils import get_string_children
    except Exception:
        get_string_children = None
    if get_string_children is None:
        return False
    for _cid, val in get_string_children(nid, children_of, nodes):
        if (val or "").strip().lower() == "define":
            return True
    return False


def _is_define_record(rec: dict, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> bool:
    for nid in (rec or {}).get("node_ids") or []:
        nid_i = _safe_int(nid)
        if nid_i is None:
            continue
        for did in _iter_descendants(int(nid_i), children_of):
            if _is_define_name_node(int(did), nodes, children_of):
                return True
    return False


def _collect_line_string_values(recs: List[dict], nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Set[str]:
    out: Set[str] = set()
    for rec in recs or []:
        for nid in (rec or {}).get("node_ids") or []:
            nid_i = _safe_int(nid)
            if nid_i is None:
                continue
            for did in _iter_descendants(int(nid_i), children_of):
                nx = nodes.get(int(did)) or {}
                if (nx.get("labels") == "string") or ((nx.get("type") or "").strip() == "string"):
                    v = (nx.get("code") or nx.get("name") or "").strip()
                    if v:
                        out.add(v)
    return out


def _ensure_trace_records_by_loc(trace_index_records: List[dict], ctx: Optional[dict] = None) -> Dict[str, List[dict]]:
    if isinstance(ctx, dict):
        cached = ctx.get("_trace_records_by_loc")
        if isinstance(cached, dict):
            return cached
    out: Dict[str, List[dict]] = {}
    for rec in trace_index_records or []:
        if not isinstance(rec, dict):
            continue
        p = (rec.get("path") or "").strip()
        ln = rec.get("line")
        if not p or ln is None:
            continue
        try:
            k = f"{p}:{int(ln)}"
        except Exception:
            continue
        out.setdefault(k, []).append(rec)
    if isinstance(ctx, dict):
        ctx["_trace_records_by_loc"] = out
    return out


def _filter_define_locs_from_include(
    locs: List[str],
    trace_index_records: List[dict],
    nodes: Dict[int, dict],
    children_of: Dict[int, List[int]],
    parent_of: Dict[int, int],
    ctx: Optional[dict] = None,
) -> List[str]:
    if not locs:
        return []
    target_parts = _collect_target_var_parts(ctx, nodes, children_of, parent_of)
    if not target_parts:
        return list(locs)
    recs_by_loc = _ensure_trace_records_by_loc(trace_index_records, ctx)
    out: List[str] = []
    for loc in locs:
        recs = recs_by_loc.get(loc) or []
        if not recs:
            out.append(loc)
            continue
        if not any(_is_define_record(r, nodes, children_of) for r in recs):
            out.append(loc)
            continue
        line_strings = _collect_line_string_values(recs, nodes, children_of)
        keep = False
        for s in line_strings:
            s2 = (s or "").lower()
            if not s2:
                continue
            for part in target_parts:
                if part and part in s2:
                    keep = True
                    break
            if keep:
                break
        if keep:
            out.append(loc)
    return out


def is_include_record(rec: dict, nodes: Dict[int, dict]) -> bool:
    for nid in (rec or {}).get("node_ids") or []:
        nid_i = _safe_int(nid)
        if nid_i is None:
            continue
        if _node_type(nid_i, nodes) == "AST_INCLUDE_OR_EVAL":
            return True
    return False


def include_record_funcid(rec: dict, nodes: Dict[int, dict]) -> Optional[int]:
    for nid in (rec or {}).get("node_ids") or []:
        nid_i = _safe_int(nid)
        if nid_i is None:
            continue
        if _node_type(nid_i, nodes) != "AST_INCLUDE_OR_EVAL":
            continue
        fid = _node_funcid(nid_i, nodes)
        if fid is not None:
            return int(fid)
    return _record_primary_funcid(rec, nodes)


def find_included_start(
    *,
    include_index: int,
    include_funcid: int,
    trace_index_records: List[dict],
    nodes: Dict[int, dict],
) -> Tuple[Optional[int], Optional[int], str]:
    if not isinstance(include_index, int) or include_index < 0:
        return None, None, "include_index_invalid"
    recs = trace_index_records or []
    if (include_index + 1) < len(recs):
        r1 = recs[include_index + 1] or {}
        fid1 = _record_primary_funcid(r1, nodes)
        if fid1 is not None and int(fid1) != int(include_funcid):
            return int(include_index + 1), int(fid1), "next_record"
    for j in range(int(include_index) + 1, len(recs)):
        r = recs[j] or {}
        for nid in r.get("node_ids") or []:
            nid_i = _safe_int(nid)
            if nid_i is None:
                continue
            fid = _node_funcid(nid_i, nodes)
            if fid is None or int(fid) == int(include_funcid):
                continue
            return int(j), int(fid), "scan_node_funcid"
        fid0 = _record_primary_funcid(r, nodes)
        if fid0 is not None and int(fid0) != int(include_funcid):
            return int(j), int(fid0), "scan_record_funcid"
    return None, None, "included_start_not_found"


def _intersects_seqs(rec: dict, stop_seqs: Set[int]) -> bool:
    if not stop_seqs:
        return False
    for s in (rec or {}).get("seqs") or []:
        si = _safe_int(s)
        if si is not None and int(si) in stop_seqs:
            return True
    return False


def collect_forward_scope_locs(
    *,
    start_index: int,
    target_funcid: int,
    include_path: str,
    include_funcid: int,
    trace_index_records: List[dict],
    nodes: Dict[int, dict],
    max_forward_records: int = 8000,
) -> List[str]:
    recs = trace_index_records or []
    if not isinstance(start_index, int) or start_index < 0 or start_index >= len(recs):
        return []
    out: List[str] = []
    include_path = (include_path or "").strip()
    for i in range(int(start_index), len(recs)):
        if max_forward_records is not None and (i - int(start_index)) > int(max_forward_records):
            break
        rec = recs[i] or {}
        if i != int(start_index):
            p0 = (rec.get("path") or "").strip()
            fid0 = _record_primary_funcid(rec, nodes)
            if include_path and p0 == include_path and fid0 is not None and int(fid0) == int(include_funcid):
                break
        fid = _record_primary_funcid(rec, nodes)
        if fid is None or int(fid) != int(target_funcid):
            continue
        p = (rec.get("path") or "").strip()
        ln = rec.get("line")
        if not p or ln is None:
            continue
        try:
            out.append(f"{p}:{int(ln)}")
        except Exception:
            continue
    return out


def expand_include_from_record(
    *,
    include_record: dict,
    trace_index_records: List[dict],
    nodes: Dict[int, dict],
    ctx: Optional[dict] = None,
) -> Tuple[List[str], dict]:
    inc_idx = _safe_int((include_record or {}).get("index"))
    if inc_idx is None:
        return [], {"action": "skip", "reason": "include_index_missing"}
    include_funcid = include_record_funcid(include_record, nodes)
    if include_funcid is None:
        return [], {"action": "skip", "reason": "include_funcid_missing", "include_index": int(inc_idx)}

    include_path = ((include_record or {}).get("path") or "").strip()
    start_idx, included_funcid, start_reason = find_included_start(
        include_index=int(inc_idx),
        include_funcid=int(include_funcid),
        trace_index_records=trace_index_records,
        nodes=nodes,
    )
    if start_idx is None or included_funcid is None:
        _log(
            ctx,
            "expand_skip",
            reason="included_start_not_found",
            include_index=int(inc_idx),
            include_funcid=int(include_funcid),
            include_path=include_path,
        )
        return [], {
            "action": "skip",
            "reason": "included_start_not_found",
            "include_index": int(inc_idx),
            "include_funcid": int(include_funcid),
        }

    locs = collect_forward_scope_locs(
        start_index=int(start_idx),
        target_funcid=int(included_funcid),
        include_path=include_path,
        include_funcid=int(include_funcid),
        trace_index_records=trace_index_records,
        nodes=nodes,
    )
    locs = _filter_func_def_locs_from_include(locs, trace_index_records, nodes, ctx)
    if isinstance(ctx, dict):
        children_of = ctx.get("children_of") or {}
        parent_of = ctx.get("parent_of") or {}
        locs = _filter_define_locs_from_include(locs, trace_index_records, nodes, children_of, parent_of, ctx)
    _log(
        ctx,
        "expand",
        include_index=int(inc_idx),
        include_funcid=int(include_funcid),
        include_path=include_path,
        included_start_index=int(start_idx),
        included_funcid=int(included_funcid),
        included_locs_count=int(len(locs)),
        start_reason=start_reason,
    )
    return (
        locs,
        {
            "action": "expand",
            "include_index": int(inc_idx),
            "include_funcid": int(include_funcid),
            "include_path": include_path,
            "included_start_index": int(start_idx),
            "included_funcid": int(included_funcid),
            "included_locs_count": int(len(locs)),
            "include_seq_min": _min_seq(include_record),
            "start_reason": start_reason,
        },
    )


def expand_includes_in_scope_recs(
    *,
    scope_recs: Iterable[dict],
    trace_index_records: List[dict],
    nodes: Dict[int, dict],
    max_expands: int = 12,
    ctx: Optional[dict] = None,
) -> Tuple[List[str], List[dict]]:
    out: List[str] = []
    debug: List[dict] = []
    seen_include_indices: Set[int] = set()
    expands = 0
    for rec in scope_recs or []:
        if expands >= int(max_expands):
            break
        if not isinstance(rec, dict):
            continue
        if not is_include_record(rec, nodes):
            continue
        inc_idx = _safe_int(rec.get("index"))
        if inc_idx is None or int(inc_idx) in seen_include_indices:
            continue
        seen_include_indices.add(int(inc_idx))
        locs, dbg = expand_include_from_record(
            include_record=rec,
            trace_index_records=trace_index_records,
            nodes=nodes,
            ctx=ctx,
        )
        debug.append(dbg)
        if locs:
            out.extend(locs)
        expands += 1
    return out, debug


def _parse_loc(loc: str) -> Tuple[Optional[str], Optional[int]]:
    s = (loc or "").strip()
    if not s or ":" not in s:
        return None, None
    p, ln_s = s.rsplit(":", 1)
    try:
        return (p or "").strip(), int(ln_s)
    except Exception:
        return (p or "").strip(), None


def _ensure_include_records_by_loc(ctx: dict) -> Dict[Tuple[str, int], List[dict]]:
    cached = ctx.get("_ast_include_records_by_loc")
    if isinstance(cached, dict):
        return cached
    nodes = ctx.get("nodes") or {}
    recs = ctx.get("trace_index_records") or []
    out: Dict[Tuple[str, int], List[dict]] = {}
    for rec in recs or []:
        if not isinstance(rec, dict):
            continue
        p = (rec.get("path") or "").strip()
        ln = rec.get("line")
        if not p or ln is None:
            continue
        try:
            k = (p, int(ln))
        except Exception:
            continue
        if not is_include_record(rec, nodes):
            continue
        out.setdefault(k, []).append(rec)
    ctx["_ast_include_records_by_loc"] = out
    return out


def _pick_best_include_record(candidates: List[dict], ref_seq: Optional[int]) -> Optional[dict]:
    if not candidates:
        return None
    if ref_seq is None:
        keyed = [(int(_min_seq(r) or 10**18), int(_safe_int(r.get("index")) or 10**18), r) for r in candidates]
        keyed.sort(key=lambda x: (x[0], x[1]))
        return keyed[0][2] if keyed else None
    try:
        r = int(ref_seq)
    except Exception:
        r = None
    if r is None:
        keyed = [(int(_min_seq(c) or 10**18), int(_safe_int(c.get("index")) or 10**18), c) for c in candidates]
        keyed.sort(key=lambda x: (x[0], x[1]))
        return keyed[0][2] if keyed else None
    before = []
    after = []
    for c in candidates:
        ms = _min_seq(c)
        if ms is None:
            continue
        if int(ms) <= int(r):
            before.append((int(ms), int(_safe_int(c.get("index")) or 10**18), c))
        else:
            after.append((int(ms), int(_safe_int(c.get("index")) or 10**18), c))
    if before:
        before.sort(key=lambda x: (-x[0], x[1]))
        return before[0][2]
    if after:
        after.sort(key=lambda x: (x[0], x[1]))
        return after[0][2]
    return candidates[0]


def expand_includes_in_locs(
    *,
    locs: List[str],
    ctx: dict,
    max_expands: int = 12,
) -> Tuple[List[str], List[dict]]:
    if not isinstance(ctx, dict):
        return [], []
    nodes = ctx.get("nodes") or {}
    recs = ctx.get("trace_index_records") or []
    if not locs or not nodes or not recs:
        return [], []
    ref_seq = ctx.get("_llm_ref_seq")
    if ref_seq is None:
        ref_seq = ctx.get("input_seq")
    try:
        ref_seq_i = int(ref_seq) if ref_seq is not None else None
    except Exception:
        ref_seq_i = None
    by_loc = _ensure_include_records_by_loc(ctx)
    picked: List[dict] = []
    seen_idx: Set[int] = set()
    for loc in locs or []:
        p, ln = _parse_loc(loc)
        if not p or ln is None:
            continue
        cand = by_loc.get((p, int(ln))) or []
        if not cand:
            continue
        rec = _pick_best_include_record(cand, ref_seq_i)
        if not isinstance(rec, dict):
            continue
        idx = _safe_int(rec.get("index"))
        if idx is None or int(idx) in seen_idx:
            continue
        seen_idx.add(int(idx))
        picked.append(rec)
        if len(picked) >= int(max_expands):
            break
    if not picked:
        _log(ctx, "locs_no_include", locs_len=int(len(locs)))
        return [], []
    _log(ctx, "locs_found_include", includes=int(len(picked)), locs_len=int(len(locs)), ref_seq=ref_seq_i)
    extra: List[str] = []
    debug: List[dict] = []
    for rec in picked:
        ex, dbg = expand_include_from_record(include_record=rec, trace_index_records=recs, nodes=nodes, ctx=ctx)
        debug.append(dbg)
        if ex:
            extra.extend(ex)
    return extra, debug

