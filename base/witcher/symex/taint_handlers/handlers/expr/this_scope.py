from typing import Dict, List, Optional, Set, Tuple

from utils.extractors.if_extract import find_first_var_string, get_string_children

from . import ast_var


def _strip_dollar(s: str) -> str:
    v = (s or "").strip()
    if v.startswith("$"):
        return v[1:]
    return v


def is_this_receiver_taint(taint: dict) -> bool:
    if not isinstance(taint, dict):
        return False
    tt = (taint.get("type") or "").strip()
    if tt == "AST_PROP":
        base = (taint.get("base") or "").strip()
        if base in ("this", "$this"):
            return True
        name = (taint.get("name") or "").replace(".", "->").strip()
        return bool(name.startswith(("this->", "$this->", "this.", "$this.")))
    if tt == "AST_METHOD_CALL":
        recv = (taint.get("recv") or "").strip()
        if recv in ("this", "$this"):
            return True
        name = (taint.get("name") or "").replace(".", "->").strip()
        return bool(name.startswith(("this->", "$this->")))
    return False


def resolve_receiver_root_context(taint: dict) -> dict:
    if not isinstance(taint, dict):
        return {}
    recv_obj = _strip_dollar((taint.get("_this_obj") or taint.get("recv") or taint.get("base") or "").strip())
    start_seq = taint.get("seq")
    if taint.get("_this_call_seq") is not None:
        start_seq = taint.get("_this_call_seq")
    try:
        start_seq_i = int(start_seq) if start_seq is not None else None
    except Exception:
        start_seq_i = None
    return {
        "recv_obj": recv_obj,
        "start_seq": start_seq_i,
        "is_this_receiver": bool(is_this_receiver_taint(taint)),
    }


def _min_seq_from_rec(rec) -> Optional[int]:
    seqs = (rec or {}).get("seqs") or []
    if not seqs:
        return None
    try:
        return int(min(int(x) for x in seqs))
    except Exception:
        return None


def _method_call_recv_name(call_id: int, nodes, children_of) -> Tuple[str, str]:
    def recv_name(expr_id: int) -> str:
        nx = nodes.get(expr_id) or {}
        tt = (nx.get("type") or "").strip()
        if tt == "AST_VAR":
            ss = get_string_children(expr_id, children_of, nodes)
            v = ss[0][1] if ss else ""
            if v:
                return v
        if tt in ("AST_PROP", "AST_DIM"):
            v = (find_first_var_string(expr_id, children_of, nodes) or "").strip()
            if v:
                return v
        v = (nx.get("code") or nx.get("name") or "").strip()
        if v.startswith("$"):
            v = v[1:]
        if "->" in v:
            v = v.split("->", 1)[0].strip()
        if "(" in v:
            v = v.split("(", 1)[0].strip()
        return v

    recv = ""
    name = ""
    ch = list(children_of.get(call_id, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get("childnum") if (nodes.get(x) or {}).get("childnum") is not None else 10**9)
    for c in ch:
        nx = nodes.get(c) or {}
        if not recv and nx.get("type") not in ("AST_ARG_LIST",) and nx.get("labels") != "string" and nx.get("type") != "string":
            recv = recv_name(int(c))
        if not name and (nx.get("labels") == "string" or nx.get("type") == "string"):
            v = (nx.get("code") or nx.get("name") or "").strip()
            if v:
                name = v
        if recv and name:
            break
    return _strip_dollar(recv), name


def _prop_base_prop(prop_id: int, nodes, children_of) -> Tuple[str, str]:
    base = ""
    prop = ""
    ch = list(children_of.get(prop_id, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get("childnum") if (nodes.get(x) or {}).get("childnum") is not None else 10**9)
    for c in ch:
        nx = nodes.get(c) or {}
        if not base and nx.get("type") == "AST_VAR":
            ss = get_string_children(c, children_of, nodes)
            base = ss[0][1] if ss else ""
        if not prop and (nx.get("labels") == "string" or nx.get("type") == "string"):
            v = (nx.get("code") or nx.get("name") or "").strip()
            if v:
                prop = v
        if base and prop:
            break
    return _strip_dollar(base), prop


def scope_has_this_prop(loc_taints, ctx, *, prop: str) -> bool:
    if not prop:
        return False
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    recs = ctx.get("trace_index_records") or []
    seq_to_idx = ctx.get("trace_seq_to_index") or {}
    for lt in loc_taints or []:
        try:
            s = int((lt or {}).get("seq"))
        except Exception:
            continue
        idx = seq_to_idx.get(s)
        if not isinstance(idx, int) or idx < 0 or idx >= len(recs):
            continue
        rec = recs[idx] or {}
        for nid in rec.get("node_ids") or []:
            nx = nodes.get(nid) or {}
            if nx.get("type") != "AST_PROP":
                continue
            b, p = _prop_base_prop(int(nid), nodes, children_of)
            if b == "this" and p == prop:
                return True
    return False


def collect_method_calls_from_recs(recs, nodes, children_of, *, recv_names: Set[str]) -> List[Tuple[int, int]]:
    out = []
    seen = set()
    wanted = {_strip_dollar(v) for v in (recv_names or set()) if _strip_dollar(v)}
    if not wanted:
        return out
    for rec in recs or []:
        call_seq = _min_seq_from_rec(rec)
        if call_seq is None:
            continue
        for nid in (rec or {}).get("node_ids") or []:
            nx = nodes.get(nid) or {}
            if (nx.get("type") or "").strip() != "AST_METHOD_CALL":
                continue
            try:
                call_id = int(nid)
            except Exception:
                continue
            if call_id in seen:
                continue
            recv, _ = _method_call_recv_name(call_id, nodes, children_of)
            if recv not in wanted:
                continue
            seen.add(call_id)
            out.append((call_id, int(call_seq)))
    return out


def collect_this_method_calls_from_loc_taints(
    loc_taints,
    ctx,
    *,
    seen_call_ids: Set[int],
    scope_min_seq: Optional[int] = None,
    scope_max_seq: Optional[int] = None,
    ref_seq: Optional[int] = None,
) -> List[Tuple[int, int]]:
    out = []
    seen_local = set()
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    recs = ctx.get("trace_index_records") or []
    seq_to_idx = ctx.get("trace_seq_to_index") or {}
    groups_by_loc = None
    pick_seq_by_ref = None
    try:
        from llm_utils.prompts.prompt_utils import ensure_seq_groups_by_loc as _ensure_seq_groups_by_loc
        from llm_utils.prompts.prompt_utils import pick_seq_by_ref as _pick_seq_by_ref

        groups_by_loc = _ensure_seq_groups_by_loc(ctx)
        pick_seq_by_ref = _pick_seq_by_ref
    except Exception:
        groups_by_loc = None
        pick_seq_by_ref = None
    for lt in loc_taints or []:
        try:
            s = int((lt or {}).get("seq"))
        except Exception:
            continue
        idx = seq_to_idx.get(s)
        if not isinstance(idx, int) or idx < 0 or idx >= len(recs):
            continue
        rec = recs[idx] or {}
        call_seq = int(s)
        call_path = (rec.get("path") or "").strip()
        call_line = rec.get("line")
        try:
            call_line_i = int(call_line) if call_line is not None else None
        except Exception:
            call_line_i = None
        for nid in rec.get("node_ids") or []:
            nx = nodes.get(nid) or {}
            if (nx.get("type") or "").strip() != "AST_METHOD_CALL":
                continue
            try:
                call_id = int(nid)
            except Exception:
                continue
            if call_id in seen_call_ids or call_id in seen_local:
                continue
            recv, _ = _method_call_recv_name(call_id, nodes, children_of)
            if recv != "this":
                continue
            if pick_seq_by_ref is not None and groups_by_loc is not None and call_path and call_line_i is not None and ref_seq is not None:
                groups_all = list(groups_by_loc.get((call_path, int(call_line_i))) or [])
                if groups_all:
                    groups = groups_all
                    if scope_min_seq is not None or scope_max_seq is not None:
                        g2 = []
                        for g in groups_all:
                            try:
                                gmin = int(g.get("min"))
                                gmax = int(g.get("max"))
                            except Exception:
                                continue
                            if scope_min_seq is not None and gmax < int(scope_min_seq):
                                continue
                            if scope_max_seq is not None and gmin > int(scope_max_seq):
                                continue
                            g2.append(g)
                        if g2:
                            groups = g2
                    picked = pick_seq_by_ref(groups, int(ref_seq), prefer="backward")
                    if picked is not None:
                        call_seq = int(picked)
            seen_local.add(call_id)
            out.append((call_id, int(call_seq)))
    return out


def _expand_method_call_scope(call_id: int, call_seq: int, ctx, *, debug_key: str) -> Tuple[List[dict], List[dict], dict]:
    try:
        from ..call import ast_method_call
    except Exception:
        return [], [], {}
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    parent_of = ctx.get("parent_of") or {}
    top_id_to_file = ctx.get("top_id_to_file") or {}
    recs = ctx.get("trace_index_records") or []
    seq_to_idx = ctx.get("trace_seq_to_index") or {}
    calls_edges_union = ctx.get("calls_edges_union")
    dbg_local = {"_": []}
    dbg_ctx = ctx.get("debug")
    if isinstance(dbg_ctx, dict):
        dbg_local = dbg_ctx
    ctx2 = {
        "nodes": nodes,
        "children_of": children_of,
        "parent_of": parent_of,
        "top_id_to_file": top_id_to_file,
        "trace_index_records": recs,
        "trace_seq_to_index": seq_to_idx,
        "calls_edges_union": calls_edges_union,
        "debug": dbg_local,
        "result_set": [],
        "llm_enabled": bool(ctx.get("llm_enabled")),
        "_llm_disable_nested_this_calls": True,
    }
    call_taint = {"id": int(call_id), "type": "AST_METHOD_CALL", "seq": int(call_seq)}
    call_res = ast_method_call.process_call_like(call_taint, ctx2, debug_key=debug_key)
    loc_taints = call_res[0] if (isinstance(call_res, list) and call_res and isinstance(call_res[0], list)) else []
    scope_locs = []
    seen = set()
    for lt in loc_taints or []:
        if not isinstance(lt, dict):
            continue
        p = (lt.get("path") or "").strip()
        ln = lt.get("line")
        if not p or ln is None:
            continue
        try:
            ln_i = int(ln)
        except Exception:
            continue
        loc = f"{p}:{ln_i}"
        seq = lt.get("seq")
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        key = (loc, seq_i)
        if key in seen:
            continue
        seen.add(key)
        item = {"path": p, "line": ln_i, "loc": loc}
        if seq_i is not None:
            item["seq"] = int(seq_i)
        scope_locs.append(item)
    return scope_locs, loc_taints, ctx2


def build_scope_tree_for_calls(
    calls,
    ctx,
    *,
    target_prop: str,
    seen_call_ids: Set[int],
    ref_seq: Optional[int],
    debug_key: str,
) -> List[dict]:
    out = []
    for call_id, call_seq in calls or []:
        try:
            cid = int(call_id)
            csq = int(call_seq)
        except Exception:
            continue
        if cid in seen_call_ids:
            continue
        seen_call_ids.add(cid)
        scope_locs, loc_taints, _ = _expand_method_call_scope(cid, csq, ctx, debug_key=debug_key)
        node = {
            "call_id": cid,
            "call_seq": csq,
            "scope_locs": scope_locs,
            "loc_taints": loc_taints,
            "children": [],
            "has_target": True if not target_prop else scope_has_this_prop(loc_taints, ctx, prop=target_prop),
        }
        if loc_taints:
            smin = None
            smax = None
            for lt in loc_taints:
                try:
                    ss = int((lt or {}).get("seq"))
                except Exception:
                    continue
                if smin is None or ss < smin:
                    smin = ss
                if smax is None or ss > smax:
                    smax = ss
            next_calls = collect_this_method_calls_from_loc_taints(
                loc_taints,
                ctx,
                seen_call_ids=seen_call_ids,
                scope_min_seq=smin,
                scope_max_seq=smax,
                ref_seq=ref_seq,
            )
            if next_calls:
                node["children"] = build_scope_tree_for_calls(
                    next_calls,
                    ctx,
                    target_prop=target_prop,
                    seen_call_ids=seen_call_ids,
                    ref_seq=ref_seq,
                    debug_key=debug_key,
                )
        out.append(node)
    return out


def prune_scope_tree(node) -> bool:
    keep = bool(node.get("has_target"))
    kept_children = []
    for ch in node.get("children") or []:
        if prune_scope_tree(ch):
            kept_children.append(ch)
            keep = True
    node["children"] = kept_children
    node["has_target"] = keep
    return keep


def collect_kept_scope_locs(node, out: list) -> None:
    for ch in node.get("children") or []:
        for loc in ch.get("scope_locs") or []:
            out.append(loc)
        collect_kept_scope_locs(ch, out)


def collect_scope_markers(node, out: List[dict]) -> None:
    for ch in node.get("children") or []:
        scope = ch.get("scope_locs") or []
        if scope:
            st = scope[0]
            ed = scope[-1]
            st_loc = st.get("loc") if isinstance(st, dict) else None
            ed_loc = ed.get("loc") if isinstance(ed, dict) else None
            if st_loc and ed_loc and st_loc != ed_loc:
                out.append({"kind": "function_scope", "start": st_loc, "end": ed_loc})
        collect_scope_markers(ch, out)


def count_tree_nodes(node) -> int:
    n = 0
    for ch in node.get("children") or []:
        n += 1
        n += count_tree_nodes(ch)
    return n


def expand_receiver_method_scopes(
    *,
    start_seq: int,
    ctx: dict,
    recv_obj: str,
    target_prop: str = "",
    include_this_calls_in_base_scope: bool = False,
    prune_to_target: bool = False,
    debug_key: str = "this_scope_expand",
) -> Tuple[List, List[dict], dict, dict]:
    if not isinstance(ctx, dict):
        return [], [], {}, {}
    try:
        start_seq_i = int(start_seq)
    except Exception:
        return [], [], {}, {}
    recv_obj = _strip_dollar(recv_obj)
    target_prop = (target_prop or "").strip()
    if not recv_obj:
        return [], [], {}, {}
    if isinstance(ctx, dict):
        ctx["_llm_ref_seq"] = int(start_seq_i)

    ast_var.ensure_trace_index(ctx)
    recs = ctx.get("trace_index_records") or []
    seq_to_idx = ctx.get("trace_seq_to_index") or {}
    start_idx = seq_to_idx.get(start_seq_i)
    if not isinstance(start_idx, int) or start_idx < 0 or start_idx >= len(recs):
        return [], [], {}, {}

    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    node_ids0 = (recs[start_idx] or {}).get("node_ids") or []
    cur0 = node_ids0[0] if node_ids0 else None
    funcid = (nodes.get(cur0) or {}).get("funcid") if cur0 is not None else None
    if funcid is None:
        return [], [], {}, {}

    scope_recs, base_locs, stop_info = ast_var.collect_scope_recs_and_locs(start_idx=int(start_idx), funcid=int(funcid), ctx=ctx)
    recv_names = {recv_obj}
    if include_this_calls_in_base_scope:
        recv_names.add("this")
    initial_calls = collect_method_calls_from_recs(scope_recs, nodes, children_of, recv_names=recv_names)
    root = {
        "call_id": None,
        "call_seq": int(start_seq_i),
        "scope_locs": list(base_locs),
        "loc_taints": [{"type": "TRACE_LOC", "seq": _min_seq_from_rec(r)} for r in scope_recs if _min_seq_from_rec(r) is not None],
        "children": [],
        "has_target": True,
    }
    seen_call_ids: Set[int] = set()
    root["children"] = build_scope_tree_for_calls(
        initial_calls,
        ctx,
        target_prop=target_prop,
        seen_call_ids=seen_call_ids,
        ref_seq=int(start_seq_i),
        debug_key=debug_key,
    )
    if prune_to_target:
        kept = []
        for ch in list(root.get("children") or []):
            if prune_scope_tree(ch):
                kept.append(ch)
        root["children"] = kept

    kept_locs = []
    collect_kept_scope_locs(root, kept_locs)
    markers = []
    collect_scope_markers(root, markers)
    stats = {
        "start_seq": int(start_seq_i),
        "funcid": int(funcid),
        "stop_by": stop_info.get("stop_by"),
        "stop_index": stop_info.get("stop_index"),
        "initial_calls_count": int(len(initial_calls)),
        "expanded_scope_nodes": int(count_tree_nodes(root)),
        "base_locs_unique": int(len(base_locs or [])),
        "kept_locs_unique": int(len(kept_locs or [])),
        "markers_count": int(len(markers or [])),
    }
    return base_locs, kept_locs, root, stats
