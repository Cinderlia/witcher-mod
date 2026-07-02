from taint_handlers.handlers.call import ast_method_call
from taint_handlers.pattern.models import PatternRelation
from taint_handlers.pattern.normalize import collect_supported_taints, filter_new_taints, seq_for_node, sorted_children
from typing import List, Optional, Set, Dict


_CALL_TYPES = {"AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"}


def collect_call_return_relations(current: dict, ctx: dict) -> List[PatternRelation]:
    if not isinstance(current, dict) or not isinstance(ctx, dict):
        return []
    if (current.get("type") or "").strip() not in _CALL_TYPES:
        return []
    call_id = current.get("id")
    call_seq = current.get("seq")
    if call_id is None or call_seq is None:
        return []
    try:
        call_id_i = int(call_id)
        call_seq_i = int(call_seq)
    except Exception:
        return []
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    this_obj = (current.get("_this_obj") or "").strip()
    this_call_seq = current.get("_this_call_seq")
    try:
        this_call_seq = int(this_call_seq) if this_call_seq is not None else None
    except Exception:
        this_call_seq = None
    out = []
    seen = set()
    for callee_id in _callee_ids(call_id_i, ctx):
        call_param_arg_info = ast_method_call.build_call_param_arg_info(call_id_i, call_seq_i, int(callee_id), ctx)
        callee_scope_locs = _callee_scope_locs(int(callee_id), ctx, ref_seq=call_seq_i)
        for ret_id in _return_node_ids_for_callee(callee_id, nodes):
            expr_root = _return_expr_root(ret_id, nodes, children_of)
            if expr_root is None:
                continue
            ret_seq = seq_for_node(int(ret_id), ctx, ref_seq=call_seq_i, prefer="forward") or call_seq_i
            taints = filter_new_taints(
                collect_supported_taints(
                    int(expr_root),
                    int(ret_seq),
                    ctx,
                    this_obj=this_obj,
                    this_call_seq=this_call_seq,
                    include_root=True,
                ),
                current,
            )
            taints = _prune_component_var_taints(taints)
            if not taints:
                continue
            rel = PatternRelation(
                seq=int(ret_seq),
                kind="call_return_bridge",
                taints=taints,
                detail={
                    "call_id": int(call_id_i),
                    "callee_id": int(callee_id),
                    "return_id": int(ret_id),
                    "callee_scope_locs": list(callee_scope_locs or []),
                    "call_param_arg_info": call_param_arg_info,
                },
            )
            key = _relation_key(rel)
            if key in seen:
                continue
            seen.add(key)
            out.append(rel)
    out.sort(key=lambda x: (int(x.seq), x.kind))
    return out


def _prune_component_var_taints(taints: List[dict]) -> List[dict]:
    items = [it for it in (taints or []) if isinstance(it, dict)]
    composite_prefixes = set()
    for item in items:
        tt = (item.get("type") or "").strip()
        name = (item.get("name") or "").replace(".", "->").strip()
        if tt not in {"AST_PROP", "AST_DIM", "AST_METHOD_CALL"} or not name:
            continue
        for sep in ("->", "["):
            pos = name.find(sep)
            if pos > 0:
                composite_prefixes.add(name[:pos].strip())
    out = []
    for item in items:
        tt = (item.get("type") or "").strip()
        name = (item.get("name") or "").replace(".", "->").strip()
        if tt == "AST_VAR" and name and name in composite_prefixes:
            continue
        out.append(item)
    return out


def _callee_ids(call_id: int, ctx: dict) -> List[int]:
    calls_edges = ctx.get("calls_edges_union")
    if calls_edges is None:
        calls_edges = ast_method_call.read_calls_edges(".")
        ctx["calls_edges_union"] = calls_edges
    out = []
    seen = set()
    for x in list(calls_edges.get(int(call_id)) or []):
        try:
            x_i = int(x)
        except Exception:
            continue
        if x_i in seen:
            continue
        seen.add(x_i)
        out.append(x_i)
    return out


def _return_node_ids_for_callee(callee_id: int, nodes: dict) -> List[int]:
    out = []
    for nid, nx in (nodes or {}).items():
        try:
            nid_i = int(nid)
        except Exception:
            continue
        if (nx or {}).get("funcid") != int(callee_id):
            continue
        if ((nx or {}).get("type") or "").strip() != "AST_RETURN":
            continue
        out.append(nid_i)
    out.sort()
    return out


def _return_expr_root(node_id: int, nodes: dict, children_of: dict) -> Optional[int]:
    for child in sorted_children(node_id, nodes, children_of):
        cx = nodes.get(child) or {}
        if (((cx.get("type") or "").strip()) or "NULL") == "NULL":
            continue
        return int(child)
    return None


def _callee_scope_locs(callee_id: int, ctx: dict, *, ref_seq: int) -> List[dict]:
    nodes = ctx.get("nodes") or {}
    recs = ctx.get("trace_index_records") or []
    out = []
    seen = set()
    decl_item = _callee_decl_loc(int(callee_id), ctx, ref_seq=ref_seq)
    if isinstance(decl_item, dict):
        key0 = (decl_item.get("path"), decl_item.get("line"), decl_item.get("seq"))
        if key0 not in seen:
            seen.add(key0)
            out.append(decl_item)
    for rec in recs:
        node_ids = rec.get("node_ids") or []
        cur_id = node_ids[0] if node_ids else None
        cur_funcid = (nodes.get(cur_id) or {}).get("funcid") if cur_id is not None else None
        if cur_funcid != int(callee_id):
            continue
        p = (rec.get("path") or "").strip()
        ln = rec.get("line")
        seqs = rec.get("seqs") or []
        if not p or ln is None:
            continue
        try:
            ln_i = int(ln)
        except Exception:
            continue
        seq_i = None
        for s in seqs:
            try:
                seq_i = int(s)
                break
            except Exception:
                continue
        key = (p, ln_i, seq_i)
        if key in seen:
            continue
        seen.add(key)
        item = {"path": p, "line": ln_i, "loc": f"{p}:{ln_i}"}
        if seq_i is not None:
            item["seq"] = int(seq_i)
        out.append(item)
    if out:
        return out
    for nid, nx in (nodes or {}).items():
        try:
            nid_i = int(nid)
        except Exception:
            continue
        if (nx or {}).get("funcid") != int(callee_id):
            continue
        line = nx.get("lineno")
        if line is None:
            continue
        try:
            line_i = int(line)
        except Exception:
            continue
        seq_i = seq_for_node(nid_i, ctx, ref_seq=ref_seq, prefer="forward")
        top_id_to_file = ctx.get("top_id_to_file") or {}
        parent_of = ctx.get("parent_of") or {}
        try:
            from utils.extractors.if_extract import resolve_top_id
        except Exception:
            continue
        top = resolve_top_id(nid_i, parent_of, nodes, top_id_to_file)
        path = top_id_to_file.get(top) if top is not None else None
        if not path:
            continue
        key = (path, line_i, seq_i)
        if key in seen:
            continue
        seen.add(key)
        item = {"path": path, "line": line_i, "loc": f"{path}:{line_i}", "source_only": seq_i is None}
        if seq_i is not None:
            item["seq"] = int(seq_i)
        out.append(item)
    out.sort(key=lambda x: ((x.get("seq") is None), int(x.get("seq") or 10**9), (x.get("loc") or "")))
    return out


def _callee_decl_loc(callee_id: int, ctx: dict, *, ref_seq: int) -> Optional[dict]:
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
    seq_i = seq_for_node(int(callee_id), ctx, ref_seq=ref_seq, prefer="forward")
    item = {"path": path, "line": line_i, "loc": f"{path}:{line_i}", "source_only": seq_i is None}
    if seq_i is not None:
        item["seq"] = int(seq_i)
    return item


def _relation_key(rel: PatternRelation) -> tuple:
    taint_keys = []
    for item in rel.taints or []:
        taint_keys.append(
            (
                int(item.get("id")) if item.get("id") is not None else None,
                int(item.get("seq")) if item.get("seq") is not None else None,
                (item.get("type") or "").strip(),
                (item.get("name") or "").strip(),
            )
        )
    return int(rel.seq), rel.kind, tuple(sorted(taint_keys))
