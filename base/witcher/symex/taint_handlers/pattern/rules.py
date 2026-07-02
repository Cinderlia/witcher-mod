from taint_handlers.pattern.models import PatternRelation
from taint_handlers.pattern.normalize import (
    collect_supported_taints,
    filter_new_taints,
    node_ids_for_loc,
    record_for_seq,
    same_taint,
    seq_for_node,
    sorted_children,
)
from taint_handlers.pattern.assignment_call_scopes import record_assignment_rhs_call_scopes
from typing import List, Optional, Set, Tuple, Dict


_ASSIGN_TYPES = {"AST_ASSIGN", "AST_ASSIGN_REF", "AST_ASSIGN_OP"}
_CALL_TYPES = {"AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"}
_CONTROL_TYPES = {"AST_IF_ELEM", "AST_ELSEIF", "AST_SWITCH_CASE", "AST_CONDITIONAL"}
_WRAPPER_TYPES = {"AST_ISSET", "AST_EMPTY", "AST_ARRAY", "AST_ARRAY_ELEM", "AST_BINARY_OP", "AST_CAST", "AST_UNARY_OP"}
_BOOL_COMPARE_TOKENS = (
    "BOOL_AND",
    "BOOL_OR",
    "BOOL_XOR",
    "IS_",
    "SMALLER",
    "GREATER",
    "EQUAL",
    "IDENTICAL",
    "SPACESHIP",
    "COALESCE",
)


def _current_this_context(current: dict) -> Tuple[str, Optional[int]]:
    this_obj = (current.get("_this_obj") or "").strip()
    this_call_seq = current.get("_this_call_seq")
    try:
        this_call_seq = int(this_call_seq) if this_call_seq is not None else None
    except Exception:
        this_call_seq = None
    return this_obj, this_call_seq


def _assignment_parts(node_id: int, nodes: dict, children_of: dict) -> Tuple[Optional[int], Optional[int]]:
    children = sorted_children(node_id, nodes, children_of)
    if len(children) < 2:
        return None, None
    return int(children[0]), int(children[1])


def _dim_index_roots(dim_id: int, nodes: dict, children_of: dict) -> List[int]:
    children = sorted_children(dim_id, nodes, children_of)
    if len(children) < 2:
        return []
    return [int(x) for x in children[1:]]


def _nested_dim_context_roots(dim_id: int, nodes: dict, children_of: dict) -> List[int]:
    out = []
    seen = set()
    cur = dim_id
    steps = 0
    while cur is not None and steps < 8:
        try:
            cur_i = int(cur)
        except Exception:
            break
        if cur_i in seen:
            break
        seen.add(cur_i)
        children = sorted_children(cur_i, nodes, children_of)
        if not children:
            break
        base_id = int(children[0])
        for idx_root in _dim_index_roots(cur_i, nodes, children_of):
            out.append(int(idx_root))
        base_type = ((nodes.get(base_id) or {}).get("type") or "").strip()
        if base_type == "AST_DIM":
            cur = int(base_id)
            steps += 1
            continue
        out.append(int(base_id))
        break
    return out


def _call_parts(node_id: int, nodes: dict, children_of: dict) -> Tuple[Optional[int], Optional[int]]:
    recv_id = None
    arg_list_id = None
    for child in sorted_children(node_id, nodes, children_of):
        cx = nodes.get(child) or {}
        ct = (cx.get("type") or "").strip()
        if ct == "AST_ARG_LIST":
            arg_list_id = int(child)
            continue
        if cx.get("labels") == "string" or ct == "string" or ct == "AST_NAME":
            continue
        if recv_id is None:
            recv_id = int(child)
    return recv_id, arg_list_id


def _return_expr_root(node_id: int, nodes: dict, children_of: dict) -> Optional[int]:
    for child in sorted_children(node_id, nodes, children_of):
        cx = nodes.get(child) or {}
        if ((cx.get("type") or "").strip() or "NULL") == "NULL":
            continue
        return int(child)
    return None


def _control_condition_root(node_id: int, nodes: dict, children_of: dict) -> Optional[int]:
    children = sorted_children(node_id, nodes, children_of)
    if not children:
        return None
    return int(children[0])


def _wrapper_relation_kind(node_id: int, ctx: dict) -> str:
    nodes = ctx.get("nodes") or {}
    nx = nodes.get(int(node_id)) or {}
    ntype = ((nx.get("type") or "")).strip()
    flags = ((nx.get("flags") or "")).strip().upper()
    if ntype == "AST_ISSET":
        return "isset_check"
    if ntype == "AST_EMPTY":
        return "empty_check"
    if ntype == "AST_ARRAY_ELEM":
        return "container_elem"
    if ntype == "AST_ARRAY":
        return "container_build"
    if ntype == "AST_BINARY_OP" and "COALESCE" in flags:
        return "coalesce"
    if ntype == "AST_BINARY_OP" and any(tok in flags for tok in _BOOL_COMPARE_TOKENS):
        return "condition_expr"
    if ntype == "AST_BINARY_OP":
        return "binary_expr"
    if ntype == "AST_CAST":
        return "cast_expr"
    if ntype == "AST_UNARY_OP":
        return "unary_expr"
    return "expr_wrapper"


def _match_against_subtree(current: dict, root_id: Optional[int], seq: int, ctx: dict) -> bool:
    if root_id is None:
        return False
    this_obj, this_call_seq = _current_this_context(current)
    for taint in collect_supported_taints(
        root_id,
        seq,
        ctx,
        this_obj=this_obj,
        this_call_seq=this_call_seq,
        include_root=True,
    ):
        if same_taint(current, taint):
            return True
    return False


def _wrapper_relations_for_node(node_id: int, seq: int, current: dict, ctx: dict) -> List[PatternRelation]:
    if not _match_against_subtree(current, node_id, seq, ctx):
        return []
    this_obj, this_call_seq = _current_this_context(current)
    taints = filter_new_taints(
        collect_supported_taints(
            node_id,
            seq,
            ctx,
            this_obj=this_obj,
            this_call_seq=this_call_seq,
            include_root=True,
        ),
        current,
    )
    if not taints:
        return []
    rel = PatternRelation(
        seq=int(seq),
        kind=_wrapper_relation_kind(node_id, ctx),
        taints=taints,
        detail={"node_id": int(node_id)},
    )
    out = [rel]
    out.extend(_collect_control_relations(node_id, current, ctx, ref_seq=seq))
    return out


def _collect_condition_signal_taints(root_id: Optional[int], seq: int, current: dict, ctx: dict) -> List[dict]:
    if root_id is None:
        return []
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    this_obj, this_call_seq = _current_this_context(current)
    out = []
    seen_nodes = set()

    def walk(nid: int):
        if nid in seen_nodes:
            return
        seen_nodes.add(nid)
        nx = nodes.get(int(nid)) or {}
        ntype = ((nx.get("type") or "")).strip()
        flags = ((nx.get("flags") or "")).strip().upper()
        if ntype in {"AST_BINARY_OP", "AST_UNARY_OP", "AST_CAST", "AST_ISSET", "AST_EMPTY", "AST_ARRAY", "AST_ARRAY_ELEM"}:
            if ntype != "AST_BINARY_OP" or any(tok in flags for tok in _BOOL_COMPARE_TOKENS):
                for child in sorted_children(int(nid), nodes, children_of):
                    walk(int(child))
                return
        out.extend(
            collect_supported_taints(
                int(nid),
                seq,
                ctx,
                this_obj=this_obj,
                this_call_seq=this_call_seq,
                include_root=True,
            )
        )

    walk(int(root_id))
    return filter_new_taints(out, current)


def _collect_control_relations(anchor_id: int, current: dict, ctx: dict, *, ref_seq: int) -> List[PatternRelation]:
    nodes = ctx.get("nodes") or {}
    parent_of = ctx.get("parent_of") or {}
    children_of = ctx.get("children_of") or {}
    this_obj, this_call_seq = _current_this_context(current)
    out = []
    seen = set()
    cur = int(anchor_id)
    depth = 0
    while depth < 12:
        pid = parent_of.get(cur)
        if pid is None:
            break
        try:
            pid_i = int(pid)
        except Exception:
            break
        ptype = ((nodes.get(pid_i) or {}).get("type") or "").strip()
        if ptype in _CONTROL_TYPES:
            key = (pid_i, ptype)
            if key not in seen:
                seen.add(key)
                cond_root = _control_condition_root(pid_i, nodes, children_of)
                cond_seq = seq_for_node(pid_i, ctx, ref_seq=ref_seq, prefer="backward") or int(ref_seq)
                cond_taints = _collect_condition_signal_taints(cond_root, cond_seq, current, ctx)
                if cond_taints:
                    out.append(
                        PatternRelation(
                            seq=int(cond_seq),
                            kind="control_dep",
                            taints=cond_taints,
                            detail={"control_id": int(pid_i), "control_type": ptype},
                        )
                    )
        cur = pid_i
        depth += 1
    return out


def _assignment_relations_for_node(node_id: int, seq: int, current: dict, ctx: dict) -> List[PatternRelation]:
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    this_obj, this_call_seq = _current_this_context(current)
    lhs_id, rhs_id = _assignment_parts(node_id, nodes, children_of)
    if lhs_id is None or rhs_id is None:
        return []
    if not _match_against_subtree(current, lhs_id, seq, ctx):
        return []
    try:
        record_assignment_rhs_call_scopes(lhs_id=lhs_id, rhs_id=rhs_id, seq=int(seq), ctx=ctx)
    except Exception:
        pass
    taints = collect_supported_taints(
        rhs_id,
        seq,
        ctx,
        this_obj=this_obj,
        this_call_seq=this_call_seq,
        include_root=True,
    )
    lhs_type = ((nodes.get(lhs_id) or {}).get("type") or "").strip()
    if lhs_type == "AST_DIM":
        for idx_root in _nested_dim_context_roots(lhs_id, nodes, children_of):
            taints.extend(
                collect_supported_taints(
                    idx_root,
                    seq,
                    ctx,
                    this_obj=this_obj,
                    this_call_seq=this_call_seq,
                    include_root=True,
                )
            )
    taints = filter_new_taints(taints, current)
    if not taints:
        return []
    ntype = ((nodes.get(node_id) or {}).get("type") or "").strip()
    kind = "compound_assign" if ntype == "AST_ASSIGN_OP" else "assign"
    out = [PatternRelation(seq=int(seq), kind=kind, taints=taints, detail={"node_id": int(node_id)})]
    out.extend(_collect_control_relations(node_id, current, ctx, ref_seq=seq))
    return out


def _call_input_relations_for_node(node_id: int, seq: int, current: dict, ctx: dict) -> List[PatternRelation]:
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    this_obj, this_call_seq = _current_this_context(current)
    root_taint = collect_supported_taints(
        node_id,
        seq,
        ctx,
        this_obj=this_obj,
        this_call_seq=this_call_seq,
        include_root=True,
    )
    if not any(same_taint(current, it) for it in root_taint):
        return []
    recv_id, arg_list_id = _call_parts(node_id, nodes, children_of)
    taints = []
    if recv_id is not None:
        taints.extend(
            collect_supported_taints(
                recv_id,
                seq,
                ctx,
                this_obj=this_obj,
                this_call_seq=this_call_seq,
                include_root=True,
            )
        )
    if arg_list_id is not None:
        taints.extend(
            collect_supported_taints(
                arg_list_id,
                seq,
                ctx,
                this_obj=this_obj,
                this_call_seq=this_call_seq,
                include_root=False,
            )
        )
    taints = filter_new_taints(taints, current)
    if not taints:
        return []
    out = [PatternRelation(seq=int(seq), kind="call_input", taints=taints, detail={"node_id": int(node_id)})]
    out.extend(_collect_control_relations(node_id, current, ctx, ref_seq=seq))
    return out


def _dim_relations_for_node(node_id: int, seq: int, current: dict, ctx: dict) -> List[PatternRelation]:
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    this_obj, this_call_seq = _current_this_context(current)
    root_taint = collect_supported_taints(
        node_id,
        seq,
        ctx,
        this_obj=this_obj,
        this_call_seq=this_call_seq,
        include_root=True,
    )
    if not any(same_taint(current, it) for it in root_taint):
        return []
    children = sorted_children(node_id, nodes, children_of)
    taints = []
    for idx_root in _nested_dim_context_roots(node_id, nodes, children_of):
        taints.extend(
            collect_supported_taints(
                idx_root,
                seq,
                ctx,
                this_obj=this_obj,
                this_call_seq=this_call_seq,
                include_root=True,
            )
        )
    taints = filter_new_taints(taints, current)
    if not taints:
        return []
    return [PatternRelation(seq=int(seq), kind="container_access", taints=taints, detail={"node_id": int(node_id)})]


def _return_relations_for_node(node_id: int, seq: int, current: dict, ctx: dict) -> List[PatternRelation]:
    current_type = (current.get("type") or "").strip()
    if current_type not in _CALL_TYPES:
        return []
    this_obj, this_call_seq = _current_this_context(current)
    expr_root = _return_expr_root(node_id, ctx.get("nodes") or {}, ctx.get("children_of") or {})
    taints = filter_new_taints(
        collect_supported_taints(
            expr_root,
            seq,
            ctx,
            this_obj=this_obj,
            this_call_seq=this_call_seq,
            include_root=True,
        ),
        current,
    )
    if not taints:
        return []
    out = [PatternRelation(seq=int(seq), kind="return_flow", taints=taints, detail={"node_id": int(node_id)})]
    out.extend(_collect_control_relations(node_id, current, ctx, ref_seq=seq))
    return out


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


def _collect_relations_for_node_candidates(current: dict, candidates: List[dict], ctx: dict) -> List[PatternRelation]:
    nodes = ctx.get("nodes") or {}
    out = []
    seen = set()
    for cand in candidates or []:
        if not isinstance(cand, dict):
            continue
        seq = cand.get("seq")
        node_ids = cand.get("node_ids") or []
        detail_base = cand.get("detail") if isinstance(cand.get("detail"), dict) else {}
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        if not node_ids:
            continue
        for nid in node_ids or []:
            try:
                node_id = int(nid)
            except Exception:
                continue
            ntype = ((nodes.get(node_id) or {}).get("type") or "").strip()
            relations = []
            if ntype in _ASSIGN_TYPES:
                relations.extend(_assignment_relations_for_node(node_id, int(seq_i), current, ctx))
            elif ntype in _CALL_TYPES:
                relations.extend(_call_input_relations_for_node(node_id, int(seq_i), current, ctx))
            elif ntype == "AST_DIM":
                relations.extend(_dim_relations_for_node(node_id, int(seq_i), current, ctx))
            elif ntype == "AST_RETURN":
                relations.extend(_return_relations_for_node(node_id, int(seq_i), current, ctx))
            elif ntype in _WRAPPER_TYPES:
                relations.extend(_wrapper_relations_for_node(node_id, int(seq_i), current, ctx))
            for rel in relations:
                if detail_base:
                    merged_detail = dict(detail_base)
                    merged_detail.update(rel.detail or {})
                    rel.detail = merged_detail
                key = _relation_key(rel)
                if key in seen:
                    continue
                seen.add(key)
                out.append(rel)
    out.sort(key=lambda x: (int(x.seq), x.kind))
    return out


def discover_relations_for_taint(current: dict, scope_seqs: List[int], ctx: dict) -> List[PatternRelation]:
    candidates = []
    for seq in scope_seqs or []:
        rec = record_for_seq(seq, ctx)
        if not isinstance(rec, dict):
            continue
        node_ids = []
        for nid in rec.get("node_ids") or []:
            try:
                node_ids.append(int(nid))
            except Exception:
                continue
        if not node_ids:
            continue
        candidates.append({"seq": int(seq), "node_ids": node_ids})
    return _collect_relations_for_node_candidates(current, candidates, ctx)


def discover_relations_for_source_locs(current: dict, source_locs: List[dict], ctx: dict, *, ref_seq: int) -> List[PatternRelation]:
    candidates = []
    for loc in source_locs or []:
        if not isinstance(loc, dict):
            continue
        path = (loc.get("path") or "").strip()
        line = loc.get("line")
        if not path or line is None:
            continue
        try:
            line_i = int(line)
        except Exception:
            continue
        node_ids = node_ids_for_loc(path, line_i, ctx)
        if not node_ids:
            continue
        candidates.append(
            {
                "seq": int(ref_seq),
                "node_ids": node_ids,
                "detail": {"source_only": True, "path": path, "line": int(line_i), "loc": f"{path}:{int(line_i)}"},
            }
        )
    return _collect_relations_for_node_candidates(current, candidates, ctx)
