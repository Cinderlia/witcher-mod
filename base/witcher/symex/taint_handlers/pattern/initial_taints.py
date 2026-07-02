from taint_handlers.pattern.normalize import collect_supported_taints, same_taint, sorted_children
from typing import List, Optional, Set


_SINK_MODES = {"sql", "xss", "cmd"}


def build_initial_taints_for_statement(st: dict, nodes: dict, children_of: dict, parent_of: dict) -> List[dict]:
    if not isinstance(st, dict):
        return []
    mode = (st.get("mode") or "if").strip().lower()
    seq = st.get("seq")
    try:
        seq_i = int(seq) if seq is not None else None
    except Exception:
        seq_i = None
    if seq_i is None:
        return []
    roots = []
    if mode in _SINK_MODES:
        roots = _sink_expr_roots(st, nodes, children_of)
    else:
        roots = _condition_expr_roots(st, nodes, children_of)
    return _collect_initial_supported_taints(roots, seq_i, nodes, children_of, parent_of)


def _condition_expr_roots(st: dict, nodes: dict, children_of: dict) -> List[int]:
    out = []
    seen = set()
    for root in st.get("targets") or []:
        try:
            root_i = int(root)
        except Exception:
            continue
        rtype = ((nodes.get(root_i) or {}).get("type") or "").strip()
        if rtype == "AST_IF_ELEM":
            ch = sorted_children(root_i, nodes, children_of)
            if ch:
                _add_root(out, seen, ch[0])
            continue
        if rtype == "AST_SWITCH":
            ch = sorted_children(root_i, nodes, children_of)
            if ch:
                _add_root(out, seen, ch[0])
            for expr_root in _switch_case_expr_roots(root_i, nodes, children_of):
                _add_root(out, seen, expr_root)
            continue
        _add_root(out, seen, root_i)
    return out


def _sink_expr_roots(st: dict, nodes: dict, children_of: dict) -> List[int]:
    out = []
    seen = set()
    for root in st.get("targets") or []:
        try:
            root_i = int(root)
        except Exception:
            continue
        rtype = ((nodes.get(root_i) or {}).get("type") or "").strip()
        if rtype in {"AST_CALL", "AST_STATIC_CALL", "AST_METHOD_CALL"}:
            for arg_root in _call_arg_expr_roots(root_i, nodes, children_of):
                _add_root(out, seen, arg_root)
            continue
        if rtype in {"AST_SHELL_EXEC", "AST_BACKTICK", "AST_ECHO", "AST_PRINT"}:
            for child in sorted_children(root_i, nodes, children_of):
                _add_root(out, seen, child)
            continue
        _add_root(out, seen, root_i)
    return out


def _switch_case_expr_roots(switch_id: int, nodes: dict, children_of: dict) -> List[int]:
    out = []
    switch_list_id = None
    for c in sorted_children(switch_id, nodes, children_of):
        if ((nodes.get(c) or {}).get("type") or "").strip() == "AST_SWITCH_LIST":
            switch_list_id = int(c)
            break
    if switch_list_id is None:
        return out
    for case_id in sorted_children(switch_list_id, nodes, children_of):
        ct = ((nodes.get(case_id) or {}).get("type") or "").strip()
        if ct != "AST_SWITCH_CASE":
            continue
        case_children = sorted_children(case_id, nodes, children_of)
        if not case_children:
            continue
        expr_id = int(case_children[0])
        et = ((nodes.get(expr_id) or {}).get("type") or "").strip()
        if et and et != "NULL":
            out.append(expr_id)
    return out


def _call_arg_expr_roots(call_id: int, nodes: dict, children_of: dict) -> List[int]:
    out = []
    for child in sorted_children(call_id, nodes, children_of):
        ct = ((nodes.get(child) or {}).get("type") or "").strip()
        if ct != "AST_ARG_LIST":
            continue
        for arg in sorted_children(child, nodes, children_of):
            out.append(int(arg))
        break
    return out


def _collect_initial_supported_taints(roots: List[int], seq: int, nodes: dict, children_of: dict, parent_of: dict) -> List[dict]:
    ctx = {
        "nodes": nodes,
        "children_of": children_of,
        "parent_of": parent_of,
    }
    out = []
    for root_id in roots or []:
        out.extend(collect_supported_taints(int(root_id), int(seq), ctx, include_root=True))
    out = _dedup_taints(out)
    out = _filter_receiver_side_taints(out, roots, seq, nodes, children_of)
    return out


def _filter_receiver_side_taints(taints: List[dict], roots: List[int], seq: int, nodes: dict, children_of: dict) -> List[dict]:
    receiver_taints = []
    ctx = {"nodes": nodes, "children_of": children_of, "parent_of": {}}
    for root_id in roots or []:
        rtype = ((nodes.get(int(root_id)) or {}).get("type") or "").strip()
        if rtype != "AST_METHOD_CALL":
            continue
        recv_id = _method_receiver_root(int(root_id), nodes, children_of)
        if recv_id is None:
            continue
        receiver_taints.extend(collect_supported_taints(int(recv_id), int(seq), ctx, include_root=True))
    if not receiver_taints:
        return taints
    out = []
    for item in taints or []:
        if any(same_taint(item, recv) for recv in receiver_taints):
            continue
        out.append(item)
    return _dedup_taints(out)


def _method_receiver_root(call_id: int, nodes: dict, children_of: dict) -> Optional[int]:
    for child in sorted_children(call_id, nodes, children_of):
        cx = nodes.get(int(child)) or {}
        ct = (cx.get("type") or "").strip()
        if ct == "AST_ARG_LIST":
            continue
        if cx.get("labels") == "string" or ct in {"string", "AST_NAME"}:
            continue
        return int(child)
    return None


def _add_root(out: List[int], seen: Set, root_id: int) -> None:
    try:
        root_i = int(root_id)
    except Exception:
        return
    if root_i in seen:
        return
    seen.add(root_i)
    out.append(root_i)


def _dedup_taints(items: List[dict]) -> List[dict]:
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if any(same_taint(item, prev) for prev in out):
            continue
        out.append(item)
    return out
