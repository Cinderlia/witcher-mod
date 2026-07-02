from typing import List, Optional

def _walk_pruned_scope_tree(root: dict):
    if not isinstance(root, dict):
        return
    stack = [(root, None, None)]
    seen = set()
    while stack:
        node, parent_call_seq, root_call_seq = stack.pop()
        if not isinstance(node, dict):
            continue
        call_id = node.get('call_id')
        call_seq = node.get('call_seq')
        k = (call_id, call_seq, id(node))
        if k in seen:
            continue
        seen.add(k)
        yield node, parent_call_seq, root_call_seq
        cur_root_call_seq = root_call_seq
        if cur_root_call_seq is None and call_seq is not None:
            try:
                cur_root_call_seq = int(call_seq)
            except Exception:
                cur_root_call_seq = root_call_seq
        cur_parent_call_seq = parent_call_seq
        if call_seq is not None:
            try:
                cur_parent_call_seq = int(call_seq)
            except Exception:
                cur_parent_call_seq = parent_call_seq
        for ch in (node.get('children') or [])[::-1]:
            stack.append((ch, cur_parent_call_seq, cur_root_call_seq))


def collect_prop_call_scopes(root: dict, ctx: dict, *, this_obj: str) -> List[dict]:
    if not isinstance(ctx, dict) or not isinstance(root, dict):
        return []
    if not this_obj:
        return []
    try:
        from taint_handlers import ast_method_call
    except Exception:
        return []

    out = []
    for node, parent_call_seq, root_call_seq in _walk_pruned_scope_tree(root):
        call_id = node.get('call_id')
        call_seq = node.get('call_seq')
        if call_id is None or call_seq is None:
            continue
        try:
            call_id_i = int(call_id)
            call_seq_i = int(call_seq)
        except Exception:
            continue
        scope_info = ast_method_call.partition_function_scope_for_call(call_id_i, call_seq_i, ctx)
        if not isinstance(scope_info, dict):
            continue
        callee_id = scope_info.get('def_id')
        def_seq = scope_info.get('def_seq')
        if callee_id is None or def_seq is None:
            continue
        try:
            callee_id_i = int(callee_id)
            def_seq_i = int(def_seq)
        except Exception:
            continue
        min_seq = None
        max_seq = None
        for row in scope_info.get('scope') or []:
            try:
                s = int((row or {}).get('seq'))
            except Exception:
                continue
            if min_seq is None or s < min_seq:
                min_seq = s
            if max_seq is None or s > max_seq:
                max_seq = s
        if min_seq is None or max_seq is None:
            min_seq = def_seq_i
            max_seq = def_seq_i

        info = None
        if ctx.get('llm_enabled'):
            try:
                info = ast_method_call.build_call_param_arg_info(call_id_i, call_seq_i, callee_id_i, ctx)
            except Exception:
                info = None

        out.append(
            {
                'call_id': call_id_i,
                'call_seq': call_seq_i,
                'callee_id': callee_id_i,
                'def_seq': def_seq_i,
                'min_seq': int(min_seq),
                'max_seq': int(max_seq),
                'parent_call_seq': (int(parent_call_seq) if parent_call_seq is not None else None),
                'root_call_seq': (int(root_call_seq) if root_call_seq is not None else call_seq_i),
                'this_obj': str(this_obj),
                'call_param_arg_info': info,
            }
        )
    return out


def pick_innermost_scope(scopes: List[dict], seq: int) -> Optional[dict]:
    try:
        s = int(seq)
    except Exception:
        return None
    best = None
    best_span = None
    for sc in scopes or []:
        try:
            lo = int(sc.get('min_seq'))
            hi = int(sc.get('max_seq'))
        except Exception:
            continue
        if s < lo or s > hi:
            continue
        span = hi - lo
        if best is None or best_span is None or span < best_span:
            best = sc
            best_span = span
    return best

