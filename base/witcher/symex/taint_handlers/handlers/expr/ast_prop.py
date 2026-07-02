"""
Taint handler for `AST_PROP` nodes.

This handler tries to widen the prompt scope for object properties by exploring
method calls on the same receiver, collecting relevant scopes that may assign or
depend on the property.
"""

from typing import Dict, List, Optional, Set, Tuple

from utils.extractors.if_extract import get_string_children, find_first_var_string

from . import ast_var
from . import this_scope
from ..call import ast_method_call


def _strip_dollar(s: str) -> str:
    """Remove a leading `$` from a variable-like string."""
    v = (s or '').strip()
    if v.startswith('$'):
        return v[1:]
    return v


def _count_unique_locs(locs: list) -> int:
    seen = set()
    count = 0
    for x in locs or []:
        if not x:
            continue
        if isinstance(x, dict):
            lk = (x.get('loc') or '').strip()
            if not lk:
                p = (x.get('path') or '').strip()
                ln = x.get('line')
                if p and ln is not None:
                    try:
                        lk = f"{p}:{int(ln)}"
                    except Exception:
                        lk = ''
            if not lk:
                continue
            seq = x.get('seq')
            try:
                seq_i = int(seq) if seq is not None else None
            except Exception:
                seq_i = None
            key = (lk, int(seq_i)) if seq_i is not None else lk
        elif isinstance(x, str):
            key = x
        else:
            continue
        if key in seen:
            continue
        seen.add(key)
        count += 1
    return count


def _parse_obj_prop(taint) -> Tuple[str, str]:
    """Parse a property taint into `(receiver_object, prop_name)`."""
    if not isinstance(taint, dict):
        return '', ''
    this_obj = _strip_dollar((taint.get('_this_obj') or '').strip())
    base = (taint.get('base') or '').strip()
    prop = (taint.get('prop') or '').strip()
    if base and prop:
        b = _strip_dollar(base)
        if this_obj and b in ('this', '$this'):
            b = this_obj
        return b, prop
    nm = (taint.get('name') or '').strip()
    if not nm:
        return '', ''
    nm = nm.replace('.', '->')
    if '->' not in nm:
        b = _strip_dollar(nm)
        if this_obj and b in ('this', '$this'):
            b = this_obj
        return b, ''
    parts = [p for p in nm.split('->') if p]
    if len(parts) < 2:
        b = _strip_dollar(parts[0] if parts else '')
        if this_obj and b in ('this', '$this'):
            b = this_obj
        return b, ''
    b = _strip_dollar(parts[0])
    if this_obj and b in ('this', '$this'):
        b = this_obj
    return b, parts[-1]


def _is_this_rewritten_prop(taint) -> bool:
    """Return True if the property was rewritten from `this` with a known call seq."""
    if not isinstance(taint, dict):
        return False
    if not (taint.get('_this_obj') or '').strip():
        return False
    s = taint.get('_this_call_seq')
    try:
        return s is not None and int(s) > 0
    except Exception:
        return False


def _this_call_seq_value(taint) -> Optional[int]:
    if not isinstance(taint, dict):
        return None
    s = taint.get('_this_call_seq')
    if s is None:
        return None
    try:
        si = int(s)
    except Exception:
        return None
    return int(si) if int(si) > 0 else None


def _is_this_prop_expr(taint) -> bool:
    if not isinstance(taint, dict):
        return False
    base = (taint.get('base') or '').strip()
    if base in ('this', '$this'):
        return True
    nm = (taint.get('name') or '').replace('.', '->').strip()
    return bool(nm.startswith(('this->', '$this->', 'this[', '$this[', 'this.', '$this.')))


def _start_seq_for_scope(taint) -> Optional[int]:
    """Choose a representative starting seq for scope search for a property taint."""
    if not isinstance(taint, dict):
        return None
    start_seq = None
    try:
        start_seq = int(taint.get('seq'))
    except Exception:
        start_seq = None
    s2 = _this_call_seq_value(taint)
    if s2 is not None:
        start_seq = int(s2)
    return start_seq


def _method_call_recv_name(call_id: int, nodes, children_of) -> Tuple[str, str]:
    """Return `(receiver_name, method_name)` extracted from an `AST_METHOD_CALL` node."""
    def recv_name(expr_id: int) -> str:
        nx = nodes.get(expr_id) or {}
        tt = (nx.get('type') or '').strip()
        if tt == 'AST_VAR':
            ss = get_string_children(expr_id, children_of, nodes)
            v = ss[0][1] if ss else ''
            if v:
                return v
        if tt in ('AST_PROP', 'AST_DIM'):
            v = (find_first_var_string(expr_id, children_of, nodes) or '').strip()
            if v:
                return v
        v = (nx.get('code') or nx.get('name') or '').strip()
        if v.startswith('$'):
            v = v[1:]
        if '->' in v:
            v = v.split('->', 1)[0].strip()
        if '(' in v:
            v = v.split('(', 1)[0].strip()
        return v

    recv = ''
    name = ''
    ch = list(children_of.get(call_id, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    for c in ch:
        nx = nodes.get(c) or {}
        if not recv and nx.get('type') not in ('AST_ARG_LIST',) and nx.get('labels') != 'string' and nx.get('type') != 'string':
            recv = recv_name(int(c))
        if not name and (nx.get('labels') == 'string' or nx.get('type') == 'string'):
            v = (nx.get('code') or nx.get('name') or '').strip()
            if v:
                name = v
        if recv and name:
            break
    return _strip_dollar(recv), name


def _prop_base_prop(prop_id: int, nodes, children_of) -> Tuple[str, str]:
    """Return `(base_var, prop_name)` extracted from an `AST_PROP` node."""
    base = ''
    prop = ''
    ch = list(children_of.get(prop_id, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    for c in ch:
        nx = nodes.get(c) or {}
        if not base and nx.get('type') == 'AST_VAR':
            ss = get_string_children(c, children_of, nodes)
            base = ss[0][1] if ss else ''
        if not prop and (nx.get('labels') == 'string' or nx.get('type') == 'string'):
            v = (nx.get('code') or nx.get('name') or '').strip()
            if v:
                prop = v
        if base and prop:
            break
    return _strip_dollar(base), prop


def _scope_has_this_prop(loc_taints, ctx, *, prop: str) -> bool:
    """Return True if any TRACE_LOC taint in scope contains `this->prop` access."""
    if not prop:
        return False
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    for lt in loc_taints or []:
        try:
            s = int((lt or {}).get('seq'))
        except Exception:
            continue
        idx = seq_to_idx.get(s)
        if not isinstance(idx, int) or idx < 0 or idx >= len(recs):
            continue
        rec = recs[idx] or {}
        for nid in rec.get('node_ids') or []:
            nx = nodes.get(nid) or {}
            if nx.get('type') != 'AST_PROP':
                continue
            b, p = _prop_base_prop(int(nid), nodes, children_of)
            if b == 'this' and p == prop:
                return True
    return False


def _min_seq_from_rec(rec) -> Optional[int]:
    """Return the minimum seq of a trace index record, if present."""
    seqs = (rec or {}).get('seqs') or []
    if not seqs:
        return None
    try:
        return int(min(int(x) for x in seqs))
    except Exception:
        return None


def _collect_method_calls_from_recs(recs, nodes, children_of, *, recv: str) -> List[Tuple[int, int]]:
    """Collect `(call_id, call_seq)` method calls in records whose receiver matches `recv`."""
    out = []
    seen = set()
    want = (recv or '').strip()
    if not want:
        return out
    for rec in recs or []:
        call_seq = _min_seq_from_rec(rec)
        if call_seq is None:
            continue
        for nid in (rec or {}).get('node_ids') or []:
            nx = nodes.get(nid) or {}
            if (nx.get('type') or '').strip() != 'AST_METHOD_CALL':
                continue
            try:
                call_id = int(nid)
            except Exception:
                continue
            if call_id in seen:
                continue
            r, _ = _method_call_recv_name(call_id, nodes, children_of)
            if r != want:
                continue
            seen.add(call_id)
            out.append((call_id, call_seq))
    return out


def _collect_this_method_calls_from_loc_taints(
    loc_taints,
    ctx,
    *,
    seen_call_ids: Set[int],
    scope_min_seq: Optional[int] = None,
    scope_max_seq: Optional[int] = None,
    ref_seq: Optional[int] = None,
) -> List[Tuple[int, int]]:
    """Collect `(call_id, call_seq)` for `this` receiver calls near TRACE_LOC taints."""
    out = []
    seen_local = set()
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
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
            s = int((lt or {}).get('seq'))
        except Exception:
            continue
        idx = seq_to_idx.get(s)
        if not isinstance(idx, int) or idx < 0 or idx >= len(recs):
            continue
        rec = recs[idx] or {}
        call_seq = int(s)
        call_path = (rec.get('path') or '').strip()
        call_line = rec.get('line')
        try:
            call_line_i = int(call_line) if call_line is not None else None
        except Exception:
            call_line_i = None
        for nid in rec.get('node_ids') or []:
            nx = nodes.get(nid) or {}
            if (nx.get('type') or '').strip() != 'AST_METHOD_CALL':
                continue
            try:
                call_id = int(nid)
            except Exception:
                continue
            if call_id in seen_call_ids or call_id in seen_local:
                continue
            r, _ = _method_call_recv_name(call_id, nodes, children_of)
            if r != 'this':
                continue
            if (
                pick_seq_by_ref is not None
                and groups_by_loc is not None
                and call_path
                and call_line_i is not None
                and ref_seq is not None
            ):
                groups_all = list(groups_by_loc.get((call_path, int(call_line_i))) or [])
                if groups_all:
                    groups = groups_all
                    if scope_min_seq is not None or scope_max_seq is not None:
                        g2 = []
                        for g in groups_all:
                            try:
                                gmin = int(g.get('min'))
                                gmax = int(g.get('max'))
                            except Exception:
                                continue
                            if scope_min_seq is not None and gmax < int(scope_min_seq):
                                continue
                            if scope_max_seq is not None and gmin > int(scope_max_seq):
                                continue
                            g2.append(g)
                        if g2:
                            groups = g2
                    picked = pick_seq_by_ref(groups, int(ref_seq), prefer='backward')
                    if picked is not None:
                        call_seq = int(picked)
            seen_local.add(call_id)
            out.append((call_id, call_seq))
    return out


def _expand_method_call_scope(call_id: int, call_seq: int, ctx, *, debug_key: str) -> Tuple[List[str], List[dict], dict]:
    """Expand a method call taint to its scope locators and trace-location taints."""
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    parent_of = ctx.get('parent_of') or {}
    top_id_to_file = ctx.get('top_id_to_file') or {}
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    calls_edges_union = ctx.get('calls_edges_union')
    dbg_local = {'_': []}
    dbg_ctx = ctx.get('debug')
    if isinstance(dbg_ctx, dict):
        dbg_local = dbg_ctx
    ctx2 = {
        'nodes': nodes,
        'children_of': children_of,
        'parent_of': parent_of,
        'top_id_to_file': top_id_to_file,
        'trace_index_records': recs,
        'trace_seq_to_index': seq_to_idx,
        'calls_edges_union': calls_edges_union,
        'debug': dbg_local,
        'result_set': [],
        'llm_enabled': bool(ctx.get('llm_enabled')),
        '_llm_disable_nested_this_calls': True,
    }
    call_taint = {'id': int(call_id), 'type': 'AST_METHOD_CALL', 'seq': int(call_seq)}
    call_res = ast_method_call.process_call_like(call_taint, ctx2, debug_key=debug_key)
    loc_taints = call_res[0] if (isinstance(call_res, list) and call_res and isinstance(call_res[0], list)) else []
    scope_locs = []
    seen = set()
    for lt in loc_taints or []:
        if not isinstance(lt, dict):
            continue
        p = (lt.get('path') or '').strip()
        ln = lt.get('line')
        if not p or ln is None:
            continue
        try:
            ln_i = int(ln)
        except Exception:
            continue
        loc = f"{p}:{ln_i}"
        if loc in seen:
            continue
        seen.add(loc)
        seq = lt.get('seq')
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        item = {'path': p, 'line': ln_i, 'loc': loc}
        if seq_i is not None:
            item['seq'] = int(seq_i)
        scope_locs.append(item)
    return scope_locs, loc_taints, ctx2


def _build_scope_tree_for_calls(calls, ctx, *, target_prop: str, seen_call_ids: Set[int]) -> List[dict]:
    """Build a call-scope tree by recursively expanding `this`-receiver method calls."""
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
        scope_locs, loc_taints, _ = _expand_method_call_scope(cid, csq, ctx, debug_key='ast_prop_expand')
        node = {
            'call_id': cid,
            'call_seq': csq,
            'scope_locs': scope_locs,
            'loc_taints': loc_taints,
            'children': [],
            'has_target': _scope_has_this_prop(loc_taints, ctx, prop=target_prop),
        }
        if loc_taints:
            smin = None
            smax = None
            for lt in loc_taints:
                try:
                    ss = int((lt or {}).get('seq'))
                except Exception:
                    continue
                if smin is None or ss < smin:
                    smin = ss
                if smax is None or ss > smax:
                    smax = ss
            next_calls = _collect_this_method_calls_from_loc_taints(
                loc_taints,
                ctx,
                seen_call_ids=seen_call_ids,
                scope_min_seq=smin,
                scope_max_seq=smax,
                ref_seq=(ctx.get('_llm_ref_seq') or ctx.get('input_seq')),
            )
            if next_calls:
                node['children'] = _build_scope_tree_for_calls(next_calls, ctx, target_prop=target_prop, seen_call_ids=seen_call_ids)
        out.append(node)
    return out


def _prune_scope_tree(node, *, target_prop: str) -> bool:
    """Prune a scope tree in place to keep only branches that reach the target prop."""
    keep = bool(node.get('has_target'))
    kept_children = []
    for ch in node.get('children') or []:
        if _prune_scope_tree(ch, target_prop=target_prop):
            kept_children.append(ch)
            keep = True
    node['children'] = kept_children
    node['has_target'] = keep
    return keep


def _collect_kept_scope_locs(node, out: List[str]) -> None:
    """Collect scope locators from kept children into `out` (depth-first)."""
    for ch in node.get('children') or []:
        for loc in ch.get('scope_locs') or []:
            out.append(loc)
        _collect_kept_scope_locs(ch, out)


def _collect_scope_markers(node, out: List[dict]) -> None:
    """Collect `FUNCTION_SCOPE_START/END` marker locators from a scope tree."""
    for ch in node.get('children') or []:
        scope = ch.get('scope_locs') or []
        if scope:
            st = scope[0]
            ed = scope[-1]
            st_loc = st.get('loc') if isinstance(st, dict) else (st if isinstance(st, str) else None)
            ed_loc = ed.get('loc') if isinstance(ed, dict) else (ed if isinstance(ed, str) else None)
            if st_loc and ed_loc:
                out.append({'kind': 'function_scope', 'start': st_loc, 'end': ed_loc})
        _collect_scope_markers(ch, out)


def _count_tree_nodes(node) -> int:
    """Return the number of nodes in the scope tree (excluding the root)."""
    n = 0
    for ch in node.get('children') or []:
        n += 1
        n += _count_tree_nodes(ch)
    return n


def _collect_initial_scope_from_start(
    *,
    start_idx: int,
    funcid: int,
    ctx: dict,
) -> Tuple[List[dict], List[str], dict]:
    if not isinstance(ctx, dict):
        return [], [], {}
    nodes = ctx.get('nodes') or {}
    recs = ctx.get('trace_index_records') or []
    if not isinstance(start_idx, int) or start_idx < 0 or start_idx >= len(recs):
        return [], [], {}
    try:
        funcid_i = int(funcid)
    except Exception:
        return [], [], {}

    stop_id = ast_var.find_toplevel_stop_id(funcid_i, nodes)
    scope_recs = []
    locs = []
    stop_by = 'file_head'
    stop_index = None
    for i in range(int(start_idx), -1, -1):
        rec = recs[i] or {}
        node_ids = rec.get('node_ids') or []
        cur_id = node_ids[0] if node_ids else None
        cur_funcid = (nodes.get(cur_id) or {}).get('funcid') if cur_id is not None else None
        if cur_funcid == funcid_i:
            scope_recs.append(rec)
            p = (rec.get('path') or '').strip()
            ln = rec.get('line')
            if p and ln is not None:
                try:
                    locs.append(f"{p}:{int(ln)}")
                except Exception:
                    pass
        if cur_id is not None and cur_id == funcid_i:
            stop_by = 'funcid'
            stop_index = int(i)
            break
        if cur_id is not None and stop_id is not None and cur_id == stop_id:
            stop_by = 'toplevel_stop'
            stop_index = int(i)
            break

    locs = ast_var.compress_consecutive(locs)
    return scope_recs, locs, {'stop_by': stop_by, 'stop_index': stop_index}


def expand_receiver_method_scopes(
    *,
    start_seq: int,
    ctx: dict,
    recv_obj: str,
    target_prop: str,
    max_depth: Optional[int] = None,
) -> Tuple[List[str], List[dict], dict]:
    base_locs, kept_locs, root, stats = this_scope.expand_receiver_method_scopes(
        start_seq=int(start_seq),
        ctx=ctx,
        recv_obj=recv_obj,
        target_prop=target_prop,
        include_this_calls_in_base_scope=False,
        prune_to_target=True,
        debug_key='ast_prop_expand',
    )
    markers = []
    if isinstance(root, dict):
        this_scope.collect_scope_markers(root, markers)
    merged = list(base_locs or []) + list(kept_locs or [])
    return merged, markers, stats


def process(taint, ctx):
    """Expand an `AST_PROP` taint by collecting backward scope and receiver method scopes."""
    if not isinstance(taint, dict) or not isinstance(ctx, dict):
        return []
    if isinstance(ctx, dict):
        ctx['_llm_scope_prefer'] = 'backward'

    ast_var.record_taint_source(taint, ctx)

    obj, prop = _parse_obj_prop(taint)

    orig_seq = None
    try:
        orig_seq = int(taint.get('seq'))
    except Exception:
        orig_seq = None

    this_call_seq = _this_call_seq_value(taint)
    start_seq = _start_seq_for_scope(taint)
    if start_seq is None:
        return []
    if isinstance(ctx, dict):
        ctx['_llm_ref_seq'] = int(start_seq)

    ast_var.ensure_trace_index(ctx)
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    start_idx = seq_to_idx.get(start_seq)
    if start_idx is None:
        return []

    nodes = ctx.get('nodes') or {}
    node_ids0 = (recs[start_idx] or {}).get('node_ids') or []
    cur0 = node_ids0[0] if node_ids0 else None
    funcid = (nodes.get(cur0) or {}).get('funcid') if cur0 is not None else None
    if funcid is None:
        nid = taint.get('id')
        funcid = (nodes.get(nid) or {}).get('funcid') if nid is not None else None
    if funcid is None:
        return []
    children_of = ctx.get('children_of') or {}
    dbg_ctx = ctx.get('debug')
    dbg = None
    if isinstance(dbg_ctx, dict):
        dbg = dbg_ctx.setdefault('ast_prop', [])

    scope_recs, results, stop_info = _collect_initial_scope_from_start(start_idx=int(start_idx), funcid=int(funcid), ctx=ctx)
    ctx.setdefault('result_set', [])
    ctx['result_set'].extend(results)

    if not obj or not prop:
        return []

    kept_locs = []
    root = None
    added = 0
    base_locs = []
    include_this_calls = bool(this_scope.is_this_receiver_taint(taint))
    if obj and prop:
        base_locs, kept_locs, root, scope_stats = this_scope.expand_receiver_method_scopes(
            start_seq=int(start_seq),
            ctx=ctx,
            recv_obj=obj,
            target_prop=prop,
            include_this_calls_in_base_scope=include_this_calls,
            prune_to_target=True,
            debug_key='ast_prop_expand',
        )
        if ctx.get('llm_enabled'):
            try:
                from .llm_prop_scope import collect_prop_call_scopes

                ctx['_llm_prop_call_scopes_info'] = collect_prop_call_scopes(root, ctx, this_obj=obj)
            except Exception:
                ctx.pop('_llm_prop_call_scopes_info', None)
        else:
            ctx.pop('_llm_prop_call_scopes_info', None)
    else:
        scope_stats = {}
        ctx.pop('_llm_prop_call_scopes_info', None)

    extra = ctx.setdefault('_llm_extra_prompt_locs', [])
    existing = set()
    for x in extra or []:
        if isinstance(x, dict):
            lk = x.get('loc')
            if lk:
                seq = x.get('seq')
                try:
                    seq_i = int(seq) if seq is not None else None
                except Exception:
                    seq_i = None
                existing.add((lk, int(seq_i)) if seq_i is not None else lk)
        elif isinstance(x, str) and x:
            existing.add(x)
    added = 0
    for loc in kept_locs:
        lk = loc.get('loc') if isinstance(loc, dict) else (loc if isinstance(loc, str) else None)
        if not lk:
            continue
        seq = loc.get('seq') if isinstance(loc, dict) else None
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        key = (lk, int(seq_i)) if seq_i is not None else lk
        if key in existing:
            continue
        existing.add(key)
        extra.append(loc)
        added += 1

    markers = []
    if root is not None:
        this_scope.collect_scope_markers(root, markers)
    if markers:
        ctx.setdefault('_llm_scope_markers', []).extend(markers)
    if dbg is not None:
        dbg.append(
            {
                'obj': obj,
                'prop': prop,
                'start_seq': int(start_seq),
                'stop_by': stop_info.get('stop_by'),
                'stop_index': stop_info.get('stop_index'),
                'recv_for_calls': obj,
                'base_scope_unique': int(len(base_locs or [])),
                'expanded_scope_nodes': int(this_scope.count_tree_nodes(root)) if root is not None else 0,
                'kept_locs_total': int(len(kept_locs)),
                'kept_locs_unique': int(_count_unique_locs(kept_locs)),
                'kept_scopes_added': int(added),
                'include_this_calls_in_base_scope': bool(include_this_calls),
                'scope_stats': scope_stats,
            }
        )
    lg = ctx.get('logger')
    if lg is not None:
        try:
            lg.debug(
                'ast_prop_expand',
                obj=obj,
                prop=prop,
                start_seq=int(start_seq),
                base_scope_unique=len(base_locs or []),
                expanded_scope_nodes=int(this_scope.count_tree_nodes(root)) if root is not None else 0,
                kept_locs_unique=int(_count_unique_locs(kept_locs)),
                kept_scopes_added=int(added),
                include_this_calls_in_base_scope=bool(include_this_calls),
            )
        except Exception:
            pass

    return []


def tmp_print_ast_prop_scope(taint, ctx, *, max_depth: int = 6) -> dict:
    block, stats = tmp_render_ast_prop_scope_block(taint, ctx, max_depth=max_depth)
    if block:
        print(block)
    return stats


def tmp_render_ast_prop_scope_block(taint, ctx, *, max_depth: int = 6) -> Tuple[str, dict]:
    if not isinstance(taint, dict) or not isinstance(ctx, dict):
        return '', {}
    obj, prop = _parse_obj_prop(taint)
    start_seq = _start_seq_for_scope(taint)
    if start_seq is None:
        return '', {}

    ast_var.ensure_trace_index(ctx)
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    start_idx = seq_to_idx.get(int(start_seq))
    if not isinstance(start_idx, int) or start_idx < 0 or start_idx >= len(recs):
        return '', {}

    nodes = ctx.get('nodes') or {}
    node_ids0 = (recs[start_idx] or {}).get('node_ids') or []
    cur0 = node_ids0[0] if node_ids0 else None
    funcid = (nodes.get(cur0) or {}).get('funcid') if cur0 is not None else None
    if funcid is None:
        nid = taint.get('id')
        funcid = (nodes.get(nid) or {}).get('funcid') if nid is not None else None
    if funcid is None:
        return '', {}

    children_of = ctx.get('children_of') or {}
    scope_recs, initial_locs, stop_info = _collect_initial_scope_from_start(start_idx=int(start_idx), funcid=int(funcid), ctx=ctx)
    initial_calls = _collect_method_calls_from_recs(scope_recs, nodes, children_of, recv=obj)

    root = {
        'call_id': None,
        'call_seq': int(start_seq),
        'scope_locs': list(initial_locs),
        'loc_taints': [{'type': 'TRACE_LOC', 'seq': _min_seq_from_rec(r)} for r in scope_recs if _min_seq_from_rec(r) is not None],
        'children': [],
        'has_target': False,
    }
    seen_call_ids: Set[int] = set()
    root['children'] = _build_scope_tree_for_calls(
        initial_calls,
        ctx,
        target_prop=prop,
        seen_call_ids=seen_call_ids,
    )
    for ch in list(root.get('children') or []):
        _prune_scope_tree(ch, target_prop=prop)
    root['children'] = [ch for ch in (root.get('children') or []) if ch.get('has_target')]

    kept_locs = []
    _collect_kept_scope_locs(root, kept_locs)
    markers = []
    _collect_scope_markers(root, markers)

    locs = []
    seen = set()
    for x in list(initial_locs) + list(kept_locs):
        if not x:
            continue
        k = x.get('loc') if isinstance(x, dict) else x
        if not k or k in seen:
            continue
        seen.add(k)
        locs.append(x)
    stats = {
        'obj': obj,
        'prop': prop,
        'start_seq': int(start_seq),
        'funcid': int(funcid),
        'stop_by': stop_info.get('stop_by'),
        'stop_index': stop_info.get('stop_index'),
        'initial_calls_count': int(len(initial_calls)),
        'expanded_scope_nodes': int(_count_tree_nodes(root)),
        'kept_locs_total': int(len(kept_locs)),
        'kept_locs_unique': int(_count_unique_locs(kept_locs)),
        'locs_total': int(len(locs)),
        'markers_count': int(len(markers)),
    }

    try:
        from llm_utils.prompts.prompt_utils import locs_to_seq_code_block
    except Exception:
        locs_to_seq_code_block = None

    header = f'AST_PROP {obj}->{prop} start_seq={int(start_seq)}'
    if locs_to_seq_code_block is not None:
        ctx2 = dict(ctx)
        ctx2['_llm_scope_markers'] = list(markers)
        ctx2['_llm_ref_seq'] = int(start_seq)
        prefer = (ctx.get('_llm_scope_prefer') or 'backward').strip() or 'backward'
        block = locs_to_seq_code_block(locs, ctx2, prefer=prefer)
        return (header + '\n' + block + '\n') if block else (header + '\n'), stats
    return (header + '\n' + '\n'.join(locs) + '\n'), stats
