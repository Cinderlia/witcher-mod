"""
Taint handler for `AST_VAR` nodes.

This handler scans trace index records backward within the same function scope and
collects trace locations likely affecting the current variable taint.
"""

import os
from typing import List
from common.app_config import load_app_config
from utils.trace_utils.trace_edges import build_trace_index_records
from utils.cpg_utils.graph_mapping import (
    build_funcid_to_call_ids,
    find_nearest_callsite_locator,
    find_nearest_callsite_record,
    read_calls_edges_union,
)

_LAST_TRACE_CTX = None
 
def record_taint_source(taint, ctx):
    """Record the current taint's normalized source string into `ctx['taint_sources']`."""
    if not isinstance(ctx, dict) or not isinstance(taint, dict):
        return
    tt = (taint.get('type') or '').strip()
    if not tt:
        return
    this_obj = (taint.get('_this_obj') or '').strip()
    if this_obj.startswith('$'):
        this_obj = this_obj[1:]
    def rewrite_this(s: str) -> str:
        if not this_obj:
            return (s or '').strip()
        v = (s or '').strip()
        if not v:
            return v
        if v == 'this':
            return this_obj
        if v.startswith('this->'):
            return this_obj + v[4:]
        if v.startswith('this['):
            return this_obj + v[4:]
        return v
    src = ''
    if tt == 'AST_VAR':
        src = rewrite_this(taint.get('name') or '')
    elif tt == 'AST_PROP':
        base = rewrite_this(taint.get('base') or '')
        prop = (taint.get('prop') or '').strip()
        if base and prop:
            src = f"{base}->{prop}"
        else:
            nm = rewrite_this(taint.get('name') or '')
            src = nm.replace('.', '->') if nm and '->' not in nm else nm
    elif tt == 'AST_DIM':
        base = rewrite_this(taint.get('base') or '')
        key = (taint.get('key') or '').strip()
        if base and key:
            src = f"{base}[{key}]"
        else:
            src = rewrite_this(taint.get('name') or '')
    elif tt == 'AST_METHOD_CALL':
        recv = rewrite_this(taint.get('recv') or '')
        name = (taint.get('name') or '').strip()
        if name.endswith('()'):
            name = name[:-2]
        if recv and name:
            src = f"{recv}->{name}()"
        elif name:
            src = name if name.endswith('()') else f"{name}()"
    elif tt == 'AST_CALL':
        name = (taint.get('name') or '').strip()
        if name:
            src = name if name.endswith('()') else f"{name}()"
    else:
        src = rewrite_this(taint.get('name') or '')
    if not src:
        return
    seen = ctx.setdefault('_taint_sources_seen', set())
    key = (tt, src)
    if key in seen:
        return
    seen.add(key)
    ctx.setdefault('taint_sources', []).append({'type': tt, 'source': src})

def build_seq_to_index(trace_index_records):
    """Build a mapping from trace seq -> trace_index_records index."""
    m = {}
    for rec in trace_index_records:
        idx = rec.get('index')
        for s in rec.get('seqs') or []:
            if s not in m:
                m[s] = idx
    return m

def ensure_trace_index(ctx):
    """Ensure trace index records exist in ctx (builds them from `trace.log` and `nodes.csv`)."""
    global _LAST_TRACE_CTX
    _LAST_TRACE_CTX = ctx
    recs = ctx.get('trace_index_records')
    if recs is not None:
        return recs
    cfg = load_app_config(argv=(ctx.get('argv') if isinstance(ctx, dict) else None))
    trace_path = (ctx.get('trace_path') if isinstance(ctx, dict) else None) or cfg.find_input_file('trace.log')
    nodes_path = (ctx.get('nodes_path') if isinstance(ctx, dict) else None) or cfg.find_input_file('nodes.csv')
    recs = build_trace_index_records(trace_path, nodes_path, None)
    ctx['trace_index_records'] = recs
    ctx['trace_seq_to_index'] = build_seq_to_index(recs)
    return recs

def compress_consecutive(items):
    """Remove consecutive duplicates from an ordered list."""
    out = []
    prev = None
    for it in items:
        if it == prev:
            continue
        out.append(it)
        prev = it
    ctx = _LAST_TRACE_CTX if isinstance(_LAST_TRACE_CTX, dict) else None
    if ctx is not None and out and all(isinstance(x, str) for x in out):
        try:
            from ..helpers.ast_var_include import expand_includes_in_locs

            extra_locs, _ = expand_includes_in_locs(locs=list(out), ctx=ctx)
            if extra_locs:
                out = list(out) + list(extra_locs)
        except Exception:
            pass
    return out

def find_toplevel_stop_id(funcid, nodes):
    """Find a stable stop node id for a function scope when lineno starts at 1."""
    fn = nodes.get(funcid) or {}
    if fn.get('lineno') != 1:
        return None
    best = None
    best_line = None
    for nid, nx in nodes.items():
        if nx.get('funcid') != funcid:
            continue
        ln = nx.get('lineno')
        if ln is None or ln == 1:
            continue
        if best is None or ln < best_line or (ln == best_line and nid < best):
            best = nid
            best_line = ln
    return best

def _collect_scope_recs_and_locs_raw(*, start_idx: int, funcid: int, ctx: dict):
    nodes = ctx.get('nodes') or {}
    ensure_trace_index(ctx)
    recs = ctx.get('trace_index_records') or []
    if not isinstance(start_idx, int) or start_idx < 0 or start_idx >= len(recs):
        return [], [], {'stop_by': None, 'stop_index': None, 'stop_loc': None}
    if funcid is None:
        return [], [], {'stop_by': None, 'stop_index': None, 'stop_loc': None}
    try:
        funcid_i = int(funcid)
    except Exception:
        return [], [], {'stop_by': None, 'stop_index': None, 'stop_loc': None}

    stop_id = find_toplevel_stop_id(funcid_i, nodes)
    scope_recs = []
    locs = []
    stop_by = None
    stop_index = None
    stop_loc = None
    def _record_contains_node(rec: dict, target_id: int) -> bool:
        for nid in (rec.get('node_ids') or []):
            try:
                if int(nid) == int(target_id):
                    return True
            except Exception:
                continue
        return False

    def _record_has_funcid(rec: dict, target_funcid: int) -> bool:
        for nid in (rec.get('node_ids') or []):
            try:
                nid_i = int(nid)
            except Exception:
                continue
            cur_funcid = (nodes.get(nid_i) or {}).get('funcid')
            try:
                if cur_funcid is not None and int(cur_funcid) == int(target_funcid):
                    return True
            except Exception:
                continue
        return False

    def _record_has_return_in_func(rec: dict, target_funcid: int) -> bool:
        for nid in (rec.get('node_ids') or []):
            try:
                nid_i = int(nid)
            except Exception:
                continue
            nx = nodes.get(nid_i) or {}
            cur_funcid = nx.get('funcid')
            ntype = (nx.get('type') or '').strip()
            try:
                if cur_funcid is not None and int(cur_funcid) == int(target_funcid) and ntype == 'AST_RETURN':
                    return True
            except Exception:
                continue
        return False

    # Backward walk across recursive frames:
    # each nested frame contributes RETURN before its function-entry marker.
    recursion_depth = 0

    for i in range(int(start_idx), -1, -1):
        rec = recs[i]
        if _record_has_return_in_func(rec, funcid_i):
            recursion_depth += 1
        if _record_has_funcid(rec, funcid_i):
            scope_recs.append(rec)
            p = (rec.get('path') or '').strip()
            ln = rec.get('line')
            if p and ln is not None:
                try:
                    locs.append(f"{p}:{int(ln)}")
                except Exception:
                    pass
        if _record_contains_node(rec, funcid_i):
            if recursion_depth > 0:
                recursion_depth -= 1
            else:
                stop_by = 'funcid'
                stop_index = int(i)
                p = (rec.get('path') or '').strip()
                ln = rec.get('line')
                if p and ln is not None:
                    try:
                        stop_loc = f"{p}:{int(ln)}"
                    except Exception:
                        stop_loc = None
                break
        if stop_id is not None and _record_contains_node(rec, int(stop_id)):
            if recursion_depth > 0:
                continue
            stop_by = 'toplevel_stop'
            stop_index = int(i)
            break
    return scope_recs, locs, {'stop_by': stop_by, 'stop_index': stop_index, 'stop_loc': stop_loc}

def _filter_scope_locs(locs: List[str], ctx: dict):
    if not locs or not isinstance(ctx, dict):
        return list(locs or [])
    try:
        from ..helpers.ast_var_include import _filter_define_locs_from_include, _filter_func_def_locs_from_include
    except Exception:
        return list(locs)
    nodes = ctx.get('nodes') or {}
    recs = ctx.get('trace_index_records') or []
    locs2 = _filter_func_def_locs_from_include(list(locs), recs, nodes, ctx)
    children_of = ctx.get('children_of') or {}
    parent_of = ctx.get('parent_of') or {}
    return _filter_define_locs_from_include(locs2, recs, nodes, children_of, parent_of, ctx)

def _extend_include_scope_from_file_head(*, stop_index: int, funcid: int, ctx: dict) -> List[str]:
    if not isinstance(ctx, dict):
        return []
    recs = ctx.get('trace_index_records') or []
    nodes = ctx.get('nodes') or {}
    if not isinstance(stop_index, int) or stop_index <= 0 or stop_index >= len(recs):
        return []
    rec = recs[int(stop_index) - 1] or {}
    try:
        from ..helpers.ast_var_include import is_include_record, include_record_funcid
    except Exception:
        return []
    if not is_include_record(rec, nodes):
        return []
    inc_funcid = include_record_funcid(rec, nodes)
    if inc_funcid is None:
        return []
    try:
        if funcid is not None and int(inc_funcid) == int(funcid):
            return []
    except Exception:
        pass
    seen = ctx.setdefault('_ast_include_extend_seen', set())
    key = (int(stop_index) - 1, int(inc_funcid))
    if key in seen:
        return []
    depth = ctx.get('_ast_include_extend_depth', 0)
    try:
        depth_i = int(depth)
    except Exception:
        depth_i = 0
    if depth_i >= 6:
        return []
    seen.add(key)
    ctx['_ast_include_extend_depth'] = depth_i + 1
    try:
        _, locs2, stop_info2 = _collect_scope_recs_and_locs_raw(
            start_idx=int(stop_index) - 1,
            funcid=int(inc_funcid),
            ctx=ctx,
        )
        stop_by2 = stop_info2.get('stop_by')
        stop_index2 = stop_info2.get('stop_index')
        if stop_by2 == 'toplevel_stop' and isinstance(stop_index2, int):
            extra = _extend_include_scope_from_file_head(stop_index=stop_index2, funcid=int(inc_funcid), ctx=ctx)
            if extra:
                locs2.extend(extra)
        return locs2
    finally:
        ctx['_ast_include_extend_depth'] = depth_i

def _extend_include_scope_from_includer(*, start_index: int, included_path: str, ctx: dict) -> List[str]:
    if not isinstance(ctx, dict):
        return []
    recs = ctx.get('trace_index_records') or []
    nodes = ctx.get('nodes') or {}
    if not isinstance(start_index, int) or start_index <= 0 or start_index >= len(recs):
        return []
    included_path = (included_path or '').strip()
    if not included_path:
        return []
    try:
        from ..helpers.ast_var_include import include_record_funcid, is_include_record
    except Exception:
        return []
    depth = ctx.get('_ast_include_includer_depth', 0)
    try:
        depth_i = int(depth)
    except Exception:
        depth_i = 0
    if depth_i >= 6:
        return []
    ctx['_ast_include_includer_depth'] = depth_i + 1
    try:
        seen = ctx.setdefault('_ast_include_includer_seen', set())
        for i in range(int(start_index) - 1, -1, -1):
            rec = recs[i] or {}
            p = (rec.get('path') or '').strip()
            if not p:
                continue
            if p == included_path:
                continue
            nxt = recs[i + 1] or {}
            p_next = (nxt.get('path') or '').strip()
            if p_next != included_path:
                continue
            if not is_include_record(rec, nodes):
                continue
            inc_funcid = include_record_funcid(rec, nodes)
            if inc_funcid is None:
                continue
            try:
                inc_funcid_i = int(inc_funcid)
            except Exception:
                continue
            key = (int(i), int(inc_funcid_i), included_path)
            if key in seen:
                continue
            seen.add(key)
            _, locs2, stop_info2 = _collect_scope_recs_and_locs_raw(
                start_idx=int(i),
                funcid=int(inc_funcid_i),
                ctx=ctx,
            )
            stop_by2 = stop_info2.get('stop_by')
            stop_index2 = stop_info2.get('stop_index')
            if stop_by2 == 'toplevel_stop' and isinstance(stop_index2, int):
                extra = _extend_include_scope_from_file_head(stop_index=int(stop_index2), funcid=int(inc_funcid_i), ctx=ctx)
                if extra:
                    locs2.extend(extra)
            locs3 = _extend_include_scope_from_includer(start_index=int(i), included_path=p, ctx=ctx)
            if locs3:
                locs2.extend(locs3)
            return locs2
        return []
    finally:
        ctx['_ast_include_includer_depth'] = depth_i

def collect_scope_recs_and_locs(*, start_idx: int, funcid: int, ctx: dict):
    scope_recs, locs, stop_info = _collect_scope_recs_and_locs_raw(start_idx=start_idx, funcid=funcid, ctx=ctx)
    nodes = ctx.get('nodes') if isinstance(ctx, dict) else {}
    has_include_in_scope = False
    if isinstance(nodes, dict):
        for rec in scope_recs or []:
            for nid in (rec.get('node_ids') or []):
                try:
                    nid_i = int(nid)
                except Exception:
                    continue
                if ((nodes.get(nid_i) or {}).get('type') or '').strip() == 'AST_INCLUDE_OR_EVAL':
                    has_include_in_scope = True
                    break
            if has_include_in_scope:
                break
    stop_by = stop_info.get('stop_by')
    stop_index = stop_info.get('stop_index')
    if has_include_in_scope and stop_by == 'toplevel_stop' and isinstance(stop_index, int):
        extra = _extend_include_scope_from_file_head(stop_index=int(stop_index), funcid=int(funcid), ctx=ctx)
        if extra:
            locs.extend(extra)
    recs = ctx.get('trace_index_records') if isinstance(ctx, dict) else None
    if has_include_in_scope and isinstance(recs, list) and isinstance(start_idx, int) and 0 <= int(start_idx) < len(recs):
        try:
            p0 = ((recs[int(start_idx)] or {}).get('path') or '').strip()
        except Exception:
            p0 = ''
        if p0:
            extra2 = _extend_include_scope_from_includer(start_index=int(start_idx), included_path=p0, ctx=ctx)
            if extra2:
                locs.extend(extra2)
    locs = compress_consecutive(locs)
    locs = _filter_scope_locs(locs, ctx)
    return scope_recs, locs, stop_info

def process(taint, ctx):
    """Expand an `AST_VAR` taint by collecting prior trace locations in the same function."""
    nid = taint.get('id')
    seq = taint.get('seq')
    if nid is None or seq is None:
        return []
    if isinstance(ctx, dict):
        ctx['_llm_scope_prefer'] = 'backward'
    record_taint_source(taint, ctx)

    nodes = ctx.get('nodes') or {}
    ensure_trace_index(ctx)
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    start_seq = None
    try:
        start_seq = int(seq)
    except Exception:
        start_seq = None
    if isinstance(taint, dict) and (taint.get('_this_obj') or '').strip():
        s2 = taint.get('_this_call_seq')
        try:
            if s2 is not None and int(s2) > 0:
                start_seq = int(s2)
        except Exception:
            pass
    if start_seq is None:
        return []
    start_idx = seq_to_idx.get(start_seq)
    if start_idx is None:
        return []

    node_ids0 = (recs[start_idx] or {}).get('node_ids') or []
    cur0 = node_ids0[0] if node_ids0 else None
    funcid = (nodes.get(cur0) or {}).get('funcid') if cur0 is not None else None
    if funcid is None:
        funcid = (nodes.get(nid) or {}).get('funcid')
    if funcid is None:
        return []

    dbg = ctx.get('debug')
    step = {'id': nid, 'seq': seq, 'funcid': funcid, 'start_seq': start_seq, 'start_index': start_idx}
    stop_id = find_toplevel_stop_id(funcid, nodes)
    if stop_id is not None:
        step['stop_id_c'] = stop_id
        step['stop_id_c_line'] = (nodes.get(stop_id) or {}).get('lineno')

    scope_recs, results, stop_info = collect_scope_recs_and_locs(start_idx=int(start_idx), funcid=int(funcid), ctx=ctx)
    stop_by = stop_info.get('stop_by')
    stop_index = stop_info.get('stop_index')
    stop_loc = stop_info.get('stop_loc')
    if ctx.get('llm_scope_debug'):
        try:
            step['walk_records'] = [
                {
                    'index': (r or {}).get('index'),
                    'path': (r or {}).get('path'),
                    'line': (r or {}).get('line'),
                    'seqs': (r or {}).get('seqs'),
                }
                for r in scope_recs
            ]
        except Exception:
            pass

    if stop_by == 'funcid' and isinstance(stop_index, int) and stop_index > 0:
        calls_edges_union = ctx.get('calls_edges_union')
        if calls_edges_union is None:
            calls_edges_union = read_calls_edges_union(os.getcwd())
            ctx['calls_edges_union'] = calls_edges_union
        funcid_to_call_ids = ctx.get('_llm_funcid_to_call_ids')
        if funcid_to_call_ids is None:
            funcid_to_call_ids = build_funcid_to_call_ids(calls_edges_union)
            ctx['_llm_funcid_to_call_ids'] = funcid_to_call_ids
        call_ids = funcid_to_call_ids.get(int(funcid)) or set()
        call_loc = None
        call_id = None
        call_seq = None
        hit = find_nearest_callsite_record(set(call_ids), recs, stop_index - 1)
        if hit:
            call_index, call_id, call_loc = hit
            try:
                rec_call = recs[int(call_index)] or {}
                seqs = rec_call.get('seqs') or []
                if seqs:
                    call_seq = int(min(int(x) for x in seqs))
            except Exception:
                call_seq = None
        if call_loc is None:
            call_loc = find_nearest_callsite_locator(set(call_ids), recs, stop_index - 1)
        preamble = []
        if call_loc:
            preamble.append(call_loc)
        if stop_loc:
            preamble.append(stop_loc)
        if preamble:
            ctx.setdefault('_llm_scope_preamble_by_key', {})[(int(nid), int(seq))] = preamble
        if call_loc:
            step['callsite_loc'] = call_loc
        if call_id is not None:
            step['callsite_id'] = int(call_id)
        if call_seq is not None:
            step['callsite_seq'] = int(call_seq)
        if stop_loc:
            step['func_def_loc'] = stop_loc
        if call_id is not None and call_seq is not None and ctx.get('llm_enabled'):
            try:
                from taint_handlers.handlers.call import ast_method_call
            except Exception:
                ast_method_call = None
            if ast_method_call is not None:
                info = ast_method_call.build_call_param_arg_info(call_id, call_seq, funcid, ctx)
                if info is not None:
                    ctx['_llm_call_param_arg_info'] = info

    results = compress_consecutive(results)
    step['results_count'] = len(results)
    step['results_preview'] = results
    if isinstance(dbg, dict):
        dbg.setdefault('ast_var', []).append(step)
    ctx.setdefault('result_set', [])
    ctx['result_set'].extend(results)
    return []
