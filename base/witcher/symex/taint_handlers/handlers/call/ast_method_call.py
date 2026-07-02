"""
Taint handler for `AST_METHOD_CALL` nodes.

This module contains shared logic for call-like nodes:
- Parse trace lines to locate callsites by `(path,line)`
- Resolve candidate callee methods via name matching heuristics
- Expand taints through call edges and argument/parameter mapping
"""

import os
import re
from typing import Dict, List, Set, Tuple
from common.app_config import load_app_config
from utils.extractors.if_extract import norm_trace_path, resolve_top_id
from utils.cpg_utils.graph_mapping import ensure_trace_edges_csv
from ..expr.ast_var import ensure_trace_index, record_taint_source

_ALLOWED_CALL_ARG_TYPES = {'AST_CALL', 'AST_METHOD_CALL', 'AST_DIM', 'AST_VAR', 'AST_PROP'}
_VAR_NAME_RE = re.compile(r'\$?([A-Za-z_][A-Za-z0-9_]*)')
_DOLLAR_VAR_RE = re.compile(r'\$([A-Za-z_][A-Za-z0-9_]*)')

def parse_trace_prefix(line):
    """Parse `path:line` from a raw trace log line and return `(norm_path, line)`."""
    line = (line or '').strip()
    if not line:
        return None
    prefix = line.split(' | ', 1)[0]
    if ':' not in prefix:
        return None
    path_part, line_part = prefix.rsplit(':', 1)
    try:
        ln = int(line_part)
    except:
        return None
    return norm_trace_path(path_part), ln

def _sorted_children(xid, nodes, children_of):
    """Return `xid` children sorted by `childnum` when available."""
    ch = list(children_of.get(xid, []) or [])
    ch.sort(key=lambda cid: (nodes.get(cid) or {}).get('childnum') if (nodes.get(cid) or {}).get('childnum') is not None else 10**9)
    return ch

def _find_descendant_by_type(root, want_type, nodes, children_of, max_depth: int = 4):
    """Find a descendant node of `root` whose type equals `want_type` (BFS)."""
    if root is None:
        return None
    q = [(int(root), 0)]
    seen = set()
    while q:
        nid, d = q.pop(0)
        if nid in seen:
            continue
        seen.add(nid)
        if d > 0 and (nodes.get(nid) or {}).get('type') == want_type:
            return nid
        if d >= max_depth:
            continue
        for c in _sorted_children(nid, nodes, children_of):
            if c not in seen:
                q.append((int(c), d + 1))
    return None

def _norm_var_name(s: str) -> str:
    """Normalize a PHP-style variable name to a bare identifier for matching."""
    v = (s or '').strip()
    if not v:
        return ''
    m2 = _DOLLAR_VAR_RE.search(v)
    if m2:
        return (m2.group(1) or '').strip()
    if v.startswith('$'):
        v = v[1:]
    m = _VAR_NAME_RE.search(v)
    return (m.group(1) if m else v).strip()

def build_call_param_arg_info(call_id, call_seq, callee_id, ctx):
    """Build parameter/argument alignment info used for mapping by-ref parameters."""
    if call_id is None or call_seq is None or callee_id is None or not isinstance(ctx, dict):
        return None
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    param_list_id = _find_descendant_by_type(callee_id, 'AST_PARAM_LIST', nodes, children_of, max_depth=6)
    if param_list_id is None:
        try:
            fid = int(callee_id)
        except Exception:
            fid = None
        if fid is not None:
            best = None
            for nid, nx in nodes.items():
                try:
                    nid_i = int(nid)
                except Exception:
                    continue
                if (nx or {}).get('funcid') != fid:
                    continue
                if (nx or {}).get('type') != 'AST_PARAM_LIST':
                    continue
                if best is None or nid_i < best:
                    best = nid_i
            param_list_id = best
    param_names = []
    if param_list_id is not None:
        for pid in _sorted_children(param_list_id, nodes, children_of):
            if (nodes.get(pid) or {}).get('type') != 'AST_PARAM':
                continue
            code = (nodes.get(pid) or {}).get('code') or (nodes.get(pid) or {}).get('name') or ''
            if not code:
                for c in _sorted_children(pid, nodes, children_of):
                    cx = nodes.get(c) or {}
                    if (cx.get('labels') == 'string') or ((cx.get('type') or '').strip() == 'string'):
                        vv = (cx.get('code') or cx.get('name') or '').strip()
                        if vv:
                            code = vv
                            break
            nm = _norm_var_name(code)
            if nm:
                param_names.append(nm)
    if not param_names:
        try:
            fid = int(callee_id)
        except Exception:
            fid = None
        if fid is not None:
            cand = []
            for nid, nx in nodes.items():
                if (nx or {}).get('funcid') != fid:
                    continue
                if (nx or {}).get('type') != 'AST_PARAM':
                    continue
                cn = (nx or {}).get('childnum')
                try:
                    cn_i = int(cn) if cn is not None else 10**9
                except Exception:
                    cn_i = 10**9
                try:
                    nid_i = int(nid)
                except Exception:
                    continue
                cand.append((cn_i, nid_i))
            cand.sort()
            for _, pid in cand:
                px = nodes.get(pid) or {}
                code = (px.get('code') or px.get('name') or '').strip()
                if not code:
                    for c in _sorted_children(pid, nodes, children_of):
                        cx = nodes.get(c) or {}
                        if (cx.get('labels') == 'string') or ((cx.get('type') or '').strip() == 'string'):
                            vv = (cx.get('code') or cx.get('name') or '').strip()
                            if vv:
                                code = vv
                                break
                nm = _norm_var_name(code)
                if nm:
                    param_names.append(nm)
    arg_list_id = _find_descendant_by_type(call_id, 'AST_ARG_LIST', nodes, children_of, max_depth=2)
    arg_ids = []
    arg_types = []
    arg_codes = []
    if arg_list_id is not None:
        for aid in _sorted_children(arg_list_id, nodes, children_of):
            nx = nodes.get(aid) or {}
            tt = (nx.get('type') or '').strip()
            if not tt:
                continue
            arg_ids.append(int(aid))
            arg_types.append(tt)
            arg_codes.append((nx.get('code') or nx.get('name') or '').strip())
    param_index = {}
    for i, pn in enumerate(param_names):
        if pn and pn not in param_index:
            param_index[pn] = i
    return {
        'call_id': int(call_id),
        'call_seq': int(call_seq),
        'callee_id': int(callee_id),
        'param_names': param_names,
        'param_index': param_index,
        'arg_ids': arg_ids,
        'arg_types': arg_types,
        'arg_codes': arg_codes,
    }

def convert_param_taint_to_call_arg_taint(param_taint, call_param_arg_info):
    """Convert a callee parameter taint into the corresponding callsite argument taint."""
    if not isinstance(param_taint, dict) or not isinstance(call_param_arg_info, dict):
        return None, None
    if (param_taint.get('type') or '').strip() != 'AST_VAR':
        return None, None
    nm = _norm_var_name((param_taint.get('name') or '').strip())
    if not nm:
        return None, None
    idx = (call_param_arg_info.get('param_index') or {}).get(nm)
    if idx is None:
        return None, None
    arg_ids = call_param_arg_info.get('arg_ids') or []
    if idx < 0 or idx >= len(arg_ids):
        return None, {'param_name': nm, 'param_index': idx, 'action': 'skip', 'reason': 'arg_missing'}
    arg_id = arg_ids[idx]
    arg_types = call_param_arg_info.get('arg_types') or []
    arg_codes = call_param_arg_info.get('arg_codes') or []
    arg_type = (arg_types[idx] if idx < len(arg_types) else '') or ''
    arg_code = (arg_codes[idx] if idx < len(arg_codes) else '') or ''
    if arg_type not in _ALLOWED_CALL_ARG_TYPES:
        return None, {'param_name': nm, 'param_index': idx, 'arg_id': arg_id, 'arg_type': arg_type, 'arg_code': arg_code, 'action': 'skip', 'reason': 'arg_type_not_allowed'}
    out = {
        'id': int(arg_id),
        'type': arg_type,
        'seq': int(call_param_arg_info.get('call_seq')),
        'name': arg_code,
    }
    return out, {'param_name': nm, 'param_index': idx, 'arg_id': int(arg_id), 'arg_type': arg_type, 'arg_code': arg_code, 'action': 'enqueue'}


def _extract_param_like_base_name(taint: dict) -> str:
    if not isinstance(taint, dict):
        return ''
    tt = (taint.get('type') or '').strip()
    if tt == 'AST_VAR':
        return (taint.get('name') or '').strip()
    if tt == 'AST_PROP':
        base = (taint.get('base') or '').strip()
        if base:
            return base
        nm = (taint.get('name') or '').strip().replace('.', '->')
        if '->' in nm:
            return (nm.split('->', 1)[0] or '').strip()
        return nm
    if tt == 'AST_DIM':
        base = (taint.get('base') or '').strip()
        if base:
            return base
        nm = (taint.get('name') or '').strip().replace('.', '->')
        if '[' in nm:
            return (nm.split('[', 1)[0] or '').strip()
        if '->' in nm:
            return (nm.split('->', 1)[0] or '').strip()
        return nm
    if tt == 'AST_METHOD_CALL':
        recv = (taint.get('recv') or '').strip()
        if recv:
            return recv
        nm = (taint.get('name') or '').strip().replace('.', '->')
        if '->' in nm:
            return (nm.split('->', 1)[0] or '').strip()
        return nm
    return ''


def convert_param_based_taint_to_call_arg_taint(taint, call_param_arg_info):
    if not isinstance(taint, dict) or not isinstance(call_param_arg_info, dict):
        return None, None
    tt = (taint.get('type') or '').strip()
    if tt == 'AST_VAR':
        return convert_param_taint_to_call_arg_taint(taint, call_param_arg_info)
    if tt not in ('AST_PROP', 'AST_DIM', 'AST_METHOD_CALL'):
        return None, None
    base = _extract_param_like_base_name(taint)
    nm = _norm_var_name(base)
    if not nm:
        return None, None
    idx = (call_param_arg_info.get('param_index') or {}).get(nm)
    if idx is None:
        return None, None
    repl, dbg = convert_param_taint_to_call_arg_taint({'type': 'AST_VAR', 'name': base}, call_param_arg_info)
    if dbg is not None:
        dbg = dict(dbg)
        dbg['src_type'] = tt
        dbg['src_name'] = (taint.get('name') or '').strip()
    return repl, dbg

def read_calls_edges(base):
    """Read and union `CALLS` edges from `cpg_edges.csv` and `trace_edges.csv`."""
    base = (base or '').strip()
    if not base:
        base = os.getcwd()
    cfg = load_app_config(config_path=os.path.join(os.path.abspath(base), 'config.json'), base_dir=base)
    ensure_trace_edges_csv(cfg.base_dir)
    def read_edges(path):
        m = {}
        if not os.path.exists(path):
            return m
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for raw in f:
                raw = raw.strip()
                if not raw or '\t' not in raw:
                    continue
                parts = raw.split('\t')
                if len(parts) < 3:
                    continue
                try:
                    s = int(parts[0]); e = int(parts[1])
                except:
                    continue
                t = parts[2].strip()
                if t != 'CALLS':
                    continue
                st = m.get(s)
                if st is None:
                    st = set()
                    m[s] = st
                st.add(e)
        return m

    out = {}
    candidates = [
        cfg.find_input_file('cpg_edges.csv'),
        cfg.tmp_path('trace_edges.csv'),
        os.path.join(cfg.base_dir, 'trace_edges.csv'),
        os.path.join(cfg.base_dir, 'cpg_edges.csv'),
    ]
    for p in candidates:
        edges = read_edges(p)
        for s, dsts in edges.items():
            cur = out.get(s)
            if cur is None:
                out[s] = set(dsts)
            else:
                cur |= dsts
    return out

def resolve_node_file_line(nid, ctx):
    """Resolve a node id to `(file_path, line)` using `top_id_to_file` and `lineno`."""
    nodes = ctx.get('nodes') or {}
    parent_of = ctx.get('parent_of') or {}
    top_id_to_file = ctx.get('top_id_to_file') or {}
    nx = nodes.get(nid) or {}
    ln = nx.get('lineno')
    top = resolve_top_id(nid, parent_of, nodes, top_id_to_file)
    if top is None:
        return None
    p = top_id_to_file.get(top)
    if not p or ln is None:
        return None
    return p, ln

def find_seq_for_file_line(start_seq, target_path, target_line, trace_path):
    """Scan `trace.log` forward from `start_seq` to find the first matching `(path,line)`."""
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        i = 0
        for raw in f:
            i += 1
            if i < start_seq:
                continue
            pr = parse_trace_prefix(raw)
            if not pr:
                continue
            p, ln = pr
            if p == target_path and ln == target_line:
                return i
    return None

def collect_trace_pairs(start_seq, stop_pair, trace_path):
    """Collect unique `(path,line)` trace pairs starting at `start_seq` until `stop_pair`."""
    out = []
    prev = None
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        i = 0
        for raw in f:
            i += 1
            if i < start_seq:
                continue
            pr = parse_trace_prefix(raw)
            if not pr:
                continue
            if pr == prev:
                continue
            if pr == stop_pair and i != start_seq:
                break
            prev = pr
            out.append({'seq': i, 'path': pr[0], 'line': pr[1]})
    return out

def build_first_node_index(targets, ctx):
    """Build an index from `(path,line)` to the smallest node id on that location."""
    target_lines_by_path = {}
    target_paths = set()
    for t in targets:
        p = t.get('path')
        ln = t.get('line')
        if not p or ln is None:
            continue
        target_paths.add(p)
        s = target_lines_by_path.get(p)
        if s is None:
            s = set()
            target_lines_by_path[p] = s
        s.add(ln)
    nodes = ctx.get('nodes') or {}
    parent_of = ctx.get('parent_of') or {}
    top_id_to_file = ctx.get('top_id_to_file') or {}
    all_target_lines = set()
    for s in target_lines_by_path.values():
        all_target_lines |= s
    out = {}
    for nid, nx in nodes.items():
        ln = nx.get('lineno')
        if ln is None or ln not in all_target_lines:
            continue
        top = resolve_top_id(nid, parent_of, nodes, top_id_to_file)
        if top is None:
            continue
        p = top_id_to_file.get(top)
        if not p or p not in target_paths:
            continue
        if ln not in (target_lines_by_path.get(p) or set()):
            continue
        k = (p, ln)
        cur = out.get(k)
        if cur is None or nid < cur:
            out[k] = nid
    return out

def compress_consecutive(items):
    """Remove consecutive duplicates from an ordered list."""
    out = []
    prev = None
    for it in items:
        if it == prev:
            continue
        out.append(it)
        prev = it
    return out

def pick_method_id(call_seq, candidate_ids, ctx, trace_path):
    """Pick the best callee method id among candidates using trace position matching."""
    if not candidate_ids:
        return None
    if len(candidate_ids) == 1:
        return candidate_ids[0]
    cand_pairs = {}
    target_pairs = set()
    for mid in candidate_ids:
        pr = resolve_node_file_line(mid, ctx)
        if not pr:
            continue
        cand_pairs[mid] = pr
        target_pairs.add(pr)
    if not target_pairs:
        return candidate_ids[0]
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        i = 0
        prev = None
        for raw in f:
            i += 1
            if i < call_seq:
                continue
            pr = parse_trace_prefix(raw)
            if not pr:
                continue
            if pr == prev:
                continue
            prev = pr
            if pr in target_pairs:
                for mid, mpr in cand_pairs.items():
                    if mpr == pr:
                        return mid
    return next(iter(cand_pairs.keys()), candidate_ids[0])

def _last_trace_seq_from_records(recs) -> int:
    last_seq = 0
    for rec in recs or []:
        seqs = rec.get('seqs') or []
        if not seqs:
            continue
        try:
            last_seq = max(int(last_seq), int(seqs[-1]))
        except Exception:
            continue
    return int(last_seq)

def _compute_call_execution_scope_range(*, call_seq: int, recs: List[dict], seq_to_idx: Dict[int, int]):
    try:
        call_seq_i = int(call_seq)
    except Exception:
        return None
    start_idx = seq_to_idx.get(call_seq_i)
    if start_idx is None:
        return None
    start_rec = recs[int(start_idx)] if 0 <= int(start_idx) < len(recs) else None
    if not isinstance(start_rec, dict):
        return None
    call_path = (start_rec.get('path') or '').strip()
    call_line = start_rec.get('line')
    if not call_path or call_line is None:
        return None
    try:
        call_line_i = int(call_line)
    except Exception:
        return None

    stop_idx = None
    left_call_loc = False
    for ridx in range(int(start_idx) + 1, len(recs)):
        rec = recs[ridx] or {}
        rp = (rec.get('path') or '').strip()
        rl = rec.get('line')
        if not rp or rl is None:
            continue
        try:
            rl_i = int(rl)
        except Exception:
            continue
        if not left_call_loc:
            if rp != call_path or rl_i != call_line_i:
                left_call_loc = True
            continue
        if rp == call_path and rl_i == call_line_i:
            stop_idx = int(ridx)
            break

    last_seq = _last_trace_seq_from_records(recs)
    if last_seq <= 0:
        return None
    if stop_idx is None:
        return {
            'start_seq': int(call_seq_i),
            'end_seq': int(last_seq),
            'call_loc': (call_path, int(call_line_i)),
            'start_rec_index': int(start_idx),
            'stop_rec_index': None,
            'stop_seq': None,
            'stop_by': 'trace_end',
        }

    stop_rec = recs[int(stop_idx)] or {}
    stop_seqs = list(stop_rec.get('seqs') or [])
    stop_seq = None
    try:
        stop_seq = int(min(int(x) for x in stop_seqs))
    except Exception:
        stop_seq = None
    if stop_seq is None:
        return None
    end_seq = int(stop_seq) - 1
    if end_seq < int(call_seq_i):
        end_seq = int(call_seq_i)
    return {
        'start_seq': int(call_seq_i),
        'end_seq': int(end_seq),
        'call_loc': (call_path, int(call_line_i)),
        'start_rec_index': int(start_idx),
        'stop_rec_index': int(stop_idx),
        'stop_seq': int(stop_seq),
        'stop_by': 'call_loc_reappears',
    }

def _collect_func_body_scope_rows(*, def_id: int, start_seq: int, end_seq: int, ctx: dict):
    nodes = ctx.get('nodes') or {}
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    if not nodes or not recs or not seq_to_idx:
        return [], None
    try:
        def_id_i = int(def_id)
        start_seq_i = int(start_seq)
        end_seq_i = int(end_seq)
    except Exception:
        return [], None

    try:
        import bisect
    except Exception:
        bisect = None

    node_min_seq: Dict[int, int] = {}
    def_file = None
    try:
        pr = resolve_node_file_line(int(def_id_i), ctx)
        if pr:
            def_file = pr[0]
    except Exception:
        def_file = None
    min_line = None
    max_line = None
    for nid_i, nx in nodes.items():
        if (nx or {}).get('funcid') != def_id_i:
            continue
        ln = (nx or {}).get('lineno')
        if ln is None:
            continue
        try:
            ln_i = int(ln)
        except Exception:
            continue
        if min_line is None or ln_i < int(min_line):
            min_line = int(ln_i)
        if max_line is None or ln_i > int(max_line):
            max_line = int(ln_i)

    for rec in recs:
        seqs = rec.get('seqs') or []
        if not seqs:
            continue
        try:
            rec_min = int(seqs[0])
            rec_max = int(seqs[-1])
        except Exception:
            continue
        if rec_max < start_seq_i or rec_min > end_seq_i:
            continue
        if bisect is not None:
            try:
                i0 = bisect.bisect_left(seqs, start_seq_i)
                i1 = bisect.bisect_right(seqs, end_seq_i)
                if i0 >= i1:
                    continue
                overlap_min = int(seqs[i0])
            except Exception:
                overlap_min = None
        else:
            overlap_min = None
            for s in seqs:
                try:
                    si = int(s)
                except Exception:
                    continue
                if si < start_seq_i:
                    continue
                if si > end_seq_i:
                    break
                overlap_min = si
                break
        if overlap_min is None:
            continue
        attached = False
        for nid in rec.get('node_ids') or []:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            if (nodes.get(nid_i) or {}).get('funcid') != def_id_i:
                continue
            attached = True
            cur = node_min_seq.get(nid_i)
            if cur is None or int(overlap_min) < int(cur):
                node_min_seq[nid_i] = int(overlap_min)
        if attached:
            continue
        if def_file is None or min_line is None or max_line is None:
            continue
        rp = (rec.get('path') or '').strip()
        rl = rec.get('line')
        if not rp or rl is None or rp != def_file:
            continue
        try:
            rl_i = int(rl)
        except Exception:
            continue
        if int(min_line) <= int(rl_i) <= int(max_line):
            cur = node_min_seq.get(def_id_i)
            if cur is None or int(overlap_min) < int(cur):
                node_min_seq[def_id_i] = int(overlap_min)
    rows = []
    min_def_seq = None
    for nid_i, seq in node_min_seq.items():
        ridx = seq_to_idx.get(int(seq))
        if ridx is None:
            continue
        rec = recs[int(ridx)] or {}
        rp = (rec.get('path') or '').strip()
        rl = rec.get('line')
        if not rp or rl is None:
            continue
        try:
            rl_i = int(rl)
        except Exception:
            continue
        rep_funcid = (nodes.get(nid_i) or {}).get('funcid')
        rows.append(
            {
                'seq': int(seq),
                'id': int(nid_i),
                'funcid': int(rep_funcid) if rep_funcid is not None else None,
                'path': rp,
                'line': int(rl_i),
            }
        )
        if min_def_seq is None or int(seq) < int(min_def_seq):
            min_def_seq = int(seq)
    rows.sort(key=lambda r: (int(r.get('seq') or 0), int(r.get('id') or 0)))
    uniq_by_seq = {}
    for row in rows:
        try:
            s = int((row or {}).get('seq'))
        except Exception:
            continue
        if s not in uniq_by_seq:
            uniq_by_seq[s] = row
    rows2 = list(uniq_by_seq.values())
    rows2.sort(key=lambda r: int(r.get('seq') or 0))
    return rows2, min_def_seq

def partition_function_scope_for_call(call_id: int, call_seq: int, ctx):
    if call_id is None or call_seq is None or not isinstance(ctx, dict):
        return None
    try:
        call_id_i = int(call_id)
        call_seq_i = int(call_seq)
    except Exception:
        return None

    ensure_trace_index(ctx)
    nodes = ctx.get('nodes') or {}
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    if not recs or not seq_to_idx:
        return None

    calls_edges = ctx.get('calls_edges_union')
    if calls_edges is None:
        calls_edges = read_calls_edges(os.getcwd())
        ctx['calls_edges_union'] = calls_edges
    cand_defs = list(calls_edges.get(call_id_i) or [])
    if not cand_defs:
        return None

    cfg = load_app_config(config_path=os.path.join(os.path.abspath(os.getcwd()), 'config.json'), base_dir=os.getcwd())
    trace_path = (ctx.get('trace_path') if isinstance(ctx, dict) else None) or cfg.find_input_file('trace.log')
    def_id = pick_method_id(call_seq_i, cand_defs, ctx, trace_path)
    if def_id is None:
        return None
    try:
        def_id_i = int(def_id)
    except Exception:
        return None

    scope_range = _compute_call_execution_scope_range(call_seq=call_seq_i, recs=recs, seq_to_idx=seq_to_idx)
    if not scope_range:
        return None

    rows, def_seq = _collect_func_body_scope_rows(
        def_id=def_id_i,
        start_seq=int(scope_range.get('start_seq')),
        end_seq=int(scope_range.get('end_seq')),
        ctx=ctx,
    )
    if def_seq is None:
        def_seq = int(scope_range.get('start_seq'))

    out = {
        'call_id': call_id_i,
        'call_seq': call_seq_i,
        'def_id': int(def_id_i),
        'def_seq': int(def_seq),
        'scope': rows,
        'scope_start_seq': int(scope_range.get('start_seq')),
        'scope_end_seq': int(scope_range.get('end_seq')),
        'scope_stop_by': scope_range.get('stop_by'),
        'scope_stop_seq': scope_range.get('stop_seq'),
        'call_loc': scope_range.get('call_loc'),
        'call_loc_start_rec_index': scope_range.get('start_rec_index'),
        'call_loc_stop_rec_index': scope_range.get('stop_rec_index'),
    }
    return out

def process_call_like(taint, ctx, *, debug_key: str = 'ast_method_call'):
    """Shared implementation for `AST_METHOD_CALL`/`AST_CALL` taint expansion."""
    def _collect_this_method_calls_from_loc_taints(loc_taints, ctx2, *, seen_call_ids: Set[int]) -> List[Tuple[int, int]]:
        out = []
        nodes2 = ctx2.get('nodes') or {}
        children_of2 = ctx2.get('children_of') or {}
        recs2 = ctx2.get('trace_index_records') or []
        seq_to_idx2 = ctx2.get('trace_seq_to_index') or {}
        if not nodes2 or not children_of2 or not recs2 or not seq_to_idx2:
            return out
        try:
            from utils.cpg_utils.graph_mapping import method_call_receiver_name
        except Exception:
            method_call_receiver_name = None
        if method_call_receiver_name is None:
            return out
        seen_local = set()
        for lt in loc_taints or []:
            try:
                s = int((lt or {}).get('seq'))
            except Exception:
                continue
            idx2 = seq_to_idx2.get(s)
            if not isinstance(idx2, int) or idx2 < 0 or idx2 >= len(recs2):
                continue
            rec = recs2[idx2] or {}
            for nid in rec.get('node_ids') or []:
                nx = nodes2.get(nid) or {}
                if (nx.get('type') or '').strip() != 'AST_METHOD_CALL':
                    continue
                try:
                    call_id2 = int(nid)
                except Exception:
                    continue
                if call_id2 in seen_call_ids or call_id2 in seen_local:
                    continue
                r = (method_call_receiver_name(call_id2, children_of2, nodes2) or '').strip()
                if r not in ('this', '$this'):
                    continue
                seen_local.add(call_id2)
                out.append((call_id2, s))
        return out

    def _expand_method_call_scope(call_id2: int, call_seq2: int, ctx2) -> Tuple[List[str], List[dict], List[str]]:
        nodes2 = ctx2.get('nodes') or {}
        children_of2 = ctx2.get('children_of') or {}
        parent_of2 = ctx2.get('parent_of') or {}
        top_id_to_file2 = ctx2.get('top_id_to_file') or {}
        recs2 = ctx2.get('trace_index_records') or []
        seq_to_idx2 = ctx2.get('trace_seq_to_index') or {}
        calls_edges_union2 = ctx2.get('calls_edges_union')
        dbg_local = {'_': []}
        dbg_ctx2 = ctx2.get('debug')
        if isinstance(dbg_ctx2, dict):
            dbg_local = dbg_ctx2
        ctx3 = {
            'nodes': nodes2,
            'children_of': children_of2,
            'parent_of': parent_of2,
            'top_id_to_file': top_id_to_file2,
            'trace_index_records': recs2,
            'trace_seq_to_index': seq_to_idx2,
            'calls_edges_union': calls_edges_union2,
            'debug': dbg_local,
            'result_set': [],
            'llm_enabled': bool(ctx2.get('llm_enabled')),
            '_llm_disable_nested_this_calls': True,
        }
        call_taint = {'id': int(call_id2), 'type': 'AST_METHOD_CALL', 'seq': int(call_seq2)}
        call_res = process_call_like(call_taint, ctx3, debug_key=debug_key)
        nested_loc_taints = call_res[0] if (isinstance(call_res, list) and call_res and isinstance(call_res[0], list)) else []
        nested_extra = list(ctx3.get('_llm_extra_prompt_locs') or [])
        return list(ctx3.get('result_set') or []), nested_loc_taints, nested_extra

    def _expand_nested_this_calls(loc_taints, ctx2, *, max_depth: int = 5) -> None:
        try:
            max_depth_i = int(max_depth)
        except Exception:
            max_depth_i = 5
        if max_depth_i <= 0:
            return
        def _loc_key(x):
            if not x:
                return None
            if isinstance(x, dict):
                lk = (x.get('loc') or '').strip()
                if not lk:
                    p = (x.get('path') or '').strip()
                    ln = x.get('line')
                    if p and ln is not None:
                        try:
                            lk = f"{p}:{int(ln)}"
                        except Exception:
                            lk = None
                seq = x.get('seq')
                try:
                    seq_i = int(seq) if seq is not None else None
                except Exception:
                    seq_i = None
                if lk and seq_i is not None:
                    return (lk, int(seq_i))
                return lk
            if isinstance(x, str):
                return x
            return None
        seen_call_ids: Set[int] = set()
        nodes2 = ctx2.get('nodes') or {}
        children_of2 = ctx2.get('children_of') or {}
        recs2 = ctx2.get('trace_index_records') or []
        seq_to_idx2 = ctx2.get('trace_seq_to_index') or {}
        if not nodes2 or not children_of2 or not recs2 or not seq_to_idx2:
            return

        todo = [(loc_taints, 0)]
        all_scope_locs = []
        all_extra_locs = []
        markers = []
        while todo:
            cur_locs, depth = todo.pop()
            if depth >= max_depth_i:
                continue
            calls = _collect_this_method_calls_from_loc_taints(cur_locs, ctx2, seen_call_ids=seen_call_ids)
            for call_id2, call_seq2 in calls:
                scope_locs, nested_loc_taints, nested_extra = _expand_method_call_scope(call_id2, call_seq2, ctx2)
                if scope_locs:
                    markers.append({'kind': 'function_scope', 'start': scope_locs[0], 'end': scope_locs[-1]})
                    for loc in scope_locs:
                        all_scope_locs.append(loc)
                if nested_extra:
                    for loc in nested_extra:
                        all_extra_locs.append(loc)
                if nested_loc_taints:
                    todo.append((nested_loc_taints, depth + 1))

        if all_scope_locs:
            rs = ctx2.setdefault('result_set', [])
            existing = set()
            for x in rs or []:
                k = _loc_key(x)
                if k:
                    existing.add(k)
            for loc in all_scope_locs:
                k = _loc_key(loc)
                if not k or k in existing:
                    continue
                existing.add(k)
                rs.append(loc)
        if all_extra_locs:
            extra = ctx2.setdefault('_llm_extra_prompt_locs', [])
            existing = set()
            for x in extra or []:
                k = _loc_key(x)
                if k:
                    existing.add(k)
            for loc in all_extra_locs:
                k = _loc_key(loc)
                if not k or k in existing:
                    continue
                existing.add(k)
                extra.append(loc)
        if markers:
            out = ctx2.setdefault('_llm_scope_markers', [])
            existing = set()
            for m in out:
                if not isinstance(m, dict):
                    continue
                st_k = _loc_key(m.get('start'))
                ed_k = _loc_key(m.get('end'))
                k = ((m.get('kind') or '').strip(), st_k, ed_k)
                existing.add(k)
            for m in markers:
                st_k = _loc_key(m.get('start'))
                ed_k = _loc_key(m.get('end'))
                k = ((m.get('kind') or '').strip(), st_k, ed_k)
                if k in existing:
                    continue
                existing.add(k)
                out.append(m)

    base = os.getcwd()
    trace_path = os.path.join(base, 'trace.log')
    call_id = taint.get('id')
    call_seq = taint.get('seq')
    if call_id is None or call_seq is None:
        return []
    if isinstance(ctx, dict):
        ctx['_llm_scope_prefer'] = 'forward'

    dbg_ctx = ctx.get('debug')
    dbg = None
    if isinstance(dbg_ctx, dict):
        dbg = dbg_ctx.setdefault(debug_key, [])
    step = {'call_id': call_id, 'call_seq': call_seq}
    lg = ctx.get('logger') if isinstance(ctx, dict) else None
    if lg is not None:
        try:
            lg.info('debug_ast_method_call_start', call_id=int(call_id), call_seq=int(call_seq))
        except Exception:
            pass
    def early(status):
        step['status'] = status
        if dbg is not None:
            dbg.append(step)
        if lg is not None:
            try:
                lg.info('debug_ast_method_call_early', call_id=int(call_id), call_seq=int(call_seq), status=status)
            except Exception:
                pass
        return []
    calls_edges = ctx.get('calls_edges_union')
    if calls_edges is None:
        calls_edges = read_calls_edges(base)
        ctx['calls_edges_union'] = calls_edges
    cands = list(calls_edges.get(call_id) or [])
    if not cands:
        return early('no_calls_candidates')
    step['calls_candidates'] = cands
    scope_info = partition_function_scope_for_call(int(call_id), int(call_seq), ctx)
    if not scope_info:
        return early('partition_scope_failed')
    method_id = scope_info.get('def_id')
    method_seq = scope_info.get('def_seq')
    step['picked_method_id'] = method_id
    step['method_seq'] = method_seq
    step['scope_start_seq'] = scope_info.get('scope_start_seq')
    step['scope_end_seq'] = scope_info.get('scope_end_seq')
    step['scope_stop_by'] = scope_info.get('scope_stop_by')
    step['scope_stop_seq'] = scope_info.get('scope_stop_seq')
    step['call_loc'] = scope_info.get('call_loc')
    if isinstance(ctx, dict) and ctx.get('llm_enabled'):
        info = build_call_param_arg_info(call_id, call_seq, method_id, ctx)
        if info is not None:
            ctx['_llm_call_param_arg_info'] = info
            lg = ctx.get('logger')
            if lg is not None:
                try:
                    lg.debug(
                        'llm_call_param_arg_info',
                        call_id=int(info.get('call_id')),
                        call_seq=int(info.get('call_seq')),
                        callee_id=int(info.get('callee_id')),
                        param_names=list(info.get('param_names') or []),
                        arg_types=list(info.get('arg_types') or []),
                        arg_codes=list(info.get('arg_codes') or []),
                    )
                except Exception:
                    pass

    nodes = ctx.get('nodes') or {}
    results = []
    loc_taints = []
    try:
        ref_seq = int(call_seq)
    except Exception:
        ref_seq = None
    prefer = (ctx.get('_llm_scope_prefer') or 'forward').strip() or 'forward'
    scope_rows = list(scope_info.get('scope') or [])
    scope_rows.sort(
        key=lambda r: (
            int((r or {}).get('seq') or 0),
            int((r or {}).get('id') or 0),
        )
    )
    step['scope_rows_count'] = len(scope_rows)
    seen_loc = set()
    for row in scope_rows:
        p = (row.get('path') or '').strip()
        ln = row.get('line')
        seq = row.get('seq')
        if not p or ln is None or seq is None:
            continue
        try:
            ln_i = int(ln)
            seq_i = int(seq)
        except Exception:
            continue
        loc = f"{p}:{ln_i}"
        if loc in seen_loc:
            continue
        seen_loc.add(loc)
        results.append({'seq': int(seq_i), 'path': p, 'line': int(ln_i), 'loc': loc})
        loc_taints.append({'type': 'TRACE_LOC', 'seq': int(seq_i), 'path': p, 'line': int(ln_i), 'funcid': row.get('funcid')})

    if (taint.get('type') or '').strip() == 'AST_METHOD_CALL' and not ctx.get('_llm_disable_nested_this_calls'):
        try:
            from ..expr import this_scope
        except Exception:
            this_scope = None
        expanded_this_scope = False
        if this_scope is not None:
            root_ctx = this_scope.resolve_receiver_root_context(taint)
            recv_obj = (root_ctx.get('recv_obj') or '').strip()
            root_seq = root_ctx.get('start_seq')
            is_this_recv = bool(root_ctx.get('is_this_receiver'))
            if not is_this_recv:
                is_this_recv = bool((taint.get('_this_obj') or '').strip() and taint.get('_this_call_seq') is not None)
            if recv_obj and root_seq is not None and is_this_recv:
                base_locs, kept_locs, root, scope_stats = this_scope.expand_receiver_method_scopes(
                    start_seq=int(root_seq),
                    ctx=ctx,
                    recv_obj=recv_obj,
                    include_this_calls_in_base_scope=True,
                    prune_to_target=False,
                    debug_key='ast_method_call_this_expand',
                )
                if base_locs or kept_locs:
                    extra = ctx.setdefault('_llm_extra_prompt_locs', [])
                    existing = set()
                    for x in extra or []:
                        if isinstance(x, dict):
                            lk = (x.get('loc') or '').strip()
                            seq = x.get('seq')
                            try:
                                seq_i = int(seq) if seq is not None else None
                            except Exception:
                                seq_i = None
                            if lk:
                                existing.add((lk, seq_i))
                    for loc in list(base_locs or []) + list(kept_locs or []):
                        if not isinstance(loc, dict):
                            continue
                        lk = (loc.get('loc') or '').strip()
                        seq = loc.get('seq')
                        try:
                            seq_i = int(seq) if seq is not None else None
                        except Exception:
                            seq_i = None
                        key = (lk, seq_i)
                        if not lk or key in existing:
                            continue
                        existing.add(key)
                        extra.append(loc)
                markers = []
                if isinstance(root, dict):
                    this_scope.collect_scope_markers(root, markers)
                if markers:
                    ctx.setdefault('_llm_scope_markers', []).extend(markers)
                step['this_scope_stats'] = scope_stats
                expanded_this_scope = True
        if not expanded_this_scope:
            _expand_nested_this_calls(loc_taints, ctx, max_depth=5)
    step['results_count'] = len(results)
    step['results_preview'] = [(x.get('loc') if isinstance(x, dict) else x) for x in results[:30]]
    if dbg is not None:
        dbg.append(step)
    if lg is not None:
        try:
            lg.info(
                'debug_ast_method_call_scope',
                call_id=int(call_id),
                call_seq=int(call_seq),
                method_id=method_id,
                method_seq=method_seq,
                scope_rows_count=len(scope_rows),
                results_count=len(results),
            )
        except Exception:
            pass
    ctx.setdefault('result_set', [])
    ctx['result_set'].extend(results)
    return [loc_taints] if loc_taints else []


def process(taint, ctx):
    """Expand an `AST_METHOD_CALL` taint and record its source string."""
    record_taint_source(taint, ctx)
    return process_call_like(taint, ctx, debug_key='ast_method_call')
