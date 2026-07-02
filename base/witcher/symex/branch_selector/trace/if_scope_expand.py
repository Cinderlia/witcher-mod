"""
Expand IF/SWITCH seq groups by taint-scoping: find nearby trace lines that influence branch conditions.
"""

import os
import sys
import bisect
import time
import concurrent.futures
from typing import Dict, Iterable, List, Optional, Set, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyze_if_line import read_trace_line, extract_if_elements_fast, build_initial_taints, parse_loc
from utils.extractors.if_extract import norm_trace_path
from taint_handlers import REGISTRY
from taint_handlers.llm.core.llm_response import _node_source_str_with_this, _norm_llm_name
from utils.cpg_utils.graph_mapping import get_string_children
from llm_utils.prompts.prompt_utils import build_seqs_by_loc


_ALLOWED_TYPES = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL', 'AST_PARAM'}


def _loc_key(path: str, line: int) -> Optional[Tuple[str, int]]:
    if not path or line is None:
        return None
    try:
        ln = int(line)
    except Exception:
        return None
    return norm_trace_path(path), ln


def _loc_to_path_line(loc) -> Optional[Tuple[str, int]]:
    if isinstance(loc, dict):
        p = loc.get('path')
        ln = loc.get('line')
        if p and ln is not None:
            return _loc_key(p, ln)
        if loc.get('loc'):
            pr = parse_loc(loc.get('loc'))
            if pr:
                return pr
        return None
    if isinstance(loc, str):
        return parse_loc(loc)
    return None


def _build_loc_to_records(trace_index_records: Iterable[dict]) -> Dict[Tuple[str, int], List[dict]]:
    out: Dict[Tuple[str, int], List[dict]] = {}
    for rec in trace_index_records or []:
        p = rec.get('path')
        ln = rec.get('line')
        key = _loc_key(p, ln)
        if not key:
            continue
        out.setdefault(key, []).append(rec)
    return out


def _build_loc_to_min_seq(trace_index_records: Iterable[dict]) -> Dict[Tuple[str, int], int]:
    out: Dict[Tuple[str, int], int] = {}
    for rec in trace_index_records or []:
        p = rec.get('path')
        ln = rec.get('line')
        key = _loc_key(p, ln)
        if not key:
            continue
        seqs = []
        for s in rec.get('seqs') or []:
            try:
                seqs.append(int(s))
            except Exception:
                continue
        if not seqs:
            continue
        cur = min(seqs)
        prev = out.get(key)
        if prev is None or cur < prev:
            out[key] = cur
    return out


def _build_node_to_min_seq(trace_index_records: Iterable[dict]) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for rec in trace_index_records or []:
        seqs = []
        for s in rec.get('seqs') or []:
            try:
                seqs.append(int(s))
            except Exception:
                continue
        if not seqs:
            continue
        min_seq = min(seqs)
        for nid in rec.get('node_ids') or []:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            prev = out.get(nid_i)
            if prev is None or min_seq < int(prev):
                out[nid_i] = int(min_seq)
    return out


def _build_funcid_to_path(trace_index_records: Iterable[dict], nodes: dict) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for rec in trace_index_records or []:
        p = (rec.get('path') or '').strip()
        if not p:
            continue
        for nid in rec.get('node_ids') or []:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            nx = nodes.get(nid_i) or {}
            funcid = nx.get('funcid')
            try:
                funcid_i = int(funcid) if funcid is not None else None
            except Exception:
                funcid_i = None
            if funcid_i is not None and funcid_i not in out:
                out[funcid_i] = p
            nt = (nx.get('type') or '').strip()
            if nt in ('AST_METHOD', 'AST_FUNC_DECL') and nid_i not in out:
                out[nid_i] = p
    return out


def _strip_call_parens(name: str) -> str:
    v = (name or '').strip()
    if v.endswith('()'):
        return v[:-2]
    return v


def _normalize_name(name: str) -> str:
    return _norm_llm_name((name or '').replace('.', '->'))


def _split_prop_like(name: str) -> Tuple[str, str]:
    v = (name or '').replace('.', '->')
    if '->' not in v:
        return v, ''
    left, right = v.split('->', 1)
    return left, right


def _split_static_call(name: str) -> Tuple[str, str]:
    v = (name or '').replace(' ', '').replace('\t', '')
    v = v.replace('$', '')
    if '::' in v:
        left, right = v.split('::', 1)
        return left, right
    if ':' in v:
        left, right = v.split(':', 1)
        return left, right
    return v, ''


def _split_dim_base(name: str) -> str:
    v = (name or '').strip().replace('.', '->')
    if '[' in v:
        v = v.split('[', 1)[0].strip()
    return v


def _split_var_parts(tt: str, name: str) -> List[Tuple[str, str]]:
    t = (tt or '').strip()
    v = (name or '').strip()
    if not t or not v:
        return []
    if t == 'AST_VAR':
        nm = _normalize_name(v)
        return [(t, nm)] if nm else []
    if t == 'AST_PARAM':
        nm = _normalize_name(v)
        return [('AST_VAR', nm)] if nm else []
    if t == 'AST_DIM':
        base = _split_dim_base(v)
        nm = _normalize_name(base)
        return [(t, nm)] if nm else []
    if t == 'AST_PROP':
        left, right = _split_prop_like(v)
        out = []
        left_n = _normalize_name(left)
        right_n = _normalize_name(right)
        if left_n:
            out.append((t, left_n))
        if right_n:
            out.append((t, right_n))
        return out
    if t == 'AST_METHOD_CALL':
        left, right = _split_prop_like(v)
        out = []
        left_n = _normalize_name(left)
        right_n = _normalize_name(_strip_call_parens(right))
        if left_n:
            out.append((t, left_n))
        if right_n:
            out.append((t, right_n))
        if not out:
            nm = _normalize_name(_strip_call_parens(v))
            if nm:
                out.append((t, nm))
        return out
    if t == 'AST_CALL':
        nm = _normalize_name(_strip_call_parens(v))
        return [(t, nm)] if nm else []
    if t == 'AST_STATIC_CALL':
        left, right = _split_static_call(v)
        out = []
        left_n = _normalize_name(left)
        right_n = _normalize_name(_strip_call_parens(right))
        if left_n:
            out.append((t, left_n))
        if right_n:
            out.append((t, right_n))
        return out
    return []


def _taint_name(taint: dict) -> str:
    tt = (taint.get('type') or '').strip()
    if tt == 'AST_PROP':
        base = (taint.get('base') or '').strip()
        prop = (taint.get('prop') or '').strip()
        if base and prop:
            return f"{base}->{prop}"
    if tt == 'AST_DIM':
        base = (taint.get('base') or '').strip()
        if base:
            return base
    if tt == 'AST_METHOD_CALL':
        recv = (taint.get('recv') or '').strip()
        name = (taint.get('name') or '').strip()
        if name and not name.endswith('()'):
            name = f"{name}()"
        if recv and name:
            return f"{recv}->{name}"
        return name
    return (taint.get('name') or '').strip()


def _build_ctx_for_seq(
    *,
    seq: int,
    st: dict,
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    trace_index_records: List[dict],
    seq_to_index: Dict[int, int],
    scope_root: str,
    windows_root: str,
    loc_to_records: Optional[dict] = None,
    idx_to_pos: Optional[dict] = None,
    fast_scope_expand: Optional[bool] = None,
) -> dict:
    return {
        'input_seq': int(seq),
        'path': st.get('path'),
        'line': st.get('line'),
        'targets': st.get('targets'),
        'result': st.get('result'),
        'nodes': nodes,
        'children_of': children_of,
        'parent_of': parent_of,
        'trace_index_records': trace_index_records,
        'trace_seq_to_index': seq_to_index,
        'loc_to_records': loc_to_records or {},
        'idx_to_pos': idx_to_pos or {},
        'fast_scope_expand': bool(fast_scope_expand),
        'scope_root': scope_root,
        'windows_root': windows_root,
        'llm_enabled': False,
        'llm_scope_debug': False,
        'debug': {},
        'logger': None,
        'result_set': [],
    }


def _collect_scope_locs(taint: dict, base_ctx: dict) -> list:
    """Run a taint handler to collect scope locations (and includes) relevant to the given taint."""
    tt = (taint.get('type') or '').strip()
    handler = REGISTRY.get(tt)
    if handler is None:
        return []
    ctx = dict(base_ctx)
    ctx['result_set'] = []
    ctx.pop('_llm_extra_prompt_locs', None)
    fast_mode = bool(ctx.get('fast_scope_expand'))
    try:
        handler(taint, ctx)
    except Exception:
        return []
    out = list(ctx.get('result_set') or [])
    extra = ctx.get('_llm_extra_prompt_locs') or []
    if extra:
        out.extend(list(extra))
    def _loc_strings(items: List) -> List[str]:
        buf: List[str] = []
        for loc in items or []:
            if isinstance(loc, str):
                if loc.strip():
                    buf.append(loc.strip())
                continue
            if isinstance(loc, dict):
                if loc.get('loc'):
                    s = str(loc.get('loc')).strip()
                    if s:
                        buf.append(s)
                    continue
                p = (loc.get('path') or '').strip()
                ln = loc.get('line')
                if p and ln is not None:
                    try:
                        buf.append(f"{p}:{int(ln)}")
                    except Exception:
                        pass
        return buf

    def _append_unique_str_items(dst: List, items: List[str], *, seen: Set[str]) -> None:
        for s in items or []:
            ss = (s or '').strip()
            if not ss or ss in seen:
                continue
            dst.append(ss)
            seen.add(ss)

    def _expand_includes(items: list) -> None:
        locs = _loc_strings(items)
        if not locs:
            return
        try:
            from taint_handlers.handlers.helpers.ast_var_include import expand_includes_in_locs

            extra_includes, _ = expand_includes_in_locs(locs=list(locs), ctx=ctx)
            if extra_includes:
                _append_unique_str_items(items, list(extra_includes), seen=set(locs))
        except Exception:
            return

    def _extend_includers(items: list) -> None:
        locs = _loc_strings(items)
        if not locs:
            return
        nodes = ctx.get('nodes') or {}
        trace_index_records = ctx.get('trace_index_records') or []
        if not nodes or not trace_index_records:
            return
        loc_to_records = ctx.get('loc_to_records') or _build_loc_to_records(trace_index_records)
        idx_to_pos = ctx.get('idx_to_pos') or {}
        if not idx_to_pos:
            for pos, rec in enumerate(trace_index_records):
                idx = rec.get('index')
                try:
                    idx_to_pos[int(idx)] = int(pos)
                except Exception:
                    continue
        ref_seq = ctx.get('input_seq')
        try:
            ref_seq_i = int(ref_seq) if ref_seq is not None else None
        except Exception:
            ref_seq_i = None

        def _rec_min_seq(rec: dict) -> Optional[int]:
            seqs = (rec or {}).get('seqs') or []
            if not seqs:
                return None
            try:
                return int(min(int(s) for s in seqs))
            except Exception:
                return None

        def _pick_best_rec(candidates: List[dict]) -> Optional[dict]:
            if not candidates:
                return None
            if ref_seq_i is None:
                keyed = [(int(_rec_min_seq(r) or 10**18), int(r.get('index') or 10**18), r) for r in candidates]
                keyed.sort(key=lambda x: (x[0], x[1]))
                return keyed[0][2] if keyed else None
            before = []
            after = []
            for c in candidates:
                ms = _rec_min_seq(c)
                if ms is None:
                    continue
                if int(ms) <= int(ref_seq_i):
                    before.append((int(ms), int(c.get('index') or 10**18), c))
                else:
                    after.append((int(ms), int(c.get('index') or 10**18), c))
            if before:
                before.sort(key=lambda x: (-x[0], x[1]))
                return before[0][2]
            if after:
                after.sort(key=lambda x: (x[0], x[1]))
                return after[0][2]
            return candidates[0]

        try:
            from taint_handlers.handlers.expr.ast_var import _collect_scope_recs_and_locs_raw, _extend_include_scope_from_file_head
        except Exception:
            return

        seen = set(locs)
        extra_all: List[str] = []
        for loc in locs:
            pr = parse_loc(loc)
            if not pr:
                continue
            recs = loc_to_records.get(pr) or []
            if not recs:
                continue
            rec = _pick_best_rec(recs)
            if not isinstance(rec, dict):
                continue
            idx = rec.get('index')
            try:
                pos = idx_to_pos.get(int(idx)) if idx is not None else None
            except Exception:
                pos = None
            if pos is None or not (0 <= int(pos) < len(trace_index_records)):
                continue
            node_ids = rec.get('node_ids') or []
            nid0 = node_ids[0] if node_ids else None
            try:
                fid = int((nodes.get(int(nid0)) or {}).get('funcid')) if nid0 is not None else None
            except Exception:
                fid = None
            if fid is None:
                continue
            _, _, stop_info = _collect_scope_recs_and_locs_raw(start_idx=int(pos), funcid=int(fid), ctx=ctx)
            stop_by = stop_info.get('stop_by')
            stop_index = stop_info.get('stop_index')
            if stop_by != 'toplevel_stop' or not isinstance(stop_index, int):
                continue
            extra2 = _extend_include_scope_from_file_head(stop_index=int(stop_index), funcid=int(fid), ctx=ctx)
            if extra2:
                for s in extra2:
                    ss = (s or '').strip()
                    if not ss or ss in seen:
                        continue
                    extra_all.append(ss)
                    seen.add(ss)
        if extra_all:
            items.extend(extra_all)

    _ = fast_mode
    return out


def _match_scope_nodes(
    *,
    target_parts: Set[Tuple[str, str]],
    scope_locs: Iterable,
    nodes: dict,
    children_of: dict,
    loc_to_records: Dict[Tuple[str, int], List[dict]],
    loc_to_min_seq: Dict[Tuple[str, int], int],
    node_parts_cache: Optional[Dict[int, Set[Tuple[str, str]]]] = None,
) -> Set[int]:
    """Return seqs whose nodes in the given scope match the target variable/call name parts."""
    out: Set[int] = set()
    if not target_parts:
        return out
    for loc in scope_locs or []:
        pr = _loc_to_path_line(loc)
        if not pr:
            continue
        recs = loc_to_records.get(pr) or []
        if not recs:
            continue
        min_seq = None
        if isinstance(loc, dict) and loc.get('seq') is not None:
            try:
                min_seq = int(loc.get('seq'))
            except Exception:
                min_seq = None
        if min_seq is None:
            min_seq = loc_to_min_seq.get(pr)
            if min_seq is None:
                continue
        for rec in recs:
            for nid in rec.get('node_ids') or []:
                try:
                    nid_i = int(nid)
                except Exception:
                    continue
                cached_parts = None
                if node_parts_cache is not None:
                    cached_parts = node_parts_cache.get(int(nid_i))
                if cached_parts is not None:
                    if any((p_tt, p_nm) in target_parts for p_tt, p_nm in cached_parts):
                        out.add(int(min_seq))
                        break
                    continue
                nx = nodes.get(nid_i) or {}
                tt = (nx.get('type') or '').strip()
                if tt not in _ALLOWED_TYPES:
                    if node_parts_cache is not None:
                        node_parts_cache[int(nid_i)] = set()
                    continue
                nm = ''
                if tt == 'AST_PARAM':
                    ss = get_string_children(nid_i, children_of, nodes)
                    nm = (ss[0][1] if ss else '')
                else:
                    nm = _node_source_str_with_this(nid_i, tt, nodes, children_of, '')
                if not nm:
                    if node_parts_cache is not None:
                        node_parts_cache[int(nid_i)] = set()
                    continue
                parts = _split_var_parts(tt, nm)
                if not parts:
                    if node_parts_cache is not None:
                        node_parts_cache[int(nid_i)] = set()
                    continue
                parts_set = set(parts)
                if node_parts_cache is not None:
                    node_parts_cache[int(nid_i)] = parts_set
                if any((p_tt, p_nm) in target_parts for p_tt, p_nm in parts):
                    out.add(int(min_seq))
                    break
            if int(min_seq) in out:
                break
    return out


def _select_near_far(
    seqs: Iterable[int],
    *,
    ref_seq: int,
    near_count: int,
    far_count: int,
) -> List[int]:
    """Pick a small set of seqs closest/farthest from ref_seq, keeping uniqueness and stable ordering."""
    items = []
    for s in seqs or []:
        try:
            items.append(int(s))
        except Exception:
            continue
    if not items:
        return []
    near_n = max(0, int(near_count))
    far_n = max(0, int(far_count))
    if near_n == 0 and far_n == 0:
        return sorted(set(items))
    uniq = sorted(set(items))
    if len(uniq) <= near_n + far_n:
        return uniq
    by_dist = sorted(uniq, key=lambda s: (abs(int(s) - int(ref_seq)), int(s)))
    near_pick = by_dist[:near_n] if near_n > 0 else []
    far_pick = list(reversed(by_dist))[:far_n] if far_n > 0 else []
    return sorted(set(near_pick + far_pick))


def _precompute_expand_indices(trace_index_records: List[dict], nodes: dict) -> dict:
    seq_to_index = {}
    seq_to_loc = {}
    idx_to_pos: Dict[int, int] = {}
    for rec in trace_index_records or []:
        idx = rec.get('index')
        rp = rec.get('path')
        rl = rec.get('line')
        try:
            if idx is not None:
                idx_to_pos[int(idx)] = len(idx_to_pos)
        except Exception:
            pass
        for s in rec.get('seqs') or []:
            try:
                si = int(s)
            except Exception:
                continue
            if si not in seq_to_index:
                seq_to_index[si] = int(idx) if idx is not None else 0
            if si not in seq_to_loc and rp and rl is not None:
                try:
                    seq_to_loc[si] = (str(rp), int(rl))
                except Exception:
                    continue
    return {
        'seq_to_index': seq_to_index,
        'seq_to_loc': seq_to_loc,
        'loc_to_records': _build_loc_to_records(trace_index_records),
        'loc_to_min_seq': _build_loc_to_min_seq(trace_index_records),
        'loc_to_seqs': build_seqs_by_loc(trace_index_records),
        'node_to_min_seq': _build_node_to_min_seq(trace_index_records),
        'funcid_to_path': _build_funcid_to_path(trace_index_records, nodes),
        'idx_to_pos': idx_to_pos,
    }


def _expand_one_seq(
    *,
    seq: int,
    rel_seqs: Optional[List[int]],
    trace_index_records: List[dict],
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    top_id_to_file: Optional[dict] = None,
    trace_path: str,
    scope_root: str,
    windows_root: str,
    nearest_seq_count: int,
    farthest_seq_count: int,
    indices: dict,
) -> Tuple[Optional[int], Optional[List[int]]]:
    timing_logger = indices.get('timing_logger')
    timing_threshold_us = indices.get('timing_threshold_us')
    try:
        timing_threshold_us = int(timing_threshold_us) if timing_threshold_us is not None else None
    except Exception:
        timing_threshold_us = None
    timing_meta = indices.get('timing_meta') or {}
    timing_on = timing_logger is not None and timing_threshold_us is not None
    if timing_on:
        _t_total_start = time.perf_counter_ns()
    try:
        seq_i = int(seq)
    except Exception:
        return None, None
    seq_to_index = indices.get('seq_to_index') or {}
    seq_to_loc = indices.get('seq_to_loc') or {}
    loc_to_records = indices.get('loc_to_records') or {}
    loc_to_min_seq = indices.get('loc_to_min_seq') or {}
    loc_to_seqs = indices.get('loc_to_seqs') or {}
    node_to_min_seq = indices.get('node_to_min_seq') or {}
    funcid_to_path = indices.get('funcid_to_path') or {}
    idx_to_pos = indices.get('idx_to_pos') or {}

    loc = seq_to_loc.get(seq_i)
    if loc is not None:
        arg = f"{loc[0]}:{int(loc[1])}"
    else:
        if timing_on:
            _t_read_start = time.perf_counter_ns()
        arg = read_trace_line(seq_i, trace_path)
        if timing_on:
            _t_read_us = int((time.perf_counter_ns() - _t_read_start) / 1000)
    if not arg:
        if timing_on:
            _t_total_us = int((time.perf_counter_ns() - _t_total_start) / 1000)
            if _t_total_us >= timing_threshold_us:
                timing_logger.info(
                    "expand_if_slow",
                    seq=int(seq_i),
                    index=timing_meta.get('index'),
                    path=timing_meta.get('path'),
                    line=timing_meta.get('line'),
                    total_us=_t_total_us,
                    read_us=locals().get('_t_read_us', 0),
                    extract_us=0,
                    taints_us=0,
                    ctx_us=0,
                    extra_us=0,
                    collect_us=0,
                    match_us=0,
                    taints=0,
                    matches=0,
                )
        return seq_i, list(rel_seqs or []) or [seq_i]
    if timing_on:
        _t_extract_start = time.perf_counter_ns()
    st = extract_if_elements_fast(arg, seq_i, nodes, children_of, trace_index_records, seq_to_index, parent_of, top_id_to_file)
    if timing_on:
        _t_extract_us = int((time.perf_counter_ns() - _t_extract_start) / 1000)
    if not (st.get('targets') or []):
        if timing_on:
            _t_total_us = int((time.perf_counter_ns() - _t_total_start) / 1000)
            if _t_total_us >= timing_threshold_us:
                timing_logger.info(
                    "expand_if_slow",
                    seq=int(seq_i),
                    index=timing_meta.get('index'),
                    path=timing_meta.get('path'),
                    line=timing_meta.get('line'),
                    total_us=_t_total_us,
                    read_us=locals().get('_t_read_us', 0),
                    extract_us=locals().get('_t_extract_us', 0),
                    taints_us=0,
                    ctx_us=0,
                    extra_us=0,
                    collect_us=0,
                    match_us=0,
                    taints=0,
                    matches=0,
                )
        return seq_i, list(rel_seqs or []) or [seq_i]
    st['seq'] = seq_i
    if timing_on:
        _t_taints_start = time.perf_counter_ns()
    taints = build_initial_taints(st, nodes, children_of, parent_of)
    if timing_on:
        _t_taints_us = int((time.perf_counter_ns() - _t_taints_start) / 1000)
    if not taints:
        if timing_on:
            _t_total_us = int((time.perf_counter_ns() - _t_total_start) / 1000)
            if _t_total_us >= timing_threshold_us:
                timing_logger.info(
                    "expand_if_slow",
                    seq=int(seq_i),
                    index=timing_meta.get('index'),
                    path=timing_meta.get('path'),
                    line=timing_meta.get('line'),
                    total_us=_t_total_us,
                    read_us=locals().get('_t_read_us', 0),
                    extract_us=locals().get('_t_extract_us', 0),
                    taints_us=locals().get('_t_taints_us', 0),
                    ctx_us=0,
                    extra_us=0,
                    collect_us=0,
                    match_us=0,
                    taints=0,
                    matches=0,
                )
        return seq_i, list(rel_seqs or []) or [seq_i]
    if timing_on:
        _t_ctx_start = time.perf_counter_ns()
    base_ctx = _build_ctx_for_seq(
        seq=seq_i,
        st=st,
        nodes=nodes,
        parent_of=parent_of,
        children_of=children_of,
        trace_index_records=trace_index_records,
        seq_to_index=seq_to_index,
        scope_root=scope_root,
        windows_root=windows_root,
        loc_to_records=loc_to_records,
        idx_to_pos=idx_to_pos,
        fast_scope_expand=bool(indices.get('fast_scope_expand')),
    )
    if timing_on:
        _t_ctx_us = int((time.perf_counter_ns() - _t_ctx_start) / 1000)
    seq_set = {seq_i}
    extra_scope_locs = []
    if timing_on:
        _t_extra_start = time.perf_counter_ns()
    for nid in st.get('targets') or []:
        try:
            nid_i = int(nid)
        except Exception:
            continue
        funcid = (nodes.get(nid_i) or {}).get('funcid')
        if funcid is None:
            continue
        try:
            funcid_i = int(funcid)
        except Exception:
            continue
        ftype = ((nodes.get(int(funcid_i)) or {}).get('type') or '').strip()
        if ftype not in ('AST_METHOD', 'AST_FUNC_DECL'):
            continue
        func_line = (nodes.get(int(funcid_i)) or {}).get('lineno')
        func_path = funcid_to_path.get(int(funcid_i))
        if func_path and func_line is not None:
            func_seq = None
            key = _loc_key(func_path, func_line)
            if key is not None:
                seqs = loc_to_seqs.get(key) or []
                if seqs:
                    pos = bisect.bisect_left(seqs, int(seq_i))
                    if pos <= 0:
                        func_seq = int(seqs[0])
                    elif pos >= len(seqs):
                        func_seq = int(seqs[-1])
                    else:
                        left = int(seqs[pos - 1])
                        right = int(seqs[pos])
                        func_seq = left if (int(seq_i) - left) <= (right - int(seq_i)) else right
            if func_seq is None:
                func_seq = node_to_min_seq.get(int(funcid_i))
            loc = {'path': str(func_path), 'line': int(func_line)}
            if func_seq is not None:
                loc['seq'] = int(func_seq)
            extra_scope_locs.append(loc)
            break
    if timing_on:
        _t_extra_us = int((time.perf_counter_ns() - _t_extra_start) / 1000)
        _t_collect_us = 0
        _t_match_us = 0
    node_parts_cache: Optional[Dict[int, Set[Tuple[str, str]]]] = {} if len(taints or []) > 1 else None
    for t in taints:
        tt = (t.get('type') or '').strip()
        if tt not in _ALLOWED_TYPES:
            continue
        tn = _taint_name(t)
        target_parts = set(_split_var_parts(tt, tn))
        if not target_parts:
            continue
        if timing_on:
            _t_collect_start = time.perf_counter_ns()
        scope_locs = _collect_scope_locs(t, base_ctx)
        if timing_on:
            _t_collect_us += int((time.perf_counter_ns() - _t_collect_start) / 1000)
        if extra_scope_locs:
            scope_locs = list(scope_locs or []) + list(extra_scope_locs)
        if timing_on:
            _t_match_start = time.perf_counter_ns()
        matches = _match_scope_nodes(
            target_parts=target_parts,
            scope_locs=scope_locs,
            nodes=nodes,
            children_of=children_of,
            loc_to_records=loc_to_records,
            loc_to_min_seq=loc_to_min_seq,
            node_parts_cache=node_parts_cache,
        )
        if timing_on:
            _t_match_us += int((time.perf_counter_ns() - _t_match_start) / 1000)
        seq_set.update(matches)
    rest = [x for x in seq_set if x != seq_i]
    picked = _select_near_far(
        rest,
        ref_seq=seq_i,
        near_count=nearest_seq_count,
        far_count=farthest_seq_count,
    )
    if timing_on:
        _t_total_us = int((time.perf_counter_ns() - _t_total_start) / 1000)
        if _t_total_us >= timing_threshold_us:
            timing_logger.info(
                "expand_if_slow",
                seq=int(seq_i),
                index=timing_meta.get('index'),
                path=timing_meta.get('path'),
                line=timing_meta.get('line'),
                total_us=_t_total_us,
                read_us=locals().get('_t_read_us', 0),
                extract_us=locals().get('_t_extract_us', 0),
                taints_us=locals().get('_t_taints_us', 0),
                ctx_us=locals().get('_t_ctx_us', 0),
                extra_us=locals().get('_t_extra_us', 0),
                collect_us=locals().get('_t_collect_us', 0),
                match_us=locals().get('_t_match_us', 0),
                taints=len(taints or []),
                matches=len(seq_set or []),
            )
    return seq_i, sorted({seq_i, *picked})


def expand_if_seq_groups_stream(
    *,
    seq_groups: Dict[int, List[int]],
    trace_index_records: List[dict],
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    trace_path: str,
    scope_root: str,
    windows_root: str,
    nearest_seq_count: int = 3,
    farthest_seq_count: int = 3,
    max_workers: Optional[int] = None,
    logger = None,
) -> Iterable[Tuple[int, List[int]]]:
    start_ts = time.perf_counter()
    items = list(seq_groups.items())
    total = len(items)
    if logger is not None:
        logger.info("expand_if_seq_groups_start", seqs=total)
    indices = _precompute_expand_indices(trace_index_records, nodes)
    workers = int(max_workers) if max_workers is not None else int(os.cpu_count() or 4)
    if workers < 1:
        workers = 1
    processed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for seq, rel_seqs in items:
            futures[ex.submit(
                _expand_one_seq,
                seq=seq,
                rel_seqs=rel_seqs,
                trace_index_records=trace_index_records,
                nodes=nodes,
                parent_of=parent_of,
                children_of=children_of,
                trace_path=trace_path,
                scope_root=scope_root,
                windows_root=windows_root,
                nearest_seq_count=nearest_seq_count,
                farthest_seq_count=farthest_seq_count,
                indices=indices,
            )] = (seq, rel_seqs)
        for fut in concurrent.futures.as_completed(futures):
            processed += 1
            try:
                seq_i, picked = fut.result()
            except Exception:
                seq, rel_seqs = futures.get(fut, (None, None))
                try:
                    seq_i = int(seq) if seq is not None else None
                except Exception:
                    seq_i = None
                picked = list(rel_seqs or []) or ([seq_i] if seq_i is not None else None)
            if seq_i is None or picked is None:
                continue
            if logger is not None and (processed % 50 == 0 or processed == total):
                elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
                logger.info("expand_if_seq_groups_progress", processed=processed, total=total, duration_ms=elapsed_ms)
            yield seq_i, picked
    if logger is not None:
        elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
        logger.info("expand_if_seq_groups_done", seqs=total, duration_ms=elapsed_ms)


def expand_if_seq_groups(
    *,
    seq_groups: Dict[int, List[int]],
    trace_index_records: List[dict],
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    trace_path: str,
    scope_root: str,
    windows_root: str,
    nearest_seq_count: int = 3,
    farthest_seq_count: int = 3,
    logger = None,
) -> Dict[int, List[int]]:
    """Expand each seed seq by collecting taint scopes and selecting nearby/farthest relevant seqs."""
    out: Dict[int, List[int]] = {}
    for seq_i, rel in expand_if_seq_groups_stream(
        seq_groups=seq_groups,
        trace_index_records=trace_index_records,
        nodes=nodes,
        parent_of=parent_of,
        children_of=children_of,
        trace_path=trace_path,
        scope_root=scope_root,
        windows_root=windows_root,
        nearest_seq_count=nearest_seq_count,
        farthest_seq_count=farthest_seq_count,
        logger=logger,
    ):
        out[int(seq_i)] = list(rel or [])
    return out
