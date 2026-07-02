"""
Helpers for handling the case where the LLM returns a variable taint that is passed
into a call by reference. In that case we enqueue the call itself as a new taint,
so downstream analysis can follow the side effects.
"""

import os
from typing import List, Optional, Set, Tuple, Union

from . import ast_method_call
from .llm_response import _node_display, _node_source_str


def _norm_name(s: str) -> str:
    """Normalize a variable/property/dim name for matching across nodes/LLM output."""
    v = (s or '').strip()
    if not v:
        return ''
    v = v.replace(' ', '').replace('\t', '')
    if v.startswith('$'):
        v = v[1:]
    v = v.replace('.', '->')
    return v


def _sorted_children(xid: int, nodes, children_of) -> List[int]:
    """Return children sorted by AST childnum (stable AST traversal order)."""
    ch = list(children_of.get(xid, []) or [])
    ch.sort(key=lambda cid: (nodes.get(cid) or {}).get('childnum') if (nodes.get(cid) or {}).get('childnum') is not None else 10**9)
    return [int(x) for x in ch]


def _find_descendant_by_type(root: int, want_type: str, nodes, children_of, *, max_depth: int) -> Optional[int]:
    """Find the first descendant of a given node that matches `want_type` within `max_depth`."""
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
        if d >= int(max_depth):
            continue
        for c in _sorted_children(nid, nodes, children_of):
            if c not in seen:
                q.append((int(c), d + 1))
    return None


def _subtree_contains(root: int, target: int, children_of) -> bool:
    """Return True if `target` is in the AST subtree rooted at `root`."""
    if root is None or target is None:
        return False
    try:
        root_i = int(root)
        target_i = int(target)
    except Exception:
        return False
    if root_i == target_i:
        return True
    q = [root_i]
    seen = set()
    cap = 8000
    while q and len(seen) < cap:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        for c in children_of.get(x, []) or []:
            try:
                ci = int(c)
            except Exception:
                continue
            if ci == target_i:
                return True
            if ci not in seen:
                q.append(ci)
    return False


def _iter_scope_records(scope_seqs: Union[Set[int], List[int]], ctx):
    """Iterate trace_index records for the provided scope seqs."""
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    for s in scope_seqs or []:
        try:
            si = int(s)
        except Exception:
            continue
        idx = seq_to_idx.get(si)
        if not isinstance(idx, int) or idx < 0 or idx >= len(recs):
            continue
        yield si, (recs[idx] or {})


def find_same_name_nodes_in_scope(var_taint: dict, scope_seqs: Union[Set[int], List[int]], ctx) -> List[dict]:
    """
    Find all AST nodes in `scope_seqs` whose source string matches `var_taint`'s name.

    This is used for the "same-name variable in current scope" fallback: the LLM may
    return a variable taint without an id, but the scope contains a node with the
    same source spelling (normalized).
    """
    if not isinstance(var_taint, dict) or not isinstance(ctx, dict):
        return []
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}

    want_name = _norm_name((var_taint.get('name') or '').strip())
    want_type = (var_taint.get('type') or '').strip()
    if not want_name or want_type not in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
        return []

    out = []
    seen = set()
    for seq, rec in _iter_scope_records(scope_seqs, ctx):
        for nid in rec.get('node_ids') or []:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            nx = nodes.get(nid_i) or {}
            tt = (nx.get('type') or '').strip()
            if tt not in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
                continue
            nm = _norm_name(_node_source_str(nid_i, tt, nodes, children_of))
            if not nm or nm != want_name:
                continue
            k = (nid_i, int(seq))
            if k in seen:
                continue
            seen.add(k)
            out.append({'id': nid_i, 'seq': int(seq), 'type': tt, 'name': nm})
    return out


def _call_taint_from_id(call_id: int, call_seq: int, ctx) -> Optional[dict]:
    """Build a taint dict for a call node id (AST_CALL/AST_METHOD_CALL)."""
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    nx = nodes.get(call_id) or {}
    tt = (nx.get('type') or '').strip()
    if tt not in ('AST_CALL', 'AST_METHOD_CALL'):
        return None
    t, nm = _node_display(call_id, nodes, children_of)
    out = {'id': int(call_id), 'seq': int(call_seq), 'type': tt}
    if isinstance(nm, str) and nm:
        out['name'] = nm
    if tt == 'AST_METHOD_CALL':
        recv = ''
        ch = list(children_of.get(call_id, []) or [])
        ch.sort(key=lambda cid: (nodes.get(cid) or {}).get('childnum') if (nodes.get(cid) or {}).get('childnum') is not None else 10**9)
        for c in ch:
            cx = nodes.get(c) or {}
            if (cx.get('type') or '').strip() == 'AST_ARG_LIST':
                continue
            if (cx.get('labels') == 'string') or ((cx.get('type') or '').strip() == 'string'):
                continue
            sub_t, sub_nm = _node_display(int(c), nodes, children_of)
            if sub_t in ('AST_VAR', 'AST_PROP', 'AST_DIM') and sub_nm:
                recv = sub_nm.split('->', 1)[0].split('.', 1)[0].lstrip('$')
                break
        if recv:
            out['recv'] = recv
    return out


def _callee_param_nodes(callee_id: int, ctx) -> List[int]:
    """Return the callee's AST_PARAM nodes (in parameter order)."""
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    param_list_id = _find_descendant_by_type(int(callee_id), 'AST_PARAM_LIST', nodes, children_of, max_depth=6)
    if param_list_id is None:
        return []
    out = []
    for pid in _sorted_children(param_list_id, nodes, children_of):
        if (nodes.get(pid) or {}).get('type') == 'AST_PARAM':
            out.append(int(pid))
    return out


def _is_param_byref(param_id: int, ctx) -> bool:
    """Return True if the parameter node has the PARAM_REF flag."""
    nodes = ctx.get('nodes') or {}
    flags = (nodes.get(int(param_id)) or {}).get('flags') or ''
    return isinstance(flags, str) and ('PARAM_REF' in flags)


def _calls_passing_node_as_arg(var_node_id: int, seq: int, ctx) -> List[Tuple[int, int]]:
    """
    Find call nodes at `seq` whose argument subtree contains `var_node_id`.

    Returns a list of `(call_id, arg_index)` where `arg_index` is the 0-based index
    in the callee argument list.
    """
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    idx = seq_to_idx.get(int(seq))
    if not isinstance(idx, int) or idx < 0 or idx >= len(recs):
        return []
    rec = recs[idx] or {}
    out = []
    for nid in rec.get('node_ids') or []:
        try:
            call_id = int(nid)
        except Exception:
            continue
        tt = (nodes.get(call_id) or {}).get('type') or ''
        if tt not in ('AST_CALL', 'AST_METHOD_CALL'):
            continue
        arg_list_id = _find_descendant_by_type(call_id, 'AST_ARG_LIST', nodes, children_of, max_depth=2)
        if arg_list_id is None:
            continue
        args = _sorted_children(arg_list_id, nodes, children_of)
        for arg_index, arg_root in enumerate(args):
            if _subtree_contains(arg_root, var_node_id, children_of):
                out.append((call_id, int(arg_index)))
                break
    return out


def collect_byref_call_taints_for_var(var_taint: dict, scope_seqs: Union[Set[int], List[int]], ctx) -> List[dict]:
    """
    Given a variable taint from the LLM, enqueue call taints when the variable is a by-ref argument.

    Algorithm:
    - Find same-name AST nodes within the LLM scope (scope_seqs).
    - For each occurrence, locate call nodes on the same seq that pass it as an argument.
    - Resolve the callee function id via CALLS edges (cpg_edges/trace_edges).
    - If the corresponding callee parameter is marked PARAM_REF, return that call as a new taint.
    """
    if not isinstance(var_taint, dict) or not isinstance(ctx, dict):
        return []
    if (var_taint.get('type') or '').strip() not in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
        return []
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}

    occurrences = find_same_name_nodes_in_scope(var_taint, scope_seqs, ctx)
    out = []
    seen_calls = set()
    base = os.getcwd()
    trace_path = os.path.join(base, 'trace.log')
    calls_edges = ctx.get('calls_edges_union')
    if calls_edges is None:
        calls_edges = ast_method_call.read_calls_edges(base)
        ctx['calls_edges_union'] = calls_edges

    for occ in occurrences:
        occ_id = occ.get('id')
        occ_seq = occ.get('seq')
        if occ_id is None or occ_seq is None:
            continue
        try:
            occ_id_i = int(occ_id)
            occ_seq_i = int(occ_seq)
        except Exception:
            continue
        idx = seq_to_idx.get(occ_seq_i)
        if not isinstance(idx, int) or idx < 0 or idx >= len(recs):
            continue
        for call_id, arg_index in _calls_passing_node_as_arg(occ_id_i, occ_seq_i, ctx):
            if (call_id, occ_seq_i) in seen_calls:
                continue
            cands = list(calls_edges.get(int(call_id)) or [])
            if not cands:
                continue
            callee_id = ast_method_call.pick_method_id(occ_seq_i, cands, ctx, trace_path)
            if callee_id is None:
                continue
            params = _callee_param_nodes(int(callee_id), ctx)
            if not params:
                continue
            if int(arg_index) < 0 or int(arg_index) >= len(params):
                continue
            if not _is_param_byref(int(params[int(arg_index)]), ctx):
                continue
            ct = _call_taint_from_id(int(call_id), occ_seq_i, ctx)
            if not ct:
                continue
            seen_calls.add((int(call_id), occ_seq_i))
            out.append(ct)
    return out
