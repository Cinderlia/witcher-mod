"""
Shared utilities for mapping between trace locations, seqs, and CPG AST nodes.

This module centralizes frequently repeated logic:
- Normalize trace/CPG paths
- Load `nodes.csv` and `rels.csv` (PARENT_OF)
- Resolve `AST_TOPLEVEL` file owners for nodes
- Query node children and extract string/name information
- Build and persist trace index records from `trace.log`
"""

import csv
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from common.app_config import load_app_config
from utils.cpg_utils import trace_index as _trace_index_mod


csv.field_size_limit(131072 * 10)

_FCALL_END_TOKEN = 'op=ZEND_EXT_FCALL_END'
_TRACE_EDGES_READY_BASES: Set[str] = set()


def safe_int(s: Any) -> Optional[int]:
    """Parse an int-like value, returning None on failure."""
    try:
        return int(s)
    except Exception:
        return None


def norm_trace_path(p: str) -> str:
    """Normalize a trace path so it matches how trace lines are indexed."""
    p = (p or '').strip()
    if p.startswith('/app/'):
        p = p[5:]
    if p.startswith('/'):
        p = p[1:]
    return p.lower()


def norm_nodes_path(p: str) -> str:
    """Normalize a CPG nodes-file path so it matches trace path normalization."""
    p = (p or '').strip()
    if p.startswith('/app/'):
        p = p[5:]
    if p.startswith('/'):
        p = p[1:]
    return p.lower()


def load_ast_edges(rels_path: str) -> Tuple[Dict[int, int], Dict[int, List[int]]]:
    """Load `PARENT_OF` edges into `(parent_of, children_of)` mappings."""
    parent_of: Dict[int, int] = {}
    children_of: Dict[int, List[int]] = {}
    with open(rels_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader((ln.replace('\x00', '') for ln in f), delimiter='\t')
        for row in reader:
            if (row.get('type') or '') != 'PARENT_OF':
                continue
            si = safe_int(row.get('start'))
            ei = safe_int(row.get('end'))
            if si is None or ei is None:
                continue
            parent_of[ei] = si
            children_of.setdefault(si, []).append(ei)
    return parent_of, children_of


def load_nodes(nodes_path: str) -> Tuple[Dict[int, dict], Dict[int, str]]:
    """Load CPG nodes from `nodes.csv` into an id->metadata dict and file mapping."""
    nodes: Dict[int, dict] = {}
    top_id_to_file: Dict[int, str] = {}
    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader((ln.replace('\x00', '') for ln in f), delimiter='\t')
        for row in reader:
            nid = safe_int(row.get('id:int'))
            if nid is None:
                continue
            nd = {
                'type': row.get('type') or '',
                'labels': row.get('labels:label') or '',
                'flags': row.get('flags:string_array') or '',
                'lineno': safe_int(row.get('lineno:int')),
                'code': row.get('code') or '',
                'childnum': safe_int(row.get('childnum:int')),
                'funcid': safe_int(row.get('funcid:int')),
                'classname': row.get('classname') or '',
                'namespace': row.get('namespace') or '',
                'name': row.get('name') or '',
                'doccomment': row.get('doccomment') or '',
            }
            nodes[nid] = nd
            if nd['type'] == 'AST_TOPLEVEL' and ('TOPLEVEL_FILE' in (nd.get('flags') or '')):
                path_val = nd.get('name') or nd.get('doccomment') or ''
                if path_val:
                    top_id_to_file[nid] = norm_nodes_path(path_val)
    return nodes, top_id_to_file


def resolve_top_id(nid: int, parent_of: Dict[int, int], nodes: Dict[int, dict], top_id_to_file: Dict[int, str]) -> Optional[int]:
    """Find the `AST_TOPLEVEL` file node containing `nid` (using parents/funcid)."""
    cur = safe_int(nid)
    steps = 0
    while cur is not None and steps < 64:
        if cur in top_id_to_file:
            return cur
        nxt = parent_of.get(cur)
        if nxt is None:
            cur = safe_int((nodes.get(cur) or {}).get('funcid'))
        else:
            cur = safe_int(nxt)
        steps += 1
    return None


def sorted_children(nid: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> List[int]:
    """Return node children sorted by `childnum` when available."""
    ch = list(children_of.get(nid, []) or [])
    ch.sort(key=lambda cid: safe_int((nodes.get(cid) or {}).get('childnum')) if safe_int((nodes.get(cid) or {}).get('childnum')) is not None else 10**9)
    return ch


def find_descendant_by_type(root_id: int, want_type: str, nodes: Dict[int, dict], children_of: Dict[int, List[int]], *, max_depth: int = 4) -> Optional[int]:
    if root_id is None:
        return None
    wt = (want_type or '').strip()
    if not wt:
        return None
    try:
        rid = int(root_id)
    except Exception:
        return None
    q: List[Tuple[int, int]] = [(rid, 0)]
    seen: Set[int] = set()
    while q:
        x, depth = q.pop(0)
        if x in seen:
            continue
        seen.add(x)
        if depth > 0:
            tt = ((nodes.get(x) or {}).get('type') or '').strip()
            if tt == wt:
                return int(x)
        if depth >= int(max_depth):
            continue
        for c in children_of.get(int(x), []) or []:
            try:
                q.append((int(c), depth + 1))
            except Exception:
                continue
    return None


def subtree_contains(root_id: int, target_id: int, children_of: Dict[int, List[int]], *, max_depth: int = 30) -> bool:
    if root_id is None or target_id is None:
        return False
    try:
        rid = int(root_id)
        tid = int(target_id)
    except Exception:
        return False
    q: List[Tuple[int, int]] = [(rid, 0)]
    seen: Set[int] = set()
    while q:
        x, depth = q.pop()
        if x == tid:
            return True
        if depth >= int(max_depth):
            continue
        if x in seen:
            continue
        seen.add(x)
        for c in children_of.get(int(x), []) or []:
            try:
                q.append((int(c), depth + 1))
            except Exception:
                continue
    return False


def dim_index_roots(dim_id: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> List[int]:
    """Return index expression roots for an `AST_DIM` node (excluding the base)."""
    if dim_id is None:
        return []
    try:
        did = int(dim_id)
    except Exception:
        return []
    ch = sorted_children(did, children_of, nodes)
    if len(ch) < 2:
        return []
    return [int(x) for x in ch[1:]]


def is_in_dim_index_subtree(dim_id: int, nid: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]], *, max_depth: int = 30) -> bool:
    """Return True if `nid` lies in the index expression subtree of `dim_id`."""
    if dim_id is None or nid is None:
        return False
    try:
        did = int(dim_id)
        tid = int(nid)
    except Exception:
        return False
    for r in dim_index_roots(did, nodes, children_of):
        if subtree_contains(int(r), tid, children_of, max_depth=max_depth):
            return True
    return False


def is_in_call_arg_subtree(call_id: int, nid: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]], *, max_depth: int = 30) -> bool:
    if call_id is None or nid is None:
        return False
    try:
        cid = int(call_id)
        tid = int(nid)
    except Exception:
        return False
    roots = call_arg_list_ids(cid, nodes, children_of)
    if not roots:
        return False
    for r in roots:
        if subtree_contains(int(r), tid, children_of, max_depth=max_depth):
            return True
    return False


def call_arg_list_ids(call_id: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> List[int]:
    if call_id is None:
        return []
    try:
        cid = int(call_id)
    except Exception:
        return []
    roots = []
    for c in sorted_children(cid, children_of, nodes):
        cx = nodes.get(int(c)) or {}
        if (cx.get('type') or '').strip() == 'AST_ARG_LIST':
            roots.append(int(c))
    if roots:
        return roots
    arg_list_id = find_descendant_by_type(cid, 'AST_ARG_LIST', nodes, children_of, max_depth=3)
    if arg_list_id is None:
        return []
    try:
        return [int(arg_list_id)]
    except Exception:
        return []


def method_call_receiver_roots(call_id: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> List[int]:
    if call_id is None:
        return []
    try:
        cid = int(call_id)
    except Exception:
        return []
    for c in sorted_children(cid, children_of, nodes):
        cx = nodes.get(int(c)) or {}
        ct = (cx.get('type') or '').strip()
        if ct == 'AST_ARG_LIST':
            continue
        if ct == 'AST_NAME':
            continue
        if (cx.get('labels') == 'string') or (ct == 'string'):
            continue
        return [int(c)]
    return []


def _norm_base_ident(s: str) -> str:
    v = (s or '').strip()
    if not v:
        return ''
    if v.startswith('$'):
        v = v[1:]
    for sep in ('->', '.', '[', '('):
        if sep in v:
            v = v.split(sep, 1)[0].strip()
    return v


def base_var_name_for_node(nid: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> str:
    if nid is None:
        return ''
    try:
        xid = int(nid)
    except Exception:
        return ''
    nx = nodes.get(xid) or {}
    tt = (nx.get('type') or '').strip()
    v = ''
    if tt == 'AST_VAR':
        ss = get_string_children(xid, children_of, nodes)
        v = ss[0][1] if ss else ''
    elif tt in ('AST_PROP', 'AST_DIM'):
        v = (find_first_var_string(xid, children_of, nodes) or '').strip()
    if not v:
        v = (nx.get('code') or nx.get('name') or '').strip()
    return _norm_base_ident(v)


def collect_base_var_names_in_subtree(root_id: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]], *, max_depth: int = 30) -> Set[str]:
    if root_id is None:
        return set()
    try:
        rid = int(root_id)
    except Exception:
        return set()
    out: Set[str] = set()
    q: List[Tuple[int, int]] = [(rid, 0)]
    seen: Set[int] = set()
    while q:
        x, depth = q.pop()
        if x in seen:
            continue
        seen.add(x)
        nx = nodes.get(int(x)) or {}
        tt = (nx.get('type') or '').strip()
        if tt in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
            nm = base_var_name_for_node(int(x), nodes, children_of)
            if nm:
                out.add(nm)
        if depth >= int(max_depth):
            continue
        for c in children_of.get(int(x), []) or []:
            try:
                q.append((int(c), depth + 1))
            except Exception:
                continue
    return out


def call_arg_base_names(call_id: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Set[str]:
    out: Set[str] = set()
    for r in call_arg_list_ids(call_id, nodes, children_of):
        out |= collect_base_var_names_in_subtree(int(r), nodes, children_of)
    return out


def method_call_receiver_base_names(call_id: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Set[str]:
    out: Set[str] = set()
    for r in method_call_receiver_roots(call_id, nodes, children_of):
        out |= collect_base_var_names_in_subtree(int(r), nodes, children_of)
    return out


def dim_index_base_names(dim_id: int, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Set[str]:
    out: Set[str] = set()
    for r in dim_index_roots(dim_id, nodes, children_of):
        out |= collect_base_var_names_in_subtree(int(r), nodes, children_of)
    return out


def is_in_method_call_receiver_subtree(
    call_id: int,
    nid: int,
    nodes: Dict[int, dict],
    children_of: Dict[int, List[int]],
    *,
    max_depth: int = 30,
) -> bool:
    if call_id is None or nid is None:
        return False
    try:
        cid = int(call_id)
        tid = int(nid)
    except Exception:
        return False
    roots = method_call_receiver_roots(cid, nodes, children_of)
    if not roots:
        return False
    for r in roots:
        if subtree_contains(int(r), tid, children_of, max_depth=max_depth):
            return True
    return False


def get_string_children(nid: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> List[Tuple[int, str]]:
    """Return direct child string nodes for an AST node as `(child_id, text)` pairs."""
    vals: List[Tuple[int, str]] = []
    for c in children_of.get(nid, []) or []:
        nc = nodes.get(c)
        if not nc:
            continue
        if nc.get('labels') == 'string' or (nc.get('type') == 'string'):
            v = (nc.get('code') or nc.get('name') or '').strip()
            if v:
                vals.append((int(c), v))
    return vals


def get_all_string_descendants(nid: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> List[Tuple[int, str]]:
    """Return all descendant string nodes for a node as `(node_id, text)` pairs."""
    vals: List[Tuple[int, str]] = []
    q = [int(nid)]
    seen: Set[int] = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if x != nid:
            nc = nodes.get(x)
            if nc and (nc.get('labels') == 'string' or (nc.get('type') == 'string')):
                v = (nc.get('code') or nc.get('name') or '').strip()
                if v:
                    vals.append((int(x), v))
        for c in children_of.get(x, []) or []:
            q.append(int(c))
    return vals


def find_first_var_string(nid: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> str:
    """Find the first `AST_VAR` descendant's string name under `nid`."""
    q = list(children_of.get(nid, []) or [])
    seen: Set[int] = set()
    while q:
        x = q.pop(0)
        try:
            xi = int(x)
        except Exception:
            continue
        if xi in seen:
            continue
        seen.add(xi)
        nx = nodes.get(xi)
        if not nx:
            continue
        if (nx.get('type') or '') == 'AST_VAR':
            ss = get_string_children(xi, children_of, nodes)
            if ss:
                return ss[0][1]
        for c in children_of.get(xi, []) or []:
            q.append(c)
    return ''


def get_string_value(nid: int, nodes: Dict[int, dict]) -> str:
    """Return the string literal value for a node if it is a string node."""
    nx = nodes.get(nid) or {}
    if nx.get('labels') == 'string' or (nx.get('type') == 'string'):
        return (nx.get('code') or nx.get('name') or '').strip()
    return ''


def get_ast_name_string_child(ast_name_id: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> str:
    """Return the first direct string child value under an `AST_NAME` node."""
    for c in children_of.get(ast_name_id, []) or []:
        v = get_string_value(int(c), nodes)
        if v:
            return v
    return ''


def get_direct_callsite_name(call_id: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> str:
    """Extract a direct callsite name from immediate children of a call node."""
    for c in children_of.get(call_id, []) or []:
        cx = nodes.get(int(c)) or {}
        ct = (cx.get('type') or '').strip()
        if ct == 'AST_ARG_LIST':
            continue
        v = get_string_value(int(c), nodes)
        if v:
            return v
        if ct == 'AST_NAME':
            v2 = get_ast_name_string_child(int(c), children_of, nodes)
            if v2:
                return v2
    return ''


def find_descendant_callsite_name(call_id: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> str:
    """Find a callsite name by searching descendants (fallback when direct name missing)."""
    q = []
    for c in children_of.get(call_id, []) or []:
        cx = nodes.get(int(c)) or {}
        if (cx.get('type') or '') == 'AST_ARG_LIST':
            continue
        q.append(int(c))
    seen: Set[int] = set()
    while q:
        x = q.pop(0)
        if x in seen:
            continue
        seen.add(x)
        xx = nodes.get(x) or {}
        if (xx.get('type') or '') == 'AST_NAME':
            v = get_ast_name_string_child(x, children_of, nodes)
            if v:
                return v
        for c in children_of.get(x, []) or []:
            q.append(int(c))
    return ''


def get_call_name(nid: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> str:
    """Resolve a call expression's name from multiple possible AST encodings."""
    nx = nodes.get(nid) or {}
    name = (nx.get('name') or '').strip()
    if name:
        return name
    v = get_direct_callsite_name(nid, children_of, nodes)
    if v:
        return v
    v2 = find_descendant_callsite_name(nid, children_of, nodes)
    if v2:
        return v2
    return (nx.get('code') or '').strip()


def get_decl_name(nid: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> str:
    """Resolve a callee declaration name from a declaration node subtree."""
    nx = nodes.get(nid) or {}
    name = (nx.get('name') or '').strip()
    if name:
        return name
    for c in children_of.get(nid, []) or []:
        cx = nodes.get(int(c)) or {}
        ct = (cx.get('type') or '').strip()
        if ct == 'AST_NAME':
            v = get_ast_name_string_child(int(c), children_of, nodes)
            if v:
                return v
        v2 = get_string_value(int(c), nodes)
        if v2:
            return v2
    ss = get_string_children(nid, children_of, nodes)
    if ss:
        return ss[0][1]
    return (nx.get('code') or '').strip()


def _merge_fcall_end_groups(groups: List[dict]) -> List[dict]:
    """Merge adjacent trace groups when Zend FCALL_END appears for the same location."""
    if not groups:
        return groups
    out: List[dict] = []
    last_pos_by_key: Dict[Tuple[str, int], int] = {}
    for g in groups:
        key = (g.get('path'), g.get('line'))
        if g.get('has_fcall_end'):
            prev_pos = last_pos_by_key.get(key)
            if prev_pos is not None:
                prev = out[prev_pos]
                if isinstance(prev.get('seqs'), list) and isinstance(g.get('seqs'), list):
                    prev['seqs'].extend(g['seqs'])
                if isinstance(prev.get('raw_lines'), list) and isinstance(g.get('raw_lines'), list):
                    prev['raw_lines'].extend(g['raw_lines'])
                continue
        ng = dict(g)
        ng.pop('has_fcall_end', None)
        out.append(ng)
        last_pos_by_key[key] = len(out) - 1
    return out


def read_trace_groups(trace_path: str, limit: Optional[int] = None) -> List[dict]:
    """Group `trace.log` lines by `(path,line)` and keep raw lines (no seqs)."""
    groups: List[dict] = []
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        count = 0
        last_key = None
        for line in f:
            if limit is not None and count >= limit:
                break
            line = line.strip()
            if not line:
                continue
            has_fcall_end = _FCALL_END_TOKEN in line
            prefix = line.split(' | ', 1)[0]
            if ':' not in prefix:
                count += 1
                continue
            path_part, line_part = prefix.rsplit(':', 1)
            ln = safe_int(line_part)
            if ln is None:
                count += 1
                continue
            np = norm_trace_path(path_part)
            key = (np, int(ln))
            if groups and key == last_key:
                groups[-1]['raw_lines'].append(line)
                groups[-1]['has_fcall_end'] = groups[-1].get('has_fcall_end') or has_fcall_end
            else:
                groups.append({'path': np, 'line': int(ln), 'raw_lines': [line], 'has_fcall_end': has_fcall_end})
                last_key = key
            count += 1
    return _merge_fcall_end_groups(groups)


def read_trace_groups_with_seqs(trace_path: str, limit: Optional[int] = None) -> List[dict]:
    """Group `trace.log` lines by `(path,line)` and keep 1-based seq numbers."""
    groups: List[dict] = []
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        count = 0
        last_key = None
        for line in f:
            if limit is not None and count >= limit:
                break
            count += 1
            raw = line.strip()
            if not raw:
                continue
            has_fcall_end = _FCALL_END_TOKEN in raw
            prefix = raw.split(' | ', 1)[0]
            if ':' not in prefix:
                continue
            path_part, line_part = prefix.rsplit(':', 1)
            ln = safe_int(line_part)
            if ln is None:
                continue
            np = norm_trace_path(path_part)
            key = (np, int(ln))
            if groups and key == last_key:
                groups[-1]['seqs'].append(int(count))
                groups[-1]['has_fcall_end'] = groups[-1].get('has_fcall_end') or has_fcall_end
            else:
                groups.append({'path': np, 'line': int(ln), 'seqs': [int(count)], 'has_fcall_end': has_fcall_end})
                last_key = key
    return _merge_fcall_end_groups(groups)


def build_nodes_index(nodes_path: str, target: List[Tuple[str, int]]) -> Dict[Tuple[str, int], List[Tuple[int, str, str]]]:
    """Index CPG nodes by `(normalized_path,line)` for a provided set of locations."""
    target_paths = set(k[0] for k in target)
    target_lines_by_path: Dict[str, Set[int]] = {}
    for p, ln in target:
        target_lines_by_path.setdefault(p, set()).add(int(ln))

    nodes_by_file_line: Dict[Tuple[str, int], List[Tuple[int, str, str]]] = {}
    top_id_to_file: Dict[int, str] = {}
    parent_of: Dict[int, int] = {}
    children_of_func: Dict[int, Set[int]] = {}

    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            nid_i = safe_int(row.get('id:int'))
            if nid_i is None:
                continue
            typ = row.get('type') or ''
            flags = row.get('flags:string_array') or ''
            name = row.get('name') or ''
            doccomment = row.get('doccomment') or ''
            if typ == 'AST_TOPLEVEL' and ('TOPLEVEL_FILE' in flags):
                path_val = name if name else doccomment
                if path_val:
                    top_id_to_file[int(nid_i)] = norm_nodes_path(path_val)
                continue
            funcid_i = safe_int(row.get('funcid:int'))
            if funcid_i is not None:
                parent_of[int(nid_i)] = int(funcid_i)
                children_of_func.setdefault(int(funcid_i), set()).add(int(nid_i))

    node_to_top: Dict[int, Optional[int]] = {}

    def resolve_top_id_local(nid_i: int) -> Optional[int]:
        cur = int(nid_i)
        seen = 0
        while cur is not None and seen < 64:
            if cur in node_to_top:
                return node_to_top[cur]
            if cur in top_id_to_file:
                node_to_top[cur] = cur
                return cur
            nxt = parent_of.get(cur)
            if nxt is None:
                ch = children_of_func.get(cur)
                if ch:
                    for cid in ch:
                        if cid in top_id_to_file:
                            node_to_top[cur] = cid
                            return cid
                node_to_top[cur] = None
                return None
            cur = int(nxt)
            seen += 1
        return None

    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            nid_i = safe_int(row.get('id:int'))
            if nid_i is None:
                continue
            typ = row.get('type') or ''
            lab = row.get('labels:label') or ''
            lineno_i = safe_int(row.get('lineno:int'))
            if lineno_i is None:
                continue
            top_i = resolve_top_id_local(int(nid_i))
            if top_i is None:
                funcid_i = safe_int(row.get('funcid:int'))
                if funcid_i is not None:
                    top_i = resolve_top_id_local(int(funcid_i))
            if top_i is None:
                continue
            file_path = top_id_to_file.get(int(top_i))
            if not file_path or file_path not in target_paths:
                continue
            if int(lineno_i) not in target_lines_by_path.get(file_path, set()):
                continue
            nodes_by_file_line.setdefault((file_path, int(lineno_i)), []).append((int(nid_i), str(lab), str(typ)))
    return nodes_by_file_line


def build_trace_index_records(trace_path: str, nodes_path: str, limit: Optional[int] = None) -> List[dict]:
    """Build trace index records by joining trace groups with CPG nodes on the same loc."""
    groups = read_trace_groups_with_seqs(trace_path, limit)
    target = [(g['path'], g['line']) for g in groups]
    nodes_index = build_nodes_index(nodes_path, target)
    records: List[dict] = []
    for i, g in enumerate(groups):
        k = (g['path'], g['line'])
        nodes = nodes_index.get(k, [])
        node_ids = [n[0] for n in nodes]
        records.append({'index': int(i), 'path': g['path'], 'line': int(g['line']), 'seqs': list(g.get('seqs') or []), 'node_ids': node_ids})
    return records


def load_trace_index_records(index_path: str) -> Optional[List[dict]]:
    """Load `trace_index.json` and return its `records` list (or None)."""
    return _trace_index_mod.load_trace_index_records(index_path)


def save_trace_index_records(index_path: str, records: List[dict], meta: Optional[dict] = None) -> None:
    """Atomically write `trace_index.json` with optional metadata."""
    _trace_index_mod.save_trace_index_records(index_path, records, meta)


def ensure_trace_edges_csv(base: str) -> bool:
    base = (base or '').strip()
    if not base:
        base = os.getcwd()
    base_norm = os.path.abspath(base)
    if base_norm in _TRACE_EDGES_READY_BASES:
        cfg0 = load_app_config(config_path=os.path.join(base_norm, 'config.json'), base_dir=base_norm)
        return os.path.exists(cfg0.tmp_path('trace_edges.csv'))
    cfg = load_app_config(config_path=os.path.join(base_norm, 'config.json'), base_dir=base_norm)
    p = cfg.tmp_path('trace_edges.csv')
    if os.path.exists(p):
        _TRACE_EDGES_READY_BASES.add(base_norm)
        return True
    script_candidates = [
        os.path.join(base_norm, 'utils', 'trace_utils', 'trace_edges.py'),
        os.path.join(base_norm, 'trace_edges.py'),
        os.path.join(base_norm, 'utils', 'cpg_utils', 'trace_call_edges.py'),
    ]
    script_paths = [sp for sp in script_candidates if os.path.exists(sp)]
    if not script_paths:
        return False
    for script_path in script_paths:
        try:
            subprocess.run(
                [sys.executable, script_path],
                cwd=base_norm,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            continue
        if os.path.exists(p):
            _TRACE_EDGES_READY_BASES.add(base_norm)
            return True
    if os.path.exists(p):
        _TRACE_EDGES_READY_BASES.add(base_norm)
        return True
    return False


def read_calls_edges_union(base: str) -> Dict[int, Set[int]]:
    """Read `CALLS` edges from `cpg_edges.csv` and `trace_edges.csv` and return their union."""
    cfg = load_app_config(config_path=os.path.join(os.path.abspath(base or os.getcwd()), 'config.json'), base_dir=(base or os.getcwd()))
    ensure_trace_edges_csv(cfg.base_dir)
    def read_edges(path: str) -> Dict[int, Set[int]]:
        m: Dict[int, Set[int]] = {}
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
                si = safe_int(parts[0])
                ei = safe_int(parts[1])
                if si is None or ei is None:
                    continue
                t = (parts[2] or '').strip()
                if t != 'CALLS':
                    continue
                m.setdefault(int(si), set()).add(int(ei))
        return m

    out: Dict[int, Set[int]] = {}
    candidates = [
        cfg.find_input_file('cpg_edges.csv'),
        cfg.tmp_path('trace_edges.csv'),
        os.path.join(cfg.base_dir, 'trace_edges.csv'),
        os.path.join(cfg.base_dir, 'cpg_edges.csv'),
    ]
    for path in candidates:
        edges = read_edges(path)
        for s, dsts in edges.items():
            cur = out.get(int(s))
            if cur is None:
                out[int(s)] = set(dsts)
            else:
                cur |= set(dsts)
    return out


def build_funcid_to_call_ids(calls_edges_union: Optional[Dict[int, Set[int]]]) -> Dict[int, Set[int]]:
    """Build a reverse mapping from callee funcid -> caller call node ids."""
    out: Dict[int, Set[int]] = {}
    if not isinstance(calls_edges_union, dict):
        return out
    for call_id, dsts in calls_edges_union.items():
        try:
            call_id_i = int(call_id)
        except Exception:
            continue
        if not isinstance(dsts, (set, list, tuple)):
            continue
        for d in dsts:
            try:
                d_i = int(d)
            except Exception:
                continue
            out.setdefault(d_i, set()).add(call_id_i)
    return out


def find_nearest_callsite_locator(call_ids: Set[int], records: List[dict], start_index: int) -> Optional[str]:
    """Find the nearest preceding trace locator whose node_ids include any of `call_ids`."""
    if not call_ids or not records:
        return None
    try:
        si = int(start_index)
    except Exception:
        return None
    if si >= len(records):
        si = len(records) - 1
    for j in range(si, -1, -1):
        rec = records[j] or {}
        node_ids = rec.get('node_ids') or []
        hit = False
        for nid in node_ids:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            if nid_i in call_ids:
                hit = True
                break
        if not hit:
            continue
        p = (rec.get('path') or '').strip()
        ln = rec.get('line')
        if not p or ln is None:
            continue
        try:
            ln_i = int(ln)
        except Exception:
            continue
        return f"{p}:{ln_i}"
    return None


def min_seq_from_trace_record(rec: dict) -> Optional[int]:
    seqs = (rec or {}).get('seqs') or []
    if not seqs:
        return None
    try:
        return int(min(int(x) for x in seqs))
    except Exception:
        return None


def _strip_dollar(s: str) -> str:
    v = (s or '').strip()
    if v.startswith('$'):
        return v[1:]
    return v


def method_call_receiver_name(call_id: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> str:
    recv = ''
    ch = list(children_of.get(int(call_id), []) or [])
    ch.sort(key=lambda cid: safe_int((nodes.get(cid) or {}).get('childnum')) if safe_int((nodes.get(cid) or {}).get('childnum')) is not None else 10**9)
    for c in ch:
        cx = nodes.get(int(c)) or {}
        ct = (cx.get('type') or '').strip()
        if ct == 'AST_ARG_LIST':
            continue
        if (cx.get('labels') == 'string') or (ct == 'string'):
            continue
        if ct == 'AST_VAR':
            ss = get_string_children(int(c), children_of, nodes)
            v = ss[0][1] if ss else ''
            if v:
                recv = v
                break
        if ct in ('AST_PROP', 'AST_DIM'):
            v = (find_first_var_string(int(c), children_of, nodes) or '').strip()
            if v:
                recv = v
                break
        v = (cx.get('code') or cx.get('name') or '').strip()
        if v:
            recv = v
            break
    recv = _strip_dollar(recv)
    if '->' in recv:
        recv = recv.split('->', 1)[0].strip()
    if '.' in recv:
        recv = recv.split('.', 1)[0].strip()
    if '(' in recv:
        recv = recv.split('(', 1)[0].strip()
    return recv


def find_nearest_callsite_record(
    call_ids: Set[int],
    records: List[dict],
    start_index: int,
) -> Optional[Tuple[int, int, str]]:
    if not call_ids or not records:
        return None
    try:
        si = int(start_index)
    except Exception:
        return None
    if si >= len(records):
        si = len(records) - 1
    for j in range(si, -1, -1):
        rec = records[j] or {}
        node_ids = rec.get('node_ids') or []
        hit_id = None
        for nid in node_ids:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            if nid_i in call_ids:
                hit_id = nid_i
                break
        if hit_id is None:
            continue
        p = (rec.get('path') or '').strip()
        ln = rec.get('line')
        if not p or ln is None:
            continue
        try:
            ln_i = int(ln)
        except Exception:
            continue
        return j, int(hit_id), f"{p}:{ln_i}"
    return None


def resolve_this_object_chain(
    *,
    records: List[dict],
    nodes: Dict[int, dict],
    children_of: Dict[int, List[int]],
    calls_edges_union: Optional[Dict[int, Set[int]]],
    start_index: int,
    max_hops: int = 8,
) -> dict:
    funcid_to_call_ids = build_funcid_to_call_ids(calls_edges_union)
    hops = []
    extra_locs = []
    origin_func_def_loc = None
    first_call_loc = None
    first_call_seq = None
    resolved_obj = ''
    resolved_call_loc = None
    resolved_call_seq = None
    cur_start = safe_int(start_index)
    for hop in range(int(max_hops)):
        if cur_start is None or cur_start < 0 or cur_start >= len(records):
            break
        rec0 = records[cur_start] or {}
        node_ids0 = rec0.get('node_ids') or []
        cur_id0 = None
        try:
            cur_id0 = int(node_ids0[0]) if node_ids0 else None
        except Exception:
            cur_id0 = None
        if cur_id0 is None:
            break
        cur_funcid = safe_int((nodes.get(int(cur_id0)) or {}).get('funcid'))
        if cur_funcid is None:
            break
        stop_index = None
        stop_loc = None
        for i in range(cur_start, -1, -1):
            rec = records[i] or {}
            node_ids = rec.get('node_ids') or []
            cur_id = None
            try:
                cur_id = int(node_ids[0]) if node_ids else None
            except Exception:
                cur_id = None
            if cur_id is None:
                continue
            if cur_id == int(cur_funcid):
                stop_index = int(i)
                p = (rec.get('path') or '').strip()
                ln = rec.get('line')
                if p and ln is not None:
                    try:
                        stop_loc = f"{p}:{int(ln)}"
                    except Exception:
                        stop_loc = None
                break
        if stop_index is None or stop_index <= 0:
            break
        if hop == 0:
            origin_func_def_loc = stop_loc
        call_ids = funcid_to_call_ids.get(int(cur_funcid)) or set()
        hit = find_nearest_callsite_record(set(call_ids), records, stop_index - 1)
        if not hit:
            break
        call_index, call_id, call_loc = hit
        call_seq = None
        try:
            rec_call = records[int(call_index)] or {}
            seqs = rec_call.get('seqs') or []
            if seqs:
                call_seq = int(min(int(x) for x in seqs))
        except Exception:
            call_seq = None
        if hop == 0:
            first_call_loc = call_loc
            if call_seq is not None:
                first_call_seq = int(call_seq)
        bridge = []
        for j in range(stop_index - 1, call_index - 1, -1):
            rj = records[j] or {}
            p = (rj.get('path') or '').strip()
            ln = rj.get('line')
            if not p or ln is None:
                continue
            try:
                bridge.append(f"{p}:{int(ln)}")
            except Exception:
                continue
        if bridge:
            extra_locs.extend(bridge)
        recv = method_call_receiver_name(int(call_id), children_of, nodes)
        hops.append(
            {
                'hop': int(hop),
                'funcid': int(cur_funcid),
                'stop_loc': stop_loc,
                'call_id': int(call_id),
                'call_loc': call_loc,
                'call_seq': int(call_seq) if call_seq is not None else None,
                'recv': recv,
            }
        )
        if recv and recv not in ('this', '$this'):
            resolved_obj = _strip_dollar(recv)
            resolved_call_loc = call_loc
            if call_seq is not None:
                resolved_call_seq = int(call_seq)
            break
        cur_start = int(call_index)
    preamble = []
    if first_call_loc:
        preamble.append(first_call_loc)
    if origin_func_def_loc:
        preamble.append(origin_func_def_loc)
    return {
        'obj': resolved_obj,
        'preamble_locs': preamble,
        'extra_locs': extra_locs,
        'first_call_loc': first_call_loc,
        'first_call_seq': first_call_seq,
        'resolved_call_loc': resolved_call_loc,
        'resolved_call_seq': resolved_call_seq,
        'hops': hops,
    }
