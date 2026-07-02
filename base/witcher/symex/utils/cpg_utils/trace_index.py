"""
Trace and CPG index helpers.

Provides utilities to:
- normalize paths used in trace and node metadata
- group trace lines by `(path,line)` and collect seq lists
- build `(path,line) -> node_ids` indices by scanning `nodes.csv`
- read/write `trace_index.json` cache files
"""

# Summary: Build a trace_index.json by joining trace.log seq groups with nodes.csv locations.
#
# This module also provides low-level utilities for normalizing paths, grouping trace records by location,
# and indexing nodes.csv by (path,line).

import csv
import os
import json
import threading
from typing import Dict, List, Optional


def norm_trace_path(p):
    """Normalize a trace log path for consistent indexing."""
    if p.startswith('/app/'):
        p = p[5:]
    if p.startswith('/'):
        p = p[1:]
    return p


def norm_nodes_path(p):
    """Normalize a node metadata path to match trace path normalization."""
    if p.startswith('/app/'):
        p = p[5:]
    if p.startswith('/'):
        p = p[1:]
    return p.lower()


_FCALL_END_TOKEN = 'op=ZEND_EXT_FCALL_END'
_CALL_LIKE_TYPES = {'AST_CALL', 'AST_METHOD_CALL', 'AST_STATIC_CALL'}
_TRACE_INDEX_CACHE: Dict[str, List[dict]] = {}
_TRACE_INDEX_CACHE_LOCK = threading.Lock()


def _trace_index_cache_key(index_path: str) -> str:
    return os.path.abspath(index_path) if index_path else ''


def _get_cached_trace_index_records(index_path: str) -> Optional[List[dict]]:
    key = _trace_index_cache_key(index_path)
    if not key:
        return None
    with _TRACE_INDEX_CACHE_LOCK:
        recs = _TRACE_INDEX_CACHE.get(key)
        return list(recs) if isinstance(recs, list) else None


def _set_cached_trace_index_records(index_path: str, records: List[dict]) -> None:
    key = _trace_index_cache_key(index_path)
    if not key:
        return
    with _TRACE_INDEX_CACHE_LOCK:
        _TRACE_INDEX_CACHE[key] = list(records or [])


def _merge_fcall_end_groups(groups):
    """Merge adjacent trace groups when Zend FCALL_END appears for the same location."""
    if not groups:
        return groups
    out = []
    last_pos_by_key = {}
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


def read_trace_groups(trace_path, limit=None, seq_start=0):
    """Group `trace.log` lines by `(path,line)` and keep raw lines (no seqs)."""
    groups = []
    try:
        start_seq = max(0, int(seq_start or 0))
    except Exception:
        start_seq = 0
    try:
        end_seq = int(limit) if limit is not None else None
    except Exception:
        end_seq = None
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        count = 0
        last_key = None
        for line in f:
            count += 1
            if end_seq is not None and count > end_seq:
                break
            if start_seq > 0 and count < start_seq:
                continue
            line = line.strip()
            if not line:
                continue
            has_fcall_end = _FCALL_END_TOKEN in line
            prefix = line.split(' | ', 1)[0]
            if ':' not in prefix:
                continue
            path_part, line_part = prefix.rsplit(':', 1)
            try:
                ln = int(line_part)
            except:
                continue
            np = norm_trace_path(path_part)
            key = (np.lower(), ln)
            if groups and key == last_key:
                groups[-1]['raw_lines'].append(line)
                groups[-1]['has_fcall_end'] = groups[-1].get('has_fcall_end') or has_fcall_end
            else:
                groups.append({'path': np, 'line': ln, 'raw_lines': [line], 'has_fcall_end': has_fcall_end})
                last_key = key
    return _merge_fcall_end_groups(groups)


def read_trace_groups_with_seqs(trace_path, limit=None, seq_start=0):
    """Group `trace.log` lines by `(path,line)` and keep 1-based seq numbers."""
    groups = []
    try:
        start_seq = max(0, int(seq_start or 0))
    except Exception:
        start_seq = 0
    try:
        end_seq = int(limit) if limit is not None else None
    except Exception:
        end_seq = None
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        count = 0
        last_key = None
        for line in f:
            count += 1
            if end_seq is not None and count > end_seq:
                break
            if start_seq > 0 and count < start_seq:
                continue
            raw = line.strip()
            if not raw:
                continue
            has_fcall_end = _FCALL_END_TOKEN in raw
            prefix = raw.split(' | ', 1)[0]
            if ':' not in prefix:
                continue
            path_part, line_part = prefix.rsplit(':', 1)
            try:
                ln = int(line_part)
            except:
                continue
            np = norm_trace_path(path_part)
            key = (np.lower(), ln)
            if groups and key == last_key:
                groups[-1]['seqs'].append(count)
                groups[-1]['has_fcall_end'] = groups[-1].get('has_fcall_end') or has_fcall_end
            else:
                groups.append({'path': np, 'line': ln, 'seqs': [count], 'has_fcall_end': has_fcall_end})
                last_key = key
    return _merge_fcall_end_groups(groups)


def build_trace_index_records(trace_path, nodes_path, limit=None, seq_start=0):
    """Build trace index records by joining trace groups with CPG nodes on the same loc."""
    groups = read_trace_groups_with_seqs(trace_path, limit, seq_start=seq_start)
    target = [(str(g['path']).lower(), g['line']) for g in groups]
    nodes_index = build_nodes_index(nodes_path, target)
    records = []
    for i, g in enumerate(groups):
        k = (str(g['path']).lower(), g['line'])
        nodes = nodes_index.get(k, [])
        node_ids = [n[0] for n in nodes]
        call_like_node_ids = sorted(
            int(nid) for nid, _lab, typ in nodes
            if (typ or '').strip() in _CALL_LIKE_TYPES
        )
        records.append({
            'index': i,
            'path': g['path'],
            'line': g['line'],
            'seqs': g['seqs'],
            'node_ids': node_ids,
            '_call_like_node_ids': call_like_node_ids,
        })
    return _merge_call_like_location_records(records)


def _merge_call_like_location_records(records):
    """Merge same-location records only when they map to the same call-like AST nodes."""
    if not records:
        return records
    out = []
    pos_by_key = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        call_like_ids = tuple(int(x) for x in (rec.get('_call_like_node_ids') or []) if x is not None)
        if not call_like_ids:
            item = dict(rec)
            item.pop('_call_like_node_ids', None)
            item['index'] = len(out)
            out.append(item)
            continue
        key = ((rec.get('path') or ''), int(rec.get('line') or 0), call_like_ids)
        prev_pos = pos_by_key.get(key)
        if prev_pos is None:
            item = dict(rec)
            item.pop('_call_like_node_ids', None)
            item['index'] = len(out)
            out.append(item)
            pos_by_key[key] = len(out) - 1
            continue
        prev = out[prev_pos]
        prev['seqs'] = sorted({int(s) for s in (prev.get('seqs') or []) + (rec.get('seqs') or [])})
        prev['node_ids'] = sorted({int(n) for n in (prev.get('node_ids') or []) + (rec.get('node_ids') or [])})
    return out


def load_trace_index_records(index_path):
    """Load `trace_index.json` and return its `records` list (or None)."""
    cached = _get_cached_trace_index_records(index_path)
    if cached is not None:
        return cached
    if not os.path.exists(index_path):
        return None
    with open(index_path, 'r', encoding='utf-8', errors='replace') as f:
        try:
            obj = json.load(f)
        except Exception:
            return None
    if isinstance(obj, dict) and isinstance(obj.get('records'), list):
        recs = obj.get('records')
        _set_cached_trace_index_records(index_path, recs)
        return recs
    if isinstance(obj, list):
        _set_cached_trace_index_records(index_path, obj)
        return obj
    return None


def save_trace_index_records(index_path, records, meta=None):
    """Atomically write `trace_index.json` with optional metadata."""
    out = {'records': records}
    if isinstance(meta, dict):
        out['meta'] = meta
    tmp_path = index_path + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, index_path)
    _set_cached_trace_index_records(index_path, records)


def build_nodes_index(nodes_path, target):
    """Index CPG nodes by `(normalized_path,line)` for a provided set of locations."""
    csv.field_size_limit(131072 * 10)
    def _canon_path(p):
        s = (p or '').replace('\\', '/').strip()
        if s.startswith('/'):
            s = s[1:]
        return s.lower()

    def _path_parts(p):
        return [x for x in _canon_path(p).split('/') if x]

    def _suffixes(parts, max_parts: int = 6):
        if not parts:
            return []
        n = min(int(max_parts), len(parts))
        return ['/'.join(parts[-k:]) for k in range(1, n + 1)]

    target_paths = set(_canon_path(k[0]) for k in target)
    target_lines_by_path = {}
    for p, ln in target:
        cp = _canon_path(p)
        s = target_lines_by_path.get(cp)
        if s is None:
            s = set()
            target_lines_by_path[cp] = s
        s.add(ln)
    suffix_to_targets = {}
    for tp in target_paths:
        for suf in _suffixes(_path_parts(tp)):
            suffix_to_targets.setdefault(suf, set()).add(tp)

    def _match_target_path(file_path: str) -> Optional[str]:
        fp = _canon_path(file_path)
        if not fp:
            return None
        if fp in target_paths:
            return fp
        parts = _path_parts(fp)
        for suf in reversed(_suffixes(parts)):
            cands = suffix_to_targets.get(suf)
            if cands and len(cands) == 1:
                return next(iter(cands))
        return None

    nodes_by_file_line = {}
    top_id_to_file = {}
    parent_of = {}
    children_of = {}

    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader((ln.replace('\x00', '') for ln in f), delimiter='\t')
        for row in reader:
            nid = row.get('id:int')
            if not nid:
                continue
            try:
                nid_i = int(nid)
            except:
                continue
            typ = row.get('type') or ''
            flags = row.get('flags:string_array') or ''
            name = row.get('name') or ''
            doccomment = row.get('doccomment') or ''
            if typ == 'AST_TOPLEVEL' and ('TOPLEVEL_FILE' in flags):
                path_val = name if name else doccomment
                if not path_val:
                    continue
                top_id_to_file[nid_i] = _canon_path(norm_nodes_path(path_val))
                continue
            funcid = row.get('funcid:int') or ''
            try:
                funcid_i = int(funcid)
            except:
                funcid_i = None
            if funcid_i is not None:
                parent_of[nid_i] = funcid_i
                ch = children_of.get(funcid_i)
                if ch is None:
                    ch = set()
                    children_of[funcid_i] = ch
                ch.add(nid_i)

    node_to_top = {}

    def resolve_top_id(nid_i):
        cur = nid_i
        seen = 0
        while cur is not None and seen < 64:
            if cur in node_to_top:
                return node_to_top[cur]
            if cur in top_id_to_file:
                node_to_top[cur] = cur
                return cur
            nxt = parent_of.get(cur)
            if nxt is None:
                ch = children_of.get(cur)
                if ch:
                    for cid in ch:
                        if cid in top_id_to_file:
                            node_to_top[cur] = cid
                            return cid
                node_to_top[cur] = None
                return None
            cur = nxt
            seen += 1
        return None

    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader((ln.replace('\x00', '') for ln in f), delimiter='\t')
        for row in reader:
            nid = row.get('id:int')
            if not nid:
                continue
            try:
                nid_i = int(nid)
            except:
                continue
            typ = row.get('type') or ''
            lab = row.get('labels:label') or ''
            lineno = row.get('lineno:int') or ''
            try:
                lineno_i = int(lineno)
            except:
                lineno_i = None
            if lineno_i is None:
                continue
            top_i = resolve_top_id(nid_i)
            if top_i is None:
                funcid = row.get('funcid:int') or ''
                try:
                    funcid_i = int(funcid)
                except:
                    funcid_i = None
                if funcid_i is not None:
                    top_i = resolve_top_id(funcid_i)
            if top_i is None:
                continue
            file_path = _match_target_path(top_id_to_file.get(top_i))
            if not file_path:
                continue
            if lineno_i not in target_lines_by_path.get(file_path, set()):
                continue
            k = (file_path, lineno_i)
            lst = nodes_by_file_line.get(k)
            if lst is None:
                lst = []
                nodes_by_file_line[k] = lst
            lst.append((nid_i, lab, typ))
    return nodes_by_file_line


def load_nodes_meta(nodes_path):
    """Load a minimal `nodes.csv` metadata mapping used by call/variable extraction."""
    meta = {}
    csv.field_size_limit(131072 * 10)
    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader((ln.replace('\x00', '') for ln in f), delimiter='\t')
        for row in reader:
            s = row.get('id:int') or ''
            try:
                nid = int(s)
            except:
                continue
            t = row.get('type') or ''
            lab = row.get('labels:label') or ''
            ln = row.get('lineno:int') or ''
            try:
                ln_i = int(ln)
            except:
                ln_i = None
            code = row.get('code') or ''
            name = row.get('name') or ''
            meta[nid] = {'type': t, 'labels': lab, 'lineno': ln_i, 'code': code, 'name': name}
    return meta


def load_ast_edges(rels_path):
    """Load `PARENT_OF` relations into a `children_of` adjacency mapping."""
    children_of = {}
    csv.field_size_limit(131072 * 10)
    with open(rels_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader((ln.replace('\x00', '') for ln in f), delimiter='\t')
        for row in reader:
            if (row.get('type') or '') != 'PARENT_OF':
                continue
            s = row.get('start') or ''
            e = row.get('end') or ''
            try:
                si = int(s)
                ei = int(e)
            except:
                continue
            lst = children_of.get(si)
            if lst is None:
                lst = []
                children_of[si] = lst
            lst.append(ei)
    return children_of
