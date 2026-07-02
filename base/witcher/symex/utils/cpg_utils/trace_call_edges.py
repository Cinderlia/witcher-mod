"""
Infer supplemental `CALLS` edges from adjacent trace groups.

This script reads:
- `trace.log` to group dynamic trace lines by `(path,line)`
- Joern CPG exports (`nodes.csv`, `rels.csv`, `cpg_edges.csv`) for AST metadata

It produces:
- `tmp/trace_edges.csv` inferred `CALLS` edges
- `test/trace_edges/trace_debug.json` debug rows
- `test/trace_edges/trace_stats.txt` summary stats
"""

import csv
import os
import json
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.app_config import load_app_config
from utils.cpg_utils.trace_index import build_nodes_index, load_nodes_meta, read_trace_groups
from utils.ast_utils.var_utils import build_children_parent, extract_varlike_for_nodes


def get_string_children(nid, children_of, nodes_meta):
    """Return direct child string nodes (id, text) for a node id."""
    vals = []
    for c in children_of.get(nid, []) or []:
        nc = nodes_meta.get(c)
        if not nc:
            continue
        if nc.get('labels') == 'string' or (nc.get('type') == 'string'):
            v = nc.get('code') or nc.get('name') or ''
            if v:
                vals.append(v)
    return vals


def get_all_string_descendants(nid, children_of, nodes_meta):
    """Return all descendant string values (text only) under an AST node."""
    vals = []
    q = [nid]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if x != nid:
            nc = nodes_meta.get(x)
            if nc and (nc.get('labels') == 'string' or (nc.get('type') == 'string')):
                v = nc.get('code') or nc.get('name') or ''
                if v:
                    vals.append(v)
        for c in children_of.get(x, []) or []:
            q.append(c)
    return vals


def find_first_var_string(nid, children_of, nodes_meta):
    """Find the first `AST_VAR` descendant's string name under `nid`."""
    q = list(children_of.get(nid, []) or [])
    seen = set()
    while q:
        x = q.pop(0)
        if x in seen:
            continue
        seen.add(x)
        nx = nodes_meta.get(x)
        if not nx:
            continue
        if nx.get('type') == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes_meta)
            if ss:
                return ss[0]
        for c in children_of.get(x, []) or []:
            q.append(c)
    return ''


def collect_descendants_on_line(root, children_of, nodes_meta, line):
    """Collect descendants of `root` that have `lineno == line` in `nodes_meta`."""
    res = []
    q = [root]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if x != root:
            nx = nodes_meta.get(x)
            if nx and nx.get('lineno') == line:
                res.append(x)
        for c in children_of.get(x, []) or []:
            q.append(c)
    return res


def extract_variables_for_line(if_elem_ids, line, children_of, nodes_meta):
    """Extract variable-like items from if-element subtrees on the given line."""
    out = []
    seen_ids = set()
    for root in if_elem_ids:
        desc = collect_descendants_on_line(root, children_of, nodes_meta, line)
        for x in desc:
            if x in seen_ids:
                continue
            nx = nodes_meta.get(x) or {}
            t = nx.get('type') or ''
            if t == 'AST_VAR':
                ss = get_string_children(x, children_of, nodes_meta)
                name = ss[0] if ss else ''
                if name:
                    out.append({'id': x, 'type': t, 'name': name})
                    seen_ids.add(x)
            elif t == 'AST_DIM':
                base = find_first_var_string(x, children_of, nodes_meta)
                ss = get_string_children(x, children_of, nodes_meta)
                key = ss[0] if ss else ''
                nm = base + ('[' + key + ']' if key else '')
                if base or key:
                    out.append({'id': x, 'type': t, 'name': nm})
                    seen_ids.add(x)
            elif t == 'AST_PROP':
                base = find_first_var_string(x, children_of, nodes_meta)
                ss = get_string_children(x, children_of, nodes_meta)
                prop = ss[0] if ss else ''
                nm = base + ('.' + prop if prop else '')
                if base or prop:
                    out.append({'id': x, 'type': t, 'name': nm})
                    seen_ids.add(x)
            elif t == 'AST_CONST':
                ss = get_string_children(x, children_of, nodes_meta)
                name = ss[0] if ss else ''
                if name:
                    out.append({'id': x, 'type': t, 'name': name})
                    seen_ids.add(x)
            elif t == 'AST_NAME':
                name = nx.get('code') or nx.get('name') or ''
                if name:
                    out.append({'id': x, 'type': t, 'name': name})
                    seen_ids.add(x)
    return out


def extract_variables_for_nodes(node_entries, children_of, nodes_meta):
    """Extract variable-like items from a set of node ids or `(id, ...)` entries."""
    out = []
    seen_ids = set()
    for entry in node_entries:
        x = entry[0] if isinstance(entry, (list, tuple)) else entry
        if x in seen_ids:
            continue
        nx = nodes_meta.get(x) or {}
        t = nx.get('type') or ''
        if t == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes_meta)
            name = ss[0] if ss else ''
            if name:
                out.append({'id': x, 'type': t, 'name': name})
                seen_ids.add(x)
        elif t == 'AST_DIM':
            base = find_first_var_string(x, children_of, nodes_meta)
            ss = get_string_children(x, children_of, nodes_meta)
            key = ss[0] if ss else ''
            nm = base + ('[' + key + ']' if key else '')
            if base or key:
                out.append({'id': x, 'type': t, 'name': nm})
                seen_ids.add(x)
        elif t == 'AST_PROP':
            base = find_first_var_string(x, children_of, nodes_meta)
            ss = get_string_children(x, children_of, nodes_meta)
            prop = ss[0] if ss else ''
            nm = base + ('.' + prop if prop else '')
            if base or prop:
                out.append({'id': x, 'type': t, 'name': nm})
                seen_ids.add(x)
        elif t == 'AST_CONST':
            ss = get_all_string_descendants(x, children_of, nodes_meta)
            name = ss[0] if ss else ''
            if name:
                out.append({'id': x, 'type': t, 'name': name})
                seen_ids.add(x)
        elif t == 'AST_NAME':
            ss = get_all_string_descendants(x, children_of, nodes_meta)
            name = ss[0] if ss else (nx.get('code') or nx.get('name') or '')
            if name:
                out.append({'id': x, 'type': t, 'name': name})
                seen_ids.add(x)
    return out


def read_existing_calls(edges_path):
    """Load existing `CALLS` edges from a `cpg_edges.csv`-like TSV file."""
    calls = set()
    if not os.path.exists(edges_path):
        return calls
    with open(edges_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            t = row.get('type') or ''
            if t != 'CALLS':
                continue
            s = row.get('start') or ''
            e = row.get('end') or ''
            try:
                si = int(s)
                ei = int(e)
            except:
                continue
            calls.add((si, ei))
    return calls


def norm_call_name(s):
    """Normalize a call name to a lowercase identifier-like prefix."""
    s = (s or '').strip().lower()
    if not s:
        return ''
    out = []
    for ch in s:
        if ch.isalnum() or ch in ('_', '\\'):
            out.append(ch)
        else:
            break
    return ''.join(out)


def get_call_name_candidates(call_name_raw):
    names = []
    base = norm_call_name(call_name_raw)
    if base:
        names.append(base)
    raw = (call_name_raw or '').strip()
    if '::' in raw:
        tail = raw.split('::')[-1].strip()
        tail_norm = norm_call_name(tail)
        if tail_norm and tail_norm not in names:
            names.append(tail_norm)
    elif ':' in raw:
        tail = raw.split(':')[-1].strip()
        tail_norm = norm_call_name(tail)
        if tail_norm and tail_norm not in names:
            names.append(tail_norm)
    return names


def get_node_best_name(nid, nodes_meta, children_of):
    """Pick the most human-readable name for a node using name/string/code fields."""
    nx = nodes_meta.get(nid) or {}
    name = (nx.get('name') or '').strip()
    if name:
        return name
    ss = get_string_children(nid, children_of, nodes_meta)
    if ss:
        return ss[0]
    code = (nx.get('code') or '').strip()
    if code:
        return code
    return ''


def get_string_value(nid, nodes_meta):
    """Return the string literal value for a node if it is a string node."""
    nx = nodes_meta.get(nid) or {}
    if nx.get('labels') == 'string' or (nx.get('type') == 'string'):
        v = (nx.get('code') or nx.get('name') or '').strip()
        return v
    return ''


def get_ast_name_string_child(ast_name_id, children_of, nodes_meta):
    """Return the first direct string child value under an `AST_NAME` node."""
    for c in children_of.get(ast_name_id, []) or []:
        v = get_string_value(c, nodes_meta)
        if v:
            return v
    return ''


def get_static_call_name(call_id, children_of, nodes_meta):
    class_name = ''
    method_name = ''
    for c in children_of.get(call_id, []) or []:
        cx = nodes_meta.get(c) or {}
        ct = cx.get('type') or ''
        if ct == 'AST_NAME' and not class_name:
            class_name = get_ast_name_string_child(c, children_of, nodes_meta)
            continue
        if not method_name:
            v = get_string_value(c, nodes_meta)
            if v:
                method_name = v
    if class_name and method_name:
        return f'{class_name}::{method_name}'
    if method_name:
        return method_name
    if class_name:
        return class_name
    return ''


def get_direct_callsite_name(call_id, children_of, nodes_meta):
    """Extract a direct callsite name from immediate children of a call node."""
    for c in children_of.get(call_id, []) or []:
        cx = nodes_meta.get(c) or {}
        ct = cx.get('type') or ''
        if ct == 'AST_ARG_LIST':
            continue
        v = get_string_value(c, nodes_meta)
        if v:
            return v
        if ct == 'AST_NAME':
            v2 = get_ast_name_string_child(c, children_of, nodes_meta)
            if v2:
                return v2
    return ''


def find_descendant_callsite_name(call_id, children_of, nodes_meta):
    """Find a callsite name by searching descendants (fallback when direct name missing)."""
    q = []
    for c in children_of.get(call_id, []) or []:
        cx = nodes_meta.get(c) or {}
        if (cx.get('type') or '') == 'AST_ARG_LIST':
            continue
        q.append(c)
    seen = set()
    while q:
        x = q.pop(0)
        if x in seen:
            continue
        seen.add(x)
        xx = nodes_meta.get(x) or {}
        xt = xx.get('type') or ''
        if xt == 'AST_NAME':
            v = get_ast_name_string_child(x, children_of, nodes_meta)
            if v:
                return v
        for c in children_of.get(x, []) or []:
            q.append(c)
    return ''


def get_call_name(nid, nodes_meta, children_of):
    """Resolve a call expression's name from multiple possible AST encodings."""
    nx = nodes_meta.get(nid) or {}
    if (nx.get('type') or '') == 'AST_STATIC_CALL':
        v0 = get_static_call_name(nid, children_of, nodes_meta)
        if v0:
            return v0
    name = (nx.get('name') or '').strip()
    if name:
        return name
    v = get_direct_callsite_name(nid, children_of, nodes_meta)
    if v:
        return v
    v2 = find_descendant_callsite_name(nid, children_of, nodes_meta)
    if v2:
        return v2
    code = (nx.get('code') or '').strip()
    if code:
        return code
    return ''


def get_decl_name(nid, nodes_meta, children_of):
    """Resolve a callee declaration name from a declaration node subtree."""
    nx = nodes_meta.get(nid) or {}
    name = (nx.get('name') or '').strip()
    if name:
        return name
    for c in children_of.get(nid, []) or []:
        cx = nodes_meta.get(c) or {}
        ct = cx.get('type') or ''
        if ct == 'AST_NAME':
            v = get_ast_name_string_child(c, children_of, nodes_meta)
            if v:
                return v
        v2 = get_string_value(c, nodes_meta)
        if v2:
            return v2
    ss = get_string_children(nid, children_of, nodes_meta)
    if ss:
        return ss[0]
    code = (nx.get('code') or '').strip()
    if code:
        return code
    return ''


def pick_call_edge(a_id, a_type, dst_type, dst_candidates, nodes_meta, children_of, existing_calls, guard_calls):
    """Pick the best callee among candidates using normalized name matching heuristics."""
    call_name_raw = get_call_name(a_id, nodes_meta, children_of)
    call_names = get_call_name_candidates(call_name_raw)
    picked = dst_candidates[0]
    picked_name_raw = get_decl_name(picked, nodes_meta, children_of)
    picked_name = norm_call_name(picked_name_raw)
    picked_by = 'first'
    name_match = ''
    skipped = False
    edge_exists = False

    if not call_names:
        skipped = True
        picked_by = 'skip_no_call_name'
    elif any(n in guard_calls for n in call_names):
        skipped = True
        picked_by = 'skip_guard'
    else:
        matched = False
        for cand in dst_candidates:
            cand_name_raw = get_decl_name(cand, nodes_meta, children_of)
            cand_name = norm_call_name(cand_name_raw)
            if cand_name and cand_name in call_names:
                picked = cand
                picked_name_raw = cand_name_raw
                picked_name = cand_name
                picked_by = 'name'
                matched = True
                break
        if not matched:
            skipped = True
            picked_by = 'skip_no_match'

    if call_names and picked_name:
        name_match = 'yes' if picked_name in call_names else 'no'

    if not skipped:
        edge_exists = (a_id, picked) in existing_calls

    return {
        'picked': picked,
        'picked_name_raw': picked_name_raw,
        'picked_by': picked_by,
        'call_name_raw': call_name_raw,
        'name_match': name_match,
        'skipped': skipped,
        'edge_exists': edge_exists,
    }


def main():
    """CLI entrypoint: build `trace_debug.json` and infer supplemental `CALLS` edges."""
    cfg = load_app_config(argv=sys.argv[1:])
    base = cfg.base_dir
    trace_path = cfg.find_input_file('trace.log')
    nodes_path = cfg.find_input_file('nodes.csv')
    edges_path = cfg.find_input_file('cpg_edges.csv')
    rels_path = cfg.find_input_file('rels.csv')
    guard_calls = {
        'function_exists',
        'defined',
        'class_exists',
        'interface_exists',
        'trait_exists',
        'method_exists',
        'property_exists',
        'extension_loaded',
        'is_callable',
    }
    groups = read_trace_groups(trace_path, None)
    target = [(g['path'], g['line']) for g in groups]
    nodes_index = build_nodes_index(nodes_path, target)
    existing_calls = read_existing_calls(edges_path)
    nodes_meta = load_nodes_meta(nodes_path)
    children_of, parent_of = build_children_parent(rels_path)
    trace_edges = []
    debug_rows = []
    existed_count = 0
    for i, g in enumerate(groups):
        k = (g['path'], g['line'])
        nodes = nodes_index.get(k, [])
        ids = [str(n[0]) for n in nodes]
        types = [n[2] for n in nodes]
        has_method_call = any(t == 'AST_METHOD_CALL' for t in types)
        has_call = any(t == 'AST_CALL' for t in types)
        call_nodes = [n for n in nodes if n[2] in ('AST_METHOD_CALL', 'AST_CALL')]
        variables = extract_varlike_for_nodes(nodes, children_of, parent_of, nodes_meta)
        debug_rows.append(
            {
                'index': i,
                'path': g['path'],
                'line': g['line'],
                'matched': 'yes' if nodes else 'no',
                'node_ids': ','.join(ids),
                'node_types': ','.join(types),
                'has_ast_method_call': 'yes' if has_method_call else 'no',
                'has_ast_call': 'yes' if has_call else 'no',
                'variables': variables,
            }
        )
        if not call_nodes:
            continue
        j = i + 1
        while j < len(groups):
            if groups[j]['path'] != g['path'] or groups[j]['line'] != g['line']:
                break
            j += 1
        if j >= len(groups):
            continue
        ng = groups[j]
        nk = (ng['path'], ng['line'])
        n_nodes = nodes_index.get(nk, [])
        n_types = [n[2] for n in n_nodes]
        for cn in call_nodes:
            a_id = cn[0]
            a_type = cn[2]
            if a_type == 'AST_METHOD_CALL':
                dst_type = 'AST_METHOD'
            else:
                dst_type = 'AST_FUNC_DECL'

            dst_candidates = [x[0] for x in n_nodes if x[2] == dst_type]
            if not dst_candidates:
                continue

            picked_info = pick_call_edge(
                a_id,
                a_type,
                dst_type,
                dst_candidates,
                nodes_meta,
                children_of,
                existing_calls,
                guard_calls,
            )
            picked = picked_info['picked']
            picked_name_raw = picked_info['picked_name_raw']
            picked_by = picked_info['picked_by']
            call_name_raw = picked_info['call_name_raw']
            name_match = picked_info['name_match']
            skipped = picked_info['skipped']
            edge_exists = picked_info['edge_exists']

            if not skipped:
                if edge_exists:
                    existed_count += 1
                else:
                    trace_edges.append((a_id, picked, 'CALLS', ''))

            debug_rows.append(
                {
                    'index': f'{i}->{j}',
                    'path': f'{g["path"]} -> {ng["path"]}',
                    'line': f'{g["line"]} -> {ng["line"]}',
                    'matched': 'pair',
                    'node_ids': f'{a_id if a_id is not None else ""},{picked if picked is not None else ""}',
                    'node_types': f'{a_type},{dst_type}',
                    'call_name': call_name_raw,
                    'decl_name': picked_name_raw,
                    'name_match': name_match,
                    'picked_by': picked_by,
                    'edge_exists_in_cpg_edges': 'skipped' if skipped else ('yes' if edge_exists else 'no'),
                }
            )

    edges_out = list(dict.fromkeys(trace_edges))
    out_edges_path = cfg.tmp_path('trace_edges.csv')
    out_debug_dir = cfg.test_path('trace_edges')
    os.makedirs(os.path.dirname(out_edges_path) or '.', exist_ok=True)
    os.makedirs(out_debug_dir, exist_ok=True)
    with open(out_edges_path, 'w', encoding='utf-8', newline='') as f:
        w = csv.writer(f, delimiter='\t')
        w.writerow(['start', 'end', 'type', 'var'])
        for a, b, t, v in edges_out:
            w.writerow([a, b, t, v])
    with open(os.path.join(out_debug_dir, 'trace_debug.json'), 'w', encoding='utf-8') as f:
        json.dump(debug_rows, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_debug_dir, 'trace_stats.txt'), 'w', encoding='utf-8') as f:
        f.write(f'groups={len(groups)}\n')
        f.write(f'missing_edges={len(edges_out)}\n')
        f.write(f'existing_edges_in_cpg_edges={existed_count}\n')


if __name__ == "__main__":
    main()
