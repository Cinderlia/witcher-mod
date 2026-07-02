"""
Scan all `AST_IF_ELEM` nodes and collect descendant variable-like node types.

This is a small dataset inspection utility that writes `if_elem_types.txt`.
"""

import csv
import os
from utils.ast_utils.var_utils import build_children_parent, extract_varlike_for_nodes
from common.app_config import load_app_config
csv.field_size_limit(10**9)

def load_nodes(nodes_path):
    """Load a minimal `nodes.csv` mapping for type and code/name fields."""
    nodes = {}
    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            s = row.get('id:int')
            if not s:
                continue
            try:
                nid = int(s)
            except:
                continue
            nodes[nid] = {
                'type': row.get('type') or '',
                'labels': row.get('labels:label') or '',
                'flags': row.get('flags:string_array') or '',
                'code': row.get('code') or '',
                'name': row.get('name') or ''
            }
    return nodes

def load_ast_edges(rels_path):
    """Load `PARENT_OF` edges into a `children_of` mapping."""
    children_of = {}
    with open(rels_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            if (row.get('type') or '') != 'PARENT_OF':
                continue
            try:
                si = int(row.get('start') or '')
                ei = int(row.get('end') or '')
            except:
                continue
            lst = children_of.get(si)
            if lst is None:
                lst = []
                children_of[si] = lst
            lst.append(ei)
    return children_of

def collect_descendants(nid, children_of):
    """Collect all descendant node ids under `nid`."""
    res = []
    q = [nid]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if x != nid:
            res.append(x)
        for c in children_of.get(x, []) or []:
            q.append(c)
    return res

def main():
    """CLI entrypoint that writes collected types to `if_elem_types.txt`."""
    cfg = load_app_config()
    nodes_path = cfg.find_input_file('nodes.csv')
    rels_path = cfg.find_input_file('rels.csv')
    nodes = load_nodes(nodes_path)
    children_of, parent_of = build_children_parent(rels_path)
    types_seen = set()
    for nid, nd in nodes.items():
        if nd.get('type') != 'AST_IF_ELEM':
            continue
        desc = collect_descendants(nid, children_of)
        items = extract_varlike_for_nodes(desc, children_of, parent_of, nodes)
        for it in items:
            t = it.get('type')
            if t:
                types_seen.add(t)
    lines = sorted(types_seen)
    out = '\n'.join(lines)
    print(out)
    out_dir = cfg.test_path('if_elem_types')
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, 'if_elem_types.txt'), 'w', encoding='utf-8') as f:
        f.write(out)

if __name__ == '__main__':
    main()
