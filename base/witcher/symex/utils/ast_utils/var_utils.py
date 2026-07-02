"""
Small AST/CPG helpers shared across scripts.

These helpers operate on Joern-exported `nodes.csv`/`rels.csv` structures and are
used to extract variable-like entities (vars/props/dims/literals) from AST nodes.
"""

import csv

def build_children_parent(rels_path):
    """Build `children_of` and `parent_of` mappings from `rels.csv` (PARENT_OF edges)."""
    parent_of = {}
    children_of = {}
    with open(rels_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            t = row.get('type') or ''
            if t != 'PARENT_OF':
                continue
            s = row.get('start') or ''
            e = row.get('end') or ''
            try:
                si = int(s)
                ei = int(e)
            except:
                continue
            parent_of[ei] = si
            lst = children_of.get(si)
            if lst is None:
                lst = []
                children_of[si] = lst
            lst.append(ei)
    return children_of, parent_of

def get_string_children(nid, children_of, nodes):
    """Return direct string children for a node as `(child_id, text)` pairs."""
    vals = []
    for c in children_of.get(nid, []) or []:
        nc = nodes.get(c)
        if not nc:
            continue
        if nc.get('labels') == 'string' or (nc.get('type') == 'string'):
            v = nc.get('code') or nc.get('name') or ''
            if v:
                vals.append((c, v))
    return vals

def get_all_string_descendants(nid, children_of, nodes):
    """Return all descendant string nodes for a node as `(node_id, text)` pairs."""
    vals = []
    q = [nid]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if x != nid:
            nc = nodes.get(x)
            if nc and (nc.get('labels') == 'string' or (nc.get('type') == 'string')):
                v = nc.get('code') or nc.get('name') or ''
                if v:
                    vals.append((x, v))
        for c in children_of.get(x, []) or []:
            q.append(c)
    return vals

def find_first_var_string(nid, children_of, nodes):
    """Find the first `AST_VAR` descendant name under `nid`."""
    q = list(children_of.get(nid, []) or [])
    seen = set()
    while q:
        x = q.pop(0)
        if x in seen:
            continue
        seen.add(x)
        nx = nodes.get(x)
        if not nx:
            continue
        if nx.get('type') == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes)
            if ss:
                return ss[0][1]
        for c in children_of.get(x, []) or []:
            q.append(c)
    return ''

def is_string_trackable(nid, children_of, parent_of, nodes):
    """Heuristic filter for string nodes that represent meaningful identifiers."""
    nx = nodes.get(nid) or {}
    if (nx.get('type') or '') != 'string':
        return False
    pid = parent_of.get(nid)
    pt = (nodes.get(pid) or {}).get('type') if pid is not None else None
    # exclude common container/operation parents: these strings are usually names or literals within expressions/calls
    if pt in (
        'AST_VAR','AST_DIM','AST_PROP','AST_ARG_LIST',
        'AST_METHOD_CALL','AST_CALL','AST_STATIC_CALL',
        'AST_ARRAY','AST_ARRAY_ELEM',
        'AST_NAME','AST_CONST',
        'AST_BINARY_OP','AST_UNARY_OP','AST_ASSIGN','AST_ASSIGN_OP','AST_ASSIGN_REF',
        'AST_CONDITIONAL','AST_IF','AST_IF_ELEM','AST_RETURN','AST_ECHO','AST_INCLUDE_OR_EVAL','AST_ISSET','AST_EMPTY','AST_INSTANCEOF'
    ):
        return False
    # require having a string-type child that carries the variable's explicit name
    s_children = get_string_children(nid, children_of, nodes)
    if s_children:
        name = s_children[0][1]
        return bool(name)
    # fallback: use own name/code only if present and no children found
    name = nx.get('name') or nx.get('code') or ''
    return bool(name)

def extract_varlike_for_nodes(node_entries, children_of, parent_of, nodes):
    """Extract variable-like entities from node ids (or node entry tuples)."""
    out = []
    seen_ids = set()
    for entry in node_entries:
        x = entry[0] if isinstance(entry, (list, tuple)) else entry
        if x in seen_ids:
            continue
        nx = nodes.get(x) or {}
        t = nx.get('type') or ''
        if t == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes)
            name = ss[0][1] if ss else ''
            if name:
                out.append({'id': x, 'type': t, 'name': name})
                seen_ids.add(x)
        elif t == 'AST_DIM':
            base = find_first_var_string(x, children_of, nodes)
            ss = get_string_children(x, children_of, nodes)
            key = ss[0][1] if ss else ''
            nm = base + ('[' + key + ']' if key else '')
            if base or key:
                out.append({'id': x, 'type': t, 'name': nm})
                seen_ids.add(x)
        elif t == 'AST_PROP':
            base = find_first_var_string(x, children_of, nodes)
            ss = get_string_children(x, children_of, nodes)
            prop = ss[0][1] if ss else ''
            nm = base + ('.' + prop if prop else '')
            if base or prop:
                out.append({'id': x, 'type': t, 'name': nm})
                seen_ids.add(x)
        elif t == 'AST_CONST':
            ss = get_all_string_descendants(x, children_of, nodes)
            name = ss[0][1] if ss else (nx.get('code') or nx.get('name') or '')
            if name:
                out.append({'id': x, 'type': t, 'name': name})
                seen_ids.add(x)
        elif t == 'AST_NAME':
            ss = get_all_string_descendants(x, children_of, nodes)
            name = ss[0][1] if ss else (nx.get('code') or nx.get('name') or '')
            if name:
                out.append({'id': x, 'type': t, 'name': name})
                seen_ids.add(x)
        elif t in ('integer','double'):
            val = nx.get('code') or nx.get('name') or ''
            if val:
                out.append({'id': x, 'type': t, 'name': val})
                seen_ids.add(x)
        elif t == 'string':
            if is_string_trackable(x, children_of, parent_of, nodes):
                ssc = get_string_children(x, children_of, nodes)
                val = ssc[0][1] if ssc else (nx.get('name') or nx.get('code') or '')
                if val:
                    out.append({'id': x, 'type': t, 'name': val})
                    seen_ids.add(x)
    return out
