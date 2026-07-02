"""
Standalone taint propagation runner over a precomputed trace and CPG exports.

This script loads `trace_debug.json` plus CSV exports (nodes, edges, rels) and
performs a simple taint expansion over:
- variable name matching within the same function
- REACHES dataflow edges
- parent CALL nodes and their arguments
- method parameter expansion via CALLS edges
"""

import os
import json
import csv
from utils.ast_utils.var_utils import build_children_parent, get_string_children, get_all_string_descendants, extract_varlike_for_nodes
from utils.cpg_utils.graph_mapping import ensure_trace_edges_csv
from common.app_config import load_app_config

def norm_trace_path(p):
    """Normalize a trace path to a comparable lowercase project-relative form."""
    if p.startswith('/app/'):
        p = p[5:]
    if p.startswith('/'):
        p = p[1:]
    return p.lower()

def load_nodes_meta(nodes_path: str):
    """Load node metadata from `nodes.csv`."""
    meta = {}
    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        csv.field_size_limit(10**9)
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            s = row.get('id:int') or ''
            try:
                nid = int(s)
            except:
                continue
            meta[nid] = {
                'type': row.get('type') or '',
                'labels': row.get('labels:label') or '',
                'code': row.get('code') or '',
                'name': row.get('name') or '',
                'funcid': None
            }
            fs = row.get('funcid:int') or ''
            try:
                fi = int(fs)
            except:
                fi = None
            meta[nid]['funcid'] = fi
    return meta

def read_if_extract(path, nodes_meta, if_extract_path: str):
    """Read `if_extract_output.txt` and return input location and initial taint items."""
    with open(if_extract_path, 'r', encoding='utf-8') as f:
        lines = [x.rstrip('\n') for x in f]
    input_line = next((l for l in lines if l.startswith('input ')), '')
    if input_line and not path:
        arg = input_line.split(' ', 1)[1]
    else:
        arg = path
    pth, ln_s = arg.rsplit(':', 1)
    line = int(ln_s)
    np = norm_trace_path(pth)
    items = []
    for l in lines:
        parts = l.split()
        if len(parts) >= 3 and parts[0].isdigit():
            nid = int(parts[0])
            typ = parts[1]
            if typ in ('AST_VAR','AST_DIM','AST_PROP','AST_CONST','AST_NAME','integer','double','string'):
                name = ' '.join(parts[2:])
                items.append({'id': nid, 'type': typ, 'name': name})
            elif typ in ('method_call','AST_METHOD_CALL'):
                # parse function args and include them into initial taint
                # format: id AST_METHOD_CALL func recv arg_list_id id:name|id:name|...
                if len(parts) >= 6:
                    # join remaining parts to accommodate args with '|'
                    args_blob = ' '.join(parts[5:])
                    for seg in args_blob.split('|'):
                        seg = seg.strip()
                        if not seg:
                            continue
                        if ':' not in seg:
                            continue
                        sid, sname = seg.split(':', 1)
                        try:
                            aid = int(sid)
                        except:
                            continue
                        at = (nodes_meta.get(aid) or {}).get('type') or ''
                if at:
                    items.append({'id': aid, 'type': at, 'name': sname})
                else:
                    items.append({'id': aid, 'type': 'string', 'name': sname})
    return {'path': np, 'line': line, 'items': items}

def read_trace_debug(trace_debug_path: str):
    """Load `trace_debug.json`."""
    with open(trace_debug_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def build_indices(records, target_path, target_line, nodes_meta):
    """Build helper indices for taint expansion within a target `(path,line)` context."""
    idx = None
    id_to_var = {}
    by_path = []
    for rec in records:
        r_idx = rec.get('index')
        r_path = rec.get('path') or ''
        r_line = rec.get('line')
        if isinstance(r_idx, int) and r_path == target_path and r_line == target_line:
            if idx is None or r_idx < idx:
                idx = r_idx
        if isinstance(r_idx, int) and r_path == target_path:
            by_path.append((r_idx, rec))
        for v in rec.get('variables') or []:
            vid = v.get('id')
            if vid is not None and vid not in id_to_var:
                funcid = (nodes_meta.get(vid) or {}).get('funcid')
                id_to_var[vid] = {'type': v.get('type'), 'name': v.get('name'), 'path': r_path, 'line': r_line, 'funcid': funcid}
    by_path.sort(key=lambda x: x[0])
    return idx, id_to_var, by_path

def build_varkey_index(by_path, start_idx, nodes_meta):
    """Index variable occurrences before `start_idx` by `(funcid,type,name)`."""
    m = {}
    for r_idx, rec in by_path:
        if start_idx is not None and r_idx >= start_idx:
            break
        for v in rec.get('variables') or []:
            vid = v.get('id')
            funcid = (nodes_meta.get(vid) or {}).get('funcid')
            k = (funcid, v.get('type'), v.get('name'))
            s = m.get(k)
            if s is None:
                s = set()
                m[k] = s
            if vid is not None:
                s.add(vid)
    return m

def read_reaches_edges(cpg_edges_path: str):
    """Read `REACHES` edges into an `end_id -> set(start_id)` mapping."""
    m = {}
    with open(cpg_edges_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or '\t' not in line:
                continue
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            t = parts[2]
            if t != 'REACHES':
                continue
            try:
                s = int(parts[0]); e = int(parts[1])
            except:
                continue
            lst = m.get(e)
            if lst is None:
                lst = set()
                m[e] = lst
            lst.add(s)
    return m

def extract_call_name(call_id, children_of, nodes_meta):
    """Extract a best-effort call name string for a call node id."""
    nx = nodes_meta.get(call_id) or {}
    t = nx.get('type') or ''
    name = ''
    if t == 'AST_METHOD_CALL':
        ss = get_string_children(call_id, children_of, nodes_meta)
        name = ss[0][1] if ss else ''
    elif t == 'AST_CALL':
        for c in children_of.get(call_id, []) or []:
            nc = nodes_meta.get(c) or {}
            if (nc.get('labels') == 'string') or (nc.get('type') == 'string'):
                v = nc.get('code') or nc.get('name') or ''
                if v:
                    name = v
                    break
        if not name:
            for c in children_of.get(call_id, []) or []:
                nc = nodes_meta.get(c) or {}
                if nc.get('type') == 'AST_NAME':
                    v = nc.get('code') or nc.get('name') or ''
                    if v:
                        name = v
                        break
    elif t == 'AST_STATIC_CALL':
        for c in children_of.get(call_id, []) or []:
            nc = nodes_meta.get(c) or {}
            if (nc.get('labels') == 'string') or (nc.get('type') == 'string'):
                v = nc.get('code') or nc.get('name') or ''
                if v:
                    name = v
                    break
        if not name:
            for c in children_of.get(call_id, []) or []:
                nc = nodes_meta.get(c) or {}
                if nc.get('type') == 'AST_NAME':
                    v = nc.get('code') or nc.get('name') or ''
                    if v:
                        name = v
                        break
    return name

def extract_call_params(call_id, children_of, parent_of, nodes_meta):
    """Extract argument-like items from a call node's `AST_ARG_LIST`."""
    params = []
    for c in children_of.get(call_id, []) or []:
        nc = nodes_meta.get(c) or {}
        if nc.get('type') != 'AST_ARG_LIST':
            continue
        for ac in children_of.get(c, []) or []:
            anc = nodes_meta.get(ac) or {}
            at = anc.get('type') or ''
            if at in ('AST_VAR', 'AST_DIM', 'AST_PROP', 'AST_CONST', 'AST_NAME', 'integer', 'double'):
                items = extract_varlike_for_nodes([ac], children_of, parent_of, nodes_meta)
                for it in items:
                    params.append(it)
            elif at == 'string':
                v = anc.get('code') or anc.get('name') or ''
                if not v:
                    # fallback to descendants if any
                    ss = get_all_string_descendants(ac, children_of, nodes_meta)
                    v = ss[0][1] if ss else ''
                if v:
                    params.append({'id': ac, 'type': 'string', 'name': v})
    return params

def read_calls_edges(cfg):
    """Read `CALLS` edges from `cpg_edges.csv` or `trace_edges.csv` as fallback."""
    calls = {}
    p1 = cfg.find_input_file('cpg_edges.csv')
    def add_edge(s, e):
        lst = calls.get(s)
        if lst is None:
            lst = set()
            calls[s] = lst
        lst.add(e)
    if os.path.exists(p1):
        with open(p1, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or '\t' not in line:
                    continue
                parts = line.split('\t')
                if len(parts) < 3:
                    continue
                t = parts[2]
                if t != 'CALLS':
                    continue
                try:
                    s = int(parts[0]); e = int(parts[1])
                except:
                    continue
                add_edge(s, e)
    if not calls:
        ensure_trace_edges_csv(cfg.base_dir)
        p2 = cfg.tmp_path('trace_edges.csv')
        if not os.path.exists(p2):
            p2 = os.path.join(cfg.base_dir, 'trace_edges.csv')
        if os.path.exists(p2):
            with open(p2, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or '\t' not in line:
                        continue
                    parts = line.split('\t')
                    if len(parts) < 3:
                        continue
                    t = parts[2]
                    if t != 'CALLS':
                        continue
                    try:
                        s = int(parts[0]); e = int(parts[1])
                    except:
                        continue
                    add_edge(s, e)
    return calls

def parse_ids_types(rec):
    """Parse `node_ids` and `node_types` fields of a trace record into lists."""
    ids = []
    types = []
    nid_s = rec.get('node_ids') or ''
    nty_s = rec.get('node_types') or ''
    if nid_s:
        try:
            ids = [int(x) for x in nid_s.split(',') if x.strip()]
        except:
            ids = []
    if nty_s:
        types = [x.strip() for x in nty_s.split(',') if x.strip()]
    return ids, types

def find_method_for_call(call_id, records, calls_edges):
    """Resolve a candidate `AST_METHOD` id for a call using trace rows and CALLS edges."""
    cands = list(calls_edges.get(call_id) or [])
    # try pair rows from trace_debug
    for rec in records:
        ids, types = parse_ids_types(rec)
        if 'AST_METHOD_CALL' in types and 'AST_METHOD' in types and call_id in ids:
            try:
                ci = ids.index(call_id)
            except:
                ci = None
            # choose a method id present in row
            for i, t in enumerate(types):
                if t == 'AST_METHOD':
                    mid = ids[i] if i < len(ids) else None
                    if mid is None:
                        continue
                    if not cands or mid in cands:
                        return mid
    # fallback to first candidate
    return cands[0] if cands else None

def node_display(nid, nodes_meta, children_of):
    """Return a best-effort `(type,name)` representation for a node id."""
    nx = nodes_meta.get(nid) or {}
    t = nx.get('type') or ''
    name = ''
    if t == 'AST_VAR':
        ss = get_string_children(nid, children_of, nodes_meta)
        name = ss[0][1] if ss else ''
    elif t == 'AST_DIM':
        base = node_display(children_of.get(nid, [None])[0] if children_of.get(nid) else None, nodes_meta, children_of)[1] if children_of.get(nid) else ''
        ss = get_string_children(nid, children_of, nodes_meta)
        key = ss[0][1] if ss else ''
        name = (base or '') + ('[' + key + ']' if key else '')
    elif t == 'AST_PROP':
        base = ''
        # find first var string in descendants
        ssb = get_string_children(nid, children_of, nodes_meta)
        ssvar = []
        for c in children_of.get(nid, []) or []:
            nc = nodes_meta.get(c) or {}
            if nc.get('type') == 'AST_VAR':
                ssvar = get_string_children(c, children_of, nodes_meta)
                break
        base = ssvar[0][1] if ssvar else ''
        prop_s = get_all_string_descendants(nid, children_of, nodes_meta)
        prop = prop_s[0][1] if prop_s else (ssb[0][1] if ssb else '')
        name = (base or '') + ('.' + prop if prop else '')
    elif t in ('AST_CONST', 'AST_NAME', 'string'):
        ssd = get_all_string_descendants(nid, children_of, nodes_meta)
        name = ssd[0][1] if ssd else (nx.get('code') or nx.get('name') or '')
    elif t in ('integer', 'double'):
        name = nx.get('code') or nx.get('name') or ''
    elif t == 'NULL':
        ssd = get_all_string_descendants(nid, children_of, nodes_meta)
        name = ssd[0][1] if ssd else (nx.get('name') or nx.get('code') or '')
    else:
        name = nx.get('name') or nx.get('code') or ''
    return t, name

def run(arg=None):
    """Run taint expansion and write `taint_debug.json` and `taint_result.txt`."""
    cfg = load_app_config()
    nodes_path = cfg.find_input_file('nodes.csv')
    rels_path = cfg.find_input_file('rels.csv')
    cpg_edges_path = cfg.find_input_file('cpg_edges.csv')
    trace_debug_path = os.path.join(cfg.test_path('trace_edges'), 'trace_debug.json')
    if_extract_path = os.path.join(cfg.test_path('if_extract'), 'if_extract_output.txt')

    nodes_meta = load_nodes_meta(nodes_path)
    st = read_if_extract(arg, nodes_meta, if_extract_path)
    recs = read_trace_debug(trace_debug_path)
    start_idx, id_to_var, by_path = build_indices(recs, st['path'], st['line'], nodes_meta)
    varkey_index = build_varkey_index(by_path, start_idx, nodes_meta)
    reaches = read_reaches_edges(cpg_edges_path) if os.path.exists(cpg_edges_path) else {}
    children_of, parent_of = build_children_parent(rels_path)
    call_types = ('AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL')
    # initialize sets
    taint_ids = set()
    taint_vars = {}
    for x in st['items']:
        taint_vars[x['id']] = {'type': x['type'], 'name': x['name'], 'funcid': (nodes_meta.get(x['id']) or {}).get('funcid')}
    preA = set(x['id'] for x in st['items'])
    preB = set()
    debug = {'input': {'path': st['path'], 'line': st['line'], 'start_index': start_idx}, 'initial': st['items'], 'iterations': []}
    calls_edges = read_calls_edges(cfg)
    it = 0
    useA = True
    while preA or preB:
        active = preA if useA else preB
        if not active:
            useA = not useA
            continue
        it += 1
        new_pre = set()
        added_by_match = []
        added_by_reaches = []
        added_by_calls = []
        added_by_method_params = []
        # expand only from active pre-set
        for tid in list(active):
            tv = taint_vars.get(tid) or id_to_var.get(tid) or {}
            ttyp = tv.get('type') or (nodes_meta.get(tid) or {}).get('type') or ''
            # only variables/constants expand via match/reaches
            if ttyp not in call_types:
                funcid = tv.get('funcid') or (nodes_meta.get(tid) or {}).get('funcid')
                name = tv.get('name')
                if funcid is not None and name:
                    k = (funcid, ttyp, name)
                    ids = varkey_index.get(k) or set()
                    for nid in ids:
                        if (nid not in taint_ids) and (nid not in active) and (nid not in new_pre):
                            new_pre.add(nid)
                            tvn = id_to_var.get(nid) or {}
                            taint_vars[nid] = {'type': tvn.get('type'), 'name': tvn.get('name'), 'funcid': tvn.get('funcid')}
                            added_by_match.append({'from': tid, 'id': nid, 'type': tvn.get('type'), 'name': tvn.get('name'), 'funcid': tvn.get('funcid')})
                starts = reaches.get(tid) or set()
                for s in starts:
                    if (s not in taint_ids) and (s not in active) and (s not in new_pre):
                        new_pre.add(s)
                        tvs = id_to_var.get(s) or {}
                        if tvs:
                            taint_vars[s] = {'type': tvs.get('type'), 'name': tvs.get('name'), 'funcid': tvs.get('funcid')}
                            added_by_reaches.append({'start': s, 'end': tid, 'type': tvs.get('type'), 'name': tvs.get('name'), 'funcid': tvs.get('funcid')})
                        else:
                            # fallback to nodes_meta
                            typ, nm = node_display(s, nodes_meta, children_of)
                            taint_vars[s] = {'type': typ, 'name': nm, 'funcid': (nodes_meta.get(s) or {}).get('funcid')}
                            added_by_reaches.append({'start': s, 'end': tid, 'type': typ, 'name': nm, 'funcid': (nodes_meta.get(s) or {}).get('funcid')})
                # upward parent call: include call and its params
                p = parent_of.get(tid)
                if p is not None:
                    pt = (nodes_meta.get(p) or {}).get('type') or ''
                    if pt in call_types:
                        if (p not in taint_ids) and (p not in active) and (p not in new_pre):
                            new_pre.add(p)
                            cname = extract_call_name(p, children_of, nodes_meta)
                            taint_vars[p] = {'type': pt, 'name': cname, 'funcid': (nodes_meta.get(p) or {}).get('funcid')}
                            added_by_calls.append({'id': p, 'type': pt, 'name': cname, 'funcid': (nodes_meta.get(p) or {}).get('funcid'), 'reason': 'parent_call'})
                        params = extract_call_params(p, children_of, parent_of, nodes_meta)
                        for param in params:
                            pid = param['id']
                            if (pid not in taint_ids) and (pid not in active) and (pid not in new_pre):
                                new_pre.add(pid)
                                taint_vars[pid] = {'type': param['type'], 'name': param['name'], 'funcid': (nodes_meta.get(pid) or {}).get('funcid')}
                                added_by_calls.append({'id': pid, 'type': param['type'], 'name': param['name'], 'funcid': (nodes_meta.get(pid) or {}).get('funcid'), 'reason': 'call_param'})
            else:
                # active is a call node: expand to its method params via CALLS edges
                mid = find_method_for_call(tid, recs, calls_edges)
                if mid is not None:
                    # find AST_PARAM_LIST under method
                    for c in children_of.get(mid, []) or []:
                        nc = nodes_meta.get(c) or {}
                        if nc.get('type') == 'AST_PARAM_LIST':
                            for p in children_of.get(c, []) or []:
                                np = nodes_meta.get(p) or {}
                                if np.get('type') != 'AST_PARAM':
                                    continue
                                # determine parameter name from string child within this AST_PARAM
                                param_name = ''
                                for sc in children_of.get(p, []) or []:
                                    sn_t, sn_v = node_display(sc, nodes_meta, children_of)
                                    if sn_t == 'string' and sn_v:
                                        param_name = sn_v
                                        break
                                for pc in children_of.get(p, []) or []:
                                    typ, nm = node_display(pc, nodes_meta, children_of)
                                    if typ == 'NULL' and not nm:
                                        nm = param_name
                                    if (pc not in taint_ids) and (pc not in active) and (pc not in new_pre):
                                        new_pre.add(pc)
                                        taint_vars[pc] = {'type': typ, 'name': nm, 'funcid': (nodes_meta.get(pc) or {}).get('funcid')}
                                        added_by_method_params.append({'call': tid, 'method': mid, 'id': pc, 'type': typ, 'name': nm})
        # move active to taint
        for a in list(active):
            taint_ids.add(a)
        # swap buffers
        if useA:
            preA = new_pre
            useA = False
        else:
            preB = new_pre
            useA = True
        debug['iterations'].append({
            'iteration': it,
            'expanding_from': 'A' if useA else 'B',
            'active_size': len(active),
            'new_pre_size': len(new_pre),
            'added_by_match': added_by_match,
            'added_by_reaches': added_by_reaches,
            'added_by_calls': added_by_calls,
            'added_by_method_params': added_by_method_params,
            'taint_size': len(taint_ids)
        })
    final = []
    for tid in sorted(taint_ids):
        tv = taint_vars.get(tid) or id_to_var.get(tid) or {}
        final.append({'id': tid, 'type': tv.get('type'), 'name': tv.get('name')})
    debug['final'] = final
    out_dir = cfg.test_path('taint_trace')
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, 'taint_debug.json'), 'w', encoding='utf-8') as f:
        json.dump(debug, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, 'taint_result.txt'), 'w', encoding='utf-8') as f:
        for x in final:
            if x.get('type') and x.get('name'):
                f.write(f"{x['id']} {x['type']} {x['name']}\n")
            else:
                f.write(str(x['id']) + "\n")

if __name__ == '__main__':
    run(None)
