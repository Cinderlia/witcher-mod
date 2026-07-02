"""
Extract `AST_IF_ELEM` information from a source location.

Given an input locator like `/app/path/file.php:123`, this script loads Joern CPG
tables (`nodes.csv`, `rels.csv`), finds `AST_IF_ELEM` nodes on that line, and
collects descendant variable-like entities for downstream taint analysis.
"""

import csv
import os
import sys
from typing import Dict, List, Optional, Set
csv.field_size_limit(10**9)

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.app_config import load_app_config
from utils.cpg_utils.graph_mapping import (
    find_first_var_string,
    get_all_string_descendants,
    get_string_children,
    load_ast_edges,
    load_nodes,
    norm_nodes_path,
    norm_trace_path,
    resolve_top_id,
    safe_int,
)


def collect_descendants(root, children_of, nodes, line):
    """Collect descendants of `root` that are on the specified source line."""
    res = []
    q = [root]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if x != root:
            nx = nodes.get(x)
            if nx and nx.get('lineno') == line:
                res.append(x)
        for c in children_of.get(x, []):
            q.append(c)
    return res

def extract_if_elements(arg, nodes_path=None, rels_path=None):
    """Extract if-element descendant entities at a given `path:line` locator."""
    cfg = load_app_config()
    base = cfg.base_dir
    nodes_path = nodes_path or cfg.find_input_file('nodes.csv')
    rels_path = rels_path or cfg.find_input_file('rels.csv')
    pth, ln_s = arg.rsplit(':', 1)
    line = int(ln_s)
    path = norm_trace_path(pth)
    nodes, top_id_to_file = load_nodes(nodes_path)
    parent_of, children_of = load_ast_edges(rels_path)
    idx_by_line = {}
    for nid, nd in nodes.items():
        ln = nd.get('lineno')
        if ln is None:
            continue
        top = resolve_top_id(nid, parent_of, nodes, top_id_to_file)
        if top is None:
            continue
        fp = top_id_to_file.get(top)
        if fp != path:
            continue
        if ln != line:
            continue
        lst = idx_by_line.get(line)
        if lst is None:
            lst = []
            idx_by_line[line] = lst
        lst.append(nid)
    targets = [nid for nid in idx_by_line.get(line, []) if nodes[nid]['type'] == 'AST_IF_ELEM']
    result = {
        'vars': [],
        'dims': [],
        'props': [],
        'consts': [],
        'calls': [],
        'isset': [],
        'empty': [],
        'class_consts': [],
        'static_props': [],
        'instanceof': [],
        'conditional': [],
        'binary_ops': [],
        'unary_ops': []
    }
    for root in targets:
        desc = collect_descendants(root, children_of, nodes, line)
        for x in desc:
            t = nodes[x]['type']
            if t == 'AST_VAR':
                ss = get_string_children(x, children_of, nodes)
                name = ss[0][1] if ss else ''
                result['vars'].append({'id': x, 'name': name})
            elif t == 'AST_DIM':
                parts = [v for _, v in get_string_children(x, children_of, nodes)]
                base_nm = find_first_var_string(x, children_of, nodes)
                key = parts[0] if parts else ''
                result['dims'].append({'id': x, 'base': base_nm, 'key': key})
            elif t == 'AST_PROP':
                parts = [v for _, v in get_string_children(x, children_of, nodes)]
                base_nm = find_first_var_string(x, children_of, nodes)
                prop = parts[0] if parts else ''
                result['props'].append({'id': x, 'base': base_nm, 'prop': prop})
            elif t == 'AST_CONST':
                parts = [v for _, v in get_all_string_descendants(x, children_of, nodes)]
                result['consts'].append({'id': x, 'type': 'AST_CONST', 'name': parts[0] if parts else ''})
            elif t == 'AST_NAME':
                parts = [v for _, v in get_all_string_descendants(x, children_of, nodes)]
                v = parts[0] if parts else (nodes[x].get('code') or nodes[x].get('name') or '')
                result['consts'].append({'id': x, 'type': 'AST_NAME', 'name': v})
            elif t == 'AST_METHOD_CALL':
                fn = ''
                recv = ''
                for c in children_of.get(x, []):
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_VAR':
                        ssc = get_string_children(c, children_of, nodes)
                        recv = ssc[0][1] if ssc else ''
                    if nc.get('labels') == 'string' or nc.get('type') == 'string':
                        vv = nc.get('code') or nc.get('name') or ''
                        if vv:
                            fn = vv
                arg_list_id = None
                args = []
                for c in children_of.get(x, []):
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_ARG_LIST':
                        arg_list_id = c
                        for ac in children_of.get(c, []) or []:
                            anc = nodes.get(ac)
                            if not anc:
                                continue
                            if anc.get('labels') == 'string' or anc.get('type') == 'string':
                                vv = anc.get('code') or anc.get('name') or ''
                                if vv:
                                    args.append({'id': ac, 'type': 'string', 'name': vv})
                            elif anc.get('type') == 'AST_VAR':
                                ssc = get_string_children(ac, children_of, nodes)
                                vv = ssc[0][1] if ssc else ''
                                if vv:
                                    args.append({'id': ac, 'type': 'AST_VAR', 'name': vv})
                            elif anc.get('type') in ('AST_PROP', 'AST_DIM'):
                                ssc = get_all_string_descendants(ac, children_of, nodes)
                                vv = ssc[0][1] if ssc else ''
                                if vv:
                                    args.append({'id': ac, 'type': anc.get('type'), 'name': vv})
                result['calls'].append({'id': x, 'kind': 'method_call', 'name': fn, 'recv': recv, 'arg_list_id': arg_list_id, 'args': args})
            elif t == 'AST_CALL':
                fn = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('labels') == 'string' or nc.get('type') == 'string':
                        vv = nc.get('code') or nc.get('name') or ''
                        if vv:
                            fn = vv
                arg_list_id = None
                args = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_ARG_LIST':
                        arg_list_id = c
                        for ac in children_of.get(c, []) or []:
                            anc = nodes.get(ac)
                            if not anc:
                                continue
                            if anc.get('labels') == 'string' or anc.get('type') == 'string':
                                vv = anc.get('code') or anc.get('name') or ''
                                if vv:
                                    args.append({'id': ac, 'type': 'string', 'name': vv})
                            elif anc.get('type') == 'AST_VAR':
                                ssc = get_string_children(ac, children_of, nodes)
                                vv = ssc[0][1] if ssc else ''
                                if vv:
                                    args.append({'id': ac, 'type': 'AST_VAR', 'name': vv})
                            elif anc.get('type') in ('AST_PROP', 'AST_DIM'):
                                ssc = get_all_string_descendants(ac, children_of, nodes)
                                vv = ssc[0][1] if ssc else ''
                                if vv:
                                    args.append({'id': ac, 'type': anc.get('type'), 'name': vv})
                result['calls'].append({'id': x, 'kind': 'call', 'name': fn, 'recv': '', 'arg_list_id': arg_list_id, 'args': args})
            elif t == 'AST_STATIC_CALL':
                cls = ''
                fn = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_NAME' or nc.get('labels') == 'string' or nc.get('type') == 'string':
                        vv = nc.get('code') or nc.get('name') or ''
                        if vv and not cls:
                            cls = vv
                        elif vv:
                            fn = vv
                arg_list_id = None
                args = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_ARG_LIST':
                        arg_list_id = c
                        for ac in children_of.get(c, []) or []:
                            anc = nodes.get(ac)
                            if not anc:
                                continue
                            if anc.get('labels') == 'string' or anc.get('type') == 'string':
                                vv = anc.get('code') or anc.get('name') or ''
                                if vv:
                                    args.append({'id': ac, 'type': 'string', 'name': vv})
                            elif anc.get('type') == 'AST_VAR':
                                ssc = get_string_children(ac, children_of, nodes)
                                vv = ssc[0][1] if ssc else ''
                                if vv:
                                    args.append({'id': ac, 'type': 'AST_VAR', 'name': vv})
                            elif anc.get('type') in ('AST_PROP', 'AST_DIM'):
                                ssc = get_all_string_descendants(ac, children_of, nodes)
                                vv = ssc[0][1] if ssc else ''
                                if vv:
                                    args.append({'id': ac, 'type': anc.get('type'), 'name': vv})
                result['calls'].append({'id': x, 'kind': 'static_call', 'name': fn, 'recv': cls, 'arg_list_id': arg_list_id, 'args': args})
            elif t == 'AST_ISSET':
                targets2 = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_VAR':
                        ss = get_string_children(c, children_of, nodes)
                        name = ss[0][1] if ss else ''
                        if name:
                            targets2.append({'id': c, 'kind': 'var', 'name': name})
                    elif nc.get('type') == 'AST_DIM':
                        parts = [v for _, v in get_string_children(c, children_of, nodes)]
                        base_nm = find_first_var_string(c, children_of, nodes)
                        key = parts[0] if parts else ''
                        targets2.append({'id': c, 'kind': 'dim', 'base': base_nm, 'key': key})
                    elif nc.get('type') == 'AST_PROP':
                        base_nm = find_first_var_string(c, children_of, nodes)
                        parts = [v for _, v in get_string_children(c, children_of, nodes)]
                        prop = parts[0] if parts else ''
                        targets2.append({'id': c, 'kind': 'prop', 'base': base_nm, 'prop': prop})
                result['isset'].append({'id': x, 'targets': targets2})
            elif t == 'AST_EMPTY':
                targets2 = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_VAR':
                        ss = get_string_children(c, children_of, nodes)
                        name = ss[0][1] if ss else ''
                        if name:
                            targets2.append({'id': c, 'kind': 'var', 'name': name})
                    elif nc.get('type') == 'AST_DIM':
                        parts = [v for _, v in get_string_children(c, children_of, nodes)]
                        base_nm = find_first_var_string(c, children_of, nodes)
                        key = parts[0] if parts else ''
                        targets2.append({'id': c, 'kind': 'dim', 'base': base_nm, 'key': key})
                    elif nc.get('type') == 'AST_PROP':
                        base_nm = find_first_var_string(c, children_of, nodes)
                        parts = [v for _, v in get_string_children(c, children_of, nodes)]
                        prop = parts[0] if parts else ''
                        targets2.append({'id': c, 'kind': 'prop', 'base': base_nm, 'prop': prop})
                result['empty'].append({'id': x, 'targets': targets2})
            elif t == 'AST_CLASS_CONST':
                cls = ''
                const = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if not cls and (nc.get('type') == 'AST_NAME' or nc.get('labels') == 'string' or nc.get('type') == 'string'):
                        cls = (nc.get('code') or nc.get('name') or '')
                    elif const == '' and (nc.get('labels') == 'string' or nc.get('type') == 'string'):
                        const = (nc.get('code') or nc.get('name') or '')
                result['class_consts'].append({'id': x, 'class': cls, 'const': const})
            elif t == 'AST_STATIC_PROP':
                cls = ''
                prop = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if not cls and (nc.get('type') == 'AST_NAME' or nc.get('labels') == 'string' or nc.get('type') == 'string'):
                        cls = (nc.get('code') or nc.get('name') or '')
                    elif prop == '' and (nc.get('labels') == 'string' or nc.get('type') == 'string'):
                        prop = (nc.get('code') or nc.get('name') or '')
                result['static_props'].append({'id': x, 'class': cls, 'prop': prop})
            elif t == 'AST_INSTANCEOF':
                expr = ''
                cls = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if expr == '' and nc.get('type') == 'AST_VAR':
                        ss = get_string_children(c, children_of, nodes)
                        expr = ss[0][1] if ss else ''
                    elif cls == '' and (nc.get('type') == 'AST_NAME' or nc.get('labels') == 'string' or nc.get('type') == 'string'):
                        cls = (nc.get('code') or nc.get('name') or '')
                result['instanceof'].append({'id': x, 'expr': expr, 'class': cls})
            elif t == 'AST_CONDITIONAL':
                names = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_VAR':
                        ss = get_string_children(c, children_of, nodes)
                        if ss:
                            names.append({'id': c, 'name': ss[0][1]})
                    elif nc.get('type') in ('AST_PROP', 'AST_DIM'):
                        ssc = get_all_string_descendants(c, children_of, nodes)
                        if ssc:
                            names.append({'id': c, 'name': ssc[0][1]})
                    elif nc.get('type') in ('AST_NAME', 'AST_CONST') or nc.get('labels') == 'string' or nc.get('type') == 'string':
                        vv = nc.get('code') or nc.get('name') or ''
                        if vv:
                            names.append({'id': c, 'name': vv})
                result['conditional'].append({'id': x, 'names': names})
            elif t == 'AST_BINARY_OP':
                result['binary_ops'].append({'id': x, 'op': nodes[x].get('flags') or ''})
            elif t == 'AST_UNARY_OP':
                result['unary_ops'].append({'id': x, 'op': nodes[x].get('flags') or ''})
    return {'arg': arg, 'path': path, 'line': line, 'targets': targets, 'result': result}


def _file_match(nid: int, nodes: dict, parent_of: dict, top_id_to_file: dict, path: str) -> bool:
    if not path or nid is None:
        return False
    try:
        top = resolve_top_id(int(nid), parent_of, nodes, top_id_to_file)
    except Exception:
        return False
    if top is None:
        return False
    return top_id_to_file.get(int(top)) == path


def _scan_nodes_for_line(path: str, line: int, nodes: dict, parent_of: dict, top_id_to_file: dict, types: Set[str]) -> List[int]:
    if not path or line is None:
        return []
    out = []
    for nid, nd in (nodes or {}).items():
        try:
            ln = nd.get('lineno')
            if ln is None or int(ln) != int(line):
                continue
        except Exception:
            continue
        tt = (nd.get('type') or '').strip()
        if tt not in types:
            continue
        if not _file_match(int(nid), nodes, parent_of, top_id_to_file, path):
            continue
        out.append(int(nid))
    return out


def _collect_if_elems_from_if(if_id: int, children_of: dict, nodes: dict, line: Optional[int] = None) -> List[int]:
    out = []
    q = [int(if_id)]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        nx = nodes.get(int(x)) or {}
        tt = (nx.get('type') or '').strip()
        if tt == 'AST_IF_ELEM':
            if line is None:
                out.append(int(x))
            else:
                try:
                    ln = int(nx.get('lineno'))
                except Exception:
                    ln = None
                if ln is not None and int(ln) == int(line):
                    out.append(int(x))
        for c in children_of.get(int(x), []) or []:
            try:
                q.append(int(c))
            except Exception:
                continue
    if out:
        return out
    out2 = []
    q = [int(if_id)]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        nx = nodes.get(int(x)) or {}
        tt = (nx.get('type') or '').strip()
        if tt == 'AST_IF_ELEM':
            out2.append(int(x))
        for c in children_of.get(int(x), []) or []:
            try:
                q.append(int(c))
            except Exception:
                continue
    return out2


def resolve_if_elem_targets(
    *,
    path: str,
    line: int,
    record: Optional[dict],
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    top_id_to_file: dict,
) -> List[int]:
    types = {'AST_IF', 'AST_IF_ELEM', 'AST_ELSEIF', 'AST_SWITCH'}
    candidates = (record or {}).get('node_ids') or []
    targets = []
    for nid in candidates:
        try:
            ni = int(nid)
        except Exception:
            continue
        tt = ((nodes.get(int(ni)) or {}).get('type') or '').strip()
        if tt in types:
            targets.append(int(ni))
    if not targets:
        targets = _scan_nodes_for_line(path, line, nodes, parent_of, top_id_to_file, types)
    out = []
    seen = set()
    for nid in targets or []:
        tt = ((nodes.get(int(nid)) or {}).get('type') or '').strip()
        if tt in ('AST_IF', 'AST_ELSEIF'):
            elems = _collect_if_elems_from_if(int(nid), children_of, nodes, line)
            if elems:
                for e in elems:
                    if int(e) not in seen:
                        seen.add(int(e))
                        out.append(int(e))
            else:
                if int(nid) not in seen:
                    seen.add(int(nid))
                    out.append(int(nid))
        else:
            if int(nid) not in seen:
                seen.add(int(nid))
                out.append(int(nid))
    return out


def collect_if_ids_for_record(
    record: Optional[dict],
    *,
    nodes: dict,
    parent_of: dict,
    top_id_to_file: dict,
) -> List[int]:
    types = {'AST_IF', 'AST_IF_ELEM', 'AST_ELSEIF'}
    out: Set[int] = set()
    for nid in (record or {}).get('node_ids') or []:
        ni = safe_int(nid)
        if ni is None:
            continue
        tt = ((nodes.get(int(ni)) or {}).get('type') or '').strip()
        if tt == 'AST_IF':
            out.add(int(ni))
            continue
        if tt in ('AST_IF_ELEM', 'AST_ELSEIF'):
            cur = parent_of.get(int(ni))
            steps = 0
            while cur is not None and steps < 12:
                ct = ((nodes.get(int(cur)) or {}).get('type') or '').strip()
                if ct == 'AST_IF':
                    out.add(int(cur))
                    break
                cur = parent_of.get(int(cur))
                steps += 1
    if out:
        return sorted(out)
    rec = record or {}
    p = norm_trace_path(rec.get('path') or '')
    ln = rec.get('line')
    if not p or ln is None:
        return []
    for nid in _scan_nodes_for_line(p, int(ln), nodes, parent_of, top_id_to_file, types):
        tt = ((nodes.get(int(nid)) or {}).get('type') or '').strip()
        if tt == 'AST_IF':
            out.add(int(nid))
            continue
        if tt in ('AST_IF_ELEM', 'AST_ELSEIF'):
            cur = parent_of.get(int(nid))
            steps = 0
            while cur is not None and steps < 12:
                ct = ((nodes.get(int(cur)) or {}).get('type') or '').strip()
                if ct == 'AST_IF':
                    out.add(int(cur))
                    break
                cur = parent_of.get(int(cur))
                steps += 1
    return sorted(out)


def collect_switch_ids_for_record(
    record: Optional[dict],
    *,
    nodes: dict,
    parent_of: dict,
    top_id_to_file: dict,
) -> List[int]:
    out: Set[int] = set()
    for nid in (record or {}).get('node_ids') or []:
        ni = safe_int(nid)
        if ni is None:
            continue
        tt = ((nodes.get(int(ni)) or {}).get('type') or '').strip()
        if tt == 'AST_SWITCH':
            out.add(int(ni))
    if out:
        return sorted(out)
    rec = record or {}
    p = norm_trace_path(rec.get('path') or '')
    ln = rec.get('line')
    if not p or ln is None:
        return []
    for nid in _scan_nodes_for_line(p, int(ln), nodes, parent_of, top_id_to_file, {'AST_SWITCH'}):
        out.add(int(nid))
    return sorted(out)

def main():
    """CLI entrypoint: `python if_extract.py <path:line>` (writes `if_extract_output.txt`)."""
    cfg = load_app_config(argv=sys.argv[1:])
    base = cfg.base_dir
    nodes_path = cfg.find_input_file('nodes.csv')
    rels_path = cfg.find_input_file('rels.csv')
    arg = '/app/phpbb/memberlist.php:98'
    if len(sys.argv) >= 2:
        arg = sys.argv[1]
    st = extract_if_elements(arg, nodes_path, rels_path)
    targets = st['targets']
    result = st['result']
    out_lines = []
    out_lines.append('input ' + arg)
    out_lines.append('if_elem_ids ' + ','.join(str(x) for x in targets))
    for item in result['vars']:
        out_lines.append(f"{item['id']} AST_VAR {item['name']}")
    for item in result['calls']:
        if item.get('kind') == 'method_call':
            args_str = '|'.join([f"{a['id']}:{a['name']}" for a in item['args']])
            out_lines.append(f"{item['id']} AST_METHOD_CALL {item['name']} {item['recv']} " + (str(item['arg_list_id']) if item['arg_list_id'] is not None else '') + ' ' + args_str)
    print('\n'.join(out_lines))
    out_path = os.path.join(cfg.test_path('if_extract'), 'if_extract_output.txt')
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out_lines))
    print(out_path)

if __name__ == '__main__':
    main()
