import os
import sys
import json

from analyze_if_line import read_trace_line, extract_if_elements_fast
from utils.extractors.if_extract import load_nodes, load_ast_edges
from taint_handlers.handlers.expr import ast_prop
from utils.trace_utils.trace_edges import build_trace_index_records, load_trace_index_records, save_trace_index_records
from common.app_config import load_app_config


def _build_ctx_for_seq(seq: int) -> dict:
    cfg = load_app_config()
    base = cfg.base_dir
    nodes_path = cfg.find_input_file('nodes.csv')
    trace_path = cfg.find_input_file('trace.log')
    rels_path = cfg.find_input_file('rels.csv')

    trace_index_path = cfg.tmp_path('trace_index.json')
    os.makedirs(os.path.dirname(trace_index_path) or '.', exist_ok=True)
    trace_index_records = load_trace_index_records(trace_index_path)
    if trace_index_records is None:
        trace_index_records = build_trace_index_records(trace_path, nodes_path, None)
        save_trace_index_records(trace_index_path, trace_index_records, {'trace_path': 'trace.log', 'nodes_path': 'nodes.csv'})
    seq_to_index = {}
    for rec in trace_index_records or []:
        idx = rec.get('index')
        for s in rec.get('seqs') or []:
            if s not in seq_to_index:
                seq_to_index[s] = idx

    nodes, top_id_to_file = load_nodes(nodes_path)
    parent_of, children_of = load_ast_edges(rels_path)

    arg = read_trace_line(int(seq), trace_path)
    st = extract_if_elements_fast(arg, int(seq), nodes, children_of, trace_index_records, seq_to_index, parent_of, top_id_to_file)

    ctx = {
        'input_seq': int(seq),
        'path': st.get('path'),
        'line': st.get('line'),
        'targets': st.get('targets'),
        'result': st.get('result'),
        'nodes': nodes,
        'children_of': children_of,
        'parent_of': parent_of,
        'top_id_to_file': top_id_to_file,
        'trace_index_records': trace_index_records,
        'trace_seq_to_index': seq_to_index,
        'scope_root': '/app',
        'windows_root': r'D:\files\witcher\app',
        'llm_enabled': False,
        'llm_scope_debug': True,
        'debug': {},
        'logger': None,
        }
    return ctx


def _extract_ast_prop_taints_from_debug_log(seq: int) -> list[dict]:
    cfg = load_app_config()
    base = cfg.base_dir
    p = os.path.join(cfg.test_path(f'seq_{int(seq)}'), 'logs', 'debug.log')
    if not os.path.exists(p):
        return []
    needle_expand = f'analyze_if_line:{int(seq)} ast_prop_expand '
    seen = set()
    out = []
    with open(p, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if needle_expand not in line:
                continue
            j = line.split(needle_expand, 1)[1].strip()
            try:
                obj = json.loads(j)
            except Exception:
                continue
            recv = (obj.get('obj') or '').strip()
            prop = (obj.get('prop') or '').strip()
            start_seq = obj.get('start_seq')
            if not recv or not prop or start_seq is None:
                continue
            try:
                ss = int(start_seq)
            except Exception:
                continue
            k = (recv, prop, ss)
            if k in seen:
                continue
            seen.add(k)
            out.append({'type': 'AST_PROP', 'name': f'{recv}->{prop}', 'seq': ss, '_this_obj': recv, '_this_call_seq': ss})
    if out:
        return out

    needle = f'analyze_if_line:{int(seq)} llm_leaf_nodes '
    best_items = None
    best_len = -1
    with open(p, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if needle not in line:
                continue
            j = line.split(needle, 1)[1].strip()
            try:
                obj = json.loads(j)
            except Exception:
                continue
            blob = obj.get('json')
            if not isinstance(blob, str) or not blob.strip():
                continue
            try:
                items = json.loads(blob)
            except Exception:
                continue
            if not isinstance(items, list):
                continue
            if len(items) > best_len:
                best_len = len(items)
                best_items = items
    if not best_items:
        return []
    out = []
    for it in best_items or []:
        if not isinstance(it, dict):
            continue
        if (it.get('type') or '').strip() != 'AST_PROP':
            continue
        if it.get('id') is None or it.get('seq') is None:
            continue
        keep = {
            'id': it.get('id'),
            'type': 'AST_PROP',
            'seq': it.get('seq'),
        }
        for k in ('name', 'base', 'prop', '_this_obj', '_this_call_seq'):
            if k in it:
                keep[k] = it.get(k)
        out.append(keep)
    return out


def main() -> None:
    seq = 52564
    if len(sys.argv) >= 2:
        try:
            seq = int(sys.argv[1])
        except Exception:
            return

    ctx = _build_ctx_for_seq(seq)
    props = _extract_ast_prop_taints_from_debug_log(seq)
    out_lines = [f'found_ast_prop={len(props)}', '']
    for t in props or []:
        block, _ = ast_prop.tmp_render_ast_prop_scope_block(t, ctx, max_depth=6)
        if block:
            out_lines.append(block.rstrip('\n'))
            out_lines.append('')

    cfg = load_app_config(argv=sys.argv[1:])
    out_path = os.path.join(cfg.test_dir, f'ast_prop_scope_dump_{int(seq)}.txt')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w', encoding='utf-8', errors='replace') as f:
        f.write('\n'.join(out_lines).rstrip() + '\n')
    print(out_path)


if __name__ == '__main__':
    main()
