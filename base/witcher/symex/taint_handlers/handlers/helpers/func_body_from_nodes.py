import os
import sys
from typing import Dict, List, Optional, Tuple

from utils.cpg_utils.graph_mapping import load_nodes, load_ast_edges, resolve_top_id
from llm_utils.prompts.prompt_utils import resolve_source_path


def collect_func_nodes(func_def_id: int, nodes: Dict[int, dict]) -> List[int]:
    out: List[int] = []
    seen = set()
    try:
        fid = int(func_def_id)
    except Exception:
        return out
    for nid, nd in nodes.items():
        if nid == fid or (nd or {}).get('funcid') == fid:
            if nid not in seen:
                seen.add(nid)
                out.append(int(nid))
    return out


def resolve_func_source_path(func_def_id: int, nodes: Dict[int, dict], parent_of: Dict[int, int], top_id_to_file: Dict[int, str]) -> str:
    try:
        fid = int(func_def_id)
    except Exception:
        return ''
    top = resolve_top_id(fid, parent_of, nodes, top_id_to_file)
    if top is None:
        return ''
    return (top_id_to_file.get(top) or '').strip()


def func_body_line_range(func_node_ids: List[int], nodes: Dict[int, dict]) -> Tuple[Optional[int], Optional[int]]:
    min_line = None
    max_line = None
    for nid in func_node_ids or []:
        ln = (nodes.get(int(nid)) or {}).get('lineno')
        if ln is None:
            continue
        try:
            ln_i = int(ln)
        except Exception:
            continue
        if min_line is None or ln_i < int(min_line):
            min_line = int(ln_i)
        if max_line is None or ln_i > int(max_line):
            max_line = int(ln_i)
    return min_line, max_line


def read_source_lines(fs_path: str, start_line: int, end_line: int) -> List[str]:
    out: List[str] = []
    if not fs_path or start_line is None or end_line is None:
        return out
    try:
        start_i = int(start_line)
        end_i = int(end_line)
    except Exception:
        return out
    if start_i > end_i:
        start_i, end_i = end_i, start_i
    try:
        with open(fs_path, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f, start=1):
                if i < start_i:
                    continue
                if i > end_i:
                    break
                out.append(f"{i} {line.rstrip()}")
    except Exception:
        return []
    return out


def build_func_body_from_nodes(*, func_def_id: int, nodes_path: str, rels_path: str, scope_root: str = '/app', windows_root: str = r'D:\files\witcher\app') -> Tuple[str, List[str]]:
    nodes, top_id_to_file = load_nodes(nodes_path)
    parent_of, _children_of = load_ast_edges(rels_path)
    func_nodes = collect_func_nodes(int(func_def_id), nodes)
    src_path = resolve_func_source_path(int(func_def_id), nodes, parent_of, top_id_to_file)
    if not src_path:
        return '', []
    fs_path = resolve_source_path(scope_root, src_path, windows_root=windows_root)
    min_line, max_line = func_body_line_range(func_nodes, nodes)
    if min_line is None or max_line is None:
        return src_path, []
    lines = read_source_lines(fs_path, int(min_line), int(max_line))
    return src_path, lines


def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: python func_body_from_nodes.py <func_def_id> [out_path]')
    try:
        func_def_id = int(sys.argv[1])
    except Exception:
        raise SystemExit('func_def_id must be int')
    out_path = sys.argv[2] if len(sys.argv) >= 3 else os.path.join('test', f'func_body_{func_def_id}.txt')
    base = os.getcwd()
    nodes_path = os.path.join(base, 'nodes.csv')
    rels_path = os.path.join(base, 'rels.csv')
    src_path, lines = build_func_body_from_nodes(func_def_id=func_def_id, nodes_path=nodes_path, rels_path=rels_path)
    header = []
    if src_path:
        header.append(f"source_path: {src_path}")
    if lines:
        header.append(f"lines: {lines[0].split(' ', 1)[0]}-{lines[-1].split(' ', 1)[0]}")
    payload = '\n'.join(header + [''] + lines if header else lines)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w', encoding='utf-8', errors='replace') as f:
        f.write(payload)


if __name__ == '__main__':
    main()
