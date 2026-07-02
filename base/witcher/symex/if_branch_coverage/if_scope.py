"""
Helpers to map an AST_IF id to source file and branch statement line sets.
"""

from utils.cpg_utils.graph_mapping import resolve_top_id, safe_int
from llm_utils.branch.if_branch import collect_stmt_list_lines, get_if_elems, get_stmt_list_id
from typing import Dict, List, Set, Tuple


def is_ast_if(if_id, nodes: Dict[int, dict]) -> bool:
    nid = safe_int(if_id)
    if nid is None:
        return False
    nx = nodes.get(int(nid)) or {}
    return (nx.get("type") or "").strip() == "AST_IF"


def get_if_branch_lines(if_id, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Tuple[Set[int], Set[int]]:
    """Return (true_branch_lines, false_branch_lines) for the IF's then/else statement lists."""
    nid = safe_int(if_id)
    if nid is None:
        return set(), set()
    if not is_ast_if(nid, nodes):
        return set(), set()
    elems = get_if_elems(int(nid), nodes=nodes, children_of=children_of)
    true_lines: Set[int] = set()
    false_lines: Set[int] = set()
    if elems:
        stmt_list = get_stmt_list_id(int(elems[0]), nodes=nodes, children_of=children_of)
        if stmt_list is not None:
            true_lines = collect_stmt_list_lines(int(stmt_list), nodes=nodes, children_of=children_of)
    if len(elems) > 1:
        stmt_list = get_stmt_list_id(int(elems[1]), nodes=nodes, children_of=children_of)
        if stmt_list is not None:
            false_lines = collect_stmt_list_lines(int(stmt_list), nodes=nodes, children_of=children_of)
    return true_lines, false_lines


def get_if_file_path(if_id, parent_of: Dict[int, int], nodes: Dict[int, dict], top_id_to_file: Dict[int, str]) -> str:
    nid = safe_int(if_id)
    if nid is None:
        return ""
    top_id = resolve_top_id(int(nid), parent_of, nodes, top_id_to_file)
    if top_id is None:
        return ""
    return (top_id_to_file.get(int(top_id)) or "").strip()
