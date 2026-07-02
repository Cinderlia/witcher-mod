"""
SWITCH-branch coverage lookup based on CPG node ids and line-coverage (cc.json) reports.
"""

import os
from typing import Dict, List, Optional, Set

from common.app_config import load_app_config
from if_branch_coverage.coverage_parser import build_coverage_index, find_cc_json, has_covered_line, load_coverage
from llm_utils.branch.switch_branch import collect_stmt_list_lines, get_case_stmt_list_id, get_switch_case_ids, get_switch_case_line
from utils.cpg_utils.graph_mapping import load_ast_edges, load_nodes, norm_nodes_path, resolve_top_id, safe_int


def is_ast_switch(switch_id, nodes: Dict[int, dict]) -> bool:
    nid = safe_int(switch_id)
    if nid is None:
        return False
    nx = nodes.get(int(nid)) or {}
    return (nx.get("type") or "").strip() == "AST_SWITCH"


def get_switch_file_path(switch_id, parent_of: Dict[int, int], nodes: Dict[int, dict], top_id_to_file: Dict[int, str]) -> str:
    nid = safe_int(switch_id)
    if nid is None:
        return ""
    top_id = resolve_top_id(int(nid), parent_of, nodes, top_id_to_file)
    if top_id is None:
        return ""
    return (top_id_to_file.get(int(top_id)) or "").strip()


def get_switch_case_lines(case_id: int, *, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Set[int]:
    lines: Set[int] = set()
    stmt_list_id = get_case_stmt_list_id(int(case_id), nodes=nodes, children_of=children_of)
    if stmt_list_id is not None:
        lines |= collect_stmt_list_lines(int(stmt_list_id), nodes=nodes, children_of=children_of)
    if not lines:
        ln = get_switch_case_line(int(case_id), nodes)
        if ln is not None and ln > 0:
            lines.add(int(ln))
    return lines


class SwitchBranchCoverageService:
    """Load coverage data and answer per-case coverage for a given AST_SWITCH id."""

    def __init__(self, *, config_path: Optional[str] = None, argv: Optional[List[str]] = None, base_dir: Optional[str] = None):
        cfg = load_app_config(config_path=config_path, argv=argv, base_dir=base_dir)
        self.config = cfg
        self.input_dir = cfg.input_dir
        self.nodes_path = cfg.find_input_file("nodes.csv")
        self.rels_path = cfg.find_input_file("rels.csv")
        self.nodes, self.top_id_to_file = load_nodes(self.nodes_path)
        self.parent_of, self.children_of = load_ast_edges(self.rels_path)
        self.cc_path = ""
        self.coverage_index = {}
        self.reload_coverage()

    def reload_coverage(self) -> None:
        cfg = self.config
        raw = cfg.raw if isinstance(cfg.raw, dict) else {}
        v = raw.get("coverage_json_path") if isinstance(raw.get("coverage_json_path"), str) else ""
        self.cc_path = v.strip() if v else find_cc_json(self.input_dir)
        self.coverage_index = build_coverage_index(load_coverage(self.cc_path)) if self.cc_path else {}

    def check_switch_coverage(self, switch_id) -> Dict[int, bool]:
        """Return {case_id: covered_bool} for all cases under the switch."""
        nid = safe_int(switch_id)
        if nid is None:
            return {}
        if not is_ast_switch(nid, self.nodes):
            return {}
        file_path = get_switch_file_path(nid, self.parent_of, self.nodes, self.top_id_to_file)
        if not file_path:
            return {}
        norm_path = norm_nodes_path(file_path)
        out: Dict[int, bool] = {}
        for case_id in get_switch_case_ids(int(nid), nodes=self.nodes, children_of=self.children_of):
            lines = get_switch_case_lines(int(case_id), nodes=self.nodes, children_of=self.children_of)
            covered = has_covered_line(self.coverage_index, norm_path, lines) if lines else False
            out[int(case_id)] = bool(covered)
        return out


_DEFAULT_SERVICE: Optional[SwitchBranchCoverageService] = None
_DEFAULT_CONFIG_KEY: str = ""


def get_service(config_path: Optional[str] = None) -> SwitchBranchCoverageService:
    global _DEFAULT_SERVICE, _DEFAULT_CONFIG_KEY
    key = (config_path or "").strip()
    if _DEFAULT_SERVICE is None or _DEFAULT_CONFIG_KEY != key:
        _DEFAULT_SERVICE = SwitchBranchCoverageService(config_path=config_path)
        _DEFAULT_CONFIG_KEY = key
    return _DEFAULT_SERVICE


def check_switch_branch_coverage(switch_id, config_path: Optional[str] = None) -> Dict[int, bool]:
    return {}
    # svc = get_service(config_path=config_path)
    # return svc.check_switch_coverage(switch_id)


def reload_switch_branch_coverage(config_path: Optional[str] = None) -> None:
    svc = get_service(config_path=config_path)
    try:
        svc.reload_coverage()
    except Exception:
        return
