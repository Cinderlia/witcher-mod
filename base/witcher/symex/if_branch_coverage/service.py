"""
IF-branch coverage lookup based on CPG node ids and line-coverage (cc.json) reports.
"""

from common.app_config import load_app_config
from utils.cpg_utils.graph_mapping import load_ast_edges, load_nodes, norm_nodes_path, safe_int

import os
from typing import List, Optional

from if_branch_coverage.cache import get_cached_result, init_cache, reset_cache, set_cached_result
from if_branch_coverage.coverage_parser import build_coverage_index, find_cc_json, has_covered_line, load_coverage
from if_branch_coverage.if_scope import get_if_branch_lines, get_if_file_path, is_ast_if


class IfBranchCoverageService:
    """Load coverage data and answer whether both IF branches are covered for a given AST_IF id."""
    def __init__(self, *, config_path: Optional[str] = None, argv: Optional[List[str]] = None, base_dir: Optional[str] = None):
        cfg = load_app_config(config_path=config_path, argv=argv, base_dir=base_dir)
        self.config = cfg
        self.input_dir = cfg.input_dir
        cache_path = os.path.join(cfg.tmp_dir, "if_branch_coverage_cache.json")
        init_cache(cache_path)
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
        try:
            import logging
            logger = logging.getLogger("coverage_skip")
            logger.info(f"reload_coverage cc_path={self.cc_path}")
        except Exception:
            pass
        self.coverage_index = build_coverage_index(load_coverage(self.cc_path)) if self.cc_path else {}
        reset_cache()

    def check_if_coverage(self, if_id) -> bool:
        """Return True if the IF's true-branch and false-branch have coverage evidence."""
        nid = safe_int(if_id)
        if nid is None:
            return False
        if not is_ast_if(nid, self.nodes):
            # compute key if possible for negative cache
            nx = self.nodes.get(int(nid)) or {}
            if_line = nx.get("lineno")
            file_path = get_if_file_path(nid, self.parent_of, self.nodes, self.top_id_to_file)
            if file_path and if_line is not None:
                norm_path = norm_nodes_path(file_path)
                key = f"{norm_path}:{int(if_line)}"
                set_cached_result(key, False)
            return False
        file_path = get_if_file_path(nid, self.parent_of, self.nodes, self.top_id_to_file)
        if not file_path:
            return False
        nx = self.nodes.get(int(nid)) or {}
        if_line = nx.get("lineno")
        if if_line is None:
            return False
        norm_path = norm_nodes_path(file_path)
        key = f"{norm_path}:{int(if_line)}"
        cached = get_cached_result(key)
        if cached is not None:
            return bool(cached)
        true_lines, false_lines = get_if_branch_lines(nid, self.nodes, self.children_of)
        true_covered = has_covered_line(self.coverage_index, norm_path, true_lines)
        if false_lines:
            false_covered = has_covered_line(self.coverage_index, norm_path, false_lines)
            result = bool(true_covered and false_covered)
        else:
            result = bool(true_covered)
            
        try:
            import logging
            logger = logging.getLogger("coverage_skip")
            logger.info(f"coverage_detail if_id={nid} norm_path={norm_path} line={if_line} true_lines={true_lines} true_covered={true_covered} false_lines={false_lines} false_covered={false_covered if false_lines else 'N/A'} result={result}")
        except Exception:
            pass
            
        set_cached_result(key, result)
        return result


_DEFAULT_SERVICE: Optional[IfBranchCoverageService] = None
_DEFAULT_CONFIG_KEY: str = ""


def get_service(config_path: Optional[str] = None) -> IfBranchCoverageService:
    """Return a cached service instance, keyed by config_path."""
    global _DEFAULT_SERVICE, _DEFAULT_CONFIG_KEY
    key = (config_path or "").strip()
    if _DEFAULT_SERVICE is None or _DEFAULT_CONFIG_KEY != key:
        _DEFAULT_SERVICE = IfBranchCoverageService(config_path=config_path)
        _DEFAULT_CONFIG_KEY = key
    return _DEFAULT_SERVICE


def reload_if_branch_coverage(config_path: Optional[str] = None) -> None:
    svc = get_service(config_path=config_path)
    try:
        svc.reload_coverage()
    except Exception:
        return


def check_if_branch_coverage(if_id, config_path: Optional[str] = None) -> bool: 
    """Convenience wrapper around the default IfBranchCoverageService."""       
    svc = get_service(config_path=config_path)
    res = svc.check_if_coverage(if_id)
    try:
        import logging
        import os
        logger = logging.getLogger("coverage_skip")
        if not logger.handlers:
            meta_dir = os.environ.get("WITCHER_SYMEX_META_DIR", "/tmp")
            log_file = os.path.join(meta_dir, "coverage_skip.log")
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        logger.info(f"check_if_branch_coverage if_id={if_id} covered={res}")
    except Exception:
        pass
    return res
