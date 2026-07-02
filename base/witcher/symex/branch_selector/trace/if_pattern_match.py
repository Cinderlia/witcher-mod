import os
import re
import sys
from typing import Dict, List, Optional, Set

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger
from if_branch_coverage import check_if_branch_coverage
from if_branch_coverage.if_scope import get_if_file_path
from if_branch_coverage.switch_coverage import check_switch_branch_coverage
from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines, resolve_source_path
from utils.cpg_utils.graph_mapping import norm_nodes_path, safe_int
from branch_selector.trace.trace_extract import _path_is_filtered, build_loc_for_seq, build_seq_to_index
from branch_selector.trace.if_scope_expand import _expand_one_seq, _precompute_expand_indices


class SourceLineCache:
    def __init__(self, scope_root: str, windows_root: str):
        self._scope_root = scope_root
        self._windows_root = windows_root
        self._cache: Dict[str, List[str]] = {}
        self._resolved_path_cache: Dict[str, str] = {}

    def get_line(self, path: str, line: int) -> str:
        if not path or line is None:
            return ""
        try:
            ln = int(line)
        except Exception:
            return ""
        key = str(path)
        fs_path = self._resolved_path_cache.get(key)
        if fs_path is None:
            fs_path = resolve_source_path(self._scope_root, path, windows_root=self._windows_root) or ""
            self._resolved_path_cache[key] = fs_path
        if not fs_path:
            return ""
        buf = self._cache.get(fs_path)
        if buf is None:
            try:
                with open(fs_path, "r", encoding="utf-8", errors="replace") as f:
                    buf = [x.rstrip("\n") for x in f]
            except Exception:
                buf = []
            self._cache[fs_path] = buf
        if 1 <= ln <= len(buf):
            return buf[ln - 1]
        return ""


_IF_RE = re.compile(r"\bif\s*\(", re.IGNORECASE)
_ELSEIF_RE = re.compile(r"\belseif\b", re.IGNORECASE)
_SWITCH_RE = re.compile(r"\bswitch\s*\(", re.IGNORECASE)


def _strip_inline_comment(line: str) -> str:
    if not isinstance(line, str):
        return ""
    s = line
    for sep in ("//", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    return s


def is_if_line(code: str) -> bool:
    s = _strip_inline_comment(code or "").strip()
    if not s:
        return False
    return bool(_IF_RE.search(s) or _ELSEIF_RE.search(s))


def is_switch_line(code: str) -> bool:
    s = _strip_inline_comment(code or "").strip()
    if not s:
        return False
    return bool(_SWITCH_RE.search(s))


def _collect_if_ids_from_nodes(node_ids: List[int], nodes: dict, parent_of: dict) -> List[int]:
    out: Set[int] = set()
    for nid in node_ids or []:
        ni = safe_int(nid)
        if ni is None:
            continue
        tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
        if tt == "AST_IF":
            out.add(int(ni))
            continue
        if tt in ("AST_IF_ELEM", "AST_ELSEIF"):
            cur = parent_of.get(int(ni))
            steps = 0
            while cur is not None and steps < 12:
                ct = ((nodes.get(int(cur)) or {}).get("type") or "").strip()
                if ct == "AST_IF":
                    out.add(int(cur))
                    break
                cur = parent_of.get(int(cur))
                steps += 1
    return sorted(out)


def _collect_switch_ids_from_nodes(node_ids: List[int], nodes: dict) -> List[int]:
    out: Set[int] = set()
    for nid in node_ids or []:
        ni = safe_int(nid)
        if ni is None:
            continue
        tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
        if tt == "AST_SWITCH":
            out.add(int(ni))
    return sorted(out)


def _load_if_branch_cache_ids(cache_path: Optional[str]) -> Set[str]:
    if not cache_path or not os.path.exists(cache_path):
        return set()
    try:
        import json
        with open(cache_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return set()
    if not isinstance(obj, dict):
        return set()
    out: Set[str] = set()
    for k in obj.keys():
        try:
            ks = str(k)
        except Exception:
            continue
        out.add(ks)
    return out


def iter_if_sections_pattern(
    *,
    trace_index_records: List[dict],
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    top_id_to_file: dict,
    seq_limit: int,
    scope_root: str,
    trace_index_path: str,
    windows_root: str,
    nearest_seq_count: int,
    farthest_seq_count: int,
    trace_path: str,
    if_branch_cache_path: Optional[str] = None,
    if_branch_cache_skip: bool = False,
    logger: Optional[Logger] = None,
):
    seq_to_index = build_seq_to_index(trace_index_records)
    cached_if_keys = _load_if_branch_cache_ids(if_branch_cache_path) if if_branch_cache_skip else set()
    if_cov_cache: Dict[int, bool] = {}
    if_cached_seq_count = 0
    if_cached_hit_count = 0
    if_cached_skip_count = 0
    if_cached_last_seq = None
    switch_cov_cache: Dict[int, Dict[int, bool]] = {}
    switch_cached_seq_count = 0
    switch_cached_hit_count = 0
    switch_cached_skip_count = 0
    switch_cached_last_seq = None
    indices = _precompute_expand_indices(trace_index_records, nodes)
    reader = SourceLineCache(scope_root, windows_root)
    if logger is not None:
        logger.info("section_iter_start")
    seen_records = 0
    non_filtered_seen = 0
    limit = int(seq_limit) if seq_limit is not None else None
    for rec in trace_index_records or []:
        seen_records += 1
        rec_path = rec.get("path")
        if _path_is_filtered(rec_path):
            continue
        seqs = []
        for s in rec.get("seqs") or []:
            try:
                si = int(s)
            except Exception:
                continue
            non_filtered_seen += 1
            if limit is not None and non_filtered_seen > limit:
                continue
            seqs.append(si)
        if not seqs:
            continue
        rec_path = rec.get("path")
        rec_line = rec.get("line")
        code = reader.get_line(rec_path, rec_line)
        if not (is_if_line(code) or is_switch_line(code)):
            continue
        if rec_line is None:
            continue
        min_seq = min(seqs)
        node_ids = rec.get("node_ids") or []
        if_ids = _collect_if_ids_from_nodes(node_ids, nodes, parent_of)
        switch_ids = _collect_switch_ids_from_nodes(node_ids, nodes)
        def _if_key(iid: int) -> Optional[str]:
            nx = nodes.get(int(iid)) or {}
            ln = nx.get("lineno")
            fp = get_if_file_path(int(iid), parent_of, nodes, top_id_to_file)
            if fp and ln is not None:
                return f"{norm_nodes_path(fp)}:{int(ln)}"
            return None
        if if_branch_cache_skip and if_ids:
            hit_ids = []
            for x in if_ids:
                k = _if_key(int(x))
                if k and k in cached_if_keys:
                    hit_ids.append(int(x))
            if hit_ids:
                if logger is not None:
                    logger.info("if_cache_skip", seq=int(min_seq), if_ids=hit_ids)
                continue
        skip_due_to_if = False
        if if_ids:
            miss_ids = []
            covered_map: Dict[int, bool] = {}
            for if_id in if_ids:
                if int(if_id) in if_cov_cache:
                    covered = bool(if_cov_cache[int(if_id)])
                    if_cached_hit_count += 1
                else:
                    covered = check_if_branch_coverage(int(if_id))
                    if logger is not None:
                        logger.info("if_coverage_result", if_id=int(if_id), covered=bool(covered))
                    if_cov_cache[int(if_id)] = bool(covered)
                    miss_ids.append(int(if_id))
                covered_map[int(if_id)] = bool(covered)
            if miss_ids and logger is not None:
                logger.info("if_coverage_check_start", seq=int(min_seq), if_ids=[int(x) for x in miss_ids])
            all_covered = True
            for if_id in if_ids:
                covered = covered_map.get(int(if_id))
                if miss_ids and logger is not None and int(if_id) in miss_ids:
                    logger.info("if_coverage_check_item", seq=int(min_seq), if_id=int(if_id), covered=bool(covered))
                if not bool(covered):
                    all_covered = False
            if all_covered:
                skip_due_to_if = True
                if miss_ids and logger is not None:
                    logger.info("if_coverage_skip", seq=int(min_seq), if_ids=[int(x) for x in if_ids])
                if_cached_skip_count += 1
            if not miss_ids:
                if_cached_seq_count += 1
                if_cached_last_seq = int(min_seq)
                if logger is not None and if_cached_seq_count % 200 == 0:
                    logger.info(
                        "if_coverage_cache_summary",
                        seqs=if_cached_seq_count,
                        hits=if_cached_hit_count,
                        skipped=if_cached_skip_count,
                        last_seq=int(if_cached_last_seq),
                    )
        skip_due_to_switch = False
        if switch_ids:
            miss_switch_ids = []
            cov_map_by_id: Dict[int, Dict[int, bool]] = {}
            for switch_id in switch_ids:
                if int(switch_id) in switch_cov_cache:
                    cov_map_by_id[int(switch_id)] = switch_cov_cache[int(switch_id)]
                    switch_cached_hit_count += 1
                else:
                    cov_map = check_switch_branch_coverage(int(switch_id))
                    switch_cov_cache[int(switch_id)] = cov_map
                    cov_map_by_id[int(switch_id)] = cov_map
                    miss_switch_ids.append(int(switch_id))
            if miss_switch_ids and logger is not None:
                logger.info("switch_coverage_check_start", seq=int(min_seq), switch_ids=[int(x) for x in miss_switch_ids])
            all_switch_covered = True
            for switch_id in switch_ids:
                cov_map = cov_map_by_id.get(int(switch_id)) or {}
                covered_all = bool(cov_map) and all(bool(v) for v in cov_map.values())
                if miss_switch_ids and logger is not None and int(switch_id) in miss_switch_ids:
                    logger.info(
                        "switch_coverage_check_item",
                        seq=int(min_seq),
                        switch_id=int(switch_id),
                        covered_all=bool(covered_all),
                        covered_count=sum(1 for v in (cov_map or {}).values() if bool(v)),
                        case_count=len(cov_map or {}),
                    )
                if not covered_all:
                    all_switch_covered = False
            if all_switch_covered:
                skip_due_to_switch = True
                if miss_switch_ids and logger is not None:
                    logger.info("switch_coverage_skip", seq=int(min_seq), switch_ids=[int(x) for x in switch_ids])
            if not miss_switch_ids:
                switch_cached_seq_count += 1
                switch_cached_last_seq = int(min_seq)
                if skip_due_to_switch:
                    switch_cached_skip_count += 1
                if logger is not None and switch_cached_seq_count % 200 == 0:
                    logger.info(
                        "switch_coverage_cache_summary",
                        seqs=switch_cached_seq_count,
                        hits=switch_cached_hit_count,
                        skipped=switch_cached_skip_count,
                        last_seq=int(switch_cached_last_seq),
                    )
        if (if_ids and skip_due_to_if and (not switch_ids or skip_due_to_switch)) or (switch_ids and skip_due_to_switch and not if_ids):
            continue
        seq_i, rel_seqs = _expand_one_seq(
            seq=int(min_seq),
            rel_seqs=[int(min_seq)],
            trace_index_records=trace_index_records,
            nodes=nodes,
            parent_of=parent_of,
            children_of=children_of,
            top_id_to_file=top_id_to_file,
            trace_path=trace_path,
            scope_root=scope_root,
            windows_root=windows_root,
            nearest_seq_count=nearest_seq_count,
            farthest_seq_count=farthest_seq_count,
            indices=indices,
        )
        if seq_i is None:
            continue
        locs = []
        for s in (rel_seqs or []):
            loc = build_loc_for_seq(int(s), trace_index_records, seq_to_index)
            if loc:
                locs.append(loc)
        lines = map_result_set_to_source_lines(scope_root, locs, trace_index_path=trace_index_path, windows_root=windows_root)
        sig_items = []
        sig_set = set()
        for it in lines or []:
            if not isinstance(it, dict):
                continue
            p = it.get("path")
            ln = it.get("line")
            if not p or ln is None:
                continue
            key = f"{p}:{int(ln)}"
            if key in sig_set:
                continue
            sig_set.add(key)
            sig_items.append(key)
        sig_items.sort()
        sig = tuple(sig_items) if sig_items else None
        yield {"seq": int(seq_i), "lines": lines, "sig": sig, "scope_seqs": list(rel_seqs or [])}
    if logger is not None:
        logger.info("section_iter_done", processed=seen_records)
