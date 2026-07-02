import json
import os
import time
from typing import Dict, List, Optional, Set

from common.logger import Logger
from if_branch_coverage import check_if_branch_coverage
from if_branch_coverage.if_scope import get_if_file_path
from if_branch_coverage.switch_coverage import check_switch_branch_coverage
from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines, resolve_source_path
from utils.cpg_utils.graph_mapping import norm_nodes_path, safe_int
from branch_selector.trace.trace_extract import _path_is_filtered, build_loc_for_seq, build_seq_to_index
from branch_selector.trace.if_scope_expand import _expand_one_seq, _precompute_expand_indices
from branch_selector.sql.sql_query_detector import find_sql_query_calls_in_record
from branch_selector.sql.sql_scope_expand import _expand_one_sql_seq
from branch_selector.trace.if_pattern_match import is_if_line, is_switch_line
from branch_selector.sql.sql_pattern_match import is_sql_line
from branch_selector.cmd.cmd_query_detector import find_cmd_calls_in_record
from branch_selector.cmd.cmd_scope_expand import _expand_one_cmd_seq


class SourceLineCache:
    def __init__(self, scope_root: str, windows_root: str):
        self._scope_root = scope_root
        self._windows_root = windows_root
        self._cache: Dict[str, List[str]] = {}

    def get_line(self, path: str, line: int) -> str:
        if not path or line is None:
            return ""
        try:
            ln = int(line)
        except Exception:
            return ""
        fs_path = resolve_source_path(self._scope_root, path, windows_root=self._windows_root)
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


def iter_dual_sections(
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
    timing_log_path: str,
    if_branch_cache_path: Optional[str] = None,
    if_branch_cache_skip: bool = False,
    logger: Optional[Logger] = None,
):
    os.makedirs(os.path.dirname(timing_log_path) or ".", exist_ok=True)
    seq_to_index = build_seq_to_index(trace_index_records)
    indices = _precompute_expand_indices(trace_index_records, nodes)
    reader = SourceLineCache(scope_root, windows_root)
    cached_if_keys = _load_if_branch_cache_ids(if_branch_cache_path) if if_branch_cache_skip else set()
    if_cov_cache: Dict[int, bool] = {}
    switch_cov_cache: Dict[int, Dict[int, bool]] = {}
    if_cached_seq_count = 0
    if_cached_hit_count = 0
    if_cached_skip_count = 0
    if_cached_last_seq = None
    switch_cached_seq_count = 0
    switch_cached_hit_count = 0
    switch_cached_skip_count = 0
    switch_cached_last_seq = None
    limit = int(seq_limit) if seq_limit is not None else None
    seen_records = 0
    non_filtered_seen = 0
    if logger is not None:
        logger.info("section_iter_start")
    with open(timing_log_path, "a", encoding="utf-8") as tf:
        for rec in trace_index_records or []:
            loop_start = time.perf_counter_ns()
            seen_records += 1
            rec_path = rec.get("path")
            if _path_is_filtered(rec_path):
                continue
            seqs = []
            seqs_start = time.perf_counter_ns()
            for s in rec.get("seqs") or []:
                try:
                    si = int(s)
                except Exception:
                    continue
                non_filtered_seen += 1
                if limit is not None and non_filtered_seen > limit:
                    continue
                seqs.append(si)
            seqs_us = int((time.perf_counter_ns() - seqs_start) / 1000)
            if not seqs:
                continue
            rec_line = rec.get("line")
            if rec_line is None:
                continue
            node_ids = rec.get("node_ids") or []
            ast_start = time.perf_counter_ns()
            if_ids = _collect_if_ids_from_nodes(node_ids, nodes, parent_of)
            switch_ids = _collect_switch_ids_from_nodes(node_ids, nodes)
            sql_hits = find_sql_query_calls_in_record(rec, nodes, children_of)
            cmd_hits = find_cmd_calls_in_record(rec, nodes, children_of)
            ast_ns = time.perf_counter_ns() - ast_start
            pattern_start = time.perf_counter_ns()
            code = reader.get_line(rec_path, rec_line)
            pattern_if = is_if_line(code)
            pattern_switch = is_switch_line(code)
            pattern_sql = is_sql_line(code)
            pattern_ns = time.perf_counter_ns() - pattern_start
            entry = {
                "index": rec.get("index"),
                "path": rec_path,
                "line": rec_line,
                "min_seq": min(seqs),
                "ast_us": int(ast_ns / 1000),
                "pattern_us": int(pattern_ns / 1000),
                "ast_ms": round(ast_ns / 1_000_000, 3),
                "pattern_ms": round(pattern_ns / 1_000_000, 3),
                "seqs_us": seqs_us,
                "node_ids_count": len(node_ids or []),
                "ast_if": bool(if_ids),
                "ast_switch": bool(switch_ids),
                "ast_sql": bool(sql_hits),
                "ast_cmd": bool(cmd_hits),
                "pattern_if": bool(pattern_if),
                "pattern_switch": bool(pattern_switch),
                "pattern_sql": bool(pattern_sql),
            }
            entry["matched_if_block"] = bool(pattern_if or pattern_switch or if_ids or switch_ids)
            entry["matched_sql_block"] = bool(pattern_sql or sql_hits)
            entry["matched_cmd_block"] = bool(cmd_hits)
            if pattern_if or pattern_switch or if_ids or switch_ids:
                def _if_key(iid: int) -> Optional[str]:
                    nx = nodes.get(int(iid)) or {}
                    ln = nx.get("lineno")
                    fp = get_if_file_path(int(iid), parent_of, nodes, top_id_to_file)
                    if fp and ln is not None:
                        return f"{norm_nodes_path(fp)}:{int(ln)}"
                    return None

                if_cache_start = time.perf_counter_ns()
                if if_branch_cache_skip and if_ids:
                    hit_ids = []
                    for x in if_ids:
                        k = _if_key(int(x))
                        if k and k in cached_if_keys:
                            hit_ids.append(int(x))
                    if hit_ids:
                        if logger is not None:
                            logger.info("if_cache_skip", seq=int(min(seqs)), if_ids=hit_ids)
                        entry["if_cache_us"] = int((time.perf_counter_ns() - if_cache_start) / 1000)
                        continue
                entry["if_cache_us"] = int((time.perf_counter_ns() - if_cache_start) / 1000)

                skip_due_to_if = False
                if if_ids:
                    if_cov_start = time.perf_counter_ns()
                    miss_ids = []
                    covered_map: Dict[int, bool] = {}
                    for if_id in if_ids:
                        if int(if_id) in if_cov_cache:
                            covered_map[int(if_id)] = bool(if_cov_cache[int(if_id)])
                            if_cached_hit_count += 1
                        else:
                            covered = check_if_branch_coverage(int(if_id))
                            if_cov_cache[int(if_id)] = bool(covered)
                            covered_map[int(if_id)] = bool(covered)
                            miss_ids.append(int(if_id))
                    entry["if_coverage_us"] = int((time.perf_counter_ns() - if_cov_start) / 1000)
                    if miss_ids and logger is not None:
                        logger.info("if_coverage_check_start", seq=int(min(seqs)), if_ids=[int(x) for x in miss_ids])
                    all_covered = True
                    for if_id in if_ids:
                        covered = covered_map.get(int(if_id))
                        if miss_ids and logger is not None and int(if_id) in miss_ids:
                            logger.info("if_coverage_check_item", seq=int(min(seqs)), if_id=int(if_id), covered=bool(covered))
                        if not bool(covered):
                            all_covered = False
                    if all_covered:
                        skip_due_to_if = True
                        if miss_ids and logger is not None:
                            logger.info("if_coverage_skip", seq=int(min(seqs)), if_ids=[int(x) for x in if_ids])
                        if_cached_skip_count += 1
                    if not miss_ids:
                        if_cached_seq_count += 1
                        if_cached_last_seq = int(min(seqs))
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
                    switch_cov_start = time.perf_counter_ns()
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
                    entry["switch_coverage_us"] = int((time.perf_counter_ns() - switch_cov_start) / 1000)
                    if miss_switch_ids and logger is not None:
                        logger.info("switch_coverage_check_start", seq=int(min(seqs)), switch_ids=[int(x) for x in miss_switch_ids])
                    all_switch_covered = True
                    for switch_id in switch_ids:
                        cov_map = cov_map_by_id.get(int(switch_id)) or {}
                        covered_all = bool(cov_map) and all(bool(v) for v in cov_map.values())
                        if miss_switch_ids and logger is not None and int(switch_id) in miss_switch_ids:
                            logger.info(
                                "switch_coverage_check_item",
                                seq=int(min(seqs)),
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
                            logger.info("switch_coverage_skip", seq=int(min(seqs)), switch_ids=[int(x) for x in switch_ids])
                    if not miss_switch_ids:
                        switch_cached_seq_count += 1
                        switch_cached_last_seq = int(min(seqs))
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

                indices["timing_logger"] = logger
                indices["timing_threshold_us"] = 1_000_000
                indices["timing_meta"] = {"index": rec.get("index"), "path": rec_path, "line": rec_line}
                indices["fast_scope_expand"] = True
                expand_if_start = time.perf_counter_ns()
                seq_i, rel_seqs = _expand_one_seq(
                    seq=int(min(seqs)),
                    rel_seqs=[int(min(seqs))],
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
                entry["expand_if_us"] = int((time.perf_counter_ns() - expand_if_start) / 1000)
                if seq_i is not None:
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
                    yield {"kind": "if", "seq": int(seq_i), "lines": lines, "sig": sig, "scope_seqs": list(rel_seqs or [])}

            if pattern_sql or sql_hits:
                call_ids = []
                for h in sql_hits or []:
                    try:
                        call_ids.append(int(h.get("id")))
                    except Exception:
                        continue
                expand_sql_start = time.perf_counter_ns()
                seq_i, rel_seqs = _expand_one_sql_seq(
                    seq=int(min(seqs)),
                    rel_seqs=[int(min(seqs))],
                    trace_index_records=trace_index_records,
                    nodes=nodes,
                    parent_of=parent_of,
                    children_of=children_of,
                    trace_path=trace_path,
                    scope_root=scope_root,
                    windows_root=windows_root,
                    nearest_seq_count=nearest_seq_count,
                    farthest_seq_count=farthest_seq_count,
                    indices=indices,
                    call_ids=call_ids,
                    record=rec,
                )
                entry["expand_sql_us"] = int((time.perf_counter_ns() - expand_sql_start) / 1000)
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
                yield {"kind": "sql", "seq": int(seq_i), "lines": lines, "sig": sig, "scope_seqs": list(rel_seqs or [])}
            if cmd_hits:
                call_ids = []
                for h in cmd_hits or []:
                    try:
                        call_ids.append(int(h.get("id")))
                    except Exception:
                        continue
                expand_cmd_start = time.perf_counter_ns()
                seq_i, rel_seqs = _expand_one_cmd_seq(
                    seq=int(min(seqs)),
                    rel_seqs=[int(min(seqs))],
                    trace_index_records=trace_index_records,
                    nodes=nodes,
                    parent_of=parent_of,
                    children_of=children_of,
                    trace_path=trace_path,
                    scope_root=scope_root,
                    windows_root=windows_root,
                    nearest_seq_count=nearest_seq_count,
                    farthest_seq_count=farthest_seq_count,
                    indices=indices,
                    call_ids=call_ids,
                    record=rec,
                    logger=logger,
                )
                entry["expand_cmd_us"] = int((time.perf_counter_ns() - expand_cmd_start) / 1000)
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
                yield {"kind": "cmd", "seq": int(seq_i), "lines": lines, "sig": sig, "scope_seqs": list(rel_seqs or [])}
            entry["loop_us"] = int((time.perf_counter_ns() - loop_start) / 1000)
            if logger is not None and entry["loop_us"] >= 1_000_000:
                logger.info(
                    "dual_detect_slow_record",
                    index=entry.get("index"),
                    seq=int(entry.get("min_seq") or 0),
                    loop_us=int(entry.get("loop_us") or 0),
                    ast_us=int(entry.get("ast_us") or 0),
                    pattern_us=int(entry.get("pattern_us") or 0),
                    if_cov_us=int(entry.get("if_coverage_us") or 0),
                    switch_cov_us=int(entry.get("switch_coverage_us") or 0),
                    expand_if_us=int(entry.get("expand_if_us") or 0),
                    expand_sql_us=int(entry.get("expand_sql_us") or 0),
                    expand_cmd_us=int(entry.get("expand_cmd_us") or 0),
                )
            tf.write(json.dumps(entry, ensure_ascii=False) + "\n")
            tf.flush()

    if logger is not None:
        logger.info("section_iter_done", processed=seen_records)
