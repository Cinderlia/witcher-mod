import os
import re
import sys
import json
import time
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger
from branch_selector.trace.trace_extract import _path_is_filtered, build_loc_for_seq, build_seq_to_index
from branch_selector.trace.if_scope_expand import _expand_one_seq, _precompute_expand_indices
from branch_selector.sql.sql_query_detector import find_sql_query_calls_in_record
from branch_selector.sql.sql_scope_expand import _expand_one_sql_seq
from branch_selector.xss.xss_output_detector import find_xss_output_calls_in_record
from branch_selector.xss.xss_scope_expand import _expand_one_xss_seq
from branch_selector.cmd.cmd_query_detector import find_cmd_calls_in_record
from branch_selector.cmd.cmd_scope_expand import _expand_one_cmd_seq
from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
from if_branch_coverage import check_if_branch_coverage
from if_branch_coverage.switch_coverage import check_switch_branch_coverage
from if_branch_coverage.if_scope import get_if_file_path
from utils.extractors.if_extract import collect_if_ids_for_record, collect_switch_ids_for_record
from utils.cpg_utils.graph_mapping import norm_nodes_path, safe_int
from branch_selector.trace.if_pattern_match import SourceLineCache, is_if_line, is_switch_line
from branch_selector.sql.sql_pattern_match import is_sql_line
from branch_selector.xss.xss_pattern_match import is_xss_line
from branch_selector.cmd.cmd_pattern_match import is_cmd_line


def _collect_if_ids_in_record(record: dict, nodes: Dict, parent_of: Dict[int, int], top_id_to_file: Dict) -> List[int]:
    out: Set[int] = set()
    for nid in (record or {}).get("node_ids") or []:
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


def _collect_switch_ids_in_record(record: dict, nodes: Dict, parent_of: Dict[int, int], top_id_to_file: Dict) -> List[int]:
    out: Set[int] = set()
    for nid in (record or {}).get("node_ids") or []:
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


def _build_sig(lines: List[dict]) -> Optional[Tuple[str, ...]]:
    sig_items: List[str] = []
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
    return tuple(sig_items) if sig_items else None


def _strip_inline_comment(line: str) -> str:
    if not isinstance(line, str):
        return ""
    s = line
    for sep in ("//", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    return s


_IF_SWITCH_HINT_RE = re.compile(r"\bif\s*\(|\belseif\b|\bswitch\s*\(", re.IGNORECASE)
_SQL_HINT_RE = re.compile(r"\b(select|insert|update|delete|replace)\b", re.IGNORECASE)
_XSS_HINT_RE = re.compile(r"\b(echo|print)\b|\bprintf\s*\(", re.IGNORECASE)
_CMD_HINT_RE = re.compile(r"`|\b(system|exec|shell_exec|passthru|popen|proc_open|eval)\s*\(", re.IGNORECASE)


def _fast_any_kind_match(code: str) -> Dict[str, bool]:
    s = _strip_inline_comment(code or "").strip()
    if not s:
        return {"if": False, "sql": False, "xss": False, "cmd": False}
    return {
        "if": bool(_IF_SWITCH_HINT_RE.search(s)),
        "sql": bool(_SQL_HINT_RE.search(s)),
        "xss": bool(_XSS_HINT_RE.search(s)),
        "cmd": bool(_CMD_HINT_RE.search(s)),
    }


def iter_combined_sections(
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
    enable_if: bool = True,
    enable_switch: bool = True,
    enable_sql: bool = True,
    enable_xss: bool = True,
    enable_cmd: bool = True,
    if_branch_cache_path: Optional[str] = None,
    if_branch_cache_skip: bool = False,
    progress_cb: Optional[Callable[..., None]] = None,
    logger: Optional[Logger] = None,
) -> Iterable[Tuple[str, dict]]:
    seq_to_index = build_seq_to_index(trace_index_records)
    cached_if_keys = _load_if_branch_cache_ids(if_branch_cache_path) if if_branch_cache_skip else set()
    if_cov_cache: Dict[int, bool] = {}
    if_cached_hit_count = 0
    switch_cov_cache: Dict[int, Dict[int, bool]] = {}
    indices = _precompute_expand_indices(trace_index_records, nodes)
    limit = int(seq_limit) if seq_limit is not None else None
    non_filtered_seen = 0
    yielded_if: Set[int] = set()
    yielded_sql: Set[int] = set()
    yielded_xss: Set[int] = set()
    yielded_cmd: Set[int] = set()
    reader = SourceLineCache(scope_root, windows_root)
    if logger is not None:
        logger.info("section_iter_start")
        logger.info(
            "section_iter_config",
            enable_if=bool(enable_if),
            enable_switch=bool(enable_switch),
            enable_sql=bool(enable_sql),
            enable_xss=bool(enable_xss),
            enable_cmd=bool(enable_cmd),
            if_branch_cache_skip=bool(if_branch_cache_skip),
        )
    started_at = time.monotonic()
    last_progress = started_at
    processed = 0
    for rec in trace_index_records or []:
        if limit is not None and non_filtered_seen >= limit:
            break
        processed += 1
        now = time.monotonic()
        if logger is not None and (now - last_progress) >= 5.0:
            logger.info(
                "section_iter_progress",
                processed=int(processed),
                non_filtered_seen=int(non_filtered_seen),
                if_seqs=len(yielded_if),
                sql_seqs=len(yielded_sql),
                xss_seqs=len(yielded_xss),
                cmd_seqs=len(yielded_cmd),
            )
            last_progress = now
        rec_path = rec.get("path")
        if _path_is_filtered(rec_path):
            continue
        min_seq = None
        for s in rec.get("seqs") or []:
            if limit is not None and non_filtered_seen >= limit:
                break
            try:
                si = int(s)
            except Exception:
                continue
            non_filtered_seen += 1
            if min_seq is None or int(si) < int(min_seq):
                min_seq = int(si)
        if progress_cb is not None:
            try:
                progress_cb(
                    processed=int(processed),
                    non_filtered_seen=int(non_filtered_seen),
                    min_seq=(int(min_seq) if min_seq is not None else None),
                )
            except Exception:
                pass
        if min_seq is None:
            continue
        # if_ids = _collect_if_ids_in_record(rec, nodes, parent_of, top_id_to_file) if enable_if else []
        # switch_ids = _collect_switch_ids_in_record(rec, nodes, parent_of, top_id_to_file) if enable_switch else []
        # sql_hits = find_sql_query_calls_in_record(rec, nodes, children_of) if enable_sql else []
        # xss_hits = find_xss_output_calls_in_record(rec, nodes, children_of) if enable_xss else []
        # cmd_hits = find_cmd_calls_in_record(rec, nodes, children_of) if enable_cmd else []

        code = reader.get_line(rec.get("path"), rec.get("line"))
        fast = _fast_any_kind_match(code)
        want_if = bool(enable_if and fast.get("if") and is_if_line(code))
        want_switch = bool(enable_switch and fast.get("if") and is_switch_line(code))
        want_sql = bool(enable_sql and fast.get("sql") and is_sql_line(code))
        want_xss = bool(enable_xss and fast.get("xss") and is_xss_line(code))
        want_cmd = bool(enable_cmd and fast.get("cmd") and is_cmd_line(code))

        if not (want_if or want_switch or want_sql or want_xss or want_cmd):
            continue

        if (want_if or want_switch) and min_seq not in yielded_if and (enable_if or enable_switch):
            if_ids = collect_if_ids_for_record(rec, nodes=nodes, parent_of=parent_of, top_id_to_file=top_id_to_file) if want_if else []
            switch_ids = collect_switch_ids_for_record(rec, nodes=nodes, parent_of=parent_of, top_id_to_file=top_id_to_file) if want_switch else []
            skip_due_to_if = False
            skip_due_to_switch = False
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
                    skip_due_to_if = True

            if if_ids and not skip_due_to_if:
                covered_map: Dict[int, bool] = {}
                miss_ids = []
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
                all_covered = True
                for if_id in if_ids:
                    covered = covered_map.get(int(if_id))
                    if not bool(covered):
                        all_covered = False
                if all_covered:
                    skip_due_to_if = True
                    if miss_ids and logger is not None:
                        logger.info("if_coverage_skip", seq=int(min_seq), if_ids=[int(x) for x in if_ids])

            if switch_ids and not skip_due_to_switch:
                cov_map_by_id: Dict[int, Dict[int, bool]] = {}
                for switch_id in switch_ids:
                    if int(switch_id) in switch_cov_cache:
                        cov_map_by_id[int(switch_id)] = switch_cov_cache[int(switch_id)]
                    else:
                        cov_map = check_switch_branch_coverage(int(switch_id))
                        switch_cov_cache[int(switch_id)] = cov_map
                        cov_map_by_id[int(switch_id)] = cov_map
                all_switch_covered = True
                for switch_id in switch_ids:
                    cov_map = cov_map_by_id.get(int(switch_id)) or {}
                    covered_all = bool(cov_map) and all(bool(v) for v in cov_map.values())
                    if not covered_all:
                        all_switch_covered = False
                if all_switch_covered:
                    skip_due_to_switch = True
                    if logger is not None:
                        logger.info("switch_coverage_skip", seq=int(min_seq), switch_ids=[int(x) for x in switch_ids])

            if not ((if_ids and skip_due_to_if and (not switch_ids or skip_due_to_switch)) or (switch_ids and skip_due_to_switch and not if_ids)):
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
                if seq_i is not None:
                    rel2 = []
                    seen = set()
                    for x in [int(min_seq)] + [int(s) for s in (rel_seqs or [])]:
                        if x in seen:
                            continue
                        seen.add(x)
                        rel2.append(int(x))
                    locs = []
                    for s in rel2:
                        loc = build_loc_for_seq(int(s), trace_index_records, seq_to_index)
                        if loc:
                            locs.append(loc)
                    lines = map_result_set_to_source_lines(scope_root, locs, trace_index_path=trace_index_path, windows_root=windows_root)
                    sig = _build_sig(lines)
                    yielded_if.add(int(min_seq))
                    if_path = norm_nodes_path(str(rec.get("path") or "")) if rec.get("path") else ""
                    if_line = safe_int(rec.get("line"))
                    yield "if", {
                        "seq": int(seq_i),
                        "lines": lines,
                        "sig": sig,
                        "scope_seqs": list(rel2 or []),
                        "mark_seqs": [int(min_seq)],
                        "if_path": if_path,
                        "if_line": int(if_line) if if_line is not None else None,
                    }

        if want_sql and min_seq not in yielded_sql and enable_sql:
            call_ids: List[int] = []
            seq_i, rel_seqs = _expand_one_sql_seq(
                seq=int(min_seq),
                rel_seqs=[int(min_seq)],
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
            if seq_i is not None:
                rel2 = []
                seen = set()
                for x in [int(min_seq)] + [int(s) for s in (rel_seqs or [])]:
                    if x in seen:
                        continue
                    seen.add(x)
                    rel2.append(int(x))
                locs = []
                for s in rel2:
                    loc = build_loc_for_seq(int(s), trace_index_records, seq_to_index)
                    if loc:
                        locs.append(loc)
                lines = map_result_set_to_source_lines(scope_root, locs, trace_index_path=trace_index_path, windows_root=windows_root)
                sig = _build_sig(lines)
                yielded_sql.add(int(min_seq))
                if logger is not None:
                    logger.info("sql_output_detected", seq=int(min_seq), hits=1)
                yield "sql", {"seq": int(seq_i), "lines": lines, "sig": sig, "scope_seqs": list(rel2 or []), "mark_seqs": [int(min_seq)]}

        if want_xss and min_seq not in yielded_xss and enable_xss:
            call_ids: List[int] = []
            seq_i, rel_seqs = _expand_one_xss_seq(
                seq=int(min_seq),
                rel_seqs=[int(min_seq)],
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
            if seq_i is not None:
                rel2 = []
                seen = set()
                for x in [int(min_seq)] + [int(s) for s in (rel_seqs or [])]:
                    if x in seen:
                        continue
                    seen.add(x)
                    rel2.append(int(x))
                locs = []
                for s in rel2:
                    loc = build_loc_for_seq(int(s), trace_index_records, seq_to_index)
                    if loc:
                        locs.append(loc)
                lines = map_result_set_to_source_lines(scope_root, locs, trace_index_path=trace_index_path, windows_root=windows_root)
                sig = _build_sig(lines)
                yielded_xss.add(int(min_seq))
                if logger is not None:
                    logger.info("xss_output_detected", seq=int(min_seq), hits=1)
                yield "xss", {"seq": int(seq_i), "lines": lines, "sig": sig, "scope_seqs": list(rel2 or []), "mark_seqs": [int(min_seq)]}

        if want_cmd and min_seq not in yielded_cmd and enable_cmd:
            call_ids: List[int] = []
            seq_i, rel_seqs = _expand_one_cmd_seq(
                seq=int(min_seq),
                rel_seqs=[int(min_seq)],
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
            if seq_i is not None:
                rel2 = []
                seen = set()
                for x in [int(min_seq)] + [int(s) for s in (rel_seqs or [])]:
                    if x in seen:
                        continue
                    seen.add(x)
                    rel2.append(int(x))
                locs = []
                for s in rel2:
                    loc = build_loc_for_seq(int(s), trace_index_records, seq_to_index)
                    if loc:
                        locs.append(loc)
                lines = map_result_set_to_source_lines(scope_root, locs, trace_index_path=trace_index_path, windows_root=windows_root)
                sig = _build_sig(lines)
                yielded_cmd.add(int(min_seq))
                if logger is not None:
                    logger.info("cmd_output_detected", seq=int(min_seq), hits=1)
                yield "cmd", {"seq": int(seq_i), "lines": lines, "sig": sig, "scope_seqs": list(rel2 or []), "mark_seqs": [int(min_seq)]}

    if logger is not None:
        logger.info(
            "section_iter_done",
            if_seqs=len(yielded_if),
            sql_seqs=len(yielded_sql),
            xss_seqs=len(yielded_xss),
            cmd_seqs=len(yielded_cmd),
        )
