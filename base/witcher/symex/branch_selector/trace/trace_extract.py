"""
Trace-index and CPG loading helpers for the branch-selection pipeline.
"""

import os
import sys
import json
from typing import Dict, Iterable, List, Optional, Set, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger
from utils.extractors.if_extract import load_nodes, load_ast_edges, collect_if_ids_for_record, collect_switch_ids_for_record
from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
from utils.trace_utils.trace_edges import build_trace_index_records, save_trace_index_records


def _safe_int(value, default=None):
    try:
        return int(value)
    except Exception:
        return default


def _load_trace_index_cache_payload(trace_index_path: str) -> Tuple[Optional[List[dict]], Dict]:
    if not os.path.exists(trace_index_path):
        return None, {}
    try:
        with open(trace_index_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return None, {}
    if isinstance(obj, dict) and isinstance(obj.get("records"), list):
        meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
        return obj.get("records"), meta
    if isinstance(obj, list):
        return obj, {}
    return None, {}


def ensure_trace_index(
    trace_index_path: str,
    trace_path: str,
    nodes_path: str,
    seq_limit: int,
    seq_start: int = 0,
    logger: Optional[Logger] = None,
) -> List[dict]:
    """Load an existing trace-index JSON file or build and persist it from trace.log and nodes.csv."""
    start_seq = max(0, _safe_int(seq_start, 0) or 0)
    end_seq = _safe_int(seq_limit, None)
    recs, meta = _load_trace_index_cache_payload(trace_index_path)
    if recs is not None:
        cached_start = max(0, _safe_int(meta.get("seq_start"), 0) or 0)
        cached_end = _safe_int(meta.get("seq_limit"), None)
        cached_trace = os.path.basename(str(meta.get("trace_path") or ""))
        cached_nodes = os.path.basename(str(meta.get("nodes_path") or ""))
        if (
            cached_start == start_seq
            and cached_end == end_seq
            and cached_trace == os.path.basename(trace_path)
            and cached_nodes == os.path.basename(nodes_path)
        ):
            if logger is not None:
                logger.info(
                    "trace_index_loaded",
                    path=trace_index_path,
                    records=len(recs),
                    seq_start=start_seq,
                    seq_limit=end_seq,
                )
            return recs
    if logger is not None:
        logger.info(
            "trace_index_build_start",
            trace_path=trace_path,
            nodes_path=nodes_path,
            seq_start=start_seq,
            limit=end_seq,
        )
    recs = build_trace_index_records(trace_path, nodes_path, end_seq, seq_start=start_seq)
    filtered = []
    for r in recs or []:
        if not isinstance(r, dict):
            continue
        p = (r.get("path") or "").replace("\\", "/").strip().lower()
        if p == "enable_cc.php" or p.endswith("/enable_cc.php"):
            continue
        filtered.append(r)
    if filtered and len(filtered) != len(recs or []):
        for i, r in enumerate(filtered):
            try:
                r["index"] = int(i)
            except Exception:
                r["index"] = i
        recs = filtered
    os.makedirs(os.path.dirname(trace_index_path) or ".", exist_ok=True)
    save_trace_index_records(
        trace_index_path,
        recs,
        {
            "trace_path": os.path.basename(trace_path),
            "nodes_path": os.path.basename(nodes_path),
            "seq_start": start_seq,
            "seq_limit": end_seq,
        },
    )
    if logger is not None:
        logger.info("trace_index_build_done", path=trace_index_path, records=len(recs), seq_start=start_seq, seq_limit=end_seq)
    return recs


def build_seq_to_index(trace_index_records: Iterable[dict]) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for rec in trace_index_records or []:
        idx = rec.get("index")
        for s in rec.get("seqs") or []:
            try:
                si = int(s)
            except Exception:
                continue
            if si not in out:
                out[si] = int(idx) if idx is not None else 0
    return out


def _record_for_seq(seq: int, trace_index_records: List[dict], seq_to_index: Dict[int, int]) -> Optional[dict]:
    idx = seq_to_index.get(int(seq))
    if idx is not None and 0 <= idx < len(trace_index_records):
        return trace_index_records[idx]
    for r in trace_index_records:
        if seq in (r.get("seqs") or []):
            return r
    return None


def _path_is_filtered(path: Optional[str]) -> bool:
    if not path:
        return False
    s = str(path).replace("\\", "/").lower()
    needles = (
        "/vendor/",
        "/composer/",
        "/node_modules/",
        "/tests/",
        "/test/",
        "/docs/",
        "/doc/",
        "/examples/",
        "/example/",
        "/demo/",
        "/demos/",
        "/samples/",
        "/sample/",
        "/benchmark/",
        "/benchmarks/",
        "/build/",
        "/dist/",
        "/coverage/",
        "/tmp/",
        "/cache/",
        "/logs/",
        "/log/",
        "/storage/",
    )
    return any(n in s for n in needles)


def collect_if_switch_seqs(
    *,
    trace_index_records: List[dict],
    nodes: dict,
    seq_limit: int,
    logger: Optional[Logger] = None,
) -> Dict[int, List[int]]:
    """Collect candidate seqs that contain IF/SWITCH-related nodes, keyed by each record's min seq."""
    out: Dict[int, List[int]] = {}
    seen_records = 0
    non_filtered_seen = 0
    filtered_records = 0
    limit = int(seq_limit) if seq_limit is not None else None
    for rec in trace_index_records or []:
        if limit is not None and non_filtered_seen >= limit:
            break
        seen_records += 1
        rec_path = rec.get("path")
        if _path_is_filtered(rec_path):
            filtered_records += 1
            if logger is not None:
                logger.debug(
                    "if_switch_path_filtered",
                    path=rec_path,
                    line=rec.get("line"),
                    index=rec.get("index"),
                )
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
        if min_seq is None:
            continue
        node_ids = rec.get("node_ids") or []
        has_if = False
        has_switch = False
        for nid in node_ids:
            try:
                ni = int(nid)
            except Exception:
                continue
            tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
            if tt in ("AST_IF", "AST_IF_ELEM"):
                has_if = True
            elif tt == "AST_SWITCH":
                has_switch = True
            if has_if or has_switch:
                break
        if not (has_if or has_switch):
            continue
        if min_seq not in out:
            out[min_seq] = [min_seq]
    if logger is not None:
        logger.debug(
            "if_switch_path_filter_stats",
            records=seen_records,
            filtered=filtered_records,
            seq_limit=limit,
        )
        logger.info("collect_if_switch_seqs_done", records=seen_records, seqs=len(out))
    return out


def iter_if_switch_records(
    *,
    trace_index_records: List[dict],
    nodes: dict,
    parent_of: dict,
    top_id_to_file: dict,
    seq_limit: int,
    logger: Optional[Logger] = None,
) -> Iterable[Tuple[int, dict]]:
    seen_records = 0
    non_filtered_seen = 0
    filtered_records = 0
    yielded = 0
    yielded_seqs: Set[int] = set()
    limit = int(seq_limit) if seq_limit is not None else None
    for rec in trace_index_records or []:
        if limit is not None and non_filtered_seen >= limit:
            break
        seen_records += 1
        rec_path = rec.get("path")
        if _path_is_filtered(rec_path):
            filtered_records += 1
            if logger is not None:
                logger.debug(
                    "if_switch_path_filtered",
                    path=rec_path,
                    line=rec.get("line"),
                    index=rec.get("index"),
                )
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
        if min_seq is None:
            continue
        node_ids = rec.get("node_ids") or []
        has_if = False
        has_switch = False
        for nid in node_ids:
            try:
                ni = int(nid)
            except Exception:
                continue
            tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
            if tt in ("AST_IF", "AST_IF_ELEM", "AST_ELSEIF"):
                has_if = True
            elif tt == "AST_SWITCH":
                has_switch = True
            if has_if or has_switch:
                break
        if not (has_if or has_switch):
            try:
                if_ids = collect_if_ids_for_record(rec, nodes=nodes, parent_of=parent_of, top_id_to_file=top_id_to_file)
            except Exception:
                if_ids = []
            try:
                switch_ids = collect_switch_ids_for_record(rec, nodes=nodes, parent_of=parent_of, top_id_to_file=top_id_to_file)
            except Exception:
                switch_ids = []
            has_if = bool(if_ids)
            has_switch = bool(switch_ids)
        if not (has_if or has_switch):
            continue
        if min_seq in yielded_seqs:
            continue
        yielded_seqs.add(int(min_seq))
        yielded += 1
        yield int(min_seq), rec
    if logger is not None:
        logger.debug(
            "if_switch_path_filter_stats",
            records=seen_records,
            filtered=filtered_records,
            seq_limit=limit,
        )
        logger.info("collect_if_switch_seqs_done", records=seen_records, seqs=yielded)


def build_loc_for_seq(seq: int, trace_index_records: List[dict], seq_to_index: Dict[int, int]) -> Optional[dict]:
    rec = _record_for_seq(int(seq), trace_index_records, seq_to_index)
    if not isinstance(rec, dict):
        return None
    p = rec.get("path")
    ln = rec.get("line")
    if not p or ln is None:
        return None
    return {"seq": int(seq), "path": p, "line": int(ln), "loc": f"{p}:{int(ln)}"}


def seqs_to_source_groups(
    seq_groups: Dict[int, List[int]],
    *,
    trace_index_records: List[dict],
    seq_to_index: Dict[int, int],
    scope_root: str,
    trace_index_path: str,
    windows_root: str,
) -> List[dict]:
    """Map seq groups to source-line context objects suitable for prompt section formatting."""
    out: List[dict] = []
    for seq, rel_seqs in seq_groups.items():
        locs = []
        for s in rel_seqs or []:
            loc = build_loc_for_seq(int(s), trace_index_records, seq_to_index)
            if loc:
                locs.append(loc)
        lines = map_result_set_to_source_lines(scope_root, locs, trace_index_path=trace_index_path, windows_root=windows_root)
        out.append({"seq": int(seq), "seqs": list(rel_seqs or []), "lines": lines})
    return out


def load_nodes_and_edges(nodes_path: str, rels_path: str):
    nodes, top_id_to_file = load_nodes(nodes_path)
    parent_of, children_of = load_ast_edges(rels_path)
    return nodes, parent_of, children_of, top_id_to_file
