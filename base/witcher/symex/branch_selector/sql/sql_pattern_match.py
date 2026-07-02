import os
import re
import sys
from typing import Dict, List, Optional, Set

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger
from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines, resolve_source_path
from branch_selector.trace.trace_extract import _path_is_filtered, build_loc_for_seq, build_seq_to_index
from branch_selector.sql.sql_query_detector import find_sql_query_calls_in_record
from branch_selector.sql.sql_scope_expand import _expand_one_sql_seq
from branch_selector.trace.if_scope_expand import _precompute_expand_indices


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


_SQL_PATTERNS = [
    re.compile(r"\bselect\b.*\bfrom\b", re.IGNORECASE),
    re.compile(r"\binsert\b.*\binto\b", re.IGNORECASE),
    re.compile(r"\bupdate\b.*\bset\b", re.IGNORECASE),
    re.compile(r"\bdelete\b.*\bfrom\b", re.IGNORECASE),
    re.compile(r"\breplace\b.*\binto\b", re.IGNORECASE),
]


def _strip_inline_comment(line: str) -> str:
    if not isinstance(line, str):
        return ""
    s = line
    for sep in ("//", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    return s


def is_sql_line(code: str) -> bool:
    s = _strip_inline_comment(code or "").strip()
    if not s:
        return False
    for pat in _SQL_PATTERNS:
        if pat.search(s):
            return True
    return False


def iter_sql_sections_pattern(
    *,
    trace_index_records: List[dict],
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    seq_limit: int,
    scope_root: str,
    trace_index_path: str,
    windows_root: str,
    nearest_seq_count: int,
    farthest_seq_count: int,
    trace_path: str,
    logger: Optional[Logger] = None,
):
    seq_to_index = build_seq_to_index(trace_index_records)
    indices = _precompute_expand_indices(trace_index_records, nodes)
    reader = SourceLineCache(scope_root, windows_root)
    limit = int(seq_limit) if seq_limit is not None else None
    seen_records = 0
    non_filtered_seen = 0
    yielded = 0
    yielded_seqs: Set[int] = set()
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
        code = reader.get_line(rec.get("path"), rec.get("line"))
        if not is_sql_line(code):
            continue
        min_seq = min(seqs)
        if min_seq in yielded_seqs:
            continue
        yielded_seqs.add(int(min_seq))
        hits = find_sql_query_calls_in_record(rec, nodes, children_of)
        call_ids = []
        for h in hits:
            try:
                call_ids.append(int(h.get("id")))
            except Exception:
                continue
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
        yielded += 1
        yield {"seq": int(seq_i), "lines": lines, "sig": sig, "scope_seqs": list(rel_seqs or [])}
    if logger is not None:
        logger.info("collect_sql_seqs_done", records=seen_records, seqs=yielded)
