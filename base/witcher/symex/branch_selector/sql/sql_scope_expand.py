import os
import sys
from typing import Dict, Iterable, List, Optional, Set, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger
from branch_selector.trace.trace_extract import build_loc_for_seq, build_seq_to_index, _path_is_filtered
from branch_selector.trace.if_scope_expand import (
    _ALLOWED_TYPES,
    _build_ctx_for_seq,
    _collect_scope_locs,
    _loc_key,
    _match_scope_nodes,
    _precompute_expand_indices,
    _select_near_far,
    _split_var_parts,
    _taint_name,
)
from branch_selector.sql.sql_query_detector import find_sql_query_calls_in_record
from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
from taint_handlers.llm.core.llm_response import _node_source_str_with_this


def _collect_sql_taints(call_ids: Iterable[int], nodes: dict, children_of: Dict[int, List[int]], seq: int) -> List[dict]:
    out = []
    seen = set()
    for cid in call_ids or []:
        try:
            root_id = int(cid)
        except Exception:
            continue
        stack = [root_id]
        while stack:
            nid = stack.pop()
            if nid in seen:
                continue
            seen.add(nid)
            nx = nodes.get(nid) or {}
            tt = (nx.get("type") or "").strip()
            if tt in _ALLOWED_TYPES:
                nm = _node_source_str_with_this(int(nid), tt, nodes, children_of, "")
                if nm:
                    out.append({"id": int(nid), "type": tt, "seq": int(seq), "name": nm})
            for c in children_of.get(int(nid), []) or []:
                try:
                    stack.append(int(c))
                except Exception:
                    continue
    return out


def _expand_one_sql_seq(
    *,
    seq: int,
    rel_seqs: Optional[List[int]],
    trace_index_records: List[dict],
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    trace_path: str,
    scope_root: str,
    windows_root: str,
    nearest_seq_count: int,
    farthest_seq_count: int,
    indices: dict,
    call_ids: List[int],
    record: dict,
) -> Tuple[Optional[int], Optional[List[int]]]:
    try:
        seq_i = int(seq)
    except Exception:
        return None, None
    if not call_ids:
        return seq_i, list(rel_seqs or []) or [seq_i]
    seq_to_index = indices.get("seq_to_index") or {}
    loc_to_records = indices.get("loc_to_records") or {}
    loc_to_min_seq = indices.get("loc_to_min_seq") or {}
    loc_to_seqs = indices.get("loc_to_seqs") or {}
    node_to_min_seq = indices.get("node_to_min_seq") or {}
    funcid_to_path = indices.get("funcid_to_path") or {}
    st = {
        "path": record.get("path"),
        "line": record.get("line"),
        "targets": list(call_ids),
        "result": {},
    }
    base_ctx = _build_ctx_for_seq(
        seq=seq_i,
        st=st,
        nodes=nodes,
        parent_of=parent_of,
        children_of=children_of,
        trace_index_records=trace_index_records,
        seq_to_index=seq_to_index,
        scope_root=scope_root,
        windows_root=windows_root,
    )
    seq_set = {seq_i}
    extra_scope_locs = []
    extra_scope_seqs = set()
    for nid in call_ids:
        try:
            nid_i = int(nid)
        except Exception:
            continue
        funcid = (nodes.get(nid_i) or {}).get("funcid")
        if funcid is None:
            continue
        try:
            funcid_i = int(funcid)
        except Exception:
            continue
        ftype = ((nodes.get(int(funcid_i)) or {}).get("type") or "").strip()
        if ftype not in ("AST_METHOD", "AST_FUNC_DECL"):
            continue
        func_line = (nodes.get(int(funcid_i)) or {}).get("lineno")
        func_path = funcid_to_path.get(int(funcid_i))
        if func_path and func_line is not None:
            func_seq = None
            key = _loc_key(func_path, func_line)
            if key is not None:
                seqs = loc_to_seqs.get(key) or []
                if seqs:
                    func_seq = int(seqs[0])
            if func_seq is None:
                func_seq = node_to_min_seq.get(int(funcid_i))
            loc = {"path": str(func_path), "line": int(func_line)}
            if func_seq is not None:
                loc["seq"] = int(func_seq)
                extra_scope_seqs.add(int(func_seq))
            extra_scope_locs.append(loc)
            break
    if extra_scope_seqs:
        seq_set.update(extra_scope_seqs)
    taints = _collect_sql_taints(call_ids, nodes, children_of, seq_i)
    node_parts_cache: Optional[Dict[int, Set[Tuple[str, str]]]] = {} if len(taints or []) > 1 else None
    for t in taints:
        tt = (t.get("type") or "").strip()
        if tt not in _ALLOWED_TYPES:
            continue
        tn = _taint_name(t)
        target_parts = set(_split_var_parts(tt, tn))
        if not target_parts:
            continue
        scope_locs = _collect_scope_locs(t, base_ctx)
        if extra_scope_locs:
            scope_locs = list(scope_locs or []) + list(extra_scope_locs)
        matches = _match_scope_nodes(
            target_parts=target_parts,
            scope_locs=scope_locs,
            nodes=nodes,
            children_of=children_of,
            loc_to_records=loc_to_records,
            loc_to_min_seq=loc_to_min_seq,
            node_parts_cache=node_parts_cache,
        )
        seq_set.update(matches)
    rest = [x for x in seq_set if x != seq_i]
    picked = _select_near_far(
        rest,
        ref_seq=seq_i,
        near_count=nearest_seq_count,
        far_count=farthest_seq_count,
    )
    return seq_i, sorted({seq_i, *picked})


def iter_sql_sections(
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
) -> Iterable[dict]:
    seq_to_index = build_seq_to_index(trace_index_records)
    indices = _precompute_expand_indices(trace_index_records, nodes)
    limit = int(seq_limit) if seq_limit is not None else None
    seen_records = 0
    non_filtered_seen = 0
    yielded = 0
    yielded_seqs: Set[int] = set()
    for rec in trace_index_records or []:
        if limit is not None and non_filtered_seen >= limit:
            break
        seen_records += 1
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
        if min_seq is None:
            continue
        hits = find_sql_query_calls_in_record(rec, nodes, children_of)
        if not hits:
            continue
        if min_seq in yielded_seqs:
            continue
        yielded_seqs.add(int(min_seq))
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
