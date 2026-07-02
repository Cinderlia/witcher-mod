"""
Infer whether an IF statement took the true or false branch based on trace index records.
"""

try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from utils.cpg_utils.trace_index import load_trace_index_records as _load_trace_index_records

@dataclass(frozen=True)
class IfDirection:
    if_seq: int
    if_id: int
    if_path: str
    if_line: Optional[int]
    max_seq_in_if_record: Optional[int]
    next_seq: Optional[int]
    next_path: Optional[str]
    next_line: Optional[int]
    direction: str


def _safe_int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None


def load_trace_index_records(trace_index_path: str) -> List[dict]:
    recs = _load_trace_index_records(trace_index_path)
    return recs if isinstance(recs, list) else []


def build_seq_to_record(trace_index_records: Iterable[dict]) -> Dict[int, dict]:
    out: Dict[int, dict] = {}
    for r in trace_index_records or []:
        if not isinstance(r, dict):
            continue
        for s in r.get("seqs") or []:
            si = _safe_int(s)
            if si is None:
                continue
            if si not in out:
                out[si] = r
    return out


def _sorted_child_ids(parent_id: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> List[int]:
    ch = list(children_of.get(int(parent_id), []) or [])
    ch.sort(
        key=lambda cid: (
            _safe_int((nodes.get(int(cid)) or {}).get("childnum")) if _safe_int((nodes.get(int(cid)) or {}).get("childnum")) is not None else 10**9
        )
    )
    return [int(x) for x in ch if _safe_int(x) is not None]


def find_if_node_ids_in_record(record: dict, nodes: Dict[int, dict]) -> List[int]:
    if not isinstance(record, dict):
        return []
    out: List[int] = []
    for nid in record.get("node_ids") or []:
        ni = _safe_int(nid)
        if ni is None:
            continue
        tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
        if tt == "AST_IF":
            out.append(int(ni))
    return out


def get_if_elems(if_id: int, *, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> List[int]:
    out = []
    for cid in _sorted_child_ids(if_id, children_of, nodes):
        tt = ((nodes.get(int(cid)) or {}).get("type") or "").strip()
        if tt == "AST_IF_ELEM":
            out.append(int(cid))
    return out


def get_stmt_list_id(if_elem_id: int, *, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Optional[int]:
    for cid in _sorted_child_ids(if_elem_id, children_of, nodes):
        tt = ((nodes.get(int(cid)) or {}).get("type") or "").strip()
        if tt == "AST_STMT_LIST":
            return int(cid)
    return None


def collect_stmt_list_lines(stmt_list_id: int, *, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Set[int]:
    out: Set[int] = set()
    q = [int(stmt_list_id)]
    seen: Set[int] = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if int(x) != int(stmt_list_id):
            ln = _safe_int((nodes.get(int(x)) or {}).get("lineno"))
            if ln is not None and ln > 0:
                out.add(int(ln))
        for c in children_of.get(int(x), []) or []:
            ci = _safe_int(c)
            if ci is not None:
                q.append(int(ci))
    return out


def infer_if_direction(
    *,
    if_seq: int,
    if_id: int,
    if_record: dict,
    seq_to_record: Dict[int, dict],
    nodes: Dict[int, dict],
    children_of: Dict[int, List[int]],
) -> IfDirection:
    """Determine branch direction by checking the next trace location against IF-true stmt lines."""
    if_path = (if_record.get("path") or "").strip()
    if_line = _safe_int(if_record.get("line"))
    seqs = [x for x in (if_record.get("seqs") or []) if _safe_int(x) is not None]
    max_seq = max((_safe_int(x) for x in seqs), default=None)
    next_seq = (int(max_seq) + 1) if max_seq is not None else None
    next_rec = seq_to_record.get(int(next_seq)) if next_seq is not None else None
    next_path = (next_rec.get("path") or "").strip() if isinstance(next_rec, dict) else None
    next_line = _safe_int(next_rec.get("line")) if isinstance(next_rec, dict) else None

    direction = "unknown"
    if_elems = get_if_elems(if_id, nodes=nodes, children_of=children_of)
    true_locs: Set[Tuple[str, int]] = set()
    no_stmt_list = False
    if if_elems:
        stmt_list = get_stmt_list_id(int(if_elems[0]), nodes=nodes, children_of=children_of)
        if stmt_list is not None:
            for ln in collect_stmt_list_lines(int(stmt_list), nodes=nodes, children_of=children_of):
                true_locs.add((if_path, int(ln)))
        else:
            no_stmt_list = True

    if next_seq is not None and next_path is not None and next_line is not None:
        if (next_path, int(next_line)) in true_locs:
            direction = "true"
        else:
            direction = "false"

    return IfDirection(
        if_seq=int(if_seq),
        if_id=int(if_id),
        if_path=if_path,
        if_line=if_line,
        max_seq_in_if_record=int(max_seq) if max_seq is not None else None,
        next_seq=int(next_seq) if next_seq is not None else None,
        next_path=next_path,
        next_line=next_line,
        direction=direction,
    )


def infer_if_directions_for_seqs(
    seqs: Iterable[int],
    *,
    trace_index_records: List[dict],
    nodes: Dict[int, dict],
    children_of: Dict[int, List[int]],
) -> List[IfDirection]:
    """Compute IfDirection entries for each candidate seq that maps to an IF record."""
    seq_set = {int(s) for s in (seqs or []) if _safe_int(s) is not None}
    trace_records = trace_index_records if isinstance(trace_index_records, list) else list(trace_index_records or [])
    if not seq_set:
        return []
    seq_to_record = build_seq_to_record(trace_records)

    out: List[IfDirection] = []
    seen: Set[Tuple[int, int]] = set()
    for s in sorted(seq_set):
        rec = seq_to_record.get(int(s))
        if not isinstance(rec, dict):
            continue
        if_ids = find_if_node_ids_in_record(rec, nodes)
        for if_id in if_ids:
            k = (int(s), int(if_id))
            if k in seen:
                continue
            seen.add(k)
            out.append(
                infer_if_direction(
                    if_seq=int(s),
                    if_id=int(if_id),
                    if_record=rec,
                    seq_to_record=seq_to_record,
                    nodes=nodes,
                    children_of=children_of,
                )
            )
    return out
