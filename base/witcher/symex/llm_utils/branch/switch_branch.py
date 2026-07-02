"""
Infer which SWITCH case executed based on trace index records and AST_SWITCH_CASE statement lines.
"""

try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class SwitchChoice:
    switch_seq: int
    switch_id: int
    switch_path: str
    switch_line: Optional[int]
    max_seq_in_switch_record: Optional[int]
    next_seq: Optional[int]
    next_path: Optional[str]
    next_line: Optional[int]
    case_id: Optional[int]
    case_line: Optional[int]
    case_label: str


def _safe_int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None


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
                out[int(si)] = r
    return out


def _sorted_child_ids(parent_id: int, children_of: Dict[int, List[int]], nodes: Dict[int, dict]) -> List[int]:
    ch = list(children_of.get(int(parent_id), []) or [])
    ch.sort(
        key=lambda cid: (
            _safe_int((nodes.get(int(cid)) or {}).get("childnum")) if _safe_int((nodes.get(int(cid)) or {}).get("childnum")) is not None else 10**9
        )
    )
    return [int(x) for x in ch if _safe_int(x) is not None]


def find_switch_node_ids_in_record(record: dict, nodes: Dict[int, dict]) -> List[int]:
    if not isinstance(record, dict):
        return []
    out: List[int] = []
    for nid in record.get("node_ids") or []:
        ni = _safe_int(nid)
        if ni is None:
            continue
        tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
        if tt == "AST_SWITCH":
            out.append(int(ni))
    return out


def get_switch_list_id(switch_id: int, *, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Optional[int]:
    for cid in _sorted_child_ids(int(switch_id), children_of, nodes):
        tt = ((nodes.get(int(cid)) or {}).get("type") or "").strip()
        if tt == "AST_SWITCH_LIST":
            return int(cid)
    return None


def get_switch_case_ids(switch_id: int, *, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> List[int]:
    out: List[int] = []
    switch_list_id = get_switch_list_id(int(switch_id), nodes=nodes, children_of=children_of)
    if switch_list_id is None:
        return out
    for cid in _sorted_child_ids(int(switch_list_id), children_of, nodes):
        tt = ((nodes.get(int(cid)) or {}).get("type") or "").strip()
        if tt == "AST_SWITCH_CASE":
            out.append(int(cid))
    return out


def get_switch_case_line(case_id: int, nodes: Dict[int, dict]) -> Optional[int]:
    return _safe_int((nodes.get(int(case_id)) or {}).get("lineno"))


def get_case_expr_id(case_id: int, *, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Optional[int]:
    ch = _sorted_child_ids(int(case_id), children_of, nodes)
    if not ch:
        return None
    return int(ch[0])


def get_case_stmt_list_id(case_id: int, *, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Optional[int]:
    for cid in _sorted_child_ids(int(case_id), children_of, nodes):
        tt = ((nodes.get(int(cid)) or {}).get("type") or "").strip()
        if tt == "AST_STMT_LIST":
            return int(cid)
    return None


def _collect_string_descendants(root_id: int, *, nodes: Dict[int, dict], children_of: Dict[int, List[int]], max_depth: int = 12) -> List[str]:
    out: List[str] = []
    q: List[Tuple[int, int]] = [(int(root_id), 0)]
    seen: Set[int] = set()
    while q:
        nid, depth = q.pop()
        if nid in seen:
            continue
        seen.add(int(nid))
        nx = nodes.get(int(nid)) or {}
        tt = (nx.get("type") or "").strip()
        lab = (nx.get("labels") or "").strip()
        if (tt == "string") or (lab == "string"):
            v = (nx.get("code") or nx.get("name") or "").strip()
            if v:
                out.append(v)
        if depth >= int(max_depth):
            continue
        for c in children_of.get(int(nid), []) or []:
            ci = _safe_int(c)
            if ci is not None:
                q.append((int(ci), depth + 1))
    return out


def _case_label_from_expr(expr_id: Optional[int], *, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> str:
    if expr_id is None:
        return ""
    nx = nodes.get(int(expr_id)) or {}
    tt = (nx.get("type") or "").strip()
    if tt == "NULL":
        return "default"
    if tt in ("integer", "double"):
        v = (nx.get("code") or nx.get("name"))
        return str(v).strip() if v is not None else ""
    lab = (nx.get("labels") or "").strip()
    if tt == "string" or lab == "string":
        v = (nx.get("code") or nx.get("name") or "").strip()
        return v
    ss = _collect_string_descendants(int(expr_id), nodes=nodes, children_of=children_of)
    if ss:
        return (ss[0] or "").strip()
    v2 = (nx.get("code") or nx.get("name") or "").strip()
    return v2


def collect_stmt_list_lines(stmt_list_id: int, *, nodes: Dict[int, dict], children_of: Dict[int, List[int]]) -> Set[int]:
    out: Set[int] = set()
    q = [int(stmt_list_id)]
    seen: Set[int] = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(int(x))
        ln = _safe_int((nodes.get(int(x)) or {}).get("lineno"))
        if ln is not None and ln > 0:
            out.add(int(ln))
        for c in children_of.get(int(x), []) or []:
            ci = _safe_int(c)
            if ci is not None:
                q.append(int(ci))
    return out


def infer_switch_choice(
    *,
    switch_seq: int,
    switch_id: int,
    switch_record: dict,
    seq_to_record: Dict[int, dict],
    nodes: Dict[int, dict],
    children_of: Dict[int, List[int]],
) -> SwitchChoice:
    """Infer the chosen case by matching the next executed location against each case's stmt list."""
    switch_path = (switch_record.get("path") or "").strip()
    switch_line = _safe_int(switch_record.get("line"))
    seqs = [x for x in (switch_record.get("seqs") or []) if _safe_int(x) is not None]
    max_seq = max((_safe_int(x) for x in seqs), default=None)
    next_seq = (int(max_seq) + 1) if max_seq is not None else None
    next_rec = seq_to_record.get(int(next_seq)) if next_seq is not None else None
    next_path = (next_rec.get("path") or "").strip() if isinstance(next_rec, dict) else None
    next_line = _safe_int(next_rec.get("line")) if isinstance(next_rec, dict) else None

    chosen_case_id = None
    chosen_case_line = None
    chosen_case_label = ""
    if next_seq is not None and next_path is not None and next_line is not None:
        for case_id in get_switch_case_ids(int(switch_id), nodes=nodes, children_of=children_of):
            stmt_list_id = get_case_stmt_list_id(int(case_id), nodes=nodes, children_of=children_of)
            if stmt_list_id is None:
                continue
            lines = collect_stmt_list_lines(int(stmt_list_id), nodes=nodes, children_of=children_of)
            if (next_path, int(next_line)) in {(switch_path, int(ln)) for ln in lines}:
                chosen_case_id = int(case_id)
                chosen_case_line = get_switch_case_line(int(case_id), nodes)
                expr_id = get_case_expr_id(int(case_id), nodes=nodes, children_of=children_of)
                chosen_case_label = _case_label_from_expr(expr_id, nodes=nodes, children_of=children_of)
                break

    return SwitchChoice(
        switch_seq=int(switch_seq),
        switch_id=int(switch_id),
        switch_path=switch_path,
        switch_line=switch_line,
        max_seq_in_switch_record=int(max_seq) if max_seq is not None else None,
        next_seq=int(next_seq) if next_seq is not None else None,
        next_path=next_path,
        next_line=next_line,
        case_id=chosen_case_id,
        case_line=chosen_case_line,
        case_label=(chosen_case_label or ("unknown" if chosen_case_id is None else "")),
    )


def infer_switch_choices_for_seqs(
    seqs: Iterable[int],
    *,
    trace_index_records: List[dict],
    nodes: Dict[int, dict],
    children_of: Dict[int, List[int]],
) -> List[SwitchChoice]:
    """Compute SwitchChoice entries for each candidate seq that maps to a SWITCH record."""
    seq_set = {int(s) for s in (seqs or []) if _safe_int(s) is not None}
    if not seq_set:
        return []
    seq_to_record = build_seq_to_record(trace_index_records)

    out: List[SwitchChoice] = []
    seen: Set[Tuple[int, int]] = set()
    for s in sorted(seq_set):
        rec = seq_to_record.get(int(s))
        if not isinstance(rec, dict):
            continue
        for switch_id in find_switch_node_ids_in_record(rec, nodes):
            k = (int(s), int(switch_id))
            if k in seen:
                continue
            seen.add(k)
            out.append(
                infer_switch_choice(
                    switch_seq=int(s),
                    switch_id=int(switch_id),
                    switch_record=rec,
                    seq_to_record=seq_to_record,
                    nodes=nodes,
                    children_of=children_of,
                )
            )
    return out


def collect_switch_case_lines(
    switch_id: int,
    *,
    nodes: Dict[int, dict],
    children_of: Dict[int, List[int]],
) -> List[int]:
    out: List[int] = []
    for case_id in get_switch_case_ids(int(switch_id), nodes=nodes, children_of=children_of):
        ln = get_switch_case_line(int(case_id), nodes)
        if ln is not None and ln > 0:
            out.append(int(ln))
    out.sort()
    uniq: List[int] = []
    last = None
    for x in out:
        if last is None or x != last:
            uniq.append(int(x))
            last = int(x)
    return uniq


def build_seq_to_case_label(switch_choices: List[SwitchChoice]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for d in switch_choices or []:
        try:
            s = int(getattr(d, "switch_seq"))
        except Exception:
            continue
        label = getattr(d, "case_label", None)
        label_s = (str(label) if label is not None else "").strip()
        if not label_s:
            continue
        if s not in out:
            out[s] = label_s
    return out


def insert_mapped_items_after_seq(mapped: List[dict], *, after_seq: int, insert_items: List[dict]) -> List[dict]:
    """Insert mapped items after a given seq, deduping by (path,line)."""
    if not mapped:
        return list(insert_items or [])
    if not insert_items:
        return list(mapped)
    existing: Set[Tuple[str, int]] = set()
    for it in mapped:
        if not isinstance(it, dict):
            continue
        p = (it.get("path") or "").strip()
        ln = it.get("line")
        try:
            ln_i = int(ln)
        except Exception:
            ln_i = None
        if p and ln_i is not None:
            existing.add((p, int(ln_i)))
    filtered: List[dict] = []
    for it in insert_items:
        if not isinstance(it, dict):
            continue
        p = (it.get("path") or "").strip()
        ln = it.get("line")
        try:
            ln_i = int(ln)
        except Exception:
            ln_i = None
        if not p or ln_i is None:
            continue
        if (p, int(ln_i)) in existing:
            continue
        filtered.append(it)
        existing.add((p, int(ln_i)))
    if not filtered:
        return list(mapped)
    idx = None
    for i, it in enumerate(mapped):
        if not isinstance(it, dict):
            continue
        try:
            si = int(it.get("seq")) if it.get("seq") is not None else None
        except Exception:
            si = None
        if si is not None and int(si) == int(after_seq):
            idx = int(i)
            break
    if idx is None:
        return list(mapped) + list(filtered)
    return list(mapped[: idx + 1]) + list(filtered) + list(mapped[idx + 1 :])


def build_switch_case_result_set_for_seq(
    input_seq: int,
    *,
    trace_index_records: List[dict],
    nodes: Dict[int, dict],
    children_of: Dict[int, List[int]],
) -> List[dict]:
    """Return a result-set of (path,line) locations for all cases in the switch at input_seq."""
    try:
        input_seq_i = int(input_seq)
    except Exception:
        return []
    seq_to_record = build_seq_to_record(trace_index_records)
    rec = seq_to_record.get(int(input_seq_i))
    if not isinstance(rec, dict):
        return []
    switch_ids = find_switch_node_ids_in_record(rec, nodes)
    if not switch_ids:
        return []
    switch_path = (rec.get("path") or "").strip()
    if not switch_path:
        return []
    case_lines: Set[int] = set()
    for sid in switch_ids:
        for ln in collect_switch_case_lines(int(sid), nodes=nodes, children_of=children_of):
            case_lines.add(int(ln))
    if not case_lines:
        return []
    return [{"path": switch_path, "line": int(ln)} for ln in sorted(case_lines)]

