from typing import Dict, List, Optional, Set, Tuple

from .normalize import sorted_children


_CALL_TYPES = {"AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"}
_PROMPT_SEQ_LIMIT = 200


def _iter_call_nodes(root_id: Optional[int], nodes: dict, children_of: dict) -> List[int]:
    if root_id is None:
        return []
    out = []
    seen = set()
    stack = [int(root_id)]
    while stack:
        nid = stack.pop()
        if nid in seen:
            continue
        seen.add(nid)
        ntype = ((nodes.get(nid) or {}).get("type") or "").strip()
        if ntype in _CALL_TYPES:
            out.append(int(nid))
        for child in reversed(sorted_children(nid, nodes, children_of)):
            stack.append(int(child))
    return out


def _scope_seqs_from_locs(scope_locs: list) -> List[int]:
    out = []
    seen = set()
    for row in scope_locs or []:
        try:
            seq = int((row or {}).get("seq"))
        except Exception:
            continue
        if seq in seen:
            continue
        seen.add(seq)
        out.append(seq)
    out.sort()
    return out


def record_assignment_rhs_call_scopes(*, lhs_id: Optional[int], rhs_id: Optional[int], seq: int, ctx: dict) -> None:
    if lhs_id is None or rhs_id is None or not isinstance(ctx, dict):
        return
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    for call_id in _iter_call_nodes(rhs_id, nodes, children_of):
        try:
            ctx.setdefault("_assignment_rhs_pending_calls", set()).add(int(call_id))
        except Exception:
            continue


def record_partitioned_assignment_call_scope(*, current: dict, relation_detail: dict, ctx: dict) -> None:
    if not isinstance(current, dict) or not isinstance(relation_detail, dict) or not isinstance(ctx, dict):
        return
    try:
        call_id = int(current.get("id")) if current.get("id") is not None else None
    except Exception:
        call_id = None
    if call_id is None:
        return
    pending = ctx.get("_assignment_rhs_pending_calls") or set()
    if int(call_id) not in pending:
        return
    scope_locs = relation_detail.get("callee_scope_locs") or []
    scope_seqs = _scope_seqs_from_locs(scope_locs)
    if not scope_seqs:
        return
    try:
        callee_id = int(relation_detail.get("callee_id")) if relation_detail.get("callee_id") is not None else None
    except Exception:
        callee_id = None
    key = (
        int(callee_id) if callee_id is not None else None,
        int(scope_seqs[0]),
        int(scope_seqs[-1]),
    )
    store = ctx.setdefault("_assignment_rhs_call_scopes", {})
    prev = store.get(key)
    item = {
        "call_id": int(call_id),
        "def_id": callee_id,
        "scope_start_seq": int(scope_seqs[0]),
        "scope_end_seq": int(scope_seqs[-1]),
        "scope_seqs": list(scope_seqs),
        "scope_seq_count": len(scope_seqs),
    }
    if not isinstance(prev, dict):
        store[key] = item
        return
    prev_seqs = set(int(x) for x in (prev.get("scope_seqs") or []) if x is not None)
    merged = prev_seqs | set(scope_seqs)
    prev["scope_seqs"] = sorted(int(x) for x in merged)
    prev["scope_seq_count"] = len(prev["scope_seqs"])


def merge_assignment_call_scopes_into_prompt_seqs(ctx: dict, *, limit: int = _PROMPT_SEQ_LIMIT) -> List[int]:
    if not isinstance(ctx, dict):
        return []
    base_set = set()
    for x in (ctx.get("llm_result_seqs") or set()):
        try:
            base_set.add(int(x))
        except Exception:
            continue
    store = ctx.get("_assignment_rhs_call_scopes") or {}
    groups = []
    for item in store.values() if isinstance(store, dict) else []:
        if not isinstance(item, dict):
            continue
        seqs = []
        seen = set()
        for x in item.get("scope_seqs") or []:
            try:
                xi = int(x)
            except Exception:
                continue
            if xi in seen:
                continue
            seen.add(xi)
            seqs.append(xi)
        if not seqs:
            continue
        seqs.sort()
        groups.append(
            {
                "def_id": item.get("def_id"),
                "scope_seqs": seqs,
                "scope_seq_count": len(seqs),
                "scope_start_seq": int(item.get("scope_start_seq") or seqs[0]),
                "scope_end_seq": int(item.get("scope_end_seq") or seqs[-1]),
            }
        )
    groups.sort(
        key=lambda x: (
            int(x.get("scope_seq_count") or 10 ** 9),
            int(x.get("scope_start_seq") or 10 ** 9),
            int(x.get("def_id") or 10 ** 9) if x.get("def_id") is not None else 10 ** 9,
        )
    )

    merged = set(base_set)
    applied = []
    blocked = None
    if len(merged) < int(limit):
        for item in groups:
            cand = merged | set(item.get("scope_seqs") or [])
            if len(cand) > int(limit):
                blocked = {
                    "def_id": item.get("def_id"),
                    "scope_seq_count": int(item.get("scope_seq_count") or 0),
                    "candidate_count": len(cand),
                }
                break
            merged = cand
            applied.append(
                {
                    "def_id": item.get("def_id"),
                    "scope_seq_count": int(item.get("scope_seq_count") or 0),
                    "merged_count": len(merged),
                }
            )
    ctx["_assignment_rhs_call_scope_merge"] = {
        "base_count": len(base_set),
        "final_count": len(merged),
        "limit": int(limit),
        "group_count": len(groups),
        "applied": applied,
        "blocked": blocked,
    }
    return sorted(int(x) for x in merged)
