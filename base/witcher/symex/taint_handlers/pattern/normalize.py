from llm_utils.prompts.prompt_utils import ensure_seq_groups_by_loc, pick_seq_by_ref
from typing import Dict, List, Optional, Set, Tuple
from taint_handlers.llm.core.llm_response import (
    _is_nonstandalone_var,
    _node_source_str_with_this,
    _norm_llm_name,
    _promote_nonstandalone_var,
    _rewrite_this_prefix,
)


ALLOWED_TAINT_TYPES = {
    "AST_VAR",
    "AST_PROP",
    "AST_DIM",
    "AST_METHOD_CALL",
    "AST_STATIC_CALL",
    "AST_CALL",
}


def sorted_children(node_id: int, nodes: dict, children_of: dict) -> List[int]:
    children = list(children_of.get(int(node_id), []) or [])
    children.sort(
        key=lambda x: (nodes.get(x) or {}).get("childnum")
        if (nodes.get(x) or {}).get("childnum") is not None
        else 10**9
    )
    out = []
    for child in children:
        try:
            out.append(int(child))
        except Exception:
            continue
    return out


def record_for_seq(seq: int, ctx: dict) -> Optional[dict]:
    recs = ctx.get("trace_index_records") or []
    seq_to_idx = ctx.get("trace_seq_to_index") or {}
    try:
        seq_i = int(seq)
    except Exception:
        return None
    idx = seq_to_idx.get(seq_i)
    if isinstance(idx, int) and 0 <= idx < len(recs):
        return recs[idx]
    for rec in recs:
        if seq_i in (rec.get("seqs") or []):
            return rec
    return None


def seq_for_node(node_id: int, ctx: dict, *, ref_seq: Optional[int] = None, prefer: str = "backward") -> Optional[int]:
    nodes = ctx.get("nodes") or {}
    parent_of = ctx.get("parent_of") or {}
    top_id_to_file = ctx.get("top_id_to_file") or {}
    try:
        from utils.extractors.if_extract import resolve_top_id
    except Exception:
        return None
    try:
        node_i = int(node_id)
    except Exception:
        return None
    nx = nodes.get(node_i) or {}
    line = nx.get("lineno")
    if line is None:
        return None
    top = resolve_top_id(node_i, parent_of, nodes, top_id_to_file)
    if top is None:
        return None
    path = top_id_to_file.get(top)
    if not path:
        return None
    groups = ensure_seq_groups_by_loc(ctx).get((path, int(line))) or []
    return pick_seq_by_ref(groups, ref_seq, prefer=prefer)


def node_to_taint(
    node_id: int,
    seq: int,
    ctx: dict,
    *,
    this_obj: str = "",
    this_call_seq: Optional[int] = None,
) -> Optional[dict]:
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    try:
        node_i = int(node_id)
        seq_i = int(seq)
    except Exception:
        return None
    tt = ((nodes.get(node_i) or {}).get("type") or "").strip()
    if tt not in ALLOWED_TAINT_TYPES:
        return None
    if tt == "AST_VAR":
        if _is_nonstandalone_var(node_i, ctx, this_obj=this_obj):
            promoted = _promote_nonstandalone_var(node_i, ctx, this_obj=this_obj)
            if not isinstance(promoted, dict):
                return None
            out = {
                "id": int(promoted.get("id")),
                "seq": seq_i,
                "type": (promoted.get("type") or "").strip(),
            }
            name = (promoted.get("name") or "").strip()
            if name:
                out["name"] = name.replace(".", "->")
            if this_obj:
                out["_this_obj"] = this_obj
            if this_call_seq is not None:
                out["_this_call_seq"] = int(this_call_seq)
            return out
    src = (_node_source_str_with_this(node_i, tt, nodes, children_of, this_obj=this_obj) or "").strip()
    if not src and tt in ("AST_VAR", "AST_PROP", "AST_DIM", "AST_METHOD_CALL", "AST_CALL", "AST_STATIC_CALL"):
        return None
    out = {"id": node_i, "seq": seq_i, "type": tt}
    if src:
        out["name"] = src.replace(".", "->")
    if this_obj and tt in ("AST_PROP", "AST_DIM", "AST_METHOD_CALL"):
        out["_this_obj"] = this_obj
    if this_call_seq is not None and tt in ("AST_PROP", "AST_DIM", "AST_METHOD_CALL"):
        out["_this_call_seq"] = int(this_call_seq)
    return out


def collect_supported_taints(
    root_id: Optional[int],
    seq: int,
    ctx: dict,
    *,
    this_obj: str = "",
    this_call_seq: Optional[int] = None,
    include_root: bool = True,
) -> List[dict]:
    if root_id is None:
        return []
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}
    out = []
    seen_nodes = set()
    seen_taints = set()
    stack = [int(root_id)]
    while stack:
        nid = stack.pop()
        if nid in seen_nodes:
            continue
        seen_nodes.add(nid)
        if include_root or nid != int(root_id):
            taint = node_to_taint(
                nid,
                seq,
                ctx,
                this_obj=this_obj,
                this_call_seq=this_call_seq,
            )
            if isinstance(taint, dict):
                key = (
                    int(taint.get("id")),
                    int(taint.get("seq")),
                    (taint.get("type") or "").strip(),
                )
                if key not in seen_taints:
                    seen_taints.add(key)
                    out.append(taint)
        for child in reversed(sorted_children(nid, nodes, children_of)):
            stack.append(int(child))
    return out


def same_taint(a: dict, b: dict) -> bool:
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    try:
        if int(a.get("id")) == int(b.get("id")):
            return True
    except Exception:
        pass
    ta = (a.get("type") or "").strip()
    tb = (b.get("type") or "").strip()
    if ta != tb:
        return False
    return bool(_canonical_name_variants(a) & _canonical_name_variants(b))


def _canonical_name_variants(item: dict) -> Set[str]:
    if not isinstance(item, dict):
        return set()
    raw = (item.get("name") or "").replace(".", "->").strip()
    if not raw:
        return set()
    this_obj = (item.get("_this_obj") or "").strip()
    out = {_norm_llm_name(raw)}
    if this_obj:
        rewritten = (_rewrite_this_prefix(raw, this_obj) or "").replace(".", "->").strip()
        if rewritten:
            out.add(_norm_llm_name(rewritten))
        obj_norm = this_obj.lstrip("$")
        raw_norm = raw.lstrip("$")
        if obj_norm and raw_norm.startswith(f"{obj_norm}->"):
            out.add(_norm_llm_name("this->" + raw_norm[len(obj_norm) + 2 :]))
        if obj_norm and raw_norm.startswith(f"{obj_norm}["):
            out.add(_norm_llm_name("this" + raw_norm[len(obj_norm) :]))
    return {x for x in out if x}


def filter_new_taints(candidates: List[dict], current: dict) -> List[dict]:
    out = []
    seen = set()
    for item in candidates or []:
        if not isinstance(item, dict):
            continue
        if same_taint(item, current):
            continue
        key = (
            int(item.get("id")) if item.get("id") is not None else None,
            int(item.get("seq")) if item.get("seq") is not None else None,
            (item.get("type") or "").strip(),
            _norm_llm_name((item.get("name") or "").replace(".", "->")),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def ensure_node_ids_by_loc(ctx: dict) -> Dict[Tuple[str, int], List[int]]:
    cached = ctx.get("_pattern_node_ids_by_loc")
    if isinstance(cached, dict):
        return cached
    nodes = ctx.get("nodes") or {}
    parent_of = ctx.get("parent_of") or {}
    top_id_to_file = ctx.get("top_id_to_file") or {}
    out: Dict[Tuple[str, int], List[int]] = {}
    try:
        from utils.extractors.if_extract import resolve_top_id
    except Exception:
        ctx["_pattern_node_ids_by_loc"] = out
        return out
    for nid, nx in (nodes or {}).items():
        try:
            nid_i = int(nid)
        except Exception:
            continue
        line = nx.get("lineno")
        if line is None:
            continue
        try:
            line_i = int(line)
        except Exception:
            continue
        top = resolve_top_id(nid_i, parent_of, nodes, top_id_to_file)
        if top is None:
            continue
        path = top_id_to_file.get(int(top))
        if not path:
            continue
        out.setdefault((path, line_i), []).append(nid_i)
    ctx["_pattern_node_ids_by_loc"] = out
    return out


def node_ids_for_loc(path: str, line: int, ctx: dict) -> List[int]:
    try:
        key = ((path or "").strip(), int(line))
    except Exception:
        return []
    loc_map = ensure_node_ids_by_loc(ctx)
    return [int(x) for x in (loc_map.get(key) or [])]
