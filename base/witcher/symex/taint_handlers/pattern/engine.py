import json
import heapq
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from llm_utils.prompts.prompt_utils import locs_to_scope_seqs
from taint_handlers import REGISTRY
from taint_handlers.handlers.call import ast_method_call
from taint_handlers.llm.utils.llm_loop_utils import _get_logger, _taint_brief, _taint_scope_key

from .debug_render import render_scope_block, render_scope_sources
from .param_bridge import bridge_current_param_to_args, expand_param_bridge_taints
from .call_return_bridge import collect_call_return_relations
from .callsite_bridge import infer_call_param_arg_info_for_current
from .assignment_call_scopes import (
    merge_assignment_call_scopes_into_prompt_seqs,
    record_partitioned_assignment_call_scope,
)
from .rules import discover_relations_for_source_locs, discover_relations_for_taint
from .scope_state import (
    all_scope_locs,
    defer_global_taint,
    is_declared_global_taint,
    pop_deferred_global_taints,
    record_scope_observations,
)
from .structural_locs import add_decl_locs_from_scope_lines, add_function_frame_locs
from .normalize import _canonical_name_variants, node_ids_for_loc, node_to_taint, record_for_seq, same_taint


_CALL_TAINT_TYPES = {"AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"}


def _taint_name_key(item: dict) -> str:
    try:
        vars = sorted(_canonical_name_variants(item) or [])
    except Exception:
        vars = []
    if vars:
        return vars[0]
    return ((item or {}).get("name") or "").replace(".", "->").strip()


def _line_taints_for_seq(seq: int, ctx: dict, *, this_obj: str = "", this_call_seq: Optional[int] = None) -> Tuple[Optional[Tuple[str, int]], List[dict]]:
    rec = record_for_seq(seq, ctx)
    if not isinstance(rec, dict):
        return None, []
    path = (rec.get("path") or "").strip()
    line = rec.get("line")
    try:
        line_i = int(line) if line is not None else None
    except Exception:
        line_i = None
    loc = (path, int(line_i)) if path and line_i is not None else None
    node_ids = rec.get("node_ids") or []
    if (not node_ids) and loc is not None:
        node_ids = node_ids_for_loc(path, int(line_i), ctx)
    out = []
    seen = set()
    for nid in node_ids or []:
        try:
            ni = int(nid)
        except Exception:
            continue
        ta = node_to_taint(ni, int(seq), ctx, this_obj=this_obj, this_call_seq=this_call_seq)
        if not isinstance(ta, dict):
            continue
        key = (
            int(ta.get("id")) if ta.get("id") is not None else None,
            int(ta.get("seq")) if ta.get("seq") is not None else None,
            (ta.get("type") or "").strip(),
            _taint_name_key(ta),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(ta)
    return loc, out


def _ensure_relaxed_seq_index(ctx: dict) -> Dict[str, List[int]]:
    cached = ctx.get("_relaxed_seq_index")
    if isinstance(cached, dict):
        return cached
    out: Dict[str, Set[int]] = {}
    recs = ctx.get("trace_index_records") or []
    for rec in recs or []:
        if not isinstance(rec, dict):
            continue
        path = (rec.get("path") or "").strip()
        line = rec.get("line")
        try:
            line_i = int(line) if line is not None else None
        except Exception:
            line_i = None
        if not path or line_i is None:
            continue
        seqs = rec.get("seqs") or []
        try:
            seq_list = [int(x) for x in (seqs or [])]
        except Exception:
            continue
        if not seq_list:
            continue
        node_ids = rec.get("node_ids") or []
        if not node_ids:
            node_ids = node_ids_for_loc(path, int(line_i), ctx)
        if not node_ids:
            continue
        rep_seq = int(seq_list[0])
        for nid in node_ids or []:
            try:
                ni = int(nid)
            except Exception:
                continue
            ta = node_to_taint(ni, rep_seq, ctx)
            if not isinstance(ta, dict):
                continue
            try:
                vars = _canonical_name_variants(ta) or set()
            except Exception:
                vars = set()
            for v in vars:
                if not v:
                    continue
                bucket = out.setdefault(str(v), set())
                for s in seq_list:
                    bucket.add(int(s))
    out2: Dict[str, List[int]] = {k: sorted(v) for k, v in out.items()}
    ctx["_relaxed_seq_index"] = out2
    return out2


def _merge_scope_locs(locs: list, extra_locs: list) -> list:
    out = []
    seen = set()
    for item in list(locs or []) + list(extra_locs or []):
        if not item:
            continue
        if isinstance(item, dict):
            loc = (item.get("loc") or "").strip()
            if not loc:
                path = (item.get("path") or "").strip()
                line = item.get("line")
                if path and line is not None:
                    try:
                        loc = f"{path}:{int(line)}"
                    except Exception:
                        loc = ""
            seq = item.get("seq")
            try:
                seq_i = int(seq) if seq is not None else None
            except Exception:
                seq_i = None
            key = (loc, seq_i) if loc and seq_i is not None else loc
        elif isinstance(item, str):
            key = item
        else:
            continue
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _loc_key(item) -> Optional[object]:
    if not item:
        return None
    if isinstance(item, dict):
        path = (item.get("path") or "").strip()
        line = item.get("line")
        loc = (item.get("loc") or "").strip()
        if not loc and path and line is not None:
            try:
                loc = f"{path}:{int(line)}"
            except Exception:
                loc = ""
        seq = item.get("seq")
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        source_only = bool(item.get("source_only"))
        return (loc, seq_i, source_only) if loc else None
    if isinstance(item, str):
        return item
    return None


def _dedup_loc_items(items: list) -> list:
    out = []
    seen = set()
    for item in items or []:
        key = _loc_key(item)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _split_trace_and_source_locs(items: list) -> Tuple[list, list]:
    trace_locs = []
    source_locs = []
    for item in items or []:
        if isinstance(item, dict) and item.get("source_only"):
            source_locs.append(item)
        else:
            trace_locs.append(item)
    return trace_locs, source_locs


def _ensure_pattern_dir(ctx: dict) -> str:
    test_dir = (ctx.get("test_dir") or "").strip() if isinstance(ctx, dict) else ""
    out_dir = os.path.join(test_dir, "pattern") if test_dir else os.path.join(os.getcwd(), "test", "pattern")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def _write_pattern_debug(ctx: dict, filename: str, payload: dict) -> None:
    try:
        out_dir = _ensure_pattern_dir(ctx)
        with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as f:
            json.dump(_debug_payload_with_source(payload, ctx), f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _debug_payload_with_source(obj, ctx: dict):
    if isinstance(obj, list):
        loc_lines = _try_render_debug_loc_lines(obj, ctx)
        if loc_lines is not None:
            return loc_lines
        return [_debug_payload_with_source(x, ctx) for x in obj]
    if isinstance(obj, dict):
        if _looks_like_loc_item(obj):
            rendered = _try_render_debug_loc_lines([obj], ctx) or []
            return rendered[0] if rendered else {}
        return {k: _debug_payload_with_source(v, ctx) for k, v in obj.items()}
    return obj


def _looks_like_loc_item(item: dict) -> bool:
    if not isinstance(item, dict):
        return False
    return bool((item.get("loc") or "").strip()) or (
        (item.get("path") is not None) and (item.get("line") is not None)
    )


def _try_render_debug_loc_lines(items: list, ctx: dict) -> Optional[List[dict]]:
    locs = [it for it in (items or []) if _looks_like_loc_item(it)]
    if not locs or len(locs) != len(items or []):
        return None
    rendered = render_scope_sources(locs, ctx)
    out = []
    for idx, line in enumerate(rendered):
        src = locs[idx] if idx < len(locs) else {}
        row = {
            "seq": line.get("seq"),
            "code": (line.get("code") or "").rstrip(),
        }
        if isinstance(src, dict) and src.get("source_only") is not None:
            row["source_only"] = bool(src.get("source_only"))
        out.append(row)
    return out


def _build_non_trace_scope_locs(current: dict, scope_seqs: List[int], ctx: dict) -> List[dict]:
    try:
        from if_branch_coverage.if_scope import get_if_branch_lines, get_if_file_path
        from llm_utils.branch.if_branch import infer_if_directions_for_seqs
    except Exception:
        return []
    nodes = ctx.get("nodes") or {}
    parent_of = ctx.get("parent_of") or {}
    children_of = ctx.get("children_of") or {}
    top_id_to_file = ctx.get("top_id_to_file") or {}
    trace_index_records = ctx.get("trace_index_records") or []
    directions = infer_if_directions_for_seqs(
        scope_seqs or [],
        trace_index_records=trace_index_records,
        nodes=nodes,
        children_of=children_of,
    )
    out = []
    seen = set()
    for item in directions or []:
        try:
            if_id = int(item.if_id)
        except Exception:
            continue
        path = get_if_file_path(if_id, parent_of, nodes, top_id_to_file)
        if not path:
            continue
        true_lines, false_lines = get_if_branch_lines(if_id, nodes, children_of)
        missing = false_lines if (item.direction or "").strip() == "true" else true_lines
        for line in sorted(int(x) for x in (missing or set())):
            key = (path, int(line))
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "path": path,
                    "line": int(line),
                    "loc": f"{path}:{int(line)}",
                    "source_only": True,
                    "if_seq": int(item.if_seq),
                    "if_id": int(if_id),
                    "if_direction": item.direction,
                    "ref_seq": int(current.get("seq")),
                }
            )
    return out


def _compute_this_context(current: dict, ctx: dict) -> Tuple[str, Optional[int]]:
    this_obj = (current.get("_this_obj") or current.get("recv") or "").strip()
    tt = (current.get("type") or "").strip()
    if not this_obj and (current.get("type") or "").strip() == "AST_PROP":
        base = (current.get("base") or "").strip()
        if base:
            this_obj = base.lstrip("$")
        else:
            name = (current.get("name") or "").replace(".", "->").strip()
            if "->" in name:
                this_obj = (name.split("->", 1)[0] or "").strip().lstrip("$")
    this_call_seq = current.get("_this_call_seq")
    try:
        this_call_seq = int(this_call_seq) if this_call_seq is not None else None
    except Exception:
        this_call_seq = None
    if this_call_seq is None and (current.get("type") or "").strip() == "AST_METHOD_CALL":
        try:
            this_call_seq = int(current.get("seq"))
        except Exception:
            this_call_seq = None
    if this_call_seq is None and (current.get("type") or "").strip() == "AST_PROP":
        raw_base = (current.get("base") or "").strip()
        raw_name = (current.get("name") or "").replace(".", "->").strip()
        if raw_base in ("this", "$this") or raw_name.startswith(("this->", "$this->", "this[", "$this[", "this.", "$this.")):
            try:
                this_call_seq = int(current.get("seq"))
            except Exception:
                this_call_seq = None
    if this_obj and this_obj not in ("this", "$this"):
        return this_obj, this_call_seq
    if tt not in ("AST_PROP", "AST_METHOD_CALL"):
        return this_obj, this_call_seq
    try:
        from taint_handlers.handlers.expr import ast_var
        from utils.cpg_utils.graph_mapping import resolve_this_object_chain
    except Exception:
        return this_obj, this_call_seq
    calls_edges_union = ctx.get("calls_edges_union")
    if calls_edges_union is None:
        calls_edges_union = ast_method_call.read_calls_edges(".")
        ctx["calls_edges_union"] = calls_edges_union
    try:
        start_seq = int(this_call_seq if this_call_seq is not None else current.get("seq"))
    except Exception:
        return this_obj, this_call_seq
    ast_var.ensure_trace_index(ctx)
    recs = ctx.get("trace_index_records") or []
    seq_to_idx = ctx.get("trace_seq_to_index") or {}
    start_idx = seq_to_idx.get(int(start_seq))
    if not isinstance(start_idx, int) or start_idx < 0 or start_idx >= len(recs):
        return this_obj, this_call_seq
    chain = resolve_this_object_chain(
        records=recs,
        nodes=ctx.get("nodes") or {},
        children_of=ctx.get("children_of") or {},
        calls_edges_union=calls_edges_union,
        start_index=int(start_idx),
    )
    if not isinstance(chain, dict):
        return this_obj, this_call_seq
    extra_scope_locs = []
    for loc in list(chain.get("preamble_locs") or []) + list(chain.get("extra_locs") or []):
        if isinstance(loc, str) and loc.strip():
            extra_scope_locs.append(loc.strip())
    if extra_scope_locs:
        current["_pattern_this_scope_locs"] = extra_scope_locs
    resolved_obj = (chain.get("obj") or "").strip()
    if resolved_obj:
        this_obj = resolved_obj
    try:
        resolved_call_seq = int(chain.get("resolved_call_seq")) if chain.get("resolved_call_seq") is not None else None
    except Exception:
        resolved_call_seq = None
    if resolved_call_seq is not None:
        this_call_seq = int(resolved_call_seq)
    return this_obj, this_call_seq


def _enqueue(queue: list, item: dict, queued: set, seen: set) -> bool:
    if not isinstance(item, dict):
        return False
    tid = item.get("id")
    seq = item.get("seq")
    if tid is None or seq is None:
        return False
    try:
        key = (int(tid), int(seq))
    except Exception:
        return False
    if key in queued or key in seen:
        return False
    queued.add(key)
    queue.append(item)
    return True


def _same_taint_identity(a: dict, b: dict) -> bool:
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    try:
        return int(a.get("id")) == int(b.get("id")) and int(a.get("seq")) == int(b.get("seq"))
    except Exception:
        return False


def _apply_relation_scope_hint(expanded: dict, original: dict, relation) -> dict:
    if not isinstance(expanded, dict):
        return expanded
    if not isinstance(relation, object):
        return expanded
    kind = getattr(relation, "kind", "")
    detail = getattr(relation, "detail", {}) or {}
    if kind != "call_return_bridge":
        return expanded
    if expanded.get("_pattern_param_bridge"):
        return expanded
    if _same_taint_identity(expanded, original):
        callee_scope_locs = list(detail.get("callee_scope_locs") or [])
        if callee_scope_locs:
            out = dict(expanded)
            out["_pattern_extra_scope_locs"] = list(callee_scope_locs)
            call_param_arg_info = detail.get("call_param_arg_info")
            if isinstance(call_param_arg_info, dict) and call_param_arg_info:
                out["_pattern_call_param_arg_info"] = call_param_arg_info
            return out
    return expanded


def _append_new_taint(ctx: dict, item: dict, relation) -> None:
    if not isinstance(ctx, dict) or not isinstance(item, dict):
        return
    out = ctx.setdefault("llm_new_taints", [])
    seen = ctx.setdefault("_llm_new_seen", set())
    tid = item.get("id")
    seq = item.get("seq")
    tt = (item.get("type") or "").strip()
    name = (item.get("name") or "").strip()
    try:
        key = (int(tid), int(seq), tt, name)
    except Exception:
        key = (tid, seq, tt, name)
    if key in seen:
        return
    seen.add(key)
    rec = dict(item)
    rec["relation_kind"] = relation.kind
    rec["relation_seq"] = int(relation.seq)
    out.append(rec)


def _is_call_taint(item: dict) -> bool:
    if not isinstance(item, dict):
        return False
    return (item.get("type") or "").strip() in _CALL_TAINT_TYPES


def _record_current_taint_source(current: dict, ctx: dict) -> None:
    if not isinstance(current, dict) or not isinstance(ctx, dict):
        return
    try:
        from taint_handlers.handlers.expr.ast_var import record_taint_source
    except Exception:
        return
    try:
        record_taint_source(current, ctx)
    except Exception:
        return


def _pick_call_param_arg_info_from_relations(relations: list) -> Optional[dict]:
    for relation in relations or []:
        detail = getattr(relation, "detail", {}) or {}
        info = detail.get("call_param_arg_info")
        if isinstance(info, dict) and info:
            return info
    return None


def _add_source_only_result(ctx: dict, relation) -> None:
    loc = (relation.detail or {}).get("loc")
    path = (relation.detail or {}).get("path")
    line = (relation.detail or {}).get("line")
    if not (loc or (path and line is not None)):
        return
    ctx["pattern_source_locs"] = _dedup_loc_items(
        list(ctx.get("pattern_source_locs") or [])
        + [
            {
                "loc": loc or f"{path}:{int(line)}",
                "path": path,
                "line": int(line),
                "source_only": True,
            }
        ]
    )


def _discover_relations_for_scope_locs(current: dict, all_locs: list, ctx: dict, *, ref_seq: int, prefer: str) -> Tuple[list, List[int], List[dict]]:
    trace_locs, source_locs = _split_trace_and_source_locs(_dedup_loc_items(all_locs))
    scope_seqs = locs_to_scope_seqs(trace_locs, ctx, ref_seq=ref_seq, prefer=prefer) if trace_locs else []
    relations = discover_relations_for_taint(current, scope_seqs, ctx)
    if source_locs:
        relations.extend(discover_relations_for_source_locs(current, source_locs, ctx, ref_seq=int(ref_seq)))
    return relations, [int(x) for x in (scope_seqs or [])], list(source_locs or [])


def _drain_deferred_globals(ctx: dict, *, round_no: int, lg, queued: Set, seen: Set) -> Tuple[int, list]:
    deferred = pop_deferred_global_taints(ctx)
    if not deferred:
        return round_no, []
    round_no += 1
    next_queue = []
    round_debug = []
    global_locs = all_scope_locs(ctx)
    trace_locs, source_locs = _split_trace_and_source_locs(global_locs)
    global_scope_source_lines = render_scope_sources(trace_locs + source_locs, ctx)
    global_scope_block = render_scope_block(global_scope_source_lines)
    for current in deferred:
        if not isinstance(current, dict):
            continue
        current = dict(current)
        try:
            ref_seq = int(current.get("seq"))
        except Exception:
            continue
        relations, scope_seqs, source_only_locs = _discover_relations_for_scope_locs(
            current,
            global_locs,
            ctx,
            ref_seq=ref_seq,
            prefer="backward",
        )
        step_debug = {
            "phase": "deferred_global",
            "current": _taint_brief(current),
            "scope_source_lines": global_scope_source_lines,
            "scope_source": global_scope_block,
            "scope_seqs": scope_seqs,
            "source_only_source_lines": render_scope_sources(source_only_locs, ctx),
            "relations": [],
        }
        for relation in relations:
            if bool((relation.detail or {}).get("source_only")):
                _add_source_only_result(ctx, relation)
            else:
                ctx.setdefault("llm_result_seqs", set()).add(int(relation.seq))
            emitted = []
            for item in relation.taints or []:
                for bridged in expand_param_bridge_taints(item, None, None):
                    _append_new_taint(ctx, bridged, relation)
                    if is_declared_global_taint(bridged, ctx) and not _same_taint_identity(bridged, current):
                        defer_global_taint(bridged, ctx)
                        emitted.append({**dict(bridged), "_deferred_global": True})
                        continue
                    _enqueue(next_queue, bridged, queued, seen)
                    emitted.append(dict(bridged))
            step_debug["relations"].append(
                {
                    "kind": relation.kind,
                    "seq": int(relation.seq),
                    "detail": relation.detail or {},
                    "new_taints": emitted,
                }
            )
        round_debug.append(step_debug)
    _write_pattern_debug(
        ctx,
        f"round_{int(round_no):03d}.json",
        {
            "round": int(round_no),
            "queue": "GLOBAL",
            "steps": round_debug,
            "queued_next": [_taint_brief(x) for x in (next_queue or [])],
        },
    )
    return round_no, next_queue


def process_taints_by_patterns(initial, ctx):
    lg = _get_logger(ctx)
    nodes = ctx.get("nodes") or {}
    children_of = ctx.get("children_of") or {}

    pre_a = list(initial or [])
    pre_b = []
    use_a = True
    seen = ctx.setdefault("_taint_seen", set())
    queued = ctx.setdefault("_taint_queued", set())
    seen_scope = ctx.setdefault("_taint_seen_scope", set())
    llm_seqs = ctx.setdefault("llm_result_seqs", set())
    input_seq = None
    try:
        input_seq = int(ctx.get("input_seq")) if ctx.get("input_seq") is not None else None
    except Exception:
        input_seq = None
    strict_match_seqs = ctx.setdefault("_strict_match_seqs", set())
    relaxed_pool = ctx.setdefault("_relaxed_taint_pool", {})
    relaxed_meta = ctx.setdefault("_relaxed_taint_pool_meta", {})
    ctx.setdefault("llm_new_taints", [])
    ctx.setdefault("llm_intermediates", [])
    ctx.setdefault("pattern_source_locs", [])
    round_no = 0
    phase = "strict"

    def _build_line_phase_seeds() -> List[dict]:
        seeds: List[dict] = []
        if not isinstance(relaxed_pool, dict) or not relaxed_pool:
            return seeds
        items = []
        for k, t in relaxed_pool.items():
            if not isinstance(t, dict):
                continue
            meta = relaxed_meta.get(k) if isinstance(relaxed_meta, dict) else None
            try:
                rr = int((meta or {}).get("round") or 0)
            except Exception:
                rr = 0
            try:
                ss = int((meta or {}).get("seq") or (t or {}).get("seq"))
            except Exception:
                ss = 10**9
            dist = None
            if input_seq is not None:
                try:
                    dist = abs(int(ss) - int(input_seq))
                except Exception:
                    dist = None
            items.append((rr, dist if dist is not None else 10**9, ss, dict(t)))
        items.sort(key=lambda x: (int(x[0]), int(x[1]), int(x[2])))
        seen_local = set()
        for _rr, _dist, _ss, t in items:
            try:
                key = (
                    int(t.get("id")) if t.get("id") is not None else None,
                    int(t.get("seq")) if t.get("seq") is not None else None,
                    (t.get("type") or "").strip(),
                    _taint_name_key(t),
                )
            except Exception:
                key = (t.get("id"), t.get("seq"), t.get("type"), t.get("name"))
            if key in seen_local:
                continue
            seen_local.add(key)
            seeds.append(dict(t))
        return seeds

    while True:
        active = pre_a if use_a else pre_b
        if not active:
            other = pre_b if use_a else pre_a
            if other:
                use_a = not use_a
                continue
            round_no, global_next = _drain_deferred_globals(ctx, round_no=round_no, lg=lg, queued=queued, seen=seen)
            if global_next:
                pre_a = list(global_next)
                pre_b = []
                use_a = True
                continue
            if phase == "strict":
                try:
                    need_more = len(ctx.get("llm_result_seqs") or set()) < 30
                except Exception:
                    need_more = False
                if need_more:
                    line_phase_seeds = _build_line_phase_seeds()
                    if line_phase_seeds:
                        phase = "line"
                        pre_a = list(line_phase_seeds)
                        pre_b = []
                        use_a = True
                        continue
            break
        round_no += 1
        next_queue = []
        round_debug = []
        while active:
            current = active.pop(0)
            if not isinstance(current, dict):
                continue
            current = dict(current)
            this_obj, this_call_seq = _compute_this_context(current, ctx)
            if this_obj:
                current["_this_obj"] = this_obj
            if this_call_seq is not None:
                current["_this_call_seq"] = int(this_call_seq)
            tid = current.get("id")
            tseq = current.get("seq")
            if tid is None or tseq is None:
                continue
            try:
                key = (int(tid), int(tseq))
            except Exception:
                continue
            scope_key = _taint_scope_key(current, nodes, children_of, (current.get("_this_obj") or "").strip())
            if key in seen:
                continue
            if scope_key is not None and scope_key in seen_scope:
                continue
            seen.add(key)
            if scope_key is not None:
                seen_scope.add(scope_key)

            handler = REGISTRY.get(current.get("type") or "")
            if handler is None:
                continue

            result_set = ctx.setdefault("result_set", [])
            before = len(result_set)
            ctx["_llm_scope_markers"] = []
            ctx["_llm_extra_prompt_locs"] = []
            call_like_current = _is_call_taint(current)
            if call_like_current:
                _record_current_taint_source(current, ctx)
            else:
                handler(current, ctx)
            call_param_arg_info = ctx.pop("_llm_call_param_arg_info", None)
            prop_call_scopes_info = ctx.pop("_llm_prop_call_scopes_info", None)
            
            explicit_call_info = call_param_arg_info
            
            if call_param_arg_info is None and not call_like_current:
                call_param_arg_info = current.get("_pattern_call_param_arg_info")
                if isinstance(call_param_arg_info, dict) and call_param_arg_info:
                    explicit_call_info = call_param_arg_info
            if call_param_arg_info is None and not call_like_current:
                try:
                    cur_funcid = (nodes.get(int(current.get("id"))) or {}).get("funcid")
                    cur_funcid = int(cur_funcid) if cur_funcid is not None else None
                except Exception:
                    cur_funcid = None
                if cur_funcid is not None:
                    call_param_arg_info = (ctx.get("pattern_func_param_arg_info") or {}).get(int(cur_funcid))
            if call_param_arg_info is None and not call_like_current:
                inferred = infer_call_param_arg_info_for_current(current, ctx)
                if isinstance(inferred, dict) and inferred:
                    call_param_arg_info = inferred
                    try:
                        callee_id = int(inferred.get("callee_id"))
                        ctx.setdefault("pattern_func_param_arg_info", {})[callee_id] = inferred
                    except Exception:
                        pass
                        
            if isinstance(explicit_call_info, dict) and explicit_call_info and not call_like_current:
                add_function_frame_locs(ctx, explicit_call_info)

            if not call_like_current:
                for bridged_cur in bridge_current_param_to_args(current, call_param_arg_info, prop_call_scopes_info):
                    pseudo_relation = type("PseudoRelation", (), {"kind": "param_bridge_current", "seq": int(tseq)})()
                    _append_new_taint(ctx, bridged_cur, pseudo_relation)
                    _enqueue(next_queue, bridged_cur, queued, seen)
                    if isinstance(call_param_arg_info, dict):
                        add_function_frame_locs(ctx, call_param_arg_info)

            scope_locs = []
            merged_locs = []
            scope_seqs = []
            source_only_locs = []
            trace_scope_source_lines = []
            try:
                ref_seq = int(tseq)
            except Exception:
                ref_seq = None
            prefer = "forward" if (current.get("type") or "").strip() in _CALL_TAINT_TYPES else "backward"
            if call_like_current:
                relations = collect_call_return_relations(current, ctx)
                for relation in relations or []:
                    try:
                        detail = getattr(relation, "detail", {}) or {}
                        if getattr(relation, "kind", "") == "call_return_bridge":
                            record_partitioned_assignment_call_scope(current=current, relation_detail=detail, ctx=ctx)
                    except Exception:
                        pass
                if call_param_arg_info is None:
                    call_param_arg_info = _pick_call_param_arg_info_from_relations(relations)
            else:
                scope_locs = list((ctx.get("result_set") or [])[before:])
                extra_locs = (
                    list(ctx.get("_llm_extra_prompt_locs") or [])
                    + list(current.get("_pattern_this_scope_locs") or [])
                    + list(current.get("_pattern_extra_scope_locs") or [])
                )
                merged_locs = _dedup_loc_items(_merge_scope_locs(scope_locs, extra_locs))
                trace_scope_source_lines = render_scope_sources(merged_locs, ctx)
                record_scope_observations(current, merged_locs, trace_scope_source_lines, ctx)
                add_decl_locs_from_scope_lines(ctx, trace_scope_source_lines)
                scope_seqs = locs_to_scope_seqs(merged_locs, ctx, ref_seq=ref_seq, prefer=prefer)
                source_only_locs = _build_non_trace_scope_locs(current, scope_seqs, ctx)
                source_only_locs = _dedup_loc_items(source_only_locs)
                record_scope_observations(current, source_only_locs, render_scope_sources(source_only_locs, ctx), ctx)

                relations, scope_seqs, source_only_locs = _discover_relations_for_scope_locs(
                    current,
                    list(merged_locs or []) + list(source_only_locs or []),
                    ctx,
                    ref_seq=int(ref_seq or tseq),
                    prefer=prefer,
                )
                relations.extend(collect_call_return_relations(current, ctx))
            strict_hit = bool(relations or []) or bool(scope_seqs or []) or bool(merged_locs or [])
            if strict_hit:
                try:
                    strict_match_seqs.add(int(tseq))
                    llm_seqs.add(int(tseq))
                except Exception:
                    pass
            if not call_like_current:
                seqs_to_probe = []
                try:
                    seqs_to_probe.append(int(tseq))
                except Exception:
                    seqs_to_probe = []
                for s in (scope_seqs or []):
                    try:
                        ss = int(s)
                    except Exception:
                        continue
                    if ss not in seqs_to_probe:
                        seqs_to_probe.append(ss)
                for s in seqs_to_probe:
                    loc, line_taints = _line_taints_for_seq(int(s), ctx, this_obj=this_obj, this_call_seq=this_call_seq)
                    if not line_taints:
                        continue
                    present = False
                    for lt in line_taints:
                        if same_taint(current, lt):
                            present = True
                            break
                    if not present:
                        continue
                    try:
                        strict_match_seqs.add(int(s))
                        llm_seqs.add(int(s))
                    except Exception:
                        pass
                    for lt in line_taints:
                        if not isinstance(lt, dict):
                            continue
                        if phase == "line":
                            pseudo_relation = type("PseudoRelation", (), {"kind": "line_match_expand", "seq": int(s)})()
                            _append_new_taint(ctx, lt, pseudo_relation)
                            _enqueue(next_queue, lt, queued, seen)
                        k = ((lt.get("type") or "").strip(), _taint_name_key(lt))
                        if not k[0] or not k[1]:
                            continue
                        dist = None
                        if input_seq is not None:
                            try:
                                dist = abs(int(s) - int(input_seq))
                            except Exception:
                                dist = None
                        prev = relaxed_meta.get(k) if isinstance(relaxed_meta, dict) else None
                        if prev is None:
                            relaxed_pool[k] = dict(lt)
                            relaxed_meta[k] = {"round": int(round_no), "seq": int(s), "dist": dist}
                            continue
                        try:
                            prev_round = int((prev or {}).get("round") or 10**9)
                        except Exception:
                            prev_round = 10**9
                        try:
                            prev_dist = (prev or {}).get("dist")
                            prev_dist = int(prev_dist) if prev_dist is not None else None
                        except Exception:
                            prev_dist = None
                        better = False
                        if int(round_no) < prev_round:
                            better = True
                        elif int(round_no) == prev_round and dist is not None and (prev_dist is None or int(dist) < int(prev_dist)):
                            better = True
                        if better:
                            relaxed_pool[k] = dict(lt)
                            relaxed_meta[k] = {"round": int(round_no), "seq": int(s), "dist": dist}
            if lg is not None:
                try:
                    lg.debug(
                        "pattern_diffusion_step",
                        current=_taint_brief(current),
                        scope_seq_count=len(scope_seqs or []),
                        relation_count=len(relations or []),
                        source_only_scope_count=len(source_only_locs or []),
                    )
                except Exception:
                    pass

            source_only_source_lines = render_scope_sources(source_only_locs, ctx)
            step_debug = {
                "current": _taint_brief(current),
                "scope_source_lines": trace_scope_source_lines,
                "scope_source": render_scope_block(trace_scope_source_lines),
                "scope_seqs": [int(x) for x in (scope_seqs or [])],
                "source_only_source_lines": source_only_source_lines,
                "source_only_source": render_scope_block(source_only_source_lines),
                "declared_globals": sorted(ctx.get("pattern_global_names") or []),
                "relations": [],
            }
            for relation in relations:
                if not relation.taints:
                    continue
                if relation.kind == "call_return_bridge":
                    detail = relation.detail or {}
                    callee_id = detail.get("callee_id")
                    info = detail.get("call_param_arg_info")
                    if callee_id is not None and isinstance(info, dict) and info:
                        try:
                            ctx.setdefault("pattern_func_param_arg_info", {})[int(callee_id)] = info
                        except Exception:
                            pass
                if not bool((relation.detail or {}).get("source_only")):
                    llm_seqs.add(int(relation.seq))
                else:
                    _add_source_only_result(ctx, relation)
                emitted = []
                for item in relation.taints:
                    for expanded in expand_param_bridge_taints(item, call_param_arg_info, prop_call_scopes_info):
                        if not isinstance(expanded, dict):
                            continue
                        if expanded.get("_pattern_param_bridge") and isinstance(call_param_arg_info, dict):
                            add_function_frame_locs(ctx, call_param_arg_info)
                        expanded = _apply_relation_scope_hint(expanded, item, relation)
                        _append_new_taint(ctx, expanded, relation)
                        if is_declared_global_taint(expanded, ctx) and not _same_taint_identity(expanded, current):
                            defer_global_taint(expanded, ctx)
                            emitted.append({**dict(expanded), "_deferred_global": True})
                            continue
                        _enqueue(next_queue, expanded, queued, seen)
                        emitted.append(dict(expanded))
                step_debug["relations"].append(
                    {
                        "kind": relation.kind,
                        "seq": int(relation.seq),
                        "detail": relation.detail or {},
                        "new_taints": emitted,
                    }
                )

            if (current.get("type") or "").strip() in ("AST_VAR", "AST_PROP", "AST_DIM"):
                try:
                    from taint_handlers.llm.utils import llm_byref
                except Exception:
                    llm_byref = None
                if llm_byref is not None:
                    try:
                        extra_calls = llm_byref.collect_byref_call_taints_for_var(current, scope_seqs, ctx) or []
                    except Exception:
                        extra_calls = []
                    for item in extra_calls:
                        pseudo_relation = type("PseudoRelation", (), {"kind": "byref_call", "seq": int(item.get("seq") or tseq)})()
                        _append_new_taint(ctx, item, pseudo_relation)
                        if is_declared_global_taint(item, ctx) and not _same_taint_identity(item, current):
                            defer_global_taint(item, ctx)
                            emitted_item = {**dict(item), "_deferred_global": True}
                        else:
                            _enqueue(next_queue, item, queued, seen)
                            emitted_item = dict(item)
                        step_debug["relations"].append(
                            {
                                "kind": "byref_call",
                                "seq": int(item.get("seq") or tseq),
                                "detail": {},
                                "new_taints": [emitted_item],
                            }
                        )
            round_debug.append(step_debug)

        _write_pattern_debug(
            ctx,
            f"round_{int(round_no):03d}.json",
            {
                "round": int(round_no),
                "queue": "A" if use_a else "B",
                "steps": round_debug,
                "queued_next": [_taint_brief(x) for x in (next_queue or [])],
            },
        )
        if use_a:
            pre_b = next_queue
            use_a = False
        else:
            pre_a = next_queue
            use_a = True

    ctx["symbolic_prompt_seqs"] = merge_assignment_call_scopes_into_prompt_seqs(ctx)
    _write_pattern_debug(
        ctx,
        "summary.json",
        {
            "symbolic_prompt_seqs": list(ctx.get("symbolic_prompt_seqs") or []),
            "assignment_rhs_call_scope_merge": dict(ctx.get("_assignment_rhs_call_scope_merge") or {}),
            "source_only_locs": list(ctx.get("pattern_source_locs") or []),
            "declared_globals": sorted(ctx.get("pattern_global_names") or []),
            "new_taints": list(ctx.get("llm_new_taints") or []),
        },
    )
    return []
