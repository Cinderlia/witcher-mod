from typing import List, Optional, Tuple

from .llm_loop_utils import _taint_brief, _taint_scope_key


def _resolve_this_context(meta: dict, ctx: dict, calls_edges_union: dict) -> Tuple[str, Optional[int]]:
    this_obj = meta.get('this_obj') or ''
    this_call_seq = meta.get('this_call_seq')
    tseq = meta.get('tseq')

    start_seq = None
    if this_call_seq is not None:
        try:
            start_seq = int(this_call_seq)
        except Exception:
            start_seq = None
    if start_seq is None and tseq is not None:
        try:
            start_seq = int(tseq)
        except Exception:
            start_seq = None

    if start_seq is not None:
        try:
            from . import ast_var
            from utils.cpg_utils.graph_mapping import resolve_this_object_chain

            nodes = ctx.get('nodes') or {}
            children_of = ctx.get('children_of') or {}

            ast_var.ensure_trace_index(ctx)
            recs = ctx.get('trace_index_records') or []
            seq_to_idx = ctx.get('trace_seq_to_index') or {}
            start_index = seq_to_idx.get(int(start_seq))
            if isinstance(start_index, int) and 0 <= start_index < len(recs):
                chain = resolve_this_object_chain(
                    records=recs,
                    nodes=nodes,
                    children_of=children_of,
                    calls_edges_union=calls_edges_union,
                    start_index=int(start_index),
                )
                if isinstance(chain, dict):
                    resolved_obj = (chain.get('obj') or '').strip()
                    if resolved_obj:
                        this_obj = resolved_obj
                    resolved_call_seq = chain.get('resolved_call_seq')
                    try:
                        resolved_call_seq_i = int(resolved_call_seq) if resolved_call_seq is not None else None
                    except Exception:
                        resolved_call_seq_i = None
                    if resolved_call_seq_i is not None:
                        this_call_seq = int(resolved_call_seq_i)
        except Exception:
            pass

    try:
        this_call_seq_i = int(this_call_seq) if this_call_seq is not None else None
    except Exception:
        this_call_seq_i = None
    return this_obj, this_call_seq_i


def _init_meta_debug(meta: dict, parsed: dict, this_obj: str) -> dict:
    call_index = meta.get('call_index')
    return {
        'call_index': call_index,
        'input': {
            'tid': meta.get('tid'),
            'tseq': meta.get('tseq'),
            'type': meta.get('tt') or '',
            'name': meta.get('nm') or '',
            'this_obj': this_obj,
            'this_call_seq': meta.get('this_call_seq'),
        },
        'llm_taints_raw': parsed.get('taints') or [],
        'llm_intermediates_raw': parsed.get('intermediates') or [],
        'llm_edges_raw': parsed.get('edges') or [],
        'variants': [],
        'expanded_components': [],
        'candidate_status': [],
        'enqueue': [],
    }


def _update_llm_scope_tracking(
    meta: dict,
    *,
    parsed: dict,
    this_obj: str,
    ctx: dict,
) -> set:
    t = meta.get('t') or {}
    tt = meta.get('tt') or ''
    prompt_scope_set = meta.get('prompt_scope_set') or set()

    call_index = meta.get('call_index')
    llm_scope_set = set(prompt_scope_set)
    if call_index is not None and llm_scope_set:
        this_call_seq = meta.get('this_call_seq')
        if this_obj and this_call_seq is not None:
            if tt in ('AST_PROP', 'AST_DIM'):
                raw_name = (t.get('name') or '').strip()
                raw_base = (t.get('base') or '').strip()
                if (
                    raw_base in ('this', '$this')
                    or raw_name.startswith('this->')
                    or raw_name.startswith('$this->')
                    or raw_name.startswith('this.')
                    or raw_name.startswith('$this.')
                    or raw_name.startswith('this[')
                    or raw_name.startswith('$this[')
                ):
                    llm_scope_set.add(int(this_call_seq))
            elif tt == 'AST_METHOD_CALL':
                raw_items = (parsed.get('taints') or []) + (parsed.get('intermediates') or [])
                for rt in raw_items:
                    if not isinstance(rt, dict):
                        continue
                    rtt = (rt.get('type') or '').strip()
                    if rtt not in ('AST_PROP', 'AST_DIM'):
                        continue
                    rnm = (rt.get('name') or '').strip()
                    if (
                        rnm.startswith('this->')
                        or rnm.startswith('$this->')
                        or rnm.startswith('this.')
                        or rnm.startswith('$this.')
                        or rnm.startswith('this[')
                        or rnm.startswith('$this[')
                    ):
                        llm_scope_set.add(int(this_call_seq))
                        break
        ctx.setdefault('llm_scopes', []).append(sorted(llm_scope_set))
    return llm_scope_set


def _add_llm_returned_seqs_to_set(parsed: dict, llm_seqs: set) -> None:
    for s in parsed.get('seqs') or []:
        try:
            llm_seqs.add(int(s))
        except Exception:
            pass
    for it in (parsed.get('taints') or []) + (parsed.get('intermediates') or []):
        if not isinstance(it, dict):
            continue
        try:
            llm_seqs.add(int(it.get('seq')))
        except Exception:
            pass


def _log_llm_variants(meta_debug: dict, parsed: dict, ctx: dict, this_obj: str) -> None:
    try:
        from ..core.llm_response import _llm_item_variants, _map_llm_item_to_node

        for rt in parsed.get('taints') or []:
            if not isinstance(rt, dict):
                continue
            vs = _llm_item_variants(rt, ctx, this_obj=this_obj)
            vdbg = []
            for v in vs:
                mapped_v = _map_llm_item_to_node(v, ctx, this_obj=this_obj)
                vdbg.append({'variant': v, 'mapped': mapped_v})
            meta_debug['variants'].append({'raw': rt, 'variants': vdbg})
    except Exception:
        pass


def _map_llm_response(parsed: dict, ctx: dict, this_obj: str) -> Tuple[List, List]:
    from ..core.llm_response import map_llm_taints_to_nodes

    mapped_taints = map_llm_taints_to_nodes(parsed.get('taints') or [], ctx, this_obj=this_obj)
    mapped_intermediates = map_llm_taints_to_nodes(parsed.get('intermediates') or [], ctx, this_obj=this_obj)
    return mapped_taints, mapped_intermediates


def _append_llm_intermediates(ctx: dict, items: list, this_obj: str) -> None:
    if not isinstance(ctx, dict) or not isinstance(items, list) or not items:
        return
    from ..core.llm_response import _rewrite_this_prefix

    out = ctx.get('llm_intermediates')
    if not isinstance(out, list):
        out = []
        ctx['llm_intermediates'] = out
    seen = ctx.get('_llm_intermediates_seen')
    if not isinstance(seen, set):
        seen = set()
        ctx['_llm_intermediates_seen'] = seen
    for it in items:
        if not isinstance(it, dict):
            continue
        iid = it.get('id')
        iseq = it.get('seq')
        if iid is None or iseq is None:
            continue
        try:
            k = (int(iid), int(iseq), (it.get('type') or '').strip())
        except Exception:
            continue
        if k in seen:
            continue
        seen.add(k)
        rec = dict(it)
        if this_obj and isinstance(rec.get('name'), str) and rec.get('name'):
            rec['name'] = _rewrite_this_prefix(rec.get('name') or '', this_obj)
        out.append(rec)


def _update_llm_graph(
    *,
    mapped_edges: list,
    llm_edges: list,
    llm_edges_seen: set,
    llm_incoming: dict,
    this_obj: str,
) -> None:
    from ..core.llm_response import _rewrite_this_prefix

    for me in mapped_edges:
        src = me.get('src') or {}
        dst = me.get('dst') or {}
        sk = (int(src.get('id')), int(src.get('seq')))
        dk = (int(dst.get('id')), int(dst.get('seq')))
        ek = (sk, dk)
        if ek not in llm_edges_seen:
            llm_edges_seen.add(ek)
            if this_obj:
                llm_edges.append(
                    {
                        'src': {**src, 'name': _rewrite_this_prefix(src.get('name') or '', this_obj)},
                        'dst': {**dst, 'name': _rewrite_this_prefix(dst.get('name') or '', this_obj)},
                    }
                )
            else:
                llm_edges.append(me)
        inc = llm_incoming.get(dk)
        if inc is None:
            inc = set()
            llm_incoming[dk] = inc
        inc.add(sk)


def _build_candidate(mapped_nodes: list, mapped_edges: list) -> dict:
    candidate = {}
    for nt in mapped_nodes:
        nid = nt.get('id')
        nseq = nt.get('seq')
        if nid is None or nseq is None:
            continue
        candidate[(int(nid), int(nseq))] = nt
    for me in mapped_edges:
        for side in ('src', 'dst'):
            nt = me.get(side) or {}
            nid = nt.get('id')
            nseq = nt.get('seq')
            if nid is None or nseq is None:
                continue
            candidate.setdefault((int(nid), int(nseq)), nt)
    return candidate


def _expand_candidate_components(candidate: dict, ctx: dict, this_obj: str, meta_debug: dict) -> dict:
    from ..core.llm_response import _expand_var_components

    candidate2 = dict(candidate)
    for nt in list(candidate.values()):
        ntt = (nt.get('type') or '').strip()
        if ntt not in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
            continue
        comps = list(_expand_var_components(nt, ctx, this_obj=this_obj) or [])
        if comps:
            meta_debug['expanded_components'].append({'from': _taint_brief(nt), 'components': comps})
        for comp in comps:
            cid = comp.get('id')
            cseq = comp.get('seq')
            if cid is None or cseq is None:
                continue
            try:
                ck = (int(cid), int(cseq))
            except Exception:
                continue
            candidate2.setdefault(ck, comp)
    return candidate2


def _select_leaf_nodes(
    *,
    candidate: dict,
    key,
    llm_incoming: dict,
    ctx: dict,
    calls_edges_union: dict,
    this_obj: str,
) -> Tuple[List, dict, int, int]:
    leaf_nodes = []
    call_kept = 0
    call_dropped = 0
    drop_reason = {}
    for nk, nt in candidate.items():
        if nk == key:
            drop_reason[nk] = 'self'
            continue
        ntt = (nt.get('type') or '').strip()
        if ntt in ('AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL'):
            cid = nt.get('id')
            if cid is None:
                drop_reason[nk] = 'call_missing_id'
                continue
            if calls_edges_union.get(int(cid)) or []:
                leaf_nodes.append(nt)
                call_kept += 1
                drop_reason[nk] = 'leaf'
            else:
                call_dropped += 1
                drop_reason[nk] = 'call_no_calls_edge'
            continue
        leaf_nodes.append(nt)
        drop_reason[nk] = 'leaf'
    return leaf_nodes, drop_reason, call_kept, call_dropped


def _maybe_extend_leaf_nodes_byref(leaf_nodes: list, llm_scope_set: set, ctx: dict, lg) -> None:
    try:
        from . import llm_byref

        extra_calls = []
        for nt in leaf_nodes:
            ntt = (nt.get('type') or '').strip()
            if ntt not in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
                continue
            extra_calls.extend(llm_byref.collect_byref_call_taints_for_var(nt, llm_scope_set, ctx) or [])
        if extra_calls:
            existing = set()
            for it in leaf_nodes:
                iid = it.get('id')
                iseq = it.get('seq')
                if iid is None or iseq is None:
                    continue
                try:
                    existing.add((int(iid), int(iseq)))
                except Exception:
                    continue
            added_byref = 0
            for ct in extra_calls:
                cid = ct.get('id')
                cseq = ct.get('seq')
                if cid is None or cseq is None:
                    continue
                try:
                    ck = (int(cid), int(cseq))
                except Exception:
                    continue
                if ck in existing:
                    continue
                existing.add(ck)
                leaf_nodes.append(ct)
                added_byref += 1
            if lg is not None and added_byref:
                lg.info('llm_byref_enqueued_calls', count=added_byref)
    except Exception:
        pass


def _record_candidate_status(
    *,
    meta_debug: dict,
    candidate: dict,
    drop_reason: dict,
    llm_incoming: dict,
    ctx: dict,
    this_obj: str,
) -> None:
    from ..core.llm_response import _rewrite_this_prefix, effective_llm_incoming_sources

    try:
        for nk, nt in candidate.items():
            nid = nt.get('id')
            nseq = nt.get('seq')
            if nid is None or nseq is None:
                continue
            nm0 = nt.get('name')
            if this_obj and isinstance(nm0, str) and nm0:
                nm0 = _rewrite_this_prefix(nm0, this_obj)
            rk = (int(nid), int(nseq))
            r = drop_reason.get(rk) or 'unknown'
            it = {
                'id': int(nid),
                'seq': int(nseq),
                'type': (nt.get('type') or '').strip(),
                'name': nm0,
                'status': 'leaf' if r == 'leaf' else 'dropped',
                'reason': r,
            }
            if r == 'has_incoming_edge':
                inc = effective_llm_incoming_sources(nt, rk, llm_incoming, ctx)
                if inc:
                    inc2 = []
                    for sk in sorted(inc):
                        try:
                            inc2.append({'id': int(sk[0]), 'seq': int(sk[1])})
                        except Exception:
                            continue
                    if inc2:
                        it['incoming_from'] = inc2[:10]
            meta_debug['candidate_status'].append(it)
    except Exception:
        pass


def _record_round_dropped(
    round_dropped: list,
    *,
    candidate: dict,
    leaf_nodes: list,
    key,
) -> None:
    leaf_keys = set()
    for nt in leaf_nodes:
        nid = nt.get('id')
        nseq = nt.get('seq')
        if nid is None or nseq is None:
            continue
        leaf_keys.add((int(nid), int(nseq)))
    for dk in sorted((set(candidate.keys()) - leaf_keys - {key}) if key is not None else (set(candidate.keys()) - leaf_keys)):
        bt = _taint_brief(candidate.get(dk) or {})
        if bt:
            round_dropped.append(bt)


def _enqueue_leaf_nodes(
    *,
    leaf_nodes: list,
    meta: dict,
    ctx: dict,
    useA: bool,
    preA: list,
    preB: list,
    nodes: dict,
    children_of: dict,
    seen: set,
    queued: set,
    seen_scope: set,
    queued_scope: set,
    llm_new_seen: set,
    append_llm_new_taint,
    meta_debug: dict,
) -> Tuple[int, int, int]:
    from ..core.llm_response import _rewrite_this_prefix
    from .llm_loop_utils import _taint_display

    target_q = preB if useA else preA
    added = 0
    skipped_seen = 0
    skipped_queued = 0
    this_obj = meta.get('this_obj') or ''
    this_call_seq = meta.get('this_call_seq')
    call_param_arg_info = meta.get('call_param_arg_info')
    prop_call_scopes_info = meta.get('prop_call_scopes_info')

    def _pick_prop_call_scope_for_leaf(nt: dict) -> Optional[dict]:
        if not isinstance(prop_call_scopes_info, list) or not prop_call_scopes_info:
            return None
        try:
            from .llm_prop_scope import pick_innermost_scope
        except Exception:
            pick_innermost_scope = None

        s0 = None
        try:
            s0 = int(nt.get('seq'))
        except Exception:
            s0 = None

        if pick_innermost_scope is not None and s0 is not None:
            try:
                sc = pick_innermost_scope(prop_call_scopes_info, s0)
            except Exception:
                sc = None
            if isinstance(sc, dict):
                return sc

        nid = nt.get('id')
        if nid is None:
            return None
        try:
            nid_i = int(nid)
        except Exception:
            return None
        funcid = (nodes.get(nid_i) or {}).get('funcid')
        if funcid is None:
            return None
        try:
            funcid_i = int(funcid)
        except Exception:
            return None

        cand = []
        for sc in prop_call_scopes_info:
            if not isinstance(sc, dict):
                continue
            try:
                if int(sc.get('callee_id')) == funcid_i:
                    cand.append(sc)
            except Exception:
                continue
        if not cand:
            return None

        def _score(sc: dict) -> Tuple[int, int, int, int]:
            try:
                lo = int(sc.get('min_seq'))
                hi = int(sc.get('max_seq'))
            except Exception:
                lo = 0
                hi = 10**18
            span = (hi - lo) if hi >= lo else 10**18
            d_call = 10**18
            d_def = 10**18
            if s0 is not None:
                try:
                    d_call = abs(int(sc.get('call_seq')) - s0)
                except Exception:
                    d_call = 10**18
                try:
                    d_def = abs(int(sc.get('def_seq')) - s0)
                except Exception:
                    d_def = 10**18
            try:
                call_seq = int(sc.get('call_seq') or 0)
            except Exception:
                call_seq = 0
            return span, d_call, d_def, call_seq

        cand.sort(key=_score)
        return cand[0]

    def _sorted_children(nid: int) -> List[int]:
        ch = list(children_of.get(int(nid), []) or [])
        try:
            ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
        except Exception:
            pass
        out = []
        for c in ch:
            try:
                out.append(int(c))
            except Exception:
                pass
        return out

    def _collect_dim_index_taints(dim_id: int, seq: int) -> List[dict]:
        from ..core.llm_response import _node_display

        try:
            dim_i = int(dim_id)
            seq_i = int(seq)
        except Exception:
            return []
        ch = _sorted_children(dim_i)
        if len(ch) < 2:
            return []
        roots = ch[1:]
        allowed = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL'}
        out = []
        seen_ids = set()
        q = list(roots)
        while q:
            x = q.pop()
            if x in seen_ids:
                continue
            seen_ids.add(x)
            tt = (nodes.get(x) or {}).get('type') or ''
            tt = tt.strip()
            if tt in allowed:
                _, nm = _node_display(x, nodes, children_of)
                rec = {'id': int(x), 'seq': seq_i, 'type': tt}
                if nm:
                    rec['name'] = (nm or '').replace('.', '->')
                out.append(rec)
            for c in children_of.get(x, []) or []:
                try:
                    q.append(int(c))
                except Exception:
                    pass
        return out

    def _normalize_leaf_nodes_complex_vars(items: list) -> list:
        from ..splits.llm_var_split import ast_dim_base_root_id, ast_enclosing_prop_id

        parent_of = (ctx.get('parent_of') or {}) if isinstance(ctx, dict) else {}
        out = []
        for it in items or []:
            tt = (it.get('type') or '').strip()
            if tt == 'AST_VAR':
                nid = it.get('id')
                nseq = it.get('seq')
                if nid is None or nseq is None:
                    out.append(it)
                    continue
                try:
                    prop_id = ast_enclosing_prop_id(int(nid), parent_of, nodes)
                except Exception:
                    prop_id = None
                if prop_id is not None:
                    try:
                        seq_i = int(nseq)
                    except Exception:
                        out.append(it)
                        continue
                    out.append({'id': int(prop_id), 'seq': seq_i, 'type': 'AST_PROP'})
                    continue
                out.append(it)
                continue
            if tt != 'AST_DIM':
                out.append(it)
                continue
            nid = it.get('id')
            nseq = it.get('seq')
            if nid is None or nseq is None:
                out.append(it)
                continue
            try:
                base_id = ast_dim_base_root_id(int(nid), children_of, nodes)
            except Exception:
                base_id = None
            base_t = (nodes.get(base_id) or {}).get('type') if base_id is not None else None
            if (base_t or '').strip() != 'AST_PROP':
                out.append(it)
                continue
            try:
                seq_i = int(nseq)
            except Exception:
                out.append(it)
                continue
            out.append({'id': int(base_id), 'seq': seq_i, 'type': 'AST_PROP'})
            out.extend(_collect_dim_index_taints(int(nid), seq_i))
        return out

    leaf_nodes = _normalize_leaf_nodes_complex_vars(leaf_nodes)
    leaf_nodes2 = []
    seen_leaf = set()
    for nt0 in leaf_nodes:
        ntt0 = (nt0.get('type') or '').strip()
        if ntt0 not in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
            leaf_nodes2.append(nt0)
            continue
        try:
            seq0 = int(nt0.get('seq'))
        except Exception:
            leaf_nodes2.append(nt0)
            continue
        tt0, nm0 = _taint_display(nt0, nodes, children_of)
        if this_obj:
            nm0 = _rewrite_this_prefix(nm0 or '', this_obj)
        nm0 = (nm0 or '').replace('.', '->').strip()
        if tt0 == 'AST_VAR' and nm0.startswith('$'):
            nm0 = nm0[1:]
        k0 = (seq0, tt0, nm0)
        if k0 in seen_leaf:
            continue
        seen_leaf.add(k0)
        leaf_nodes2.append(nt0)
    leaf_nodes = leaf_nodes2
    def _should_write_this_call_seq(nt: dict, eff_this_obj0: str) -> bool:
        if not isinstance(nt, dict):
            return False
        if not (eff_this_obj0 or '').strip():
            return False
        ntt = (nt.get('type') or '').strip()
        if ntt not in ('AST_PROP', 'AST_METHOD_CALL'):
            return False
        nid = nt.get('id')
        if nid is None:
            return False
        try:
            from ..core.llm_response import _node_source_str_with_this
        except Exception:
            _node_source_str_with_this = None
        if _node_source_str_with_this is None:
            return False
        try:
            nid_i = int(nid)
        except Exception:
            return False
        raw = (_node_source_str_with_this(nid_i, ntt, nodes, children_of, '') or '').replace('.', '->').strip()
        if not raw:
            return False
        if ntt == 'AST_PROP':
            return raw.startswith(('this->', '$this->', 'this[', '$this[', 'this.', '$this.'))
        return raw.startswith(('this->', '$this->', 'this.', '$this.'))
    for nt in leaf_nodes:
        enqueue_dbg = {
            'leaf': _taint_brief(nt),
            'action': '',
            'queue': '',
            'reason': '',
        }
        eff_this_obj = this_obj
        eff_this_call_seq = this_call_seq
        if not isinstance(call_param_arg_info, dict) and isinstance(prop_call_scopes_info, list):
            sc = _pick_prop_call_scope_for_leaf(nt) if isinstance(nt, dict) else None
            if isinstance(sc, dict):
                if not eff_this_obj:
                    eff_this_obj = (sc.get('this_obj') or '').strip()
                if eff_this_call_seq is None:
                    try:
                        eff_this_call_seq = int(sc.get('root_call_seq'))
                    except Exception:
                        eff_this_call_seq = None
                scoped_info = sc.get('call_param_arg_info')
                if isinstance(scoped_info, dict):
                    from taint_handlers import ast_method_call

                    repl, dbg = ast_method_call.convert_param_based_taint_to_call_arg_taint(nt, scoped_info)
                    if dbg is not None:
                        lg = meta.get('_lg')
                        if lg is not None:
                            try:
                                lg.debug(
                                    'llm_param_to_arg',
                                    call_id=scoped_info.get('call_id'),
                                    call_seq=scoped_info.get('call_seq'),
                                    callee_id=scoped_info.get('callee_id'),
                                    **dbg,
                                )
                            except Exception:
                                pass
                        if repl is None:
                            enqueue_dbg['action'] = 'dropped'
                            enqueue_dbg['reason'] = 'param_to_arg_filtered'
                            enqueue_dbg['detail'] = dbg
                            meta_debug['enqueue'].append(enqueue_dbg)
                            continue
                        enqueue_dbg['action'] = 'param_to_arg_rewrite'
                        enqueue_dbg['detail'] = dbg
                        nt = repl
                        if eff_this_call_seq is not None and _should_write_this_call_seq(nt, eff_this_obj):
                            nt['_this_call_seq'] = int(eff_this_call_seq)

        if isinstance(call_param_arg_info, list):
            from taint_handlers import ast_method_call

            for info in call_param_arg_info:
                if not isinstance(info, dict):
                    continue
                repl, dbg = ast_method_call.convert_param_based_taint_to_call_arg_taint(nt, info)
                if dbg is None:
                    continue
                lg = meta.get('_lg')
                if lg is not None:
                    try:
                        lg.debug(
                            'llm_param_to_arg',
                            call_id=info.get('call_id'),
                            call_seq=info.get('call_seq'),
                            callee_id=info.get('callee_id'),
                            **dbg,
                        )
                    except Exception:
                        pass
                if repl is None:
                    enqueue_dbg['action'] = 'dropped'
                    enqueue_dbg['reason'] = 'param_to_arg_filtered'
                    enqueue_dbg['detail'] = dbg
                    meta_debug['enqueue'].append(enqueue_dbg)
                    nt = None
                    break
                enqueue_dbg['action'] = 'param_to_arg_rewrite'
                enqueue_dbg['detail'] = dbg
                nt = repl
                if eff_this_call_seq is None:
                    try:
                        eff_this_call_seq = int(info.get('call_seq'))
                    except Exception:
                        eff_this_call_seq = None
                break
            if nt is None:
                continue

        if isinstance(call_param_arg_info, dict):
            from taint_handlers import ast_method_call

            repl, dbg = ast_method_call.convert_param_based_taint_to_call_arg_taint(nt, call_param_arg_info)
            if dbg is not None:
                lg = meta.get('_lg')
                if lg is not None:
                    lg.debug(
                        'llm_param_to_arg',
                        call_id=call_param_arg_info.get('call_id'),
                        call_seq=call_param_arg_info.get('call_seq'),
                        callee_id=call_param_arg_info.get('callee_id'),
                        **dbg,
                    )
                if repl is None:
                    enqueue_dbg['action'] = 'dropped'
                    enqueue_dbg['reason'] = 'param_to_arg_filtered'
                    enqueue_dbg['detail'] = dbg
                    meta_debug['enqueue'].append(enqueue_dbg)
                    continue
                enqueue_dbg['action'] = 'param_to_arg_rewrite'
                enqueue_dbg['detail'] = dbg
                nt = repl

        nid = nt.get('id')
        nseq = nt.get('seq')
        if nid is None or nseq is None:
            enqueue_dbg['action'] = 'dropped'
            enqueue_dbg['reason'] = 'missing_id_or_seq'
            meta_debug['enqueue'].append(enqueue_dbg)
            continue
        k2 = (int(nid), int(nseq))
        scope_k2 = _taint_scope_key(nt, nodes, children_of, eff_this_obj)
        if scope_k2 is not None and scope_k2 in seen_scope:
            skipped_seen += 1
            enqueue_dbg['action'] = 'skipped'
            enqueue_dbg['reason'] = 'seen_scope'
            meta_debug['enqueue'].append(enqueue_dbg)
            continue
        if k2 in seen:
            skipped_seen += 1
            enqueue_dbg['action'] = 'skipped'
            enqueue_dbg['reason'] = 'seen'
            meta_debug['enqueue'].append(enqueue_dbg)
            continue
        if scope_k2 is not None and scope_k2 in queued_scope:
            skipped_queued += 1
            enqueue_dbg['action'] = 'skipped'
            enqueue_dbg['reason'] = 'queued_scope'
            meta_debug['enqueue'].append(enqueue_dbg)
            continue
        if k2 in queued:
            skipped_queued += 1
            enqueue_dbg['action'] = 'skipped'
            enqueue_dbg['reason'] = 'queued'
            meta_debug['enqueue'].append(enqueue_dbg)
            continue
        queued.add(k2)
        if scope_k2 is not None:
            queued_scope.add(scope_k2)
        ntq = dict(nt)
        if eff_this_obj:
            ntq['_this_obj'] = eff_this_obj
            if eff_this_call_seq is not None and _should_write_this_call_seq(nt, eff_this_obj):
                base_seq = None
                try:
                    base_seq = int(eff_this_call_seq)
                except Exception:
                    base_seq = None
                if base_seq is not None:
                    cur_seq = None
                    try:
                        cur_seq = int(nt.get('_this_call_seq'))
                    except Exception:
                        cur_seq = None
                    ntq['_this_call_seq'] = min(cur_seq, base_seq) if cur_seq is not None else base_seq
        scope_only = meta.get('scope_only_seqs')
        if scope_only:
            try:
                from llm_utils.scope.scope_opt import record_parent_scope_for_enqueued_taint

                record_parent_scope_for_enqueued_taint(ctx=ctx, taint_key=(int(nid), int(nseq)), parent_scope=scope_only)
            except Exception:
                pass
        target_q.append(ntq)
        added += 1
        enqueue_dbg['action'] = 'enqueued'
        enqueue_dbg['queue'] = ('B' if useA else 'A')
        meta_debug['enqueue'].append(enqueue_dbg)
        k3 = (int(nid), int(nseq), nt.get('type') or '', nt.get('name') or '', this_obj or '')
        if k3 not in llm_new_seen:
            llm_new_seen.add(k3)
            if this_obj:
                disp = dict(ntq)
                disp.pop('_this_obj', None)
                disp['name'] = _rewrite_this_prefix(disp.get('name') or '', this_obj)
                append_llm_new_taint(disp)
            else:
                append_llm_new_taint(ntq)
    return added, skipped_seen, skipped_queued


def _update_qstats(qstats: dict, *, useA: bool, added: int, skipped_seen: int, skipped_queued: int) -> None:
    if useA:
        qstats['enqueued_to_B'] = int(qstats.get('enqueued_to_B') or 0) + added
    else:
        qstats['enqueued_to_A'] = int(qstats.get('enqueued_to_A') or 0) + added
    qstats['skipped_seen'] = int(qstats.get('skipped_seen') or 0) + skipped_seen
    qstats['skipped_queued'] = int(qstats.get('skipped_queued') or 0) + skipped_queued


def _should_stop_due_to_max_calls(ctx: dict, llm_calls: int, llm_max_calls, lg) -> bool:
    stop_due_to_max_calls = False
    if llm_max_calls is not None:
        try:
            if llm_calls >= int(llm_max_calls):
                if lg is not None:
                    lg.warning('llm_stop_after_max_calls', llm_calls=llm_calls, llm_max_calls=llm_max_calls)
                    lg.log_json(
                        'INFO',
                        'llm_partial_summary',
                        {
                            'result_set_count': len(ctx.get('result_set') or []),
                            'llm_result_seqs': sorted(int(x) for x in (ctx.get('llm_result_seqs') or set()) if str(x).isdigit()),
                            'llm_new_taints': ctx.get('llm_new_taints') or [],
                            'llm_edges': ctx.get('llm_edges') or [],
                        },
                    )
                    stop_due_to_max_calls = True
        except Exception:
            pass
    return bool(stop_due_to_max_calls)


def _process_llm_round_meta(
    meta: dict,
    *,
    ctx,
    useA: bool,
    preA,
    preB,
    processed,
    round_dropped: list,
    seen: set,
    queued: set,
    seen_scope: set,
    queued_scope: set,
    llm_seqs: set,
    llm_edges: list,
    llm_edges_seen: set,
    llm_incoming: dict,
    llm_new_seen: set,
    append_llm_new_taint,
    qstats: dict,
    calls_edges_union: dict,
    lg,
) -> bool:
    from llm_utils.taint.taint_json import parse_llm_taint_response

    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    llm_max_calls = ctx.get('llm_max_calls')
    llm_calls = ctx.get('_llm_call_count', 0)

    resp_txt = meta.get('resp_txt') or ''

    this_obj, this_call_seq = _resolve_this_context(meta, ctx, calls_edges_union)
    meta = dict(meta)
    meta['this_obj'] = this_obj
    meta['this_call_seq'] = this_call_seq
    parsed = parse_llm_taint_response(resp_txt) if resp_txt else {'taints': [], 'intermediates': [], 'edges': [], 'seqs': []}
    if lg is not None:
        lg.log_json('DEBUG', 'llm_parsed', parsed)

    meta_debug = _init_meta_debug(meta, parsed, this_obj)

    llm_scope_set = _update_llm_scope_tracking(meta, parsed=parsed, this_obj=this_obj, ctx=ctx)
    _add_llm_returned_seqs_to_set(parsed, llm_seqs)
    _log_llm_variants(meta_debug, parsed, ctx, this_obj)

    mapped_taints, mapped_intermediates = _map_llm_response(parsed, ctx, this_obj)
    if lg is not None:
        lg.log_json('DEBUG', 'llm_mapped_taints', mapped_taints)
        lg.log_json('DEBUG', 'llm_mapped_intermediates', mapped_intermediates)

    _append_llm_intermediates(ctx, mapped_intermediates, this_obj)

    mapped_edges = []
    candidate = _build_candidate(mapped_taints, mapped_edges)
    candidate = _expand_candidate_components(candidate, ctx, this_obj, meta_debug)

    leaf_nodes, drop_reason, call_kept, call_dropped = _select_leaf_nodes(
        candidate=candidate,
        key=meta.get('key'),
        llm_incoming=llm_incoming,
        ctx=ctx,
        calls_edges_union=calls_edges_union,
        this_obj=this_obj,
    )
    if lg is not None:
        lg.log_json('DEBUG', 'llm_leaf_nodes', leaf_nodes)

    _maybe_extend_leaf_nodes_byref(leaf_nodes, llm_scope_set, ctx, lg)
    _record_candidate_status(
        meta_debug=meta_debug,
        candidate=candidate,
        drop_reason=drop_reason,
        llm_incoming=llm_incoming,
        ctx=ctx,
        this_obj=this_obj,
    )
    _record_round_dropped(round_dropped, candidate=candidate, leaf_nodes=leaf_nodes, key=meta.get('key'))

    meta2 = dict(meta)
    meta2['_lg'] = lg
    added, skipped_seen, skipped_queued = _enqueue_leaf_nodes(
        leaf_nodes=leaf_nodes,
        meta=meta2,
        ctx=ctx,
        useA=useA,
        preA=preA,
        preB=preB,
        nodes=nodes,
        children_of=children_of,
        seen=seen,
        queued=queued,
        seen_scope=seen_scope,
        queued_scope=queued_scope,
        llm_new_seen=llm_new_seen,
        append_llm_new_taint=append_llm_new_taint,
        meta_debug=meta_debug,
    )
    _update_qstats(qstats, useA=useA, added=added, skipped_seen=skipped_seen, skipped_queued=skipped_queued)
    if lg is not None:
        lg.info(
            'queue_diffusion',
            from_queue=('A' if useA else 'B'),
            to_queue=('B' if useA else 'A'),
            leaf_count=len(leaf_nodes),
            candidate_count=len(candidate),
            mapped_nodes_count=len(mapped_taints),
            mapped_edges_count=len(mapped_edges),
            call_kept=call_kept,
            call_dropped=call_dropped,
            added=added,
            skipped_seen=skipped_seen,
            skipped_queued=skipped_queued,
            preA_len=len(preA),
            preB_len=len(preB),
        )

    stop_due_to_max_calls = _should_stop_due_to_max_calls(ctx, llm_calls, llm_max_calls, lg)

    try:
        ctx['_llm_round_debug'].append(meta_debug)
    except Exception:
        pass

    return bool(stop_due_to_max_calls)
