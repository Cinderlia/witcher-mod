"""
LLM-assisted taint diffusion loop.

This module wraps the rule-based taint handlers to build scoped code blocks and
ask an LLM for additional influencing taints and dataflow edges. Returned items
are mapped back to CPG nodes and enqueued for further expansion.
"""

import os
from typing import Optional, Set, Tuple

from taint_handlers import REGISTRY

from ..utils.llm_loop_utils import (
    _get_logger,
    _llm_replay_path,
    _queue_brief,
    _run_coros_limited,
    _taint_brief,
    _taint_display,
    _taint_scope_key,
    _try_read_text,
    _write_llm_round_file,
)

from ..utils.llm_round_meta import _process_llm_round_meta

def _has_valid_llm_json(text: str) -> bool:
    try:
        from llm_utils.taint.taint_json import llm_taint_response_has_valid_json
        return bool(llm_taint_response_has_valid_json(text))
    except Exception:
        return False


def _ensure_llm_offline_and_client(ctx: dict, get_default_client):
    llm_offline = ctx.get('llm_offline')
    if llm_offline is None:
        llm_offline = False
    ctx['llm_offline'] = bool(llm_offline)

    client = ctx.get('llm_client')
    if client is None:
        if ctx.get('llm_offline'):
            client = None
            ctx['llm_client'] = None
            lg = ctx.get('logger') if isinstance(ctx, dict) else None
            if lg is not None:
                try:
                    lg.info(
                        'llm_client_init_state',
                        llm_offline=bool(ctx.get('llm_offline')),
                        llm_client_type=None,
                    )
                except Exception:
                    pass
            return None
        lg = ctx.get('logger') if isinstance(ctx, dict) else None
        try:
            client = get_default_client()
        except Exception:
            if lg is not None:
                try:
                    lg.exception('llm_client_init_failed')
                except Exception:
                    pass
            client = None
        ctx['llm_client'] = client
        if lg is not None:
            try:
                lg.info(
                    'llm_client_init_state',
                    llm_offline=bool(ctx.get('llm_offline')),
                    llm_client_type=(type(client).__name__ if client is not None else None),
                )
            except Exception:
                pass
    return client


def _ensure_calls_edges_union(ctx: dict) -> dict:
    calls_edges_union = ctx.get('calls_edges_union')
    if calls_edges_union is None:
        try:
            from taint_handlers.handlers.call import ast_method_call

            calls_edges_union = ast_method_call.read_calls_edges(os.getcwd())
        except Exception:
            calls_edges_union = {}
        ctx['calls_edges_union'] = calls_edges_union
    return calls_edges_union


def _make_append_llm_new_taint(llm_new: list, llm_new_minseq: dict, llm_new_key_to_index: dict, _norm_llm_name):
    def append_llm_new_taint(item: dict) -> None:
        if not isinstance(item, dict):
            return
        tt = (item.get('type') or '').strip()
        nm = (item.get('name') or '').strip()
        seq = item.get('seq')
        if tt in ('AST_VAR', 'AST_PROP', 'AST_DIM') and nm and isinstance(seq, int):
            if tt == 'AST_PROP':
                nm = nm.replace('.', '->')
            k = (tt, _norm_llm_name(nm))
            cur = llm_new_minseq.get(k)
            if cur is None or seq < int(cur):
                idx = llm_new_key_to_index.get(k)
                if isinstance(idx, int) and 0 <= idx < len(llm_new):
                    llm_new[idx] = item
                else:
                    llm_new_key_to_index[k] = len(llm_new)
                    llm_new.append(item)
                llm_new_minseq[k] = int(seq)
            return
        llm_new.append(item)

    return append_llm_new_taint


def _merge_prompt_locs(locs: list, extra_locs: list) -> list:
    if not extra_locs:
        return locs
    combined = []
    seen_loc = set()
    for x in list(locs) + list(extra_locs):
        if not x:
            continue
        if isinstance(x, dict):
            lk = x.get('loc')
            if not lk:
                p = x.get('path')
                ln = x.get('line')
                if p and ln is not None:
                    try:
                        lk = f"{p}:{int(ln)}"
                    except Exception:
                        lk = None
            seq = x.get('seq')
            try:
                seq_i = int(seq) if seq is not None else None
            except Exception:
                seq_i = None
            key = (lk, int(seq_i)) if (lk and seq_i is not None) else lk
            if not key or key in seen_loc:
                continue
            seen_loc.add(key)
        else:
            if x in seen_loc:
                continue
            seen_loc.add(x)
        combined.append(x)
    return combined


def _compute_this_context(t: dict, *, tseq, ctx: Optional[dict] = None, calls_edges_union: Optional[dict] = None):
    this_obj_hint = (t.get('recv') or '').strip() if (t.get('type') or '').strip() == 'AST_METHOD_CALL' else ''
    if not this_obj_hint:
        this_obj_hint = (t.get('_this_obj') or '').strip()
    if not this_obj_hint and (t.get('type') or '').strip() == 'AST_PROP':
        base = (t.get('base') or '').strip()
        if base:
            this_obj_hint = base.lstrip('$')
        else:
            nm = (t.get('name') or '').replace('.', '->').strip()
            if '->' in nm:
                this_obj_hint = (nm.split('->', 1)[0] or '').strip().lstrip('$')

    this_obj = (t.get('recv') or '').strip() if (t.get('type') or '').strip() == 'AST_METHOD_CALL' else ''
    if not this_obj:
        this_obj = (t.get('_this_obj') or '').strip()
    if not this_obj and (t.get('type') or '').strip() == 'AST_PROP':
        base = (t.get('base') or '').strip()
        if base:
            this_obj = base.lstrip('$')
        else:
            nm = (t.get('name') or '').replace('.', '->').strip()
            if '->' in nm:
                this_obj = (nm.split('->', 1)[0] or '').strip().lstrip('$')

    this_call_seq = t.get('_this_call_seq')
    if this_call_seq is not None:
        try:
            this_call_seq = int(this_call_seq)
        except Exception:
            this_call_seq = None
    if this_call_seq is None and (t.get('type') or '').strip() == 'AST_METHOD_CALL' and tseq is not None:
        try:
            this_call_seq = int(tseq)
        except Exception:
            this_call_seq = None
    if this_call_seq is None and (t.get('type') or '').strip() == 'AST_PROP' and tseq is not None:
        raw_base = (t.get('base') or '').strip()
        raw_name = (t.get('name') or '').replace('.', '->').strip()
        if raw_base in ('this', '$this') or raw_name.startswith(('this->', '$this->', 'this[', '$this[', 'this.', '$this.')):
            try:
                this_call_seq = int(tseq)
            except Exception:
                this_call_seq = None

    if isinstance(ctx, dict) and isinstance(calls_edges_union, dict):
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
        tt = (t.get('type') or '').strip()
        if start_seq is not None and tt in ('AST_PROP', 'AST_METHOD_CALL', 'AST_DIM'):
            this_obj_raw = (this_obj or '').strip()
            should_resolve = (not this_obj_raw) or (this_obj_raw.lstrip('$') == 'this')
            if should_resolve:
                try:
                    from . import ast_var
                    from utils.cpg_utils.graph_mapping import resolve_this_object_chain

                    ast_var.ensure_trace_index(ctx)
                    recs = ctx.get('trace_index_records') or []
                    seq_to_idx = ctx.get('trace_seq_to_index') or {}
                    start_index = seq_to_idx.get(int(start_seq))
                    if isinstance(start_index, int) and 0 <= start_index < len(recs):
                        chain = resolve_this_object_chain(
                            records=recs,
                            nodes=ctx.get('nodes') or {},
                            children_of=ctx.get('children_of') or {},
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

    return this_obj, this_call_seq, this_obj_hint


def _find_replay_response_for_round(ctx: dict, *, seq: int, node_id: int, round_no: int) -> Tuple[str, Optional[int]]:
    base_dir = ctx.get('test_dir') if isinstance(ctx, dict) else None
    base_dir = base_dir if base_dir else os.path.join(os.getcwd(), 'test')
    resp_dir = os.path.join(base_dir, 'llm', 'responses')
    suffix = f'_seq_{int(seq)}_id_{int(node_id)}.txt'
    try:
        prefix = f'round{int(round_no)}-response'
        for fn in os.listdir(resp_dir):
            if not isinstance(fn, str):
                continue
            if not (fn.startswith(prefix) and fn.endswith(suffix)):
                continue
            within = None
            try:
                mid = fn[len(prefix) :]
                if mid.startswith('.'):
                    mid = mid[1:]
                mid = mid.split('_seq_', 1)[0]
                within = int(mid)
            except Exception:
                within = None
            return os.path.join(resp_dir, fn), within
    except Exception:
        pass
    try:
        prefix = f'round{int(round_no)}-response'
        want = f'_seq_{int(seq)}_id_'
        best = None
        for fn in os.listdir(resp_dir):
            if not isinstance(fn, str):
                continue
            if not fn.startswith(prefix):
                continue
            if want not in fn:
                continue
            if not fn.endswith('.txt'):
                continue
            within = None
            try:
                mid = fn[len(prefix) :]
                if mid.startswith('.'):
                    mid = mid[1:]
                mid = mid.split('_seq_', 1)[0]
                within = int(mid)
            except Exception:
                within = None
            cand = (within if within is not None else 10**9, fn)
            if best is None or cand < best[0]:
                best = (cand, fn, within)
        if best is not None:
            _, fn, within = best
            return os.path.join(resp_dir, fn), within
    except Exception:
        pass
    try:
        return _llm_replay_path(ctx, 1, seq=seq, node_id=node_id), None
    except Exception:
        return '', None


def _maybe_schedule_llm_call_for_meta(
    meta: dict,
    *,
    ctx: dict,
    client,
    llm_calls: int,
    llm_max_calls,
    call_coros: list,
    call_metas: list,
    chat_text_with_retries,
    lg,
) -> Tuple[int, bool, bool]:
    block = meta.get('block')
    if not block:
        return llm_calls, False, False

    tid = meta.get('tid')
    tseq = meta.get('tseq')
    tt = meta.get('tt') or ''
    nm = meta.get('nm') or ''
    locs = meta.get('locs') or []
    prompt = meta.get('prompt') or ''
    llm_temperature = ctx.get('llm_temperature') if isinstance(ctx, dict) else None

    round_no = 0
    try:
        round_no = int(ctx.get('_llm_round_index') or 0) + 1
    except Exception:
        round_no = 0

    if llm_max_calls is not None:
        try:
            if llm_calls >= int(llm_max_calls):
                if lg is not None:
                    lg.warning('llm_max_calls_reached_before_call', llm_calls=llm_calls, llm_max_calls=llm_max_calls)
                return llm_calls, True, True
        except Exception:
            pass

    llm_calls += 1
    ctx['_llm_call_count'] = llm_calls
    call_index = llm_calls
    meta['call_index'] = call_index
    if lg is not None:
        lg.info(
            'llm_call',
            call_index=call_index,
            taint_type=tt,
            taint_name=nm,
            locs_count=len(locs),
            block_lines=len((block or '').splitlines()),
        )
        try:
            within_round = int(ctx.get('_llm_round_prompt_counter') or 0) + 1
            ctx['_llm_round_prompt_counter'] = within_round
            meta['round_no'] = round_no
            meta['round_prompt_index'] = within_round
            lg.write_text(
                'llm/prompts',
                f'round{round_no}-prompt{within_round}_seq_{tseq}_id_{tid}.txt',
                prompt,
            )
        except Exception:
            pass

    if ctx.get('llm_offline'):
        base_dir = ctx.get('test_dir') if isinstance(ctx, dict) else None
        base_dir = base_dir if base_dir else os.path.join(os.getcwd(), 'test')
        resp_dir = os.path.join(base_dir, 'llm', 'responses')
        replay_txt = None
        replay_path = ''
        try:
            round_no2 = int(meta.get('round_no') or 0)
            within_round2 = int(meta.get('round_prompt_index') or 0)
        except Exception:
            round_no2 = 0
            within_round2 = 0
        prefixes = []
        if round_no2 and within_round2:
            prefixes.append(f'round{int(round_no2)}-response{int(within_round2)}')
        prefixes.append(f'response_{int(call_index)}')
        try:
            fns = list(os.listdir(resp_dir))
        except Exception:
            fns = []
        for pref in prefixes:
            for fn in fns:
                if not isinstance(fn, str):
                    continue
                if fn.startswith(pref) and fn.endswith('.txt'):
                    replay_path = os.path.join(resp_dir, fn)
                    replay_txt = _try_read_text(replay_path)
                    if replay_txt is not None:
                        break
                    replay_path = ''
            if replay_txt is not None:
                break
        if replay_txt is None:
            meta['resp_txt'] = ''
            if lg is not None:
                lg.warning('llm_offline_missing_replay', call_index=call_index, path=replay_path, taint_type=tt, taint_name=nm)
            return llm_calls, False, False
        meta['resp_txt'] = replay_txt
        if lg is not None:
            lg.info('llm_replay_response', call_index=call_index, path=replay_path)
        return llm_calls, False, False

    replay_paths = []
    try:
        round_no2 = int(meta.get('round_no') or 0)
        within_round2 = int(meta.get('round_prompt_index') or 0)
    except Exception:
        round_no2 = 0
        within_round2 = 0
    if round_no2 and within_round2:
        replay_paths.append(_llm_replay_path(ctx, call_index, seq=tseq, node_id=tid, round_no=round_no2, within_round=within_round2))
    replay_paths.append(_llm_replay_path(ctx, call_index, seq=tseq, node_id=tid))

    replay_txt = None
    replay_path = ''
    for rp in replay_paths:
        if not rp:
            continue
        txt = _try_read_text(rp)
        if txt is not None:
            replay_txt = txt
            replay_path = rp
            break
    if replay_txt is not None:
        meta['resp_txt'] = replay_txt
        if lg is not None:
            lg.info('llm_replay_response', call_index=call_index, path=replay_path)
    elif client is None:
        if lg is not None:
            lg.warning('llm_client_missing', taint_type=tt, taint_name=nm)
    else:
        call_coros.append(
            chat_text_with_retries(
                client=client,
                prompt=prompt,
                system=None,
                temperature=llm_temperature,
                logger=lg,
                max_attempts=getattr(client, 'max_retries', 3) if client is not None else 3,
                call_timeout_s=getattr(client, 'timeout_s', None) if client is not None else None,
                call_index=call_index,
                taint_type=tt,
                taint_name=nm,
                response_validator=_has_valid_llm_json,
                response_validator_name='_has_valid_llm_json',
            )
        )
        call_metas.append(meta)

    return llm_calls, False, False


def _fill_llm_responses_into_metas(
    *,
    call_coros: list,
    call_metas: list,
    max_concurrency: int,
    lg,
    LLMCallFailure,
) -> Optional[BaseException]:
    if not call_coros:
        return None

    call_results = _run_coros_limited(call_coros, max_concurrency=max_concurrency)
    first_exc = None
    def _is_timeout_failure(exc: BaseException) -> bool:
        if not isinstance(exc, LLMCallFailure):
            return False
        try:
            msg = exc.message
        except Exception:
            msg = str(exc)
        if not msg:
            msg = str(exc)
        return 'timeout' in msg.lower()

    for meta, res in zip(call_metas, call_results):
        call_index = meta.get('call_index')
        tid = meta.get('tid')
        tseq = meta.get('tseq')
        resp_txt = ''
        if isinstance(res, BaseException):
            if isinstance(res, LLMCallFailure) and _is_timeout_failure(res):
                resp_txt = '{"taints":[],"edges":[],"seqs":[]}'
            else:
                if isinstance(res, LLMCallFailure):
                    resp_txt = f'[joerntrace] llm_call_failed: {res}'
                else:
                    resp_txt = f'[joerntrace] llm_call_failed: {type(res).__name__}'
                if first_exc is None:
                    first_exc = res
        else:
            resp_txt = str(res)
        meta['resp_txt'] = resp_txt
        if lg is not None and call_index is not None:
            try:
                lg.info(
                    'llm_response_ready',
                    call_index=call_index,
                    tid=tid,
                    tseq=tseq,
                    resp_chars=len(resp_txt or ''),
                    resp_empty=(not bool(resp_txt)),
                )
            except Exception:
                pass
            round_no = meta.get('round_no')
            within_round = meta.get('round_prompt_index')
            if round_no is not None and within_round is not None:
                lg.write_text('llm/responses', f'round{int(round_no)}-response{int(within_round)}_seq_{tseq}_id_{tid}.txt', resp_txt or '')
            else:
                lg.write_text('llm/responses', f'response_{call_index}_seq_{tseq}_id_{tid}.txt', resp_txt or '')
    return first_exc


def process_taints_llm(initial, ctx):
    """
    Iterative taint diffusion loop with LLM expansion (or offline replay).

    Flow per round:
    - Use rule-based handlers to build a scoped code block for the current taint.
    - Call LLM (or load `test/llm/responses/response_<i>_seq_<seq>_id_<id>.txt`).
    - Map returned taints/edges back to CPG nodes and compute leaf nodes.
    - Enqueue leaf nodes for the next round and record `llm_new_taints`.

    Extra: if the LLM returns a variable taint that is passed into a call by reference,
    also enqueue that call as a new taint so side effects can be followed.
    """
    from llm_utils import get_default_client
    from llm_utils.prompts.prompt_utils import (
        DEFAULT_LLM_TAINT_TEMPLATE,
        locs_to_scope_seqs,
        locs_to_seq_code_block,
        render_llm_taint_prompt,
        should_skip_llm_scope,
    )
    from llm_utils.taint.taint_json import parse_llm_taint_response
    from llm_utils.taint.taint_llm_calls import LLMCallFailure, chat_text_with_retries

    from .llm_response import (
        _expand_var_components,
        _llm_item_variants,
        _map_llm_item_to_node,
        _norm_llm_name,
        _rewrite_this_prefix,
        map_llm_edges_to_nodes,
        map_llm_taints_to_nodes,
    )

    def _prompt_body_scope_set(*, locs: list, preamble_locs: list, ref_seq: Optional[int], prefer: str) -> Set[int]:
        def _loc_key(x) -> Optional[str]:
            if not x:
                return None
            if isinstance(x, dict):
                lk = (x.get('loc') or '').strip()
                if lk:
                    return lk
                p = (x.get('path') or '').strip()
                ln = x.get('line')
                if p and ln is not None:
                    try:
                        return f"{p}:{int(ln)}"
                    except Exception:
                        return None
                return None
            if isinstance(x, str):
                return x
            return None

        preamble_set = set()
        for x in preamble_locs or []:
            k = _loc_key(x)
            if k:
                preamble_set.add(k)

        dedupe_locs = []
        for x in locs or []:
            k = _loc_key(x)
            if not k or k in preamble_set:
                continue
            dedupe_locs.append(x)
        scope_seqs = locs_to_scope_seqs(dedupe_locs, ctx, ref_seq=ref_seq, prefer=prefer) if dedupe_locs else []
        out = set()
        for x in scope_seqs or []:
            try:
                out.add(int(x))
            except Exception:
                continue
        return out

    lg = _get_logger(ctx)
    client = _ensure_llm_offline_and_client(ctx, get_default_client)
    if isinstance(ctx, dict) and ctx.get('llm_temperature') is None:
        ctx['llm_temperature'] = 0.0

    preA = list(initial)
    preB = []
    useA = True
    seen = ctx.setdefault('_taint_seen', set())
    queued = ctx.setdefault('_taint_queued', set())
    seen_scope = ctx.setdefault('_taint_seen_scope', set())
    queued_scope = ctx.setdefault('_taint_queued_scope', set())
    llm_seqs = ctx.setdefault('llm_result_seqs', set())
    llm_new = ctx.setdefault('llm_new_taints', [])
    llm_new_seen = ctx.setdefault('_llm_new_seen', set())
    llm_new_minseq = ctx.setdefault('_llm_new_minseq', {})
    llm_new_key_to_index = ctx.setdefault('_llm_new_key_to_index', {})
    llm_edges = ctx.setdefault('llm_edges', [])
    llm_edges_seen = ctx.setdefault('_llm_edges_seen', set())
    llm_incoming = ctx.setdefault('_llm_graph_incoming', {})
    llm_calls = ctx.setdefault('_llm_call_count', 0)
    llm_max_calls = ctx.get('llm_max_calls')
    qstats = ctx.setdefault(
        '_llm_queue_stats',
        {
            'processed_A': 0,
            'processed_B': 0,
            'enqueued_to_A': 0,
            'enqueued_to_B': 0,
            'skipped_seen': 0,
            'skipped_queued': 0,
        },
    )
    calls_edges_union = _ensure_calls_edges_union(ctx)
    append_llm_new_taint = _make_append_llm_new_taint(llm_new, llm_new_minseq, llm_new_key_to_index, _norm_llm_name)

    processed = ctx.setdefault('_llm_processed', [])
    prev_dropped = ctx.setdefault('_llm_prev_dropped', [])
    round_index = ctx.setdefault('_llm_round_index', 0)
    max_concurrency = ctx.get('llm_max_concurrency')
    try:
        max_concurrency = int(max_concurrency) if max_concurrency is not None else 6
    except Exception:
        max_concurrency = 6

    while preA or preB:
        ctx['_llm_round_debug'] = []
        active = preA if useA else preB
        if not active:
            useA = not useA
            continue
        ctx['_llm_round_prompt_counter'] = 0
        if lg is not None:
            lg.debug(
                'queue_state',
                active_queue=('A' if useA else 'B'),
                preA_len=len(preA),
                preB_len=len(preB),
            )
            lg.log_json('DEBUG', 'queue_preA', _queue_brief(preA))
            lg.log_json('DEBUG', 'queue_preB', _queue_brief(preB))

        round_dropped = []
        round_metas = []
        call_coros = []
        call_metas = []
        stop_due_to_max_calls = False
        enable_scope_opt = True
        try:
            enable_scope_opt = bool(ctx.get('enable_scope_opt', True))
        except Exception:
            enable_scope_opt = True
        if enable_scope_opt:
            try:
                from llm_utils.scope.scope_opt import (
                    build_merged_llm_prompt,
                    merge_round_metas_by_scope,
                    scope_seqs_from_scope_locs,
                    should_skip_llm_for_child_scope,
                )
            except Exception:
                enable_scope_opt = False

        for _ in range(len(active)):
            t = active.pop(0)
            tid = t.get('id')
            tseq = t.get('seq')
            if tid is None or tseq is None:
                continue
            key = (int(tid), int(tseq))
            nodes = ctx.get('nodes') or {}
            children_of = ctx.get('children_of') or {}
            bt = _taint_brief(t)
            if bt and isinstance(t, dict):
                this_obj, this_call_seq, this_obj_hint = _compute_this_context(t, tseq=tseq, ctx=ctx, calls_edges_union=calls_edges_union)
                if this_obj_hint:
                    bt = dict(bt)
                    bt['_this_obj'] = this_obj_hint
            else:
                this_obj, this_call_seq, _ = _compute_this_context(t, tseq=tseq, ctx=ctx, calls_edges_union=calls_edges_union)
            scope_key = _taint_scope_key(t, nodes, children_of, this_obj)
            if scope_key is not None and scope_key in seen_scope:
                continue
            if key in seen:
                continue
            seen.add(key)
            if scope_key is not None:
                seen_scope.add(scope_key)
            if bt:
                processed.append(bt)
            fn = REGISTRY.get(t.get('type') or '')
            if not fn:
                continue
            if lg is not None:
                lg.log_json('DEBUG', 'processing_taint', bt)
            before = len(ctx.get('result_set') or [])
            ctx['_llm_scope_markers'] = []
            ctx['_llm_extra_prompt_locs'] = []
            fn(t, ctx)
            after = len(ctx.get('result_set') or [])
            if lg is not None:
                try:
                    lg.info(
                        'debug_llm_scope_after_handler',
                        taint_type=(t.get('type') or ''),
                        taint_id=tid,
                        taint_seq=tseq,
                        scope_loc_count=max(0, after - before),
                    )
                except Exception:
                    pass
            if useA:
                qstats['processed_A'] = int(qstats.get('processed_A') or 0) + 1
            else:
                qstats['processed_B'] = int(qstats.get('processed_B') or 0) + 1
            rs_all = ctx.get('result_set') or []
            scope_locs = rs_all[before:after] if after >= before else []
            extra_locs = ctx.get('_llm_extra_prompt_locs') or []
            locs = _merge_prompt_locs(scope_locs, extra_locs)
            ctx['_llm_ref_seq'] = int(tseq) if tseq is not None else None
            prefer = (ctx.get('_llm_scope_prefer') or '').strip()
            if not prefer:
                prefer = 'forward' if (t.get('type') or '').strip() in ('AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL') else 'backward'
            preamble_by_key = ctx.get('_llm_scope_preamble_by_key') if isinstance(ctx, dict) else None
            if isinstance(preamble_by_key, dict) and tid is not None and tseq is not None:
                try:
                    ctx['_llm_scope_preamble_locs'] = list(preamble_by_key.get((int(tid), int(tseq))) or [])
                except Exception:
                    ctx['_llm_scope_preamble_locs'] = []
            else:
                ctx['_llm_scope_preamble_locs'] = []
            preamble_locs = list(ctx.get('_llm_scope_preamble_locs') or [])
            block = locs_to_seq_code_block(locs, ctx, prefer=prefer)
            if isinstance(ctx, dict):
                ctx.pop('_llm_scope_preamble_locs', None)
            tt, nm = _taint_display(t, nodes, children_of)
            if this_obj:
                nm = _rewrite_this_prefix(nm or '', this_obj)
            if lg is not None:
                try:
                    lg.info(
                        'debug_llm_prompt_block',
                        taint_type=tt,
                        taint_name=nm,
                        taint_id=tid,
                        taint_seq=tseq,
                        locs_count=len(locs or []),
                        block_lines=len((block or '').splitlines()),
                    )
                except Exception:
                    pass
            prompt_template = t.get('llm_prompt_template') if isinstance(t, dict) else None
            prompt = render_llm_taint_prompt(
                template=(prompt_template or DEFAULT_LLM_TAINT_TEMPLATE),
                taint_type=tt,
                taint_name=nm,
                result_set=block,
            )

            prompt_scope_set = (
                _prompt_body_scope_set(
                    locs=scope_locs,
                    preamble_locs=preamble_locs,
                    ref_seq=(int(tseq) if tseq is not None else None),
                    prefer=prefer,
                )
                if block
                else set()
            )
            scope_only_seqs = frozenset()
            if enable_scope_opt and block:
                try:
                    scope_only_seqs = scope_seqs_from_scope_locs(
                        scope_locs=scope_locs,
                        ctx=ctx,
                        ref_seq=(int(tseq) if tseq is not None else None),
                        prefer=prefer,
                    )
                except Exception:
                    scope_only_seqs = frozenset()

            # if enable_scope_opt and scope_only_seqs and tid is not None and tseq is not None:
            #     try:
            #         if should_skip_llm_for_child_scope(
            #             ctx=ctx,
            #             taint_key=(int(tid), int(tseq)),
            #             scope_seqs=scope_only_seqs,
            #         ):
            #             if lg is not None:
            #                 lg.info(
            #                     'llm_skip_child_scope_subset',
            #                     taint_type=tt,
            #                     taint_name=nm,
            #                     scope_len=len(scope_only_seqs),
            #                 )
            #             continue
            #     except Exception:
            #         pass
            # if prompt_scope_set and (not ctx.get('llm_offline')) and should_skip_llm_scope(sorted(prompt_scope_set), ctx, dedupe_key=f'{tt}:{nm}'):
            #     if lg is not None:
            #         lg.info('llm_skip_scope_subset', taint_type=tt, taint_name=nm, scope_len=len(prompt_scope_set))
            #     continue

            meta = {
                't': t,
                'tid': tid,
                'tseq': tseq,
                'key': key,
                'this_obj': this_obj,
                'this_call_seq': this_call_seq,
                'tt': tt,
                'nm': nm,
                'locs': locs,
                'block': block,
                'prompt': prompt,
                'prompt_scope_set': prompt_scope_set,
                'scope_only_seqs': scope_only_seqs,
            }
            call_param_arg_info = ctx.pop('_llm_call_param_arg_info', None) if isinstance(ctx, dict) else None
            if call_param_arg_info is not None:
                meta['call_param_arg_info'] = call_param_arg_info
            elif lg is not None and (t.get('type') or '').strip() in ('AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL'):
                lg.debug('llm_call_param_arg_info_missing', tid=tid, tseq=tseq, taint_type=tt, taint_name=nm)
            if (t.get('type') or '').strip() == 'AST_PROP':
                prop_call_scopes_info = ctx.pop('_llm_prop_call_scopes_info', None) if isinstance(ctx, dict) else None
                if prop_call_scopes_info is not None:
                    meta['prop_call_scopes_info'] = prop_call_scopes_info
            round_metas.append(meta)
            if lg is not None:
                try:
                    lg.info(
                        'debug_llm_meta_ready',
                        taint_type=tt,
                        taint_name=nm,
                        taint_id=tid,
                        taint_seq=tseq,
                        block_empty=not bool(block),
                    )
                except Exception:
                    pass

        if stop_due_to_max_calls:
            round_metas = []
        scheduled_round_metas = []
        if round_metas:
            try:
                from llm_utils.prompts.composite_prompt import pack_small_scopes_into_composites
            except Exception:
                pack_small_scopes_into_composites = None
            if enable_scope_opt:
                try:
                    by_obj = {}
                    for m in round_metas:
                        if not isinstance(m, dict):
                            continue
                        k = (m.get('this_obj') or '').strip()
                        by_obj.setdefault(k, []).append(m)
                    merged2 = []
                    for _, buf in by_obj.items():
                        merged2.extend(merge_round_metas_by_scope(list(buf)))
                    round_metas = merged2
                except Exception:
                    pass
                for meta in round_metas:
                    merged_members = meta.get('merged_members')
                    if not (isinstance(merged_members, list) and merged_members):
                        continue
                    try:
                        meta['prompt'] = build_merged_llm_prompt(
                            merged_members=merged_members,
                            result_set=meta.get('block') or '',
                        )
                    except Exception:
                        pass
            if pack_small_scopes_into_composites is not None:
                try:
                    round_metas = pack_small_scopes_into_composites(round_metas, small_scope_max=30, max_prompt_seqs=100)
                except Exception:
                    pass

            for meta in round_metas:
                llm_calls, stop_due_to_max_calls, should_break = _maybe_schedule_llm_call_for_meta(
                    meta,
                    ctx=ctx,
                    client=client,
                    llm_calls=llm_calls,
                    llm_max_calls=llm_max_calls,
                    call_coros=call_coros,
                    call_metas=call_metas,
                    chat_text_with_retries=chat_text_with_retries,
                    lg=lg,
                )
                if should_break:
                    break
                scheduled_round_metas.append(meta)
        round_metas = scheduled_round_metas
        if stop_due_to_max_calls:
            round_metas = []

        if lg is not None:
            try:
                lg.info(
                    'debug_llm_call_schedule',
                    round_index=round_index,
                    round_metas=len(round_metas),
                    call_coros=len(call_coros),
                    call_metas=len(call_metas),
                    llm_calls=llm_calls,
                    llm_max_calls=llm_max_calls,
                )
            except Exception:
                pass

        fatal_exc = _fill_llm_responses_into_metas(
            call_coros=call_coros,
            call_metas=call_metas,
            max_concurrency=max_concurrency,
            lg=lg,
            LLMCallFailure=LLMCallFailure,
        )

        if fatal_exc is not None:
            round_metas = []

        json_retry_attempts = 3
        try:
            json_retry_attempts = int(ctx.get('llm_json_retry_attempts') or 3)
        except Exception:
            json_retry_attempts = 3
        if json_retry_attempts < 1:
            json_retry_attempts = 1
        llm_temperature = ctx.get('llm_temperature') if isinstance(ctx, dict) else None
        if round_metas and (not ctx.get('llm_offline')) and client is not None:
            for meta in round_metas:
                try:
                    resp_txt = meta.get('resp_txt') or ''
                except Exception:
                    resp_txt = ''
                attempts_left = int(json_retry_attempts)
                while attempts_left > 0 and (not _has_valid_llm_json(resp_txt)):
                    try:
                        if llm_max_calls is not None and int(llm_calls) >= int(llm_max_calls):
                            break
                    except Exception:
                        pass
                    llm_calls = int(llm_calls) + 1
                    ctx['_llm_call_count'] = llm_calls
                    if lg is not None:
                        try:
                            lg.warning('llm_json_retry_call', call_index=meta.get('call_index'), attempts_left=attempts_left)
                        except Exception:
                            pass
                    coros = [
                        chat_text_with_retries(
                            client=client,
                            prompt=meta.get('prompt') or '',
                            system=None,
                            temperature=llm_temperature,
                            logger=lg,
                            max_attempts=getattr(client, 'max_retries', 3) if client is not None else 3,
                            call_timeout_s=getattr(client, 'timeout_s', None) if client is not None else None,
                            call_index=meta.get('call_index'),
                            taint_type=meta.get('tt'),
                            taint_name=meta.get('nm'),
                            response_validator=_has_valid_llm_json,
                            response_validator_name='_has_valid_llm_json',
                        )
                    ]
                    try:
                        res_list = _run_coros_limited(coros, max_concurrency=1)
                        new_txt = res_list[0] if res_list else ''
                        if isinstance(new_txt, BaseException):
                            break
                        resp_txt = str(new_txt or '')
                        meta['resp_txt'] = resp_txt
                    except Exception:
                        break
                    attempts_left -= 1

        for meta in round_metas:
            stop_due_to_max_calls = _process_llm_round_meta(
                meta,
                ctx=ctx,
                useA=useA,
                preA=preA,
                preB=preB,
                processed=processed,
                round_dropped=round_dropped,
                seen=seen,
                queued=queued,
                seen_scope=seen_scope,
                queued_scope=queued_scope,
                llm_seqs=llm_seqs,
                llm_edges=llm_edges,
                llm_edges_seen=llm_edges_seen,
                llm_incoming=llm_incoming,
                llm_new_seen=llm_new_seen,
                append_llm_new_taint=append_llm_new_taint,
                qstats=qstats,
                calls_edges_union=calls_edges_union,
                lg=lg,
            )
            if stop_due_to_max_calls:
                break

        round_index += 1
        ctx['_llm_round_index'] = round_index
        _write_llm_round_file(
            lg=lg,
            ctx=ctx,
            round_index=round_index,
            queue_label=('A' if useA else 'B'),
            preA=preA,
            preB=preB,
            processed=processed,
            dropped=prev_dropped,
        )
        prev_dropped = list(round_dropped)
        ctx['_llm_prev_dropped'] = prev_dropped
        if fatal_exc is not None:
            raise SystemExit(1)
        if stop_due_to_max_calls:
            return []
        useA = not useA
    return []
