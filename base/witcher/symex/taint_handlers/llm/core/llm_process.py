"""
LLM-assisted taint diffusion loop.

This module wraps the rule-based taint handlers to build scoped code blocks and
ask an LLM for additional influencing taints and dataflow edges. Returned items
are mapped back to CPG nodes and enqueued for further expansion.
"""

import os
from typing import Optional, Tuple

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
    Taint diffusion entry kept for compatibility.

    The original prompt-building and LLM-calling path has been disabled. We now
    reuse the existing scope-building handlers, then expand taints through local
    AST pattern matching so downstream modules can keep using the same entrypoint.
    """
    from taint_handlers.pattern import process_taints_by_patterns
    from . import llm_process_legacy

    lg = _get_logger(ctx)
    ctx.setdefault("_legacy_taint_process", llm_process_legacy.process_taints_llm)
    if lg is not None:
        try:
            lg.info("pattern_diffusion_enabled", llm_prompt_call_disabled=True)
        except Exception:
            pass

    # The previous implementation built prompt blocks with `render_llm_taint_prompt`
    # and dispatched `chat_text_with_retries(...)` here. That LLM expansion path is
    # intentionally disabled and replaced by `process_taints_by_patterns(...)`.
    # Rollback path: switch the return below to
    # `llm_process_legacy.process_taints_llm(initial, ctx)`.
    return process_taints_by_patterns(initial, ctx)
