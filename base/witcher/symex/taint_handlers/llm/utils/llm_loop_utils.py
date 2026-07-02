import os
from typing import Optional, Tuple

from common.logger import Logger


def _get_logger(ctx):
    """Return a logger from ctx, creating a default one under `test/` when needed."""
    if not isinstance(ctx, dict):
        return None
    lg = ctx.get('logger')
    if lg is not None:
        return lg
    test_dir = ctx.get('test_dir') or os.path.join(os.getcwd(), 'test')
    try:
        lg = Logger(base_dir=test_dir, min_level='INFO', name='joerntrace', also_console=False)
        ctx['logger'] = lg
        return lg
    except Exception:
        return None


def _taint_brief(t):
    """Return a compact taint dict for logging/debug output."""
    if not isinstance(t, dict):
        return None
    out = {
        'id': t.get('id'),
        'seq': t.get('seq'),
        'type': t.get('type'),
    }
    nm = t.get('name')
    if isinstance(nm, str) and nm:
        out['name'] = nm
    recv = t.get('recv')
    if isinstance(recv, str) and recv:
        out['recv'] = recv
    return out


def _queue_brief(q, limit: int = 50):
    """Summarize a taint queue as a list of brief taint dicts."""
    out = []
    for it in (q or [])[: max(0, int(limit))]:
        b = _taint_brief(it)
        if b:
            out.append(b)
    return out


def _taint_display(taint, nodes, children_of):
    """Compute a display `(type,name)` for taint dicts using node metadata as fallback."""
    from ..core.llm_response import _node_display

    tt = (taint.get('type') or '').strip()
    if not tt:
        return '', ''
    if tt == 'AST_VAR':
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        return tt, nm
    if tt == 'AST_PROP':
        base = (taint.get('base') or '').strip()
        prop = (taint.get('prop') or '').strip()
        if base and prop:
            return tt, f"{base}->{prop}"
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        nm = nm.replace('.', '->')
        return tt, nm
    if tt == 'AST_DIM':
        base = (taint.get('base') or '').strip()
        key = (taint.get('key') or '').strip()
        if base and key:
            return tt, f"{base}[{key}]"
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        return tt, nm
    if tt == 'AST_CALL':
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        if nm and not nm.endswith('()'):
            nm = f"{nm}()"
        return tt, nm
    if tt == 'AST_STATIC_CALL':
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        if nm and not nm.endswith('()'):
            nm = f"{nm}()"
        return tt, nm
    if tt == 'AST_METHOD_CALL':
        recv = (taint.get('recv') or '').strip()
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        if nm and not nm.endswith('()'):
            nm = f"{nm}()"
        if recv and nm:
            recv_n = recv.replace('.', '->')
            nm_n = nm.replace('.', '->')
            if nm_n.startswith('this->') or nm_n.startswith('$this->') or nm_n.startswith(f"{recv_n}->"):
                return tt, nm_n
            if '->' in nm_n:
                nm_head, nm_tail = nm_n.split('->', 1)
                recv_tail = (recv_n.split('->')[-1] or '').lstrip('$')
                if nm_head.lstrip('$') == recv_tail and nm_tail:
                    return tt, f"{recv_n}->{nm_tail}"
                if recv_n in ('this', '$this'):
                    return tt, f"{recv_n}->{nm_n}"
                return tt, nm_n
            return tt, f"{recv_n}->{nm_n}"
        return tt, nm
    nm = (taint.get('name') or '').strip()
    if not nm and taint.get('id') is not None:
        _, nm = _node_display(taint.get('id'), nodes, children_of)
    return tt, nm


def _dedupe_name_key(tt: str, nm: str) -> str:
    """Compute a normalized name key used for de-duplicating taints within a scope."""
    from ..core.llm_response import _norm_llm_name

    t = (tt or '').strip()
    v = (nm or '').strip()
    if not v:
        return ''
    v = v.replace('.', '->')
    v = _norm_llm_name(v)
    if not v:
        return ''
    if t == 'AST_DIM':
        return (v.split('[', 1)[0] or '').strip()
    if t == 'AST_PROP':
        parts = [p for p in v.split('->') if p]
        if len(parts) >= 2:
            return parts[0] + '->' + parts[1]
        return v
    if t == 'AST_METHOD_CALL':
        if v.endswith('()'):
            v = v[:-2]
        parts = [p for p in v.split('->') if p]
        if len(parts) >= 2:
            return parts[0] + '->' + parts[1]
        return v
    if t == 'AST_CALL':
        if v.endswith('()'):
            v = v[:-2]
        return v
    if t == 'AST_STATIC_CALL':
        if v.endswith('()'):
            v = v[:-2]
        return v
    if t == 'AST_VAR':
        return v
    return v


def _taint_scope_key(taint, nodes, children_of, this_obj: str = ''):
    """Build a `(funcid,type,name_key)` tuple for scope-level de-duplication."""
    from ..core.llm_response import _rewrite_this_prefix

    tid = taint.get('id')
    if tid is None:
        return None
    try:
        tid_i = int(tid)
    except Exception:
        return None
    funcid = (nodes.get(tid_i) or {}).get('funcid')
    if funcid is None:
        return None
    tt, nm = _taint_display(taint, nodes, children_of)
    if this_obj:
        nm = _rewrite_this_prefix(nm or '', this_obj)
    nk = _dedupe_name_key(tt, nm)
    if not nk:
        return None
    return (int(funcid), tt, nk)


def _create_task(asyncio_mod, coro):
    ct = getattr(asyncio_mod, "create_task", None)
    if ct is not None:
        return ct(coro)
    return asyncio_mod.ensure_future(coro)


def _asyncio_run(asyncio_mod, coro):
    runner = getattr(asyncio_mod, "run", None)
    if runner is not None:
        return runner(coro)
    loop = asyncio_mod.get_event_loop()
    return loop.run_until_complete(coro)


def _run_coros_limited(call_coros, *, max_concurrency: int = 6):
    import asyncio

    async def _run():
        sem = asyncio.Semaphore(max(1, int(max_concurrency)))

        async def _run_one(c):
            async with sem:
                try:
                    return await c
                except BaseException as e:
                    return e

        tasks = [_create_task(asyncio, _run_one(c)) for c in (call_coros or [])]
        if not tasks:
            return []
        return await asyncio.gather(*tasks)

    if not call_coros:
        return []
    return _asyncio_run(asyncio, _run())


def _llm_replay_path(
    ctx,
    call_index: int,
    *,
    seq: int,
    node_id: int,
    round_no: Optional[int] = None,
    within_round: Optional[int] = None,
) -> str:
    base_dir = ctx.get('test_dir') if isinstance(ctx, dict) else None
    base_dir = base_dir if base_dir else os.path.join(os.getcwd(), 'test')
    resp_dir = os.path.join(base_dir, 'llm', 'responses')
    if round_no is not None and within_round is not None:
        exact = os.path.join(resp_dir, f'round{int(round_no)}-response{int(within_round)}_seq_{int(seq)}_id_{int(node_id)}.txt')
    else:
        exact = os.path.join(resp_dir, f'response_{int(call_index)}_seq_{int(seq)}_id_{int(node_id)}.txt')
    if os.path.exists(exact):
        return exact
    try:
        suffix = f'_seq_{int(seq)}_id_{int(node_id)}.txt'
        for fn in os.listdir(resp_dir):
            if not isinstance(fn, str):
                continue
            if fn.endswith(suffix):
                return os.path.join(resp_dir, fn)
    except Exception:
        pass
    try:
        want = f'_seq_{int(seq)}_id_'
        prefix = f'round{int(round_no)}-response' if round_no is not None else None
        for fn in os.listdir(resp_dir):
            if not isinstance(fn, str):
                continue
            if prefix and (not fn.startswith(prefix)):
                continue
            if want not in fn:
                continue
            if not fn.endswith('.txt'):
                continue
            return os.path.join(resp_dir, fn)
    except Exception:
        pass
    return exact


def _try_read_text(path: str) -> Optional[str]:
    if not path:
        return None
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception:
        return None


def _write_llm_round_file(
    *,
    lg,
    ctx,
    round_index: int,
    queue_label: str,
    preA,
    preB,
    processed,
    dropped,
):
    from ..core.llm_response import _rewrite_this_prefix

    if lg is None:
        return round_index

    def _round_brief(x):
        if not isinstance(x, dict):
            return None
        b = _taint_brief(x)
        if not b:
            return None
        o = ''
        if (x.get('type') or '').strip() == 'AST_METHOD_CALL':
            o = (x.get('recv') or '').strip()
        if not o:
            o = (x.get('_this_obj') or '').strip()
        if o and isinstance(b.get('name'), str) and b.get('name'):
            b['name'] = _rewrite_this_prefix(b.get('name') or '', o)
        return b

    def _round_queue(q):
        out = []
        for it in q or []:
            b = _round_brief(it)
            if b:
                out.append(b)
        return out

    def _round_processed(p):
        out = []
        for it in p or []:
            if not isinstance(it, dict):
                continue
            it2 = dict(it)
            o = (it2.get('_this_obj') or '').strip()
            if not o:
                o = (it2.get('recv') or '').strip()
            if o and isinstance(it2.get('name'), str) and it2.get('name'):
                it2['name'] = _rewrite_this_prefix(it2.get('name') or '', o)
            it2.pop('_this_obj', None)
            out.append(it2)
        return out

    lg.write_json(
        'rounds',
        f'round_{int(round_index)}_{queue_label}.json',
        {
            'A': _round_queue(preA),
            'B': _round_queue(preB),
            'processed': _round_processed(processed),
            'dropped': list(dropped or []),
            'llm_debug': ctx.get('_llm_round_debug') or [],
        },
    )
    return round_index
