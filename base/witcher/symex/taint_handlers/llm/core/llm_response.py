"""
Mapping utilities for converting LLM outputs into CPG node taints and edges.

The LLM returns taints and edges in terms of `(seq,type,name)`; this module maps
those items back to concrete node ids within the trace-index scope and expands
variable components for better coverage.
"""

import re
from typing import List, Optional, Set, Tuple

from utils.extractors.if_extract import get_all_string_descendants, get_string_children, find_first_var_string


_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def _pick_identifier(x: str) -> str:
    """Return `x` if it matches an identifier shape, else empty string."""
    s = (x or '').strip()
    if not s:
        return ''
    if _IDENT_RE.match(s):
        return s
    return ''


def _method_call_recv_name(call_id, nodes, children_of, *, this_obj: str = '') -> str:
    """Return a normalized receiver string for `AST_METHOD_CALL`."""
    ch = list(children_of.get(call_id, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    recv_id = None
    for c in ch:
        nc = nodes.get(c) or {}
        tt = (nc.get('type') or '').strip()
        if tt == 'AST_ARG_LIST':
            continue
        if nc.get('labels') == 'string' or tt == 'string':
            continue
        recv_id = int(c)
        break
    if recv_id is None:
        return ''
    recv_tt = ((nodes.get(recv_id) or {}).get('type') or '').strip()
    if this_obj:
        recv = _node_source_str_with_this(recv_id, recv_tt, nodes, children_of, this_obj=this_obj)
    else:
        recv = _node_source_str(recv_id, recv_tt, nodes, children_of)
    return (recv or '').replace('.', '->').strip().lstrip('$')


def _call_name_from_children(call_id, nodes, children_of) -> str:
    """Extract a best-effort call name token from a call node's children."""
    ch = list(children_of.get(call_id, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    for c in ch:
        nc = nodes.get(c) or {}
        if (nc.get('type') or '').strip() == 'AST_NAME':
            ss = get_string_children(c, children_of, nodes)
            if ss:
                got = _pick_identifier(ss[0][1])
                if got:
                    return got
    for c in ch:
        nc = nodes.get(c) or {}
        if nc.get('labels') == 'string' or (nc.get('type') or '').strip() == 'string':
            vv = (nc.get('code') or nc.get('name') or '').strip()
            got = _pick_identifier(vv)
            if got:
                return got
    return ''


def _static_call_parts_from_children(call_id, nodes, children_of) -> Tuple[str, str]:
    ch = list(children_of.get(call_id, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    cls = ''
    fn = ''
    for c in ch:
        nc = nodes.get(c) or {}
        ct = (nc.get('type') or '').strip()
        if ct == 'AST_ARG_LIST':
            continue
        val = ''
        if ct == 'AST_NAME':
            ss = get_string_children(c, children_of, nodes)
            if ss:
                val = (ss[0][1] or '').strip()
            else:
                val = (nc.get('code') or nc.get('name') or '').strip()
        elif nc.get('labels') == 'string' or ct == 'string':
            val = (nc.get('code') or nc.get('name') or '').strip()
        if val:
            if not cls:
                cls = val
            elif not fn:
                fn = val
            if cls and fn:
                break
    return cls, fn


def _static_call_name_from_children(call_id, nodes, children_of) -> str:
    cls, fn = _static_call_parts_from_children(call_id, nodes, children_of)
    if cls and fn:
        return f"{cls}::{fn}"
    return fn or cls


def _split_static_call_name(name: str) -> Tuple[str, str]:
    v = (name or '').strip()
    if not v:
        return '', ''
    v = v.replace(' ', '').replace('\t', '')
    v = v.replace('$', '')
    parts = []
    if '::' in v:
        parts = [p for p in v.split('::') if p]
    elif ':' in v:
        parts = [p for p in v.split(':') if p]
    if not parts:
        return '', ''
    if len(parts) == 1:
        return parts[0], ''
    return parts[0], parts[-1]


def _normalize_static_call_name(name: str) -> str:
    cls, fn = _split_static_call_name(name)
    if cls and fn:
        return f"{cls}::{fn}"
    return fn or cls


def _node_display(nid, nodes, children_of):
    """Return a best-effort `(type,name)` display for a node id."""
    nx = nodes.get(nid) or {}
    t = nx.get('type') or ''
    if t == 'AST_VAR':
        ss = get_string_children(nid, children_of, nodes)
        return t, (ss[0][1] if ss else '')
    if t == 'AST_METHOD_CALL':
        nm = _call_name_from_children(nid, nodes, children_of)
        if nm:
            return t, nm
        ss = get_string_children(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_CALL':
        nm = _call_name_from_children(nid, nodes, children_of)
        if nm:
            return t, nm
        ss = get_all_string_descendants(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_STATIC_CALL':
        nm = _static_call_name_from_children(nid, nodes, children_of)
        if nm:
            return t, nm
        ss = get_all_string_descendants(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_PROP':
        ch = list(children_of.get(nid, []) or [])
        ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
        base_id = None
        prop_token = ''
        for c in ch:
            cx = nodes.get(int(c)) or {}
            ct = (cx.get('type') or '').strip()
            if ct == 'AST_ARG_LIST':
                continue
            if cx.get('labels') == 'string' or ct == 'string':
                v = (cx.get('code') or cx.get('name') or '').strip()
                if v and not prop_token:
                    prop_token = v
                continue
            if base_id is None:
                base_id = int(c)
        base_nm = ''
        if base_id is not None:
            try:
                _, base_nm = _node_display(int(base_id), nodes, children_of)
            except Exception:
                base_nm = ''
        if not base_nm:
            base_nm = (find_first_var_string(nid, children_of, nodes) or '').strip()
        if not prop_token:
            ss = get_string_children(nid, children_of, nodes)
            prop_token = (ss[0][1] if ss else '').strip()
        if base_nm and prop_token:
            return t, f"{base_nm.replace('.', '->')}->{prop_token}"
        return t, ((nx.get('code') or nx.get('name') or '').strip())
    if t == 'AST_DIM':
        ch = list(children_of.get(nid, []) or [])
        ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
        base_id = int(ch[0]) if len(ch) >= 1 else None
        key_id = int(ch[1]) if len(ch) >= 2 else None
        base_nm = ''
        if base_id is not None:
            try:
                _, base_nm = _node_display(int(base_id), nodes, children_of)
            except Exception:
                base_nm = ''
        if not base_nm:
            base_nm = (find_first_var_string(nid, children_of, nodes) or '').strip()
        key_nm = ''
        if key_id is not None:
            try:
                _, key_nm = _node_display(int(key_id), nodes, children_of)
            except Exception:
                key_nm = ''
        if not key_nm:
            ss = get_string_children(nid, children_of, nodes)
            key_nm = (ss[0][1] if ss else '').strip()
        if base_nm and key_nm:
            return t, f"{base_nm.replace('.', '->')}[{key_nm}]"
        return t, ((nx.get('code') or nx.get('name') or '').strip())
    if t in ('AST_CONST', 'AST_NAME', 'string', 'integer', 'double'):
        ss = get_all_string_descendants(nid, children_of, nodes)
        if ss:
            return t, ss[0][1]
        return t, (nx.get('code') or nx.get('name') or '')
    return t, (nx.get('code') or nx.get('name') or '')


def effective_llm_incoming_sources(node: dict, node_key: Tuple[int, int], llm_incoming: dict, ctx) -> Set[Tuple[int, int]]:
    """
    Return the effective incoming LLM graph sources for `node_key`, applying AST-based exceptions.

    Exceptions:
    - If `node` is `AST_DIM`, incoming edges originating from its own index expression subtree
      are ignored.
    - If `node` is `AST_CALL`, incoming edges originating from its own argument list subtree
      are ignored.
    - If `node` is `AST_METHOD_CALL`, incoming edges originating from its own receiver expression
      subtree or argument list subtree are ignored.
    """
    inc = llm_incoming.get(node_key)
    if not inc:
        return set()
    if not isinstance(node, dict):
        return set(inc)
    tt = (node.get('type') or '').strip()
    if tt not in ('AST_DIM', 'AST_CALL', 'AST_STATIC_CALL', 'AST_METHOD_CALL'):
        return set(inc)
    dst_id = node.get('id')
    if dst_id is None:
        return set(inc)
    nodes = (ctx or {}).get('nodes') or {}
    children_of = (ctx or {}).get('children_of') or {}
    if not nodes or not children_of:
        return set(inc)
    if tt in ('AST_CALL', 'AST_STATIC_CALL'):
        try:
            from utils.cpg_utils.graph_mapping import base_var_name_for_node, call_arg_base_names, is_in_call_arg_subtree
        except Exception:
            base_var_name_for_node = None
            call_arg_base_names = None
            is_in_call_arg_subtree = None
        if is_in_call_arg_subtree is None:
            return set(inc)
        arg_names = set()
        if call_arg_base_names is not None:
            try:
                arg_names = {_norm_llm_name(x) for x in (call_arg_base_names(int(dst_id), nodes, children_of) or set()) if x}
            except Exception:
                arg_names = set()
        out = set()
        for sk in inc:
            try:
                sid = int(sk[0])
            except Exception:
                out.add(sk)
                continue
            if is_in_call_arg_subtree(int(dst_id), sid, nodes, children_of):
                continue
            if arg_names and base_var_name_for_node is not None:
                try:
                    sb = _norm_llm_name(base_var_name_for_node(int(sid), nodes, children_of))
                except Exception:
                    sb = ''
                if sb and sb in arg_names:
                    continue
            out.add(sk)
        return out
    if tt == 'AST_METHOD_CALL':
        try:
            from utils.cpg_utils.graph_mapping import (
                base_var_name_for_node,
                call_arg_base_names,
                is_in_call_arg_subtree,
                is_in_method_call_receiver_subtree,
                method_call_receiver_base_names,
            )
        except Exception:
            base_var_name_for_node = None
            call_arg_base_names = None
            is_in_call_arg_subtree = None
            is_in_method_call_receiver_subtree = None
            method_call_receiver_base_names = None
        if is_in_call_arg_subtree is None or is_in_method_call_receiver_subtree is None:
            return set(inc)
        recv_names = set()
        if method_call_receiver_base_names is not None:
            try:
                recv_names = {_norm_llm_name(x) for x in (method_call_receiver_base_names(int(dst_id), nodes, children_of) or set()) if x}
            except Exception:
                recv_names = set()
        arg_names = set()
        if call_arg_base_names is not None:
            try:
                arg_names = {_norm_llm_name(x) for x in (call_arg_base_names(int(dst_id), nodes, children_of) or set()) if x}
            except Exception:
                arg_names = set()
        out = set()
        for sk in inc:
            try:
                sid = int(sk[0])
            except Exception:
                out.add(sk)
                continue
            if is_in_method_call_receiver_subtree(int(dst_id), sid, nodes, children_of):
                continue
            if is_in_call_arg_subtree(int(dst_id), sid, nodes, children_of):
                continue
            if (recv_names or arg_names) and base_var_name_for_node is not None:
                try:
                    sb = _norm_llm_name(base_var_name_for_node(int(sid), nodes, children_of))
                except Exception:
                    sb = ''
                if sb and (sb in recv_names or sb in arg_names):
                    continue
            out.add(sk)
        return out
    try:
        from utils.cpg_utils.graph_mapping import base_var_name_for_node, dim_index_base_names, is_in_dim_index_subtree
    except Exception:
        base_var_name_for_node = None
        dim_index_base_names = None
        is_in_dim_index_subtree = None
    if is_in_dim_index_subtree is None:
        return set(inc)
    idx_names = set()
    if dim_index_base_names is not None:
        try:
            idx_names = {_norm_llm_name(x) for x in (dim_index_base_names(int(dst_id), nodes, children_of) or set()) if x}
        except Exception:
            idx_names = set()
    out = set()
    for sk in inc:
        try:
            sid = int(sk[0])
        except Exception:
            out.add(sk)
            continue
        if is_in_dim_index_subtree(int(dst_id), sid, nodes, children_of):
            continue
        if idx_names and base_var_name_for_node is not None:
            try:
                sb = _norm_llm_name(base_var_name_for_node(int(sid), nodes, children_of))
            except Exception:
                sb = ''
            if sb and sb in idx_names:
                continue
        out.add(sk)
    return out


def _norm_llm_name(s: str) -> str:
    """Normalize an LLM name string for matching (strip, remove spaces, drop `$`)."""
    s = (s or '').strip()
    if not s:
        return ''
    s = s.replace(' ', '').replace('\t', '')
    s = s.replace('$', '')
    return s


def _strip_quotes(s: str) -> str:
    v = (s or '').strip()
    if not v:
        return ''
    return v.replace("'", "").replace('"', '').replace('`', '')


def _norm_llm_name_loose(s: str) -> str:
    return _strip_quotes(_norm_llm_name(s))


_DIM_SHAPE_RE = re.compile(r'\[[^\]]*\]')
_PAREN_RE = re.compile(r'\([^)]*\)')


def _shape_name(s: str) -> str:
    """Normalize an expression name to a shape string (dims -> `[]`, remove `$`)."""
    v = _norm_llm_name_loose(s)
    if not v:
        return ''
    v = v.replace('$', '')
    v = _DIM_SHAPE_RE.sub('[]', v)
    return v


def _rewrite_this_prefix(name: str, this_obj: str) -> str:
    """Rewrite `this`-prefixed names to the concrete receiver object when available."""
    v = (name or '').strip()
    o = (this_obj or '').strip()
    if not v or not o:
        return v
    if o.startswith('$'):
        o = o[1:]
    if o == 'this' or o.startswith('this->') or o.startswith('this['):
        return v
    v = v.replace('.', '->')
    if v == '$this':
        v = 'this'
    if v == 'this':
        return o
    if v.startswith('$this->'):
        return o + v[5:]
    if v.startswith('this->'):
        return o + v[4:]
    if v.startswith('$this['):
        return o + v[5:]
    if v.startswith('this['):
        return o + v[4:]
    return v


def _llm_item_variants(it, ctx: Optional[dict] = None, *, this_obj: str = ''):
    from ..splits.llm_taint_split import llm_item_variants
    from ..splits.llm_var_split import ast_enclosing_prop_id, ast_prop_name, llm_item_variants_by_rules

    if not isinstance(it, dict):
        return []
    try:
        seq = int(it.get('seq'))
    except Exception:
        return []
    nm0 = (it.get('name') or '').strip()
    if not nm0:
        return []

    if not isinstance(ctx, dict):
        return llm_item_variants(it)

    mapped = _map_llm_item_to_node({'seq': seq, 'type': (it.get('type') or ''), 'name': nm0.replace('.', '->')}, ctx, this_obj=this_obj)
    if not isinstance(mapped, dict) or mapped.get('id') is None:
        return []

    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    parent_of = ctx.get('parent_of') or {}
    mtt = (mapped.get('type') or '').strip()
    mnm = (mapped.get('name') or '').replace('.', '->').strip()

    if mtt == 'AST_VAR':
        try:
            prop_id = ast_enclosing_prop_id(int(mapped.get('id')), parent_of, nodes)
        except Exception:
            prop_id = None
        if prop_id is not None:
            nm_prop = ast_prop_name(int(prop_id), nodes, children_of, this_obj=this_obj)
            if nm_prop:
                return llm_item_variants_by_rules({'seq': seq, 'type': 'AST_PROP', 'name': nm_prop})
        this_norm = (this_obj or '').strip().lstrip('$')
        v0 = mnm.lstrip('$')
        if v0 == 'this':
            v0 = this_norm or v0
        return [{'seq': seq, 'type': 'AST_VAR', 'name': v0}]

    if mtt == 'AST_DIM':
        return llm_item_variants_by_rules({'seq': seq, 'type': 'AST_DIM', 'name': mnm})

    if mtt and mnm:
        return llm_item_variants_by_rules({'seq': seq, 'type': mtt, 'name': mnm})

    return []


def _preset_matches_ast_var(
    cand_ids: list,
    *,
    seq: int,
    want_name_norm: str,
    nodes: dict,
    children_of: dict,
    this_obj: str,
) -> list:
    if not want_name_norm:
        return []
    matches = []
    for nid in cand_ids or []:
        nx = nodes.get(nid) or {}
        if (nx.get('type') or '').strip() != 'AST_VAR':
            continue
        src_main = _node_source_str_with_this(nid, 'AST_VAR', nodes, children_of, this_obj).replace('.', '->')
        if not src_main:
            continue
        src_n = _norm_llm_name(src_main)
        if src_n and src_n == want_name_norm:
            matches.append({'id': nid, 'type': 'AST_VAR', 'seq': seq, 'name': src_main, '_score': 3})
    return matches


def _preset_matches_ast_prop(
    cand_ids: list,
    *,
    seq: int,
    want_name_norm: str,
    want_shape: str,
    nodes: dict,
    children_of: dict,
    this_obj: str,
) -> list:
    if not want_name_norm:
        return []
    matches = []
    for nid in cand_ids or []:
        nx = nodes.get(nid) or {}
        if (nx.get('type') or '').strip() != 'AST_PROP':
            continue
        src_main = _node_source_str_with_this(nid, 'AST_PROP', nodes, children_of, this_obj).replace('.', '->')
        if not src_main:
            continue
        src_candidates = [src_main]
        if _subtree_has_string_token(nid, nodes, children_of, 'this'):
            prop = _prop_name_for_alias(nid, nodes, children_of)
            if prop:
                src_candidates.append(f"this->{prop}")
                src_candidates.append(f"$this->{prop}")
        best_local_score = 0
        for src in src_candidates:
            src_n = _norm_llm_name(src)
            if not src_n:
                continue
            score = 0
            if src_n == want_name_norm:
                score = 3
            if score > best_local_score:
                best_local_score = score
        if best_local_score > 0:
            matches.append({'id': nid, 'type': 'AST_PROP', 'seq': seq, 'name': src_main, '_score': best_local_score})
    return matches


def _preset_matches_ast_dim(
    cand_ids: list,
    *,
    seq: int,
    want_name_norm: str,
    want_shape: str,
    nodes: dict,
    children_of: dict,
    this_obj: str,
) -> list:
    if not want_name_norm:
        return []
    want_loose = _strip_quotes(want_name_norm)
    matches = []
    for nid in cand_ids or []:
        nx = nodes.get(nid) or {}
        if (nx.get('type') or '').strip() != 'AST_DIM':
            continue
        src_main = _node_source_str_with_this(nid, 'AST_DIM', nodes, children_of, this_obj).replace('.', '->')
        if not src_main:
            continue
        src_candidates = [src_main]
        if _subtree_has_string_token(nid, nodes, children_of, 'this'):
            src2 = _node_source_str_with_this(nid, 'AST_DIM', nodes, children_of, '').replace('.', '->')
            if src2.startswith('this[') or src2.startswith('$this['):
                src_candidates.append(src2)
        best_local_score = 0
        for src in src_candidates:
            src_n = _norm_llm_name(src)
            if not src_n:
                continue
            src_loose = _strip_quotes(src_n)
            score = 0
            if src_n == want_name_norm:
                score = 3
            elif src_loose and want_loose and src_loose == want_loose:
                score = 2
            elif want_shape:
                try:
                    if _shape_name(src) == want_shape:
                        score = 1
                except Exception:
                    score = 0
            if score > best_local_score:
                best_local_score = score
        if best_local_score > 0:
            matches.append({'id': nid, 'type': 'AST_DIM', 'seq': seq, 'name': src_main, '_score': best_local_score})
    return matches


def _preset_matches_ast_method_call(
    cand_ids: list,
    *,
    seq: int,
    want_name_norm: str,
    nodes: dict,
    children_of: dict,
    this_obj: str,
) -> list:
    if not want_name_norm:
        return []
    want_variants = {want_name_norm}
    if want_name_norm.endswith('()'):
        want_variants.add(want_name_norm[:-2])
    else:
        want_variants.add(want_name_norm + '()')
    matches = []
    for nid in cand_ids or []:
        nx = nodes.get(nid) or {}
        if (nx.get('type') or '').strip() != 'AST_METHOD_CALL':
            continue
        src_main = _node_source_str_with_this(nid, 'AST_METHOD_CALL', nodes, children_of, this_obj).replace('.', '->')
        if not src_main:
            continue
        src_candidates = [src_main]
        if _subtree_has_string_token(nid, nodes, children_of, 'this'):
            fn = _call_name_from_children(int(nid), nodes, children_of)
            if fn:
                fn2 = fn if fn.endswith('()') else f"{fn}()"
                src_candidates.append(f"this->{fn2}")
                src_candidates.append(f"$this->{fn2}")
        best_local_score = 0
        for src in src_candidates:
            src_n = _norm_llm_name(src)
            if not src_n:
                continue
            score = 0
            if src_n in want_variants:
                score = 3
            else:
                for w in want_variants:
                    if not w:
                        continue
                    if src_n.endswith(w) or w.endswith(src_n):
                        score = 2
                        break
                    if src_n.endswith('->' + w):
                        score = 2
                        break
            if score > best_local_score:
                best_local_score = score
        if best_local_score > 0:
            matches.append({'id': nid, 'type': 'AST_METHOD_CALL', 'seq': seq, 'name': src_main, '_score': best_local_score})
    return matches


def _preset_matches_ast_call(
    cand_ids: list,
    *,
    seq: int,
    want_name_norm: str,
    nodes: dict,
    children_of: dict,
    this_obj: str,
) -> list:
    if not want_name_norm:
        return []
    want_variants = {want_name_norm}
    if want_name_norm.endswith('()'):
        want_variants.add(want_name_norm[:-2])
    else:
        want_variants.add(want_name_norm + '()')
    matches = []
    for nid in cand_ids or []:
        nx = nodes.get(nid) or {}
        if (nx.get('type') or '').strip() != 'AST_CALL':
            continue
        src_main = _node_source_str_with_this(nid, 'AST_CALL', nodes, children_of, this_obj).replace('.', '->')
        if not src_main:
            continue
        src_n = _norm_llm_name(src_main)
        if not src_n:
            continue
        score = 0
        if src_n in want_variants:
            score = 3
        else:
            for w in want_variants:
                if len(src_n) >= 4 and len(w) >= 4 and (src_n in w or w in src_n):
                    score = 1
                    break
        if score > 0:
            matches.append({'id': nid, 'type': 'AST_CALL', 'seq': seq, 'name': src_main, '_score': score})
    return matches


def _preset_matches_ast_static_call(
    cand_ids: list,
    *,
    seq: int,
    want_name_norm: str,
    nodes: dict,
    children_of: dict,
    this_obj: str,
) -> list:
    if not want_name_norm:
        return []
    want_variants = {want_name_norm}
    if want_name_norm.endswith('()'):
        want_variants.add(want_name_norm[:-2])
    else:
        want_variants.add(want_name_norm + '()')
    matches = []
    for nid in cand_ids or []:
        nx = nodes.get(nid) or {}
        if (nx.get('type') or '').strip() != 'AST_STATIC_CALL':
            continue
        src_main = _node_source_str_with_this(nid, 'AST_STATIC_CALL', nodes, children_of, this_obj).replace('.', '->')
        if not src_main:
            continue
        src_n = _norm_llm_name(src_main)
        if not src_n:
            continue
        score = 0
        if src_n in want_variants:
            score = 3
        else:
            for w in want_variants:
                if len(src_n) >= 4 and len(w) >= 4 and (src_n in w or w in src_n):
                    score = 1
                    break
        if score > 0:
            matches.append({'id': nid, 'type': 'AST_STATIC_CALL', 'seq': seq, 'name': src_main, '_score': score})
    return matches


def _preset_matches_for_type(
    cand_ids: list,
    *,
    seq: int,
    want_name_norm: str,
    want_shape: str,
    want_type: str,
    nodes: dict,
    children_of: dict,
    this_obj: str,
) -> list:
    wtype = (want_type or '').strip()
    if wtype == 'AST_VAR':
        return _preset_matches_ast_var(cand_ids, seq=seq, want_name_norm=want_name_norm, nodes=nodes, children_of=children_of, this_obj=this_obj)
    if wtype == 'AST_PROP':
        return _preset_matches_ast_prop(
            cand_ids,
            seq=seq,
            want_name_norm=want_name_norm,
            want_shape=want_shape,
            nodes=nodes,
            children_of=children_of,
            this_obj=this_obj,
        )
    if wtype == 'AST_DIM':
        return _preset_matches_ast_dim(
            cand_ids,
            seq=seq,
            want_name_norm=want_name_norm,
            want_shape=want_shape,
            nodes=nodes,
            children_of=children_of,
            this_obj=this_obj,
        )
    if wtype == 'AST_METHOD_CALL':
        return _preset_matches_ast_method_call(
            cand_ids,
            seq=seq,
            want_name_norm=want_name_norm,
            nodes=nodes,
            children_of=children_of,
            this_obj=this_obj,
        )
    if wtype == 'AST_CALL':
        return _preset_matches_ast_call(
            cand_ids,
            seq=seq,
            want_name_norm=want_name_norm,
            nodes=nodes,
            children_of=children_of,
            this_obj=this_obj,
        )
    if wtype == 'AST_STATIC_CALL':
        return _preset_matches_ast_static_call(
            cand_ids,
            seq=seq,
            want_name_norm=want_name_norm,
            nodes=nodes,
            children_of=children_of,
            this_obj=this_obj,
        )
    return []


def _subtree_has_string_token(root_id: int, nodes: dict, children_of: dict, token: str) -> bool:
    want = (token or '').strip()
    if not want:
        return False
    q = [int(root_id)]
    seen_local = set()
    cap = 800
    while q and len(seen_local) < cap:
        x = q.pop()
        if x in seen_local:
            continue
        seen_local.add(x)
        nx = nodes.get(x) or {}
        if nx.get('labels') == 'string' or (nx.get('type') or '').strip() == 'string':
            v = (nx.get('code') or nx.get('name') or '').strip()
            if v == want:
                return True
        for c in children_of.get(x, []) or []:
            try:
                q.append(int(c))
            except Exception:
                continue
    return False


def _prop_name_for_alias(prop_id: int, nodes: dict, children_of: dict) -> str:
    ch = list(children_of.get(int(prop_id), []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    toks = []
    for c in ch:
        cx = nodes.get(c) or {}
        if cx.get('labels') == 'string' or (cx.get('type') or '').strip() == 'string':
            v = (cx.get('code') or cx.get('name') or '').strip()
            if v:
                toks.append(v)
    for v in reversed(toks):
        if v not in ('this', '$this'):
            return v
    return (toks[-1] if toks else '').strip()


def _is_nonstandalone_var(var_id: int, ctx: dict, *, this_obj: str = '') -> bool:
    if not isinstance(ctx, dict) or var_id is None:
        return False
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    parent_of = ctx.get('parent_of') or {}
    if not nodes or not children_of or not parent_of:
        return False
    def _sorted_children(xid: int) -> List[int]:
        ch = list(children_of.get(int(xid), []) or [])
        ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
        out = []
        for c in ch:
            try:
                out.append(int(c))
            except Exception:
                continue
        return out

    def _prop_base_child_id(prop_id: int) -> Optional[int]:
        for c in _sorted_children(prop_id):
            cx = nodes.get(c) or {}
            tt = (cx.get('type') or '').strip()
            if tt == 'AST_ARG_LIST':
                continue
            if cx.get('labels') == 'string' or tt == 'string':
                continue
            return int(c)
        return None

    def _method_call_recv_child_id(call_id: int) -> Optional[int]:
        for c in _sorted_children(call_id):
            cx = nodes.get(c) or {}
            tt = (cx.get('type') or '').strip()
            if tt == 'AST_ARG_LIST':
                continue
            if cx.get('labels') == 'string' or tt == 'string':
                continue
            return int(c)
        return None

    try:
        from .llm_var_split import ast_dim_base_id
    except Exception:
        ast_dim_base_id = None
    if ast_dim_base_id is None:
        return False

    try:
        cur = int(var_id)
    except Exception:
        return False
    prev = cur
    depth = 0
    while depth < 20:
        pid = parent_of.get(cur)
        if pid is None:
            break
        try:
            pid_i = int(pid)
        except Exception:
            break
        pt = ((nodes.get(pid_i) or {}).get('type') or '').strip()
        if pt == 'AST_DIM':
            try:
                base_id = ast_dim_base_id(pid_i, children_of, nodes)
            except Exception:
                base_id = None
            if base_id is not None and int(base_id) == int(prev):
                return True
        elif pt == 'AST_PROP':
            base_child = _prop_base_child_id(pid_i)
            if base_child is not None and int(base_child) == int(prev):
                return True
        elif pt == 'AST_METHOD_CALL':
            recv_child = _method_call_recv_child_id(pid_i)
            if recv_child is not None and int(recv_child) == int(prev):
                return True
        prev = pid_i
        cur = pid_i
        depth += 1
    return False


def _promote_nonstandalone_var(var_id: int, ctx: dict, *, this_obj: str = '') -> Optional[dict]:
    if not isinstance(ctx, dict) or var_id is None:
        return None
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    parent_of = ctx.get('parent_of') or {}
    if not nodes or not children_of or not parent_of:
        return None
    try:
        from .llm_var_split import ast_enclosing_kind_id
    except Exception:
        ast_enclosing_kind_id = None
    if ast_enclosing_kind_id is None:
        return None
    var_src = _norm_llm_name(_node_source_str_with_this(int(var_id), 'AST_VAR', nodes, children_of, this_obj).replace('.', '->'))
    if not var_src:
        return None
    for kind, sep in (('AST_METHOD_CALL', '->'), ('AST_PROP', '->'), ('AST_DIM', '[')):
        try:
            enc_id = ast_enclosing_kind_id(int(var_id), kind, parent_of, nodes, max_up=10)
        except Exception:
            enc_id = None
        if enc_id is None:
            continue
        enc_src = _node_source_str_with_this(int(enc_id), kind, nodes, children_of, this_obj).replace('.', '->')
        enc_n = _norm_llm_name(enc_src)
        if not enc_n:
            continue
        if enc_n.startswith(var_src + sep):
            return {'id': int(enc_id), 'type': kind, 'name': enc_src}
    return None


def _record_for_seq(seq, trace_index_records, seq_to_index):
    """Return the trace index record for `seq` (fast path: seq_to_index)."""
    idx = seq_to_index.get(seq)
    if idx is not None and 0 <= idx < len(trace_index_records):
        return trace_index_records[idx]
    for r in trace_index_records:
        if seq in (r.get('seqs') or []):
            return r
    return None


def _node_source_str(nid, ntype, nodes, children_of):
    """Compute a normalized source string for a node, used for LLM name matching."""
    if ntype == 'AST_VAR':
        _, nm = _node_display(nid, nodes, children_of)
        return nm
    if ntype == 'AST_PROP':
        base = find_first_var_string(nid, children_of, nodes)
        ch = list(children_of.get(int(nid), []) or [])
        ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
        prop = ''
        if len(ch) >= 2:
            try:
                _, prop_nm = _node_display(int(ch[1]), nodes, children_of)
            except Exception:
                prop_nm = ''
            prop = (prop_nm or '').strip()
        if not prop:
            ss = get_string_children(nid, children_of, nodes)
            prop = ss[0][1] if ss else ''
        if base and prop:
            return f"{base}->{prop}"
        _, nm = _node_display(nid, nodes, children_of)
        return nm.replace('.', '->')
    if ntype == 'AST_DIM':
        def sorted_children(xid):
            ch = list(children_of.get(xid, []) or [])
            ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
            return ch

        def expr_str(xid, depth: int = 0) -> str:
            if xid is None or depth > 6:
                return ''
            nx = nodes.get(xid) or {}
            tt = (nx.get('type') or '').strip()
            if tt in ('AST_VAR', 'AST_PROP', 'AST_CALL', 'AST_METHOD_CALL'):
                return _node_source_str(xid, tt, nodes, children_of) or ''
            if tt == 'AST_DIM':
                ch = sorted_children(xid)
                if len(ch) >= 2:
                    base_s = expr_str(ch[0], depth + 1) or (find_first_var_string(xid, children_of, nodes) or '')
                    key_s = expr_str(ch[1], depth + 1)
                    if not key_s:
                        ss2 = get_string_children(xid, children_of, nodes)
                        key_s = ss2[0][1] if ss2 else ''
                    if base_s and key_s:
                        return f"{base_s}[{key_s}]"
                base = find_first_var_string(xid, children_of, nodes)
                ss3 = get_string_children(xid, children_of, nodes)
                key = ss3[0][1] if ss3 else ''
                if base and key:
                    return f"{base}[{key}]"
                _, nm = _node_display(xid, nodes, children_of)
                return nm
            if tt in ('AST_CONST', 'AST_NAME', 'string', 'integer', 'double'):
                _, nm = _node_display(xid, nodes, children_of)
                return nm
            _, nm = _node_display(xid, nodes, children_of)
            return nm

        s = expr_str(nid, 0)
        if s:
            return s
        _, nm = _node_display(nid, nodes, children_of)
        return nm
    if ntype == 'AST_CALL':
        _, nm = _node_display(nid, nodes, children_of)
        if nm and not nm.endswith('()'):
            nm = f"{nm}()"
        return nm
    if ntype == 'AST_STATIC_CALL':
        cls, fn = _static_call_parts_from_children(nid, nodes, children_of)
        if fn and not fn.endswith('()'):
            fn = f"{fn}()"
        if cls and fn:
            return f"{cls}::{fn}"
        return fn or cls
    if ntype == 'AST_METHOD_CALL':
        fn = _call_name_from_children(nid, nodes, children_of)
        recv = _method_call_recv_name(nid, nodes, children_of)
        if fn and not fn.endswith('()'):
            fn = f"{fn}()"
        return f"{recv}->{fn}" if recv else fn
    return ''

def _node_source_str_with_this(nid, ntype, nodes, children_of, this_obj: str = '') -> str:
    if nid is None:
        return ''
    try:
        nid_i = int(nid)
    except Exception:
        return ''
    tt = (ntype or '').strip()
    if tt == 'AST_VAR':
        ss = get_string_children(nid_i, children_of, nodes)
        nm = (ss[0][1] if ss else '')
        if nm in ('this', '$this') and this_obj:
            return this_obj.lstrip('$')
        return nm
    if tt == 'AST_PROP':
        ch = list(children_of.get(nid_i, []) or [])
        ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)

        str_tokens = []
        for c in ch:
            cx = nodes.get(c) or {}
            if cx.get('labels') == 'string' or (cx.get('type') or '').strip() == 'string':
                v = (cx.get('code') or cx.get('name') or '').strip()
                if v:
                    str_tokens.append(v)

        base = (find_first_var_string(nid_i, children_of, nodes) or '').strip()
        if not base and str_tokens:
            base = (str_tokens[0] or '').strip()
        if base in ('this', '$this') and this_obj:
            base = this_obj.lstrip('$')
        base = base.lstrip('$')

        prop = ''
        if str_tokens:
            for v in reversed(str_tokens):
                if v not in ('this', '$this'):
                    prop = v
                    break
            if not prop:
                prop = str_tokens[-1]

        if base and prop:
            return f"{base}->{prop}"

        _, nm = _node_display(nid_i, nodes, children_of)
        nm = (nm or '').replace('.', '->').strip()
        if nm and this_obj:
            if nm.startswith('this->') or nm.startswith('$this->'):
                nm = this_obj.lstrip('$') + nm.split('this', 1)[1]
        return nm
    if tt == 'AST_DIM':
        def sorted_children(xid):
            ch = list(children_of.get(xid, []) or [])
            ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
            return ch

        def expr_str(xid, depth: int = 0) -> str:
            if xid is None or depth > 6:
                return ''
            nx = nodes.get(xid) or {}
            t2 = (nx.get('type') or '').strip()
            if t2 in ('AST_VAR', 'AST_PROP', 'AST_CALL', 'AST_STATIC_CALL', 'AST_METHOD_CALL'):
                return _node_source_str_with_this(xid, t2, nodes, children_of, this_obj) or ''
            if t2 == 'AST_DIM':
                ch2 = sorted_children(xid)
                if len(ch2) >= 2:
                    base_s = expr_str(ch2[0], depth + 1) or (find_first_var_string(xid, children_of, nodes) or '')
                    if base_s in ('this', '$this') and this_obj:
                        base_s = this_obj.lstrip('$')
                    key_s = expr_str(ch2[1], depth + 1)
                    if not key_s:
                        ss2 = get_string_children(xid, children_of, nodes)
                        key_s = ss2[0][1] if ss2 else ''
                    if base_s and key_s:
                        return f"{base_s}[{key_s}]"
                base = find_first_var_string(xid, children_of, nodes)
                if base in ('this', '$this') and this_obj:
                    base = this_obj.lstrip('$')
                ss3 = get_string_children(xid, children_of, nodes)
                key = ss3[0][1] if ss3 else ''
                if base and key:
                    return f"{base}[{key}]"
                _, nm2 = _node_display(xid, nodes, children_of)
                return nm2
            if t2 in ('AST_CONST', 'AST_NAME', 'string', 'integer', 'double'):
                _, nm2 = _node_display(xid, nodes, children_of)
                return nm2
            _, nm2 = _node_display(xid, nodes, children_of)
            return nm2

        s = expr_str(nid_i, 0)
        if s:
            return s.replace('.', '->')
        _, nm = _node_display(nid_i, nodes, children_of)
        return (nm or '').replace('.', '->')
    if tt == 'AST_CALL':
        _, nm = _node_display(nid_i, nodes, children_of)
        nm = (nm or '').strip()
        if nm and not nm.endswith('()'):
            nm = f"{nm}()"
        return nm
    if tt == 'AST_STATIC_CALL':
        cls, fn = _static_call_parts_from_children(nid_i, nodes, children_of)
        if fn and not fn.endswith('()'):
            fn = f"{fn}()"
        if cls and fn:
            return f"{cls}::{fn}"
        return fn or cls
    if tt == 'AST_METHOD_CALL':
        fn = _call_name_from_children(nid_i, nodes, children_of)
        recv = _method_call_recv_name(nid_i, nodes, children_of, this_obj=this_obj)
        if fn and not fn.endswith('()'):
            fn = f"{fn}()"
        return f"{recv}->{fn}" if recv else fn
    return _node_source_str(nid_i, tt, nodes, children_of).replace('.', '->')


def _map_llm_item_to_node(it, ctx, *, this_obj: str = ''):
    """Map an `(seq,type,name)` LLM item to a concrete node id within that trace record."""
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    allowed = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL'}
    lg = ctx.get('logger') if isinstance(ctx, dict) else None
    if not isinstance(it, dict):
        return None
    try:
        seq = int(it.get('seq'))
    except Exception:
        return None
    tt_llm = (it.get('type') or '').strip()
    nm = (it.get('name') or '').strip()
    if not nm:
        return None
    nm = nm.replace('.', '->')
    if this_obj:
        nm = _rewrite_this_prefix(nm, this_obj)
    nm_n = _norm_llm_name(nm)
    nm_shape = _shape_name(nm)
    if not nm_n:
        return None
    if '(' in nm_n and ')' in nm_n:
        nm_n = _PAREN_RE.sub('()', nm_n)
    rec = _record_for_seq(seq, recs, seq_to_idx)
    node_ids = rec.get('node_ids') if isinstance(rec, dict) else []
    cand_ids = list(node_ids or [])
    if lg is not None:
        lg.debug('llm_map_start', seq=seq, llm_type=tt_llm, llm_name=nm_n, node_ids_count=len(node_ids or []), expanded_ids_count=len(cand_ids or []))

    cand_preview = []
    for nid in cand_ids or []:
        if len(cand_preview) >= 30:
            break
        nx = nodes.get(nid) or {}
        nt = (nx.get('type') or '').strip()
        if nt not in allowed:
            continue
        src_main = _node_source_str_with_this(nid, nt, nodes, children_of, this_obj).replace('.', '->')
        src_n = _norm_llm_name(src_main)
        if src_main and src_n:
            cand_preview.append({'id': nid, 'type': nt, 'src': src_main, 'src_n': src_n})

    matches = []
    if ':' in nm_n:
        static_name = _normalize_static_call_name(nm_n)
        if static_name:
            matches = _preset_matches_ast_static_call(
                cand_ids,
                seq=seq,
                want_name_norm=static_name,
                nodes=nodes,
                children_of=children_of,
                this_obj=this_obj,
            )
    if not matches:
        for wtype in ('AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_STATIC_CALL', 'AST_CALL', 'AST_VAR'):
            matches.extend(
                _preset_matches_for_type(
                    cand_ids,
                    seq=seq,
                    want_name_norm=nm_n,
                    want_shape=nm_shape,
                    want_type=wtype,
                    nodes=nodes,
                    children_of=children_of,
                    this_obj=this_obj,
                )
            )

    if matches:
        matches2 = []
        for m in matches:
            if (m.get('type') or '').strip() == 'AST_VAR':
                try:
                    if _is_nonstandalone_var(int(m.get('id')), ctx, this_obj=this_obj):
                        promoted = _promote_nonstandalone_var(int(m.get('id')), ctx, this_obj=this_obj)
                        if promoted is not None:
                            mm = dict(m)
                            mm['id'] = int(promoted.get('id'))
                            mm['type'] = (promoted.get('type') or '').strip()
                            mm['name'] = (promoted.get('name') or '').strip()
                            matches2.append(mm)
                        continue
                except Exception:
                    pass
            matches2.append(m)
        matches = matches2

    if not matches:
        if tt_llm in allowed:
            has_llm_type = False
            for nid in cand_ids or []:
                if (nodes.get(nid) or {}).get('type') == tt_llm:
                    has_llm_type = True
                    break
            if has_llm_type:
                matches = _preset_matches_for_type(
                    cand_ids,
                    seq=seq,
                    want_name_norm=nm_n,
                    want_shape=nm_shape,
                    want_type=tt_llm,
                    nodes=nodes,
                    children_of=children_of,
                    this_obj=this_obj,
                )
                if tt_llm == 'AST_VAR' and matches:
                    matches = [m for m in matches if not _is_nonstandalone_var(int(m.get('id')), ctx, this_obj=this_obj)]

    if not matches and ':' in nm_n:
        cls, fn = _split_static_call_name(nm_n)
        for part in (fn, cls):
            if not part:
                continue
            part_shape = _shape_name(part)
            part_matches = []
            for wtype in ('AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL', 'AST_VAR', 'AST_STATIC_CALL'):
                part_matches.extend(
                    _preset_matches_for_type(
                        cand_ids,
                        seq=seq,
                        want_name_norm=part,
                        want_shape=part_shape,
                        want_type=wtype,
                        nodes=nodes,
                        children_of=children_of,
                        this_obj=this_obj,
                    )
                )
            if part_matches:
                matches = part_matches
                break

    if not matches:
        if lg is not None:
            lg.log_json('DEBUG', 'llm_map_no_match_candidates', {'seq': seq, 'llm_type': tt_llm, 'llm_name': nm_n, 'candidates': cand_preview})
        return None
    best_score = max(m.get('_score') or 0 for m in matches)
    best = [m for m in matches if (m.get('_score') or 0) == best_score]
    if len(best) == 1:
        picked = best[0]
        if lg is not None:
            lg.debug('llm_map_picked', seq=seq, llm_type=tt_llm, llm_name=nm_n, picked_id=picked.get('id'), picked_type=picked.get('type'), picked_name=picked.get('name'), score=best_score)
        return {'id': picked['id'], 'type': picked['type'], 'seq': picked['seq'], 'name': picked['name']}
    preferred = None
    if '::' in nm_n or ':' in nm_n:
        preferred = 'AST_STATIC_CALL'
    elif '->' in nm_n and nm_n.endswith('()'):
        preferred = 'AST_METHOD_CALL'
    elif nm_n.endswith('()'):
        preferred = 'AST_CALL'
    elif '[' in nm_n and ']' in nm_n:
        preferred = 'AST_DIM'
    elif '->' in nm_n:
        preferred = 'AST_PROP'
    else:
        preferred = 'AST_VAR'
    cand2 = [m for m in best if m.get('type') == preferred]
    if not cand2 and preferred != 'AST_VAR':
        cand2 = [m for m in best if m.get('type') == 'AST_VAR']
    if cand2:
        cand2.sort(key=lambda m: int(m.get('id') or 10**18))
        picked = cand2[0]
        return {'id': picked['id'], 'type': picked['type'], 'seq': picked['seq'], 'name': picked['name']}
    best.sort(key=lambda m: int(m.get('id') or 10**18))
    picked = best[0]
    return {'id': picked['id'], 'type': picked['type'], 'seq': picked['seq'], 'name': picked['name']}


def map_llm_taints_to_nodes(llm_taints, ctx, *, this_obj: str = ''):
    """Map LLM taints into concrete node taints, expanding variants and de-duplicating."""
    out = []
    seen = set()
    for it in llm_taints or []:
        for v in _llm_item_variants(it, ctx, this_obj=this_obj):
            mapped = _map_llm_item_to_node(v, ctx, this_obj=this_obj)
            if not mapped:
                continue
            k = (int(mapped.get('id')), int(mapped.get('seq')))
            if k in seen:
                continue
            seen.add(k)
            out.append(mapped)
    return out


def _expand_var_components(taint_node: dict, ctx, *, this_obj: str = '') -> list:
    """Expand a variable-like node taint into its AST component vars/props/dims."""
    if not isinstance(taint_node, dict) or not isinstance(ctx, dict):
        return []
    nid = taint_node.get('id')
    nseq = taint_node.get('seq')
    if nid is None or nseq is None:
        return []
    try:
        nid_i = int(nid)
        seq_i = int(nseq)
    except Exception:
        return []
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    parent_of = ctx.get('parent_of') or {}
    from ..splits.llm_var_split import ast_enclosing_prop_id, ast_dim_base_id
    root_name = (taint_node.get('name') or '').strip().replace('.', '->')
    if root_name.startswith('$'):
        root_name = root_name[1:]
    root_recv = ''
    if '[' in root_name:
        root_name = (root_name.split('[', 1)[0] or '').strip()
    if '->' in root_name:
        root_recv = (root_name.split('->', 1)[0] or '').strip().lstrip('$')

    def sorted_children(xid: int) -> list:
        ch = list(children_of.get(xid, []) or [])
        ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
        return ch

    out = []
    seen_ids = set()
    root_tt = ((nodes.get(nid_i) or {}).get('type') or '').strip()
    if root_tt == 'AST_DIM':
        ch = sorted_children(nid_i)
        base_id = None
        try:
            base_id = ast_dim_base_id(int(nid_i), children_of, nodes)
        except Exception:
            base_id = None
        q = []
        for c in ch:
            try:
                c_i = int(c)
            except Exception:
                continue
            if base_id is not None and int(base_id) == c_i:
                continue
            q.append(c_i)
    else:
        q = [nid_i]
    cap = 2000
    while q and len(seen_ids) < cap:
        x = q.pop()
        if x in seen_ids:
            continue
        seen_ids.add(x)
        nx = nodes.get(x) or {}
        tt = (nx.get('type') or '').strip()
        if tt in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
            if tt == 'AST_VAR':
                prop_id = ast_enclosing_prop_id(x, parent_of, nodes)
                if prop_id is not None:
                    nm_prop = _node_source_str_with_this(int(prop_id), 'AST_PROP', nodes, children_of, this_obj=this_obj)
                    if nm_prop:
                        out.append({'id': int(prop_id), 'type': 'AST_PROP', 'seq': seq_i, 'name': nm_prop})
                else:
                    nm = _node_source_str_with_this(x, tt, nodes, children_of, this_obj=this_obj)
                    if nm:
                        nm0 = (nm or '').strip()
                        if nm0.startswith('$'):
                            nm0 = nm0[1:]
                        if nm0 == 'this':
                            nm = ''
                        if root_recv and nm0 == root_recv:
                            nm = ''
                        if nm:
                            out.append({'id': x, 'type': tt, 'seq': seq_i, 'name': nm})
            else:
                nm = _node_source_str_with_this(x, tt, nodes, children_of, this_obj=this_obj)
                if nm:
                    out.append({'id': x, 'type': tt, 'seq': seq_i, 'name': nm})
        for c in sorted_children(x):
            if c not in seen_ids:
                q.append(c)

    up = nid_i
    up_cap = 20
    up_depth = 0
    while up is not None and up_depth < up_cap:
        pid = parent_of.get(up)
        if pid is None:
            break
        try:
            pid_i = int(pid)
        except Exception:
            break
        if pid_i in seen_ids:
            break
        seen_ids.add(pid_i)
        nx = nodes.get(pid_i) or {}
        tt = (nx.get('type') or '').strip()
        if tt in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
            if tt == 'AST_VAR':
                prop_id = ast_enclosing_prop_id(pid_i, parent_of, nodes)
                if prop_id is not None:
                    nm_prop = _node_source_str_with_this(int(prop_id), 'AST_PROP', nodes, children_of, this_obj=this_obj)
                    if nm_prop:
                        out.append({'id': int(prop_id), 'type': 'AST_PROP', 'seq': seq_i, 'name': nm_prop})
                else:
                    nm = _node_source_str_with_this(pid_i, tt, nodes, children_of, this_obj=this_obj)
                    if nm:
                        nm0 = (nm or '').strip()
                        if nm0.startswith('$'):
                            nm0 = nm0[1:]
                        if nm0 == 'this':
                            nm = ''
                        if root_recv and nm0 == root_recv:
                            nm = ''
                        if nm:
                            out.append({'id': pid_i, 'type': tt, 'seq': seq_i, 'name': nm})
            else:
                nm = _node_source_str_with_this(pid_i, tt, nodes, children_of, this_obj=this_obj)
                if nm:
                    out.append({'id': pid_i, 'type': tt, 'seq': seq_i, 'name': nm})
        up = pid_i
        up_depth += 1
    return out


def _map_llm_node_cached(node, cache, ctx, *, this_obj: str = ''):
    """Map an LLM node dict to a taint node using a `(seq,type,name)` cache."""
    if not isinstance(node, dict):
        return None
    nm = (node.get('name') or '').strip()
    if not nm:
        return None
    tt = (node.get('type') or '').strip()
    if tt == 'AST_PROP':
        nm = nm.replace('.', '->')
    elif tt == 'AST_METHOD_CALL':
        nm = nm.replace('.', '->')
    nm_n = _norm_llm_name(nm)
    try:
        seq = int(node.get('seq'))
    except Exception:
        return None
    k = (seq, tt, nm_n, (this_obj or '').strip().lstrip('$'))
    if k in cache:
        return cache.get(k)
    out = _map_llm_item_to_node({'seq': seq, 'type': tt, 'name': nm}, ctx, this_obj=this_obj)
    cache[k] = out
    return out


def map_llm_edges_to_nodes(llm_edges, ctx, *, this_obj: str = ''):
    """Map LLM dataflow edges to concrete `(src,dst)` node edges."""
    cache = ctx.setdefault('_llm_node_map_cache', {})
    out = []
    for e in llm_edges or []:
        if not isinstance(e, dict):
            continue
        src = e.get('src')
        dst = e.get('dst')
        msrc = _map_llm_node_cached(src, cache, ctx, this_obj=this_obj)
        mdst = _map_llm_node_cached(dst, cache, ctx, this_obj=this_obj)
        if not msrc or not mdst:
            continue
        out.append({'src': msrc, 'dst': mdst})
    return out

