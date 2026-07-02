import re
from typing import List, Optional, Set

from utils.extractors.if_extract import get_string_children, find_first_var_string


_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_PAREN_RE = re.compile(r'\([^)]*\)')


def _strip_dollar(s: str) -> str:
    v = (s or '').strip()
    if v.startswith('$'):
        return v[1:]
    return v


def _normalize_name(name: str) -> str:
    return (name or '').strip().replace('.', '->')


def _strip_parens(name: str) -> str:
    v = _normalize_name(name)
    if '(' in v and ')' in v:
        v = _PAREN_RE.sub('()', v)
    return v


def _pick_identifier(x: str) -> str:
    s = (x or '').strip()
    if not s:
        return ''
    if s.startswith('$'):
        s = s[1:]
    if _IDENT_RE.match(s):
        return s
    return ''


def _extract_index_tokens_from_name(name: str) -> List[str]:
    v = _normalize_name(name)
    out: List[str] = []
    seen: Set[str] = set()
    for m in re.finditer(r'\[([^\]]*)\]', v):
        inner = (m.group(1) or '').strip()
        if not inner:
            continue
        for tok in re.split(r'[^A-Za-z0-9_$]+', inner):
            tok = tok.strip().strip("'\"")
            if not tok:
                continue
            got = _pick_identifier(tok)
            if not got or got in seen:
                continue
            seen.add(got)
            out.append(got)
    return out


def _base_before_first_index(name: str) -> str:
    v = _normalize_name(name)
    if '[' not in v:
        return v
    return (v.split('[', 1)[0] or '').strip()


def _last_chain_atom(name: str) -> str:
    v = _strip_parens(name)
    if not v:
        return ''
    v = v.replace('$', '')
    if '->' not in v:
        if v.endswith('()'):
            return v
        return f'{v}()'
    parts = [p for p in v.split('->') if p]
    if not parts:
        return ''
    last = parts[-1].strip()
    if not last:
        return ''
    if last.endswith('()'):
        return last
    return f'{last}()'


def ast_enclosing_kind_id(nid: int, kind: str, parent_of: dict, nodes: dict, *, max_up: int = 12) -> Optional[int]:
    if nid is None:
        return None
    try:
        cur = int(nid)
    except Exception:
        return None
    want = (kind or '').strip()
    if not want:
        return None
    seen = set()
    for _ in range(max(1, int(max_up))):
        if cur in seen:
            break
        seen.add(cur)
        p = parent_of.get(cur)
        if p is None:
            return None
        try:
            p_i = int(p)
        except Exception:
            return None
        pt = (nodes.get(p_i) or {}).get('type')
        if (pt or '').strip() == want:
            return p_i
        cur = p_i
    return None


def ast_enclosing_prop_id(nid: int, parent_of: dict, nodes: dict) -> Optional[int]:
    return ast_enclosing_kind_id(nid, 'AST_PROP', parent_of, nodes, max_up=12)


def ast_dim_base_id(dim_id: int, children_of: dict, nodes: dict) -> Optional[int]:
    if dim_id is None:
        return None
    try:
        did = int(dim_id)
    except Exception:
        return None
    ch = list(children_of.get(did, []) or [])
    if not ch:
        return None
    def child_key(x):
        nx = nodes.get(int(x)) or {}
        cn = nx.get('childnum')
        cn_i = int(cn) if cn is not None else 10**9
        tt = (nx.get('type') or '').strip()
        rank = 5
        if tt == 'AST_PROP':
            rank = 1
        elif tt == 'AST_DIM':
            rank = 2
        elif tt == 'AST_METHOD_CALL':
            rank = 3
        elif tt == 'AST_VAR':
            rank = 4
        return (cn_i, rank)
    try:
        ch.sort(key=child_key)
    except Exception:
        pass
    for x in ch:
        try:
            return int(x)
        except Exception:
            continue
    return None


def ast_dim_base_root_id(dim_id: int, children_of: dict, nodes: dict) -> Optional[int]:
    cur = dim_id
    seen = set()
    for _ in range(10):
        if cur is None:
            return None
        try:
            cur_i = int(cur)
        except Exception:
            return None
        if cur_i in seen:
            return None
        seen.add(cur_i)
        base = ast_dim_base_id(cur_i, children_of, nodes)
        if base is None:
            return None
        bt = (nodes.get(base) or {}).get('type') or ''
        bt = bt.strip()
        if bt != 'AST_DIM':
            return base
        cur = base
    return None


def ast_prop_name(prop_id: int, nodes: dict, children_of: dict, *, this_obj: str = '') -> str:
    if prop_id is None:
        return ''
    try:
        pid = int(prop_id)
    except Exception:
        return ''
    ch = list(children_of.get(pid, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)

    str_tokens = []
    for c in ch:
        cx = nodes.get(c) or {}
        if cx.get('labels') == 'string' or (cx.get('type') or '').strip() == 'string':
            v = (cx.get('code') or cx.get('name') or '').strip()
            if v:
                str_tokens.append(v)

    base = (find_first_var_string(pid, children_of, nodes) or '').strip()
    if not base and str_tokens:
        base = (str_tokens[0] or '').strip()
    if base in ('this', '$this') and this_obj:
        base = this_obj.lstrip('$')
    base = _strip_dollar(base)

    prop = ''
    if str_tokens:
        for v in reversed(str_tokens):
            if v not in ('this', '$this'):
                prop = v
                break
    prop = (prop or '').strip()
    if prop.startswith('$'):
        prop = prop[1:]

    if base and prop:
        return f'{base}->{prop}'
    nx = nodes.get(pid) or {}
    nm = (nx.get('code') or nx.get('name') or '').strip()
    nm = _strip_dollar(nm).replace('.', '->')
    return nm


def case_keep_simple_prop_or_method(it: dict) -> Optional[List[dict]]:
    tt = (it.get('type') or '').strip()
    if tt not in ('AST_PROP', 'AST_METHOD_CALL'):
        return None
    nm = _strip_parens(it.get('name') or '')
    if not nm:
        return None
    if '[' in nm or ']' in nm:
        return None
    parts = [p for p in nm.split('->') if p]
    if len(parts) != 2:
        return None
    return [{'seq': int(it.get('seq')), 'type': tt, 'name': nm}]


def case_dim_only_split(it: dict) -> Optional[List[dict]]:
    tt = (it.get('type') or '').strip()
    if tt != 'AST_DIM':
        return None
    nm = _strip_parens(it.get('name') or '')
    if '[' not in nm or ']' not in nm:
        return None
    base = _base_before_first_index(nm)
    if not base or '->' in base:
        return None
    toks = _extract_index_tokens_from_name(nm)
    out = [{'seq': int(it.get('seq')), 'type': 'AST_DIM', 'name': nm}]
    for t in toks:
        out.append({'seq': int(it.get('seq')), 'type': 'AST_VAR', 'name': t})
    return out


def case_prop_dim_mixed_split(it: dict) -> Optional[List[dict]]:
    tt = (it.get('type') or '').strip()
    if tt != 'AST_DIM':
        return None
    nm = _strip_parens(it.get('name') or '')
    if '[' not in nm or ']' not in nm:
        return None
    base = _base_before_first_index(nm)
    if not base or '->' not in base:
        return None
    parts = [p for p in base.split('->') if p]
    if len(parts) != 2:
        return None
    base_prop = parts[0] + '->' + parts[1]
    toks = _extract_index_tokens_from_name(nm)
    out = [{'seq': int(it.get('seq')), 'type': 'AST_PROP', 'name': base_prop}]
    for t in toks:
        out.append({'seq': int(it.get('seq')), 'type': 'AST_VAR', 'name': t})
    return out


def case_weird_method_call_keep_last(it: dict) -> Optional[List[dict]]:
    nm0 = (it.get('name') or '').strip()
    nm = _strip_parens(nm0)
    if not nm or '->' not in nm:
        return None
    parts = [p for p in nm.split('->') if p]
    call_count = nm.count('()')
    if call_count >= 2:
        last = _last_chain_atom(nm)
        if last:
            return [{'seq': int(it.get('seq')), 'type': 'AST_METHOD_CALL', 'name': last}]
        return [{'seq': int(it.get('seq')), 'type': 'AST_METHOD_CALL', 'name': nm}]
    if '[' in nm and ']' in nm and nm.endswith('()'):
        last = _last_chain_atom(nm)
        if last:
            return [{'seq': int(it.get('seq')), 'type': 'AST_METHOD_CALL', 'name': last}]
        return [{'seq': int(it.get('seq')), 'type': 'AST_METHOD_CALL', 'name': nm}]
    if len(parts) >= 3:
        last = _last_chain_atom(nm)
        if last:
            return [{'seq': int(it.get('seq')), 'type': 'AST_METHOD_CALL', 'name': last}]
        return [{'seq': int(it.get('seq')), 'type': 'AST_METHOD_CALL', 'name': nm}]
    return None


def llm_item_variants_by_rules(it: dict) -> List[dict]:
    if not isinstance(it, dict):
        return []
    try:
        seq = int(it.get('seq'))
    except Exception:
        return []
    tt = (it.get('type') or '').strip()
    nm = (it.get('name') or '').strip()
    if not tt or not nm:
        return []
    it2 = {'seq': seq, 'type': tt, 'name': nm}

    for fn in (
        case_keep_simple_prop_or_method,
        case_dim_only_split,
        case_prop_dim_mixed_split,
        case_weird_method_call_keep_last,
    ):
        got = fn(it2)
        if got:
            return got

    nm2 = _strip_parens(nm)
    return [{'seq': seq, 'type': tt, 'name': nm2}]

