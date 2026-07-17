"""
Scope-selection optimizations for LLM prompting (scope dedupe, parent-child scope relations, merging).
"""
from typing import FrozenSet, Iterable, List, Optional, Tuple


def scope_seqs_from_scope_locs(*, scope_locs: list, ctx: dict, ref_seq: Optional[int], prefer: str) -> FrozenSet[int]:
    if not isinstance(ctx, dict):
        return frozenset()
    try:
        from llm_utils.prompts.prompt_utils import locs_to_scope_seqs
    except Exception:
        locs_to_scope_seqs = None
    if locs_to_scope_seqs is None:
        return frozenset()
    seqs = locs_to_scope_seqs(scope_locs or [], ctx, ref_seq=ref_seq, prefer=prefer)
    out = set()
    for s in seqs or []:
        try:
            out.add(int(s))
        except Exception:
            continue
    return frozenset(out)


def should_skip_llm_for_child_scope(*, ctx: dict, taint_key: Tuple[int, int], scope_seqs: Iterable[int]) -> bool:
    if not isinstance(ctx, dict):
        return False
    if not isinstance(taint_key, tuple) or len(taint_key) != 2:
        return False
    try:
        tid = int(taint_key[0])
        tseq = int(taint_key[1])
    except Exception:
        return False
    parent = (ctx.get('_llm_parent_prompt_scope_by_taint') or {}).get((tid, tseq))
    if not parent:
        return False
    cur = set()
    for x in scope_seqs or []:
        try:
            cur.add(int(x))
        except Exception:
            continue
    if not cur:
        return False
    try:
        return cur.issubset(set(parent))
    except Exception:
        return False


def record_parent_scope_for_enqueued_taint(*, ctx: dict, taint_key: Tuple[int, int], parent_scope: Iterable[int]) -> None:
    if not isinstance(ctx, dict):
        return
    if not isinstance(taint_key, tuple) or len(taint_key) != 2:
        return
    try:
        tid = int(taint_key[0])
        tseq = int(taint_key[1])
    except Exception:
        return
    parent_set = set()
    for x in parent_scope or []:
        try:
            parent_set.add(int(x))
        except Exception:
            continue
    if not parent_set:
        return
    m = ctx.setdefault('_llm_parent_prompt_scope_by_taint', {})
    prev = m.get((tid, tseq))
    if prev:
        try:
            prev_set = set(prev)
        except Exception:
            prev_set = set()
        if prev_set:
            if parent_set.issubset(prev_set):
                return
            if prev_set.issubset(parent_set):
                m[(tid, tseq)] = frozenset(parent_set)
                return
            m[(tid, tseq)] = frozenset(prev_set.union(parent_set))
            return
    m[(tid, tseq)] = frozenset(parent_set)


def merge_round_metas_by_scope(metas: List[dict]) -> List[dict]:
    """Merge LLM round metadata when one scope is a subset of another to reduce calls."""
    groups: List[dict] = []
    for meta in metas or []:
        if not isinstance(meta, dict):
            continue
        cur_scope = meta.get('scope_only_seqs')
        if not cur_scope:
            groups.append({'rep': meta, 'members': [meta]})
            continue
        try:
            cur_set = set(cur_scope)
        except Exception:
            cur_set = set()
        if not cur_set:
            groups.append({'rep': meta, 'members': [meta]})
            continue

        merged_into_existing = False
        for g in groups:
            rep = g.get('rep') or {}
            rep_scope = rep.get('scope_only_seqs')
            try:
                rep_set = set(rep_scope) if rep_scope else set()
            except Exception:
                rep_set = set()
            if rep_set and cur_set.issubset(rep_set):
                (g.get('members') or []).append(meta)
                merged_into_existing = True
                break
        if merged_into_existing:
            continue

        new_group = {'rep': meta, 'members': [meta]}
        kept_groups = []
        for g in groups:
            rep = g.get('rep') or {}
            rep_scope = rep.get('scope_only_seqs')
            try:
                rep_set = set(rep_scope) if rep_scope else set()
            except Exception:
                rep_set = set()
            if rep_set and rep_set.issubset(cur_set):
                new_group['members'].extend(list(g.get('members') or []))
            else:
                kept_groups.append(g)
        groups = kept_groups
        groups.append(new_group)

    out = []
    for g in groups:
        rep = g.get('rep')
        members = [m for m in (g.get('members') or []) if isinstance(m, dict)]
        if not isinstance(rep, dict):
            continue
        if len(members) <= 1:
            out.append(rep)
            continue
        merged = dict(rep)
        merged['merged_members'] = [
            {
                'tid': m.get('tid'),
                'tseq': m.get('tseq'),
                'tt': m.get('tt'),
                'nm': m.get('nm'),
            }
            for m in members
        ]
        if not isinstance(merged.get('call_param_arg_info'), dict):
            for m in members:
                info = m.get('call_param_arg_info')
                if isinstance(info, dict):
                    merged['call_param_arg_info'] = info
                    break
        out.append(merged)
    return out


def build_merged_llm_prompt(*, merged_members: List[dict], result_set: str) -> str:
    try:
        from llm_utils.prompts.prompt_utils import _DEFAULT_LLM_TAINT_TEMPLATE_TAIL
    except Exception:
        _DEFAULT_LLM_TAINT_TEMPLATE_TAIL = None
    tail = (_DEFAULT_LLM_TAINT_TEMPLATE_TAIL or '').lstrip('\n')
    items = []
    has_prop = False
    for m in merged_members or []:
        if not isinstance(m, dict):
            continue
        tt = (m.get('tt') or '').strip()
        nm = (m.get('nm') or '').strip()
        if not tt or not nm:
            continue
        if tt == 'AST_PROP':
            has_prop = True
        items.append(f"- {tt} {nm}")
    head = "You are a code analysis assistant. In the following code, identify all variables and function calls that could affect the values of the following taints:\n"
    head += "\n".join(items) + "\n"
    out = head + tail.replace("{result_set}", str(result_set or ""))
    if has_prop:
        out += (
            "\nNote: The code block may contain expanded function scopes, marked with FUNCTION_SCOPE_START and FUNCTION_SCOPE_END."
            "\nWithin a function scope of a class method, $this refers to the current object itself: $this->x is equivalent to object->x."
        )
    return out

