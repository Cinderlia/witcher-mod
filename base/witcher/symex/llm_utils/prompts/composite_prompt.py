import re
from typing import Dict, List, Optional, Set

from common.app_config import build_app_name_prompt_line, load_symex_app_config


_SEQ_LINE_RE = re.compile(r'^\s*(\d+)\s')


def _safe_int(x) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None


def block_seq_set(block: str) -> Set[int]:
    out: Set[int] = set()
    if not isinstance(block, str) or not block.strip():
        return out
    for line in block.splitlines():
        m = _SEQ_LINE_RE.match(line)
        if not m:
            continue
        si = _safe_int(m.group(1))
        if si is not None:
            out.add(int(si))
    return out


def _taint_items_for_meta(meta: dict) -> List[dict]:
    merged = meta.get('merged_members')
    if isinstance(merged, list) and merged:
        out = []
        for m in merged:
            if not isinstance(m, dict):
                continue
            tt = (m.get('tt') or '').strip()
            nm = (m.get('nm') or '').strip()
            if tt and nm:
                out.append({'tt': tt, 'nm': nm})
        if out:
            return out
    tt0 = (meta.get('tt') or '').strip()
    nm0 = (meta.get('nm') or '').strip()
    return [{'tt': tt0, 'nm': nm0}] if tt0 and nm0 else []


def _scope_group_for_meta(meta: dict) -> Optional[dict]:
    if not isinstance(meta, dict):
        return None
    block = meta.get('block') or ''
    if not isinstance(block, str) or not block.strip():
        return None
    seq_set = block_seq_set(block)
    return {
        'meta': meta,
        'this_obj': (meta.get('this_obj') or '').strip(),
        'seqs': seq_set,
        'block': block,
        'taints': _taint_items_for_meta(meta),
        'prompt_scope_set': set(meta.get('prompt_scope_set') or set()),
    }


def _is_merge_candidate(group: dict, *, small_scope_max: int) -> bool:
    if not isinstance(group, dict):
        return False
    seqs = group.get('seqs')
    if not isinstance(seqs, set) or not seqs:
        return False
    if len(seqs) >= int(small_scope_max):
        return False
    meta = group.get('meta') or {}
    if isinstance(meta.get('prop_call_scopes_info'), list):
        return False
    return True


def _render_scope_section(group: dict, *, index: int) -> str:
    taints = group.get('taints') or []
    taint_lines = []
    for t in taints:
        if not isinstance(t, dict):
            continue
        tt = (t.get('tt') or '').strip()
        nm = (t.get('nm') or '').strip()
        if tt and nm:
            taint_lines.append(f"- {tt} {nm}")
    taints_part = "\n".join(taint_lines) if taint_lines else "- <UNKNOWN>"
    block = (group.get('block') or '').rstrip()
    return (
            f"[Scope {int(index)}]\n"
            "Within this Scope only, identify the variables and function calls that can affect the values of the following taints. Do not reference assignment relationships from other Scopes.\n"
            "Taints:\n"
            + taints_part
            + "\n"
            + block
            + "\n"
        )


def build_composite_taint_prompt(scope_groups: List[dict]) -> str:
    sections = []
    for i, g in enumerate(scope_groups or [], start=1):
        sections.append(_render_scope_section(g, index=i))
    body = "\n".join(sections).strip() + "\n"
    try:
        app_line = build_app_name_prompt_line(load_symex_app_config())
    except Exception:
        app_line = ""
    parts = [
        "You are a code analysis assistant.",
    ]
    if app_line:
        parts.append(app_line)
    parts.extend([
        "Multiple Scopes are provided below. Each Scope contains a set of taints. Analyze the influencing factors within each Scope independently.",
        "If an influencing factor for a taint does not reside in its own Scope, do not infer across Scopes.",
        "The type field should be determined based on literal form as much as possible. Only the following types are allowed: AST_VAR, AST_PROP, AST_DIM, AST_METHOD_CALL, AST_STATIC_CALL, AST_CALL.",
        "When a taint is indirectly affected via intermediate variables, place the intermediate variables in intermediates, and place the final influencing factors in taints.",
        "Output only valid JSON. Do not output explanatory text or Markdown.",
        "",
        "Code (each line format: seq + source line):",
        body.rstrip(),
        "",
        "Place all taints from all Scopes into the taints field, and all intermediate variables into the intermediates field. Output only one JSON object.",
        "",
        "Output JSON format must be:",
        "{\"taints\":[{\"seq\":51529,\"type\":\"AST_VAR\",\"name\":\"negate\"}],\"intermediates\":[{\"seq\":51573,\"type\":\"AST_VAR\",\"name\":\"ret\"}]}",
        "If no new taints are found, output:",
        "{\"taints\":[],\"intermediates\":[]}",
    ])
    return "\n".join(parts).rstrip() + "\n"


def pack_small_scopes_into_composites(
    metas: List[dict],
    *,
    small_scope_max: int = 30,
    max_prompt_seqs: int = 100,
) -> List[dict]:
    groups = []
    kept = []
    for m in metas or []:
        g = _scope_group_for_meta(m)
        if g is None:
            kept.append(m)
            continue
        if _is_merge_candidate(g, small_scope_max=small_scope_max):
            groups.append(g)
        else:
            kept.append(m)

    by_obj: Dict[str, List[dict]] = {}
    for g in groups:
        key = (g.get('this_obj') or '').strip()
        by_obj.setdefault(key, []).append(g)

    composite_metas: List[dict] = []
    for _, lst in by_obj.items():
        pending = list(lst)
        pending.sort(key=lambda x: len(x.get('seqs') or set()))
        while pending:
            bucket = []
            bucket_seqs: Set[int] = set()
            i = 0
            while i < len(pending):
                g = pending[i]
                seqs = g.get('seqs') or set()
                merged = bucket_seqs.union(seqs)
                if len(merged) >= int(max_prompt_seqs):
                    i += 1
                    continue
                bucket.append(g)
                bucket_seqs = merged
                pending.pop(i)
                continue
            if not bucket:
                bucket.append(pending.pop(0))
            if len(bucket) <= 1:
                kept.append((bucket[0] or {}).get('meta') or {})
                continue
            rep_meta = dict((bucket[0] or {}).get('meta') or {})
            rep_meta['key'] = None
            rep_meta['merged_members'] = None
            rep_meta['composite_scopes'] = [
                {'taints': (g.get('taints') or []), 'seq_count': len(g.get('seqs') or set())}
                for g in bucket
            ]
            rep_meta['prompt_scope_set'] = set().union(*(g.get('prompt_scope_set') or set() for g in bucket))
            rep_meta['scope_only_seqs'] = frozenset(bucket_seqs)
            infos = []
            for g in bucket:
                info = ((g.get('meta') or {}).get('call_param_arg_info') or None)
                if isinstance(info, dict):
                    infos.append(info)
            if infos:
                rep_meta['call_param_arg_info'] = infos
            rep_meta['prompt'] = build_composite_taint_prompt(bucket)
            composite_metas.append(rep_meta)

    return kept + composite_metas
