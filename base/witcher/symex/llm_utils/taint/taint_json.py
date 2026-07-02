"""Parse and sanitize taint JSON responses returned by the LLM."""

import json
import re
from typing import Dict, List, Optional


def _try_load_json(s: str):
    """Best-effort JSON parser that returns None for invalid input."""
    if not isinstance(s, str):
        return None
    s = s.strip()
    if not s:
        return None
    try:
        obj = json.loads(s)
    except Exception:
        return None
    return obj


def _extract_json_text(text: str) -> Optional[str]:
    """
    Extract a JSON object substring from an LLM response.

    Supports:
    - fenced code blocks ```json ... ```
    - a raw `{...}` object embedded in text
    """
    if not isinstance(text, str):
        return None
    t = text.strip()
    if not t:
        return None
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", t, flags=re.IGNORECASE)
    if m:
        inner = (m.group(1) or '').strip()
        if inner.startswith('{') and inner.endswith('}'):
            return inner
    i = t.find('{')
    j = t.rfind('}')
    if i >= 0 and j >= 0 and j > i:
        return t[i : j + 1]
    return None


def parse_llm_taint_response(text: str):
    """
    Parse an LLM response into a normalized structure.

    Output:
    - `taints`: list of `{seq:int, type:str, name:str}` (deduped)
    - `intermediates`: list of `{seq:int, type:str, name:str}` (deduped)
    - `edges`: kept for backward-compatibility (always empty)
    - `seqs`: kept for backward-compatibility (sorted list of ints, deduped)
    """
    raw_obj = _try_load_json(text)
    if raw_obj is None:
        js = _extract_json_text(text)
        raw_obj = _try_load_json(js or '')
    if not isinstance(raw_obj, dict):
        return {'taints': [], 'intermediates': [], 'edges': [], 'seqs': []}
    taints = raw_obj.get('taints')
    intermediates = raw_obj.get('intermediates')
    if intermediates is None:
        intermediates = raw_obj.get('intermediate_vars')
    edges = raw_obj.get('edges')
    seqs = raw_obj.get('seqs')
    if not isinstance(taints, list):
        taints = []
    if not isinstance(intermediates, list):
        intermediates = []
    if not isinstance(edges, list):
        edges = []
    if not isinstance(seqs, list):
        seqs = []
    seq_set = set()
    for s in seqs:
        try:
            seq_set.add(int(s))
        except Exception:
            continue
    for it in taints:
        if not isinstance(it, dict):
            continue
        try:
            seq_set.add(int(it.get('seq')))
        except Exception:
            pass
    for it in intermediates:
        if not isinstance(it, dict):
            continue
        try:
            seq_set.add(int(it.get('seq')))
        except Exception:
            pass

    def _norm_items(items: list) -> List[Dict]:
        out = []
        seen = set()
        for it in items or []:
            if not isinstance(it, dict):
                continue
            seq = it.get('seq')
            tt = (it.get('type') or '').strip()
            nm = (it.get('name') or '').strip()
            try:
                seq_i = int(seq)
            except Exception:
                continue
            if not tt or not nm:
                continue
            k = (seq_i, tt, nm)
            if k in seen:
                continue
            seen.add(k)
            out.append({'seq': seq_i, 'type': tt, 'name': nm})
        return out

    out_taints = _norm_items(taints)
    out_intermediates = _norm_items(intermediates)
    out_edges = []
    out_seqs = sorted(seq_set)
    return {'taints': out_taints, 'intermediates': out_intermediates, 'edges': out_edges, 'seqs': out_seqs}


def llm_taint_response_has_valid_json(text: str) -> bool:
    if not isinstance(text, str):
        return False
    raw_obj = _try_load_json(text)
    if raw_obj is None:
        js = _extract_json_text(text)
        raw_obj = _try_load_json(js or '')
    return isinstance(raw_obj, dict)
