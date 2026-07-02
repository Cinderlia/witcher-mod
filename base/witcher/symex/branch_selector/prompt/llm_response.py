"""
Parse the LLM response for branch selection into groups of trace sequence numbers.
"""

import json
import os
import random
import sys
from typing import Iterable, List, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger


def extract_llm_json_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    s = (text or "").strip()
    if not s:
        return ""

    def _try_parse(candidate: str) -> bool:
        if not candidate:
            return False
        try:
            json.loads(candidate)
            return True
        except Exception:
            return False

    def _extract_json_block(raw: str) -> str:
        t = (raw or "").strip()
        if not t:
            return ""
        if t.startswith("```"):
            parts = t.split("```")
            if len(parts) >= 3:
                inner = parts[1]
                if inner.lower().startswith("json"):
                    inner = inner[4:]
                return inner.strip()
        if "```" in t:
            head = t.split("```", 1)[1]
            inner = head.split("```", 1)[0]
            if inner.lower().startswith("json"):
                inner = inner[4:]
            return inner.strip()
        return t

    direct = s
    if _try_parse(direct):
        return direct

    fenced = _extract_json_block(s)
    if fenced and _try_parse(fenced):
        return fenced

    i1 = s.find("{")
    j1 = s.rfind("}")
    if i1 >= 0 and j1 > i1:
        mid = s[i1 : j1 + 1]
        if _try_parse(mid):
            return mid

    i2 = s.find("[")
    j2 = s.rfind("]")
    if i2 >= 0 and j2 > i2:
        mid = s[i2 : j2 + 1]
        if _try_parse(mid):
            return mid

    if fenced:
        i3 = fenced.find("{")
        j3 = fenced.rfind("}")
        if i3 >= 0 and j3 > i3:
            mid = fenced[i3 : j3 + 1]
            if _try_parse(mid):
                return mid
        i4 = fenced.find("[")
        j4 = fenced.rfind("]")
        if i4 >= 0 and j4 > i4:
            mid = fenced[i4 : j4 + 1]
            if _try_parse(mid):
                return mid

    return ""


# Summary: Decode JSON produced by the LLM into groups of integer seqs (tolerant to minor format variants).
def parse_llm_response(text: str, logger: Optional[Logger] = None) -> List[List[int]]:
    if not isinstance(text, str):
        return []
    s = text.strip()
    if not s:
        return []

    def _extract_json_block(raw: str) -> str:
        t = (raw or "").strip()
        if not t:
            return ""
        if t.startswith("```"):
            parts = t.split("```")
            if len(parts) >= 3:
                inner = parts[1]
                if inner.lower().startswith("json"):
                    inner = inner[4:]
                return inner.strip()
        if "```" in t:
            head = t.split("```", 1)[1]
            inner = head.split("```", 1)[0]
            if inner.lower().startswith("json"):
                inner = inner[4:]
            return inner.strip()
        return t

    def _parse_obj(raw: str):
        candidate = extract_llm_json_text(raw) or _extract_json_block(raw)
        if not candidate:
            return None
        try:
            return json.loads(candidate)
        except Exception:
            i = candidate.find("[")
            j = candidate.rfind("]")
            if i >= 0 and j > i:
                try:
                    return json.loads(candidate[i : j + 1])
                except Exception:
                    return None
            return None

    obj = _parse_obj(s)
    if obj is None:
        try:
            obj = json.loads(s)
        except Exception:
            obj = None
    if isinstance(obj, dict) and "raw" in obj:
        raw = obj.get("raw")
        if isinstance(raw, str):
            obj = _parse_obj(raw)
    if obj is None:
        if logger is not None:
            logger.warning("llm_response_parse_failed")
        return []
    if isinstance(obj, list):
        if not obj:
            return []
        if all(isinstance(x, int) or (isinstance(x, str) and str(x).isdigit()) for x in obj):
            out = [[int(x) for x in obj]]
            if logger is not None:
                logger.info("llm_response_parsed", groups=len(out), seqs=len(out[0]))
            return out
        out: List[List[int]] = []
        for it in obj:
            if isinstance(it, list):
                buf = []
                for x in it:
                    try:
                        buf.append(int(x))
                    except Exception:
                        continue
                if buf:
                    out.append(buf)
        if logger is not None:
            total = sum(len(x) for x in out)
            logger.info("llm_response_parsed", groups=len(out), seqs=total)
        return out
    return []


def llm_response_has_valid_json(text: str) -> bool:
    if not isinstance(text, str):
        return False
    s = text.strip()
    if not s:
        return False
    return bool(extract_llm_json_text(s))


def build_test_response_from_prompts(prompt_items: Iterable[dict], pick_count: int = 5, logger: Optional[Logger] = None) -> List[List[int]]:
    seqs = []
    for it in prompt_items or []:
        s = it.get("seq")
        if s is None:
            continue
        try:
            seqs.append(int(s))
        except Exception:
            continue
    if not seqs:
        return []
    if len(seqs) <= int(pick_count):
        chosen = seqs
    else:
        chosen = random.sample(seqs, int(pick_count))
    out = [list(chosen)]
    if logger is not None:
        logger.info("llm_test_response_built", picked=len(out[0]))
    return out
