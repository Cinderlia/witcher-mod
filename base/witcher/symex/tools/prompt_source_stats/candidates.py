"""Extract condition candidate variables and prepare merged prompt payloads."""

import re
try:
    from dataclasses import dataclass, field
except Exception:
    from compat_dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from prompt_source_stats.scanner import ContextItem, PromptCodeBlock


_IDENT_START = re.compile(r"[A-Za-z_\x80-\xff]")
_IDENT_CHAR = re.compile(r"[A-Za-z0-9_\x80-\xff]")


@dataclass(frozen=True)
class BatchPromptData:
    reference_lines: List[str]
    context_lines: List[str]
    candidate_variables: List[str]
    candidate_lookup: Dict[str, str]
    block_candidate_keys: List[Set[str]] = field(default_factory=list)


def normalize_candidate_name(text: str) -> str:
    raw = (text or "").strip()
    if not raw:
        return ""
    raw = raw.replace('"', "'")
    raw = re.sub(r"\s+", "", raw)
    raw = re.sub(r"\[\s*'([^']+)'\s*\]", r"['\1']", raw)
    raw = re.sub(r"\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]", r"[\1]", raw)
    return raw.lower()


def _dedupe_keep_order(items: List[str]) -> List[str]:
    out = []
    seen = set()
    for item in items or []:
        key = normalize_candidate_name(item)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append((item or "").strip())
    return out


def _skip_spaces(raw: str, index: int) -> int:
    while index < len(raw) and raw[index].isspace():
        index += 1
    return index


def _consume_balanced(raw: str, index: int, open_ch: str, close_ch: str) -> int:
    if index >= len(raw) or raw[index] != open_ch:
        return index
    depth = 0
    quote = ""
    escape = False
    while index < len(raw):
        ch = raw[index]
        if escape:
            escape = False
            index += 1
            continue
        if ch == "\\":
            escape = True
            index += 1
            continue
        if quote:
            if ch == quote:
                quote = ""
            index += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            index += 1
            continue
        if ch == open_ch:
            depth += 1
            index += 1
            continue
        if ch == close_ch:
            depth -= 1
            index += 1
            if depth <= 0:
                break
            continue
        index += 1
    return index


def _consume_identifier(raw: str, index: int) -> int:
    if index >= len(raw) or _IDENT_START.match(raw[index]) is None:
        return index
    index += 1
    while index < len(raw) and _IDENT_CHAR.match(raw[index]) is not None:
        index += 1
    return index


def _consume_member_name(raw: str, index: int) -> int:
    index = _skip_spaces(raw, index)
    if index >= len(raw):
        return index
    if raw[index] == "$":
        return _consume_php_variable(raw, index)[1]
    if raw[index] == "{":
        return _consume_balanced(raw, index, "{", "}")
    return _consume_identifier(raw, index)


def _consume_suffixes(raw: str, index: int) -> int:
    while index < len(raw):
        next_index = _skip_spaces(raw, index)
        if raw.startswith("->", next_index):
            member_start = next_index + 2
            member_end = _consume_member_name(raw, member_start)
            if member_end <= member_start:
                return next_index
            index = member_end
            continue
        if raw.startswith("::", next_index):
            member_start = next_index + 2
            member_end = _consume_member_name(raw, member_start)
            if member_end <= member_start:
                return next_index
            index = member_end
            continue
        if next_index < len(raw) and raw[next_index] == "[":
            index = _consume_balanced(raw, next_index, "[", "]")
            continue
        break
    return index


def _consume_php_variable(raw: str, index: int):
    start = index
    while index < len(raw) and raw[index] == "$":
        index += 1
    if index < len(raw) and raw[index] == "{":
        index = _consume_balanced(raw, index, "{", "}")
    else:
        ident_end = _consume_identifier(raw, index)
        if ident_end <= index:
            return "", start + 1
        index = ident_end
    index = _consume_suffixes(raw, index)
    return raw[start:index], index


def _consume_static_variable(raw: str, index: int):
    start = index
    index = _consume_identifier(raw, index)
    while index < len(raw) and raw[index] == "\\":
        next_index = _consume_identifier(raw, index + 1)
        if next_index <= index + 1:
            break
        index = next_index
    index = _skip_spaces(raw, index)
    if not raw.startswith("::", index):
        return "", start + 1
    index += 2
    index = _skip_spaces(raw, index)
    if index >= len(raw) or raw[index] != "$":
        return "", start + 1
    variable_expr, var_end = _consume_php_variable(raw, index)
    if not variable_expr:
        return "", start + 1
    return raw[start:index] + variable_expr, var_end


def _sanitize_candidate(candidate: str) -> str:
    text = (candidate or "").strip()
    if not text:
        return ""
    text = re.sub(r"\s+", "", text)
    text = text.replace('"', "'")
    return text


def _build_candidate_aliases(candidate: str) -> Set[str]:
    raw = _sanitize_candidate(candidate)
    if not raw:
        return set()
    aliases = set([normalize_candidate_name(raw), raw])
    if raw.startswith("$"):
        aliases.add(normalize_candidate_name(raw[1:]))
        aliases.add(raw[1:])
    if "['" in raw:
        aliases.add(normalize_candidate_name(re.sub(r"\['([^']+)'\]", r"[\1]", raw)))
    bracket_keys = re.findall(r"\[\s*'([^']+)'\s*\]", raw)
    for key in bracket_keys:
        aliases.add(normalize_candidate_name(key))
        aliases.add(key)
    return set(alias for alias in aliases if alias)


def extract_candidate_variables(condition_text: str) -> List[str]:
    raw = (condition_text or "").strip()
    if not raw:
        return []
    out = []
    seen = set()
    index = 0
    quote = ""
    escape = False
    while index < len(raw):
        ch = raw[index]
        if escape:
            escape = False
            index += 1
            continue
        if ch == "\\":
            escape = True
            index += 1
            continue
        if quote:
            if ch == quote:
                quote = ""
            index += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            index += 1
            continue
        if ch == "$":
            candidate, next_index = _consume_php_variable(raw, index)
            sanitized = _sanitize_candidate(candidate)
            key = normalize_candidate_name(sanitized)
            if sanitized and key not in seen:
                seen.add(key)
                out.append(sanitized)
            index = max(next_index, index + 1)
            continue
        if _IDENT_START.match(ch) is not None:
            candidate, next_index = _consume_static_variable(raw, index)
            sanitized = _sanitize_candidate(candidate)
            key = normalize_candidate_name(sanitized)
            if sanitized and key not in seen:
                seen.add(key)
                out.append(sanitized)
                index = max(next_index, index + 1)
                continue
        index += 1
    return out


def collect_block_candidate_variables(block: PromptCodeBlock) -> List[str]:
    out = []
    seen = set()
    for condition in block.iter_condition_texts():
        for candidate in extract_candidate_variables(condition):
            key = normalize_candidate_name(candidate)
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(candidate)
    return out


def _merge_reference_lines(blocks: List[PromptCodeBlock]) -> List[str]:
    env_keys = []
    input_keys = {"COOKIE": [], "GET": [], "POST": [], "SESSION": [], "SEED": []}
    for block in blocks or []:
        env_keys.extend(block.env_keys or [])
        for label, keys in (block.input_keys or {}).items():
            input_keys.setdefault(label, [])
            input_keys[label].extend(keys or [])
    env_keys = _dedupe_keep_order(env_keys)
    for label in list(input_keys.keys()):
        input_keys[label] = _dedupe_keep_order(input_keys[label])

    lines = ["本次执行的环境变量是："]
    lines.extend(env_keys)
    lines.append("")
    lines.append("本次执行的输入是：")
    for label in ("COOKIE", "GET", "POST", "SESSION", "SEED"):
        keys = input_keys.get(label, [])
        if keys:
            lines.append(label + ":" + ", ".join(keys))
        else:
            lines.append(label + ":")
    return lines


def _merge_context_items(blocks: List[PromptCodeBlock]) -> List[ContextItem]:
    chosen = {}
    for block in blocks or []:
        for item in block.context_items or []:
            key = (item.location or "").strip()
            if not key:
                key = "seq:" + (item.seq_text or "")
            prev = chosen.get(key)
            if prev is None:
                chosen[key] = item
                continue
            prev_seq = prev.seq if prev.seq is not None else float("inf")
            cur_seq = item.seq if item.seq is not None else float("inf")
            if cur_seq < prev_seq:
                chosen[key] = item
    return sorted(
        chosen.values(),
        key=lambda item: (
            item.seq if item.seq is not None else float("inf"),
            item.location or "",
        ),
    )


def prepare_batch_prompt(blocks: List[PromptCodeBlock]) -> BatchPromptData:
    merged_context_items = _merge_context_items(blocks)
    context_lines = [
        "{0} | {1} | {2}".format(item.seq_text, item.location, item.code)
        for item in merged_context_items
    ]

    candidate_variables = []
    candidate_lookup = {}
    block_candidate_keys = []
    for block in blocks or []:
        block_keys = set()
        for candidate in collect_block_candidate_variables(block):
            canonical = _sanitize_candidate(candidate)
            canonical_key = normalize_candidate_name(canonical)
            if not canonical_key:
                continue
            if canonical_key not in candidate_lookup:
                candidate_variables.append(canonical)
            for alias in _build_candidate_aliases(canonical):
                candidate_lookup[alias] = canonical
            candidate_lookup[canonical_key] = canonical
            block_keys.add(canonical_key)
        block_candidate_keys.append(block_keys)

    return BatchPromptData(
        reference_lines=_merge_reference_lines(blocks),
        context_lines=context_lines,
        candidate_variables=_dedupe_keep_order(candidate_variables),
        candidate_lookup=candidate_lookup,
        block_candidate_keys=block_candidate_keys,
    )
