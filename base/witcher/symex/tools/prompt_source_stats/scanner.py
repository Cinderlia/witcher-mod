"""Scan archived symbolic prompt files and extract code-only context blocks."""

import glob
import os
import re
try:
    from dataclasses import dataclass, field
except Exception:
    from compat_dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional


_CONTEXT_LINE_RE = re.compile(r"^\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*(.*)$")
_KEY_VALUE_KEY_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_\-\.\[\]]*)\s*(?:=>|=|:)')
_CONDITION_HEAD_RE = re.compile(r"\b(?:if|elseif|else\s+if|switch)\s*\(", flags=re.IGNORECASE)
_INPUT_LABELS = ("COOKIE", "GET", "POST", "SESSION", "SEED")


@dataclass(frozen=True)
class ContextItem:
    seq: Optional[int]
    seq_text: str
    location: str
    code: str


@dataclass(frozen=True)
class PromptCodeBlock:
    """Code-only payload extracted from one `symbolic_prompt_*.txt` file."""

    source_path: str
    relative_path: str
    env_keys: List[str] = field(default_factory=list)
    input_keys: Dict[str, List[str]] = field(default_factory=dict)
    context_items: List[ContextItem] = field(default_factory=list)

    def to_prompt_text(self) -> str:
        lines = []
        reference_lines = self.reference_lines
        if reference_lines:
            lines.extend(reference_lines)
            lines.append("")
        lines.append("Code context:")
        lines.extend(self.code_lines)
        return "\n".join(lines).rstrip() + "\n"

    def iter_condition_texts(self) -> Iterator[str]:
        for item in self.context_items:
            for condition in _extract_conditions_from_line(item.code):
                yield condition

    @property
    def code_lines(self) -> List[str]:
        return [item.code for item in self.context_items]

    @property
    def reference_lines(self) -> List[str]:
        return _build_reference_lines(self.env_keys, self.input_keys)


def _extract_context_items(prompt_text: str) -> List[ContextItem]:
    if not isinstance(prompt_text, str) or not prompt_text.strip():
        return []

    lines = prompt_text.splitlines()
    in_context = False
    context_items = []

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        if not in_context:
            if stripped == "Code context:" or stripped == "Code context (each line: seq | path:line | code):":
                in_context = True
                continue
            if stripped.endswith("| code):") and "seq |" in stripped and "path:line |" in stripped:
                in_context = True
            continue

        if not stripped:
            break

        match = _CONTEXT_LINE_RE.match(line)
        if not match:
            if context_items:
                break
            continue

        seq_text = (match.group(1) or "").strip()
        location = (match.group(2) or "").strip()
        code_text = (match.group(3) or "").rstrip()
        try:
            seq_int = int(seq_text)
        except Exception:
            seq_int = None
        context_items.append(
            ContextItem(
                seq=seq_int,
                seq_text=seq_text,
                location=location,
                code=code_text,
            )
        )

    return context_items


def _extract_reference_data(prompt_text: str) -> Dict[str, object]:
    if not isinstance(prompt_text, str) or not prompt_text.strip():
        return {
            "env_keys": [],
            "input_keys": {label: [] for label in _INPUT_LABELS},
        }

    lines = prompt_text.splitlines()
    start_index = None
    end_index = None

    for index, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        if start_index is None and stripped == "Environment variables for this execution:":
            start_index = index
            continue
        if start_index is not None and (
            stripped == "Code context:" or stripped == "Code context (each line: seq | path:line | code):"
        ):
            end_index = index
            break

    if start_index is None:
        return {
            "env_keys": [],
            "input_keys": {label: [] for label in _INPUT_LABELS},
        }
    if end_index is None:
        end_index = len(lines)

    return _sanitize_reference_lines(lines[start_index:end_index])


def _extract_parenthesized_text(raw: str, open_index: int) -> str:
    if not isinstance(raw, str):
        return ""
    if open_index < 0 or open_index >= len(raw) or raw[open_index] != "(":
        return ""
    depth = 0
    quote = ""
    escape = False
    chars = []

    for index in range(open_index, len(raw)):
        ch = raw[index]
        if escape:
            if depth >= 1 and index != open_index:
                chars.append(ch)
            escape = False
            continue
        if ch == "\\":
            if depth >= 1 and index != open_index:
                chars.append(ch)
            escape = True
            continue
        if quote:
            if depth >= 1 and index != open_index:
                chars.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"'):
            if depth >= 1 and index != open_index:
                chars.append(ch)
            quote = ch
            continue
        if ch == "(":
            depth += 1
            if depth > 1:
                chars.append(ch)
            continue
        if ch == ")":
            depth -= 1
            if depth <= 0:
                return "".join(chars).strip()
            chars.append(ch)
            continue
        if depth >= 1:
            chars.append(ch)
    return ""


def _extract_conditions_from_line(line: str) -> List[str]:
    raw = (line or "").strip()
    if not raw:
        return []
    out = []
    for match in _CONDITION_HEAD_RE.finditer(raw):
        head = match.group(0) or ""
        open_index = match.start() + len(head) - 1
        condition = _extract_parenthesized_text(raw, open_index)
        if condition:
            out.append(condition)
    return out


def _dedupe_keep_order(items: List[str]) -> List[str]:
    out = []
    seen = set()
    for item in items:
        key = (item or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _extract_keys_from_value_text(text: str) -> List[str]:
    raw = (text or "").strip()
    if not raw:
        return []

    keys = []
    for match in _KEY_VALUE_KEY_RE.finditer(raw):
        candidate = (match.group(1) or "").strip()
        if candidate:
            keys.append(candidate)
    if keys:
        return _dedupe_keep_order(keys)

    parts = []
    for chunk in re.split(r"[\s,&;\n]+", raw):
        item = (chunk or "").strip()
        if not item:
            continue
        if "=" in item:
            item = item.split("=", 1)[0].strip()
        if ":" in item and not item.startswith("http"):
            item = item.split(":", 1)[0].strip()
        item = item.strip("{}[]()'\"")
        if item:
            parts.append(item)
    return _dedupe_keep_order(parts)


def _extract_env_key(line: str) -> str:
    raw = (line or "").strip()
    if not raw:
        return ""
    if "=" in raw:
        return raw.split("=", 1)[0].strip()
    if ":" in raw:
        return raw.split(":", 1)[0].strip()
    return raw


def _format_key_only_line(label: str, raw_value: str) -> str:
    keys = _extract_keys_from_value_text(raw_value)
    if not keys:
        return label + ":"
    return label + ":" + ", ".join(keys)


def _sanitize_reference_lines(raw_lines: List[str]) -> Dict[str, object]:
    env_keys = []
    input_keys = {label: [] for label in _INPUT_LABELS}
    in_env_block = False
    pending_seed = False

    for raw_line in raw_lines or []:
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        if not stripped:
            continue

        if stripped == "Environment variables for this execution:":
            in_env_block = True
            pending_seed = False
            continue

        if stripped == "Input for this execution:":
            in_env_block = False
            pending_seed = False
            continue

        if in_env_block:
            env_key = _extract_env_key(stripped)
            if env_key:
                env_keys.append(env_key)
            continue

        for label in ("COOKIE", "GET", "POST", "SESSION"):
            prefix = label + ":"
            if stripped.startswith(prefix):
                pending_seed = False
                input_keys[label].extend(_extract_keys_from_value_text(stripped[len(prefix) :]))
                break
        else:
            if stripped == "SEED:":
                pending_seed = True
                continue
            if pending_seed:
                input_keys["SEED"].extend(_extract_keys_from_value_text(stripped))
                pending_seed = False
                continue
    return {
        "env_keys": _dedupe_keep_order(env_keys),
        "input_keys": {
            label: _dedupe_keep_order(input_keys.get(label, []))
            for label in _INPUT_LABELS
        },
    }


def _build_reference_lines(env_keys: List[str], input_keys: Dict[str, List[str]]) -> List[str]:
    lines = ["Environment variables for this execution:"]
    lines.extend(_dedupe_keep_order(env_keys or []))
    lines.append("")
    lines.append("Input for this execution:")
    for label in ("COOKIE", "GET", "POST", "SESSION", "SEED"):
        keys = _dedupe_keep_order((input_keys or {}).get(label, []) or [])
        if keys:
            lines.append(label + ":" + ", ".join(keys))
        else:
            lines.append(label + ":")
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def _scan_prompt_paths_iter(input_dir: str) -> Iterator[str]:
    pattern = os.path.join(
        input_dir,
        "tr0_*",
        "symex_runtime",
        "runs",
        "*",
        "test",
        "seqs",
        "seq_*",
        "symbolic",
        "prompts",
        "symbolic_prompt_*.txt",
    )
    for path in glob.iglob(pattern):
        yield path


def iter_prompt_paths(input_dir: str) -> Iterator[str]:
    root_dir = os.path.abspath(input_dir)
    if not os.path.isdir(root_dir):
        raise FileNotFoundError("input_dir_not_found: " + root_dir)
    for prompt_path in _scan_prompt_paths_iter(root_dir):
        yield os.path.abspath(prompt_path)


def extract_prompt_code_block(prompt_path: str, input_dir: str) -> Optional[PromptCodeBlock]:
    root_dir = os.path.abspath(input_dir)
    prompt_path = os.path.abspath(prompt_path)
    try:
        with open(prompt_path, "r", encoding="utf-8", errors="replace") as f:
            prompt_text = f.read()
    except Exception:
        return None

    context_items = _extract_context_items(prompt_text)
    if not context_items:
        return None
    reference_data = _extract_reference_data(prompt_text)

    return PromptCodeBlock(
        source_path=prompt_path,
        relative_path=os.path.relpath(prompt_path, root_dir),
        env_keys=list(reference_data.get("env_keys") or []),
        input_keys=dict(reference_data.get("input_keys") or {}),
        context_items=context_items,
    )


def iter_prompt_code_blocks(input_dir: str) -> Iterator[PromptCodeBlock]:
    root_dir = os.path.abspath(input_dir)
    for prompt_path in iter_prompt_paths(root_dir):
        block = extract_prompt_code_block(prompt_path, root_dir)
        if block is not None:
            yield block


def scan_prompt_code_blocks(input_dir: str) -> List[PromptCodeBlock]:
    root_dir = os.path.abspath(input_dir)
    if not os.path.isdir(root_dir):
        raise FileNotFoundError("input_dir_not_found: " + root_dir)
    return list(iter_prompt_code_blocks(root_dir))
