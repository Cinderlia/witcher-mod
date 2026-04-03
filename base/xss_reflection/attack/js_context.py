import re
from typing import List, Optional

from .common import WITCHER_MARKER


def build_payloads(quote: Optional[str] = None) -> List[str]:
    if quote == "'":
        return [f"';{WITCHER_MARKER};//"]
    if quote == "`":
        return [f"`;{WITCHER_MARKER};//"]
    return [f"\";{WITCHER_MARKER};//", f"';{WITCHER_MARKER};//"]


def is_success(body: str) -> bool:
    for script_text in _script_blocks(body):
        if _marker_executable(script_text):
            return True
    return False


def _script_blocks(body: str):
    for match in re.finditer(r"<script[^>]*>([\s\S]*?)</script>", body, re.IGNORECASE):
        yield match.group(1)


def _marker_executable(text: str) -> bool:
    in_single = False
    in_double = False
    in_template = False
    in_line = False
    in_block = False
    escape = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_line:
            if ch == "\n":
                in_line = False
        elif in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                i += 1
        elif in_single:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "'":
                in_single = False
        elif in_double:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_double = False
        elif in_template:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "`":
                in_template = False
        else:
            if text.startswith(WITCHER_MARKER, i):
                return True
            if ch == "/" and nxt == "/":
                in_line = True
                i += 1
            elif ch == "/" and nxt == "*":
                in_block = True
                i += 1
            elif ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "`":
                in_template = True
        i += 1
    return False
