import re
from typing import Optional

_XSS_RE = re.compile(r"\b(echo|print)\b|\bprintf\s*\(", re.IGNORECASE)


def _strip_inline_comment(line: str) -> str:
    if not isinstance(line, str):
        return ""
    s = line
    for sep in ("//", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    return s


def is_xss_line(code: Optional[str]) -> bool:
    s = _strip_inline_comment(code or "").strip()
    if not s:
        return False
    return bool(_XSS_RE.search(s))
