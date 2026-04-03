import re
from typing import List, Optional

from .common import WITCHER_MARKER


def build_payloads(quote: Optional[str] = None) -> List[str]:
    q = quote or '"'
    if quote is None:
        return [
            f" onerror=alert({WITCHER_MARKER}) ",
            f" onclick=alert({WITCHER_MARKER}) ",
        ]
    if q == "'":
        return [
            f"' onerror=alert({WITCHER_MARKER}) x='",
            f"' onclick=alert({WITCHER_MARKER}) x='",
        ]
    return [
        f"\" onerror=alert({WITCHER_MARKER}) x=\"",
        f"\" onclick=alert({WITCHER_MARKER}) x=\"",
    ]


def is_success(body: str) -> bool:
    tag_re = re.compile(r"<[^>]+>")
    attr_re = re.compile(r'([a-zA-Z0-9:_-]+)\s*=\s*(".*?"|\'.*?\'|[^\s>]+)')
    success = False
    for tag_match in tag_re.finditer(body):
        tag = tag_match.group(0)
        for attr_match in attr_re.finditer(tag):
            name = attr_match.group(1).lower()
            if name not in {"onerror", "onclick"}:
                continue
            value = attr_match.group(2)
            if not value:
                continue
            quoted = value[0] in {"'", '"'} and value[-1] == value[0]
            raw_value = value[1:-1] if quoted else value
            if WITCHER_MARKER in raw_value:
                if not quoted and re.search(r"\w+\s*\(", raw_value):
                    return True
                success = False
    return success
