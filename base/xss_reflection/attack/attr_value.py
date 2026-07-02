import re
from typing import List, Optional

from .common import WITCHER_MARKER

_EVENTFUL_ONERROR_TAGS = {
    "audio",
    "body",
    "embed",
    "frame",
    "iframe",
    "img",
    "image",
    "input",
    "object",
    "script",
    "source",
    "track",
    "video",
}


def build_payloads(quote: Optional[str] = None) -> List[str]:
    q = quote or '"'
    if quote is None:
        return [
            f" onerror=alert({WITCHER_MARKER}) ",
        ]
    if q == "'":
        return [
            f"' onerror=alert({WITCHER_MARKER}) x='",
        ]
    return [
        f"\" onerror=alert({WITCHER_MARKER}) x=\"",
    ]


def is_success(body: str) -> bool:
    tag_re = re.compile(r"<[^>]+>")
    attr_re = re.compile(r'([a-zA-Z0-9:_-]+)\s*=\s*(".*?"|\'.*?\'|[^\s>]+)')
    for tag_match in tag_re.finditer(body):
        tag = tag_match.group(0)
        tag_name_match = re.match(r"<\s*/?\s*([a-zA-Z0-9:_-]+)", tag)
        tag_name = tag_name_match.group(1).lower() if tag_name_match else ""
        if tag_name not in _EVENTFUL_ONERROR_TAGS or tag_name == "input":
            continue
        for attr_match in attr_re.finditer(tag):
            name = attr_match.group(1).lower()
            if name != "onerror":
                continue
            value = attr_match.group(2)
            if not value:
                continue
            quoted = value[0] in {"'", '"'} and value[-1] == value[0]
            raw_value = value[1:-1] if quoted else value
            if quoted:
                continue
            if WITCHER_MARKER not in raw_value:
                continue
            if re.search(r"^[a-zA-Z_]\w*\s*\([^>]*%s[^>]*\)\s*$" % WITCHER_MARKER, raw_value):
                return True
    return False
