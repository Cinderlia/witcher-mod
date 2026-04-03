import re
from typing import List, Optional

from .common import WITCHER_MARKER


def build_payloads(quote: Optional[str] = None) -> List[str]:
    return [f"onerror=alert({WITCHER_MARKER})"]


def is_success(body: str) -> bool:
    tag_re = re.compile(r"<[^>]+>")
    attr_re = re.compile(r'([a-zA-Z0-9:_-]+)\s*=\s*(".*?"|\'.*?\'|[^\s>]+)')
    for tag_match in tag_re.finditer(body):
        tag = tag_match.group(0)
        for attr_match in attr_re.finditer(tag):
            name = attr_match.group(1).lower()
            value = attr_match.group(2)
            if name != "onerror":
                continue
            if not value:
                continue
            quoted = value[0] in {"'", '"'} and value[-1] == value[0]
            raw_value = value[1:-1] if quoted else value
            if not quoted and WITCHER_MARKER in raw_value:
                if "=" in raw_value:
                    continue
                if re.search(r"^[a-zA-Z_]\w*\s*\(.*\)\s*$", raw_value):
                    return True
    return False
