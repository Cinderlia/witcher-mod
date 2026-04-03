import re
from typing import List, Optional

from .common import WITCHER_MARKER


def build_payloads(quote: Optional[str] = None) -> List[str]:
    return [
        f"<script>{WITCHER_MARKER}</script>",
        f"<img src=x onerror=alert({WITCHER_MARKER})>",
    ]


def is_success(body: str) -> bool:
    if re.search(r"<script>\s*%s\s*</script>" % WITCHER_MARKER, body, re.IGNORECASE):
        return True
    if re.search(r"<img[^>]+onerror\s*=\s*alert\(\s*%s\s*\)" % WITCHER_MARKER, body, re.IGNORECASE):
        return True
    return False
