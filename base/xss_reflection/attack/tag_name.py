import re
from typing import List, Optional

from .common import WITCHER_MARKER


def build_payloads(quote: Optional[str] = None) -> List[str]:
    return [f"script>{WITCHER_MARKER}</script"]


def is_success(body: str) -> bool:
    return re.search(r"<script>\s*%s\s*</script" % WITCHER_MARKER, body, re.IGNORECASE) is not None
