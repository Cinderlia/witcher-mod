import hashlib
from typing import Set


class SeedDeduper:
    def __init__(self):
        self._seen: Set[str] = set()

    def is_duplicate(self, data: bytes) -> bool:
        key = hashlib.sha256(data).hexdigest()
        if key in self._seen:
            return True
        self._seen.add(key)
        return False
