from typing import List, Tuple

from .types import SeedInput, Param


class SeedParser:
    def parse_seed(self, raw: bytes) -> SeedInput:
        parts = raw.split(b"\x00")
        while len(parts) < 4:
            parts.append(b"")
        cookies = parts[0].decode("latin-1", errors="ignore")
        query = parts[1].decode("latin-1", errors="ignore")
        post = parts[2].decode("latin-1", errors="ignore")
        headers = parts[3].decode("latin-1", errors="ignore")
        return SeedInput(raw=raw, cookies=cookies, query=query, post=post, headers=headers)

    def extract_params(self, seed: SeedInput) -> List[Param]:
        params = []
        params.extend(self._parse_kv(seed.query, "GET"))
        params.extend(self._parse_kv(seed.post, "POST"))
        return params

    def _parse_kv(self, data: str, location: str) -> List[Param]:
        items = []
        for index, (key, value) in enumerate(self._split_pairs(data)):
            items.append(Param(location=location, key=key, value=value, index=index))
        return items

    def _split_pairs(self, data: str) -> List[Tuple[str, str]]:
        items: List[Tuple[str, str]] = []
        if not data:
            return items
        parts = data.split("&")
        for part in parts:
            if part == "":
                continue
            if "=" in part:
                key, value = part.split("=", 1)
            else:
                key, value = part, ""
            items.append((key, value))
        return items
