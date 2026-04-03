from typing import List, Tuple

from .types import SeedInput, Param


class SeedMutator:
    def replace_param(self, seed: SeedInput, param: Param, new_value: str) -> bytes:
        cookies = seed.cookies
        query = seed.query
        post = seed.post
        headers = seed.headers
        if param.location == "GET":
            query = self._replace_kv_by_index(seed.query, param.index, new_value)
        elif param.location == "POST":
            post = self._replace_kv_by_index(seed.post, param.index, new_value)
        raw = "\x00".join([cookies, query, post, headers]).encode("latin-1", errors="ignore")
        return raw

    def _replace_kv_by_index(self, data: str, index: int, value: str) -> str:
        items = self._split_pairs(data)
        if index < 0 or index >= len(items):
            return data
        new_items: List[Tuple[str, str]] = []
        for idx, (k, v) in enumerate(items):
            if idx == index:
                new_items.append((k, value))
            else:
                new_items.append((k, v))
        return "&".join([f"{k}={v}" for k, v in new_items])

    def _split_pairs(self, data: str) -> List[Tuple[str, str]]:
        items: List[Tuple[str, str]] = []
        if data == "":
            return items
        for part in data.split("&"):
            if part == "":
                continue
            if "=" in part:
                key, value = part.split("=", 1)
            else:
                key, value = part, ""
            items.append((key, value))
        return items
