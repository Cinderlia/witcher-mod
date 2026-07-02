"""
Small persistent cache for IF-branch coverage results (path:line -> covered bool).
"""

import json
import os
from typing import Dict, Optional


class IfBranchCoverageCache:
    """File-backed cache for per-AST_IF coverage checks."""
    def __init__(self, cache_path: str):
        self._cache: Dict[str, bool] = {}
        self._cache_path = cache_path or ""
        self._loaded = False
        self._dirty = 0

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        if not self._cache_path or not os.path.exists(self._cache_path):
            return
        try:
            with open(self._cache_path, "r", encoding="utf-8", errors="replace") as f:
                obj = json.load(f)
        except Exception:
            return
        if not isinstance(obj, dict):
            return
        for k, v in obj.items():
            try:
                ks = str(k)
            except Exception:
                continue
            self._cache[ks] = bool(v)

    def _save(self):
        if not self._cache_path:
            return
        try:
            os.makedirs(os.path.dirname(self._cache_path) or ".", exist_ok=True)
        except Exception:
            return
        data = {str(k): bool(v) for k, v in self._cache.items()}
        try:
            with open(self._cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            return
        self._dirty = 0

    def get(self, key):
        self._load()
        try:
            ks = str(key)
        except Exception:
            return None
        return self._cache.get(ks)

    def set(self, key, value):
        self._load()
        try:
            ks = str(key)
        except Exception:
            return
        self._cache[ks] = bool(value)
        self._dirty += 1
        if self._dirty >= 200:
            self._save()

    def reset(self):
        self._cache = {}
        self._loaded = True
        if self._cache_path and os.path.exists(self._cache_path):
            try:
                os.remove(self._cache_path)
            except Exception:
                return


_CACHE: Optional[IfBranchCoverageCache] = None


def init_cache(cache_path: str):
    global _CACHE
    _CACHE = IfBranchCoverageCache(cache_path)


def get_cached_result(if_id):
    if _CACHE is None:
        return None
    return _CACHE.get(if_id)


def set_cached_result(if_id, value):
    if _CACHE is None:
        return
    _CACHE.set(if_id, value)


def reset_cache():
    if _CACHE is None:
        return
    _CACHE.reset()
