from typing import List, Sequence, Tuple
from urllib.parse import urljoin, urlparse, urlunparse


class BuiltUrl(object):
    __slots__ = ("href", "path", "query")

    def __init__(self, href: str, path: str, query: str) -> None:
        self.href = href
        self.path = path
        self.query = query


def build_url(base_url: str, rel_posix_path: str, query_string: str) -> BuiltUrl:
    base = base_url.strip()
    if not base:
        raise ValueError("base_url is empty")

    parsed = urlparse(base)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("base_url is not absolute: {}".format(base_url))

    rel_path = rel_posix_path.replace("\\", "/").strip().lstrip("/")
    rel_path = _dedupe_overlapping_prefix(parsed.path, rel_path)

    base_for_join = base if base.endswith("/") else base + "/"
    joined = urljoin(base_for_join, rel_path)
    joined_parsed = urlparse(joined)
    href = urlunparse(joined_parsed._replace(query=query_string or ""))
    return BuiltUrl(href=href, path=joined_parsed.path, query=query_string or "")


def _dedupe_overlapping_prefix(base_path: str, rel_path: str) -> str:
    base_segs = [s for s in base_path.split("/") if s]
    rel_segs = [s for s in rel_path.split("/") if s]
    if not base_segs or not rel_segs:
        return rel_path

    max_k = min(len(base_segs), len(rel_segs))
    for k in range(max_k, 0, -1):
        if base_segs[-k:] == rel_segs[:k]:
            rel_segs = rel_segs[k:]
            break
    return "/".join(rel_segs)


def ensure_unique_keys(keys: Sequence[str]) -> List[str]:
    seen = {}
    out: List[str] = []
    for k in keys:
        if k not in seen:
            seen[k] = 1
            out.append(k)
            continue
        seen[k] += 1
        out.append("{} #{}".format(k, seen[k]))
    return out
