import re
from typing import Iterable, List, Tuple


class RawPhpUrl(object):
    __slots__ = ("path", "query")

    def __init__(self, path: str, query: str) -> None:
        self.path = path
        self.query = query


_PHP_PATH_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_])
    (?P<path>(?:(?:\.\./)|(?:\./)|/)?(?:[A-Za-z0-9_\-\.~%]+/)*[A-Za-z0-9_\-\.~%]+\.php)
    """,
    re.VERBOSE,
)

_QUOTED_FULL_RE = re.compile(
    r"""
    (["'])
    (?P<val>(?:(?:\.\./)|(?:\./)|/)?(?:[A-Za-z0-9_\-\.~%]+/)*[A-Za-z0-9_\-\.~%]+\.php(?:\?[^"']*)?)
    \1
    """,
    re.VERBOSE,
)

_CONCAT_RE = re.compile(
    r"""
    (["'])
    (?P<path>(?:(?:\.\./)|(?:\./)|/)?(?:[A-Za-z0-9_\-\.~%]+/)*[A-Za-z0-9_\-\.~%]+\.php)
    \1
    \s*[\.\+]\s*
    (["'])
    (?P<query>\?[^"']*)
    \3
    """,
    re.VERBOSE,
)

_QUERY_STOP_RE = re.compile(r"[\n\r;<>)\]}]")


def extract_raw_php_urls(text: str) -> List[RawPhpUrl]:
    out: List[RawPhpUrl] = []
    seen = set()

    for m in _QUOTED_FULL_RE.finditer(text):
        val = (m.group("val") or "").strip()
        if not val:
            continue
        if "?" in val:
            p, q = val.split("?", 1)
            path = p
            query = "?" + q
        else:
            path = val
            query = ""
        key = (path, query)
        if key in seen:
            continue
        seen.add(key)
        out.append(RawPhpUrl(path=path, query=query))

    for m in _CONCAT_RE.finditer(text):
        path = (m.group("path") or "").strip()
        query = (m.group("query") or "").strip()
        if not path:
            continue
        key = (path, query)
        if key in seen:
            continue
        seen.add(key)
        out.append(RawPhpUrl(path=path, query=query))

    for m in _PHP_PATH_RE.finditer(text):
        path = (m.group("path") or "").strip()
        if not path:
            continue
        key = (path, "")
        if key in seen:
            continue
        seen.add(key)
        out.append(RawPhpUrl(path=path, query=""))

    return out


def normalize_query(query: str) -> List[Tuple[str, str]]:
    q = query.strip()
    q = _cleanup_query_expression(q)
    if not q:
        return []

    pairs: List[Tuple[str, str]] = []
    for part in re.split(r"[&;]", q):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, value = part.split("=", 1)
        else:
            key, value = part, ""
        key = _strip_quotes(key.strip())
        value = _strip_quotes(value.strip())
        if not key:
            continue
        if _key_is_dynamic(key):
            continue
        if not value or _value_is_dynamic(value):
            value = "1"
        key = _clean_key(key)
        if not key:
            continue
        pairs.append((key, value))
    return pairs


def build_query_string(pairs: Iterable[Tuple[str, str]]) -> str:
    out: List[str] = []
    for k, v in pairs:
        if not k:
            continue
        out.append("{}={}".format(k, v))
    return "&".join(out)


def _strip_quotes(s: str) -> str:
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    return s


def _key_is_dynamic(s: str) -> bool:
    if "$" in s:
        return True
    if "{" in s or "}" in s:
        return True
    return False


def _value_is_dynamic(s: str) -> bool:
    if "$" in s:
        return True
    if "{" in s or "}" in s:
        return True
    if "[" in s or "]" in s:
        return True
    if "(" in s or ")" in s:
        return True
    if "->" in s or "::" in s:
        return True
    if "\\" in s:
        return True
    return False


def _cleanup_query_expression(expr: str) -> str:
    s = expr.strip()
    if not s:
        return ""
    if s.startswith("?"):
        s = s[1:]

    s = s.replace('"', "").replace("'", "")
    s = s.replace("\\n", "").replace("\\r", "").replace("\\t", "")
    s = _strip_concat_operators(s)
    s = re.sub(r"\s+", "", s)
    s = s.replace("%26", "&").replace("%3D", "=").replace("%3d", "=")
    return s


def _clean_key(key: str) -> str:
    k = key.strip()
    k = k.strip("&;? ")
    k = re.sub(r"[^A-Za-z0-9_\-\.~%]", "", k)
    return k


def _strip_concat_operators(s: str) -> str:
    out: List[str] = []
    n = len(s)
    for i, ch in enumerate(s):
        if ch in {".", "+"}:
            prev = s[i - 1] if i - 1 >= 0 else ""
            nxt = s[i + 1] if i + 1 < n else ""
            if prev.isalnum() and nxt.isalnum():
                out.append(ch)
                continue
            continue
        out.append(ch)
    return "".join(out)
