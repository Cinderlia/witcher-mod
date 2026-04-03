import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


_SUPERGLOBAL_RE = re.compile(r"\$_(?P<kind>GET|POST|REQUEST|COOKIE)\s*\[\s*(?P<keyexpr>[^\]\n\r]{1,120})\s*\]")
_COOKIE_ALT_RE = re.compile(r"\$COOKIE\s*\[\s*(?P<keyexpr>[^\]\n\r]{1,120})\s*\]")

_CMP_RE = re.compile(
    r"""
    (?P<lhs>
        (?:\$_(?:GET|POST|REQUEST|COOKIE)|\$COOKIE)
        \s*\[\s*(?P<keyexpr1>[^\]\n\r]{1,120})\s*\]
    )
    \s*(?P<op>==|===)\s*
    (?P<rhs>[^;\n\r]{1,200})
    """,
    re.VERBOSE,
)

_CMP_RE_REV = re.compile(
    r"""
    (?P<lhs>[^;\n\r]{1,200})
    \s*(?P<op>==|===)\s*
    (?P<rhs>
        (?:\$_(?:GET|POST|REQUEST|COOKIE)|\$COOKIE)
        \s*\[\s*(?P<keyexpr1>[^\]\n\r]{1,120})\s*\]
    )
    """,
    re.VERBOSE,
)

_QUOTED_STR_RE = re.compile(r"""(?P<q>["'])(?P<val>(?:\\.|[^"']){0,200})\1""")
_QUOTED_STR_FULL_RE = re.compile(r"""\A\s*(?P<q>["'])(?P<val>(?:\\.|[^"']){0,200})\1\s*\Z""")
_NUM_RE = re.compile(r"^[+-]?[0-9]+(?:\.[0-9]+)?$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def extract_params_from_tree(tree, max_file_bytes: int = 5 * 1024 * 1024) -> Dict[str, Dict[str, Set[str]]]:
    acc: Dict[str, Dict[str, Set[str]]] = {"GET": {}, "POST": {}, "COOKIE": {}}
    seen_key_use: Dict[str, Set[str]] = {"GET": set(), "POST": set(), "COOKIE": set()}

    for leaf in tree.leaves:
        abs_path = getattr(leaf, "abs_path", None)
        if abs_path is None:
            continue
        text = _try_read_text(abs_path, max_file_bytes=max_file_bytes)
        if text is None:
            continue

        _scan_comparisons(text, acc, seen_key_use)
        _scan_plain_access(text, acc, seen_key_use)

    _fill_default_values(acc, seen_key_use)
    return acc


def _scan_plain_access(text: str, acc: Dict[str, Dict[str, Set[str]]], seen_key_use: Dict[str, Set[str]]) -> None:
    for m in _SUPERGLOBAL_RE.finditer(text):
        kind = (m.group("kind") or "").upper()
        if _is_write_context(text, m.end()):
            continue
        keyexpr = (m.group("keyexpr") or "").strip()
        key = _parse_keyexpr(keyexpr)
        if key is None:
            continue
        _note_key_use(kind, key, seen_key_use)
        _ensure_key(kind, key, acc)

    for m in _COOKIE_ALT_RE.finditer(text):
        if _is_write_context(text, m.end()):
            continue
        keyexpr = (m.group("keyexpr") or "").strip()
        key = _parse_keyexpr(keyexpr)
        if key is None:
            continue
        _note_key_use("COOKIE", key, seen_key_use)
        _ensure_key("COOKIE", key, acc)


def _scan_comparisons(text: str, acc: Dict[str, Dict[str, Set[str]]], seen_key_use: Dict[str, Set[str]]) -> None:
    for m in _CMP_RE.finditer(text):
        lhs = m.group("lhs") or ""
        keyexpr = (m.group("keyexpr1") or "").strip()
        rhs = (m.group("rhs") or "").strip()
        kind = _infer_kind_from_expr(lhs)
        key = _parse_keyexpr(keyexpr)
        if kind is None or key is None:
            continue
        value = _parse_literal_value(rhs)
        _note_key_use(kind, key, seen_key_use)
        _ensure_key(kind, key, acc)
        if value is not None:
            _add_value(kind, key, value, acc)

    for m in _CMP_RE_REV.finditer(text):
        lhs = (m.group("lhs") or "").strip()
        rhs = m.group("rhs") or ""
        keyexpr = (m.group("keyexpr1") or "").strip()
        kind = _infer_kind_from_expr(rhs)
        key = _parse_keyexpr(keyexpr)
        if kind is None or key is None:
            continue
        value = _parse_literal_value(lhs)
        _note_key_use(kind, key, seen_key_use)
        _ensure_key(kind, key, acc)
        if value is not None:
            _add_value(kind, key, value, acc)


def _infer_kind_from_expr(expr: str) -> Optional[str]:
    s = expr.replace(" ", "")
    if s.startswith("$_GET["):
        return "GET"
    if s.startswith("$_POST["):
        return "POST"
    if s.startswith("$_COOKIE[") or s.startswith("$COOKIE["):
        return "COOKIE"
    if s.startswith("$_REQUEST["):
        return "REQUEST"
    return None


def _parse_keyexpr(keyexpr: str) -> Optional[str]:
    s = keyexpr.strip()
    if not s:
        return None
    if "$" in s or "{" in s or "}" in s:
        return None
    if "." in s or "+" in s or "(" in s or ")" in s or "[" in s or "]" in s or "->" in s or "::" in s:
        return None
    qm = _QUOTED_STR_FULL_RE.match(s)
    if qm:
        val = qm.group("val") or ""
        val = val.encode("utf-8", "ignore").decode("unicode_escape", "ignore")
        val = val.strip()
        if not val:
            return None
        return val
    if _IDENT_RE.match(s):
        return s
    return None


def _parse_literal_value(expr: str) -> Optional[str]:
    s = expr.strip()
    if not s:
        return None
    for _ in range(3):
        if s.startswith("(") and s.endswith(")"):
            s = s[1:-1].strip()
        else:
            break

    if _looks_dynamic_value(s):
        return None

    qm = _QUOTED_STR_FULL_RE.match(s)
    if qm:
        val = qm.group("val") or ""
        val = val.encode("utf-8", "ignore").decode("unicode_escape", "ignore")
        return val
    low = s.lower()
    if low in ("true", "false", "null"):
        return low
    if _NUM_RE.match(s):
        return s
    return None


def _looks_dynamic_value(s: str) -> bool:
    if "$" in s or "{" in s or "}" in s:
        return True
    if "." in s or "+" in s:
        return True
    if "[" in s or "]" in s:
        return True
    if "(" in s or ")" in s:
        return True
    if "->" in s or "::" in s:
        return True
    return False


def _is_write_context(text: str, idx_after_bracket: int) -> bool:
    i = idx_after_bracket
    n = len(text)
    while i < n and text[i].isspace():
        i += 1
    if i >= n:
        return False

    if text[i : i + 3] == "??=":
        return True
    if text[i : i + 2] == "=>":
        return True

    if text[i] == "=":
        if i + 1 < n and text[i + 1] == "=":
            return False
        return True

    if i + 1 < n and text[i + 1] == "=" and text[i] in ".+-*/%&|^":
        return True

    return False


def _note_key_use(kind: str, key: str, seen_key_use: Dict[str, Set[str]]) -> None:
    if kind == "REQUEST":
        seen_key_use["GET"].add(key)
        return
    if kind in seen_key_use:
        seen_key_use[kind].add(key)


def _ensure_key(kind: str, key: str, acc: Dict[str, Dict[str, Set[str]]]) -> None:
    if kind == "REQUEST":
        _ensure_key("GET", key, acc)
        return
    if kind not in acc:
        return
    if key not in acc[kind]:
        acc[kind][key] = set()


def _add_value(kind: str, key: str, value: str, acc: Dict[str, Dict[str, Set[str]]]) -> None:
    if kind == "REQUEST":
        _add_value("GET", key, value, acc)
        return
    if kind not in acc:
        return
    if key not in acc[kind]:
        acc[kind][key] = set()
    acc[kind][key].add(value)


def _fill_default_values(acc: Dict[str, Dict[str, Set[str]]], seen_key_use: Dict[str, Set[str]]) -> None:
    for kind in ("GET", "POST", "COOKIE"):
        for key in sorted(seen_key_use[kind]):
            if key not in acc[kind]:
                acc[kind][key] = set()
            if not acc[kind][key]:
                acc[kind][key].add("1")


def _try_read_text(path: Path, max_file_bytes: int) -> Optional[str]:
    try:
        st = path.stat()
        if st.st_size <= 0:
            return None
        if st.st_size > max_file_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        try:
            return data.decode(errors="ignore")
        except Exception:
            return None
