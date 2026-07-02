import re
try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Optional, Tuple


_INT_RE = re.compile(rb"[+-]?\d+")
_FLOAT_RE = re.compile(rb"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")


@dataclass
class SessionValidationResult:
    ok: bool
    fixed_text: str
    changed: bool
    error: str


def validate_and_fix_php_session_text(text: str) -> SessionValidationResult:
    raw = (text or "")
    s = raw.strip()
    if not s:
        return SessionValidationResult(ok=False, fixed_text="", changed=False, error="empty_session")

    data = s.encode("utf-8", errors="replace")
    out = bytearray()
    pos = 0
    changed = False

    def skip_ws(i: int) -> int:
        while i < len(data) and data[i] in b" \t\r\n":
            i += 1
        return i

    def parse_len(i: int) -> Tuple[Optional[int], int, str]:
        i = skip_ws(i)
        m = _INT_RE.match(data, i)
        if not m:
            return None, i, "expected_int"
        try:
            v = int(m.group(0))
        except Exception:
            return None, i, "bad_int"
        return v, m.end(), ""

    def parse_expect(i: int, token: bytes) -> Tuple[int, str]:
        i = skip_ws(i)
        if data[i : i + len(token)] != token:
            return i, "expected_token"
        return i + len(token), ""

    def parse_serialize(i: int, depth: int) -> Tuple[int, Optional[bytes], bool, str]:
        nonlocal changed
        if depth > 200:
            return i, None, False, "max_depth"
        i = skip_ws(i)
        if i >= len(data):
            return i, None, False, "unexpected_eof"
        t = data[i : i + 1]
        if t == b"N":
            j, err = parse_expect(i + 1, b";")
            if err:
                return i, None, False, "bad_null"
            return j, b"N;", True, ""
        if t == b"b":
            j, err = parse_expect(i + 1, b":")
            if err:
                return i, None, False, "bad_bool"
            j = skip_ws(j)
            if j >= len(data) or data[j] not in b"01":
                return i, None, False, "bad_bool_value"
            val = data[j : j + 1]
            j2, err = parse_expect(j + 1, b";")
            if err:
                return i, None, False, "bad_bool_term"
            return j2, b"b:" + val + b";", True, ""
        if t == b"i":
            j, err = parse_expect(i + 1, b":")
            if err:
                return i, None, False, "bad_int"
            v, j2, err2 = parse_len(j)
            if err2 or v is None:
                return i, None, False, "bad_int_value"
            j3, err3 = parse_expect(j2, b";")
            if err3:
                return i, None, False, "bad_int_term"
            return j3, b"i:" + str(int(v)).encode("ascii") + b";", True, ""
        if t == b"d":
            j, err = parse_expect(i + 1, b":")
            if err:
                return i, None, False, "bad_double"
            j = skip_ws(j)
            m = _FLOAT_RE.match(data, j)
            if not m:
                return i, None, False, "bad_double_value"
            num = m.group(0)
            j2, err2 = parse_expect(m.end(), b";")
            if err2:
                return i, None, False, "bad_double_term"
            return j2, b"d:" + num + b";", True, ""
        if t == b"s":
            j, err = parse_expect(i + 1, b":")
            if err:
                return i, None, False, "bad_string"
            _, j2, err2 = parse_len(j)
            if err2:
                return i, None, False, "bad_string_len"
            j3, err3 = parse_expect(j2, b':"')
            if err3:
                return i, None, False, "bad_string_open"
            end = data.find(b'";', j3)
            if end < 0:
                return i, None, False, "bad_string_close"
            content = data[j3:end]
            actual = len(content)
            fixed = b"s:" + str(actual).encode("ascii") + b':"' + content + b'";'
            if data[i : end + 2] != fixed:
                changed = True
            return end + 2, fixed, True, ""
        if t == b"a":
            j, err = parse_expect(i + 1, b":")
            if err:
                return i, None, False, "bad_array"
            n, j2, err2 = parse_len(j)
            if err2 or n is None or n < 0:
                return i, None, False, "bad_array_len"
            j3, err3 = parse_expect(j2, b":{")
            if err3:
                return i, None, False, "bad_array_open"
            buf = bytearray()
            buf.extend(b"a:")
            buf.extend(str(int(n)).encode("ascii"))
            buf.extend(b":{")
            cur = j3
            for _ in range(int(n) * 2):
                cur, vv, ok, er = parse_serialize(cur, depth + 1)
                if not ok or vv is None:
                    return i, None, False, er or "bad_array_elem"
                buf.extend(vv)
            cur = skip_ws(cur)
            if cur >= len(data) or data[cur : cur + 1] != b"}":
                return i, None, False, "bad_array_close"
            buf.extend(b"}")
            return cur + 1, bytes(buf), True, ""
        if t == b"O":
            j, err = parse_expect(i + 1, b":")
            if err:
                return i, None, False, "bad_object"
            _, j2, err2 = parse_len(j)
            if err2:
                return i, None, False, "bad_object_class_len"
            j3, err3 = parse_expect(j2, b':"')
            if err3:
                return i, None, False, "bad_object_class_open"
            end = data.find(b'":', j3)
            if end < 0:
                return i, None, False, "bad_object_class_close"
            class_name = data[j3:end]
            class_len = len(class_name)
            k, errk = parse_expect(end + 2, b"")
            if errk:
                return i, None, False, "bad_object_after_class"
            k = skip_ws(k)
            m = _INT_RE.match(data, k)
            if not m:
                return i, None, False, "bad_object_propcount"
            try:
                prop_n = int(m.group(0))
            except Exception:
                return i, None, False, "bad_object_propcount"
            k2, errk2 = parse_expect(m.end(), b":{")
            if errk2:
                return i, None, False, "bad_object_open"
            buf = bytearray()
            buf.extend(b"O:")
            buf.extend(str(int(class_len)).encode("ascii"))
            buf.extend(b':"')
            buf.extend(class_name)
            buf.extend(b'":')
            buf.extend(str(int(prop_n)).encode("ascii"))
            buf.extend(b":{")
            cur = k2
            for _ in range(int(prop_n) * 2):
                cur, vv, ok, er = parse_serialize(cur, depth + 1)
                if not ok or vv is None:
                    return i, None, False, er or "bad_object_elem"
                buf.extend(vv)
            cur = skip_ws(cur)
            if cur >= len(data) or data[cur : cur + 1] != b"}":
                return i, None, False, "bad_object_close"
            buf.extend(b"}")
            if data[i : cur + 1] != bytes(buf):
                changed = True
            return cur + 1, bytes(buf), True, ""
        if t in (b"R", b"r"):
            j, err = parse_expect(i + 1, b":")
            if err:
                return i, None, False, "bad_ref"
            v, j2, err2 = parse_len(j)
            if err2 or v is None:
                return i, None, False, "bad_ref_id"
            j3, err3 = parse_expect(j2, b";")
            if err3:
                return i, None, False, "bad_ref_term"
            return j3, t + b":" + str(int(v)).encode("ascii") + b";", True, ""
        return i, None, False, "unsupported_type"

    pos = skip_ws(pos)
    while pos < len(data):
        pos = skip_ws(pos)
        if pos >= len(data):
            break
        sep = data.find(b"|", pos)
        if sep < 0:
            return SessionValidationResult(ok=False, fixed_text=s, changed=False, error="missing_var_separator")
        name_b = data[pos:sep]
        if not name_b:
            return SessionValidationResult(ok=False, fixed_text=s, changed=False, error="empty_var_name")
        try:
            name_s = name_b.decode("utf-8", errors="replace")
        except Exception:
            name_s = ""
        if not name_s:
            return SessionValidationResult(ok=False, fixed_text=s, changed=False, error="bad_var_name")
        out.extend(name_b)
        out.extend(b"|")
        pos = sep + 1
        pos, vv, ok, err = parse_serialize(pos, 0)
        if not ok or vv is None:
            return SessionValidationResult(ok=False, fixed_text=s, changed=False, error=err or "bad_serialize")
        out.extend(vv)
        pos = skip_ws(pos)

    fixed = out.decode("utf-8", errors="replace")
    return SessionValidationResult(ok=True, fixed_text=fixed, changed=(changed or (fixed != s)), error="")
