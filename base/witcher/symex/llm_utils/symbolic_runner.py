"""
Run LLM-assisted symbolic-execution prompts and normalize the JSON solutions output.
"""

import asyncio
import json
import os
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from typing import Any, Dict, List, Optional, Tuple

from common.app_config import load_app_config
from db_query.query_executor import (
    db_query_result_to_text,
    execute_database_query,
    is_non_retryable_db_result,
    load_db_query_config_from_raw,
)
from llm_utils import get_default_client
from llm_utils.prompts.symbolic_prompt import extract_db_search_source_from_prompt_text, extract_symbolic_objective_from_prompt_text
from llm_utils.taint.taint_llm_calls import LLMCallFailure, chat_text_with_retries, write_llm_failure_artifact


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", flags=re.IGNORECASE)


def _asyncio_run(coro):
    runner = getattr(asyncio, "run", None)
    if runner is not None:
        return runner(coro)
    created_loop = False
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        created_loop = True
    try:
        return loop.run_until_complete(coro)
    finally:
        if created_loop:
            try:
                loop.close()
            finally:
                try:
                    asyncio.set_event_loop(None)
                except Exception:
                    pass


def _load_symbolic_llm_temperature() -> float:
    try:
        cfg = load_app_config()
        raw = cfg.raw if hasattr(cfg, "raw") else {}
    except Exception:
        raw = {}
    sec = raw.get("symbolic_prompt")
    if not isinstance(sec, dict):
        sec = {}
    v = sec.get("llm_temperature")
    try:
        return float(v) if v is not None else 0.2
    except Exception:
        return 0.2


def _read_json(path: str) -> Dict[str, Any]:
    if not isinstance(path, str) or not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _load_session_capture(test_command_path: str) -> Dict[str, Any]:
    candidates: List[str] = []
    if isinstance(test_command_path, str) and test_command_path:
        base_dir = os.path.dirname(test_command_path)
        if base_dir:
            candidates.append(os.path.join(base_dir, "session_capture.json"))
            try:
                import hashlib

                key = hashlib.sha1(base_dir.encode("utf-8", errors="replace")).hexdigest()
                candidates.append(os.path.join("/tmp", "wc_session_trace", key + ".json"))
            except Exception:
                pass
    candidates.append(os.path.join(os.getcwd(), "input", "session_capture.json"))
    seen = set()
    for cand in candidates:
        p = os.path.abspath(cand)
        if p in seen:
            continue
        seen.add(p)
        obj = _read_json(p)
        if obj:
            return obj
    return {}


def _load_symbolic_db_raw_cfg() -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    cfg = None
    try:
        cfg = load_app_config()
        raw = cfg.raw if hasattr(cfg, "raw") else {}
        if isinstance(raw, dict):
            out.update(raw)
    except Exception:
        cfg = None
    cfg_dir = ""
    try:
        cfg_path = str(getattr(cfg, "config_path", "") or "")
        cfg_dir = os.path.dirname(os.path.abspath(cfg_path)) if cfg_path else ""
    except Exception:
        cfg_dir = ""
    candidates = []
    if cfg_dir:
        candidates.append(os.path.join(cfg_dir, "symex_config.json"))
    candidates.append(os.path.join(os.getcwd(), "symex_config.json"))
    for p in candidates:
        sec = _read_json(p)
        if not sec:
            continue
        if isinstance(sec.get("symbolic_db"), dict):
            out["symbolic_db"] = sec.get("symbolic_db")
            break
    return out


def _ensure_dir(p: str) -> None:
    if not p:
        return
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        return


def _read_text(path: str) -> str:
    if not isinstance(path, str) or not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _write_text(path: str, text: str) -> None:
    _ensure_dir(os.path.dirname(os.path.abspath(path)))
    with open(path, "w", encoding="utf-8") as f:
        f.write(text or "")


def _extract_json_text(text: str) -> Optional[str]:
    if not isinstance(text, str):
        return None
    t = text.strip()
    if not t:
        return None
    m = _FENCE_RE.search(t)
    if m:
        inner = (m.group(1) or "").strip()
        if inner.startswith("{") and inner.endswith("}"):
            return inner
    i = t.find("{")
    j = t.rfind("}")
    if i >= 0 and j >= 0 and j > i:
        return t[i : j + 1]
    return None


def _iter_json_object_candidates(text: str) -> List[str]:
    if not isinstance(text, str) or not text:
        return []
    s = text
    out: List[str] = []
    depth = 0
    start = None
    in_str = False
    esc = False
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
            continue
        if ch == "}":
            if depth <= 0:
                continue
            depth -= 1
            if depth == 0 and start is not None:
                cand = s[start : i + 1].strip()
                if cand.startswith("{") and cand.endswith("}"):
                    out.append(cand)
                start = None
    return out


def _repair_json_text(text: str) -> str:
    s = (text or "").strip()
    if not s:
        return s
    s = re.sub(r",\s*([}\]])", r"\1", s)
    s = re.sub(r"\bTrue\b", "true", s)
    s = re.sub(r"\bFalse\b", "false", s)
    s = re.sub(r"\bNone\b", "null", s)
    return s


def _parse_json_best_effort(text: str):
    if not isinstance(text, str) or not text.strip():
        return None
    raw = text.strip()
    try:
        return json.loads(raw)
    except Exception:
        pass
    js = _extract_json_text(raw)
    if js:
        try:
            return json.loads(js)
        except Exception:
            try:
                return json.loads(_repair_json_text(js))
            except Exception:
                pass
    repaired = _repair_json_text(raw)
    if repaired and repaired != raw:
        try:
            return json.loads(repaired)
        except Exception:
            pass
    for cand in _iter_json_object_candidates(raw)[:10]:
        try:
            return json.loads(cand)
        except Exception:
            try:
                return json.loads(_repair_json_text(cand))
            except Exception:
                continue
    return None


def _normalize_solutions(obj) -> List[dict]:
    if obj is None:
        return []
    if isinstance(obj, list):
        out = []
        for x in obj:
            if isinstance(x, dict):
                out.append(x)
        return out
    if isinstance(obj, dict):
        sols = obj.get("solutions")
        if isinstance(sols, list):
            out = []
            for x in sols:
                if isinstance(x, dict):
                    out.append(x)
            return out
        return [obj] if obj else []
    return []


def _extract_db_query_from_obj(obj) -> str:
    keys = ("DB_QUERY", "db_query", "DBQUERY", "QUERY")
    def _pick_from_solution_list(solutions) -> str:
        if not isinstance(solutions, list):
            return ""
        for s in solutions:
            if not isinstance(s, dict):
                continue
            for k in keys:
                v = s.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
        return ""
    if isinstance(obj, dict):
        # Prefer solutions[*].DB_QUERY to align with prompt JSON example.
        q = _pick_from_solution_list(obj.get("solutions"))
        if q:
            return q
        for k in keys:
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(obj, list):
        q = _pick_from_solution_list(obj)
        if q:
            return q
    return ""


def _extract_db_query_from_text(text: str) -> str:
    if not isinstance(text, str) or not text.strip():
        return ""
    try:
        obj = json.loads(text)
    except Exception:
        js = _extract_json_text(text)
        if not js:
            return ""
        try:
            obj = json.loads(js)
        except Exception:
            return ""
    return _extract_db_query_from_obj(obj)


def _extract_db_request_from_obj(obj) -> Dict[str, Any]:
    keys = ("DB_REQUEST", "db_request", "DBREQUEST")

    def _pick_from_solution_list(solutions) -> Dict[str, Any]:
        if not isinstance(solutions, list):
            return {}
        for s in solutions:
            if not isinstance(s, dict):
                continue
            for k in keys:
                v = s.get(k)
                if isinstance(v, dict) and v:
                    return dict(v)
        return {}

    if isinstance(obj, dict):
        req = _pick_from_solution_list(obj.get("solutions"))
        if req:
            return req
        for k in keys:
            v = obj.get(k)
            if isinstance(v, dict) and v:
                return dict(v)
    if isinstance(obj, list):
        req = _pick_from_solution_list(obj)
        if req:
            return req
    return {}


def _extract_db_request_from_text(text: str) -> Dict[str, Any]:
    obj = _parse_json_best_effort(text)
    return _extract_db_request_from_obj(obj)


def _build_prompt_with_db_feedback(base_prompt: str, db_rounds: List[Dict[str, Any]]) -> str:
    prompt = (base_prompt or "").rstrip()
    if not db_rounds:
        return prompt + "\n"
    lines: List[str] = [prompt, "", "以下是你请求并已执行的数据库查询结果（这是可能需要的数据库数据）："]
    for i, rec in enumerate(db_rounds, 1):
        q = str((rec or {}).get("query") or "").strip()
        rs = (rec or {}).get("result")
        lines.append(f"[数据库查询回合 {int(i)}]")
        lines.append("查询语句：")
        lines.append(q or "<EMPTY_QUERY>")
        lines.append("查询结果（JSON）：")
        lines.append(db_query_result_to_text(rs if isinstance(rs, dict) else {}))
        lines.append("")
    lines.append("请严格基于上述数据库数据继续求解；只有在仍然缺少关键数据库数据时，才输出新的 DB_QUERY。")
    lines.append("如果已有足够信息，请直接输出可用于生成新seed的 solutions JSON。")
    return "\n".join(lines).rstrip() + "\n"


def parse_symbolic_response(text: str) -> List[dict]:
    obj = _parse_json_best_effort(text)
    return _normalize_solutions(obj)


def symbolic_response_has_valid_json(text: str) -> bool:
    obj = _parse_json_best_effort(text)
    return isinstance(obj, (dict, list))


def _stringify_value(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        try:
            return json.dumps(v, ensure_ascii=False)
        except Exception:
            return str(v)
    return str(v)


def _split_query_pairs(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    s = (text or "").strip()
    if not s:
        return out
    for part in s.split("&"):
        part_s = (part or "").strip()
        if not part_s:
            continue
        if "=" in part_s:
            k, v = part_s.split("=", 1)
            out.append((k, v))
        else:
            out.append((part_s, ""))
    return out


def _pairs_to_query(pairs: List[Tuple[str, str]]) -> str:
    buf = []
    for k, v in pairs:
        ks = (k or "").strip()
        vs = _stringify_value(v)
        if not ks and not vs:
            continue
        buf.append(f"{ks}={vs}")
    return "&".join(buf)


def _normalize_export_line(line: str) -> str:
    v = (line or "").strip()
    if not v:
        return ""
    if v.startswith("export "):
        return v
    return "export " + v


def _parse_env_kv(line: str) -> Optional[Tuple[str, str]]:
    v = (line or "").strip()
    if not v:
        return None
    if v.startswith("export "):
        v = (v[len("export ") :] or "").strip()
    if "=" not in v:
        return None
    k, val = v.split("=", 1)
    k = (k or "").strip()
    if not k:
        return None
    return k, val


def _merge_env_lines(base_lines: List[str], override_lines: List[str]) -> List[str]:
    if not base_lines and not override_lines:
        return []
    out: List[str] = []
    index: Dict[str, int] = {}
    for line in base_lines or []:
        kv = _parse_env_kv(line)
        if not kv:
            continue
        k, v = kv
        index[k] = len(out)
        out.append(_normalize_export_line(f"{k}={v}"))
    for line in override_lines or []:
        kv = _parse_env_kv(line)
        if not kv:
            continue
        k, v = kv
        norm_line = _normalize_export_line(f"{k}={v}")
        if k in index:
            out[index[k]] = norm_line
        else:
            index[k] = len(out)
            out.append(norm_line)
    return out


def _normalize_env_lines(env_obj, *, defaults: Optional[List[str]] = None, use_default: bool = False) -> List[str]:
    if use_default:
        return list(defaults or [])
    if env_obj is None:
        return []
    if isinstance(env_obj, dict):
        return [_normalize_export_line(f"{k}={_stringify_value(v)}") for k, v in env_obj.items()]
    if isinstance(env_obj, (list, tuple)):
        out = []
        for it in env_obj:
            if isinstance(it, dict):
                out.extend([_normalize_export_line(f"{k}={_stringify_value(v)}") for k, v in it.items()])
                continue
            if isinstance(it, (list, tuple)) and len(it) >= 2:
                out.append(_normalize_export_line(f"{it[0]}={_stringify_value(it[1])}"))
                continue
            if isinstance(it, str):
                v = it.strip()
                if v:
                    out.append(_normalize_export_line(v))
                continue
        return [x for x in out if x]
    if isinstance(env_obj, str):
        out = []
        for line in env_obj.splitlines():
            v = line.strip()
            if v:
                out.append(_normalize_export_line(v))
        return [x for x in out if x]
    return []


def _normalize_request_field(field_obj, *, default_value: str, use_default: bool) -> str:
    if use_default:
        return (default_value or "").strip()
    if field_obj is None:
        return ""
    if isinstance(field_obj, dict):
        pairs = [(k, _stringify_value(v)) for k, v in field_obj.items()]
        return _pairs_to_query(pairs).strip()
    if isinstance(field_obj, (list, tuple)):
        pairs: List[Tuple[str, str]] = []
        for it in field_obj:
            if isinstance(it, dict):
                for k, v in it.items():
                    pairs.append((k, _stringify_value(v)))
                continue
            if isinstance(it, (list, tuple)) and len(it) >= 2:
                pairs.append((it[0], _stringify_value(it[1])))
                continue
            if isinstance(it, str):
                pairs.extend(_split_query_pairs(it))
                continue
        if pairs:
            return _pairs_to_query(pairs).strip()
        return ""
    if isinstance(field_obj, str):
        return field_obj.strip()
    return _stringify_value(field_obj).strip()


def _parse_test_command_text(text: str) -> dict:
    env_lines: List[str] = []
    cookie_value = ""
    get_value = ""
    post_value = ""
    if not isinstance(text, str) or not text.strip():
        return {"env_lines": env_lines, "COOKIE": cookie_value, "GET": get_value, "POST": post_value}
    for raw in text.splitlines() or []:
        line = (raw or "").strip()
        if not line:
            continue
        if line.startswith("export "):
            rest = (line[len("export ") :] or "").strip()
            if rest:
                env_lines.append(_normalize_export_line(rest))
            continue
        if line.startswith("COOKIE:"):
            cookie_value = (line.split("COOKIE:", 1)[1] or "").strip()
            continue
        if line.startswith("GET:"):
            get_value = (line.split("GET:", 1)[1] or "").strip()
            continue
        if line.startswith("POST:"):
            post_value = (line.split("POST:", 1)[1] or "").strip()
            continue
    return {"env_lines": env_lines, "COOKIE": cookie_value, "GET": get_value, "POST": post_value}


def _parse_url_text(text: str) -> dict:
    env_lines: List[str] = []
    cookie_value = ""
    get_value = ""
    post_value = ""
    url_value = ""
    if not isinstance(text, str) or not text.strip():
        return {"env_lines": env_lines, "COOKIE": cookie_value, "GET": get_value, "POST": post_value, "URL": url_value, "MODE": "URL"}
    for raw in text.splitlines() or []:
        line = (raw or "").strip()
        if not line:
            continue
        m_cookie = re.search(r"\bCookie\s*:\s*(.*)$", line, flags=re.IGNORECASE)
        if m_cookie and not cookie_value:
            cookie_value = (m_cookie.group(1) or "").strip()
            continue
        if line.startswith("COOKIE:") and not cookie_value:
            cookie_value = (line.split("COOKIE:", 1)[1] or "").strip()
            continue
        if line.startswith("GET:") and not get_value:
            get_value = (line.split("GET:", 1)[1] or "").strip()
            continue
        if line.startswith("POST:") and not post_value:
            post_value = (line.split("POST:", 1)[1] or "").strip()
            continue
        if not url_value:
            m_url = re.search(r"(https?://[^\s\"']+)", line)
            if m_url:
                url_value = (m_url.group(1) or "").strip()
                continue
    if not url_value:
        m_url = re.search(r"(https?://[^\s\"']+)", text or "")
        if m_url:
            url_value = (m_url.group(1) or "").strip()
    if url_value and not get_value:
        try:
            qs = urlsplit(url_value).query or ""
            if qs:
                pairs = parse_qsl(qs, keep_blank_values=True)
                get_value = _pairs_to_query([(k, v) for k, v in pairs])
        except Exception:
            get_value = get_value
    return {"env_lines": env_lines, "COOKIE": cookie_value, "GET": get_value, "POST": post_value, "URL": url_value, "MODE": "URL"}


def load_symbolic_solution_defaults(test_command_path: str) -> dict:
    if isinstance(test_command_path, str) and os.path.exists(test_command_path):
        out = _parse_test_command_text(_read_text(test_command_path))
        out["SESSION_CAPTURE"] = _load_session_capture(test_command_path)
        return out
    url_path = ""
    if isinstance(test_command_path, str) and test_command_path:
        base_dir = os.path.dirname(test_command_path)
        url_path = os.path.join(base_dir, "url.txt")
        if not os.path.exists(url_path):
            url_path = ""
    if not url_path:
        url_path = os.path.join(os.getcwd(), "input", "url.txt")
    if url_path and os.path.exists(url_path):
        out = _parse_url_text(_read_text(url_path))
        out["SESSION_CAPTURE"] = _load_session_capture(url_path)
        return out
    out = _parse_test_command_text("")
    out["SESSION_CAPTURE"] = _load_session_capture(test_command_path)
    return out


def format_symbolic_solution_text(solution: dict, *, defaults: Optional[dict] = None, seq: Optional[int] = None) -> str:
    sol = solution if isinstance(solution, dict) else {}
    norm: Dict[str, object] = {}
    for k, v in sol.items():
        if not isinstance(k, str):
            continue
        norm[k.strip().upper()] = v
    defaults = defaults if isinstance(defaults, dict) else {}
    env_defaults = defaults.get("env_lines") if isinstance(defaults.get("env_lines"), list) else []
    hidden_keys = {"OPCODE_TRACE", "SCRIPT_FILENAME", "LOGIN_COOKIE", "SCRIPT_NAME"}
    def _shell_single_quote(v: str) -> str:
        s = v if isinstance(v, str) else ""
        return "'" + s.replace("'", "'\\''") + "'"

    def _cookie_parts_from_text(text: str) -> List[Tuple[str, Optional[str]]]:
        out: List[Tuple[str, Optional[str]]] = []
        s = (text or "").strip()
        if not s:
            return out
        for raw in re.split(r"[;&]", s):
            part = (raw or "").strip()
            if not part:
                continue
            if "=" in part:
                k, v = part.split("=", 1)
                k2 = (k or "").strip()
                v2 = (v or "").strip()
                if k2:
                    out.append((k2, v2))
                continue
            out.append((part, None))
        return out

    def _cookie_parts_from_obj(obj) -> List[Tuple[str, Optional[str]]]:
        if obj is None:
            return []
        if isinstance(obj, dict):
            out: List[Tuple[str, Optional[str]]] = []
            for k, v in obj.items():
                ks = (k or "").strip() if isinstance(k, str) else ""
                if not ks:
                    continue
                if v is None:
                    out.append((ks, None))
                    continue
                vs = (v if isinstance(v, str) else _stringify_value(v)).strip()
                out.append((ks, None if vs == "" else vs))
            return out
        if isinstance(obj, (list, tuple)):
            out: List[Tuple[str, Optional[str]]] = []
            for it in obj:
                if isinstance(it, dict):
                    out.extend(_cookie_parts_from_obj(it))
                    continue
                if isinstance(it, (list, tuple)) and len(it) >= 2:
                    k = it[0]
                    v = it[1]
                    ks = (k or "").strip() if isinstance(k, str) else ""
                    if not ks:
                        continue
                    if v is None:
                        out.append((ks, None))
                        continue
                    vs = (v if isinstance(v, str) else _stringify_value(v)).strip()
                    out.append((ks, None if vs == "" else vs))
                    continue
                if isinstance(it, str):
                    out.extend(_cookie_parts_from_text(it))
                    continue
            return out
        if isinstance(obj, str):
            return _cookie_parts_from_text(obj)
        return _cookie_parts_from_text(_stringify_value(obj))

    def _cookie_parts_to_text(parts: List[Tuple[str, Optional[str]]]) -> str:
        buf: List[str] = []
        for k, v in parts or []:
            ks = (k or "").strip()
            if not ks:
                continue
            if v is None:
                buf.append(ks)
            else:
                buf.append(f"{ks}={v}")
        return "&".join(buf).strip("&")

    def _normalize_cookie_field(field_obj, *, default_value: str, use_default: bool) -> str:
        if use_default:
            return _cookie_parts_to_text(_cookie_parts_from_text(default_value))
        return _cookie_parts_to_text(_cookie_parts_from_obj(field_obj))

    def _inject_phpsessid(cookie_value: str, session_id: str) -> str:
        parts = _cookie_parts_from_text(cookie_value or "")
        out: List[Tuple[str, Optional[str]]] = [("PHPSESSID", session_id)]
        for k, v in parts:
            if (k or "").strip().upper() == "PHPSESSID":
                continue
            out.append((k, v))
        return _cookie_parts_to_text(out)

    def _stringify_session(v: object) -> str:
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        try:
            return json.dumps(v, ensure_ascii=False)
        except Exception:
            return str(v)

    def _parse_env_pairs(lines: List[str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for raw in lines or []:
            s = (raw or "").strip()
            if not s:
                continue
            k = (s.split("=", 1)[0] or "").strip().upper()
            v = (s.split("=", 1)[1] if "=" in s else "")
            if k:
                out[k] = v
        return out
    if "ENV" in norm:
        llm_env_lines = _normalize_env_lines(norm.get("ENV"), defaults=env_defaults, use_default=False)
        base_lines = _merge_env_lines(env_defaults, llm_env_lines)
        env_map = _parse_env_pairs(base_lines)
        def_map = _parse_env_pairs(env_defaults)
        for hk in hidden_keys:
            if hk in def_map and hk not in env_map:
                base_lines.append(f"{hk}={def_map.get(hk) or ''}")
        env_lines = base_lines
    else:
        env_map = _parse_env_pairs(env_defaults)
        base_lines = list(env_defaults)
        for hk in hidden_keys:
            if hk in env_map and hk not in { (x.split('=',1)[0] or '').strip().upper() for x in base_lines }:
                base_lines.append(f"{hk}={env_map.get(hk) or ''}")
        env_lines = base_lines
    cookie_value = _normalize_cookie_field(
        norm.get("COOKIE"),
        default_value=str(defaults.get("COOKIE") or ""),
        use_default=("COOKIE" not in norm),
    )
    get_value = _normalize_request_field(
        norm.get("GET"),
        default_value=str(defaults.get("GET") or ""),
        use_default=("GET" not in norm),
    )
    post_value = _normalize_request_field(
        norm.get("POST"),
        default_value=str(defaults.get("POST") or ""),
        use_default=("POST" not in norm),
    )
    sess_content = ""
    if "SESSION" in norm and seq is not None:
        sess_content = _stringify_session(norm.get("SESSION")).strip()
        if sess_content:
            session_id = f"sym-preview-{int(seq)}"
            cookie_value = _inject_phpsessid(cookie_value or "", session_id)
    is_url_mode = bool((defaults or {}).get("MODE") == "URL" or (defaults or {}).get("URL"))
    lines: List[str] = []
    if is_url_mode:
        if "ENV" in norm and env_lines:
            lines.extend(env_lines)
        url_value = str((defaults or {}).get("URL") or "").strip()
        url_out = url_value
        if url_value:
            try:
                u = urlsplit(url_value)
                url_out = urlunsplit((u.scheme, u.netloc, u.path, get_value or "", u.fragment))
            except Exception:
                url_out = url_value
        if sess_content and seq is not None:
            lines.append("# SESSION patch will be merged with the captured session and rendered by the downstream PHP helper.")
            lines.append("SESSION_PATCH:" + sess_content)
        cookie_parts = _cookie_parts_from_text(cookie_value or "")
        post_parts = _split_query_pairs(post_value or "")
        cmd_parts = ["curl"]
        for k, v in cookie_parts:
            ks = (k or "").strip()
            if not ks:
                continue
            if v is None:
                cmd_parts.extend(["-b", _shell_single_quote(ks)])
            else:
                cmd_parts.extend(["-b", _shell_single_quote(f"{ks}={v}")])
        for k, v in post_parts:
            ks = (k or "").strip()
            if not ks:
                continue
            cmd_parts.extend(["-d", _shell_single_quote(f"{ks}={v}")])
        if url_out:
            cmd_parts.append(_shell_single_quote(url_out))
        lines.append(" ".join(cmd_parts))
        return "\n".join(lines).rstrip() + "\n"
    if env_lines:
        lines.extend(env_lines)
        lines.append("")
    seed_cmd = (
        "printf '%s\\0%s\\0%s' "
        + _shell_single_quote(cookie_value or "")
        + " "
        + _shell_single_quote(get_value or "")
        + " "
        + _shell_single_quote(post_value or "")
        + " > seed"
    )
    lines.append(seed_cmd)
    if sess_content and seq is not None:
        lines.append("# SESSION patch will be merged with the captured session and rendered by the downstream PHP helper.")
        lines.append("SESSION_PATCH:" + sess_content)
    return "\n".join(lines).rstrip() + "\n"


def write_symbolic_solution_outputs(
    solutions: List[dict],
    *,
    output_root: str,
    seq: Optional[int] = None,
    defaults: Optional[dict] = None,
) -> List[str]:
    if not isinstance(output_root, str) or not output_root.strip():
        return []
    if not solutions:
        return []
    solution_dir = os.path.join(output_root, "solution")
    out_paths: List[str] = []
    ensured = False
    for i, sol in enumerate(solutions or [], 1):
        if not isinstance(sol, dict):
            continue
        if not ensured:
            _ensure_dir(solution_dir)
            ensured = True
        name = f"solution_{int(seq)}_{i}.txt" if seq is not None else f"solution_{i}.txt"
        path = os.path.join(solution_dir, name)
        text = format_symbolic_solution_text(sol, defaults=defaults, seq=seq)
        _write_text(path, text)
        out_paths.append(path)
    return out_paths


def build_symbolic_response_example() -> str:
    lines = []
    lines.append("{")
    lines.append('  "solutions": [')
    lines.append("    {")
    lines.append('      "POST": {')
    lines.append('        "username": "new_admin",')
    lines.append('        "status": "active"')
    lines.append("      },")
    lines.append('      "COOKIE": {')
    lines.append('        "session_id": "updated_session_12345",')
    lines.append('        "user_token": "new_token_abc"')
    lines.append("      }")
    lines.append("    },")
    lines.append("    {")
    lines.append('      "SESSION": {')
    lines.append('        "is_admin": true,')
    lines.append('        "user_id": 1')
    lines.append("      }")
    lines.append("    }")
    lines.append("  ]")
    lines.append("}")
    return "\n".join(lines).rstrip() + "\n"


def write_symbolic_prompt(prompt_text: str, *, run_dir: str, seq: int) -> str:
    prompt_dir = os.path.join(run_dir, "symbolic", "prompts")
    _ensure_dir(prompt_dir)
    path = os.path.join(prompt_dir, f"symbolic_prompt_{int(seq)}.txt")
    _write_text(path, prompt_text)
    return path


def write_symbolic_response(
    text: str,
    *,
    run_dir: str,
    seq: int,
    db_rounds: Optional[List[Dict[str, Any]]] = None,
    solutions_override: Optional[List[dict]] = None,
    extra_payload: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    resp_dir = os.path.join(run_dir, "symbolic", "responses")
    _ensure_dir(resp_dir)
    raw_path = os.path.join(resp_dir, f"symbolic_response_{int(seq)}.txt")
    json_path = os.path.join(resp_dir, f"symbolic_response_{int(seq)}.json")
    raw_text = text if isinstance(text, str) else str(text or "")
    _write_text(raw_path, raw_text)
    payload: Dict[str, Any] = {"raw_response": raw_text}
    if isinstance(solutions_override, list):
        payload["solutions"] = [dict(sol) for sol in solutions_override if isinstance(sol, dict)]
    if isinstance(db_rounds, list) and db_rounds:
        payload["db_rounds"] = db_rounds
    if isinstance(extra_payload, dict) and extra_payload:
        payload.update(extra_payload)
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        fallback_payload = {"raw_response": raw_text}
        if "solutions" in payload:
            fallback_payload["solutions"] = payload.get("solutions") or []
        _write_text(json_path, json.dumps(fallback_payload, ensure_ascii=False, indent=2))
    return raw_path, json_path


def write_symbolic_db_request_artifacts(
    text: str,
    *,
    run_dir: str,
    seq: int,
    db_request: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    resp_dir = os.path.join(run_dir, "symbolic", "responses")
    _ensure_dir(resp_dir)
    raw_path = os.path.join(resp_dir, f"symbolic_response_{int(seq)}_llm_raw.txt")
    json_path = os.path.join(resp_dir, f"symbolic_response_{int(seq)}_db_request.json")
    _write_text(raw_path, text)
    payload = {
        "db_request": dict(db_request or {}),
        "raw_response_text": str(text or ""),
    }
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        _write_text(json_path, "{\n  \"db_request\": {}\n}\n")
    return raw_path, json_path


def _run_db_search_from_symbolic_request(
    *,
    db_request: Dict[str, Any],
    prompt_text: str,
    run_dir: str,
    seq: int,
    logger=None,
) -> Dict[str, Any]:
    try:
        from db_search import build_db_search_request_from_symbolic_prompt, run_db_search_pipeline
    except Exception:
        return {"ok": False, "error": "db_search_import_failed"}

    source = extract_db_search_source_from_prompt_text(prompt_text, target_seq=seq)
    symbolic_objective = extract_symbolic_objective_from_prompt_text(prompt_text, target_seq=seq)
    mode = str(db_request.get("mode") or "").strip()
    reason = str(db_request.get("reason") or "").strip()
    goal = str(db_request.get("goal") or "").strip()
    notes: List[str] = []
    if mode:
        notes.append("llm_db_request_mode=" + mode)
    if goal:
        notes.append("llm_db_request_goal=" + goal)
    if symbolic_objective:
        notes.append("symbolic_objective=" + symbolic_objective.replace("\n", " | "))
    focus = db_request.get("focus")
    if isinstance(focus, list):
        focus_items = [str(x).strip() for x in focus if str(x).strip()]
        if focus_items:
            notes.append("llm_db_request_focus=" + json.dumps(focus_items, ensure_ascii=False))
    else:
        focus_items = []
    notes.append("db_search_primary_objective=flip_target_branch")
    shared_cfg_path = str(os.environ.get("SYMEX_SHARED_CONFIG_PATH") or "").strip()

    req = build_db_search_request_from_symbolic_prompt(
        target_seq=seq,
        target_loc=str(source.get("target_loc") or ""),
        code_slice=str(source.get("code_slice") or ""),
        env_block=str(source.get("env_block") or ""),
        get_block=str(source.get("get_block") or ""),
        post_block=str(source.get("post_block") or ""),
        cookie_block=str(source.get("cookie_block") or ""),
        session_block=str(source.get("session_block") or ""),
        session_data=None,
        trigger_reason=(reason or "llm_requested_database_assistance"),
        symbolic_objective=symbolic_objective,
        db_request_mode=mode,
        db_request_goal=goal,
        db_request_reason=reason,
        db_request_focus=focus_items,
        notes=notes,
        config_path=(shared_cfg_path or None),
        run_dir=os.path.join(run_dir, "db_search"),
    )
    if logger is not None:
        try:
            logger.info(
                "symbolic_db_search_triggered",
                seq=int(seq),
                mode=mode,
                has_goal=bool(goal),
                code_slice_lines=len((str(source.get("code_slice") or "")).splitlines()),
            )
        except Exception:
            pass
    state = run_db_search_pipeline(req)
    final_output = dict(getattr(state, "final_output", {}) or {})
    solutions = final_output.get("solutions") if isinstance(final_output.get("solutions"), list) else []
    external_seed_paths = final_output.get("external_seed_paths") if isinstance(final_output.get("external_seed_paths"), list) else []
    fatal_error = str(getattr(state, "fatal_error", "") or str(final_output.get("error") or "")).strip()
    return {
        "ok": not bool(fatal_error),
        "error": fatal_error,
        "solutions": [dict(x) for x in (solutions or []) if isinstance(x, dict)],
        "external_seed_paths": list(external_seed_paths or []),
        "db_search_run_dir": str(getattr(state, "run_dir", "") or ""),
        "sql_log_paths": list(getattr(state, "sql_log_paths", []) or []),
        "fatal_error_detail": dict(getattr(state, "fatal_error_detail", {}) or {}),
    }


# Summary: Execute a symbolic-execution prompt (or reuse offline outputs) and persist prompt/response artifacts.
def run_symbolic_prompt(
    prompt_text: str,
    *,
    run_dir: str,
    seq: int,
    llm_offline: bool = False,
    logger=None,
) -> dict:
    prompt_path = write_symbolic_prompt(prompt_text, run_dir=run_dir, seq=int(seq))
    failure_dir = os.path.join(run_dir, "symbolic", "failed_responses")
    resp_dir = os.path.join(run_dir, "symbolic", "responses")
    raw_resp_path = os.path.join(resp_dir, f"symbolic_response_{int(seq)}.txt")
    json_resp_path = os.path.join(resp_dir, f"symbolic_response_{int(seq)}.json")

    if llm_offline:
        solutions = []
        if os.path.exists(json_resp_path):
            try:
                obj2 = json.loads(_read_text(json_resp_path))
                solutions = _normalize_solutions(obj2)
            except Exception:
                solutions = []
        return {
            "prompt_path": prompt_path,
            "response_path": raw_resp_path if os.path.exists(raw_resp_path) else "",
            "response_json_path": json_resp_path if os.path.exists(json_resp_path) else "",
            "response_obj": solutions,
            "llm_offline": True,
        }

    client = None
    try:
        client = get_default_client()
    except Exception:
        client = None
    if client is None:
        raise RuntimeError("llm_client_init_failed")

    max_attempts = 3
    try:
        mr = getattr(client, "max_retries", None)
        if mr is not None:
            max_attempts = max(1, int(mr))
    except Exception:
        max_attempts = 3

    async def _call(prompt_for_call: str, call_index: int):
        return await chat_text_with_retries(
            client=client,
            prompt=prompt_for_call,
            system=None,
            temperature=_load_symbolic_llm_temperature(),
            logger=logger,
            max_attempts=max_attempts,
            call_index=int(call_index),
            response_validator=symbolic_response_has_valid_json,
            response_validator_name='symbolic_response_has_valid_json',
        )

    max_db_rounds = 3
    db_rounds: List[Dict[str, Any]] = []
    response_text = ""
    solutions_override: List[dict] = []
    extra_payload: Dict[str, Any] = {}
    call_index = 0
    while True:
        call_index += 1
        prompt_for_call = _build_prompt_with_db_feedback(prompt_text, db_rounds)
        prompt_path_for_call = prompt_path
        if call_index > 1:
            prompt_path_for_call = os.path.join(
                run_dir,
                "symbolic",
                "prompts",
                f"symbolic_prompt_{int(seq)}_db_round_{int(call_index - 1)}.txt",
            )
            _write_text(prompt_path_for_call, prompt_for_call)
        try:
            response_text = _asyncio_run(_call(prompt_for_call, call_index))
        except LLMCallFailure as e:
            write_llm_failure_artifact(
                failure_dir=failure_dir,
                failure_name=f"symbolic_prompt_{int(seq)}_call_{int(call_index)}",
                prompt_path=prompt_path_for_call,
                failure=e,
                extra={
                    "seq": int(seq),
                    "call_index": int(call_index),
                    "db_round_count": int(len(db_rounds)),
                },
            )
            raise
        db_request = _extract_db_request_from_text(response_text)
        if db_request:
            db_request_raw_path, db_request_json_path = write_symbolic_db_request_artifacts(
                response_text,
                run_dir=run_dir,
                seq=int(seq),
                db_request=db_request,
            )
            db_search_result = _run_db_search_from_symbolic_request(
                db_request=db_request,
                prompt_text=prompt_text,
                run_dir=run_dir,
                seq=int(seq),
                logger=logger,
            )
            if logger is not None:
                try:
                    logger.info(
                        "symbolic_db_search_finished",
                        seq=int(seq),
                        ok=bool(db_search_result.get("ok")),
                        solution_count=len(db_search_result.get("solutions") or []),
                        external_seed_count=len(db_search_result.get("external_seed_paths") or []),
                    )
                except Exception:
                    pass
            if bool(db_search_result.get("ok")):
                solutions_override = [dict(x) for x in (db_search_result.get("solutions") or []) if isinstance(x, dict)]
                extra_payload["db_search"] = {
                    "triggered": True,
                    "external_seed_paths": list(db_search_result.get("external_seed_paths") or []),
                    "db_search_run_dir": str(db_search_result.get("db_search_run_dir") or ""),
                    "sql_log_paths": list(db_search_result.get("sql_log_paths") or []),
                    "request": dict(db_request or {}),
                    "llm_raw_response_path": db_request_raw_path,
                    "db_request_artifact_path": db_request_json_path,
                }
            else:
                extra_payload["db_search"] = {
                    "triggered": True,
                    "ok": False,
                    "error": str(db_search_result.get("error") or ""),
                    "fatal_error_detail": dict(db_search_result.get("fatal_error_detail") or {}),
                    "db_search_run_dir": str(db_search_result.get("db_search_run_dir") or ""),
                    "sql_log_paths": list(db_search_result.get("sql_log_paths") or []),
                    "request": dict(db_request or {}),
                    "llm_raw_response_path": db_request_raw_path,
                    "db_request_artifact_path": db_request_json_path,
                }
            break
        db_query = _extract_db_query_from_text(response_text)
        if not db_query:
            break
        if len(db_rounds) >= int(max_db_rounds):
            if logger is not None:
                try:
                    logger.info("symbolic_db_query_limit_reached", seq=int(seq), db_rounds=int(len(db_rounds)))
                except Exception:
                    pass
            break
        db_cfg = load_db_query_config_from_raw(_load_symbolic_db_raw_cfg())
        db_result = execute_database_query(db_query, db_cfg)
        db_rounds.append({"query": db_query, "result": db_result})
        if logger is not None:
            try:
                logger.info(
                    "symbolic_db_query_executed",
                    seq=int(seq),
                    db_round=int(len(db_rounds)),
                    ok=bool((db_result or {}).get("ok")),
                    row_count=int((db_result or {}).get("row_count") or 0),
                )
            except Exception:
                pass
        if is_non_retryable_db_result(db_result):
            if logger is not None:
                try:
                    logger.warning(
                        "symbolic_db_query_non_retryable_stop",
                        seq=int(seq),
                        db_round=int(len(db_rounds)),
                        error=str((db_result or {}).get("error") or ""),
                        error_code=int((db_result or {}).get("error_code") or 0),
                    )
                except Exception:
                    pass
            # Exhaust DB retry budget and stop further LLM/DB follow-up calls.
            while len(db_rounds) < int(max_db_rounds):
                db_rounds.append({"query": "", "result": {"ok": False, "error": "db_round_exhausted", "retryable": False}})
            break

    response_text_for_parse = response_text if isinstance(response_text, str) else str(response_text or "")
    parsed_response_obj = list(solutions_override or []) if solutions_override else parse_symbolic_response(response_text_for_parse)
    if logger is not None:
        try:
            logger.info(
                "symbolic_response_before_write",
                seq=int(seq),
                raw_response_len=len(response_text_for_parse),
                parsed_solution_count=len(parsed_response_obj or []),
                parsed_solution_keys=[sorted([str(k) for k in sol.keys()]) for sol in (parsed_response_obj or []) if isinstance(sol, dict)],
                has_db_search=bool(extra_payload.get("db_search")) if isinstance(extra_payload, dict) else False,
                used_solutions_override=bool(solutions_override),
                db_round_count=len(db_rounds or []),
            )
        except Exception:
            pass
    raw_path, json_path = write_symbolic_response(
        response_text,
        run_dir=run_dir,
        seq=int(seq),
        db_rounds=db_rounds,
        solutions_override=solutions_override,
        extra_payload=extra_payload,
    )
    resp_obj = list(parsed_response_obj or [])
    json_solutions_count = -1
    json_solutions_keys = []
    try:
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8", errors="replace") as f:
                obj = json.load(f)
            if isinstance(obj, dict) and isinstance(obj.get("solutions"), list):
                json_solutions_count = len(obj.get("solutions") or [])
                json_solutions_keys = [sorted([str(k) for k in sol.keys()]) for sol in (obj.get("solutions") or []) if isinstance(sol, dict)]
    except Exception:
        resp_obj = resp_obj
    if logger is not None:
        try:
            logger.info(
                "symbolic_response_after_write",
                seq=int(seq),
                raw_path=str(raw_path or ""),
                json_path=str(json_path or ""),
                raw_exists=bool(raw_path and os.path.exists(raw_path)),
                json_exists=bool(json_path and os.path.exists(json_path)),
                final_response_obj_count=len(resp_obj or []),
                final_response_obj_keys=[sorted([str(k) for k in sol.keys()]) for sol in (resp_obj or []) if isinstance(sol, dict)],
                json_solutions_count=int(json_solutions_count),
                json_solutions_keys=json_solutions_keys,
            )
        except Exception:
            pass
    out = {
        "prompt_path": prompt_path,
        "response_path": raw_path,
        "response_json_path": json_path,
        "response_obj": resp_obj,
        "db_rounds": db_rounds,
        "llm_offline": False,
    }
    if isinstance(extra_payload.get("db_search"), dict):
        out["db_search"] = dict(extra_payload.get("db_search") or {})
        out["external_seed_paths"] = list((extra_payload.get("db_search") or {}).get("external_seed_paths") or [])
    return out
