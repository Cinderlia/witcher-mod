"""
Helpers for building LLM prompts and translating trace locations into code blocks.

This module provides:
- Prompt template rendering for taint expansion
- Trace-index based selection of representative seqs for `(path,line)` locations
- Conversion of scope locations into `seq + source_line` code blocks
"""

from string import Template
from typing import Any, Dict, List, Optional, Set, Tuple
import json
import os
import re

from common.app_config import append_app_name_to_prompt, load_symex_app_config, load_symbolic_seed_kind_flags
from utils.extractors.if_extract import norm_trace_path

DEFAULT_SESSION_CAPTURE_PATH = os.path.join("input", "session_capture.json")
DEFAULT_TEST_COMMAND_PATH = os.path.join("input", "test_command.txt")
DEFAULT_URL_PATH = os.path.join("input", "url.txt")
MAX_VISIBLE_INPUT_VALUE_LEN = 32
HIDDEN_VALUE_PLACEHOLDER = "<HIDDEN>"
INPUT_VALUE_MASK_NOTICE = "注意：部分参数值长度超过32个字符，已隐藏具体值，仅保留参数键。"
_SYMEX_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def render_template(template: str, **kwargs: Any) -> str:
    """Render a string.Template using `safe_substitute`."""
    return Template(template).safe_substitute(**kwargs)


def resolve_prompt_input_path(path: str) -> str:
    p = (path or '').strip()
    if p and os.path.exists(p):
        return p
    fallback = os.path.join(_SYMEX_ROOT, p) if p else ""
    if fallback and os.path.exists(fallback):
        return fallback
    return p or fallback


def read_text_file(path: str) -> str:
    if not isinstance(path, str) or not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def build_session_capture_fallback_path_from_input_dir(input_dir: str) -> str:
    base_dir = str(input_dir or "").strip()
    if not base_dir:
        return ""
    try:
        import hashlib

        key = hashlib.sha1(base_dir.encode("utf-8", errors="replace")).hexdigest()
    except Exception:
        return ""
    return os.path.join("/tmp", "wc_session_trace", key + ".json")


def iter_session_capture_candidate_paths(path: str = DEFAULT_SESSION_CAPTURE_PATH) -> List[str]:
    resolved = resolve_prompt_input_path(path)
    raw = (path or "").strip()
    candidates: List[str] = []
    if resolved:
        candidates.append(resolved)
        try:
            input_dir = os.path.dirname(os.path.abspath(resolved))
            fallback = build_session_capture_fallback_path_from_input_dir(input_dir)
            if fallback:
                candidates.append(fallback)
        except Exception:
            pass
    if raw and raw != resolved:
        raw_abs = os.path.abspath(raw)
        candidates.append(raw_abs)
        try:
            input_dir = os.path.dirname(raw_abs)
            fallback = build_session_capture_fallback_path_from_input_dir(input_dir)
            if fallback:
                candidates.append(fallback)
        except Exception:
            pass
    seen = set()
    out: List[str] = []
    for item in candidates:
        cand = str(item or "").strip()
        if not cand:
            continue
        norm = os.path.abspath(cand) if not cand.startswith("/tmp/") else cand
        if norm in seen:
            continue
        seen.add(norm)
        out.append(cand)
    return out


def read_json_obj(path: str) -> Dict[str, Any]:
    if not isinstance(path, str) or not path:
        return {}
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def load_session_capture(path: str = DEFAULT_SESSION_CAPTURE_PATH) -> Dict[str, Any]:
    for cand in iter_session_capture_candidate_paths(path):
        obj = read_json_obj(cand)
        if obj:
            return obj
    return {}


def hide_long_value(value: object) -> str:
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    return s if len(s) <= MAX_VISIBLE_INPUT_VALUE_LEN else HIDDEN_VALUE_PLACEHOLDER


def mask_env_lines(env_lines: List[str]) -> List[str]:
    out: List[str] = []
    for raw in env_lines or []:
        line = (raw or "").strip()
        if not line:
            continue
        if "=" not in line:
            out.append(line)
            continue
        key, value = line.split("=", 1)
        out.append(f"{key}={hide_long_value(value)}")
    return out


def mask_query_like_text(text: str, *, separators: str) -> str:
    s = (text or "").strip()
    if not s:
        return ""
    parts = re.split(f"([{re.escape(separators)}])", s)
    out: List[str] = []
    for part in parts:
        if part == "":
            continue
        if len(part) == 1 and part in separators:
            out.append(part)
            continue
        raw = part
        core = raw.strip()
        if "=" not in core:
            out.append(raw)
            continue
        key, value = core.split("=", 1)
        prefix_len = len(raw) - len(raw.lstrip())
        suffix_len = len(raw) - len(raw.rstrip())
        prefix = raw[:prefix_len] if prefix_len > 0 else ""
        suffix = raw[len(raw) - suffix_len:] if suffix_len > 0 else ""
        out.append(f"{prefix}{key}={hide_long_value(value)}{suffix}")
    return "".join(out)


def mask_request_fields(req_fields: Dict[str, str]) -> Dict[str, str]:
    out = dict(req_fields or {})
    out["COOKIE"] = mask_query_like_text(str(out.get("COOKIE") or ""), separators=";&")
    out["GET"] = mask_query_like_text(str(out.get("GET") or ""), separators="&;")
    out["POST"] = mask_query_like_text(str(out.get("POST") or ""), separators="&;")
    return out


def extract_test_command_fields(test_command_text: str) -> Tuple[List[str], Dict[str, str]]:
    env_lines: List[str] = []
    cookie_value = ""
    get_value = ""
    post_value = ""
    seed_value = ""
    if not isinstance(test_command_text, str) or not test_command_text.strip():
        return env_lines, {"COOKIE": cookie_value, "GET": get_value, "POST": post_value, "SEED": seed_value}
    for raw in (test_command_text.splitlines() or []):
        line = (raw or "").strip()
        if not line:
            continue
        if line.startswith("export "):
            rest = (line[len("export "):] or "").strip()
            if rest:
                env_lines.append(rest)
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
        if line.startswith("seed:"):
            seed_value = (line.split("seed:", 1)[1] or "").strip()
            continue
        if "seed:" in line:
            seed_value = (line.split("seed:", 1)[1] or "").strip()
            continue
    return env_lines, {"COOKIE": cookie_value, "GET": get_value, "POST": post_value, "SEED": seed_value}


def extract_url_fields(url_text: str) -> Dict[str, str]:
    url_value = ""
    cookie_value = ""
    get_value = ""
    post_value = ""
    if not isinstance(url_text, str) or not url_text.strip():
        return {"URL": url_value, "COOKIE": cookie_value, "GET": get_value, "POST": post_value}
    for raw in url_text.splitlines() or []:
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
        m_url = re.search(r"(https?://[^\s\"']+)", url_text or "")
        if m_url:
            url_value = (m_url.group(1) or "").strip()
    if url_value and not get_value:
        try:
            qs = urlsplit(url_value).query or ""
            if qs:
                pairs = parse_qsl(qs, keep_blank_values=True)
                get_value = "&".join([f"{k}={v}" for k, v in pairs]).strip()
        except Exception:
            pass
    return {"URL": url_value, "COOKIE": cookie_value, "GET": get_value, "POST": post_value}


def split_env_lines(env_lines: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in env_lines or []:
        line = (raw or "").strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key_s = (key or "").strip()
        if not key_s:
            continue
        value_s = (value or "").strip()
        if len(value_s) >= 2 and value_s[:1] == value_s[-1:] and value_s[:1] in ("'", '"'):
            value_s = value_s[1:-1]
        out[key_s] = value_s
    return out


def filter_env_lines(env_lines: List[str], *, hidden_keys: Set[str]) -> List[str]:
    hidden = {str(x).strip().upper() for x in (hidden_keys or set()) if str(x).strip()}
    out: List[str] = []
    for raw in env_lines or []:
        line = (raw or "").strip()
        if not line:
            continue
        if line.lower().startswith("export "):
            line = (line[len("export "):] or "").strip()
        key = (line.split("=", 1)[0] or "").strip().upper()
        if key and key in hidden:
            continue
        out.append(line)
    return out


def flatten_session_vars(value: Any, *, prefix: str = "") -> List[str]:
    if isinstance(value, dict):
        out: List[str] = []
        for key, child in value.items():
            key_s = str(key)
            child_prefix = f"{prefix}.{key_s}" if prefix else key_s
            out.extend(flatten_session_vars(child, prefix=child_prefix))
        return out
    if isinstance(value, list):
        out: List[str] = []
        for idx, child in enumerate(value):
            child_prefix = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            out.extend(flatten_session_vars(child, prefix=child_prefix))
        return out
    label = prefix or "session"
    return [f"{label}={hide_long_value(value)}"]


def build_session_display(session_capture: Dict[str, Any]) -> str:
    if not isinstance(session_capture, dict) or not session_capture:
        return ""
    session_vars = session_capture.get("session_vars")
    lines = flatten_session_vars(session_vars, prefix="") if isinstance(session_vars, (dict, list)) else []
    if lines:
        return "\n".join(lines).strip()
    session_text = str(session_capture.get("session_text") or "").strip()
    if not session_text:
        return ""
    return "session_raw=" + hide_long_value(session_text)


def build_env_block(env: dict, *, mask_long_values: bool = False) -> str:
    if not isinstance(env, dict):
        return ""
    lines = []
    for k, v in env.items():
        if k is None:
            continue
        key = str(k).strip()
        if not key:
            continue
        val = "" if v is None else str(v)
        if mask_long_values:
            val = hide_long_value(val)
        lines.append(f"{key}={val}")
    return "\n".join(lines).strip()


def build_headers_block(headers: dict, *, mask_long_values: bool = False) -> str:
    if not isinstance(headers, dict):
        return ""
    lines = []
    for k, v in headers.items():
        if k is None:
            continue
        key = str(k).strip()
        if not key:
            continue
        val = "" if v is None else str(v)
        if mask_long_values:
            val = hide_long_value(val)
        lines.append(f"{key}: {val}")
    return "\n".join(lines).strip()


def collect_prompt_input_blocks(
    *,
    test_command_path: str = DEFAULT_TEST_COMMAND_PATH,
    url_path: str = DEFAULT_URL_PATH,
    session_capture_path: str = DEFAULT_SESSION_CAPTURE_PATH,
    hidden_env_keys: Optional[Set[str]] = None,
    base_inputs: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    resolved_test_command_path = resolve_prompt_input_path(test_command_path)
    resolved_url_path = resolve_prompt_input_path(url_path)
    env_lines: List[str] = []
    req_inputs: Dict[str, str] = {}
    if resolved_test_command_path and os.path.exists(resolved_test_command_path):
        env_lines, req_inputs = extract_test_command_fields(read_text_file(resolved_test_command_path))
    elif resolved_url_path and os.path.exists(resolved_url_path):
        req_inputs = extract_url_fields(read_text_file(resolved_url_path))
    filtered_env_lines = filter_env_lines(env_lines, hidden_keys=hidden_env_keys or set())
    env_block = "\n".join(mask_env_lines(filtered_env_lines)).strip()
    header_block = ""
    masked_req_inputs = mask_request_fields(req_inputs)
    cookie_block = masked_req_inputs.get("COOKIE") or ""
    get_block = masked_req_inputs.get("GET") or ""
    post_block = masked_req_inputs.get("POST") or ""
    seed_block = (req_inputs.get("SEED") or "").strip()
    if isinstance(base_inputs, dict):
        env_block = build_env_block(base_inputs.get("ENV") or {}, mask_long_values=True) or env_block
        header_block = build_headers_block(base_inputs.get("HEADERS") or {}, mask_long_values=True)
        merged_inputs = mask_request_fields({
            "COOKIE": base_inputs.get("COOKIE") or req_inputs.get("COOKIE") or "",
            "GET": base_inputs.get("GET") or req_inputs.get("GET") or "",
            "POST": base_inputs.get("POST") or req_inputs.get("POST") or "",
            "SEED": base_inputs.get("SEED") or req_inputs.get("SEED") or "",
        })
        cookie_block = merged_inputs.get("COOKIE") or ""
        get_block = merged_inputs.get("GET") or ""
        post_block = merged_inputs.get("POST") or ""
        seed_block = str(base_inputs.get("SEED") or req_inputs.get("SEED") or "").strip()
        if not env_block and env_lines:
            env_block = build_env_block(split_env_lines(filtered_env_lines), mask_long_values=True)
    session_block = build_session_display(load_session_capture(session_capture_path))
    return {
        "env_block": env_block,
        "header_block": header_block,
        "cookie_block": cookie_block,
        "get_block": get_block,
        "post_block": post_block,
        "seed_block": seed_block,
        "session_block": session_block,
    }


def append_standard_input_sections(
    lines: List[str],
    *,
    env_block: str,
    cookie_block: str,
    get_block: str,
    post_block: str,
    session_block: str,
    seed_block: str,
    input_value_mask_notice: str = INPUT_VALUE_MASK_NOTICE,
) -> None:
    flags = load_symbolic_seed_kind_flags()
    lines.append("本次执行的环境变量是：")
    if env_block:
        lines.append(env_block)
    lines.append("")
    lines.append("本次执行的输入是：")
    lines.append(input_value_mask_notice)
    lines.append("COOKIE:" + str(cookie_block or ""))
    lines.append("GET:" + str(get_block or ""))
    lines.append("POST:" + str(post_block or ""))
    lines.append("")
    lines.append("SESSION:")
    if session_block:
        lines.append(session_block)
    if seed_block and (not cookie_block and not get_block and not post_block):
        lines.append("SEED:")
        lines.append(seed_block)
    disabled = [key for key in ("POST", "GET", "COOKIE", "SESSION", "ENV", "SQL", "FILE") if not bool(flags.get(key, True))]
    if disabled:
        lines.append("")
        lines.append("额外约束：以下类型已在 symex_config.json 中被禁用，禁止修改，也不要在 solutions 中输出这些字段：" + ", ".join(disabled))
    lines.append("")


def append_http_input_sections(
    lines: List[str],
    *,
    env_block: str,
    header_block: str,
    cookie_block: str,
    get_block: str,
    post_block: str,
    session_block: str,
    seed_block: str,
    input_value_mask_notice: str = INPUT_VALUE_MASK_NOTICE,
) -> None:
    lines.append("本次执行的环境变量是：")
    lines.append(input_value_mask_notice)
    if env_block:
        lines.append(env_block)
    if header_block:
        lines.append("")
        lines.append("本次执行的HTTP HEADER是：")
        lines.append(header_block)
    if cookie_block or get_block or post_block:
        lines.append("")
        lines.append("本次执行的HTTP输入是：")
        if cookie_block:
            lines.append("COOKIE:" + str(cookie_block or ""))
        if get_block:
            lines.append("GET:" + str(get_block or ""))
        if post_block:
            lines.append("POST:" + str(post_block or ""))
    if session_block:
        lines.append("")
        lines.append("本次执行的SESSION是：")
        lines.append(session_block)
    if seed_block:
        lines.append("")
        lines.append("本次Fuzz用到的种子文件是：")
        lines.append(seed_block)
    lines.append("")

_DEFAULT_LLM_TAINT_TEMPLATE_TAIL = (
    "，并以json格式输出变量名、变量类型和所在行的id（id就是每行开头的seq）。\n"
    "type字段仅为猜测，尽量基于字面形式判断类型。\n"
    "仅允许输出以下类型：AST_VAR、AST_PROP、AST_DIM、AST_METHOD_CALL、AST_STATIC_CALL、AST_CALL。\n"
    "必须列出所有能够影响到{name}取值的变量和函数调用，不管是直接影响还是间接地影响。\n"
    "还可能通过中间变量间接影响：A = B; {name} = A;\n"
    "如果是通过中间变量间接影响，请把中间变量放入intermediates，同时把最终影响{name}的所有因素放入taints。\n"
    "如果没有找到新的影响因素，仍然必须输出合法json，确保字段存在。\n"
    "必须输出合法的json格式，只输出json，不要输出任何解释性文字或Markdown。\n\n"
    "代码（每行格式为：seq + 源码行）：\n"
    "{result_set}\n\n"
    "输出json格式必须为：\n"
    "{\"taints\":[{\"seq\":51529,\"type\":\"AST_VAR\",\"name\":\"negate\"}],\"intermediates\":[{\"seq\":51573,\"type\":\"AST_VAR\",\"name\":\"ret\"}]}\n"
    "如果找不到新污点，输出：\n"
    "{\"taints\":[],\"intermediates\":[]}\n"
)

DEFAULT_LLM_TAINT_TEMPLATE_VAR = (
    "你是一个代码分析助手,请你找出下列代码中"
    "所有的有可能影响到{type}变量{name}取值的变量和函数调用"
    + _DEFAULT_LLM_TAINT_TEMPLATE_TAIL
)

DEFAULT_LLM_TAINT_TEMPLATE_FUNC = (
    "你是一个代码分析助手,请你找出下列代码中"
    "所有的有可能影响到{type}函数{name}的返回值的变量和函数调用"
    + _DEFAULT_LLM_TAINT_TEMPLATE_TAIL
)

DEFAULT_LLM_TAINT_TEMPLATE = DEFAULT_LLM_TAINT_TEMPLATE_VAR

def _name_with_this_alias(tt: str, name: str) -> str:
    t = (tt or '').strip()
    v = (name or '').strip()
    if not v or '或者' in v:
        return v
    if t not in ('AST_PROP', 'AST_METHOD_CALL'):
        return v
    if v.startswith('this->') or v.startswith('$this->'):
        return v
    if '->' not in v:
        return v
    tail = (v.split('->', 1)[1] or '').strip()
    if not tail:
        return v
    alt = f'this->{tail}'
    if alt == v:
        return v
    return f'{v}或者{alt}'

def render_llm_taint_prompt(*, template: str, taint_type: str, taint_name: str, result_set: str) -> str:
    """Render the final prompt text for a given taint and its scoped code block."""
    tt = (taint_type or '').strip()
    use_default = (template is None) or (template in (DEFAULT_LLM_TAINT_TEMPLATE, DEFAULT_LLM_TAINT_TEMPLATE_VAR, DEFAULT_LLM_TAINT_TEMPLATE_FUNC))
    if use_default:
        t = DEFAULT_LLM_TAINT_TEMPLATE_FUNC if tt in ('AST_METHOD_CALL', 'AST_CALL') else DEFAULT_LLM_TAINT_TEMPLATE_VAR
    else:
        t = template
    if tt == 'AST_PROP':
        t += (
            "\n注意：代码块中可能包含展开的函数scope，范围用FUNCTION_SCOPE_START和FUNCTION_SCOPE_END标记。"
            "\n在类方法的函数scope内，this指代当前对象本身：this->x 等价于 对象->x。"
        )
    name_for_prompt = _name_with_this_alias(tt, taint_name)
    prompt = (
        (t.replace('{type}', str(taint_type or ''))
          .replace('{name}', str(name_for_prompt or ''))
          .replace('{result_set}', str(result_set or '')))
    )
    try:
        return append_app_name_to_prompt(prompt, load_symex_app_config())
    except Exception:
        return append_app_name_to_prompt(prompt, {})


def _strip_app_prefix(p: str) -> str:
    """Strip leading `/app/` or `/` to match project-relative paths."""
    p = (p or '').strip()
    if p.startswith('/app/'):
        return p[5:]
    if p.startswith('/'):
        return p[1:]
    return p


def _parse_loc(loc: str):
    """Parse a `path:line` locator into `(normalized_path, line)`."""
    if not loc or ':' not in loc:
        return None
    p, ln_s = loc.rsplit(':', 1)
    try:
        ln = int(ln_s)
    except:
        return None
    p = _strip_app_prefix(p).replace('\\', '/')
    return p, ln


def _load_trace_index_min_seqs(trace_index_path: str):
    """Load `(path,line)->min_seq` mapping from a `trace_index.json` file."""
    if not trace_index_path:
        return {}
    if not os.path.exists(trace_index_path):
        return {}
    with open(trace_index_path, 'r', encoding='utf-8', errors='replace') as f:
        try:
            obj = json.load(f)
        except Exception:
            return {}
    recs = obj.get('records') if isinstance(obj, dict) else obj
    if not isinstance(recs, list):
        return {}
    out = {}
    for r in recs:
        if not isinstance(r, dict):
            continue
        p = r.get('path')
        ln = r.get('line')
        if not p or ln is None:
            continue
        seqs = r.get('seqs') or []
        if not seqs:
            continue
        try:
            seq_min = min(int(x) for x in seqs)
        except:
            continue
        try:
            k = (norm_trace_path(str(p)), int(ln))
        except Exception:
            continue
        cur = out.get(k)
        if cur is None or seq_min < cur:
            out[k] = seq_min
    return out


def _load_trace_index_path_case_map(trace_index_path: str):
    if not trace_index_path:
        return {}
    if not os.path.exists(trace_index_path):
        return {}
    with open(trace_index_path, 'r', encoding='utf-8', errors='replace') as f:
        try:
            obj = json.load(f)
        except Exception:
            return {}
    recs = obj.get('records') if isinstance(obj, dict) else obj
    if not isinstance(recs, list):
        return {}
    out = {}
    for r in recs:
        if not isinstance(r, dict):
            continue
        p = r.get('path')
        ln = r.get('line')
        if not p or ln is None:
            continue
        try:
            out[(norm_trace_path(str(p)), int(ln))] = str(p)
        except Exception:
            continue
    return out


def resolve_source_path(scope_root: str, src_path: str, windows_root: str = r'D:\files\witcher\app') -> str:
    """Resolve a source path from trace/CPG to a local filesystem path."""
    scope_root = (scope_root or '').strip()
    src_path = (src_path or '').strip()
    src_path = src_path.replace('\\', '/')
    if os.name == 'nt' and scope_root.startswith('/app'):
        suffix = scope_root[4:]
        suffix = _strip_app_prefix(suffix).replace('/', os.sep)
        scope_root = os.path.join(windows_root, suffix) if suffix else windows_root
    if os.name == 'nt' and src_path.startswith('/app/'):
        src_path = _strip_app_prefix(src_path)
    if src_path.startswith('/'):
        return src_path
    return os.path.join(scope_root, src_path.replace('/', os.sep))


def build_seqs_by_loc(trace_index_records):
    """Build `(path,line)->sorted unique seqs` mapping from trace index records."""
    out = {}
    for rec in trace_index_records or []:
        if not isinstance(rec, dict):
            continue
        p = rec.get('path')
        ln = rec.get('line')
        if not p or ln is None:
            continue
        try:
            k = (norm_trace_path(str(p)), int(ln))
        except Exception:
            continue
        buf = out.get(k)
        if buf is None:
            buf = []
            out[k] = buf
        for s in rec.get('seqs') or []:
            try:
                buf.append(int(s))
            except Exception:
                continue
    for k, buf in list(out.items()):
        if not buf:
            out.pop(k, None)
            continue
        buf.sort()
        uniq = []
        last = None
        for x in buf:
            if last is None or x != last:
                uniq.append(x)
                last = x
        out[k] = uniq
    return out


def build_seq_groups_by_loc(trace_index_records):
    """Build `(path,line)->seq groups` where each group is a contiguous trace record."""
    out = {}
    for rec in trace_index_records or []:
        if not isinstance(rec, dict):
            continue
        p = rec.get('path')
        ln = rec.get('line')
        if not p or ln is None:
            continue
        try:
            k = (norm_trace_path(str(p)), int(ln))
        except Exception:
            continue
        seqs = []
        for s in rec.get('seqs') or []:
            try:
                seqs.append(int(s))
            except Exception:
                continue
        if not seqs:
            continue
        seqs.sort()
        groups = out.get(k)
        if groups is None:
            groups = []
            out[k] = groups
        groups.append({'min': int(seqs[0]), 'max': int(seqs[-1]), 'seqs': seqs})
    for k, groups in list(out.items()):
        if not groups:
            out.pop(k, None)
            continue
        groups.sort(key=lambda g: (int(g.get('min') or 0), int(g.get('max') or 0)))
        out[k] = groups
    return out


def pick_seq_by_ref(groups, ref_seq: Optional[int], prefer: str = 'forward'):
    """Pick a representative seq from grouped seq ranges given a reference seq."""
    if not groups:
        return None
    if ref_seq is None:
        g0 = groups[0]
        return int(g0.get('min')) if g0 else None
    try:
        r = int(ref_seq)
    except Exception:
        g0 = groups[0]
        return int(g0.get('min')) if g0 else None
    if (prefer or '').strip() == 'backward':
        picked = None
        for g in groups:
            try:
                gmin = int(g.get('min'))
            except Exception:
                continue
            if gmin <= r:
                picked = g
                continue
            break
        return int(picked.get('min')) if picked else None
    for g in groups:
        try:
            gmin = int(g.get('min'))
        except Exception:
            continue
        if gmin >= r:
            return int(gmin)
    return None


def loc_to_path_line(loc):
    """Normalize a locator (dict or string) to `(path,line)` or return None."""
    if isinstance(loc, dict):
        p = loc.get('path')
        ln = loc.get('line')
        if p and ln is not None:
            try:
                return norm_trace_path(str(p)), int(ln)
            except Exception:
                pass
        loc2 = loc.get('loc')
        if isinstance(loc2, str) and loc2:
            pr = _parse_loc(loc2)
            if pr:
                return norm_trace_path(pr[0]), int(pr[1])
        return None
    if isinstance(loc, str):
        pr = _parse_loc(loc)
        if pr:
            return norm_trace_path(pr[0]), int(pr[1])
        return None
    return None


def ensure_seqs_by_loc(ctx):
    """Cache and return `(path,line)->seqs` mapping inside ctx."""
    if not isinstance(ctx, dict):
        return {}
    seqs_by_loc = ctx.get('_seqs_by_loc')
    if seqs_by_loc is None:
        seqs_by_loc = build_seqs_by_loc(ctx.get('trace_index_records') or [])
        ctx['_seqs_by_loc'] = seqs_by_loc
    return seqs_by_loc


def ensure_seq_groups_by_loc(ctx):
    """Cache and return `(path,line)->seq groups` mapping inside ctx."""
    if not isinstance(ctx, dict):
        return {}
    groups_by_loc = ctx.get('_seq_groups_by_loc')
    if groups_by_loc is None:
        groups_by_loc = build_seq_groups_by_loc(ctx.get('trace_index_records') or [])
        ctx['_seq_groups_by_loc'] = groups_by_loc
    return groups_by_loc


def _filter_prompt_locs(locs, ctx):
    if not locs or not isinstance(ctx, dict):
        return list(locs or [])
    try:
        from taint_handlers.handlers.helpers.ast_var_include import (
            _filter_define_locs_from_include,
            _filter_func_def_locs_from_include,
        )
    except Exception:
        return list(locs or [])
    recs = ctx.get('trace_index_records') or []
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    parent_of = ctx.get('parent_of') or {}
    def _loc_key(x):
        if not x:
            return None
        if isinstance(x, dict):
            lk = (x.get('loc') or '').strip()
            if lk:
                return lk
            p = (x.get('path') or '').strip()
            ln = x.get('line')
            if p and ln is not None:
                try:
                    return f"{p}:{int(ln)}"
                except Exception:
                    return None
            return None
        if isinstance(x, str):
            return x
        return None
    loc_keys = []
    for x in locs or []:
        k = _loc_key(x)
        if k:
            loc_keys.append(k)
    if not loc_keys:
        return list(locs or [])
    loc_keys = _filter_func_def_locs_from_include(list(loc_keys), recs, nodes, ctx)
    loc_keys = _filter_define_locs_from_include(list(loc_keys), recs, nodes, children_of, parent_of, ctx)
    keep = set(loc_keys)
    if not keep:
        return []
    out = []
    for x in locs or []:
        k = _loc_key(x)
        if k and k in keep:
            out.append(x)
    return out


def locs_to_seq_code_block(locs, ctx, *, prefer: str = 'forward'):
    """Convert a list of locators into a sorted `seq + source_line` code block string."""
    scope_root = (ctx.get('scope_root') if isinstance(ctx, dict) else None) or '/app'
    windows_root = (ctx.get('windows_root') if isinstance(ctx, dict) else None) or r'D:\files\witcher\app'
    ref_seq = (ctx.get('_llm_ref_seq') if isinstance(ctx, dict) else None)
    if ref_seq is None and isinstance(ctx, dict):
        ref_seq = ctx.get('input_seq')
    groups_by_loc = ensure_seq_groups_by_loc(ctx)
    preamble_locs = (ctx.get('_llm_scope_preamble_locs') if isinstance(ctx, dict) else None) or []
    preamble_locs = _filter_prompt_locs(preamble_locs, ctx)
    locs = _filter_prompt_locs(locs, ctx)
    starts = set()
    ends = set()
    if isinstance(ctx, dict):
        for m in ctx.get('_llm_scope_markers') or []:
            if not isinstance(m, dict):
                continue
            if (m.get('kind') or '').strip() != 'function_scope':
                continue
            st = m.get('start')
            ed = m.get('end')
            if isinstance(st, str) and st:
                starts.add(st)
            if isinstance(ed, str) and ed:
                ends.add(ed)

    preamble_set = set()
    preamble_lines = []
    pj = 0
    for loc in preamble_locs or []:
        if not loc:
            continue
        loc_key = loc.get('loc') if isinstance(loc, dict) else loc
        if not loc_key:
            pr = loc_to_path_line(loc)
            if pr:
                p0, ln0 = pr
                loc_key = f"{p0}:{int(ln0)}"
        if not loc_key or loc_key in preamble_set:
            continue
        pr = loc_to_path_line(loc)
        if not pr:
            continue
        p, ln = pr
        seq = None
        if isinstance(loc, dict) and loc.get('seq') is not None:
            try:
                seq = int(loc.get('seq'))
            except Exception:
                seq = None
        if seq is None:
            seq = pick_seq_by_ref(groups_by_loc.get((p, int(ln))) or [], ref_seq, prefer=prefer)
        if seq is None:
            continue
        fs = resolve_source_path(scope_root, p, windows_root=windows_root)
        code = ''
        try:
            with open(fs, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f, start=1):
                    if i == int(ln):
                        code = line.strip()
                        break
        except Exception:
            code = ''
        if not code:
            continue
        if loc_key in starts:
            preamble_lines.append((int(seq), 0, pj, f"{seq} // FUNCTION_SCOPE_START"))
            pj += 1
        preamble_lines.append((int(seq), 1, pj, f"{seq} {code}"))
        pj += 1
        if loc_key in ends:
            preamble_lines.append((int(seq), 2, pj, f"{seq} // FUNCTION_SCOPE_END"))
            pj += 1
        preamble_set.add(loc_key)
    preamble_lines.sort(key=lambda x: (x[0], x[1], x[2]))
    preamble_out = [s for _, _, _, s in preamble_lines]

    out_lines = []
    j = 0
    seen_loc = set()
    for loc in locs or []:
        if not loc:
            continue
        loc_key = loc.get('loc') if isinstance(loc, dict) else loc
        if not loc_key:
            pr = loc_to_path_line(loc)
            if pr:
                p0, ln0 = pr
                loc_key = f"{p0}:{int(ln0)}"
        if not loc_key or loc_key in preamble_set or loc_key in seen_loc:
            continue
        seen_loc.add(loc_key)
        pr = loc_to_path_line(loc)
        if not pr:
            continue
        p, ln = pr
        seq = None
        if isinstance(loc, dict) and loc.get('seq') is not None:
            try:
                seq = int(loc.get('seq'))
            except Exception:
                seq = None
        if seq is None:
            seq = pick_seq_by_ref(groups_by_loc.get((p, int(ln))) or [], ref_seq, prefer=prefer)
        if seq is None:
            continue
        fs = resolve_source_path(scope_root, p, windows_root=windows_root)
        code = ''
        try:
            with open(fs, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f, start=1):
                    if i == int(ln):
                        code = line.strip()
                        break
        except Exception:
            code = ''
        if not code:
            continue
        if loc_key in starts:
            out_lines.append((int(seq), 0, j, f"{seq} // FUNCTION_SCOPE_START"))
            j += 1
        out_lines.append((int(seq), 1, j, f"{seq} {code}"))
        j += 1
        if loc_key in ends:
            out_lines.append((int(seq), 2, j, f"{seq} // FUNCTION_SCOPE_END"))
            j += 1
    out_lines.sort(key=lambda x: (x[0], x[1], x[2]))
    rest = [s for _, _, _, s in out_lines]
    if preamble_out and rest:
        return '\n'.join(list(preamble_out) + [''] + rest)
    if preamble_out:
        return '\n'.join(preamble_out)
    return '\n'.join(rest)


def locs_to_scope_seqs(locs, ctx, *, ref_seq: Optional[int], prefer: str = 'forward'):
    """Convert locators into a sorted unique list of representative seqs."""
    groups_by_loc = ensure_seq_groups_by_loc(ctx)
    out = []
    seen = set()
    for loc in locs or []:
        if isinstance(loc, dict) and loc.get('seq') is not None:
            try:
                seq = int(loc.get('seq'))
            except Exception:
                seq = None
            if seq is None:
                continue
            if seq in seen:
                continue
            seen.add(seq)
            out.append(int(seq))
            continue
        pr = loc_to_path_line(loc)
        if not pr:
            continue
        p, ln = pr
        seq = pick_seq_by_ref(groups_by_loc.get((p, int(ln))) or [], ref_seq, prefer=prefer)
        if seq is None:
            continue
        if seq in seen:
            continue
        seen.add(seq)
        out.append(int(seq))
    out.sort()
    return out


# Summary: Dedupe LLM scope requests by skipping scopes already covered by prior calls.
def should_skip_llm_scope(scope_seqs, ctx, *, dedupe_key: Optional[str] = None) -> bool:
    """Return True if a given scope has already been processed for LLM calls."""
    if not isinstance(ctx, dict):
        return False
    lg = ctx.get('logger')
    cur = []
    for x in scope_seqs or []:
        try:
            cur.append(int(x))
        except Exception:
            continue
    if not cur:
        if lg is not None and ctx.get('llm_scope_debug'):
            try:
                lg.debug('llm_scope_dedupe_empty_scope_seqs')
            except Exception:
                pass
        return False
    cur_set = frozenset(cur)
    dk = (dedupe_key or '').strip() or None
    history = ctx.setdefault('_llm_scope_history', [])
    for i, prev in enumerate(history or []):
        try:
            prev_key = None
            prev_set = None
            if isinstance(prev, dict):
                prev_key = (prev.get('key') or '').strip() or None
                prev_set = prev.get('scope')
            else:
                prev_set = prev
            if prev_set is None:
                continue
            if dk is not None and prev_key is not None and dk != prev_key:
                continue
            # if cur_set.issubset(set(prev_set)):
            #     if lg is not None and ctx.get('llm_scope_debug'):
            #         try:
            #             cur_sorted = sorted(cur_set)
            #             prev_sorted = sorted(set(prev_set))
            #             lg.debug(
            #                 'llm_scope_dedupe_skip',
            #                 cur_len=len(cur_set),
            #                 prev_len=len(set(prev_set)),
            #                 prev_index=i,
            #                 cur_preview=cur_sorted[:12],
            #                 prev_preview=prev_sorted[:12],
            #             )
            #         except Exception:
            #             pass
            #     return True
        except Exception:
            continue
    if history:
        pruned = []
        for prev in history:
            try:
                if isinstance(prev, dict):
                    prev_key = (prev.get('key') or '').strip() or None
                    prev_scope = prev.get('scope')
                    if prev_scope is None:
                        pruned.append(prev)
                        continue
                    if dk is not None and prev_key is not None and dk != prev_key:
                        pruned.append(prev)
                        continue
                    if set(prev_scope).issubset(cur_set):
                        continue
                    pruned.append(prev)
                    continue
                if set(prev).issubset(cur_set):
                    continue
            except Exception:
                pruned.append(prev)
                continue
            pruned.append(prev)
        history[:] = pruned
    history.append({'key': dk, 'scope': cur_set} if dk is not None else cur_set)
    if lg is not None and ctx.get('llm_scope_debug'):
        try:
            lg.debug(
                'llm_scope_dedupe_check',
                cur_len=len(cur_set),
                history_len=len(history),
                cur_preview=sorted(cur_set)[:12],
            )
        except Exception:
            pass
    return False


def map_result_set_to_source_lines(scope_root: str, result_set, trace_index_path: str = os.path.join("tmp", "trace_index.json"), windows_root: str = r'D:\files\witcher\app'):
    """Map a result-set of locators to `{seq,path,line,code}` entries with source lines."""
    min_seqs = _load_trace_index_min_seqs(trace_index_path)
    path_case_map = _load_trace_index_path_case_map(trace_index_path)
    file_case_map = {}
    for k, v in (path_case_map or {}).items():
        try:
            p0 = (k[0] if isinstance(k, tuple) and len(k) >= 1 else "") or ""
            lk = str(p0).lower()
        except Exception:
            lk = ""
        if lk and lk not in file_case_map and isinstance(v, str) and v:
            file_case_map[lk] = v
    out = []
    seen_seqs = set()
    for it in result_set or []:
        if isinstance(it, dict):
            p = it.get('path')
            ln = it.get('line')
            seq = it.get('seq')
            if (not p or ln is None) and it.get('loc'):
                pr = _parse_loc(it.get('loc'))
                if pr:
                    p, ln = pr
            if not p or ln is None:
                continue
            try:
                ln_i = int(ln)
            except Exception:
                continue
            p_norm = norm_trace_path(str(p))
            k = (p_norm, int(ln_i))
            k2 = (str(p_norm).lower(), int(ln_i))
            seq_min = min_seqs.get(k)
            if seq_min is None:
                seq_min = min_seqs.get(k2)
            if seq is None and seq_min is not None:
                seq = seq_min
            if seq is not None:
                try:
                    seq_i = int(seq)
                except Exception:
                    seq_i = None
                if seq_i is not None:
                    if seq_i in seen_seqs:
                        continue
                    seen_seqs.add(seq_i)
                    seq = int(seq_i)
            p_case = path_case_map.get(k) or path_case_map.get(k2) or file_case_map.get(str(p_norm).lower()) or p
            fs_path = resolve_source_path(scope_root, p_case, windows_root=windows_root)
            code = ''
            try:
                with open(fs_path, 'r', encoding='utf-8', errors='replace') as f:
                    for i, line in enumerate(f, start=1):
                        if i == int(ln_i):
                            code = line.rstrip('\n')
                            break
            except Exception:
                code = ''
                alt = file_case_map.get(str(p_norm).lower())
                if alt and alt != p_case:
                    try:
                        fs_path2 = resolve_source_path(scope_root, alt, windows_root=windows_root)
                        with open(fs_path2, 'r', encoding='utf-8', errors='replace') as f:
                            for i, line in enumerate(f, start=1):
                                if i == int(ln_i):
                                    code = line.rstrip('\n')
                                    break
                        if code:
                            p_case = alt
                    except Exception:
                        code = ''
            out.append({'seq': seq, 'path': p_case, 'line': int(ln_i), 'code': code})
            continue
        if isinstance(it, str):
            pr = _parse_loc(it)
            if not pr:
                continue
            p, ln = pr
            try:
                ln_i = int(ln)
            except Exception:
                continue
            p_norm = norm_trace_path(str(p))
            k = (p_norm, int(ln_i))
            k2 = (str(p_norm).lower(), int(ln_i))
            seq = min_seqs.get(k)
            if seq is None:
                seq = min_seqs.get(k2)
            if seq is not None:
                try:
                    seq_i = int(seq)
                except Exception:
                    seq_i = None
                if seq_i is not None:
                    if seq_i in seen_seqs:
                        continue
                    seen_seqs.add(seq_i)
                    seq = int(seq_i)
            p_case = path_case_map.get(k) or path_case_map.get(k2) or file_case_map.get(str(p_norm).lower()) or p
            fs_path = resolve_source_path(scope_root, p_case, windows_root=windows_root)
            code = ''
            try:
                with open(fs_path, 'r', encoding='utf-8', errors='replace') as f:
                    for i, line in enumerate(f, start=1):
                        if i == int(ln_i):
                            code = line.rstrip('\n')
                            break
            except Exception:
                code = ''
                alt = file_case_map.get(str(p_norm).lower())
                if alt and alt != p_case:
                    try:
                        fs_path2 = resolve_source_path(scope_root, alt, windows_root=windows_root)
                        with open(fs_path2, 'r', encoding='utf-8', errors='replace') as f:
                            for i, line in enumerate(f, start=1):
                                if i == int(ln_i):
                                    code = line.rstrip('\n')
                                    break
                        if code:
                            p_case = alt
                    except Exception:
                        code = ''
            out.append({'seq': seq, 'path': p_case, 'line': int(ln_i), 'code': code})
    return out


def generate_taint_prompt(result_set_or_path, scope_root: str, base_prompt: str = '', trace_index_path: str = os.path.join("tmp", "trace_index.json"), windows_root: str = r'D:\files\witcher\app', taint_sources=None) -> str:
    """Build a plain-text prompt from taint sources and `seq + code` source lines."""
    rs = None
    ts = taint_sources
    if isinstance(result_set_or_path, str) and os.path.exists(result_set_or_path):
        with open(result_set_or_path, 'r', encoding='utf-8', errors='replace') as f:
            obj = json.load(f)
        if isinstance(obj, dict):
            rs = obj.get('result_set')
            if ts is None:
                ts = obj.get('taint_sources') or obj.get('taints')
    else:
        rs = result_set_or_path
    lines = map_result_set_to_source_lines(scope_root, rs or [], trace_index_path=trace_index_path, windows_root=windows_root)
    chunks = [base_prompt] if base_prompt else []
    for it in ts or []:
        if isinstance(it, str):
            s = it.strip()
            if s:
                chunks.append(s)
            continue
        if isinstance(it, dict):
            tt = (it.get('type') or '').strip()
            src = (it.get('source') or it.get('name') or '').strip()
            if tt and src:
                chunks.append(f"{tt} {src}")
    for it in lines:
        seq = it.get('seq')
        if seq is None:
            continue
        code = (it.get('code') or '').strip()
        chunks.append(f"{seq} {code}".rstrip())
    return '\n'.join(x for x in chunks if x is not None)


def generate_llm_taint_prompt_from_result_set(
    *,
    taint_type: str,
    taint_name: str,
    result_set_or_path,
    scope_root: str,
    template: Optional[str] = None,
    trace_index_path: str = os.path.join("tmp", "trace_index.json"),
    windows_root: str = r'D:\files\witcher\app',
) -> str:
    """Generate an LLM prompt for one taint using a scoped result-set as context."""
    body = generate_taint_prompt(
        result_set_or_path,
        scope_root=scope_root,
        base_prompt='',
        trace_index_path=trace_index_path,
        windows_root=windows_root,
        taint_sources=None,
    )
    return render_llm_taint_prompt(
        template=(template or DEFAULT_LLM_TAINT_TEMPLATE),
        taint_type=taint_type,
        taint_name=taint_name,
        result_set=body,
    )
