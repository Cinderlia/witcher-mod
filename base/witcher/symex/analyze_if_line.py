"""
Entry-point script for analyzing a single trace line (seq) and expanding taints.

This script:
- Locates `AST_IF_ELEM` nodes corresponding to a trace log line.
- Extracts variables/props/dims/calls under the condition element.
- Runs taint expansion using rule-based handlers, optionally augmented by LLM.
"""

import os
import sys
import json
import base64
import atexit
import bisect
import shutil
import re
import time
import random
import subprocess
import signal
import threading
import traceback
from typing import Any, Dict, List, Optional, Set, Tuple
from common.app_config import load_app_config, load_symbolic_seed_kind_flags
from common.logger import Logger
from utils.extractors.if_extract import (
    norm_trace_path,
    collect_descendants,
    resolve_if_elem_targets,
    load_nodes,
    load_ast_edges,
    get_string_children,
    get_all_string_descendants,
    find_first_var_string,
)
from taint_handlers import REGISTRY
from taint_handlers.llm.core.llm_process import process_taints_llm
from utils.trace_utils.trace_index_utils import ensure_trace_index_records_for_seq
from llm_utils.prompts.symbolic_prompt import generate_symbolic_execution_prompt
from llm_utils.prompts.sql_symbolic_prompt import generate_symbolic_execution_prompt as generate_sql_symbolic_execution_prompt
from llm_utils.prompts.xss_symbolic_prompt import generate_symbolic_execution_prompt as generate_xss_symbolic_execution_prompt
from llm_utils.prompts.cmd_symbolic_prompt import generate_symbolic_execution_prompt as generate_cmd_symbolic_execution_prompt
from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines, _DEFAULT_LLM_TAINT_TEMPLATE_TAIL
from llm_utils.solution_markers import DELETE_KEY_SENTINEL, is_delete_sentinel
from llm_utils.session_validator import validate_and_fix_php_session_text
from llm_utils.symbolic_runner import (
    build_symbolic_response_example,
    load_symbolic_solution_defaults,
    parse_symbolic_response,
    run_symbolic_prompt,
    write_symbolic_prompt,
    write_symbolic_response,
    write_symbolic_solution_outputs,
)
from shared_mem.providers import build_analyze_context_provider


def _heartbeat_ts() -> str:
    t = time.time()
    lt = time.localtime(t)
    ms = int((t - int(t)) * 1000)
    return time.strftime('%Y-%m-%d %H:%M:%S', lt) + f'.{ms:03d}'


def _atomic_write_text(path: str, text: str) -> None:
    out_path = os.path.abspath(path or "")
    if not out_path:
        return
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(text or "")
    os.replace(tmp_path, out_path)


def _atomic_write_json(path: str, obj: dict) -> None:
    try:
        txt = json.dumps(obj or {}, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        txt = "{}"
    _atomic_write_text(path, txt)


def _append_json_line(path: str, obj: dict) -> None:
    out_path = os.path.abspath(path or "")
    if not out_path:
        return
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    try:
        txt = json.dumps(obj or {}, ensure_ascii=False, sort_keys=True)
    except Exception:
        txt = "{}"
    with open(out_path, "a", encoding="utf-8", errors="replace") as f:
        f.write(txt + "\n")


def _append_stage_debug(run_dir: str, event: str, **fields) -> None:
    payload = {
        "ts": _heartbeat_ts(),
        "event": str(event or ""),
        "pid": int(os.getpid()),
        "ppid": int(os.getppid()),
    }
    for k, v in (fields or {}).items():
        payload[str(k)] = v
    _append_json_line(os.path.join(os.path.abspath(run_dir), "logs", "stage_debug.ndjson"), payload)


def _deep_copy_jsonish(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except Exception:
        return value


def _jsonish_equal(left: Any, right: Any) -> bool:
    try:
        return json.dumps(left, ensure_ascii=False, sort_keys=True) == json.dumps(right, ensure_ascii=False, sort_keys=True)
    except Exception:
        return left == right


def _normalize_session_patch(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list, bool, int, float)):
        return _deep_copy_jsonish(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return json.loads(s)
        except Exception:
            return None
    return _deep_copy_jsonish(value)


def _merge_session_patch(base: Any, patch: Any) -> Any:
    if isinstance(base, dict) and isinstance(patch, dict):
        out: Dict[str, Any] = {}
        for key, value in base.items():
            out[str(key)] = _deep_copy_jsonish(value)
        for key, value in patch.items():
            k = str(key)
            if is_delete_sentinel(value):
                if k in out:
                    del out[k]
                continue
            if k in out:
                out[k] = _merge_session_patch(out.get(k), value)
            else:
                out[k] = _deep_copy_jsonish(value)
        return out
    return _deep_copy_jsonish(patch)


def _resolve_session_capture(defaults: Optional[dict]) -> Dict[str, Any]:
    if not isinstance(defaults, dict):
        return {}
    obj = defaults.get("SESSION_CAPTURE")
    return obj if isinstance(obj, dict) else {}


def _resolve_session_cookie_name(defaults: Optional[dict]) -> str:
    capture = _resolve_session_capture(defaults)
    name = str(capture.get("session_name") or "").strip()
    return name or "PHPSESSID"


_WITCHER_FILE_UPLOAD_MARKER = "__WITCHER_FILE_PAYLOAD__"
_WITCHER_FILE_UPLOAD_FIELD = "__WITCHER_FILE_PAYLOADS__"
_WITCHER_FILE_PATH_PREFIX = "__WITCHER_FILE_PATH__:"
_WITCHER_FILE_PATH_FIELD = "__WITCHER_FILE_PATH_PAYLOADS__"
_WITCHER_FILE_TMP_DIR = "/tmp/symex_files"


def _safe_file_name(name: Any, *, default: str = "payload.bin") -> str:
    raw = str(name or "").strip()
    if not raw:
        raw = default
    raw = raw.replace("\\", "_").replace("/", "_").replace("\x00", "_")
    raw = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    raw = raw.strip("._") or default
    if len(raw) > 120:
        base, ext = os.path.splitext(raw)
        raw = (base[:96] or "payload") + ext[:24]
    return raw


def _normalize_file_descriptor(value: Any) -> Optional[Dict[str, str]]:
    if not isinstance(value, dict):
        return None
    filename = _safe_file_name(value.get("filename"), default="payload.bin")
    content_base64 = str(value.get("content_base64") or "").strip()
    if not content_base64:
        return None
    content_type = str(value.get("content_type") or "application/octet-stream").strip() or "application/octet-stream"
    return {
        "filename": filename,
        "content_base64": content_base64,
        "content_type": content_type,
    }


def _solution_file_uploads(solution: dict) -> Dict[str, Dict[str, str]]:
    if not isinstance(solution, dict):
        return {}
    raw = None
    for key, value in solution.items():
        if isinstance(key, str) and key.strip().upper() == _WITCHER_FILE_UPLOAD_FIELD.upper():
            raw = value
            break
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, Dict[str, str]] = {}
    for field_name, desc in raw.items():
        field = str(field_name or "").strip()
        norm = _normalize_file_descriptor(desc)
        if field and norm is not None:
            out[field] = norm
    return out


def _solution_file_path_payloads(solution: dict) -> Dict[str, Dict[str, str]]:
    if not isinstance(solution, dict):
        return {}
    raw = None
    for key, value in solution.items():
        if isinstance(key, str) and key.strip().upper() == _WITCHER_FILE_PATH_FIELD.upper():
            raw = value
            break
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, Dict[str, str]] = {}
    for payload_key, desc in raw.items():
        key_s = str(payload_key or "").strip()
        norm = _normalize_file_descriptor(desc)
        if key_s and norm is not None:
            out[key_s] = norm
    return out


def _split_named_pairs_text(text: str, *, cookie_mode: bool) -> List[Tuple[str, Optional[str]]]:
    out: List[Tuple[str, Optional[str]]] = []
    s = (text or "").strip()
    if not s:
        return out
    splitter = r"[;&]" if cookie_mode else r"&"
    for raw in re.split(splitter, s):
        part = (raw or "").strip()
        if not part:
            continue
        if "=" in part:
            key, value = part.split("=", 1)
            out.append(((key or "").strip(), value))
        else:
            out.append((part, None if cookie_mode else ""))
    return out


def _pairs_to_named_text(parts: List[Tuple[str, Optional[str]]], *, cookie_mode: bool) -> str:
    buf: List[str] = []
    for key, value in parts or []:
        key_s = (key or "").strip()
        if not key_s:
            continue
        if value is None and cookie_mode:
            buf.append(key_s)
        else:
            buf.append("%s=%s" % (key_s, "" if value is None else value))
    return "&".join(buf).strip("&")


def _iter_named_patch_items(field_obj: Any, *, cookie_mode: bool) -> List[Tuple[str, Optional[str]]]:
    out: List[Tuple[str, Optional[str]]] = []
    if isinstance(field_obj, dict):
        for key, value in field_obj.items():
            key_s = str(key or "").strip()
            if not key_s:
                continue
            if is_delete_sentinel(value):
                out.append((key_s, None))
            else:
                out.append((key_s, "" if value is None else str(value)))
        return out
    if isinstance(field_obj, (list, tuple)):
        for item in field_obj:
            if isinstance(item, dict):
                out.extend(_iter_named_patch_items(item, cookie_mode=cookie_mode))
                continue
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                key_s = str(item[0] or "").strip()
                if not key_s:
                    continue
                value = item[1]
                if is_delete_sentinel(value):
                    out.append((key_s, None))
                else:
                    out.append((key_s, "" if value is None else str(value)))
                continue
            if isinstance(item, str):
                for key_s, value in _split_named_pairs_text(item, cookie_mode=cookie_mode):
                    if is_delete_sentinel(value):
                        out.append((key_s, None))
                    else:
                        out.append((key_s, value))
        return out
    return out


def _apply_named_patch(default_text: str, field_obj: Any, *, cookie_mode: bool) -> str:
    if field_obj is None:
        return ""
    if isinstance(field_obj, str):
        field_s = field_obj.strip()
        if is_delete_sentinel(field_s):
            return ""
        return field_s

    base_parts = _split_named_pairs_text(default_text or "", cookie_mode=cookie_mode)
    order: List[str] = []
    display: Dict[str, str] = {}
    values: Dict[str, Optional[str]] = {}
    for key, value in base_parts:
        key_s = str(key or "").strip()
        if not key_s:
            continue
        norm = key_s.lower()
        if norm not in display:
            order.append(norm)
        display[norm] = key_s
        values[norm] = value

    for key, value in _iter_named_patch_items(field_obj, cookie_mode=cookie_mode):
        key_s = str(key or "").strip()
        if not key_s:
            continue
        norm = key_s.lower()
        if value is None:
            if norm in values:
                del values[norm]
            if norm in display:
                del display[norm]
            if norm in order:
                order = [x for x in order if x != norm]
            continue
        if norm not in order:
            order.append(norm)
        display[norm] = key_s
        values[norm] = value

    parts: List[Tuple[str, Optional[str]]] = []
    for norm in order:
        if norm not in values:
            continue
        parts.append((display.get(norm) or norm, values.get(norm)))
    return _pairs_to_named_text(parts, cookie_mode=cookie_mode)


def _effective_request_field(solution: dict, field_name: str, *, defaults: Optional[dict], cookie_mode: bool) -> str:
    try:
        from llm_utils.symbolic_runner import _normalize_request_field
    except Exception:
        _normalize_request_field = None
    norm = _normalize_solution_keys(solution if isinstance(solution, dict) else {})
    field_key = str(field_name or "").strip().upper()
    default_value = str((defaults or {}).get(field_key) or "")
    if field_key not in norm:
        return default_value
    field_obj = norm.get(field_key)
    if isinstance(field_obj, (dict, list, tuple)):
        return _apply_named_patch(default_value, field_obj, cookie_mode=cookie_mode)
    if _normalize_request_field is None:
        if field_obj is None:
            return ""
        field_s = str(field_obj).strip()
        return "" if is_delete_sentinel(field_s) else field_s
    return _normalize_request_field(field_obj, default_value=default_value, use_default=False)


def _normalize_env_patch_map(env_obj: Any) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {}

    if isinstance(env_obj, dict):
        for key, value in env_obj.items():
            key_s = str(key or "").strip()
            if not key_s:
                continue
            out[key_s] = None if is_delete_sentinel(value) else ("" if value is None else str(value))
        return out

    if isinstance(env_obj, (list, tuple)):
        for item in env_obj:
            if isinstance(item, dict):
                out.update(_normalize_env_patch_map(item))
                continue
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                key_s = str(item[0] or "").strip()
                if not key_s:
                    continue
                value = item[1]
                out[key_s] = None if is_delete_sentinel(value) else ("" if value is None else str(value))
                continue
            if isinstance(item, str):
                out.update(_normalize_env_patch_map(item))
        return out

    if isinstance(env_obj, str):
        for raw_line in env_obj.splitlines():
            line = str(raw_line or "").strip()
            if line.startswith("export "):
                line = (line[len("export ") :] or "").strip()
            if not line:
                continue
            if "=" in line:
                key_s, value = line.split("=", 1)
                key_s = str(key_s or "").strip()
                if not key_s:
                    continue
                out[key_s] = None if is_delete_sentinel(value) else str(value)
            else:
                out[str(line)] = None
        return out

    return out


def _canonicalize_env_patch_map(env_map: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
    if not isinstance(env_map, dict) or not env_map:
        return {}
    out: Dict[str, Optional[str]] = {}
    method_seen = False
    method_value: Optional[str] = None
    for key, value in env_map.items():
        key_s = str(key or "").strip()
        if not key_s:
            continue
        key_u = key_s.upper()
        if key_u == "METHOD":
            method_seen = True
            method_value = value
            continue
        out[key_s] = value
    if "REQUEST_METHOD" not in out and method_seen:
        out["REQUEST_METHOD"] = method_value
    return out


def _resolve_php_session_renderer_command(cfg, helper_path: str) -> Tuple[List[str], str]:
    helper_abs = os.path.abspath(helper_path or "")
    raw = cfg.raw if hasattr(cfg, "raw") else {}
    if not isinstance(raw, dict):
        raw = {}
    cli_candidates: List[str] = []
    for key in ("session_render_php_binary", "php_binary", "system_php_binary"):
        value = str(raw.get(key) or "").strip()
        if value:
            cli_candidates.append(value)
    env_cli = str(os.environ.get("WC_SESSION_RENDER_PHP") or "").strip()
    if env_cli:
        cli_candidates.append(env_cli)
    which_php = shutil.which("php")
    if which_php:
        cli_candidates.append(which_php)
    seen = set()
    for cand in cli_candidates:
        cand_s = str(cand or "").strip()
        if not cand_s:
            continue
        norm = os.path.abspath(cand_s) if os.path.isabs(cand_s) else cand_s
        if norm in seen:
            continue
        seen.add(norm)
        return [cand_s, helper_abs], "cli"

    cgi_candidates: List[str] = []
    for key in ("afl_inst_interpreter_binary", "wc_inst_interpreter_binary"):
        value = str(raw.get(key) or "").strip()
        if value:
            cgi_candidates.append(value)
    for cand in cgi_candidates:
        cand_s = str(cand or "").strip()
        if not cand_s:
            continue
        return [cand_s], "cgi"
    return [], ""


def _resolve_session_render_helper_path() -> str:
    base_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base_root, "helpers", "render_session.php")


def _make_symbolic_session_id(*, seq: int, external_seed_id: int, solution_index: int) -> str:
    # Keep the symbolic session id within the launcher-compatible length window.
    seed = "|".join([
        str(int(seq)),
        str(int(external_seed_id)),
        str(int(solution_index)),
        str(int(os.getpid())),
        str(int(getattr(time, "time_ns", lambda: int(time.time() * 1_000_000_000))())),
        os.urandom(8).hex(),
    ]).encode("utf-8", errors="replace")
    try:
        import hashlib
        return hashlib.md5(seed).hexdigest()
    except Exception:
        return os.urandom(16).hex()


def _best_effort_copy_file(src: str, dst: str) -> bool:
    src_s = str(src or "").strip()
    dst_s = str(dst or "").strip()
    if not src_s or not dst_s or not os.path.isfile(src_s):
        return False
    try:
        os.makedirs(os.path.dirname(dst_s), exist_ok=True)
    except Exception:
        pass
    tmp_dst = dst_s + ".tmp"
    try:
        shutil.copyfile(src_s, tmp_dst)
        os.replace(tmp_dst, dst_s)
        return True
    except Exception:
        try:
            if os.path.exists(tmp_dst):
                os.remove(tmp_dst)
        except Exception:
            pass
        return False


def _ensure_symbolic_session_runtime_aliases(
    *,
    session_id: str,
    rendered_path: str,
    logger: Optional[Logger],
    seq: int,
    solution_index: int,
) -> List[str]:
    sid = str(session_id or "").strip()
    src = str(rendered_path or "").strip()
    if not sid or not src:
        return []
    alias_paths = [
        os.path.join("/tmp", f"sess_{sid}"),
        os.path.join("/tmp", f"save_{sid}"),
    ]
    created: List[str] = []
    for alias_path in alias_paths:
        if _best_effort_copy_file(src, alias_path):
            created.append(alias_path)
            continue
        if logger is not None:
            try:
                logger.warning(
                    "symbolic_session_alias_copy_failed",
                    seq=int(seq),
                    solution_index=int(solution_index),
                    source=src,
                    alias_path=alias_path,
                )
            except Exception:
                pass
    return created


def _parse_cgi_json_output(stdout_text: str) -> Dict[str, Any]:
    body = stdout_text or ""
    if "\r\n\r\n" in body:
        body = body.split("\r\n\r\n", 1)[1]
    elif "\n\n" in body:
        body = body.split("\n\n", 1)[1]
    body = body.strip()
    if not body:
        return {}
    try:
        obj = json.loads(body)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _render_symbolic_session_file(
    *,
    cfg,
    session_vars: Any,
    session_id: str,
    session_name: str,
    session_save_path: str,
    logger: Optional[Logger],
    seq: int,
    solution_index: int,
) -> Tuple[str, str]:
    helper_path = _resolve_session_render_helper_path()
    cmd, mode = _resolve_php_session_renderer_command(cfg, helper_path)
    if not cmd or not os.path.isfile(helper_path):
        return "", ""
    payload = {
        "session_id": str(session_id or "").strip(),
        "session_name": str(session_name or "").strip() or "PHPSESSID",
        "session_save_path": str(session_save_path or "").strip(),
        "session_vars": session_vars,
    }
    input_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8", errors="replace")
    env = dict(os.environ)
    if mode == "cgi":
        env["REDIRECT_STATUS"] = "1"
        env["GATEWAY_INTERFACE"] = "CGI/1.1"
        env["REQUEST_METHOD"] = "POST"
        env["SCRIPT_FILENAME"] = helper_path
        env["CONTENT_TYPE"] = "application/json"
        env["CONTENT_LENGTH"] = str(len(input_bytes))
    try:
        proc = subprocess.run(
            cmd,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=10,
        )
    except Exception:
        if logger is not None:
            logger.exception("render_session_php_run_failed", seq=int(seq), solution_index=int(solution_index), command=cmd, mode=mode)
        return "", ""
    out_text = (proc.stdout or b"").decode("utf-8", errors="replace")
    err_text = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    obj = _parse_cgi_json_output(out_text)
    if proc.returncode != 0 or not obj or not obj.get("ok"):
        if logger is not None:
            try:
                logger.warning(
                    "render_session_php_failed",
                    seq=int(seq),
                    solution_index=int(solution_index),
                    returncode=int(proc.returncode),
                    mode=mode,
                    stderr=err_text,
                    stdout=(out_text or "")[:400],
                )
            except Exception:
                pass
        return "", ""
    return str(obj.get("session_id") or "").strip(), str(obj.get("session_file_path") or "").strip()


def _prepare_solution_session(
    solution: dict,
    *,
    cfg,
    seq: int,
    external_seed_id: int,
    solution_index: int,
    defaults: Optional[dict],
    logger: Optional[Logger],
) -> Tuple[str, str, str]:
    if logger is not None:
        try:
            logger.info(
                "prepare_solution_session_start",
                seq=int(seq),
                external_seed_id=int(external_seed_id),
                solution_index=int(solution_index),
                has_solution=bool(isinstance(solution, dict)),
                solution_keys=sorted([str(k) for k in solution.keys()]) if isinstance(solution, dict) else [],
            )
        except Exception:
            pass
    if not isinstance(solution, dict):
        return "", "", ""
    has_session_key = False
    raw_patch = None
    for key, value in solution.items():
        if isinstance(key, str) and key.strip().upper() == "SESSION":
            has_session_key = True
            raw_patch = value
            break
    if not has_session_key:
        return "", "", ""
    patch = _normalize_session_patch(raw_patch)
    if patch is None:
        if logger is not None:
            try:
                logger.info(
                    "prepare_solution_session_skip_no_patch",
                    seq=int(seq),
                    external_seed_id=int(external_seed_id),
                    solution_index=int(solution_index),
                )
            except Exception:
                pass
        return "", "", ""
    capture = _resolve_session_capture(defaults)
    base_session_vars = capture.get("session_vars")
    if not isinstance(base_session_vars, (dict, list)):
        base_session_vars = {}
    merged_session = _merge_session_patch(base_session_vars, patch)
    if logger is not None:
        try:
            logger.info(
                "prepare_solution_session_merged",
                seq=int(seq),
                external_seed_id=int(external_seed_id),
                solution_index=int(solution_index),
                session_patch_keys=sorted([str(k) for k in (patch.keys() if isinstance(patch, dict) else [])]),
                base_session_type=type(base_session_vars).__name__,
            )
        except Exception:
            pass
    session_id = _make_symbolic_session_id(seq=int(seq), external_seed_id=int(external_seed_id), solution_index=int(solution_index))
    session_name = str(capture.get("session_name") or "").strip() or "PHPSESSID"
    session_save_path = str(capture.get("session_save_path") or "").strip() or "/tmp/php_sessions"
    rendered_session_id, rendered_path = _render_symbolic_session_file(
        cfg=cfg,
        session_vars=merged_session,
        session_id=session_id,
        session_name=session_name,
        session_save_path=session_save_path,
        logger=logger,
        seq=int(seq),
        solution_index=int(solution_index),
    )
    if not rendered_session_id or not rendered_path:
        if logger is not None:
            try:
                logger.warning(
                    "prepare_solution_session_render_failed",
                    seq=int(seq),
                    external_seed_id=int(external_seed_id),
                    solution_index=int(solution_index),
                    session_name=session_name,
                    session_save_path=session_save_path,
                )
            except Exception:
                pass
        return "", "", ""
    alias_paths = _ensure_symbolic_session_runtime_aliases(
        session_id=rendered_session_id,
        rendered_path=rendered_path,
        logger=logger,
        seq=int(seq),
        solution_index=int(solution_index),
    )
    if logger is not None:
        try:
            logger.info(
                "prepare_solution_session_done",
                seq=int(seq),
                external_seed_id=int(external_seed_id),
                solution_index=int(solution_index),
                rendered_session_id=str(rendered_session_id),
                rendered_path=str(rendered_path),
                alias_count=len(alias_paths or []),
            )
        except Exception:
            pass
    if logger is not None:
        try:
            logger.info(
                "symbolic_session_prepared",
                seq=int(seq),
                solution_index=int(solution_index),
                session_id=str(rendered_session_id),
                rendered_path=str(rendered_path),
                alias_paths=alias_paths,
            )
        except Exception:
            pass
    return rendered_session_id, rendered_path, session_name


def _parse_seed_id_from_name(name: str) -> Optional[int]:
    m = re.search(r"\bid:(\d+)\b", str(name or ""))
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _parse_seed_id_text_from_name(name: str) -> str:
    m = re.search(r"\bid:(\d+)\b", str(name or ""))
    if not m:
        return ""
    return str(m.group(1) or "").strip()


def _parse_seed_env_id_from_name(name: str) -> str:
    m = re.search(r"\benv:([0-9A-Fa-f]+)\b", str(name or ""))
    if not m:
        return ""
    return str(m.group(1) or "").strip()


def _derive_source_fuzzer_name(meta: Dict[str, Any]) -> str:
    source_fuzzer = str(meta.get("source_fuzzer") or "").strip()
    if source_fuzzer:
        return source_fuzzer
    queue_dir = str(meta.get("queue_dir") or "").strip()
    if queue_dir:
        try:
            parent = os.path.basename(os.path.dirname(queue_dir.rstrip("/\\")))
            if parent:
                return parent
        except Exception:
            pass
    seed_path = str(meta.get("seed_path") or "").strip()
    if seed_path:
        try:
            queue_dir_guess = os.path.dirname(seed_path.rstrip("/\\"))
            parent = os.path.basename(os.path.dirname(queue_dir_guess))
            if parent:
                return parent
        except Exception:
            pass
    return "unknown"


def _derive_parent_seed_id_text(meta: Dict[str, Any]) -> str:
    raw = str(meta.get("seed_id_text") or "").strip()
    if raw:
        return raw
    raw_name = str(meta.get("seed_name") or "").strip()
    parsed = _parse_seed_id_text_from_name(raw_name)
    if parsed:
        return parsed
    seed_path = str(meta.get("seed_path") or "").strip()
    parsed = _parse_seed_id_text_from_name(os.path.basename(seed_path))
    if parsed:
        return parsed
    seed_id = meta.get("seed_id")
    if seed_id is None:
        return ""
    try:
        return str(int(seed_id))
    except Exception:
        return str(seed_id).strip()


def _parent_seed_info_candidate_paths() -> List[str]:
    cwd = os.path.abspath(os.getcwd())
    out = [
        os.path.join(cwd, "meta", "parent_seed_info.json"),
        os.path.join(cwd, "parent_seed_info.json"),
    ]
    seen = set()
    uniq: List[str] = []
    for item in out:
        norm = os.path.abspath(str(item or ""))
        if not norm or norm in seen:
            continue
        seen.add(norm)
        uniq.append(norm)
    return uniq


def _load_parent_seed_info() -> Dict[str, Any]:
    for path in _parent_seed_info_candidate_paths():
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                obj = json.load(f)
        except Exception:
            obj = None
        if isinstance(obj, dict) and obj:
            obj["_loaded_from"] = path
            return obj
    return {}


def _record_parent_seed_resolution(payload: Dict[str, Any]) -> None:
    return


def _resolve_parent_seed_id_info() -> Dict[str, Any]:
    meta = _load_parent_seed_info()
    meta_seed_id_text = _derive_parent_seed_id_text(meta)
    source_fuzzer = _derive_source_fuzzer_name(meta)
    if meta_seed_id_text:
        payload = {
            "resolved_parent_seed_id": str(meta_seed_id_text).strip(),
            "resolved_parent_seed_id_text": str(meta_seed_id_text).strip(),
            "resolved_source_fuzzer": str(source_fuzzer or "unknown"),
            "source": "meta",
            "resolved_parent_seed_hash8": str(meta.get("seed_hash8") or "").strip(),
            "meta_path_candidates": _parent_seed_info_candidate_paths(),
            "meta": meta,
            "cwd": os.path.abspath(os.getcwd()),
        }
        _record_parent_seed_resolution(payload)
        return payload
    payload = {
        "resolved_parent_seed_id": "unknown",
        "resolved_parent_seed_id_text": "",
        "resolved_source_fuzzer": str(source_fuzzer or "unknown"),
        "resolved_parent_seed_hash8": str(meta.get("seed_hash8") or "").strip(),
        "source": "unknown",
        "meta_path_candidates": _parent_seed_info_candidate_paths(),
        "meta": meta,
        "cwd": os.path.abspath(os.getcwd()),
    }
    _record_parent_seed_resolution(payload)
    return payload


def _resolve_parent_seed_id() -> str:
    return str((_resolve_parent_seed_id_info().get("resolved_parent_seed_id") or "unknown")).strip() or "unknown"


def _derive_parent_seed_env_id(meta: Dict[str, Any]) -> str:
    raw = str(meta.get("seed_env_id") or "").strip()
    if raw:
        return raw
    raw_name = str(meta.get("seed_name") or "").strip()
    parsed = _parse_seed_env_id_from_name(raw_name)
    if parsed:
        return parsed
    seed_path = str(meta.get("seed_path") or "").strip()
    parsed = _parse_seed_env_id_from_name(os.path.basename(seed_path))
    if parsed:
        return parsed
    return ""


def _resolve_seed_env_child_dir(cfg) -> str:
    v = os.environ.get("WC_ENV_CHILD_DIR") or ""
    if isinstance(v, str) and v.strip():
        return os.path.abspath(v.strip())
    prep = _load_prepare_report(cfg)
    work_dir = str(prep.get("work_dir") or "").strip() if isinstance(prep, dict) else ""
    if work_dir:
        return os.path.abspath(os.path.join(work_dir, "seed_env_profiles", "child"))
    return os.path.abspath(os.path.join(cfg.base_dir, "..", "seed_env_profiles", "child"))


def _read_seed_env_profile_file(path: str) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {}
    if not isinstance(path, str) or not path or not os.path.exists(path):
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as rf:
            for raw_line in rf:
                line = str(raw_line or "").rstrip("\r\n")
                if not line:
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    parsed_val: Optional[str] = str(val or "")
                else:
                    key = line
                    parsed_val = None
                key = str(key or "").strip()
                if not key:
                    continue
                out[key] = parsed_val
    except Exception:
        return {}
    return out


def _load_prompt_base_inputs_for_parent_seed(cfg) -> Dict[str, Any]:
    base_inputs: Dict[str, Any] = {}
    env_json_path = os.path.join(os.getcwd(), "input", "env.json")
    try:
        if os.path.exists(env_json_path):
            with open(env_json_path, "r", encoding="utf-8", errors="replace") as rf:
                obj = json.load(rf)
            if isinstance(obj, dict):
                base_inputs = dict(obj)
    except Exception:
        base_inputs = {}
    seed_info = _resolve_parent_seed_id_info()
    meta = seed_info.get("meta") if isinstance(seed_info, dict) else {}
    meta = meta if isinstance(meta, dict) else {}
    env_id = _derive_parent_seed_env_id(meta)
    if not env_id:
        return base_inputs
    env_map: Dict[str, Optional[str]] = {}
    child_path = os.path.join(_resolve_seed_env_child_dir(cfg), "%s.env" % env_id)
    parent_path = os.path.join(_resolve_seed_env_parent_dir(cfg), "%s.env" % env_id)
    for path in (child_path, parent_path):
        env_map = _read_seed_env_profile_file(path)
        if env_map:
            break
    if not env_map:
        return base_inputs
    merged = dict(base_inputs)
    env_block = dict(merged.get("ENV") or {})
    for key, val in env_map.items():
        key_s = str(key)
        if val is None:
            env_block.pop(key_s, None)
        else:
            env_block[key_s] = str(val)
    merged["ENV"] = env_block
    merged["_WC_ENV_ID"] = env_id
    return merged


def _env_defaults_to_map(defaults: Optional[dict]) -> Dict[str, str]:
    env_defaults = defaults.get("env_lines") if isinstance(defaults, dict) and isinstance(defaults.get("env_lines"), list) else []
    out: Dict[str, str] = {}
    for raw in env_defaults or []:
        s = (raw or "").strip()
        if s.startswith("export "):
            s = (s[len("export ") :] or "").strip()
        if not s or "=" not in s:
            continue
        k, v = s.split("=", 1)
        k = (k or "").strip()
        if not k:
            continue
        out[k] = v
    return out


def _env_map_to_lines(env_map: Dict[str, str]) -> List[str]:
    out: List[str] = []
    if not isinstance(env_map, dict):
        return out
    for key in sorted(str(k).strip() for k in env_map.keys() if str(k).strip()):
        out.append("%s=%s" % (key, str(env_map.get(key) or "")))
    return out


def _merge_defaults_with_base_inputs(defaults: Optional[dict], base_inputs: Optional[dict]) -> Dict[str, Any]:
    merged = dict(defaults or {}) if isinstance(defaults, dict) else {}
    if not isinstance(base_inputs, dict):
        return merged
    env_block = base_inputs.get("ENV")
    if not isinstance(env_block, dict):
        return merged
    env_map = _env_defaults_to_map(merged)
    for key, value in env_block.items():
        key_s = str(key or "").strip()
        if not key_s:
            continue
        if value is None:
            env_map.pop(key_s, None)
        else:
            env_map[key_s] = str(value)
    merged["env_lines"] = _env_map_to_lines(env_map)
    return merged


def _apply_env_solution_to_defaults(solution: dict, *, defaults: Optional[dict]) -> Dict[str, str]:
    norm = _normalize_solution_keys(solution)
    base_map = _env_defaults_to_map(defaults)
    if "ENV" not in norm:
        return dict(base_map)
    patch_map = _canonicalize_env_patch_map(_normalize_env_patch_map(norm.get("ENV")))
    if not patch_map:
        return dict(base_map)
    effective = dict(base_map)
    for key, value in patch_map.items():
        key_s = str(key or "").strip()
        if not key_s:
            continue
        if value is None:
            effective.pop(key_s, None)
        else:
            effective[key_s] = str(value)
    return effective


def _diff_env_maps(base_map: Dict[str, str], effective_map: Dict[str, str]) -> Dict[str, Optional[str]]:
    changed: Dict[str, Optional[str]] = {}
    all_keys = set()
    all_keys.update(str(k) for k in (base_map or {}).keys())
    all_keys.update(str(k) for k in (effective_map or {}).keys())
    for key in sorted(str(k).strip() for k in all_keys if str(k).strip()):
        if key not in effective_map:
            if key in base_map:
                changed[key] = None
            continue
        value = str(effective_map.get(key))
        if key not in base_map or str(base_map.get(key)) != value:
            changed[key] = value
    return changed


def _solution_change_markers(solution: dict, *, defaults: Optional[dict]) -> List[str]:
    if not isinstance(solution, dict):
        return []
    out: List[str] = []
    norm = _normalize_solution_keys(solution)
    file_uploads = _solution_file_uploads(solution)
    file_path_payloads = _solution_file_path_payloads(solution)

    def _block_has_non_file_change(block_name: str, *, cookie_mode: bool) -> bool:
        if block_name not in norm:
            return False
        raw_block = norm.get(block_name)
        if not isinstance(raw_block, dict):
            effective_value = _effective_request_field(norm, block_name, defaults=defaults, cookie_mode=cookie_mode)
            return str(effective_value or "") != str((defaults or {}).get(block_name) or "")
        filtered_block = {}
        for raw_key, raw_value in raw_block.items():
            key_s = str(raw_key or "").strip()
            if not key_s:
                continue
            if str(raw_value or "") == _WITCHER_FILE_UPLOAD_MARKER and key_s in file_uploads:
                continue
            if isinstance(raw_value, str) and raw_value.startswith(_WITCHER_FILE_PATH_PREFIX):
                payload_key = raw_value[len(_WITCHER_FILE_PATH_PREFIX):].strip()
                if payload_key and payload_key in file_path_payloads:
                    continue
            filtered_block[key_s] = raw_value
        if not filtered_block:
            return False
        temp_solution = dict(solution)
        temp_solution[block_name] = filtered_block
        temp_norm = _normalize_solution_keys(temp_solution)
        effective_value = _effective_request_field(temp_norm, block_name, defaults=defaults, cookie_mode=cookie_mode)
        return str(effective_value or "") != str((defaults or {}).get(block_name) or "")

    if _block_has_non_file_change("COOKIE", cookie_mode=True):
        out.append("COOKIE")
    if _block_has_non_file_change("GET", cookie_mode=False):
        out.append("GET")
    if _block_has_non_file_change("POST", cookie_mode=False):
        out.append("POST")

    if "SESSION" in norm:
        session_block = norm.get("SESSION")
        if not isinstance(session_block, dict):
            out.append("SESSION")
        else:
            filtered_session = {}
            for raw_key, raw_value in session_block.items():
                key_s = str(raw_key or "").strip()
                if not key_s:
                    continue
                if str(raw_value or "") == _WITCHER_FILE_UPLOAD_MARKER and key_s in file_uploads:
                    continue
                if isinstance(raw_value, str) and raw_value.startswith(_WITCHER_FILE_PATH_PREFIX):
                    payload_key = raw_value[len(_WITCHER_FILE_PATH_PREFIX):].strip()
                    if payload_key and payload_key in file_path_payloads:
                        continue
                filtered_session[key_s] = raw_value
            if filtered_session:
                out.append("SESSION")

    if _env_change_map_from_solution(norm, defaults=defaults):
        out.append("ENV")
    if file_uploads or file_path_payloads:
        out.append("FILE")
    sql_value = norm.get("SQL")
    if isinstance(sql_value, str) and sql_value.strip():
        out.append("SQL")
    elif isinstance(sql_value, (list, tuple)):
        for item in sql_value:
            if isinstance(item, str) and item.strip():
                out.append("SQL")
                break
            if isinstance(item, dict) and str(item.get("sql") or "").strip():
                out.append("SQL")
                break
    return out


def _build_external_seed_name(*, external_seed_id: int, seq: int, solution_index: int, solution: dict, defaults: Optional[dict], seed_kind_flags: Optional[Dict[str, bool]] = None) -> str:
    parent_seed_info = _resolve_parent_seed_id_info()
    parent_seed_id = str(parent_seed_info.get("resolved_parent_seed_id_text") or parent_seed_info.get("resolved_parent_seed_id") or "unknown")
    source_fuzzer = str(parent_seed_info.get("resolved_source_fuzzer") or "unknown")
    markers = _seed_mods_from_solution(solution, defaults=defaults, seed_kind_flags=seed_kind_flags)
    mods = "+".join(markers) if markers else "NONE"
    parts = [
        "id:%06d" % int(external_seed_id),
        "src:%s" % str(source_fuzzer),
        "srcid:%s" % str(parent_seed_id),
        "seq:%d" % int(seq),
        "idx:%d" % int(solution_index + 1),
        "mods:%s" % mods,
    ]
    env_id = ""
    try:
        env_id = str(solution.get("_WC_ENV_ID") or "").strip()
    except Exception:
        env_id = ""
    if env_id and "ENV" in markers:
        parts.append("env:%s" % env_id)
    return ",".join(parts)


def _build_sql_log_name(*, external_seed_id: int, parent_seed_id: str, source_fuzzer: str, seq: int) -> str:
    safe_fuzzer = re.sub(r"[^A-Za-z0-9_\-]+", "_", str(source_fuzzer or "unknown").strip() or "unknown")
    safe_seed = re.sub(r"[^A-Za-z0-9_\-]+", "_", str(parent_seed_id or "unknown").strip() or "unknown")
    safe_new_seed = re.sub(r"[^A-Za-z0-9_\-]+", "_", str(int(external_seed_id)).strip())
    safe_seq = re.sub(r"[^A-Za-z0-9_\-]+", "_", str(int(seq)).strip())
    return "%s_srcid-%s_newid-%s_seq-%s.sql" % (safe_fuzzer, safe_seed, safe_new_seed, safe_seq)


def _build_sql_log_newid(*, external_seed_id: int) -> str:
    return "%06d" % int(external_seed_id)


def _log_sql_seed_pair(*, logger: Optional[Logger], seq: int, solution_index: int, sql_log_path: str, seed_path: str, new_seed_id: int) -> None:
    if logger is None:
        return
    try:
        logger.info(
            "sql_seed_pair_written",
            seq=int(seq),
            solution_index=int(solution_index),
            sql_log_path=str(sql_log_path or ""),
            seed_path=str(seed_path or ""),
            new_seed_id=int(new_seed_id),
        )
    except Exception:
        pass


def _log_sql_record_written(*, logger: Optional[Logger], seq: int, solution_index: int, sql_log_path: str, newid: str, seed_path: str) -> None:
    if logger is None:
        return
    try:
        logger.info(
            "sql_record_written",
            seq=int(seq),
            solution_index=int(solution_index),
            sql_log_path=str(sql_log_path or ""),
            newid=str(newid or ""),
            seed_path=str(seed_path or ""),
        )
    except Exception:
        pass


def _solution_sql_records(solution: dict) -> List[str]:
    if not isinstance(solution, dict):
        return []
    norm = _normalize_solution_keys(solution)
    sql_value = norm.get("SQL")
    out: List[str] = []
    if isinstance(sql_value, str):
        sql_s = sql_value.strip()
        if sql_s:
            out.append(sql_s)
    elif isinstance(sql_value, (list, tuple)):
        for item in sql_value:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
            elif isinstance(item, dict):
                sql_s = str(item.get("sql") or "").strip()
                if sql_s:
                    out.append(sql_s)
    return out


def _solution_mods(solution: dict, *, defaults: Optional[dict]) -> List[str]:
    markers = _solution_change_markers(solution, defaults=defaults)
    if "SQL" in markers:
        return markers
    if _solution_sql_records(solution):
        markers = list(markers)
        markers.append("SQL")
    return markers


def _seed_mods_from_solution(solution: dict, *, defaults: Optional[dict], seed_kind_flags: Optional[Dict[str, bool]] = None) -> List[str]:
    markers = _solution_mods(solution, defaults=defaults)
    flags = seed_kind_flags if isinstance(seed_kind_flags, dict) else {}
    out: List[str] = []
    for marker in markers:
        if marker in {"POST", "GET", "COOKIE", "SESSION", "ENV", "SQL", "FILE"} and not bool(flags.get(marker, True)):
            continue
        out.append(marker)
    return out


_ACTIVE_EXIT_RECORDER = None


class AnalyzeExitRecorder:
    def __init__(self, *, run_dir: str, seq: int, heartbeat: "AnalyzeHeartbeat"):
        self.run_dir = os.path.abspath(run_dir)
        self.logs_dir = os.path.join(self.run_dir, "logs")
        self.seq = int(seq)
        self.pid = int(os.getpid())
        self.parent_pid = int(os.getppid())
        self.heartbeat = heartbeat
        self._lock = threading.Lock()
        self._finalized = False
        self._installed = False
        self._previous_handlers = {}
        self._previous_excepthook = None
        self._debug_path = os.path.join(self.logs_dir, "exit_debug.ndjson")

    def install(self) -> None:
        global _ACTIVE_EXIT_RECORDER
        _ACTIVE_EXIT_RECORDER = self
        if self._installed:
            return
        self._installed = True
        self._write_debug("install")
        self._previous_excepthook = sys.excepthook
        sys.excepthook = self._handle_uncaught_exception
        for sig_name in ("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"):
            sig = getattr(signal, sig_name, None)
            if sig is None:
                continue
            try:
                self._previous_handlers[int(sig)] = signal.getsignal(sig)
                signal.signal(sig, self._make_signal_handler(sig_name, int(sig)))
            except Exception:
                continue
        try:
            atexit.register(self._handle_atexit)
        except Exception:
            pass

    def mark_finished(self, status: str, *, reason: str = "", **extra) -> None:
        self._write_debug("mark_finished", status=str(status or ""), reason=str(reason or ""), extra=(extra or {}))
        with self._lock:
            self._finalized = True

    def _snapshot(self) -> dict:
        hb = self.heartbeat._snapshot() if self.heartbeat is not None else {}
        return hb if isinstance(hb, dict) else {}

    def _write_debug(self, event: str, **fields) -> None:
        payload = {
            "ts": _heartbeat_ts(),
            "event": str(event or ""),
            "seq": int(self.seq),
            "pid": int(self.pid),
            "parent_pid": int(self.parent_pid),
            "heartbeat": self._snapshot(),
        }
        for k, v in (fields or {}).items():
            payload[str(k)] = v
        try:
            _append_json_line(self._debug_path, payload)
        except Exception:
            pass

    def _write_exit_record(self, *, status: str, reason: str = "", extra: Optional[dict] = None, allow_overwrite: bool = False) -> None:
        with self._lock:
            if self._finalized and not allow_overwrite:
                return
            if not allow_overwrite or status in ("success", "error", "terminated", "uncaught_exception", "abnormal_exit"):
                self._finalized = True
        payload = {
            "ts": _heartbeat_ts(),
            "status": str(status or ""),
            "reason": str(reason or ""),
            "seq": int(self.seq),
            "pid": int(self.pid),
            "parent_pid": int(self.parent_pid),
            "heartbeat": self._snapshot(),
        }
        if isinstance(extra, dict):
            payload.update(extra)
        try:
            _append_json_line(os.path.join(self.logs_dir, "exit_record.ndjson"), payload)
        except Exception:
            pass

    def _make_signal_handler(self, sig_name: str, sig_num: int):
        def _handler(signum, _frame):
            msg = "received %s" % str(sig_name)
            self._write_debug("signal_received", signal_name=str(sig_name), signal_number=int(sig_num), signum=int(signum))
            try:
                if self.heartbeat is not None:
                    self.heartbeat.finish(
                        "terminated",
                        message=msg,
                        reason="received_signal",
                        signal_name=str(sig_name),
                        signal_number=int(sig_num),
                        exit_code=int(128 + int(sig_num)),
                    )
            except Exception:
                pass
            self._write_exit_record(
                status="terminated",
                reason="received_signal",
                extra={
                    "signal_name": str(sig_name),
                    "signal_number": int(sig_num),
                    "exit_code": int(128 + int(sig_num)),
                },
            )
            raise SystemExit(128 + int(sig_num))
        return _handler

    def _handle_uncaught_exception(self, exc_type, exc_value, exc_tb) -> None:
        try:
            tb_text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        except Exception:
            tb_text = str(exc_value or "")
        self._write_debug(
            "uncaught_exception",
            exception_type=getattr(exc_type, "__name__", str(exc_type)),
            exception_message=str(exc_value or ""),
            traceback=tb_text,
        )
        try:
            if self.heartbeat is not None:
                self.heartbeat.finish(
                    "uncaught_exception",
                    message=str(exc_value or exc_type),
                    reason="uncaught_exception",
                    exception_type=getattr(exc_type, "__name__", str(exc_type)),
                )
        except Exception:
            pass
        self._write_exit_record(
            status="uncaught_exception",
            reason="uncaught_exception",
            extra={
                "exception_type": getattr(exc_type, "__name__", str(exc_type)),
                "exception_message": str(exc_value or ""),
                "traceback": tb_text,
            },
        )
        prev = self._previous_excepthook
        if callable(prev):
            prev(exc_type, exc_value, exc_tb)

    def _handle_atexit(self) -> None:
        if self._finalized:
            return
        hb = self._snapshot()
        self._write_debug(
            "atexit_unfinished",
            heartbeat_stage=str(hb.get("stage") or ""),
            heartbeat_status=str(hb.get("status") or ""),
        )
        try:
            if self.heartbeat is not None:
                self.heartbeat.finish(
                    "abnormal_exit",
                    message="process_exit_without_finish",
                    reason="process_exit_without_finish",
                    heartbeat_stage=str(hb.get("stage") or ""),
                    heartbeat_status=str(hb.get("status") or ""),
                )
        except Exception:
            pass
        self._write_exit_record(
            status="abnormal_exit",
            reason="process_exit_without_finish",
            extra={
                "heartbeat_stage": str(hb.get("stage") or ""),
                "heartbeat_status": str(hb.get("status") or ""),
            },
        )


class AnalyzeHeartbeat:
    def __init__(self, *, run_dir: str, seq: int, interval_seconds: int = 10):
        self.run_dir = os.path.abspath(run_dir)
        self.logs_dir = os.path.join(self.run_dir, "logs")
        self.seq = int(seq)
        self.interval_seconds = max(1, int(interval_seconds))
        self.pid = int(os.getpid())
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._state = {
            "seq": int(self.seq),
            "pid": int(self.pid),
            "status": "starting",
            "stage": "starting",
            "message": "",
            "tick": 0,
            "started_at": _heartbeat_ts(),
            "updated_at": _heartbeat_ts(),
            "finished_at": "",
        }

    def start(self) -> None:
        os.makedirs(self.logs_dir, exist_ok=True)
        self._write_snapshot(event="start", force_log=True)
        self._thread = threading.Thread(target=self._run, name=f"analyze-heartbeat-{self.seq}", daemon=True)
        self._thread.start()

    def update(self, stage: str, *, status: Optional[str] = None, message: str = "", **extra) -> None:
        with self._lock:
            self._state["stage"] = str(stage or "").strip() or self._state.get("stage") or "running"
            if status:
                self._state["status"] = str(status).strip()
            if message:
                self._state["message"] = str(message)
            elif "message" in self._state:
                self._state["message"] = self._state.get("message") or ""
            self._state["updated_at"] = _heartbeat_ts()
            for k, v in (extra or {}).items():
                self._state[str(k)] = v
        self._write_snapshot(event="update", force_log=True)

    def finish(self, status: str, *, message: str = "", **extra) -> None:
        with self._lock:
            self._state["status"] = str(status or "finished").strip() or "finished"
            self._state["stage"] = "finished"
            if message:
                self._state["message"] = str(message)
            self._state["updated_at"] = _heartbeat_ts()
            self._state["finished_at"] = self._state["updated_at"]
            for k, v in (extra or {}).items():
                self._state[str(k)] = v
        self._write_snapshot(event="finish", force_log=True)
        self._stop.set()
        th = self._thread
        if th is not None and th.is_alive():
            th.join(timeout=1.0)

    def _snapshot(self) -> dict:
        with self._lock:
            return dict(self._state)

    def _write_snapshot(self, *, event: str, force_log: bool) -> None:
        snap = self._snapshot()
        status_path = os.path.join(self.logs_dir, "heartbeat.status.json")
        try:
            _atomic_write_json(status_path, snap)
        except Exception:
            pass

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            with self._lock:
                self._state["tick"] = int(self._state.get("tick") or 0) + 1
                self._state["updated_at"] = _heartbeat_ts()
            self._write_snapshot(event="tick", force_log=True)


def _resolve_external_seed_dir(cfg) -> str:
    v = os.environ.get("WC_EXTERNAL_SEED_DIR") or ""
    if isinstance(v, str) and v.strip():
        return os.path.abspath(v.strip())
    raw = cfg.raw if hasattr(cfg, "raw") else {}
    if isinstance(raw, dict):
        v2 = raw.get("external_seed_dir") or ""
        if isinstance(v2, str) and v2.strip():
            return os.path.abspath(os.path.join(cfg.base_dir, v2.strip())) if not os.path.isabs(v2) else os.path.abspath(v2.strip())
        paths = raw.get("paths") if isinstance(raw.get("paths"), dict) else {}
        v3 = paths.get("external_seed_dir") if isinstance(paths, dict) else ""
        if isinstance(v3, str) and v3.strip():
            return os.path.abspath(os.path.join(cfg.base_dir, v3.strip())) if not os.path.isabs(v3) else os.path.abspath(v3.strip())
    prep = _load_prepare_report(cfg)
    work_dir = str(prep.get("work_dir") or "").strip() if isinstance(prep, dict) else ""
    if work_dir:
        return os.path.abspath(os.path.join(work_dir, "extsync", "queue"))
    return os.path.abspath(os.path.join(cfg.base_dir, "..", "extsync", "queue"))


def _resolve_seed_env_parent_dir(cfg) -> str:
    v = os.environ.get("WC_ENV_PARENT_DIR") or ""
    if isinstance(v, str) and v.strip():
        return os.path.abspath(v.strip())
    prep = _load_prepare_report(cfg)
    work_dir = str(prep.get("work_dir") or "").strip() if isinstance(prep, dict) else ""
    if work_dir:
        return os.path.abspath(os.path.join(work_dir, "seed_env_profiles", "parent"))
    return os.path.abspath(os.path.join(cfg.base_dir, "..", "seed_env_profiles", "parent"))


def _write_seed_env_profile(
    *,
    cfg,
    env_id: str,
    env_change_map: Dict[str, Optional[str]],
    logger: Optional[Logger],
    seq: int,
    solution_index: int,
) -> str:
    env_id = str(env_id or "").strip()
    if not env_id or not isinstance(env_change_map, dict) or not env_change_map:
        return ""
    out_dir = _resolve_seed_env_parent_dir(cfg)
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception:
        return ""
    out_path = os.path.join(out_dir, "%s.env" % env_id)
    tmp_path = out_path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8", errors="replace") as wf:
            for key in sorted(str(k).strip() for k in env_change_map.keys() if str(k).strip()):
                value = env_change_map.get(key)
                if value is None:
                    wf.write("%s\n" % key)
                else:
                    wf.write("%s=%s\n" % (key, str(value)))
        os.replace(tmp_path, out_path)
        return out_path
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        if logger is not None:
            try:
                logger.exception(
                    "external_seed_env_profile_write_failed",
                    seq=int(seq),
                    solution_index=int(solution_index),
                    env_id=env_id,
                    path=out_path,
                )
            except Exception:
                pass
        return ""


def _materialize_solution_file_payloads(
    solution: dict,
    *,
    external_seed_id: int,
    seq: int,
    logger: Optional[Logger],
    solution_index: int,
) -> Tuple[Dict[str, object], List[str]]:
    sol2: Dict[str, object] = dict(solution) if isinstance(solution, dict) else {}
    created_paths: List[str] = []
    file_uploads = _solution_file_uploads(sol2)
    file_path_payloads = _solution_file_path_payloads(sol2)
    if not file_uploads and not file_path_payloads:
        return sol2, created_paths

    try:
        os.makedirs(_WITCHER_FILE_TMP_DIR, exist_ok=True)
    except Exception:
        if logger is not None:
            try:
                logger.exception(
                    "symbolic_file_tmp_dir_create_failed",
                    seq=int(seq),
                    solution_index=int(solution_index),
                    dir=_WITCHER_FILE_TMP_DIR,
                )
            except Exception:
                pass
        return sol2, created_paths

    def _write_materialized_file(desc: Dict[str, str]) -> str:
        rand = "%06d" % random.randint(0, 999999)
        filename = _safe_file_name(desc.get("filename"), default="payload.bin")
        out_name = f"seed{int(external_seed_id):06d}_seq{int(seq)}_{rand}_{filename}"
        out_path = os.path.join(_WITCHER_FILE_TMP_DIR, out_name)
        tmp_path = out_path + ".tmp"
        raw = base64.b64decode(str(desc.get("content_base64") or "").encode("ascii"), validate=False)
        with open(tmp_path, "wb") as wf:
            wf.write(raw)
        os.replace(tmp_path, out_path)
        created_paths.append(out_path)
        return out_path

    for block_name in ("POST", "GET", "COOKIE", "ENV", "SESSION"):
        block = sol2.get(block_name)
        if not isinstance(block, dict):
            continue
        for key, value in list(block.items()):
            key_s = str(key or "").strip()
            if not key_s:
                continue
            if str(value or "") == _WITCHER_FILE_UPLOAD_MARKER and key_s in file_uploads:
                desc = file_uploads.get(key_s) or {}
                file_path = _write_materialized_file(desc)
                block[key] = file_path
            elif isinstance(value, str) and value.startswith(_WITCHER_FILE_PATH_PREFIX):
                payload_key = value[len(_WITCHER_FILE_PATH_PREFIX):].strip()
                if not payload_key:
                    continue
                desc = file_path_payloads.get(payload_key)
                if desc is None:
                    continue
                file_path = _write_materialized_file(desc)
                block[key] = file_path
        sol2[block_name] = block

    sol2.pop(_WITCHER_FILE_UPLOAD_FIELD, None)
    sol2.pop(_WITCHER_FILE_PATH_FIELD, None)
    return sol2, created_paths


def _solution_to_afl_seed_bytes(solution: dict, *, defaults: Optional[dict]) -> Optional[bytes]:
    sol = solution if isinstance(solution, dict) else {}
    norm: Dict[str, object] = {}
    for k, v in sol.items():
        if not isinstance(k, str):
            continue
        norm[k.strip().upper()] = v
    defaults = defaults if isinstance(defaults, dict) else {}
    cookie = _effective_request_field(norm, "COOKIE", defaults=defaults, cookie_mode=True)
    get_value = _effective_request_field(norm, "GET", defaults=defaults, cookie_mode=False)
    post_value = _effective_request_field(norm, "POST", defaults=defaults, cookie_mode=False)
    sess_id = ""
    try:
        sess_id = str(norm.get("_WC_PHPSESSID") or "").strip()
    except Exception:
        sess_id = ""
    sess_cookie_name = ""
    try:
        sess_cookie_name = str(norm.get("_WC_SESSION_COOKIE_NAME") or "").strip()
    except Exception:
        sess_cookie_name = ""
    if not sess_cookie_name:
        sess_cookie_name = _resolve_session_cookie_name(defaults)

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
                out.append(((k or "").strip(), v))
            else:
                out.append((part, None))
        return out

    def _cookie_parts_to_text(parts: List[Tuple[str, Optional[str]]]) -> str:
        buf: List[str] = []
        for key, value in parts or []:
            key_s = (key or "").strip()
            if not key_s:
                continue
            if value is None:
                buf.append(key_s)
            else:
                buf.append("%s=%s" % (key_s, value))
        return "&".join(buf).strip("&")

    def _inject_cookie_value(cookie_text: str, cookie_name: str, cookie_value: str) -> str:
        target_name = (cookie_name or "").strip()
        if not target_name:
            return cookie_text or ""
        parts = _cookie_parts_from_text(cookie_text or "")
        out: List[Tuple[str, Optional[str]]] = [(target_name, cookie_value)]
        for key, value in parts:
            if str(key or "").strip().lower() == target_name.lower():
                continue
            out.append((key, value))
        return _cookie_parts_to_text(out)

    cookie = (cookie or "").replace("\x00", "")
    get_value = (get_value or "").replace("\x00", "")
    post_value = (post_value or "").replace("\x00", "")
    if sess_id:
        cid = str(sess_id).strip()
        if cid:
            cookie = _inject_cookie_value(str(cookie or ""), sess_cookie_name, cid)
    if not cookie and not get_value and not post_value:
        return None
    data = (cookie + "\x00" + get_value + "\x00" + post_value + "\x00").encode("utf-8", errors="replace")
    return data if data else None


def _prepare_solution_for_seed(
    solution: dict,
    *,
    cfg,
    seq: int,
    external_seed_id: int,
    solution_index: int,
    defaults: Optional[dict],
    logger: Optional[Logger],
) -> Tuple[Dict[str, object], str, List[str]]:
    sol2: Dict[str, object] = dict(solution) if isinstance(solution, dict) else {}
    sess_id = ""
    sess_file_path = ""
    sess_cookie_name = ""
    created_file_paths: List[str] = []
    if logger is not None:
        try:
            logger.info(
                "prepare_solution_for_seed_start",
                seq=int(seq),
                external_seed_id=int(external_seed_id),
                solution_index=int(solution_index),
                solution_keys=sorted([str(k) for k in sol2.keys()]),
            )
        except Exception:
            pass
    try:
        sess_id, sess_file_path, sess_cookie_name = _prepare_solution_session(
            solution,
            cfg=cfg,
            seq=int(seq),
            external_seed_id=int(external_seed_id),
            solution_index=int(solution_index),
            defaults=defaults,
            logger=logger,
        )
    except Exception:
        if logger is not None:
            logger.exception("prepare_solution_session_failed", seq=int(seq), solution_index=int(solution_index))
        return sol2, "", created_file_paths
    if sess_id:
        sol2["_WC_PHPSESSID"] = str(sess_id)
        sol2["_WC_SESSION_COOKIE_NAME"] = str(sess_cookie_name or "PHPSESSID")
        if logger is not None:
            try:
                logger.info(
                    "prepare_solution_for_seed_session_materialized",
                    seq=int(seq),
                    external_seed_id=int(external_seed_id),
                    solution_index=int(solution_index),
                    session_id=str(sess_id),
                    session_file_path=str(sess_file_path or ""),
                )
            except Exception:
                pass
    elif isinstance(solution, dict):
        norm = _normalize_solution_keys(solution)
        if "SESSION" in norm and logger is not None:
            try:
                logger.warning("session_solution_not_materialized", seq=int(seq), solution_index=int(solution_index))
            except Exception:
                pass
        if logger is not None:
            try:
                logger.info(
                    "prepare_solution_for_seed_no_session_materialized",
                    seq=int(seq),
                    external_seed_id=int(external_seed_id),
                    solution_index=int(solution_index),
                    prepared_solution_keys=sorted([str(k) for k in sol2.keys()]),
                )
            except Exception:
                pass
    try:
        sol2, created_file_paths = _materialize_solution_file_payloads(
            sol2,
            external_seed_id=int(external_seed_id),
            seq=int(seq),
            logger=logger,
            solution_index=int(solution_index),
        )
    except Exception:
        if logger is not None:
            logger.exception("prepare_solution_file_payloads_failed", seq=int(seq), solution_index=int(solution_index))
        return sol2, str(sess_file_path or ""), created_file_paths
    return sol2, str(sess_file_path or ""), created_file_paths


def _seed_generation_debug_fields(solution: dict, prepared_solution: Optional[dict], sess_file_path: str, file_paths: Optional[List[str]] = None) -> Dict[str, object]:
    orig = _normalize_solution_keys(solution if isinstance(solution, dict) else {})
    prep = _normalize_solution_keys(prepared_solution if isinstance(prepared_solution, dict) else {})
    upload_map = _solution_file_uploads(solution if isinstance(solution, dict) else {})
    path_map = _solution_file_path_payloads(solution if isinstance(solution, dict) else {})
    file_paths = list(file_paths or [])
    return {
        "solution_keys": sorted(orig.keys()),
        "prepared_solution_keys": sorted(prep.keys()),
        "has_session": bool("SESSION" in orig),
        "has_cookie": bool("COOKIE" in orig),
        "has_get": bool("GET" in orig),
        "has_post": bool("POST" in orig),
        "has_file_upload_marker": bool(upload_map),
        "has_file_path_marker": bool(path_map),
        "materialized_file_count": len(file_paths),
        "materialized_files": file_paths,
        "cookie_len": len(str(_effective_request_field(orig, "COOKIE", defaults=None, cookie_mode=True) or "")),
        "get_len": len(str(_effective_request_field(orig, "GET", defaults=None, cookie_mode=False) or "")),
        "post_len": len(str(_effective_request_field(orig, "POST", defaults=None, cookie_mode=False) or "")),
        "prepared_cookie_len": len(str(_effective_request_field(prep, "COOKIE", defaults=None, cookie_mode=True) or "")),
        "prepared_get_len": len(str(_effective_request_field(prep, "GET", defaults=None, cookie_mode=False) or "")),
        "prepared_post_len": len(str(_effective_request_field(prep, "POST", defaults=None, cookie_mode=False) or "")),
        "has_wc_phpsessid": bool(str(prep.get("_WC_PHPSESSID") or "").strip()),
        "session_file_path": str(sess_file_path or ""),
        "session_file_exists": bool(sess_file_path and os.path.exists(sess_file_path)),
    }


def _try_lock_file(fp) -> bool:
    try:
        import fcntl  # type: ignore
        try:
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except Exception:
            return False
    except Exception:
        pass
    try:
        import msvcrt  # type: ignore
        try:
            fp.seek(0)
        except Exception:
            pass
        try:
            msvcrt.locking(fp.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except Exception:
            return False
    except Exception:
        return False


def _unlock_file(fp) -> None:
    try:
        import fcntl  # type: ignore
        try:
            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        return
    except Exception:
        pass
    try:
        import msvcrt  # type: ignore
        try:
            fp.seek(0)
        except Exception:
            pass
        try:
            msvcrt.locking(fp.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
    except Exception:
        return


def _alloc_external_seed_id(out_dir: str) -> Optional[int]:
    base_dir = ""
    try:
        base_dir = os.path.dirname(os.path.abspath(out_dir.rstrip("\\/")))
    except Exception:
        base_dir = ""
    counter_dir = base_dir if base_dir and os.path.isdir(base_dir) else os.path.abspath(out_dir)
    try:
        os.makedirs(counter_dir, exist_ok=True)
    except Exception:
        pass
    counter_path = os.path.join(counter_dir, "latest_id")
    while True:
        fp = None
        try:
            fp = open(counter_path, "a+b")
        except Exception:
            return None
        try:
            if not _try_lock_file(fp):
                try:
                    fp.close()
                except Exception:
                    pass
                time.sleep(random.uniform(0.01, 0.1))
                continue
            try:
                fp.seek(0)
                raw = fp.read()
            except Exception:
                raw = b""
            cur = -1
            try:
                s = (raw or b"").decode("utf-8", errors="ignore").strip()
                if s:
                    cur = int(s)
            except Exception:
                cur = -1
            nxt = int(cur) + 1
            try:
                fp.seek(0)
                fp.truncate(0)
                fp.write((str(int(nxt)) + "\n").encode("utf-8"))
                fp.flush()
                try:
                    os.fsync(fp.fileno())
                except Exception:
                    pass
            except Exception:
                return None
            return int(nxt)
        finally:
            try:
                _unlock_file(fp)
            except Exception:
                pass
            try:
                fp.close()
            except Exception:
                pass


def _write_external_seeds_from_solutions(
    solutions: List[dict],
    *,
    cfg,
    seq: int,
    defaults: Optional[dict],
    logger: Optional[Logger] = None,
    seed_kind_flags: Optional[Dict[str, bool]] = None,
) -> List[Dict[str, object]]:
    solutions = _filter_solutions_by_seed_kinds(solutions, seed_kind_flags=seed_kind_flags)
    out_dir = _resolve_external_seed_dir(cfg)
    env_parent_dir = _resolve_seed_env_parent_dir(cfg)
    parent_seed_info = _resolve_parent_seed_id_info()
    parent_seed_id = str(parent_seed_info.get("resolved_parent_seed_id") or "unknown")
    parent_seed_source = str(parent_seed_info.get("source") or "unknown")
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception:
        return []
    try:
        os.makedirs(env_parent_dir, exist_ok=True)
    except Exception:
        pass
    current_defaults = _merge_defaults_with_base_inputs(defaults, _load_prompt_base_inputs_for_parent_seed(cfg))
    env_enabled = bool((seed_kind_flags or {}).get("ENV", True))
    session_enabled = bool((seed_kind_flags or {}).get("SESSION", True))
    cookie_enabled = bool((seed_kind_flags or {}).get("COOKIE", True))
    get_enabled = bool((seed_kind_flags or {}).get("GET", True))
    post_enabled = bool((seed_kind_flags or {}).get("POST", True))
    sql_enabled = bool((seed_kind_flags or {}).get("SQL", True))
    file_enabled = bool((seed_kind_flags or {}).get("FILE", True))
    seed_records: List[Dict[str, object]] = []
    wrote: List[str] = []
    for i, sol in enumerate(solutions or []):
        if logger is not None:
            try:
                logger.info(
                    "external_seed_solution_start",
                    seq=int(seq),
                    solution_index=int(i),
                    solution_keys=sorted([str(k) for k in sol.keys()]) if isinstance(sol, dict) else [],
                    out_dir=out_dir,
                )
            except Exception:
                pass
        sid = _alloc_external_seed_id(out_dir)
        if sid is None:
            if logger is not None:
                try:
                    logger.warning(
                        "external_seed_alloc_id_failed",
                        seq=int(seq),
                        solution_index=int(i),
                        out_dir=out_dir,
                    )
                except Exception:
                    pass
            continue
        env_marker_map = _env_change_map_from_solution(sol if isinstance(sol, dict) else {}, defaults=current_defaults) if env_enabled else {}
        effective_env_map = _apply_env_solution_to_defaults(sol if isinstance(sol, dict) else {}, defaults=current_defaults) if env_enabled else _env_defaults_to_map(defaults)
        env_change_map = _diff_env_maps(_env_defaults_to_map(defaults), effective_env_map) if env_enabled else {}
        env_id = ("%06d" % int(sid)) if env_change_map else ""
        if logger is not None:
            try:
                logger.info(
                    "external_seed_solution_env_diff",
                    seq=int(seq),
                    solution_index=int(i),
                    external_seed_id=int(sid),
                    has_env_change=bool(env_change_map),
                    env_id=env_id,
                    env_marker_count=len(env_marker_map or {}),
                )
            except Exception:
                pass
        sol2, sess_file_path, created_file_paths = _prepare_solution_for_seed(
            sol,
            cfg=cfg,
            seq=int(seq),
            external_seed_id=int(sid),
            solution_index=int(i),
            defaults=defaults,
            logger=logger,
        )
        if not session_enabled:
            sol2.pop("SESSION", None)
            sol2.pop("_WC_PHPSESSID", None)
            sol2.pop("_WC_SESSION_COOKIE_NAME", None)
            sess_file_path = ""
        if not cookie_enabled:
            sol2.pop("COOKIE", None)
            sol2.pop("_WC_PHPSESSID", None)
            sol2.pop("_WC_SESSION_COOKIE_NAME", None)
        if not get_enabled:
            sol2.pop("GET", None)
        if not post_enabled:
            sol2.pop("POST", None)
        if not env_enabled:
            sol2.pop("ENV", None)
            sol2.pop("_WC_ENV_ID", None)
        if not sql_enabled:
            sol2.pop("SQL", None)
            sol2.pop("DB_REQUEST", None)
            sol2.pop("DB_QUERY", None)
            sol2.pop("DBREQUEST", None)
        if not file_enabled:
            sol2.pop(_WITCHER_FILE_UPLOAD_FIELD, None)
            sol2.pop(_WITCHER_FILE_PATH_FIELD, None)
            created_file_paths = []
        if env_enabled and env_id:
            sol2["_WC_ENV_ID"] = env_id
        data = _solution_to_afl_seed_bytes(sol2, defaults=defaults)
        if logger is not None:
            try:
                debug_fields = _seed_generation_debug_fields(sol if isinstance(sol, dict) else {}, sol2, sess_file_path, created_file_paths)
                logger.info(
                    "external_seed_bytes_built",
                    seq=int(seq),
                    solution_index=int(i),
                    external_seed_id=int(sid),
                    has_request_bytes=bool(data),
                    request_bytes_len=len(data or b""),
                    **debug_fields,
                )
            except Exception:
                pass
        if not data:
            if logger is not None:
                try:
                    logger.warning(
                        "external_seed_skipped_no_request_bytes",
                        seq=int(seq),
                        solution_index=int(i),
                        external_seed_id=int(sid),
                        **_seed_generation_debug_fields(sol if isinstance(sol, dict) else {}, sol2, sess_file_path, created_file_paths),
                    )
                except Exception:
                    pass
            try:
                if sess_file_path and os.path.exists(sess_file_path):
                    os.remove(sess_file_path)
                for file_path in created_file_paths:
                    if file_path and os.path.exists(file_path):
                        os.remove(file_path)
            except Exception:
                pass
            continue
        name = _build_external_seed_name(
            external_seed_id=int(sid),
            seq=int(seq),
            solution_index=int(i),
            solution=sol2,
            defaults=current_defaults,
            seed_kind_flags=seed_kind_flags,
        )
        if logger is not None:
            try:
                logger.info(
                    "external_seed_name_built",
                    seq=int(seq),
                    solution_index=int(i),
                    external_seed_id=int(sid),
                    name=name,
                )
            except Exception:
                pass
        tmp_path = os.path.join(out_dir, "." + name + ".tmp")
        out_path = os.path.join(out_dir, name)
        try:
            with open(tmp_path, "wb") as wf:
                wf.write(data)
            os.replace(tmp_path, out_path)
        except Exception:
            if logger is not None:
                try:
                    logger.exception(
                        "external_seed_write_failed",
                        seq=int(seq),
                        solution_index=int(i),
                        external_seed_id=int(sid),
                        out_path=out_path,
                        tmp_path=tmp_path,
                    )
                except Exception:
                    pass
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            try:
                if sess_file_path and os.path.exists(sess_file_path):
                    os.remove(sess_file_path)
                for file_path in created_file_paths:
                    if file_path and os.path.exists(file_path):
                        os.remove(file_path)
            except Exception:
                pass
            continue
        sql_newid = _build_sql_log_newid(external_seed_id=int(sid))
        _log_sql_seed_pair(
            logger=logger,
            seq=int(seq),
            solution_index=int(i),
            sql_log_path=out_path,
            seed_path=out_path,
            new_seed_id=int(sid),
        )
        _log_sql_record_written(
            logger=logger,
            seq=int(seq),
            solution_index=int(i),
            sql_log_path=out_path,
            newid=sql_newid,
            seed_path=out_path,
        )
        env_profile_path = ""
        if env_id:
            env_profile_path = _write_seed_env_profile(
                cfg=cfg,
                env_id=env_id,
                env_change_map=env_change_map,
                logger=logger,
                seq=int(seq),
                solution_index=int(i),
            )
        wrote.append(out_path)
        seed_records.append(
            {
                "solution_index": int(i),
                "seed_id": int(sid),
                "seed_path": str(out_path or ""),
                "seed_name": str(name or ""),
                "mods": _seed_mods_from_solution(sol2, defaults=current_defaults, seed_kind_flags=seed_kind_flags),
            }
        )
        if logger is not None:
            try:
                logger.info(
                    "external_seed_written",
                    path=out_path,
                    bytes=len(data),
                    seq=int(seq),
                    parent_seed_id=parent_seed_id,
                    parent_seed_source=parent_seed_source,
                    env_marker_count=len(env_marker_map or {}),
                    env_id=env_id,
                    env_profile_path=env_profile_path,
                )
            except Exception:
                pass
    if logger is not None:
        try:
            logger.info("external_seed_write_done", dir=out_dir, seq=int(seq), count=len(wrote))
        except Exception:
            pass
    return seed_records


def _load_symbolic_seed_kind_flags_for_cfg(cfg=None) -> Dict[str, bool]:
    config_path = None
    try:
        config_path = str(getattr(cfg, "config_path", "") or "") or None
    except Exception:
        config_path = None
    try:
        return load_symbolic_seed_kind_flags(config_path=config_path)
    except Exception:
        return load_symbolic_seed_kind_flags()


def _normalize_solution_keys(solution: dict) -> Dict[str, object]:
    out: Dict[str, object] = {}
    if not isinstance(solution, dict):
        return out
    for k, v in solution.items():
        if not isinstance(k, str):
            continue
        out[k.strip().upper()] = v
    return out


def _filter_solution_by_seed_kinds(solution: dict, *, seed_kind_flags: Optional[Dict[str, bool]]) -> Dict[str, object]:
    norm = _normalize_solution_keys(solution)
    flags = seed_kind_flags if isinstance(seed_kind_flags, dict) else {}
    if not norm:
        return {}
    file_upload_field = str(_WITCHER_FILE_UPLOAD_FIELD or "").strip().upper()
    file_path_field = str(_WITCHER_FILE_PATH_FIELD or "").strip().upper()
    out: Dict[str, object] = {}
    for key, value in norm.items():
        if key in {"POST", "GET", "COOKIE", "SESSION", "ENV", "SQL"} and not bool(flags.get(key, True)):
            continue
        if key in {"DB_REQUEST", "DB_QUERY", "DBREQUEST"} and not bool(flags.get("SQL", True)):
            continue
        if key in {file_upload_field, file_path_field} and not bool(flags.get("FILE", True)):
            continue
        out[key] = value

    if not bool(flags.get("FILE", True)):
        for block_name in ("POST", "GET", "COOKIE", "ENV", "SESSION"):
            block = out.get(block_name)
            if not isinstance(block, dict):
                continue
            cleaned: Dict[str, object] = {}
            for sub_key, sub_value in block.items():
                if isinstance(sub_value, str):
                    if sub_value == _WITCHER_FILE_UPLOAD_MARKER:
                        continue
                    if sub_value.startswith(_WITCHER_FILE_PATH_PREFIX):
                        continue
                cleaned[sub_key] = sub_value
            out[block_name] = cleaned
    return out


def _filter_solutions_by_seed_kinds(solutions: List[dict], *, seed_kind_flags: Optional[Dict[str, bool]]) -> List[dict]:
    out: List[dict] = []
    for sol in solutions or []:
        if not isinstance(sol, dict):
            continue
        out.append(_filter_solution_by_seed_kinds(sol, seed_kind_flags=seed_kind_flags))
    return out


def _env_change_map_from_solution(solution: dict, *, defaults: Optional[dict]) -> Dict[str, Optional[str]]:
    norm = _normalize_solution_keys(solution)
    if "ENV" not in norm:
        return {}
    base_map = _env_defaults_to_map(defaults)
    effective_map = _apply_env_solution_to_defaults(norm, defaults=defaults)
    return _diff_env_maps(base_map, effective_map)



def _load_prepare_report(cfg) -> dict:
    path = ""
    base_dir = ""
    try:
        base_dir = os.path.abspath(str(getattr(cfg, "base_dir", "") or ""))
    except Exception:
        base_dir = ""
    candidates = []
    if base_dir:
        cur = base_dir
        for _ in range(8):
            candidates.append(os.path.join(cur, "meta", "prepare_report.json"))
            parent = os.path.dirname(cur)
            if not parent or parent == cur:
                break
            cur = parent
    try:
        cwd = os.path.abspath(os.getcwd())
    except Exception:
        cwd = ""
    if cwd:
        cur = cwd
        for _ in range(6):
            candidates.append(os.path.join(cur, "meta", "prepare_report.json"))
            parent = os.path.dirname(cur)
            if not parent or parent == cur:
                break
            cur = parent
    seen = set()
    for cand in candidates:
        p = os.path.abspath(cand)
        if p in seen:
            continue
        seen.add(p)
        if os.path.isfile(p):
            path = p
            break
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _safe_rmtree(p: str) -> None:
    """Best-effort recursive delete for a directory path."""
    if not p:
        return
    if not os.path.exists(p):
        return
    try:
        shutil.rmtree(p)
    except Exception:
        return


def clean_previous_test_outputs(test_dir: str, seq: Optional[int] = None) -> None:
    """Remove prior test outputs (logs/prompts/rounds and optional output json) for a run."""
    if not test_dir:
        return
    try:
        os.makedirs(test_dir, exist_ok=True)
    except Exception:
        pass
    _safe_rmtree(os.path.join(test_dir, 'logs'))
    _safe_rmtree(os.path.join(test_dir, 'rounds'))
    _safe_rmtree(os.path.join(test_dir, 'symbolic'))
    _safe_rmtree(os.path.join(test_dir, 'llm'))
    _safe_rmtree(os.path.join(test_dir, 'pattern'))
    if seq is not None:
        try:
            out_path = os.path.join(test_dir, f"analysis_output_{int(seq)}.json")
        except Exception:
            out_path = ''
        if out_path and os.path.exists(out_path):
            try:
                os.remove(out_path)
            except Exception:
                pass


def clean_llm_io_dirs(test_dir: str, *, llm_mode: bool, llm_test_mode: bool) -> None:
    if not test_dir or not llm_mode:
        return
    _safe_rmtree(os.path.join(test_dir, 'llm'))


def _resolve_output_root(cfg) -> str:
    raw = cfg.raw if hasattr(cfg, 'raw') else {}
    paths = raw.get('paths') if isinstance(raw, dict) else {}
    output_dir = ''
    if isinstance(paths, dict):
        output_dir = paths.get('output_dir') or ''
    if not output_dir and isinstance(raw, dict):
        output_dir = raw.get('output_dir') or ''
    output_dir = (output_dir or 'output').strip()
    if not output_dir:
        output_dir = 'output'
    if os.path.isabs(output_dir):
        return os.path.abspath(output_dir)
    return os.path.abspath(os.path.join(cfg.base_dir, output_dir))
 
def read_trace_line(n, trace_path: Optional[str] = None):
    """Read `trace.log` line N and return a normalized `path:line` locator string."""
    p = trace_path or os.path.join(os.getcwd(), 'trace.log')
    with open(p, 'r', encoding='utf-8', errors='replace') as f:
        i = 0
        for line in f:
            i += 1
            if i == n:
                line = line.strip()
                if not line:
                    return None
                prefix = line.split(' | ', 1)[0]
                if ':' not in prefix:
                    return None
                path_part, line_part = prefix.rsplit(':', 1)
                try:
                    ln = int(line_part)
                except:
                    return None
                return f"{path_part}:{ln}"
    return None
 
def node_display(nid, nodes, children_of):
    """Return a best-effort `(type, name)` display for a CPG node id."""
    nx = nodes.get(nid) or {}
    t = nx.get('type') or ''
    def sorted_children(xid: int) -> List[int]:
        ch = list(children_of.get(int(xid), []) or [])
        ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
        out = []
        for c in ch:
            try:
                out.append(int(c))
            except Exception:
                continue
        return out
    def static_call_name(call_id: int) -> str:
        class_name = ''
        method_name = ''
        for c in sorted_children(int(call_id)):
            cx = nodes.get(c) or {}
            ct = (cx.get('type') or '').strip()
            if ct == 'AST_NAME' and not class_name:
                ss = get_string_children(c, children_of, nodes)
                class_name = (ss[0][1] if ss else '').strip()
                continue
            if not method_name and (cx.get('labels') == 'string' or ct == 'string'):
                v = (cx.get('code') or cx.get('name') or '').strip()
                if v:
                    method_name = v
        if class_name and method_name:
            return f"{class_name}::{method_name}"
        return method_name or class_name
    def expr_str(xid: Optional[int], depth: int = 0, seen: Optional[Set[int]] = None) -> str:
        if xid is None:
            return ''
        try:
            x = int(xid)
        except Exception:
            return ''
        if depth > 10:
            return ''
        if seen is None:
            seen = set()
        if x in seen:
            return ''
        seen.add(x)
        xx = nodes.get(x) or {}
        tt = (xx.get('type') or '').strip()
        if tt == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes)
            return (ss[0][1] if ss else '').strip()
        if tt == 'AST_PROP':
            base_id = None
            prop_token = ''
            for c in sorted_children(x):
                cx = nodes.get(c) or {}
                ctt = (cx.get('type') or '').strip()
                if ctt == 'AST_ARG_LIST':
                    continue
                if cx.get('labels') == 'string' or ctt == 'string':
                    v = (cx.get('code') or cx.get('name') or '').strip()
                    if v and not prop_token:
                        prop_token = v
                    continue
                if base_id is None:
                    base_id = c
            base_s = expr_str(base_id, depth + 1, seen) if base_id is not None else ''
            if not base_s:
                base_s = (find_first_var_string(x, children_of, nodes) or '').strip()
            if not prop_token:
                ss = get_string_children(x, children_of, nodes)
                prop_token = (ss[0][1] if ss else '').strip()
            if base_s and prop_token:
                return f"{base_s}->{prop_token}"
            return (xx.get('code') or xx.get('name') or '').strip().replace('.', '->')
        if tt == 'AST_DIM':
            ch = sorted_children(x)
            base_id = ch[0] if len(ch) >= 1 else None
            key_id = ch[1] if len(ch) >= 2 else None
            base_s = expr_str(base_id, depth + 1, seen) if base_id is not None else ''
            if not base_s:
                base_s = (find_first_var_string(x, children_of, nodes) or '').strip()
            key_s = expr_str(key_id, depth + 1, seen) if key_id is not None else ''
            if not key_s:
                ss = get_string_children(x, children_of, nodes)
                key_s = (ss[0][1] if ss else '').strip()
            if base_s and key_s:
                return f"{base_s}[{key_s}]"
            return (xx.get('code') or xx.get('name') or '').strip().replace('.', '->')
        if tt == 'AST_METHOD_CALL':
            fn = ''
            recv_id = None
            for c in sorted_children(x):
                cx = nodes.get(c) or {}
                ctt = (cx.get('type') or '').strip()
                if ctt == 'AST_ARG_LIST':
                    continue
                if cx.get('labels') == 'string' or ctt == 'string':
                    v = (cx.get('code') or cx.get('name') or '').strip()
                    if v and not fn:
                        fn = v
                    continue
                if recv_id is None:
                    recv_id = c
            recv = expr_str(recv_id, depth + 1, seen) if recv_id is not None else ''
            if fn and not fn.endswith('()'):
                fn = f"{fn}()"
            if recv:
                recv = recv.replace('.', '->')
            return f"{recv}->{fn}" if recv and fn else (fn or '')
        if tt == 'AST_CALL':
            fn = ''
            for c in sorted_children(x):
                cx = nodes.get(c) or {}
                ctt = (cx.get('type') or '').strip()
                if ctt == 'AST_ARG_LIST':
                    continue
                if cx.get('labels') == 'string' or ctt == 'string':
                    v = (cx.get('code') or cx.get('name') or '').strip()
                    if v and not fn:
                        fn = v
                if ctt == 'AST_NAME' and not fn:
                    ss = get_string_children(c, children_of, nodes)
                    if ss:
                        fn = (ss[0][1] or '').strip()
            if fn and not fn.endswith('()'):
                fn = f"{fn}()"
            return fn
        if tt == 'AST_STATIC_CALL':
            fn = static_call_name(x)
            if fn and not fn.endswith('()'):
                fn = f"{fn}()"
            return fn
        if tt in ('AST_CONST', 'AST_NAME', 'string', 'integer', 'double'):
            ss = get_all_string_descendants(x, children_of, nodes)
            if ss:
                return (ss[0][1] or '').strip()
            return (xx.get('code') or xx.get('name') or '').strip()
        return (xx.get('code') or xx.get('name') or '').strip().replace('.', '->')
    if t == 'AST_VAR':
        ss = get_string_children(nid, children_of, nodes)
        return t, (ss[0][1] if ss else '')
    if t == 'AST_METHOD_CALL':
        ss = get_string_children(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_CALL':
        ss = get_all_string_descendants(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_STATIC_CALL':
        nm = static_call_name(int(nid))
        if nm:
            return t, nm
        ss = get_all_string_descendants(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_PROP':
        return t, expr_str(int(nid))
    if t == 'AST_DIM':
        return t, expr_str(int(nid))
    if t in ('AST_CONST', 'AST_NAME', 'string', 'integer', 'double'):
        ss = get_all_string_descendants(nid, children_of, nodes)
        if ss:
            return t, ss[0][1]
        return t, (nx.get('code') or nx.get('name') or '')
    return t, (nx.get('code') or nx.get('name') or '')
 
def dim_index_roots(dim_id, nodes, children_of):
    """Return index expression roots for an `AST_DIM` node (excluding the base)."""
    ch = list(children_of.get(dim_id, []) or [])
    if len(ch) < 2:
        return []
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    return ch[1:]
 
def extract_dim_index_taints(dim_id, nodes, children_of):
    """Collect variable-like taints from the index expression(s) of an `AST_DIM` node."""
    roots = dim_index_roots(dim_id, nodes, children_of)
    if not roots:
        return []
    allowed = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL'}
    out = []
    seen = set()
    seen_index_literals = set()
    q = list(roots)
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        nx = nodes.get(x) or {}
        xt = (nx.get('type') or '').strip()
        xl = (nx.get('labels') or '').strip()
        if xl == 'string' or xt == 'string':
            v = (nx.get('code') or nx.get('name') or '').strip().strip("'\"")
            if v and v not in seen_index_literals:
                seen_index_literals.add(v)
                out.append({'id': x, 'type': 'AST_VAR', 'name': v})
            continue
        t, nm = node_display(x, nodes, children_of)
        if t in ('AST_CONST', 'AST_NAME') and nm:
            v = (nm or '').strip().strip("'\"")
            if v and v not in seen_index_literals:
                seen_index_literals.add(v)
                out.append({'id': x, 'type': 'AST_VAR', 'name': v})
        elif t in allowed:
            rec = {'id': x, 'type': t}
            if nm:
                rec['name'] = nm
            out.append(rec)
        for c in children_of.get(x, []) or []:
            q.append(c)
    return out


def _init_extract_result() -> dict:
    return {
        'vars': [],
        'dims': [],
        'props': [],
        'consts': [],
        'calls': [],
        'isset': [],
        'empty': [],
        'class_consts': [],
        'static_props': [],
        'instanceof': [],
        'conditional': [],
        'binary_ops': [],
        'unary_ops': []
    }


def _handle_extracted_node(x: int, result: dict, nodes, children_of, parent_of):
    nx = nodes.get(x) or {}
    t = (nx.get('type') or '').strip()
    if t == 'AST_VAR':
        ss = get_string_children(x, children_of, nodes)
        name = ss[0][1] if ss else ''
        result['vars'].append({'id': x, 'name': name})
        return
    if t == 'AST_DIM':
        ch = list(children_of.get(x, []) or [])
        ch.sort(key=lambda y: (nodes.get(y) or {}).get('childnum') if (nodes.get(y) or {}).get('childnum') is not None else 10**9)
        base_id = None
        key_id = None
        if len(ch) >= 1:
            base_id = ch[0]
        if len(ch) >= 2:
            key_id = ch[1]
        base_nm = ''
        if base_id is not None:
            _, base_nm = node_display(int(base_id), nodes, children_of)
        if not base_nm:
            base_nm = find_first_var_string(x, children_of, nodes)
        key = ''
        if key_id is not None:
            try:
                _, key_nm = node_display(int(key_id), nodes, children_of)
            except Exception:
                key_nm = ''
            key = (key_nm or '').strip()
        if not key:
            parts = [v for _, v in get_string_children(x, children_of, nodes)]
            key = parts[0] if parts else ''
        result['dims'].append({'id': x, 'base': base_nm, 'key': key})
        return
    if t == 'AST_PROP':
        ch = list(children_of.get(x, []) or [])
        ch.sort(key=lambda y: (nodes.get(y) or {}).get('childnum') if (nodes.get(y) or {}).get('childnum') is not None else 10**9)
        base_id = None
        for c in ch:
            nc = nodes.get(c) or {}
            ctt = (nc.get('type') or '').strip()
            if ctt == 'AST_ARG_LIST':
                continue
            if nc.get('labels') == 'string' or ctt == 'string':
                continue
            base_id = c
            break
        base_nm = ''
        if base_id is not None:
            _, base_nm = node_display(int(base_id), nodes, children_of)
        if not base_nm:
            base_nm = find_first_var_string(x, children_of, nodes)
        prop = ''
        if len(ch) >= 2:
            try:
                _, prop_nm = node_display(int(ch[1]), nodes, children_of)
            except Exception:
                prop_nm = ''
            prop = (prop_nm or '').strip()
        if not prop:
            parts = [v for _, v in get_string_children(x, children_of, nodes)]
            prop = parts[0] if parts else ''
        result['props'].append({'id': x, 'base': base_nm, 'prop': prop})
        return
    if t == 'AST_CONST':
        parts = [v for _, v in get_all_string_descendants(x, children_of, nodes)]
        result['consts'].append({'id': x, 'type': 'AST_CONST', 'name': parts[0] if parts else ''})
        return
    if t == 'AST_NAME':
        parts = [v for _, v in get_all_string_descendants(x, children_of, nodes)]
        v = parts[0] if parts else (nx.get('code') or nx.get('name') or '')
        result['consts'].append({'id': x, 'type': 'AST_NAME', 'name': v})
        return
    if t in ('string', 'integer', 'double'):
        pt = ''
        if isinstance(parent_of, dict):
            try:
                pid = parent_of.get(x)
                pt = (nodes.get(pid) or {}).get('type') if pid is not None else ''
            except Exception:
                pt = ''
        if (pt or '').strip() in ('AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL', 'AST_CLASS_CONST', 'AST_STATIC_PROP'):
            return
        v = (nx.get('code') or nx.get('name') or '').strip()
        result['consts'].append({'id': x, 'type': t, 'name': v})
        return
    if t == 'AST_METHOD_CALL':
        fn = ''
        recv = ''
        recv_id = None
        for c in children_of.get(x, []) or []:
            nc = nodes.get(c) or {}
            if nc.get('type') == 'AST_VAR':
                ssc = get_string_children(c, children_of, nodes)
                recv = ssc[0][1] if ssc else ''
                if recv_id is None:
                    recv_id = c
            if nc.get('labels') == 'string' or nc.get('type') == 'string':
                vv = nc.get('code') or nc.get('name') or ''
                if vv:
                    fn = vv
            if recv_id is None and nc.get('type') != 'AST_ARG_LIST' and nc.get('labels') != 'string' and nc.get('type') != 'string':
                recv_id = c
                _, recv_nm = node_display(c, nodes, children_of)
                recv = recv_nm
        fn = (fn or '').replace('.', '->').strip()
        recv = (recv or '').replace('.', '->').strip()
        if fn.endswith('()'):
            fn = fn[:-2]
        if '->' in fn:
            head, tail = fn.split('->', 1)
            head = head.lstrip('$')
            recv_tail = (recv.split('->')[-1] if recv else '').lstrip('$')
            if recv and head and recv_tail and head == recv_tail and tail:
                fn = tail
            elif not recv and head and tail:
                recv = head
                fn = tail
        arg_list_id = None
        for c in children_of.get(x, []) or []:
            nc = nodes.get(c) or {}
            if nc.get('type') == 'AST_ARG_LIST':
                arg_list_id = c
        result['calls'].append({'id': x, 'kind': 'method_call', 'name': fn, 'recv': recv, 'recv_id': recv_id, 'arg_list_id': arg_list_id})
        return
    if t == 'AST_CALL':
        fn = ''
        for c in children_of.get(x, []) or []:
            nc = nodes.get(c) or {}
            if nc.get('labels') == 'string' or nc.get('type') == 'string':
                vv = nc.get('code') or nc.get('name') or ''
                if vv:
                    fn = vv
            if nc.get('type') == 'AST_NAME':
                ssc = get_string_children(c, children_of, nodes)
                if ssc:
                    fn = ssc[0][1]
        arg_list_id = None
        for c in children_of.get(x, []) or []:
            nc = nodes.get(c) or {}
            if nc.get('type') == 'AST_ARG_LIST':
                arg_list_id = c
        result['calls'].append({'id': x, 'kind': 'call', 'name': fn, 'arg_list_id': arg_list_id})
        return
    if t == 'AST_STATIC_CALL':
        fn = ''
        cls = ''
        for c in children_of.get(x, []) or []:
            nc = nodes.get(c) or {}
            ct = (nc.get('type') or '').strip()
            if ct == 'AST_NAME' and not cls:
                ssc = get_string_children(c, children_of, nodes)
                cls = ssc[0][1] if ssc else ''
            if (nc.get('labels') == 'string' or ct == 'string') and not fn:
                vv = nc.get('code') or nc.get('name') or ''
                if vv:
                    fn = vv
        name = f"{cls}::{fn}" if cls and fn else (fn or cls)
        arg_list_id = None
        for c in children_of.get(x, []) or []:
            nc = nodes.get(c) or {}
            if nc.get('type') == 'AST_ARG_LIST':
                arg_list_id = c
        result['calls'].append({'id': x, 'kind': 'static_call', 'name': name, 'arg_list_id': arg_list_id})
        return

def _normalize_literal_var_name(name: str) -> str:
    v = (name or '').strip().strip("'\"")
    try:
        from taint_handlers.llm.splits.llm_var_split import _pick_identifier
    except Exception:
        _pick_identifier = None
    if _pick_identifier:
        got = _pick_identifier(v)
        if got:
            return got
    return v

def _literal_var_name_from_node(nid, nodes, children_of) -> str:
    _, nm = node_display(nid, nodes, children_of)
    return _normalize_literal_var_name(nm)

def _collect_literal_vars_from_arg_list(arg_list_id, nodes, children_of):
    if arg_list_id is None:
        return []
    out = []
    seen = set()
    q = [arg_list_id]
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        nx = nodes.get(x) or {}
        t = (nx.get('type') or '').strip()
        if t in ('string', 'AST_CONST', 'AST_NAME', 'integer', 'double'):
            nm = _literal_var_name_from_node(x, nodes, children_of)
            if nm:
                out.append({'id': x, 'type': 'AST_VAR', 'name': nm})
        for c in children_of.get(x, []) or []:
            q.append(c)
    return out
 
def build_initial_taints(st, nodes, children_of, parent_of):
    """Build initial taint seeds from the full entry expression roots."""
    from taint_handlers.pattern.initial_taints import build_initial_taints_for_statement

    return build_initial_taints_for_statement(st, nodes, children_of, parent_of)

IF_LLM_TAINT_TEMPLATE = (
    "You are a code analysis assistant. In the following code, identify "
    "all variables and function calls that could affect the value of the boolean quantity ({name})"
    + _DEFAULT_LLM_TAINT_TEMPLATE_TAIL
)

def _if_prompt_name(st, trace_index_path: str, scope_root: str, windows_root: str) -> str:
    p = st.get('path')
    ln = st.get('line')
    seq = st.get('seq')
    if not p or ln is None or seq is None:
        return ''
    loc = {'seq': int(seq), 'path': p, 'line': int(ln), 'loc': f"{p}:{int(ln)}"}
    try:
        lines = map_result_set_to_source_lines(scope_root, [loc], trace_index_path=trace_index_path, windows_root=windows_root)
    except Exception:
        lines = []
    for it in lines or []:
        if it.get('seq') == seq:
            return (it.get('code') or '').strip()
    return ''

def _extract_if_condition_expr(code_line: str) -> str:
    s = (code_line or '').strip()
    if not s:
        return ''
    m = re.search(r'(^|[^A-Za-z0-9_])(?:else\s+)?if\s*\(', s)
    if not m:
        return ''
    open_i = s.find('(', m.end() - 1)
    if open_i < 0:
        return ''
    depth = 0
    close_i = -1
    for i in range(open_i, len(s)):
        ch = s[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                close_i = i
                break
    if close_i <= open_i:
        return ''
    return (s[open_i + 1 : close_i] or '').strip()

def build_if_initial_taint(st, nodes, children_of, parent_of, trace_index_path: str, scope_root: str, windows_root: str):
    return build_initial_taints(st, nodes, children_of, parent_of)

def handle_if_taint(t, ctx):
    inner = t.get('_if_inner_taints') if isinstance(t, dict) else None
    inner = inner if isinstance(inner, list) else []
    results = []
    if isinstance(ctx, dict):
        rs = ctx.get('result_set')
        if rs is None:
            rs = []
            ctx['result_set'] = rs
    else:
        rs = []
    before = len(rs)
    for it in inner:
        if not isinstance(it, dict):
            continue
        fn = REGISTRY.get(it.get('type') or '')
        if not fn:
            continue
        res_sets = fn(it, ctx) or []
        if isinstance(res_sets, (list, tuple)):
            for x in res_sets:
                if isinstance(x, dict):
                    results.append(x)
        elif isinstance(res_sets, dict):
            results.append(res_sets)
    rs = ctx.get('result_set') if isinstance(ctx, dict) else rs
    after = len(rs) if isinstance(rs, list) else 0
    if isinstance(rs, list) and after > before:
        new_items = rs[before:after]
        seen = set()
        deduped = []
        for it in new_items:
            if isinstance(it, dict):
                loc = it.get('loc')
                if not loc:
                    p = it.get('path')
                    ln = it.get('line')
                    if p and ln is not None:
                        loc = f"{p}:{ln}"
                key = (loc, it.get('seq'))
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(it)
                continue
            if isinstance(it, str):
                key = it
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(it)
        ctx['result_set'] = rs[:before] + deduped + rs[after:]
    return results
 
def extract_if_elements_fast(arg, seq, nodes, children_of, trace_index_records, seq_to_index, parent_of=None, top_id_to_file=None):
    """Locate `AST_IF_ELEM` nodes for a trace locator and extract relevant descendant nodes."""
    pth, ln_s = arg.rsplit(':', 1)
    line = int(ln_s)
    path = norm_trace_path(pth)

    rec = None
    idx = seq_to_index.get(seq)
    if idx is not None and 0 <= idx < len(trace_index_records):
        rec = trace_index_records[idx]
    if rec is None:
        for r in trace_index_records:
            if r.get('path') != path or r.get('line') != line:
                continue
            if seq in (r.get('seqs') or []):
                rec = r
                break

    targets = resolve_if_elem_targets(
        path=path,
        line=line,
        record=rec if isinstance(rec, dict) else None,
        nodes=nodes,
        parent_of=parent_of or {},
        children_of=children_of or {},
        top_id_to_file=top_id_to_file or {},
    )

    result = _init_extract_result()

    def sorted_children(xid: int) -> List[int]:
        ch = list(children_of.get(int(xid), []) or [])
        ch.sort(key=lambda y: (nodes.get(y) or {}).get('childnum') if (nodes.get(y) or {}).get('childnum') is not None else 10**9)
        return ch

    def extract_switch_case_expr_roots(switch_id: int) -> List[int]:
        out = []
        sw_children = sorted_children(switch_id)
        switch_list_id = None
        for c in sw_children:
            if ((nodes.get(c) or {}).get('type') or '').strip() == 'AST_SWITCH_LIST':
                switch_list_id = c
                break
        if switch_list_id is None:
            return out
        for case_id in sorted_children(switch_list_id):
            ct = ((nodes.get(case_id) or {}).get('type') or '').strip()
            if ct != 'AST_SWITCH_CASE':
                continue
            case_children = sorted_children(case_id)
            if not case_children:
                continue
            expr_id = case_children[0]
            et = ((nodes.get(expr_id) or {}).get('type') or '').strip()
            if et and et != 'NULL':
                out.append(expr_id)
        return out

    for root in targets:
        rt = ((nodes.get(root) or {}).get('type') or '').strip()
        if rt == 'AST_IF_ELEM':
            desc = collect_descendants(root, children_of, nodes, line)
            for x in desc:
                _handle_extracted_node(int(x), result, nodes, children_of, parent_of)
            continue
        if rt == 'AST_SWITCH':
            desc = collect_descendants(root, children_of, nodes, line)
            for x in desc:
                _handle_extracted_node(int(x), result, nodes, children_of, parent_of)
            for expr_root in extract_switch_case_expr_roots(int(root)):
                expr_line = (nodes.get(expr_root) or {}).get('lineno')
                if expr_line is None:
                    continue
                _handle_extracted_node(int(expr_root), result, nodes, children_of, parent_of)
                for x in collect_descendants(int(expr_root), children_of, nodes, int(expr_line)):
                    _handle_extracted_node(int(x), result, nodes, children_of, parent_of)

    return {'arg': arg, 'path': path, 'line': line, 'targets': targets, 'result': result}


def extract_sql_elements_fast(arg, seq, nodes, children_of, trace_index_records, seq_to_index, parent_of=None):
    pth, ln_s = arg.rsplit(':', 1)
    line = int(ln_s)
    path = norm_trace_path(pth)

    rec = None
    idx = seq_to_index.get(seq)
    if idx is not None and 0 <= idx < len(trace_index_records):
        rec = trace_index_records[idx]
    if rec is None:
        for r in trace_index_records:
            if r.get('path') != path or r.get('line') != line:
                continue
            if seq in (r.get('seqs') or []):
                rec = r
                break

    try:
        from branch_selector.sql.sql_query_detector import find_sql_query_calls_in_record
    except Exception:
        find_sql_query_calls_in_record = None
    hits = find_sql_query_calls_in_record(rec, nodes, children_of) if find_sql_query_calls_in_record else []
    targets = []
    for h in hits or []:
        try:
            targets.append(int(h.get('id')))
        except Exception:
            continue

    result = {
        'vars': [],
        'dims': [],
        'props': [],
        'consts': [],
        'calls': [],
        'isset': [],
        'empty': [],
        'class_consts': [],
        'static_props': [],
        'instanceof': [],
        'conditional': [],
        'binary_ops': [],
        'unary_ops': []
    }

    def handle_extracted_node(x: int):
        nx = nodes.get(x) or {}
        t = (nx.get('type') or '').strip()
        if t == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes)
            name = ss[0][1] if ss else ''
            result['vars'].append({'id': x, 'name': name})
            return
        if t == 'AST_DIM':
            ch = list(children_of.get(x, []) or [])
            ch.sort(key=lambda y: (nodes.get(y) or {}).get('childnum') if (nodes.get(y) or {}).get('childnum') is not None else 10**9)
            base_id = None
            key_id = None
            if len(ch) >= 1:
                base_id = ch[0]
            if len(ch) >= 2:
                key_id = ch[1]
            base_nm = ''
            if base_id is not None:
                _, base_nm = node_display(int(base_id), nodes, children_of)
            if not base_nm:
                base_nm = find_first_var_string(x, children_of, nodes)
            key = ''
            if key_id is not None:
                try:
                    _, key_nm = node_display(int(key_id), nodes, children_of)
                except Exception:
                    key_nm = ''
                key = (key_nm or '').strip()
            if not key:
                parts = [v for _, v in get_string_children(x, children_of, nodes)]
                key = parts[0] if parts else ''
            result['dims'].append({'id': x, 'base': base_nm, 'key': key})
            return
        if t == 'AST_PROP':
            ch = list(children_of.get(x, []) or [])
            ch.sort(key=lambda y: (nodes.get(y) or {}).get('childnum') if (nodes.get(y) or {}).get('childnum') is not None else 10**9)
            base_id = None
            for c in ch:
                nc = nodes.get(c) or {}
                ctt = (nc.get('type') or '').strip()
                if ctt == 'AST_ARG_LIST':
                    continue
                if nc.get('labels') == 'string' or ctt == 'string':
                    continue
                base_id = c
                break
            base_nm = ''
            if base_id is not None:
                _, base_nm = node_display(int(base_id), nodes, children_of)
            if not base_nm:
                base_nm = find_first_var_string(x, children_of, nodes)
            prop = ''
            if len(ch) >= 2:
                try:
                    _, prop_nm = node_display(int(ch[1]), nodes, children_of)
                except Exception:
                    prop_nm = ''
                prop = (prop_nm or '').strip()
            if not prop:
                parts = [v for _, v in get_string_children(x, children_of, nodes)]
                prop = parts[0] if parts else ''
            result['props'].append({'id': x, 'base': base_nm, 'prop': prop})
            return
        if t == 'AST_CONST':
            parts = [v for _, v in get_all_string_descendants(x, children_of, nodes)]
            result['consts'].append({'id': x, 'type': 'AST_CONST', 'name': parts[0] if parts else ''})
            return
        if t == 'AST_NAME':
            parts = [v for _, v in get_all_string_descendants(x, children_of, nodes)]
            v = parts[0] if parts else (nx.get('code') or nx.get('name') or '')
            result['consts'].append({'id': x, 'type': 'AST_NAME', 'name': v})
            return
        if t in ('string', 'integer', 'double'):
            pt = ''
            if isinstance(parent_of, dict):
                try:
                    pid = parent_of.get(x)
                    pt = (nodes.get(pid) or {}).get('type') if pid is not None else ''
                except Exception:
                    pt = ''
            if (pt or '').strip() in ('AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL', 'AST_CLASS_CONST', 'AST_STATIC_PROP'):
                return
            v = (nx.get('code') or nx.get('name') or '').strip()
            result['consts'].append({'id': x, 'type': t, 'name': v})
            return
        if t == 'AST_METHOD_CALL':
            fn = ''
            recv = ''
            recv_id = None
            for c in children_of.get(x, []) or []:
                nc = nodes.get(c) or {}
                if nc.get('type') == 'AST_VAR':
                    ssc = get_string_children(c, children_of, nodes)
                    recv = ssc[0][1] if ssc else ''
                    if recv_id is None:
                        recv_id = c
                if nc.get('labels') == 'string' or nc.get('type') == 'string':
                    vv = nc.get('code') or nc.get('name') or ''
                    if vv:
                        fn = vv
            arg_list_id = None
            args = []
            for c in children_of.get(x, []) or []:
                nc = nodes.get(c) or {}
                if nc.get('type') == 'AST_ARG_LIST':
                    arg_list_id = c
                    for ac in children_of.get(c, []) or []:
                        anc = nodes.get(ac) or {}
                        if anc.get('labels') == 'string' or anc.get('type') == 'string':
                            vv = anc.get('code') or anc.get('name') or ''
                            if vv:
                                args.append({'id': ac, 'type': 'string', 'name': vv})
                        elif anc.get('type') == 'AST_VAR':
                            ssc = get_string_children(ac, children_of, nodes)
                            vv = ssc[0][1] if ssc else ''
                            if vv:
                                args.append({'id': ac, 'type': 'AST_VAR', 'name': vv})
                        elif anc.get('type') in ('AST_PROP', 'AST_DIM'):
                            ssc = get_all_string_descendants(ac, children_of, nodes)
                            vv = ssc[0][1] if ssc else ''
                            if vv:
                                args.append({'id': ac, 'type': anc.get('type'), 'name': vv})
            result['calls'].append({'id': x, 'kind': 'method_call', 'name': fn, 'recv': recv, 'recv_id': recv_id, 'arg_list_id': arg_list_id, 'args': args})
            return
        if t == 'AST_CALL':
            fn = ''
            for c in children_of.get(x, []) or []:
                nc = nodes.get(c) or {}
                if nc.get('labels') == 'string' or nc.get('type') == 'string':
                    vv = nc.get('code') or nc.get('name') or ''
                    if vv:
                        fn = vv
            arg_list_id = None
            args = []
            for c in children_of.get(x, []) or []:
                nc = nodes.get(c) or {}
                if nc.get('type') == 'AST_ARG_LIST':
                    arg_list_id = c
                    for ac in children_of.get(c, []) or []:
                        anc = nodes.get(ac) or {}
                        if anc.get('labels') == 'string' or anc.get('type') == 'string':
                            vv = anc.get('code') or anc.get('name') or ''
                            if vv:
                                args.append({'id': ac, 'type': 'string', 'name': vv})
                        elif anc.get('type') == 'AST_VAR':
                            ssc = get_string_children(ac, children_of, nodes)
                            vv = ssc[0][1] if ssc else ''
                            if vv:
                                args.append({'id': ac, 'type': 'AST_VAR', 'name': vv})
                        elif anc.get('type') in ('AST_PROP', 'AST_DIM'):
                            ssc = get_all_string_descendants(ac, children_of, nodes)
                            vv = ssc[0][1] if ssc else ''
                            if vv:
                                args.append({'id': ac, 'type': anc.get('type'), 'name': vv})
            result['calls'].append({'id': x, 'kind': 'call', 'name': fn, 'recv': '', 'arg_list_id': arg_list_id, 'args': args})
            return
        if t == 'AST_STATIC_CALL':
            cls = ''
            fn = ''
            for c in children_of.get(x, []) or []:
                nc = nodes.get(c) or {}
                if nc.get('type') == 'AST_NAME' or nc.get('labels') == 'string' or nc.get('type') == 'string':
                    vv = nc.get('code') or nc.get('name') or ''
                    if vv and not cls:
                        cls = vv
                    elif vv:
                        fn = vv
            arg_list_id = None
            args = []
            for c in children_of.get(x, []) or []:
                nc = nodes.get(c) or {}
                if nc.get('type') == 'AST_ARG_LIST':
                    arg_list_id = c
                    for ac in children_of.get(c, []) or []:
                        anc = nodes.get(ac) or {}
                        if anc.get('labels') == 'string' or anc.get('type') == 'string':
                            vv = anc.get('code') or anc.get('name') or ''
                            if vv:
                                args.append({'id': ac, 'type': 'string', 'name': vv})
                        elif anc.get('type') == 'AST_VAR':
                            ssc = get_string_children(ac, children_of, nodes)
                            vv = ssc[0][1] if ssc else ''
                            if vv:
                                args.append({'id': ac, 'type': 'AST_VAR', 'name': vv})
                        elif anc.get('type') in ('AST_PROP', 'AST_DIM'):
                            ssc = get_all_string_descendants(ac, children_of, nodes)
                            vv = ssc[0][1] if ssc else ''
                            if vv:
                                args.append({'id': ac, 'type': anc.get('type'), 'name': vv})
            result['calls'].append({'id': x, 'kind': 'static_call', 'name': fn, 'recv': cls, 'arg_list_id': arg_list_id, 'args': args})
            return

    for root in targets:
        handle_extracted_node(int(root))
        desc = collect_descendants(root, children_of, nodes, line)
        for x in desc:
            handle_extracted_node(int(x))

    return {'arg': arg, 'path': path, 'line': line, 'targets': targets, 'result': result}


def extract_xss_elements_fast(arg, seq, nodes, children_of, trace_index_records, seq_to_index, parent_of=None):
    pth, ln_s = arg.rsplit(':', 1)
    line = int(ln_s)
    path = norm_trace_path(pth)

    rec = None
    idx = seq_to_index.get(seq)
    if idx is not None and 0 <= idx < len(trace_index_records):
        rec = trace_index_records[idx]
    if rec is None:
        for r in trace_index_records:
            if r.get('path') != path or r.get('line') != line:
                continue
            if seq in (r.get('seqs') or []):
                rec = r
                break

    try:
        from branch_selector.xss.xss_output_detector import find_xss_output_calls_in_record
    except Exception:
        find_xss_output_calls_in_record = None
    hits = find_xss_output_calls_in_record(rec, nodes, children_of) if find_xss_output_calls_in_record else []
    targets = []
    for h in hits or []:
        try:
            targets.append(int(h.get('id')))
        except Exception:
            continue

    result = _init_extract_result()
    for root in targets:
        _handle_extracted_node(int(root), result, nodes, children_of, parent_of)
        desc = collect_descendants(root, children_of, nodes, line)
        for x in desc:
            _handle_extracted_node(int(x), result, nodes, children_of, parent_of)
    return {'arg': arg, 'path': path, 'line': line, 'targets': targets, 'result': result}


def extract_cmd_elements_fast(arg, seq, nodes, children_of, trace_index_records, seq_to_index, parent_of=None):
    pth, ln_s = arg.rsplit(':', 1)
    line = int(ln_s)
    path = norm_trace_path(pth)

    rec = None
    idx = seq_to_index.get(seq)
    if idx is not None and 0 <= idx < len(trace_index_records):
        rec = trace_index_records[idx]
    if rec is None:
        for r in trace_index_records:
            if r.get('path') != path or r.get('line') != line:
                continue
            if seq in (r.get('seqs') or []):
                rec = r
                break

    try:
        from branch_selector.cmd.cmd_query_detector import find_cmd_calls_in_record
    except Exception:
        find_cmd_calls_in_record = None
    hits = find_cmd_calls_in_record(rec, nodes, children_of) if find_cmd_calls_in_record else []
    targets = []
    for h in hits or []:
        try:
            targets.append(int(h.get('id')))
        except Exception:
            continue

    def sorted_children(xid: int) -> List[int]:
        ch = list(children_of.get(int(xid), []) or [])
        ch.sort(key=lambda y: (nodes.get(y) or {}).get('childnum') if (nodes.get(y) or {}).get('childnum') is not None else 10**9)
        return ch

    def cmd_arg_roots(call_id: int) -> List[int]:
        nx = nodes.get(int(call_id)) or {}
        t = (nx.get('type') or '').strip()
        if t in ('AST_CALL', 'AST_STATIC_CALL'):
            arg_list_id = None
            for c in sorted_children(int(call_id)):
                ct = ((nodes.get(int(c)) or {}).get('type') or '').strip()
                if ct == 'AST_ARG_LIST':
                    arg_list_id = int(c)
                    break
            if arg_list_id is None:
                return []
            arg_nodes = sorted_children(int(arg_list_id))
            if not arg_nodes:
                return []
            return [int(arg_nodes[0])]
        if t in ('AST_SHELL_EXEC', 'AST_BACKTICK'):
            return [int(c) for c in sorted_children(int(call_id))]
        return []

    result = _init_extract_result()
    for root in targets:
        for ar in cmd_arg_roots(int(root)):
            _handle_extracted_node(int(ar), result, nodes, children_of, parent_of)
            desc = collect_descendants(int(ar), children_of, nodes, line)
            for x in desc:
                _handle_extracted_node(int(x), result, nodes, children_of, parent_of)
    return {'arg': arg, 'path': path, 'line': line, 'targets': targets, 'result': result}
 
def process_taints(initial, ctx):
    """Run taint processing, defaulting to pattern-based diffusion."""
    if ctx.get('llm_enabled'):
        return process_taints_llm(initial, ctx)
    logger = ctx.get('logger') if isinstance(ctx, dict) else None
    if logger is not None:
        logger.info('taint_process_start', initial=len(initial or []))
    preA = list(initial)
    preB = []
    useA = True
    round_idx = 0
    while preA or preB:
        active = preA if useA else preB
        if not active:
            useA = not useA
            continue
        round_idx += 1
        active_size = len(active)
        nxt = []
        processed = 0
        for t in list(active):
            fn = REGISTRY.get(t.get('type') or '')
            if fn:
                res_sets = fn(t, ctx) or []
                for s in res_sets:
                    if isinstance(s, (list, tuple)):
                        for x in s:
                            nxt.append(x)
                    elif isinstance(s, dict):
                        nxt.append(s)
            active.pop(0)
            processed += 1
        if logger is not None:
            other = preB if useA else preA
            logger.info(
                'taint_round',
                round=round_idx,
                queue=('A' if useA else 'B'),
                active=active_size,
                processed=processed,
                next=len(nxt),
                pending_other=len(other),
            )
        if useA:
            preA = nxt
            useA = False
        else:
            preB = nxt
            useA = True
    if logger is not None:
        logger.info('taint_process_done', rounds=round_idx)
    return []
 
def parse_loc(loc):
    """Parse a `path:line` locator and return `(normalized_path, line)`."""
    if not loc or ':' not in loc:
        return None
    p, ln_s = loc.rsplit(':', 1)
    try:
        ln = int(ln_s)
    except:
        return None
    return norm_trace_path(p), ln

def build_seq_index(trace_index_records):
    """Build a `(path,line) -> sorted unique seq list` index from trace index records."""
    m = {}
    for rec in trace_index_records or []:
        p = rec.get('path')
        ln = rec.get('line')
        if not p or ln is None:
            continue
        seqs = rec.get('seqs') or []
        if not seqs:
            continue
        buf = m.get((p, ln))
        if buf is None:
            buf = []
            m[(p, ln)] = buf
        for x in seqs:
            try:
                buf.append(int(x))
            except:
                continue
    for k, buf in list(m.items()):
        if not buf:
            m.pop(k, None)
            continue
        buf.sort()
        uniq = []
        last = None
        for x in buf:
            if last is None or x != last:
                uniq.append(x)
                last = x
        m[k] = uniq
    return m

def _pick_seq_near(seqs, ref_seq: Optional[int], prefer: str):
    """Pick a seq from sorted `seqs` near `ref_seq` using forward/backward preference."""
    if not seqs:
        return None
    if ref_seq is None:
        return seqs[0]
    r = int(ref_seq)
    if prefer == 'backward':
        i = bisect.bisect_right(seqs, r) - 1
        if i >= 0:
            return seqs[i]
        return seqs[0]
    i = bisect.bisect_left(seqs, r)
    if i < len(seqs):
        return seqs[i]
    return seqs[-1]

def attach_min_seq_to_result_set(result_set, trace_index_records, ref_seq: Optional[int] = None, prefer: str = 'forward'):
    """Attach a best-effort `seq` to each result-set location using trace index records."""
    idx = build_seq_index(trace_index_records)
    out = []
    for it in result_set or []:
        if isinstance(it, dict):
            p = it.get('path')
            ln = it.get('line')
            if not p or ln is None:
                pr = parse_loc(it.get('loc') or '')
                if pr:
                    p, ln = pr
            if not p or ln is None:
                continue
            seq = it.get('seq')
            if seq is None:
                seq = _pick_seq_near(idx.get((p, ln)) or [], ref_seq, prefer)
            out.append({'seq': seq, 'path': p, 'line': ln, 'loc': f"{p}:{ln}"})
            continue
        if isinstance(it, str):
            pr = parse_loc(it)
            if not pr:
                continue
            p, ln = pr
            out.append({'seq': _pick_seq_near(idx.get((p, ln)) or [], ref_seq, prefer), 'path': p, 'line': ln, 'loc': f"{p}:{ln}"})
    return out

def sort_dedup_result_set_by_seq(result_set):
    """Sort and de-duplicate result-set items by `seq` (or by locator when seq is missing)."""
    items = [it for it in (result_set or []) if isinstance(it, dict)]
    def key(it):
        s = it.get('seq')
        try:
            s2 = int(s)
        except:
            s2 = 10**18
        return (s2, str(it.get('path') or ''), int(it.get('line') or 0))
    items.sort(key=key)
    seen_seq = set()
    seen_loc = set()
    out = []
    for it in items:
        s = it.get('seq')
        if s is None:
            loc = it.get('loc') or f"{it.get('path') or ''}:{it.get('line') or ''}"
            if loc in seen_loc:
                continue
            seen_loc.add(loc)
            out.append(it)
            continue
        try:
            si = int(s)
        except:
            loc = it.get('loc') or f"{it.get('path') or ''}:{it.get('line') or ''}"
            if loc in seen_loc:
                continue
            seen_loc.add(loc)
            out.append(it)
            continue
        if si in seen_seq:
            continue
        seen_seq.add(si)
        out.append(it)
    return out

def build_result_set_from_llm_seqs(ctx):
    """Build a result-set locator list from the set of seqs returned/used by the LLM."""
    if not isinstance(ctx, dict):
        return []
    seqs = ctx.get('symbolic_prompt_seqs')
    if not seqs:
        seqs = ctx.get('llm_result_seqs') or set()
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    recs = ctx.get('trace_index_records') or []
    out = []
    for s in seqs:
        try:
            si = int(s)
        except Exception:
            continue
        idx = seq_to_idx.get(si)
        if idx is None:
            for i, r in enumerate(recs):
                if si in (r.get('seqs') or []):
                    idx = i
                    break
        if isinstance(idx, int) and 0 <= idx < len(recs):
            rec = recs[idx] or {}
            p = rec.get('path')
            ln = rec.get('line')
            if p and ln is not None:
                out.append({'seq': si, 'path': p, 'line': ln, 'loc': f"{p}:{ln}"})
                continue
        out.append({'seq': si})
    for loc in ctx.get('pattern_source_locs') or []:
        if not isinstance(loc, dict):
            continue
        p = (loc.get('path') or '').strip()
        ln = loc.get('line')
        if not p or ln is None:
            continue
        try:
            ln_i = int(ln)
        except Exception:
            continue
        out.append({'path': p, 'line': ln_i, 'loc': f"{p}:{ln_i}"})
    return out

def parse_cli_args(argv: List[str]) -> Dict:
    """
    Parse CLI args for `analyze_if_line.py`.

    Supported flags:
    - `--debug`: enable debug logging.
    - `--llm`: run the later symbolic stage with the configured LLM.
    - `--sql`: enable SQL-mode extraction for SQL callsites.
    - `--xss` / `-xss`: enable XSS-mode extraction for output callsites.
    - `--cmd` / `-cmd`: enable command-mode extraction for command callsites.
    - `--prompt`: accepted for compatibility (no behavioral change).
    - `--llm-max=<N>` / `--llm-max <N>`: keep for compatibility.
    """
    args = list(argv or [])
    args = [x.replace('--llm--', '--llm-') if isinstance(x, str) and x.startswith('--llm--') else x for x in args]
    debug_mode = any(x == '--debug' for x in args)
    llm_mode = any(x == '--llm' for x in args)
    prompt_mode = any(x == '--prompt' for x in args)
    sql_mode = any(x == '--sql' for x in args)
    xss_mode = any(x in ('--xss', '-xss') for x in args)
    cmd_mode = any(x in ('--cmd', '-cmd') for x in args)

    llm_max_calls = None
    for i, x in enumerate(args):
        if x.startswith('--llm-max='):
            try:
                llm_max_calls = int(x.split('=', 1)[1])
            except Exception:
                llm_max_calls = None
        if x == '--llm-max' and (i + 1) < len(args):
            try:
                llm_max_calls = int(args[i + 1])
            except Exception:
                llm_max_calls = None

    return {
        'debug_mode': bool(debug_mode),
        'llm_mode': bool(llm_mode),
        'llm_max_calls': llm_max_calls,
        'prompt_mode': bool(prompt_mode),
        'sql_mode': bool(sql_mode),
        'xss_mode': bool(xss_mode),
        'cmd_mode': bool(cmd_mode),
    }

def _parse_analyze_flags_from_config(cfg_raw: dict) -> dict:
    if not isinstance(cfg_raw, dict):
        return {'test': False, 'debug': False, 'prompt': False}
    sec = cfg_raw.get('analyze_if')
    if not isinstance(sec, dict):
        sec = cfg_raw.get('analyze_if_line')
    if not isinstance(sec, dict):
        sec = {}
    test_mode = bool(sec.get('test'))
    debug_mode = bool(sec.get('debug'))
    prompt_mode = bool(sec.get('prompt'))
    return {'test': test_mode, 'debug': debug_mode, 'prompt': prompt_mode}


def _parse_analyze_llm_temperature_from_config(cfg_raw: dict) -> float:
    if not isinstance(cfg_raw, dict):
        return 0.3
    sec = cfg_raw.get('analyze_if')
    if not isinstance(sec, dict):
        sec = cfg_raw.get('analyze_if_line')
    if not isinstance(sec, dict):
        sec = {}
    v = sec.get('llm_temperature')
    try:
        return float(v) if v is not None else 0.3
    except Exception:
        return 0.3

def _parse_retry_counts_from_config(cfg_raw: dict) -> dict:
    if not isinstance(cfg_raw, dict):
        return {'llm_json_retry_attempts': 3, 'symbolic_prompt_retry_attempts': 1}
    sec = cfg_raw.get('analyze_if')
    if not isinstance(sec, dict):
        sec = cfg_raw.get('analyze_if_line')
    if not isinstance(sec, dict):
        sec = {}
    a = sec.get('llm_json_retry_attempts')
    b = sec.get('symbolic_prompt_retry_attempts')
    try:
        ai = int(a) if a is not None else 3
    except Exception:
        ai = 3
    try:
        bi = int(b) if b is not None else 1
    except Exception:
        bi = 1
    return {'llm_json_retry_attempts': max(1, ai), 'symbolic_prompt_retry_attempts': max(0, bi)}

def _extract_json_text(text: str) -> Optional[str]:
    if not isinstance(text, str):
        return None
    t = (text or '').strip()
    if not t:
        return None
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", t, flags=re.IGNORECASE)
    if m:
        inner = (m.group(1) or '').strip()
        if inner.startswith('{') and inner.endswith('}'):
            return inner
    i = t.find('{')
    j = t.rfind('}')
    if i >= 0 and j >= 0 and j > i:
        return t[i : j + 1]
    return None

def _read_text(path: str) -> str:
    if not isinstance(path, str) or not path:
        return ''
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception:
        return ''

def _llm_response_has_valid_json(run_dir: str, seq: int) -> bool:
    resp_dir = os.path.join(run_dir, 'symbolic', 'responses')
    raw_resp_path = os.path.join(resp_dir, f'symbolic_response_{int(seq)}.txt')
    raw = _read_text(raw_resp_path)
    js = _extract_json_text(raw)
    if not js:
        return False
    try:
        json.loads(js)
    except Exception:
        return False
    sols = parse_symbolic_response(js)
    for sol in sols or []:
        if not isinstance(sol, dict):
            continue
        sess = sol.get("SESSION")
        if sess is None:
            continue
        # Accept the current SESSION JSON-patch format directly. Only fall back
        # to PHP serialized-session validation when the model returned raw text.
        if _normalize_session_patch(sess) is not None:
            continue
        sess_s = (sess if isinstance(sess, str) else str(sess)).strip()
        if not sess_s:
            continue
        vr = validate_and_fix_php_session_text(sess_s)
        if not vr.ok:
            return False
    return True

def _symbolic_response_json_is_empty(run_dir: str, seq: int) -> bool:
    resp_dir = os.path.join(run_dir, 'symbolic', 'responses')
    json_resp_path = os.path.join(resp_dir, f'symbolic_response_{int(seq)}.json')
    try:
        with open(json_resp_path, 'r', encoding='utf-8', errors='replace') as f:
            obj = json.load(f)
        sols = obj.get('solutions') if isinstance(obj, dict) else []
        return not bool(sols)
    except Exception:
        return True


def _symbolic_solutions_is_empty(solutions: Any) -> bool:
    if isinstance(solutions, str):
        try:
            solutions = parse_symbolic_response(solutions)
        except Exception:
            return True
    if not isinstance(solutions, list):
        return True
    return not any(isinstance(sol, dict) and bool(sol) for sol in solutions)

def _run_symbolic_with_json_retry(prompt_text: str, *, run_dir: str, seq: int, logger, attempts: int) -> dict:
    tries = max(1, int(attempts or 1))
    last = {}
    for i in range(tries):
        _append_stage_debug(run_dir, "symbolic_json_retry_attempt_enter", seq=int(seq), attempt=int(i + 1), attempt_limit=int(tries))
        rr = run_symbolic_prompt(
            prompt_text,
            run_dir=run_dir,
            seq=int(seq),
            llm_offline=False,
            logger=logger,
        )
        _append_stage_debug(run_dir, "symbolic_json_retry_attempt_after_run", seq=int(seq), attempt=int(i + 1), response_obj_count=len(rr.get('response_obj') or []) if isinstance(rr, dict) else 0, has_response_path=bool(isinstance(rr, dict) and rr.get('response_path')), has_response_json_path=bool(isinstance(rr, dict) and rr.get('response_json_path')))
        last = rr if isinstance(rr, dict) else {}
        ok = _llm_response_has_valid_json(run_dir, int(seq))
        _append_stage_debug(run_dir, "symbolic_json_retry_attempt_after_validate", seq=int(seq), attempt=int(i + 1), json_valid=bool(ok))
        if logger is not None:
            try:
                logger.info(
                    'symbolic_json_retry_attempt',
                    seq=int(seq),
                    attempt=int(i + 1),
                    attempt_limit=int(tries),
                    json_valid=bool(ok),
                    response_obj_count=len(last.get('response_obj') or []) if isinstance(last, dict) else 0,
                    response_path=str(last.get('response_path') or '') if isinstance(last, dict) else '',
                    response_json_path=str(last.get('response_json_path') or '') if isinstance(last, dict) else '',
                )
            except Exception:
                pass
        if ok:
            break
    _append_stage_debug(run_dir, "symbolic_json_retry_return", seq=int(seq), attempt_limit=int(tries), final_response_obj_count=len(last.get('response_obj') or []) if isinstance(last, dict) else 0)
    return last

def _run_analyze_once(
    *,
    n: int,
    cfg,
    opts: dict,
    debug_mode: bool,
    prompt_mode: bool,
    test_mode: bool,
    llm_enabled: bool,
    llm_max_calls,
    llm_temperature: float,
    retry_cfg: dict,
) -> Tuple[dict, bool]:
    test_root = cfg.test_dir
    seq_root = os.path.join(test_root, "seqs")
    os.makedirs(seq_root, exist_ok=True)
    run_dir = os.path.join(seq_root, f"seq_{int(n)}")
    clean_previous_test_outputs(run_dir, n)
    clean_llm_io_dirs(run_dir, llm_mode=llm_enabled, llm_test_mode=test_mode)
    logger = Logger(base_dir=run_dir, min_level=('DEBUG' if debug_mode else 'INFO'), name=f'analyze_if_line:{n}', also_console=True)
    seed_kind_flags = _load_symbolic_seed_kind_flags_for_cfg(cfg)
    heartbeat = AnalyzeHeartbeat(run_dir=run_dir, seq=int(n), interval_seconds=10)
    heartbeat.start()
    exit_recorder = AnalyzeExitRecorder(run_dir=run_dir, seq=int(n), heartbeat=heartbeat)
    exit_recorder.install()
    heartbeat.update("logger_ready", status="running", run_dir=run_dir, llm_enabled=bool(llm_enabled), prompt_mode=bool(prompt_mode))
    out_path = os.path.join(run_dir, f"analysis_output_{n}.json")
    def finish(obj, *, symbolic_empty: bool = False):
        heartbeat.update("writing_output", status="running", out_path=out_path, symbolic_empty=bool(symbolic_empty))
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        logger.info('write_output', out_path=out_path)
        finish_status = 'success'
        finish_message = 'analysis completed'
        if isinstance(obj, dict) and obj.get('error'):
            finish_status = 'error'
            finish_message = str(obj.get('error') or 'analysis failed')
        heartbeat.finish(finish_status, message=finish_message, out_path=out_path, symbolic_empty=bool(symbolic_empty))
        exit_recorder.mark_finished(
            finish_status,
            reason=finish_message,
            out_path=out_path,
            symbolic_empty=bool(symbolic_empty),
        )
        logger.close()
        return obj, bool(symbolic_empty)

    heartbeat.update("loading_context", status="running")
    provider = build_analyze_context_provider(cfg=cfg, run_dir=run_dir, logger=logger)
    bundle = provider.load_inputs(seq=int(n), cfg=cfg, logger=logger)
    arg = bundle.trace.trace_locator
    trace_path = bundle.trace.trace_path
    trace_index_path = bundle.trace.trace_index_path
    trace_index_records = bundle.trace.trace_index_records
    seq_to_index = bundle.trace.seq_to_index
    nodes_path = bundle.ast.nodes_path
    rels_path = bundle.ast.rels_path
    nodes = bundle.ast.nodes
    top_id_to_file = bundle.ast.top_id_to_file
    parent_of = bundle.ast.parent_of
    children_of = bundle.ast.children_of
    logger.info(
        'analyze_context_provider_ready',
        provider=bundle.provider_name,
        mode=bundle.provider_mode,
        shared_enabled=bool(bundle.settings.enabled),
        shared_mode=bundle.settings.mode,
    )
    heartbeat.update(
        "context_ready",
        status="running",
        provider=bundle.provider_name,
        provider_mode=bundle.provider_mode,
        shared_enabled=bool(bundle.settings.enabled),
    )
    sql_mode = bool(opts.get('sql_mode'))
    xss_mode = bool(opts.get('xss_mode'))
    cmd_mode = bool(opts.get('cmd_mode'))
    if sql_mode:
        st = extract_sql_elements_fast(arg, n, nodes, children_of, trace_index_records, seq_to_index, parent_of)
        st['mode'] = 'sql'
        if not (st.get('targets') or []):
            return finish({'error': 'sql_call_not_found_for_trace_line'})
    elif xss_mode:
        st = extract_xss_elements_fast(arg, n, nodes, children_of, trace_index_records, seq_to_index, parent_of)
        st['mode'] = 'xss'
        if not (st.get('targets') or []):
            return finish({'error': 'xss_output_not_found_for_trace_line'})
    elif cmd_mode:
        st = extract_cmd_elements_fast(arg, n, nodes, children_of, trace_index_records, seq_to_index, parent_of)
        st['mode'] = 'cmd'
        if not (st.get('targets') or []):
            return finish({'error': 'cmd_call_not_found_for_trace_line'})
    else:
        st = extract_if_elements_fast(arg, n, nodes, children_of, trace_index_records, seq_to_index, parent_of, top_id_to_file)
        st['mode'] = 'if'
        if not (st.get('targets') or []):
            return finish({'error': 'if_elem_not_found_for_trace_line'})

    heartbeat.update(
        "targets_extracted",
        status="running",
        mode=str(st.get('mode') or ''),
        targets=len(st.get('targets') or []),
        loc=f"{st.get('path')}:{st.get('line')}",
    )
    st['seq'] = n
    try:
        logger.info(
            'analyze_start',
            seq=int(n),
            loc=f"{st.get('path')}:{st.get('line')}",
            targets=len(st.get('targets') or []),
            llm_enabled=bool(llm_enabled),
            llm_test_mode=bool(test_mode),
            prompt_mode=bool(prompt_mode),
            sql_mode=bool(sql_mode),
            xss_mode=bool(xss_mode),
            cmd_mode=bool(cmd_mode),
        )
    except Exception:
        pass
    REGISTRY['AST_IF'] = handle_if_taint
    initial = build_if_initial_taint(
        st,
        nodes,
        children_of,
        parent_of,
        trace_index_path=trace_index_path,
        scope_root='/app',
        windows_root=r'D:\files\witcher\app',
    )

    ctx = {
        'input_seq': n,
        'path': st['path'],
        'line': st['line'],
        'targets': st['targets'],
        'result': st['result'],
        'initial_taints': initial,
        'nodes': nodes,
        'children_of': children_of,
        'parent_of': parent_of,
        'top_id_to_file': top_id_to_file,
        'trace_index_records': trace_index_records,
        'trace_seq_to_index': seq_to_index,
        'argv': sys.argv[2:],
        'trace_path': trace_path,
        'nodes_path': nodes_path,
        'rels_path': rels_path,
        'scope_root': '/app',
        'windows_root': r'D:\files\witcher\app',
        'llm_enabled': llm_enabled,
        'llm_max_calls': (llm_max_calls if llm_enabled else None),
        'llm_offline': (True if test_mode else False) if llm_enabled else None,
        'llm_temperature': llm_temperature,
        'llm_scope_debug': bool(debug_mode),
        'llm_json_retry_attempts': int(retry_cfg.get('llm_json_retry_attempts') or 3),
        'debug': {},
        'logger': logger,
        'test_dir': run_dir,
    }
    try:
        logger.log_json('INFO', 'initial_taints', initial)
        logger.info(
            'initial_taints_summary',
            count=len(initial or []),
            types=[(t or {}).get('type') for t in (initial or [])],
            ids=[(t or {}).get('id') for t in (initial or [])],
        )
    except Exception:
        pass
    heartbeat.update("initial_taints_ready", status="running", initial_taints=len(initial or []))
    try:
        logger.info('taint_loop_start', llm_enabled=bool(llm_enabled))
        heartbeat.update("taint_loop_running", status="running", llm_enabled=bool(llm_enabled))
        process_taints(initial, ctx)
        logger.info(
            'taint_loop_done',
            llm_enabled=bool(llm_enabled),
            llm_calls=int(ctx.get('_llm_call_count') or 0) if llm_enabled else 0,
            llm_new_taints=len(ctx.get('llm_new_taints') or []) if llm_enabled else 0,
            llm_intermediates=len(ctx.get('llm_intermediates') or []) if llm_enabled else 0,
            llm_result_seqs=len(ctx.get('llm_result_seqs') or []) if llm_enabled else 0,
            result_set=len(ctx.get('result_set') or []),
        )
        heartbeat.update(
            "taint_loop_done",
            status="running",
            llm_calls=int(ctx.get('_llm_call_count') or 0) if llm_enabled else 0,
            result_set=len(ctx.get('result_set') or []),
        )
    except Exception:
        logger.exception('analyze_failed')
        try:
            if llm_enabled:
                rs2 = sort_dedup_result_set_by_seq(build_result_set_from_llm_seqs(ctx))
            else:
                rs = ctx.get('result_set') or []
                rs2 = attach_min_seq_to_result_set(rs, trace_index_records, ref_seq=n, prefer='forward')
                rs2 = sort_dedup_result_set_by_seq(rs2)
        except Exception:
            rs2 = []
        finish({'input_seq': n, 'initial_taints': initial, 'result_set': rs2, 'error': 'analyze_failed'})
        raise SystemExit(1)
    if llm_enabled:
        rs2 = sort_dedup_result_set_by_seq(build_result_set_from_llm_seqs(ctx))
    else:
        rs = ctx.get('result_set') or []
        rs2 = attach_min_seq_to_result_set(rs, trace_index_records, ref_seq=n, prefer='forward')
        rs2 = sort_dedup_result_set_by_seq(rs2)
    try:
        logger.info('result_set_built', count=len(rs2 or []), llm_enabled=bool(llm_enabled))
    except Exception:
        pass
    heartbeat.update("result_set_ready", status="running", result_set=len(rs2 or []), llm_enabled=bool(llm_enabled))
    out = {
        'input_seq': n,
        'initial_taints': initial,
        'result_set': rs2,
    }
    if llm_enabled:
        out['symbolic_prompt_seqs'] = sorted(int(x) for x in (ctx.get('symbolic_prompt_seqs') or []))
    symbolic_empty = False
    if prompt_mode:
        try:
            heartbeat.update("prompt_building", status="running", prompt_mode=True)
            _append_stage_debug(run_dir, "prompt_building_enter", seq=int(n), llm_mode=bool(opts.get('llm_mode')), test_mode=bool(test_mode), result_set=len(rs2 or []))
            prompt_base_inputs = _load_prompt_base_inputs_for_parent_seed(cfg)
            _append_stage_debug(run_dir, "prompt_base_inputs_loaded", seq=int(n), has_base_inputs=bool(isinstance(prompt_base_inputs, dict) and prompt_base_inputs))
            if sql_mode:
                prompt_builder = generate_sql_symbolic_execution_prompt
            elif xss_mode:
                prompt_builder = generate_xss_symbolic_execution_prompt
            elif cmd_mode:
                prompt_builder = generate_cmd_symbolic_execution_prompt
            else:
                prompt_builder = generate_symbolic_execution_prompt
            _append_stage_debug(run_dir, "prompt_builder_selected", seq=int(n), builder=getattr(prompt_builder, '__name__', 'unknown'))
            prompt_inputs = dict(prompt_base_inputs) if isinstance(prompt_base_inputs, dict) else {}
            prompt_inputs['__WITCHER_RUN_DIR__'] = run_dir
            prompt_text = prompt_builder(
                rs2,
                input_seq=n,
                input_path=ctx.get('path'),
                input_line=ctx.get('line'),
                scope_root=ctx.get('scope_root') or '/app',
                trace_index_path=trace_index_path,
                windows_root=ctx.get('windows_root') or r'D:\files\witcher\app',
                base_prompt=None,
                base_inputs=prompt_inputs,
                trace_index_records=ctx.get('trace_index_records') if isinstance(ctx.get('trace_index_records'), list) else None,
                trace_seq_to_index=ctx.get('trace_seq_to_index') if isinstance(ctx.get('trace_seq_to_index'), dict) else None,
                nodes=ctx.get('nodes') if isinstance(ctx.get('nodes'), dict) else None,
                parent_of=ctx.get('parent_of') if isinstance(ctx.get('parent_of'), dict) else None,
                children_of=ctx.get('children_of') if isinstance(ctx.get('children_of'), dict) else None,
                top_id_to_file=ctx.get('top_id_to_file') if isinstance(ctx.get('top_id_to_file'), dict) else None,
            )
            _append_stage_debug(run_dir, "prompt_built", seq=int(n), prompt_len=len(prompt_text or ""))
            if bool(opts.get('llm_mode')) and not test_mode:
                heartbeat.update("symbolic_llm_running", status="running", llm_mode=True, test_mode=False)
                _append_stage_debug(run_dir, "symbolic_llm_before_run", seq=int(n), retry_attempts=int(retry_cfg.get('llm_json_retry_attempts') or 3))
                rr = _run_symbolic_with_json_retry(
                    prompt_text,
                    run_dir=run_dir,
                    seq=int(n),
                    logger=logger,
                    attempts=int(retry_cfg.get('llm_json_retry_attempts') or 3),
                )
                _append_stage_debug(run_dir, "symbolic_llm_after_run", seq=int(n), response_obj_count=len(rr.get('response_obj') or []) if isinstance(rr, dict) else 0, has_response_path=bool(isinstance(rr, dict) and rr.get('response_path')), has_response_json_path=bool(isinstance(rr, dict) and rr.get('response_json_path')))
                out['symbolic_prompt_path'] = rr.get('prompt_path')
                out['symbolic_response_path'] = rr.get('response_path')
                out['symbolic_response_json_path'] = rr.get('response_json_path')
                logger.info('write_symbolic_prompt', prompt_path=out.get('symbolic_prompt_path'), llm_mode=True, test_mode=False)
                try:
                    logger.info(
                        'symbolic_prompt_run_result',
                        seq=int(n),
                        response_path=str(rr.get('response_path') or ''),
                        response_json_path=str(rr.get('response_json_path') or ''),
                        response_obj_count=len(rr.get('response_obj') or []),
                        response_obj_keys=[sorted([str(k) for k in sol.keys()]) for sol in (rr.get('response_obj') or []) if isinstance(sol, dict)],
                        external_seed_path_count=len(rr.get('external_seed_paths') or []),
                        has_db_search=bool(rr.get('db_search')),
                    )
                except Exception:
                    pass
                try:
                    heartbeat.update("writing_external_seeds", status="running", llm_mode=True)
                    _append_stage_debug(run_dir, "writing_external_seeds_enter", seq=int(n))
                    output_root = _resolve_output_root(cfg)
                    defaults = load_symbolic_solution_defaults(cfg.find_input_file('test_command.txt'))
                    raw_response_obj = rr.get('response_obj')
                    sols = raw_response_obj or []
                    external_paths = list(rr.get("external_seed_paths") or [])
                    json_reload_attempted = False
                    json_reload_succeeded = False
                    json_reload_used_raw_response = False
                    if isinstance(sols, str):
                        sols = parse_symbolic_response(sols)
                    if _symbolic_solutions_is_empty(sols) and isinstance(rr.get('raw_response'), str):
                        try:
                            sols = parse_symbolic_response(rr.get('raw_response') or '')
                        except Exception:
                            sols = []
                    if _symbolic_solutions_is_empty(sols) and isinstance(out.get('symbolic_response_json_path'), str) and os.path.exists(out.get('symbolic_response_json_path')):
                        json_reload_attempted = True
                        try:
                            with open(out.get('symbolic_response_json_path'), 'r', encoding='utf-8', errors='replace') as f:
                                obj = json.load(f)
                            sols = obj.get('solutions') if isinstance(obj, dict) else []
                            if _symbolic_solutions_is_empty(sols) and isinstance(obj, dict) and isinstance(obj.get('raw_response'), str):
                                sols = parse_symbolic_response(obj.get('raw_response') or '')
                                json_reload_used_raw_response = True
                            json_reload_succeeded = True
                        except Exception:
                            sols = []
                    sols = _filter_solutions_by_seed_kinds(sols or [], seed_kind_flags=seed_kind_flags)
                    try:
                        logger.info(
                            'write_external_seeds_input',
                            seq=int(n),
                            solution_count=len(sols or []),
                            solution_keys=[sorted([str(k) for k in sol.keys()]) for sol in (sols or []) if isinstance(sol, dict)],
                            existing_external_path_count=len(external_paths or []),
                            external_seed_dir=_resolve_external_seed_dir(cfg),
                            symbolic_response_path=str(out.get('symbolic_response_path') or ''),
                            symbolic_response_json_path=str(out.get('symbolic_response_json_path') or ''),
                            symbolic_response_path_exists=bool(out.get('symbolic_response_path') and os.path.exists(out.get('symbolic_response_path'))),
                            symbolic_response_json_path_exists=bool(out.get('symbolic_response_json_path') and os.path.exists(out.get('symbolic_response_json_path'))),
                            json_reload_attempted=bool(json_reload_attempted),
                            json_reload_succeeded=bool(json_reload_succeeded),
                            json_reload_used_raw_response=bool(json_reload_used_raw_response),
                        )
                    except Exception:
                        pass
                    _append_stage_debug(run_dir, "writing_external_seeds_before_write", seq=int(n), solution_count=len(sols or []), existing_external_path_count=len(external_paths or []), json_reload_attempted=bool(json_reload_attempted), json_reload_succeeded=bool(json_reload_succeeded), json_reload_used_raw_response=bool(json_reload_used_raw_response))
                    local_external_paths = _write_external_seeds_from_solutions(sols or [], cfg=cfg, seq=int(n), defaults=defaults, logger=logger, seed_kind_flags=seed_kind_flags)
                    _append_stage_debug(run_dir, "writing_external_seeds_after_write", seq=int(n), local_external_path_count=len(local_external_paths or []))
                    seen_external_paths = set()
                    merged_external_paths = []
                    for p in list(external_paths or []) + [p for p in (local_external_paths or []) if p]:
                        ps = str(p or "").strip()
                        if not ps or ps in seen_external_paths:
                            continue
                        seen_external_paths.add(ps)
                        merged_external_paths.append(ps)
                    external_paths = merged_external_paths
                    out["external_seed_paths"] = external_paths
                    out["symbolic_solutions"] = sols if isinstance(sols, list) else []
                    logger.info('write_external_seeds', count=len(external_paths), local_count=len(local_external_paths or []), external_seed_dir=_resolve_external_seed_dir(cfg))
                    if external_paths:
                        try:
                            from skip_cache.if_stmt_counter import inc_count
                            _ = inc_count(ctx.get("path"), ctx.get("line"), inc=1)
                        except Exception:
                            pass
                except Exception as exc:
                    _append_stage_debug(run_dir, "writing_external_seeds_failed", seq=int(n), error=str(exc))
                    logger.exception('write_external_seeds_failed')
                symbolic_empty = _symbolic_solutions_is_empty(out.get("symbolic_solutions"))
                _append_stage_debug(run_dir, "prompt_llm_branch_done", seq=int(n), symbolic_empty=bool(symbolic_empty), external_seed_path_count=len(out.get("external_seed_paths") or []), symbolic_solution_count=len(out.get("symbolic_solutions") or []))
            else:
                heartbeat.update("writing_symbolic_prompt", status="running", llm_mode=False, test_mode=bool(test_mode))
                _append_stage_debug(run_dir, "writing_symbolic_prompt_enter", seq=int(n), test_mode=bool(test_mode))
                prompt_path = write_symbolic_prompt(prompt_text, run_dir=run_dir, seq=int(n))
                _append_stage_debug(run_dir, "writing_symbolic_prompt_done", seq=int(n), prompt_path=str(prompt_path or ""))
                out['symbolic_prompt_path'] = prompt_path
                if test_mode:
                    raw_path, json_path = write_symbolic_response(build_symbolic_response_example(), run_dir=run_dir, seq=int(n))
                    out['symbolic_response_path'] = raw_path
                    out['symbolic_response_json_path'] = json_path
                logger.info('write_symbolic_prompt', prompt_path=prompt_path, llm_mode=False, test_mode=bool(test_mode))
                if test_mode:
                    try:
                        heartbeat.update("writing_external_seeds", status="running", llm_mode=False, test_mode=True)
                        output_root = _resolve_output_root(cfg)
                        defaults = load_symbolic_solution_defaults(cfg.find_input_file('test_command.txt'))
                        sols = []
                        try:
                            with open(out.get('symbolic_response_json_path', ''), 'r', encoding='utf-8', errors='replace') as f:
                                obj = json.load(f)
                            sols = (obj.get('solutions') or []) if isinstance(obj, dict) else []
                        except Exception:
                            sols = []
                        external_paths = _write_external_seeds_from_solutions(sols or [], cfg=cfg, seq=int(n), defaults=defaults, logger=logger, seed_kind_flags=seed_kind_flags)
                        out["external_seed_paths"] = external_paths
                        logger.info('write_external_seeds', count=len(external_paths), external_seed_dir=_resolve_external_seed_dir(cfg))
                        if external_paths:
                            try:
                                from skip_cache.if_stmt_counter import inc_count
                                _ = inc_count(ctx.get("path"), ctx.get("line"), inc=1)
                            except Exception:
                                pass
                    except Exception:
                        logger.exception('write_external_seeds_failed')
        except Exception as exc:
            _append_stage_debug(run_dir, "prompt_failed", seq=int(n), error=str(exc))
            heartbeat.update("prompt_failed", status="running", message="write_symbolic_prompt_failed")
            logger.exception('write_symbolic_prompt_failed')
    return finish(out, symbolic_empty=symbolic_empty)

def run_analyze_job(
    seq: int,
    *,
    cfg=None,
    argv: Optional[List[str]] = None,
    opts: Optional[dict] = None,
    llm_test_mode: bool = False,
    release_token: bool = False,
) -> dict:
    args = list(argv or [])
    cfg = cfg or load_app_config(argv=args)
    opts = dict(opts or {})
    if "llm_mode" not in opts:
        opts["llm_mode"] = (not bool(llm_test_mode))
    cfg_flags = _parse_analyze_flags_from_config(cfg.raw if hasattr(cfg, 'raw') else {})
    llm_temperature = _parse_analyze_llm_temperature_from_config(cfg.raw if hasattr(cfg, 'raw') else {})
    retry_cfg = _parse_retry_counts_from_config(cfg.raw if hasattr(cfg, 'raw') else {})
    debug_mode = bool(opts.get('debug_mode') or cfg_flags.get('debug'))
    prompt_mode = bool(opts.get('prompt_mode') or cfg_flags.get('prompt'))
    test_mode = bool(cfg_flags.get('test'))
    llm_enabled = not bool(llm_test_mode)
    llm_max_calls = opts.get('llm_max_calls')
    retry_times = int(retry_cfg.get('symbolic_prompt_retry_attempts') or 1)
    total_attempts = 1 + max(0, retry_times)
    last_obj = {}
    try:
        for attempt_idx in range(total_attempts):
            last_obj, symbolic_empty = _run_analyze_once(
                n=int(seq),
                cfg=cfg,
                opts=opts,
                debug_mode=bool(debug_mode),
                prompt_mode=bool(prompt_mode),
                test_mode=bool(test_mode),
                llm_enabled=bool(llm_enabled),
                llm_max_calls=llm_max_calls,
                llm_temperature=float(llm_temperature),
                retry_cfg=retry_cfg,
            )
            if not symbolic_empty:
                break
        return last_obj if isinstance(last_obj, dict) else {}
    finally:
        if release_token:
            pool_dir = os.environ.get("WC_TOKEN_POOL_DIR") or ""
            kind = os.environ.get("WC_TOKEN_KIND") or ""
            if pool_dir and kind:
                try:
                    from hybrid_io.token_pool import release
                    release(pool_dir.strip(), kind=str(kind))
                except Exception:
                    pass


def main():
    """CLI entrypoint: `python analyze_if_line.py <seq> [--debug] [--llm] [--llm-max=N]`."""
    if len(sys.argv) < 2:
        return
    s = sys.argv[1]
    args = sys.argv[2:]
    cfg = load_app_config(argv=args)
    opts = parse_cli_args(args)
    cfg_flags = _parse_analyze_flags_from_config(cfg.raw if hasattr(cfg, 'raw') else {})
    try:
        n = int(s)
    except:
        return
    llm_test_mode = not bool(opts.get('llm_mode'))
    run_analyze_job(
        int(n),
        cfg=cfg,
        argv=args,
        opts=opts,
        llm_test_mode=llm_test_mode,
        release_token=True,
    )
    return

if __name__ == '__main__':
    main()
