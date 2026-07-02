"""Artifact and structured logging helpers for db_search."""

import json
import os
import re
import time
from typing import Any, Dict, Optional


def append_runtime_debug_log(*, run_dir: str = "", runtime_dir: str = "", message: str = "") -> str:
    log_dir = ensure_log_dir(run_dir=run_dir, runtime_dir=runtime_dir)
    if not log_dir:
        return ""
    path = os.path.join(log_dir, "runtime_debug.log")
    line = "[%d] %s" % (int(time.time()), str(message or "").strip())
    try:
        with open(path, "a", encoding="utf-8", errors="replace") as f:
            f.write(line.rstrip() + "\n")
    except Exception:
        return ""
    return path


def _safe_name(text: str) -> str:
    s = str(text or "").strip()
    if not s:
        return "unknown"
    out = []
    for ch in s:
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out).strip("_") or "unknown"


def ensure_log_dir(*, run_dir: str = "", runtime_dir: str = "") -> str:
    base = ""
    if run_dir:
        base = os.path.abspath(run_dir)
    elif runtime_dir:
        base = os.path.abspath(runtime_dir)
    if not base:
        return ""
    try:
        os.makedirs(base, exist_ok=True)
    except Exception:
        return ""
    return base


def _round_dir_name(*, phase: str = "", round_index: int = 0, role: str = "") -> str:
    return "phase_%s_round_%02d" % (_safe_name(phase), int(round_index or 0))


def _guess_round_subdir(*, stream: str = "", payload: Optional[Dict[str, Any]] = None) -> str:
    obj = dict(payload or {})
    phase = str(obj.get("phase") or obj.get("phase_name") or "").strip()
    round_index = obj.get("round_index")
    role = str(obj.get("role") or "").strip()
    if phase and round_index not in (None, ""):
        try:
            return _round_dir_name(phase=phase, round_index=int(round_index), role=role)
        except Exception:
            pass
    stream_s = _safe_name(stream)
    if stream_s in ("db_runtime_events", "errors"):
        command_id = str(obj.get("command_id") or "").strip()
        if command_id:
            m = re.search(r"phase_([A-Za-z0-9_]+)_round_(\d+)", command_id)
            if m:
                return "phase_%s_round_%02d" % (_safe_name(m.group(1)), int(m.group(2)))
    return ""


def append_jsonl_event(*, run_dir: str = "", runtime_dir: str = "", stream: str = "events", payload: Optional[Dict[str, Any]] = None) -> str:
    log_dir = ensure_log_dir(run_dir=run_dir, runtime_dir=runtime_dir)
    if not log_dir:
        return ""
    round_subdir = _guess_round_subdir(stream=stream, payload=payload)
    target_dir = os.path.join(log_dir, round_subdir) if round_subdir else log_dir
    try:
        os.makedirs(target_dir, exist_ok=True)
    except Exception:
        return ""
    path = os.path.join(target_dir, "error.log" if _safe_name(stream) == "errors" else (_safe_name(stream) + ".jsonl"))
    obj = dict(payload or {})
    obj.setdefault("ts", int(time.time()))
    try:
        with open(path, "a", encoding="utf-8", errors="replace") as f:
            f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception:
        return ""
    return path


def archive_text_blob(*, run_dir: str = "", runtime_dir: str = "", category: str = "artifacts", basename: str = "artifact", suffix: str = ".txt", text: str = "") -> str:
    log_dir = ensure_log_dir(run_dir=run_dir, runtime_dir=runtime_dir)
    if not log_dir:
        return ""
    cat = _safe_name(category)
    sub_dir = os.path.join(log_dir, cat) if cat and cat != "unknown" else log_dir
    try:
        os.makedirs(sub_dir, exist_ok=True)
    except Exception:
        return ""
    path = os.path.join(sub_dir, _safe_name(basename) + suffix)
    try:
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(str(text or ""))
    except Exception:
        return ""
    return path


def archive_llm_exchange(
    *,
    run_dir: str = "",
    runtime_dir: str = "",
    phase: str = "",
    round_index: int = 0,
    role: str = "planner",
    prompt_text: str = "",
    response_text: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    base_dir = ensure_log_dir(run_dir=run_dir, runtime_dir=runtime_dir)
    if not base_dir:
        return {"prompt_path": "", "response_path": ""}
    round_subdir = _round_dir_name(phase=phase, round_index=round_index, role=role)
    target_dir = os.path.join(base_dir, round_subdir)
    try:
        os.makedirs(target_dir, exist_ok=True)
    except Exception:
        return {"prompt_path": "", "response_path": ""}
    prompt_path = os.path.join(target_dir, "prompt.txt")
    response_path = os.path.join(target_dir, "response.txt")
    try:
        with open(prompt_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(str(prompt_text or ""))
        with open(response_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(str(response_text or ""))
    except Exception:
        return {"prompt_path": "", "response_path": ""}
    append_jsonl_event(
        run_dir=run_dir,
        runtime_dir=runtime_dir,
        stream="llm_events",
        payload={
            "kind": "llm_exchange",
            "phase": str(phase or ""),
            "round_index": int(round_index or 0),
            "role": str(role or ""),
            "prompt_path": prompt_path,
            "response_path": response_path,
            "metadata": dict(metadata or {}),
        },
    )
    return {"prompt_path": prompt_path, "response_path": response_path}
