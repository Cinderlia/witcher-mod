import heapq
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl

from common.process_kill_audit import record_process_kill
from hybrid_io.seed_picker import list_queue_dirs, pick_preferred_seed
from hybrid_io import token_pool


_ID_RE = re.compile(r"id:(\d+)")
_ENV_RE = re.compile(r"env:([0-9A-Fa-f]+)")
_KV_SPLIT_RE = re.compile(r"[;&\n\r\t ]+")


def _read_json(path: str) -> Any:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def _write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def _parse_seed_id(path: str) -> Optional[int]:
    m = _ID_RE.search(os.path.basename(path or ""))
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _parse_seed_env_id(path: str) -> str:
    m = _ENV_RE.search(os.path.basename(path or ""))
    if not m:
        return ""
    return str(m.group(1) or "").strip()


def _seed_dedupe_hash(path: str, seed_hash: str) -> str:
    base = str(seed_hash or "").strip()
    if not base:
        return ""
    env_id = _parse_seed_env_id(path).lower()
    if not env_id:
        return base
    return hashlib.sha1(("%s|env:%s" % (base, env_id)).encode("utf-8", errors="replace")).hexdigest()


def _seen_hashes_path(runtime_root: str) -> str:
    return os.path.join(runtime_root, "meta", "seen_seed_hashes.json")


def _load_seen_hashes(runtime_root: str) -> Set[str]:
    obj = _read_json(_seen_hashes_path(runtime_root))
    if isinstance(obj, dict) and isinstance(obj.get("hashes"), list):
        return {str(x) for x in obj.get("hashes") if isinstance(x, str)}
    if isinstance(obj, list):
        return {str(x) for x in obj if isinstance(x, str)}
    return set()


def _save_seen_hashes(runtime_root: str, hashes: Set[str]) -> None:
    _write_json(_seen_hashes_path(runtime_root), {"hashes": sorted(set(hashes or set()))})


def _load_prepare_report(runtime_root: str) -> Dict[str, str]:
    obj = _read_json(os.path.join(runtime_root, "meta", "prepare_report.json"))
    if not isinstance(obj, dict):
        return {}
    out: Dict[str, str] = {}
    v = obj.get("ast_dir")
    if isinstance(v, str) and v.strip():
        out["ast_dir"] = os.path.abspath(v.strip())
    c = obj.get("coverage_json_expected")
    if isinstance(c, str) and c.strip():
        out["coverage_json_path"] = c.strip()
    sc = obj.get("trace_session_capture_filename")
    if isinstance(sc, str) and sc.strip():
        out["trace_session_capture_filename"] = os.path.basename(sc.strip())
    return out


def _parent_seed_info_path(run_dir: str) -> str:
    return os.path.join(run_dir, "meta", "parent_seed_info.json")


def _parse_seed_id_text(path: str) -> str:
    m = _ID_RE.search(os.path.basename(path or ""))
    if not m:
        return ""
    return str(m.group(1) or "").strip()


def _source_fuzzer_name(queue_dir: str) -> str:
    try:
        name = os.path.basename(os.path.dirname(str(queue_dir or "").rstrip("/\\")))
    except Exception:
        name = ""
    return str(name or "").strip() or "unknown"


def _write_parent_seed_info(run_dir: str, *, seed_path: str, seed_id: Optional[int], seed_hash: str, queue_dir: str) -> str:
    path = _parent_seed_info_path(run_dir)
    seed_name = os.path.basename(str(seed_path or "").rstrip("/\\"))
    _write_json(
        path,
        {
            "seed_path": str(seed_path or ""),
            "seed_name": seed_name,
            "seed_id": (int(seed_id) if seed_id is not None else None),
            "seed_id_text": _parse_seed_id_text(seed_name),
            "seed_env_id": _parse_seed_env_id(seed_name),
            "seed_hash8": str((seed_hash or "")[:8]),
            "queue_dir": str(queue_dir or ""),
            "source_fuzzer": _source_fuzzer_name(queue_dir),
            "recorded_at": int(time.time()),
            "recorded_by_pid": int(os.getpid()),
        },
    )
    return path


def _trace_session_capture_source_path(runtime_root: str) -> str:
    prep = _load_prepare_report(runtime_root)
    name = str(prep.get("trace_session_capture_filename") or "").strip()
    if not name:
        return ""
    return os.path.join("/tmp", "wc_session_trace", os.path.basename(name))


def _seed_env_dir(runtime_root: str, kind: str) -> str:
    if str(kind or "").strip().lower() == "child":
        env_v = os.environ.get("WC_ENV_CHILD_DIR") or ""
        default_path = os.path.join(runtime_root, "seed_env_profiles", "child")
    else:
        env_v = os.environ.get("WC_ENV_PARENT_DIR") or ""
        default_path = os.path.join(runtime_root, "seed_env_profiles", "parent")
    if isinstance(env_v, str) and env_v.strip():
        return os.path.abspath(env_v.strip())
    return os.path.abspath(default_path)


def _read_seed_env_profile(path: str) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {}
    if not path or not os.path.isfile(path):
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


def _shell_quote_double(value: str) -> str:
    s = str(value or "")
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("$", "\\$")
    s = s.replace("`", "\\`")
    return s


def _write_trace_env_overrides(runtime_root: str, run_dir: str, seed_path: str, logger) -> str:
    inp_dir = os.path.join(run_dir, "input")
    os.makedirs(inp_dir, exist_ok=True)
    override_path = os.path.join(inp_dir, "trace_env_overrides.sh")
    seed_env_id = _parse_seed_env_id(seed_path)
    env_map: Dict[str, Optional[str]] = {}
    source_path = ""
    if seed_env_id:
        child_path = os.path.join(_seed_env_dir(runtime_root, "child"), "%s.env" % seed_env_id)
        parent_path = os.path.join(_seed_env_dir(runtime_root, "parent"), "%s.env" % seed_env_id)
        for cand in (child_path, parent_path):
            env_map = _read_seed_env_profile(cand)
            if env_map:
                source_path = cand
                break
    lines: List[str] = ["#!/bin/bash", "set -euo pipefail"]
    for key in sorted(env_map.keys()):
        key_s = str(key or "").strip()
        if not key_s:
            continue
        value = env_map.get(key_s)
        if value is None:
            lines.append("unset %s" % key_s)
        else:
            lines.append('export %s="%s"' % (key_s, _shell_quote_double(value)))
    try:
        with open(override_path, "w", encoding="utf-8", errors="replace") as wf:
            wf.write("\n".join(lines).rstrip() + "\n")
        try:
            logger(
                runtime_root,
                "trace_env_override_ready seed=%s env_id=%s override_path=%s source=%s keys=%s"
                % (
                    str(seed_path or ""),
                    str(seed_env_id or ""),
                    override_path,
                    str(source_path or ""),
                    ",".join(sorted(env_map.keys())),
                ),
            )
        except Exception:
            pass
    except Exception as ex:
        try:
            logger(runtime_root, "trace_env_override_write_failed seed=%s path=%s error=%s" % (str(seed_path or ""), override_path, str(ex)))
        except Exception:
            pass
    return override_path


def _reset_trace_session_capture(runtime_root: str, run_dir: str, logger) -> None:
    paths = [
        _trace_session_capture_source_path(runtime_root),
        os.path.join(run_dir, "input", "session_capture.json"),
    ]
    for path in paths:
        if not path or not os.path.exists(path):
            continue
        try:
            os.remove(path)
        except Exception:
            continue


def _collect_trace_session_capture(runtime_root: str, run_dir: str, logger) -> bool:
    src = _trace_session_capture_source_path(runtime_root)
    dst = os.path.join(run_dir, "input", "session_capture.json")
    if not src:
        try:
            logger(runtime_root, "trace_session_capture_skip reason=missing_filename run_dir=%s" % run_dir)
        except Exception:
            pass
        return False
    if not os.path.exists(src):
        try:
            logger(runtime_root, "trace_session_capture_missing source=%s run_dir=%s" % (src, run_dir))
        except Exception:
            pass
        return False
    try:
        os.makedirs(os.path.dirname(os.path.abspath(dst)) or ".", exist_ok=True)
        shutil.copy2(src, dst)
        try:
            logger(runtime_root, "trace_session_capture_copied source=%s dest=%s run_dir=%s" % (src, dst, run_dir))
        except Exception:
            pass
        return True
    except Exception as ex:
        try:
            logger(runtime_root, "trace_session_capture_copy_failed source=%s dest=%s run_dir=%s error=%s" % (src, dst, run_dir, str(ex)))
        except Exception:
            pass
        return False


def _sha1_file(path: str, limit_bytes: int = 4 * 1024 * 1024) -> Optional[str]:
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha1()
    read_total = 0
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
                read_total += len(chunk)
                if read_total >= int(limit_bytes):
                    break
    except Exception:
        return None
    return h.hexdigest()


def _popcount(x: int) -> int:
    bc = getattr(int, "bit_count", None)
    if bc is not None:
        try:
            return int(bc(x))
        except Exception:
            return int(bin(int(x)).count("1"))
    return int(bin(int(x)).count("1"))


def _sig_distance(a: int, b: int) -> float:
    try:
        ia = int(a) & int(b)
        ua = int(a) | int(b)
        inter = _popcount(int(ia))
        union = _popcount(int(ua))
        if union <= 0:
            return 0.0
        return float(union - inter) / float(union)
    except Exception:
        return 0.0


def _seed_get_keys_signature(path: str, limit_bytes: int = 64 * 1024, bit_count: int = 2048) -> Optional[int]:
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as f:
            data = f.read(int(limit_bytes))
    except Exception:
        return None
    if not data:
        return 0
    parts = (data or b"").split(b"\x00")
    get_raw = parts[1] if len(parts) >= 2 else b""
    try:
        get_s = get_raw.decode("utf-8", errors="replace")
    except Exception:
        get_s = ""
    if not get_s:
        return 0
    keys: List[str] = []
    try:
        items = parse_qsl(get_s, keep_blank_values=True, strict_parsing=False)
    except Exception:
        items = []
    if items:
        for k, _v in items:
            kk = (k or "").strip()
            if kk:
                keys.append(kk)
    else:
        for it in _KV_SPLIT_RE.split(get_s):
            if not it:
                continue
            if "=" in it:
                k, _v = it.split("=", 1)
                kk = (k or "").strip()
                if kk:
                    keys.append(kk)
            else:
                kk = (it or "").strip()
                if kk:
                    keys.append(kk)
    if not keys:
        return 0
    mask = int(bit_count) - 1
    sig = 0
    for k in keys:
        try:
            hb = hashlib.sha1(("g:k:%s" % k).encode("utf-8", errors="replace")).digest()
        except Exception:
            continue
        if not hb or len(hb) < 8:
            continue
        h = int.from_bytes(hb[:8], "little", signed=False)
        i1 = int(h) & mask
        i2 = int((h >> 17) & mask)
        sig |= (1 << i1)
        sig |= (1 << i2)
    return int(sig)



def _load_limits(symex_cfg_path: str):
    obj = _read_json(symex_cfg_path) if symex_cfg_path else None
    if not isinstance(obj, dict):
        return 10, 1
    sec = obj.get("symex_scheduler") if isinstance(obj.get("symex_scheduler"), dict) else {}
    max_analyze = sec.get("max_analyze_procs")
    max_bs = sec.get("max_branch_selector_procs")
    try:
        max_analyze_i = int(max_analyze) if max_analyze is not None else 10
    except Exception:
        max_analyze_i = 10
    try:
        max_bs_i = int(max_bs) if max_bs is not None else 1
    except Exception:
        max_bs_i = 1
    return max(1, max_analyze_i), max(1, max_bs_i)


def _seed_run_name(seed_path: str, queue_dir: str, seed_hash: str) -> str:
    seed_name = os.path.basename(str(seed_path or "").rstrip("/\\")) or (seed_hash or "seed")[:8] or "seed"
    qd = os.path.abspath(str(queue_dir or ""))
    qd_base = os.path.basename(qd)
    if qd_base == "queue":
        qd_base = os.path.basename(os.path.dirname(qd))
    qd_base = str(qd_base or "").strip()
    if qd_base:
        return "%s__%s" % (qd_base, seed_name)
    return seed_name


def _make_run_dir(runtime_root: str, seed_path: str, queue_dir: str, seed_hash: str) -> str:
    runs = os.path.join(runtime_root, "runs")
    os.makedirs(runs, exist_ok=True)
    name = _seed_run_name(seed_path, queue_dir, seed_hash)
    run_dir = os.path.join(runs, name)
    if os.path.exists(run_dir):
        suffix = 1
        while True:
            candidate = os.path.join(runs, "%s__dup%d" % (name, int(suffix)))
            if not os.path.exists(candidate):
                run_dir = candidate
                break
            suffix += 1
    os.makedirs(run_dir, exist_ok=True)
    for d in ("input", "tmp", "test", "output", "meta", "traces"):
        os.makedirs(os.path.join(run_dir, d), exist_ok=True)
    return run_dir


def _tail_text(s: str, limit: int = 2000) -> str:
    try:
        if s is None:
            return ""
        s = str(s)
    except Exception:
        return ""
    if limit is None or int(limit) <= 0:
        return s
    lim = int(limit)
    return s[-lim:] if len(s) > lim else s


def _write_text(path: str, text: str) -> None:
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(text or "")
    except Exception:
        pass


def _read_text(path: str, limit: int = 2000) -> str:
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except Exception:
        return ""
    return _tail_text(data, limit=limit)


def _close_process_logs(proc: subprocess.Popen) -> None:
    for attr in ("_wc_stdout_fp", "_wc_stderr_fp"):
        fp = getattr(proc, attr, None)
        if fp is None:
            continue
        try:
            fp.close()
        except Exception:
            pass
        try:
            setattr(proc, attr, None)
        except Exception:
            pass


def _close_log_pair(out_fp, err_fp) -> None:
    for fp in (out_fp, err_fp):
        if fp is None:
            continue
        try:
            fp.close()
        except Exception:
            pass


def _branch_selector_token_marker_path(run_dir: str) -> str:
    return os.path.join(os.path.abspath(run_dir or "."), "meta", "branch_selector.token.released")


def _branch_selector_process_info_path(run_dir: str) -> str:
    return os.path.join(os.path.abspath(run_dir or "."), "meta", "branch_selector.process.json")


def _branch_selector_heartbeat_status_path(run_dir: str) -> str:
    return os.path.join(os.path.abspath(run_dir or "."), "meta", "branch_selector.heartbeat.status.json")


def _branch_selector_reclaim_log_path(run_dir: str) -> str:
    return os.path.join(os.path.abspath(run_dir or "."), "meta", "branch_selector.token.reclaim.jsonl")


def _pid_alive(pid: int) -> Optional[bool]:
    try:
        pid_i = int(pid)
    except Exception:
        return None
    if pid_i <= 0:
        return None
    try:
        os.kill(pid_i, 0)
        return True
    except OSError:
        return False
    except Exception:
        return None


def _append_jsonl(path: str, payload: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            f.write("\n")
    except Exception:
        pass


def _write_branch_selector_process_info(run_dir: str, payload: Dict[str, Any]) -> None:
    out = dict(payload or {})
    out["run_dir"] = os.path.abspath(run_dir or ".")
    out["updated_at"] = int(time.time())
    _write_json(_branch_selector_process_info_path(run_dir), out)


def _collect_branch_selector_debug(run_dir: str) -> Dict[str, Any]:
    run_dir_abs = os.path.abspath(run_dir or ".")
    process_info = _read_json(_branch_selector_process_info_path(run_dir_abs))
    hb = _read_json(_branch_selector_heartbeat_status_path(run_dir_abs))
    marker_path = _branch_selector_token_marker_path(run_dir_abs)
    out_path = os.path.join(run_dir_abs, "meta", "branch_selector.out")
    err_path = os.path.join(run_dir_abs, "meta", "branch_selector.err")
    payload: Dict[str, Any] = {
        "run_dir": run_dir_abs,
        "marker_exists": bool(os.path.exists(marker_path)),
        "marker_path": marker_path,
        "heartbeat_exists": bool(isinstance(hb, dict) and hb),
        "heartbeat_path": _branch_selector_heartbeat_status_path(run_dir_abs),
        "process_info_exists": bool(isinstance(process_info, dict) and process_info),
        "process_info_path": _branch_selector_process_info_path(run_dir_abs),
        "branch_selector_out_path": out_path,
        "branch_selector_err_path": err_path,
    }
    if isinstance(process_info, dict):
        payload["process_pid"] = int(process_info.get("pid") or 0) if process_info.get("pid") is not None else 0
        payload["process_started_at"] = int(process_info.get("started_at") or 0) if process_info.get("started_at") is not None else 0
        payload["process_status"] = str(process_info.get("status") or "")
        payload["seed_path"] = str(process_info.get("seed_path") or "")
        payload["queue_dir"] = str(process_info.get("queue_dir") or "")
    if isinstance(hb, dict):
        payload["heartbeat_pid"] = int(hb.get("pid") or 0) if hb.get("pid") is not None else 0
        payload["heartbeat_status"] = str(hb.get("status") or "")
        payload["heartbeat_stage"] = str(hb.get("stage") or "")
        payload["heartbeat_message"] = str(hb.get("message") or "")
        payload["heartbeat_updated_at"] = str(hb.get("updated_at") or "")
    try:
        payload["heartbeat_mtime"] = float(os.path.getmtime(_branch_selector_heartbeat_status_path(run_dir_abs)))
    except Exception:
        pass
    payload["stdout_tail"] = _read_text(out_path)
    payload["stderr_tail"] = _read_text(err_path)
    return payload


def _branch_selector_heartbeat_fresh(run_dir: str, *, stale_after_sec: float = 35.0) -> bool:
    try:
        mtime = float(os.path.getmtime(_branch_selector_heartbeat_status_path(run_dir)))
    except Exception:
        return False
    return (time.time() - mtime) <= max(1.0, float(stale_after_sec))


def _signal_name_from_return_code(rc: Optional[int]) -> str:
    if rc is None:
        return ""
    try:
        rc_i = int(rc)
    except Exception:
        return ""
    if rc_i >= 0:
        return ""
    try:
        import signal
        return signal.Signals(abs(int(rc_i))).name
    except Exception:
        return "SIG%d" % abs(int(rc_i))


def _reclaim_branch_selector_token(meta_dir: str, run_dir: str, runtime_root: str, logger, *, reason: str, debug_payload: Dict[str, Any]) -> bool:
    marker_path = _branch_selector_token_marker_path(run_dir)
    if os.path.exists(marker_path):
        return False
    try:
        ok = token_pool.release(meta_dir, kind="branch_selector")
    except Exception:
        ok = False
    event = dict(debug_payload or {})
    event["reason"] = str(reason or "")
    event["reclaimed_at"] = int(time.time())
    event["released"] = bool(ok)
    event["released_by"] = "daemon_scavenger"
    _append_jsonl(_branch_selector_reclaim_log_path(run_dir), event)
    if bool(ok):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(marker_path)) or ".", exist_ok=True)
            with open(marker_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "released_by": "daemon_scavenger",
                        "pid": int((debug_payload or {}).get("heartbeat_pid") or (debug_payload or {}).get("process_pid") or 0),
                        "released_at": int(time.time()),
                        "reason": str(reason or ""),
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
        except Exception:
            pass
        try:
            logger(
                runtime_root,
                "branch_selector_token_reclaimed reason=%s run_dir=%s pid=%s heartbeat_status=%s heartbeat_stage=%s"
                % (
                    str(reason or ""),
                    str(run_dir or ""),
                    str((debug_payload or {}).get("heartbeat_pid") or (debug_payload or {}).get("process_pid") or ""),
                    str((debug_payload or {}).get("heartbeat_status") or ""),
                    str((debug_payload or {}).get("heartbeat_stage") or ""),
                ),
            )
        except Exception:
            pass
    return bool(ok)


def _ensure_branch_selector_token_released(meta_dir: str, proc: subprocess.Popen, runtime_root: str, logger) -> None:
    try:
        if bool(getattr(proc, "_wc_token_released", False)):
            return
    except Exception:
        pass
    marker_path = str(getattr(proc, "_wc_token_release_marker", "") or "")
    if not marker_path:
        run_dir = str(getattr(proc, "_wc_run_dir", "") or "")
        if run_dir:
            marker_path = _branch_selector_token_marker_path(run_dir)
    if marker_path and os.path.exists(marker_path):
        try:
            setattr(proc, "_wc_token_released", True)
        except Exception:
            pass
        return
    try:
        ok = token_pool.release(meta_dir, kind="branch_selector")
    except Exception:
        ok = False
    if bool(ok):
        try:
            if marker_path:
                os.makedirs(os.path.dirname(os.path.abspath(marker_path)) or ".", exist_ok=True)
                with open(marker_path, "w", encoding="utf-8") as f:
                    json.dump({"released_by": "daemon", "pid": int(getattr(proc, "pid", 0) or 0), "released_at": int(time.time())}, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        try:
            setattr(proc, "_wc_token_released", True)
        except Exception:
            pass
        try:
            logger(
                runtime_root,
                "branch_selector_token_released_by_daemon pid=%s run_dir=%s"
                % (str(getattr(proc, "pid", "")), str(getattr(proc, "_wc_run_dir", "") or "")),
            )
        except Exception:
            pass


def _run_trace_into(
    runtime_root: str,
    seed_path: str,
    run_dir: str,
    trace_timeout: int,
    logger,
    *,
    seed_id: Optional[int] = None,
    seed_hash: str = "",
) -> bool:
    trace_script = os.path.join(runtime_root, "commands", "run_trace_with_seed.sh")
    if not os.path.isfile(trace_script):
        logger(runtime_root, "trace_script_missing path=%s" % trace_script)
        return False
    inp_dir = os.path.join(run_dir, "input")
    os.makedirs(inp_dir, exist_ok=True)
    _write_trace_env_overrides(runtime_root, run_dir, seed_path, logger)
    _reset_trace_session_capture(runtime_root, run_dir, logger)
    try:
        logger(
            runtime_root,
            "trace_start seed=%s seed_id=%s seed_hash8=%s run_dir=%s"
            % (seed_path, str(seed_id) if seed_id is not None else "", str((seed_hash or "")[:8]), run_dir),
        )
    except Exception:
        pass
    try:
        proc = subprocess.run(
            ["bash", trace_script, seed_path],
            cwd=inp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(trace_timeout)),
            check=False,
        )
    except Exception as ex:
        logger(runtime_root, "trace_fail seed=%s error=%s" % (seed_path, str(ex)))
        return False
    trace_path = os.path.join(inp_dir, "trace.log")
    trace_ok = False
    if os.path.exists(trace_path):
        if proc.returncode == 0:
            trace_ok = True
        else:
            try:
                with open(trace_path, "rb") as f:
                    line_count = sum(1 for _ in f)
                if line_count > 100:
                    trace_ok = True
            except Exception:
                pass
    if not trace_ok:
        out_path = os.path.join(inp_dir, "trace_stdout.log")
        err_path = os.path.join(inp_dir, "trace_stderr.log")
        _write_text(out_path, proc.stdout or "")
        _write_text(err_path, proc.stderr or "")
        cmd_out = os.path.join(inp_dir, "trace_cmd.stdout")
        cmd_err = os.path.join(inp_dir, "trace_cmd.stderr")
        cmd_rc = os.path.join(inp_dir, "trace_cmd.rc")
        cmd_env = os.path.join(inp_dir, "trace_cmd.env")
        stdout_tail = _tail_text(proc.stdout or "")
        stderr_tail = _tail_text(proc.stderr or "")
        cmd_stdout_tail = _read_text(cmd_out)
        cmd_stderr_tail = _read_text(cmd_err)
        cmd_rc_val = _read_text(cmd_rc, limit=64)
        cmd_env_tail = _read_text(cmd_env)
        logger(
            runtime_root,
            "trace_fail seed=%s rc=%s trace_script=%s cwd=%s trace_log=%s stdout_log=%s stderr_log=%s trace_cmd_rc=%s trace_cmd_env=%s trace_cmd_stdout_tail=%s trace_cmd_stderr_tail=%s stdout_tail=%s stderr_tail=%s"
            % (
                seed_path,
                str(proc.returncode),
                trace_script,
                inp_dir,
                trace_path,
                out_path,
                err_path,
                cmd_rc_val.replace("\n", "\\n"),
                cmd_env_tail.replace("\n", "\\n"),
                cmd_stdout_tail.replace("\n", "\\n"),
                cmd_stderr_tail.replace("\n", "\\n"),
                stdout_tail.replace("\n", "\\n"),
                stderr_tail.replace("\n", "\\n"),
            ),
        )
        return False
    try:
        import shutil
        shutil.copy2(seed_path, os.path.join(inp_dir, "seed.bin"))
    except Exception:
        pass
    try:
        cmd_src = os.path.join(runtime_root, "commands", "test_command.txt")
        cmd_dst = os.path.join(inp_dir, "test_command.txt")
        cmd_txt = ""
        try:
            with open(cmd_src, "r", encoding="utf-8", errors="replace") as f:
                cmd_txt = f.read()
        except Exception:
            cmd_txt = ""
        cookie_s = ""
        get_s = ""
        post_s = ""
        try:
            with open(seed_path, "rb") as f:
                data = f.read()
            parts = (data or b"").split(b"\x00")
            cookie_s = (parts[0] if len(parts) > 0 else b"").decode("utf-8", errors="replace")
            get_s = (parts[1] if len(parts) > 1 else b"").decode("utf-8", errors="replace")
            post_s = (parts[2] if len(parts) > 2 else b"").decode("utf-8", errors="replace")
        except Exception:
            pass
        with open(cmd_dst, "w", encoding="utf-8", errors="replace") as f:
            if cmd_txt:
                f.write(cmd_txt.rstrip() + "\n")
            f.write("COOKIE:" + (cookie_s or "").strip() + "\n")
            f.write("GET:" + (get_s or "").strip() + "\n")
            f.write("POST:" + (post_s or "").strip() + "\n")
    except Exception:
        pass
    _collect_trace_session_capture(runtime_root, run_dir, logger)
    return True


def _build_run_config(symex_cfg_path: Optional[str], run_dir: str, extra: Optional[Dict[str, Any]] = None) -> str:
    base_obj = _read_json(symex_cfg_path) if symex_cfg_path else None
    if not isinstance(base_obj, dict):
        base_obj = {}
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k not in base_obj:
                base_obj[k] = v
    paths = base_obj.get("paths") if isinstance(base_obj.get("paths"), dict) else {}
    if not isinstance(paths, dict):
        paths = {}
    paths.setdefault("input_dir", "input")
    paths.setdefault("tmp_dir", "tmp")
    paths.setdefault("test_dir", "test")
    paths.setdefault("output_dir", "output")
    base_obj["paths"] = paths
    out_path = os.path.join(run_dir, "config.json")
    _write_json(out_path, base_obj)
    return out_path


def _symex_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pick_one_seed(work_dir: str, processed_by_queue: Dict[str, Dict[int, int]]) -> Optional[Tuple[str, Optional[int]]]:
    for qd in list_queue_dirs(work_dir):
        proc_map = processed_by_queue.setdefault(qd, {})
        sp = pick_preferred_seed(qd, processed_ids=proc_map)
        if not sp:
            continue
        sid = _parse_seed_id(sp)
        if sid is not None:
            proc_map[int(sid)] = int(proc_map.get(int(sid), 0)) + 1
        return sp, sid
    return None


def _list_new_seeds(queue_dir: str, last_id: int) -> Tuple[List[Tuple[int, str, float]], int]:
    out: List[Tuple[int, str, float]] = []
    max_id = int(last_id)
    if not queue_dir or not os.path.isdir(queue_dir):
        return out, max_id
    try:
        with os.scandir(queue_dir) as it:
            for ent in it:
                try:
                    if not ent.is_file():
                        continue
                    nm = ent.name
                    if not isinstance(nm, str) or not nm.startswith("id:"):
                        continue
                    sid = _parse_seed_id(nm)
                    if sid is None:
                        continue
                    sid_i = int(sid)
                    if sid_i <= int(last_id):
                        continue
                    try:
                        mt = float(ent.stat().st_mtime)
                    except Exception:
                        mt = 0.0
                    out.append((sid_i, ent.path, mt))
                    if sid_i > max_id:
                        max_id = sid_i
                except Exception:
                    continue
    except Exception:
        return out, max_id
    out.sort(key=lambda t: (int(t[0]), float(t[2])))
    return out, max_id


def _count_scanned_seeds(work_dir: str) -> int:
    total = 0
    for qd in list_queue_dirs(work_dir):
        try:
            with os.scandir(qd) as it:
                for ent in it:
                    try:
                        if ent.is_file() and ent.name.startswith("id:"):
                            total += 1
                    except Exception:
                        continue
        except Exception:
            continue
    return int(total)


class HybridTokenDaemon:
    def __init__(self, *, runtime_root: str, work_dir: str, symex_cfg_path: Optional[str], trace_timeout: int, logger):
        self.runtime_root = runtime_root
        self.work_dir = work_dir
        self.symex_cfg_path = symex_cfg_path
        self.trace_timeout = int(trace_timeout)
        self.logger = logger

        self.meta_dir = os.path.join(self.runtime_root, "meta")
        self.processed_by_queue: Dict[str, Dict[int, int]] = {}
        self.seen_hashes = _load_seen_hashes(self.runtime_root)

        max_analyze, max_bs = _load_limits(self.symex_cfg_path)
        token_pool.ensure_counter(self.meta_dir, kind="analyze", initial=int(max_analyze))
        token_pool.ensure_counter(self.meta_dir, kind="branch_selector", initial=int(max_bs))

        self.pipeline_py = os.path.join(_symex_root(), "branch_selector", "pipeline.py")
        self.extsync_queue_dir = os.path.join(self.work_dir, "extsync", "queue")
        self.running: List[subprocess.Popen] = []
        self._run_cfg_path = os.path.join(self.runtime_root, "config.json")
        self._bs_cfg_path = self.symex_cfg_path or os.path.join(_symex_root(), "config.json")

        self._queue_last_id: Dict[str, int] = {}
        self._enqueued_seed_keys: Set[Tuple[str, int]] = set()
        self._seed_heap: List[Tuple[Tuple[int, int, float, int], str, str, int, int]] = []
        self._processed_get_sigs: List[int] = []
        self._processed_get_sigs_set: Set[int] = set()

    def _update_branch_selector_process_info(self, run_dir: str, **fields) -> None:
        cur = _read_json(_branch_selector_process_info_path(run_dir))
        if not isinstance(cur, dict):
            cur = {}
        for k, v in (fields or {}).items():
            cur[str(k)] = v
        _write_branch_selector_process_info(run_dir, cur)

    def _scavenge_branch_selector_tokens(self) -> None:
        runs_root = os.path.join(self.runtime_root, "runs")
        if not os.path.isdir(runs_root):
            return
        startup_grace_sec = 20.0
        for name in os.listdir(runs_root):
            run_dir = os.path.join(runs_root, name)
            if not os.path.isdir(run_dir):
                continue
            debug_payload = _collect_branch_selector_debug(run_dir)
            if not bool(debug_payload.get("process_info_exists")) and not bool(debug_payload.get("heartbeat_exists")):
                continue
            process_pid = int(debug_payload.get("process_pid") or 0)
            heartbeat_pid = int(debug_payload.get("heartbeat_pid") or 0)
            process_pid_alive = _pid_alive(process_pid)
            heartbeat_pid_alive = _pid_alive(heartbeat_pid)
            heartbeat_fresh = _branch_selector_heartbeat_fresh(run_dir, stale_after_sec=35.0)
            debug_payload["process_pid_alive"] = process_pid_alive
            debug_payload["heartbeat_pid_alive"] = heartbeat_pid_alive
            debug_payload["heartbeat_fresh"] = bool(heartbeat_fresh)
            try:
                started_at = int(debug_payload.get("process_started_at") or 0)
            except Exception:
                started_at = 0
            age_sec = max(0.0, time.time() - float(started_at)) if started_at > 0 else None
            debug_payload["process_age_sec"] = age_sec
            if bool(debug_payload.get("marker_exists")):
                continue
            if process_pid_alive is True or heartbeat_pid_alive is True:
                if (
                    process_pid_alive is True
                    and not bool(debug_payload.get("heartbeat_exists"))
                    and age_sec is not None
                    and float(age_sec) >= float(startup_grace_sec)
                ):
                    process_info = _read_json(_branch_selector_process_info_path(run_dir))
                    if not isinstance(process_info, dict) or not process_info.get("startup_missing_heartbeat_logged_at"):
                        self._update_branch_selector_process_info(
                            run_dir,
                            startup_missing_heartbeat_logged_at=int(time.time()),
                            startup_missing_heartbeat_age_sec=float(age_sec),
                            startup_missing_heartbeat_pid=int(process_pid),
                            status=str(debug_payload.get("process_status") or "spawned"),
                        )
                        self.logger(
                            self.runtime_root,
                            "branch_selector_startup_missing_heartbeat run_dir=%s pid=%s age_sec=%.1f process_status=%s stdout_tail=%s stderr_tail=%s"
                            % (
                                str(run_dir),
                                str(process_pid),
                                float(age_sec),
                                str(debug_payload.get("process_status") or ""),
                                str(debug_payload.get("stdout_tail") or "").replace("\n", "\\n"),
                                str(debug_payload.get("stderr_tail") or "").replace("\n", "\\n"),
                            ),
                        )
                continue
            reason = ""
            heartbeat_status = str(debug_payload.get("heartbeat_status") or "").strip().lower()
            process_status = str(debug_payload.get("process_status") or "").strip().lower()
            if bool(debug_payload.get("heartbeat_exists")) and heartbeat_status in ("finished", "done", "failed", "error"):
                reason = "heartbeat_%s_pid_dead" % heartbeat_status
            elif bool(debug_payload.get("heartbeat_exists")) and heartbeat_pid_alive is False and bool(heartbeat_fresh):
                reason = "heartbeat_recent_but_pid_dead"
            elif bool(debug_payload.get("heartbeat_exists")) and heartbeat_pid_alive is False:
                reason = "heartbeat_stopped_and_pid_dead"
            elif process_pid > 0 and process_pid_alive is False and age_sec is not None and float(age_sec) >= float(startup_grace_sec):
                if process_status in ("spawned", "starting", "running"):
                    reason = "startup_missing_heartbeat_pid_dead"
                else:
                    reason = "process_pid_dead_no_heartbeat"
            if not reason:
                continue
            self._update_branch_selector_process_info(
                run_dir,
                status="reclaimed",
                reclaim_reason=str(reason),
                reclaim_requested_at=int(time.time()),
                process_pid_alive=process_pid_alive,
                heartbeat_pid_alive=heartbeat_pid_alive,
                heartbeat_fresh=bool(heartbeat_fresh),
            )
            _reclaim_branch_selector_token(
                self.meta_dir,
                run_dir,
                self.runtime_root,
                self.logger,
                reason=reason,
                debug_payload=debug_payload,
            )

    def scan(self) -> None:
        for qd in list_queue_dirs(self.work_dir):
            last_id = int(self._queue_last_id.get(qd, -1))
            seeds, new_last = _list_new_seeds(qd, last_id)
            if int(new_last) > int(last_id):
                self._queue_last_id[qd] = int(new_last)
            for sid, path, mt in seeds:
                key = (str(qd), int(sid))
                if key in self._enqueued_seed_keys:
                    continue
                self._enqueued_seed_keys.add(key)

                sig = _seed_get_keys_signature(str(path))
                sig_i = int(sig) if sig is not None else 0
                nm = os.path.basename(str(path) or "")
                extsync_pri = 1 if "extsync" in (nm or "").lower() else 0
                div = 1.0
                if self._processed_get_sigs:
                    try:
                        div = min(_sig_distance(sig_i, int(x)) for x in self._processed_get_sigs)
                    except Exception:
                        div = 0.0
                div_score = int(max(0.0, min(1.0, float(div))) * 10000.0)
                pri = (-int(extsync_pri), -int(div_score), -float(mt), -int(sid))
                heapq.heappush(self._seed_heap, (pri, str(path), str(qd), int(sid), int(sig_i)))

    def reap(self) -> None:
        alive = []
        for p in self.running:
            if p.poll() is None:
                alive.append(p)
                continue
            run_dir = str(getattr(p, "_wc_run_dir", "") or "")
            rc = p.poll()
            debug_payload = _collect_branch_selector_debug(run_dir) if run_dir else {}
            if run_dir:
                self._update_branch_selector_process_info(
                    run_dir,
                    status="exited",
                    pid=int(getattr(p, "pid", 0) or 0),
                    exited_at=int(time.time()),
                    returncode=(int(rc) if rc is not None else None),
                    signal_name=_signal_name_from_return_code(rc),
                    heartbeat_exists=bool(debug_payload.get("heartbeat_exists")),
                    heartbeat_status=str(debug_payload.get("heartbeat_status") or ""),
                    heartbeat_stage=str(debug_payload.get("heartbeat_stage") or ""),
                    stdout_tail=str(debug_payload.get("stdout_tail") or ""),
                    stderr_tail=str(debug_payload.get("stderr_tail") or ""),
                )
            try:
                self.logger(
                    self.runtime_root,
                    "branch_selector_reaped pid=%s rc=%s run_dir=%s"
                    % (
                        str(p.pid),
                        str(rc),
                        str(run_dir),
                    ),
                )
            except Exception:
                pass
            if run_dir and not bool(debug_payload.get("heartbeat_exists")):
                try:
                    self.logger(
                        self.runtime_root,
                        "branch_selector_reaped_without_heartbeat pid=%s rc=%s run_dir=%s stdout_tail=%s stderr_tail=%s"
                        % (
                            str(p.pid),
                            str(rc),
                            str(run_dir),
                            str(debug_payload.get("stdout_tail") or "").replace("\n", "\\n"),
                            str(debug_payload.get("stderr_tail") or "").replace("\n", "\\n"),
                        ),
                    )
                except Exception:
                    pass
            _ensure_branch_selector_token_released(self.meta_dir, p, self.runtime_root, self.logger)
            _close_process_logs(p)
        self.running = alive

    def tick(self) -> None:
        self.reap()
        self._scavenge_branch_selector_tokens()

        if not token_pool.try_acquire(self.meta_dir, kind="branch_selector"):
            return

        try:
            seed_path = ""
            seed_qd = ""
            seed_id: Optional[int] = None
            seed_sig = 0
            seed_hash = ""
            seed_dedupe_hash = ""
            attempts = 0
            while attempts < 200:
                attempts += 1
                if not self._seed_heap:
                    break
                _pri, path, qd, sid, sig = heapq.heappop(self._seed_heap)
                self._enqueued_seed_keys.discard((str(qd), int(sid)))
                seed_path, seed_qd, seed_id, seed_sig = str(path), str(qd), int(sid), int(sig)
                seed_hash = _sha1_file(seed_path) or ""
                seed_dedupe_hash = _seed_dedupe_hash(seed_path, seed_hash)
                if not seed_hash or not seed_dedupe_hash or seed_dedupe_hash in self.seen_hashes:
                    seed_path = ""
                    seed_qd = ""
                    seed_id = None
                    seed_sig = 0
                    seed_hash = ""
                    seed_dedupe_hash = ""
                    continue
                break
            if not seed_path:
                token_pool.release(self.meta_dir, kind="branch_selector")
                return

            if seed_id is not None:
                proc_map = self.processed_by_queue.setdefault(seed_qd, {})
                proc_map[int(seed_id)] = int(proc_map.get(int(seed_id), 0)) + 1

            run_dir = _make_run_dir(self.runtime_root, seed_path, seed_qd, seed_hash)
            self.logger(
                self.runtime_root,
                "seed_selected path=%s seed_id=%s hash=%s run_dir=%s"
                % (seed_path, str(seed_id) if seed_id is not None else "", seed_hash[:8], run_dir),
            )
            parent_seed_meta_path = _write_parent_seed_info(
                run_dir,
                seed_path=seed_path,
                seed_id=seed_id,
                seed_hash=seed_hash,
                queue_dir=seed_qd,
            )
            self.logger(
                self.runtime_root,
                "parent_seed_info_written path=%s seed=%s seed_id=%s hash=%s"
                % (parent_seed_meta_path, seed_path, str(seed_id) if seed_id is not None else "", seed_hash[:8]),
            )

            if not _run_trace_into(
                self.runtime_root,
                seed_path,
                run_dir,
                self.trace_timeout,
                self.logger,
                seed_id=seed_id,
                seed_hash=seed_hash,
            ):
                token_pool.release(self.meta_dir, kind="branch_selector")
                return
            if int(seed_sig) not in self._processed_get_sigs_set:
                self._processed_get_sigs_set.add(int(seed_sig))
                self._processed_get_sigs.append(int(seed_sig))

            env = dict(os.environ)
            env["JOERNTRACE_CONFIG"] = self._run_cfg_path
            env["WC_TOKEN_POOL_DIR"] = self.meta_dir
            env["WC_TOKEN_KIND"] = "branch_selector"
            env["WC_TOKEN_RELEASE_MARKER"] = _branch_selector_token_marker_path(run_dir)
            env["WC_EXTERNAL_SEED_DIR"] = self.extsync_queue_dir
            try:
                env["WC_SEED_SCANNED_COUNT"] = str(int(_count_scanned_seeds(self.work_dir)))
            except Exception:
                env["WC_SEED_SCANNED_COUNT"] = "0"
            try:
                env["WC_BRANCH_SELECTOR_CALLED_COUNT"] = str(int(len(self.seen_hashes)))
            except Exception:
                env["WC_BRANCH_SELECTOR_CALLED_COUNT"] = "0"

            out_fp = open(os.path.join(run_dir, "meta", "branch_selector.out"), "a", encoding="utf-8", errors="replace")
            err_fp = open(os.path.join(run_dir, "meta", "branch_selector.err"), "a", encoding="utf-8", errors="replace")
            try:
                p = subprocess.Popen([sys.executable, self.pipeline_py, self._bs_cfg_path, "--config", self._run_cfg_path], cwd=run_dir, stdout=out_fp, stderr=err_fp, env=env)
            except Exception as ex:
                self._update_branch_selector_process_info(
                    run_dir,
                    status="spawn_failed",
                    pid=0,
                    started_at=int(time.time()),
                    spawn_failed_at=int(time.time()),
                    seed_path=str(seed_path),
                    queue_dir=str(seed_qd),
                    config_path=str(self._run_cfg_path),
                    shared_config_path=str(self._bs_cfg_path),
                    daemon_pid=int(os.getpid()),
                    error=str(ex),
                    stdout_tail="",
                    stderr_tail="",
                )
                try:
                    self.logger(
                        self.runtime_root,
                        "branch_selector_start_failed run_dir=%s seed=%s error=%s"
                        % (str(run_dir), str(seed_path), str(ex)),
                    )
                except Exception:
                    pass
                _close_log_pair(out_fp, err_fp)
                raise
            setattr(p, "_wc_stdout_fp", out_fp)
            setattr(p, "_wc_stderr_fp", err_fp)
            setattr(p, "_wc_run_dir", run_dir)
            setattr(p, "_wc_token_release_marker", env.get("WC_TOKEN_RELEASE_MARKER") or "")
            setattr(p, "_wc_token_released", False)
            self._update_branch_selector_process_info(
                run_dir,
                status="spawned",
                pid=int(p.pid),
                parent_pid=int(os.getpid()),
                started_at=int(time.time()),
                seed_path=str(seed_path),
                queue_dir=str(seed_qd),
                config_path=str(self._run_cfg_path),
                shared_config_path=str(self._bs_cfg_path),
                daemon_pid=int(os.getpid()),
                stdout_path=os.path.join(run_dir, "meta", "branch_selector.out"),
                stderr_path=os.path.join(run_dir, "meta", "branch_selector.err"),
                token_release_marker=str(env.get("WC_TOKEN_RELEASE_MARKER") or ""),
                seed_hash8=str(seed_hash[:8]),
            )
            self.running.append(p)
            self.seen_hashes.add(seed_dedupe_hash)
            _save_seen_hashes(self.runtime_root, self.seen_hashes)
            self.logger(self.runtime_root, "branch_selector_start pid=%s run_dir=%s seed=%s" % (str(p.pid), run_dir, seed_path))
        except Exception:
            try:
                token_pool.release(self.meta_dir, kind="branch_selector")
            except Exception:
                pass
            try:
                self.logger(self.runtime_root, "branch_selector_tick_spawn_error traceback=%s" % traceback.format_exc())
            except Exception:
                pass

    def shutdown(self) -> None:
        for p in list(self.running):
            run_dir = str(getattr(p, "_wc_run_dir", "") or "")
            self.logger(self.runtime_root, "branch_selector_shutdown_begin pid=%s run_dir=%s" % (str(p.pid), run_dir))
            try:
                if p.poll() is None:
                    record_process_kill(
                        self.runtime_root,
                        int(p.pid),
                        source="hybrid_io.daemon_token_loop.shutdown",
                        signal_name="SIGTERM",
                        reason="branch_selector_shutdown",
                        run_dir=run_dir,
                    )
                    p.terminate()
            except Exception:
                pass
            rc = p.poll()
            if rc is None:
                try:
                    rc = p.wait(timeout=5)
                except Exception:
                    rc = None
            if rc is None:
                self.logger(self.runtime_root, "branch_selector_shutdown_kill pid=%s run_dir=%s" % (str(p.pid), run_dir))
                try:
                    record_process_kill(
                        self.runtime_root,
                        int(p.pid),
                        source="hybrid_io.daemon_token_loop.shutdown",
                        signal_name="SIGKILL",
                        reason="branch_selector_shutdown_timeout",
                        run_dir=run_dir,
                    )
                    p.kill()
                except Exception:
                    pass
                try:
                    rc = p.wait(timeout=5)
                except Exception:
                    rc = p.poll()
            self.logger(
                self.runtime_root,
                "branch_selector_shutdown_done pid=%s rc=%s run_dir=%s" % (str(p.pid), str(rc), run_dir),
            )
            if run_dir:
                self._update_branch_selector_process_info(
                    run_dir,
                    status="shutdown",
                    pid=int(getattr(p, "pid", 0) or 0),
                    shutdown_at=int(time.time()),
                    returncode=(int(rc) if rc is not None else None),
                    signal_name=_signal_name_from_return_code(rc),
                )
            _ensure_branch_selector_token_released(self.meta_dir, p, self.runtime_root, self.logger)
            _close_process_logs(p)
        self.running = []
        _save_seen_hashes(self.runtime_root, self.seen_hashes)
