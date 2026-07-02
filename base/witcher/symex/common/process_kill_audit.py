import glob
import json
import os
import tempfile
import time


def _safe_read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return {}


def _write_json_atomic(path, payload):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_kill_", suffix=".json", dir=(parent or None))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, ensure_ascii=False, indent=2, sort_keys=True)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def _append_jsonl(path, payload):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fp:
        fp.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        fp.write("\n")


def _pid_alive(pid):
    try:
        pid_i = int(pid or 0)
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


def _iter_candidate_logs_dirs(runtime_root, run_dir):
    seen = set()
    roots = []
    run_dir_abs = os.path.abspath(str(run_dir or "")).strip()
    if run_dir_abs:
        roots.append(os.path.join(run_dir_abs, "test", "seqs", "*", "logs"))
    runtime_root_abs = os.path.abspath(str(runtime_root or "")).strip()
    if runtime_root_abs:
        roots.append(os.path.join(runtime_root_abs, "runs", "*", "test", "seqs", "*", "logs"))
    for pattern in roots:
        try:
            matches = sorted(glob.glob(pattern))
        except Exception:
            matches = []
        for logs_dir in matches:
            logs_abs = os.path.abspath(logs_dir)
            if logs_abs in seen or not os.path.isdir(logs_abs):
                continue
            seen.add(logs_abs)
            yield logs_abs


def _event_base(target_pid, source, signal_name, reason, run_dir, extra):
    return {
        "target_pid": int(target_pid or 0),
        "source": str(source or ""),
        "signal_name": str(signal_name or ""),
        "reason": str(reason or ""),
        "observer_pid": int(os.getpid()),
        "observed_at": int(time.time()),
        "run_dir": os.path.abspath(str(run_dir or "")).strip(),
        "target_pid_alive_before_signal": _pid_alive(target_pid),
        "extra": (extra if isinstance(extra, dict) else {}),
    }


def record_process_kill(runtime_root, target_pid, *, source, signal_name, reason="", run_dir="", extra=None):
    event = _event_base(target_pid, source, signal_name, reason, run_dir, extra)
    matched = []
    for logs_dir in _iter_candidate_logs_dirs(runtime_root, run_dir):
        status_path = os.path.join(logs_dir, "heartbeat.status.json")
        hb = _safe_read_json(status_path)
        try:
            hb_pid = int(hb.get("pid") or 0)
        except Exception:
            hb_pid = 0
        if hb_pid != int(target_pid or 0):
            continue
        seq_event = dict(event)
        seq_event["seq"] = int(hb.get("seq") or 0)
        seq_event["heartbeat_stage"] = str(hb.get("stage") or "")
        seq_event["heartbeat_status"] = str(hb.get("status") or "")
        seq_event["heartbeat_updated_at"] = str(hb.get("updated_at") or "")
        matched.append(logs_dir)
    return {
        "matched_seq_logs": matched,
        "target_pid_alive_before_signal": event.get("target_pid_alive_before_signal"),
    }


def record_stop_request(runtime_root, target_pid, *, source, reason="", run_dir="", extra=None):
    event = _event_base(target_pid, source, "STOP_REQUEST", reason, run_dir, extra)
    matched = []
    for logs_dir in _iter_candidate_logs_dirs(runtime_root, run_dir):
        status_path = os.path.join(logs_dir, "heartbeat.status.json")
        hb = _safe_read_json(status_path)
        try:
            hb_pid = int(hb.get("pid") or 0)
        except Exception:
            hb_pid = 0
        if hb_pid != int(target_pid or 0):
            continue
        seq_event = dict(event)
        seq_event["seq"] = int(hb.get("seq") or 0)
        seq_event["heartbeat_stage"] = str(hb.get("stage") or "")
        seq_event["heartbeat_status"] = str(hb.get("status") or "")
        seq_event["heartbeat_updated_at"] = str(hb.get("updated_at") or "")
        matched.append(logs_dir)
    return {
        "matched_seq_logs": matched,
        "target_pid_alive_before_signal": event.get("target_pid_alive_before_signal"),
    }
