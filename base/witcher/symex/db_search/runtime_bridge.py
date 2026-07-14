"""Seed/log helpers for db_search after removing rollback/runtime bridge."""

import json
import os
import re
import shutil
import time
try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Any, Dict, List, Optional

_ID_RE = re.compile(r"^id:(\d+)")


@dataclass(frozen=True)
class DBRuntimePaths:
    """Resolved filesystem layout for external seed allocation only."""

    work_dir: str = ""
    extsync_dir: str = ""
    queue_dir: str = ""
    runtime_dir: str = ""
    command_lock_dir: str = ""
    latest_id_path: str = ""


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _read_json(path: str) -> Dict[str, Any]:
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _atomic_write_json(path: str, obj: Dict[str, Any]) -> str:
    out_path = os.path.abspath(path or "")
    if not out_path:
        return ""
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8", errors="replace") as f:
        json.dump(obj if isinstance(obj, dict) else {}, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, out_path)
    return out_path


def _atomic_write_text(path: str, text: str) -> str:
    out_path = os.path.abspath(path or "")
    if not out_path:
        return ""
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(str(text or ""))
    os.replace(tmp_path, out_path)
    return out_path


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


def _acquire_lock(lock_dir: str, *, timeout_sec: float = 10.0) -> bool:
    lock_path = os.path.abspath(lock_dir or "")
    if not lock_path:
        return False
    deadline = time.time() + max(float(timeout_sec), 0.1)
    while time.time() < deadline:
        try:
            os.makedirs(lock_path)
            _atomic_write_json(
                os.path.join(lock_path, "holder.json"),
                {"pid": int(os.getpid()), "acquired_at": int(time.time())},
            )
            return True
        except FileExistsError:
            holder = _read_json(os.path.join(lock_path, "holder.json"))
            holder_pid = _safe_int(holder.get("pid"), 0)
            if holder_pid > 0 and _pid_alive(holder_pid) is False:
                try:
                    shutil.rmtree(lock_path)
                    continue
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(0.1)
    return False


def _release_lock(lock_dir: str) -> None:
    lock_path = os.path.abspath(lock_dir or "")
    if not lock_path:
        return
    try:
        if os.path.isdir(lock_path):
            shutil.rmtree(lock_path)
    except Exception:
        return


def derive_work_dir_from_env() -> str:
    queue_dir = str(os.environ.get("WC_EXTERNAL_SEED_DIR") or "").strip()
    if queue_dir:
        qd = os.path.abspath(queue_dir)
        if os.path.basename(qd) == "queue":
            return os.path.dirname(os.path.dirname(qd))
    work_dir = str(os.environ.get("WC_DB_WORK_DIR") or "").strip()
    if work_dir:
        return os.path.abspath(work_dir)
    return ""


def resolve_db_runtime_paths(*, work_dir: str = "") -> Optional[DBRuntimePaths]:
    wd = os.path.abspath(work_dir) if work_dir else derive_work_dir_from_env()
    if not wd:
        return None
    extsync_dir = os.path.join(wd, "extsync")
    queue_dir = os.path.join(extsync_dir, "queue")
    runtime_dir = os.path.join(extsync_dir, "db_runtime")
    return DBRuntimePaths(
        work_dir=wd,
        extsync_dir=extsync_dir,
        queue_dir=queue_dir,
        runtime_dir=runtime_dir,
        command_lock_dir=os.path.join(runtime_dir, "command.lock"),
        latest_id_path=os.path.join(extsync_dir, "latest_id"),
    )


def ensure_db_runtime_layout(paths: DBRuntimePaths) -> DBRuntimePaths:
    for path in (
        paths.extsync_dir,
        paths.queue_dir,
        paths.runtime_dir,
    ):
        os.makedirs(path, exist_ok=True)
    return paths


def _parse_seed_id_from_name(name: str) -> Optional[int]:
    m = _ID_RE.search(str(name or ""))
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def allocate_external_seed_id(paths: DBRuntimePaths, *, timeout_sec: float = 10.0) -> Optional[int]:
    ensure_db_runtime_layout(paths)
    if not _acquire_lock(paths.command_lock_dir, timeout_sec=timeout_sec):
        return None
    try:
        latest_id_path = os.path.abspath(str(paths.latest_id_path or "").strip())
        if not latest_id_path:
            return None
        os.makedirs(os.path.dirname(latest_id_path) or ".", exist_ok=True)
        cur = -1
        try:
            with open(latest_id_path, "a+", encoding="utf-8", errors="replace") as f:
                f.seek(0)
                raw = (f.read() or "").strip()
                if raw:
                    cur = int(raw)
                nxt = int(cur) + 1
                f.seek(0)
                f.truncate(0)
                f.write(str(int(nxt)) + "\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
                return int(nxt)
        except Exception:
            return None
    finally:
        _release_lock(paths.command_lock_dir)


def _read_parent_seed_meta(run_dir: str) -> Dict[str, Any]:
    return _read_json(os.path.join(run_dir, "meta", "parent_seed_info.json"))


def emit_identical_seed_for_sync(*, run_dir: str, work_dir: str = "") -> Dict[str, Any]:
    paths = resolve_db_runtime_paths(work_dir=work_dir)
    if paths is None:
        return {"ok": False, "error": "db_runtime_paths_unavailable"}
    ensure_db_runtime_layout(paths)
    seed_src = os.path.join(run_dir, "input", "seed.bin")
    if not os.path.isfile(seed_src):
        return {"ok": False, "error": "seed_bin_missing", "seed_path": seed_src}
    new_id = allocate_external_seed_id(paths)
    if new_id is None:
        return {"ok": False, "error": "seed_id_allocation_failed"}
    meta = _read_parent_seed_meta(run_dir)
    parts = ["id:%06d" % int(new_id)]
    parent_seed_id = meta.get("seed_id")
    if parent_seed_id is not None:
        try:
            parts.append("src:%d" % int(parent_seed_id))
        except Exception:
            parts.append("src:dbtx")
    else:
        parts.append("src:dbtx")
    env_id = str(meta.get("seed_env_id") or "").strip()
    if env_id:
        parts.append("env:" + env_id)
    seed_name = ",".join(parts)
    seed_dst = os.path.join(paths.queue_dir, seed_name)
    try:
        shutil.copy2(seed_src, seed_dst)
    except Exception as ex:
        return {"ok": False, "error": "seed_copy_failed", "exception": str(ex), "seed_path": seed_src}
    return {"ok": True, "seed_id": int(new_id), "seed_name": seed_name, "seed_path": seed_dst}


