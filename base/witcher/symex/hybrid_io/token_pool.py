import errno
import os
import random
import time
from typing import Optional

try:
    import fcntl
except Exception:
    fcntl = None


def _counter_path(meta_dir: str, kind: str) -> str:
    return os.path.join(os.path.abspath(meta_dir or "."), "token_%s.count" % str(kind))


def ensure_counter(meta_dir: str, *, kind: str, initial: int) -> str:
    path = _counter_path(meta_dir, kind)
    if os.path.exists(path):
        return path
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    except Exception:
        pass
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(str(max(0, int(initial))) + "\n")
    except Exception:
        pass
    return path


def _try_lock(f) -> bool:
    if fcntl is None:
        return True
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as e:
        if getattr(e, "errno", None) in (errno.EACCES, errno.EAGAIN):
            return False
        return False
    except Exception:
        return False


def _unlock(f) -> None:
    if fcntl is None:
        return
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception:
        return


def _read_int(f, default: int = 0) -> int:
    try:
        f.seek(0)
        raw = f.read().strip()
        return int(raw) if raw else int(default)
    except Exception:
        return int(default)


def _write_int(f, v: int) -> None:
    try:
        f.seek(0)
        f.truncate()
        f.write(str(int(v)) + "\n")
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    except Exception:
        return


def try_acquire(meta_dir: str, *, kind: str) -> bool:
    path = ensure_counter(meta_dir, kind=kind, initial=0)
    while True:
        try:
            f = open(path, "r+", encoding="utf-8", errors="replace")
        except Exception:
            return False
        try:
            if not _try_lock(f):
                time.sleep(random.uniform(0.01, 0.1))
                continue
            cur = _read_int(f, default=0)
            if int(cur) <= 0:
                return False
            _write_int(f, int(cur) - 1)
            return True
        finally:
            try:
                _unlock(f)
            except Exception:
                pass
            try:
                f.close()
            except Exception:
                pass


def acquire_with_wait(meta_dir: str, *, kind: str, wait_no_token_seconds: int = 10) -> None:
    wait_s = max(0.0, float(wait_no_token_seconds))
    while True:
        ok = try_acquire(meta_dir, kind=kind)
        if ok:
            return
        if wait_s <= 0:
            return
        time.sleep(float(wait_s))


def release(meta_dir: str, *, kind: str) -> bool:
    path = ensure_counter(meta_dir, kind=kind, initial=0)
    while True:
        try:
            f = open(path, "r+", encoding="utf-8", errors="replace")
        except Exception:
            return False
        try:
            if not _try_lock(f):
                time.sleep(random.uniform(0.01, 0.1))
                continue
            cur = _read_int(f, default=0)
            _write_int(f, int(cur) + 1)
            return True
        finally:
            try:
                _unlock(f)
            except Exception:
                pass
            try:
                f.close()
            except Exception:
                pass
