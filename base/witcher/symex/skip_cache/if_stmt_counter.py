import json
import os
from typing import Any, Dict, Optional, Tuple

try:
    import fcntl  # type: ignore
except Exception:
    fcntl = None

try:
    from utils.cpg_utils.graph_mapping import norm_nodes_path
except Exception:
    norm_nodes_path = None


def _default_cache_path() -> str:
    env_p = os.environ.get("WC_IF_STMT_CACHE_PATH")
    if isinstance(env_p, str) and env_p.strip():
        return os.path.abspath(env_p.strip())
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, "if_stmt_counts.json")
    try:
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        with open(os.path.join(os.path.dirname(p) or ".", ".wc_write_test"), "w") as f:
            f.write("1")
        os.remove(os.path.join(os.path.dirname(p) or ".", ".wc_write_test"))
        return p
    except Exception:
        return "/tmp/if_stmt_counts.json"


def _normalize_path(p: Any) -> str:
    try:
        s = str(p)
    except Exception:
        s = ""
    if not s:
        return ""
    if norm_nodes_path is not None:
        try:
            return str(norm_nodes_path(s))
        except Exception:
            pass
    return s.replace("\\", "/")


def _safe_int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None


def _read_obj(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {"version": 1, "files": {}}
    if not isinstance(obj, dict):
        return {"version": 1, "files": {}}
    files = obj.get("files")
    if not isinstance(files, dict):
        obj["files"] = {}
    obj.setdefault("version", 1)
    return obj


def _write_obj_atomic(path: str, obj: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def _with_lock(path: str):
    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(os.path.abspath(lock_path)) or ".", exist_ok=True)
    fp = None
    try:
        fp = open(lock_path, "a", encoding="utf-8", errors="replace")
    except Exception:
        fp = None
    if fp is None or fcntl is None:
        class _NoLock:
            def __enter__(self):
                return None
            def __exit__(self, exc_type, exc, tb):
                return False
        return _NoLock()
    class _Flock:
        def __enter__(self):
            try:
                fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
            except Exception:
                pass
            return fp
        def __exit__(self, exc_type, exc, tb):
            try:
                fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                fp.close()
            except Exception:
                pass
            return False
    return _Flock()


def get_count(file_path: Any, line: Any, *, cache_path: Optional[str] = None) -> int:
    fp = _normalize_path(file_path)
    ln = _safe_int(line)
    if not fp or ln is None:
        return 0
    p = cache_path or _default_cache_path()
    with _with_lock(p):
        obj = _read_obj(p)
        files = obj.get("files") if isinstance(obj.get("files"), dict) else {}
        m = files.get(fp)
        if not isinstance(m, dict):
            return 0
        v = m.get(str(int(ln)))
        try:
            return int(v)
        except Exception:
            return 0


def inc_count(file_path: Any, line: Any, *, inc: int = 1, cache_path: Optional[str] = None) -> int:
    fp = _normalize_path(file_path)
    ln = _safe_int(line)
    if not fp or ln is None:
        return 0
    p = cache_path or _default_cache_path()
    with _with_lock(p):
        obj = _read_obj(p)
        files = obj.get("files") if isinstance(obj.get("files"), dict) else {}
        if not isinstance(files, dict):
            files = {}
        m = files.get(fp)
        if not isinstance(m, dict):
            m = {}
        cur = 0
        try:
            cur = int(m.get(str(int(ln))) or 0)
        except Exception:
            cur = 0
        nxt = cur + max(0, int(inc))
        m[str(int(ln))] = int(nxt)
        files[fp] = m
        obj["files"] = files
        _write_obj_atomic(p, obj)
        return int(nxt)


def should_skip(file_path: Any, line: Any, *, remaining_seeds: int, cache_path: Optional[str] = None) -> Tuple[bool, int]:
    cnt = get_count(file_path, line, cache_path=cache_path)
    if cnt > 10:
        return True, cnt
    if cnt > 3 and int(remaining_seeds) > 10:
        return True, cnt
    return False, cnt
