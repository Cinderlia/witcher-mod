import gzip
import json
import mmap
import os
import sys
import time
import uuid
from typing import Dict, Optional

try:
    from multiprocessing import shared_memory
except Exception:
    shared_memory = None


_ATTACHED_PAYLOADS = {}


def shared_payload_backend() -> str:
    if not (os.name == "posix" and sys.platform.startswith("linux")):
        return ""
    if shared_memory is not None:
        return "shared_memory"
    if mmap is not None:
        return "mmap"
    return ""


def shared_payload_supported() -> bool:
    return bool(shared_payload_backend())


def _backend_reason() -> str:
    if not (os.name == "posix" and sys.platform.startswith("linux")):
        return "non_linux_platform"
    if shared_memory is not None:
        return "shared_memory"
    if mmap is not None:
        return "mmap_fallback"
    return "shared_payload_backend_unavailable"


def _sanitize_name(raw: str) -> str:
    out = []
    for ch in str(raw or ""):
        if ch.isalnum():
            out.append(ch.lower())
        else:
            out.append("_")
    text = "".join(out).strip("_")
    return text or "payload"


def _segment_name(kind: str, key: str) -> str:
    return "symx_%s_%s_%d_%s" % (
        _sanitize_name(kind),
        _sanitize_name(key),
        int(os.getpid()),
        uuid.uuid4().hex[:10],
    )


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def publish_payloads(*, kind: str, payload_paths: Dict[str, str], logger=None) -> Dict[str, object]:
    segments = {}
    handles = {}
    backend = shared_payload_backend()
    if not backend:
        if logger is not None:
            logger.warning(
                "shared_payloads_unsupported",
                kind=str(kind),
                reason=_backend_reason(),
                python_version=sys.version.split()[0],
                os_name=os.name,
                platform=sys.platform,
            )
        return {
            "enabled": False,
            "kind": str(kind),
            "segments": {},
            "reason": _backend_reason(),
            "backend": "",
            "python_version": sys.version.split()[0],
            "_handles": {},
        }
    try:
        for key, raw_path in (payload_paths or {}).items():
            path = os.path.abspath(str(raw_path or ""))
            if not path or not os.path.exists(path):
                raise FileNotFoundError("payload file missing: %s" % path)
            if backend == "shared_memory":
                raw = _read_bytes(path)
                name = _segment_name(str(kind), str(key))
                shm = shared_memory.SharedMemory(name=name, create=True, size=max(1, len(raw)))
                try:
                    if raw:
                        shm.buf[: len(raw)] = raw
                except Exception:
                    try:
                        shm.close()
                    except Exception:
                        pass
                    try:
                        shm.unlink()
                    except Exception:
                        pass
                    raise
                handles[str(key)] = {"backend": "shared_memory", "handle": shm}
                segments[str(key)] = {
                    "backend": "shared_memory",
                    "name": str(shm.name),
                    "size": int(len(raw)),
                    "source_path": path,
                    "encoding": ("json+gzip" if path.endswith(".gz") else "json"),
                    "published_at": int(time.time()),
                }
            else:
                size = int(os.path.getsize(path))
                handles[str(key)] = {"backend": "mmap", "path": path}
                segments[str(key)] = {
                    "backend": "mmap",
                    "path": path,
                    "size": int(size),
                    "source_path": path,
                    "encoding": ("json+gzip" if path.endswith(".gz") else "json"),
                    "published_at": int(time.time()),
                }
        if logger is not None:
            logger.info(
                "shared_payloads_published",
                kind=str(kind),
                backend=str(backend),
                segment_count=len(segments),
                keys=sorted(list(segments.keys())),
            )
        return {
            "enabled": True,
            "kind": str(kind),
            "backend": str(backend),
            "reason": _backend_reason(),
            "segments": segments,
            "_handles": handles,
        }
    except Exception as exc:
        close_published_payloads({"_handles": handles}, logger=logger)
        if logger is not None:
            logger.exception("shared_payloads_publish_failed", kind=str(kind), error=str(exc))
        raise


def close_published_payloads(bundle: Optional[Dict[str, object]], *, logger=None) -> None:
    bundle = bundle if isinstance(bundle, dict) else {}
    handles = bundle.get("_handles") if isinstance(bundle.get("_handles"), dict) else {}
    for key, meta in list(handles.items()):
        meta = meta if isinstance(meta, dict) else {}
        backend = str(meta.get("backend") or "")
        if backend == "shared_memory":
            shm = meta.get("handle")
            try:
                if shm is not None:
                    shm.close()
            except Exception:
                pass
            try:
                if shm is not None:
                    shm.unlink()
            except Exception:
                pass
            if logger is not None:
                logger.info("shared_payload_unlinked", key=str(key), backend=backend, name=getattr(shm, "name", ""))
        elif logger is not None:
            logger.info("shared_payload_unlinked", key=str(key), backend=backend, path=str(meta.get("path") or ""))


def _read_json_bytes(raw: bytes, encoding: str) -> Dict[str, object]:
    if str(encoding or "").strip().lower() == "json+gzip":
        raw = gzip.decompress(raw)
    obj = json.loads((raw or b"{}").decode("utf-8", errors="replace"))
    return obj if isinstance(obj, dict) else {}


def attach_payload_json(meta: Optional[Dict[str, object]]) -> Dict[str, object]:
    meta = meta if isinstance(meta, dict) else {}
    backend = str(meta.get("backend") or "").strip() or shared_payload_backend()
    name = str(meta.get("name") or "").strip()
    path = os.path.abspath(str(meta.get("path") or meta.get("source_path") or "").strip()) if (meta.get("path") or meta.get("source_path")) else ""
    size = int(meta.get("size") or 0)
    encoding = str(meta.get("encoding") or "json").strip() or "json"
    if backend == "shared_memory" and (not name or size < 0):
        return {}
    if backend == "mmap" and (not path or size < 0 or not os.path.exists(path)):
        return {}
    cache_key = "%s:%s:%d:%s" % (backend, (name if backend == "shared_memory" else path), int(size), encoding)
    cached = _ATTACHED_PAYLOADS.get(cache_key)
    if cached is not None:
        return cached.get("obj") if isinstance(cached.get("obj"), dict) else {}
    if not shared_payload_supported():
        return {}
    if backend == "shared_memory":
        shm = shared_memory.SharedMemory(name=name, create=False)
        raw = bytes(shm.buf[: int(size)])
        obj = _read_json_bytes(raw, encoding)
        _ATTACHED_PAYLOADS[cache_key] = {"backend": backend, "shm": shm, "obj": obj}
        return obj
    fp = open(path, "rb")
    try:
        mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
        raw = mm[: int(size)]
        obj = _read_json_bytes(raw, encoding)
    except Exception:
        try:
            fp.close()
        except Exception:
            pass
        raise
    _ATTACHED_PAYLOADS[cache_key] = {"backend": backend, "mmap": mm, "fp": fp, "obj": obj}
    return obj


def close_attached_payloads() -> None:
    for cached in list(_ATTACHED_PAYLOADS.values()):
        backend = str(cached.get("backend") or "")
        if backend == "shared_memory":
            shm = cached.get("shm")
            try:
                if shm is not None:
                    shm.close()
            except Exception:
                pass
            continue
        mm = cached.get("mmap")
        fp = cached.get("fp")
        try:
            if mm is not None:
                mm.close()
        except Exception:
            pass
        try:
            if fp is not None:
                fp.close()
        except Exception:
            pass
    _ATTACHED_PAYLOADS.clear()
