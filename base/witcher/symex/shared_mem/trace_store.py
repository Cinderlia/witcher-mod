import hashlib
import json
import os
import socket
from typing import Dict, Optional


def _pipeline_runtime_root(run_dir: str) -> str:
    root = os.path.abspath(run_dir or "")
    parent = os.path.dirname(root)
    if os.path.basename(parent) == "runs":
        return os.path.dirname(parent)
    return root


def _pipeline_socket_path(run_dir: str) -> str:
    root = os.path.abspath(run_dir)
    digest = hashlib.md5(root.encode("utf-8", errors="replace")).hexdigest()[:16]
    runtime_root = _pipeline_runtime_root(root)
    short_runtime = os.path.join(runtime_root, "ipc", "ptm_%s.sock" % digest)
    if os.name == "posix":
        if len(short_runtime) <= 100:
            return short_runtime
        return os.path.join("/tmp", "ptm_%s.sock" % digest)
    return os.path.join(root, "ipc", "pipeline_trace_master.sock")


def _read_json(path: str) -> Dict[str, object]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def pipeline_trace_state_paths(run_dir: str) -> Dict[str, str]:
    root = os.path.abspath(run_dir)
    socket_path = _pipeline_socket_path(root)
    return {
        "run_dir": root,
        "shared_root": os.path.join(root, "shared_trace"),
        "ipc_dir": os.path.dirname(socket_path),
        "socket_path": socket_path,
        "pid_path": os.path.join(root, "meta", "pipeline_trace_master.pid"),
        "state_path": os.path.join(root, "meta", "pipeline_trace_master.state.json"),
        "header_path": os.path.join(root, "shared_trace", "trace.header.json"),
        "sources_path": os.path.join(root, "shared_trace", "trace.sources.json"),
    }


def load_pipeline_trace_master_state(*, state_path: Optional[str] = None, run_dir: Optional[str] = None) -> Dict[str, object]:
    if state_path:
        return _read_json(os.path.abspath(state_path))
    if run_dir:
        return _read_json(pipeline_trace_state_paths(run_dir)["state_path"])
    return {}


def resolve_pipeline_trace_master_state_from_env() -> Dict[str, object]:
    state_path = os.environ.get("SYMEX_PIPELINE_TRACE_MASTER_STATE") or ""
    run_dir = os.environ.get("SYMEX_PIPELINE_RUN_DIR") or ""
    if state_path:
        return load_pipeline_trace_master_state(state_path=state_path)
    if run_dir:
        return load_pipeline_trace_master_state(run_dir=run_dir)
    return {}


def ping_pipeline_trace_master(socket_path: str, timeout_sec: float = 1.0) -> Optional[Dict[str, object]]:
    path = os.path.abspath(socket_path or "")
    if not path or not os.path.exists(path):
        return None
    if os.name != "posix":
        return None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(float(timeout_sec))
            sock.connect(path)
            sock.sendall(b'{"cmd":"ping"}\n')
            data = sock.recv(65536)
        finally:
            sock.close()
    except Exception:
        return None
    if not data:
        return None
    try:
        obj = json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def request_pipeline_trace_payloads(socket_path: str, timeout_sec: float = 2.0) -> Optional[Dict[str, object]]:
    path = os.path.abspath(socket_path or "")
    if not path or not os.path.exists(path):
        return None
    if os.name != "posix":
        return None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(float(timeout_sec))
            sock.connect(path)
            sock.sendall(b'{"cmd":"attach_trace_payloads"}\n')
            data = sock.recv(131072)
        finally:
            sock.close()
    except Exception:
        return None
    if not data:
        return None
    try:
        obj = json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def release_pipeline_trace_payloads(socket_path: str, timeout_sec: float = 2.0) -> Optional[Dict[str, object]]:
    path = os.path.abspath(socket_path or "")
    if not path or not os.path.exists(path):
        return None
    if os.name != "posix":
        return None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(float(timeout_sec))
            sock.connect(path)
            sock.sendall(b'{"cmd":"release_trace_payloads"}\n')
            data = sock.recv(65536)
        finally:
            sock.close()
    except Exception:
        return None
    if not data:
        return None
    try:
        obj = json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def shutdown_pipeline_trace_master(socket_path: str, timeout_sec: float = 3.0) -> Optional[Dict[str, object]]:
    path = os.path.abspath(socket_path or "")
    if not path or not os.path.exists(path):
        return None
    if os.name != "posix":
        return None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(float(timeout_sec))
            sock.connect(path)
            sock.sendall(b'{"cmd":"shutdown"}\n')
            data = sock.recv(65536)
        finally:
            sock.close()
    except Exception:
        return None
    if not data:
        return None
    try:
        obj = json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None
