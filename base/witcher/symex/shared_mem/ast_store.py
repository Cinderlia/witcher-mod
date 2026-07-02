import json
import os
import socket
from typing import Dict, Optional


def _read_json(path: str) -> Dict[str, object]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def global_ast_state_paths(runtime_root: str) -> Dict[str, str]:
    root = os.path.abspath(runtime_root)
    return {
        "runtime_root": root,
        "shared_root": os.path.join(root, "shared_ast"),
        "ipc_dir": os.path.join(root, "ipc"),
        "socket_path": os.path.join(root, "ipc", "global_ast_master.sock"),
        "pid_path": os.path.join(root, "meta", "global_ast_master.pid"),
        "state_path": os.path.join(root, "meta", "global_ast_master.state.json"),
        "header_path": os.path.join(root, "shared_ast", "ast.header.json"),
        "sources_path": os.path.join(root, "shared_ast", "ast.sources.json"),
    }


def load_global_ast_master_state(*, state_path: Optional[str] = None, runtime_root: Optional[str] = None) -> Dict[str, object]:
    if state_path:
        return _read_json(os.path.abspath(state_path))
    if runtime_root:
        return _read_json(global_ast_state_paths(runtime_root)["state_path"])
    return {}


def resolve_global_ast_master_state_from_env() -> Dict[str, object]:
    state_path = os.environ.get("SYMEX_GLOBAL_AST_MASTER_STATE") or ""
    runtime_root = os.environ.get("SYMEX_RUNTIME_ROOT") or ""
    if state_path:
        return load_global_ast_master_state(state_path=state_path)
    if runtime_root:
        return load_global_ast_master_state(runtime_root=runtime_root)
    return {}


def ping_global_ast_master(socket_path: str, timeout_sec: float = 1.0) -> Optional[Dict[str, object]]:
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


def request_global_ast_payloads(socket_path: str, timeout_sec: float = 2.0) -> Optional[Dict[str, object]]:
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
            sock.sendall(b'{"cmd":"attach_ast_payloads"}\n')
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


def release_global_ast_payloads(socket_path: str, timeout_sec: float = 2.0) -> Optional[Dict[str, object]]:
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
            sock.sendall(b'{"cmd":"release_ast_payloads"}\n')
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


def shutdown_global_ast_master(socket_path: str, timeout_sec: float = 3.0) -> Optional[Dict[str, object]]:
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
