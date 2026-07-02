import json
import os
import socket
from typing import Dict, Optional


def send_request(socket_path: str, payload: Dict[str, object], timeout_sec: float = 1200.0) -> Optional[Dict[str, object]]:
    path = os.path.abspath(socket_path or "")
    if not path or not os.path.exists(path):
        return None
    if os.name != "posix":
        return None
    data = (json.dumps(payload or {}, ensure_ascii=False) + "\n").encode("utf-8", errors="replace")
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(float(timeout_sec))
            sock.connect(path)
            sock.sendall(data)
            chunks = []
            while True:
                part = sock.recv(65536)
                if not part:
                    break
                chunks.append(part)
        finally:
            sock.close()
    except Exception:
        return None
    raw = b"".join(chunks)
    if not raw:
        return None
    try:
        obj = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None
