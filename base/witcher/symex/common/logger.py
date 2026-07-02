"""
Lightweight file logger with optional console output.

This module provides a minimal thread-safe logger used across the taint pipeline.
Logs are written under `<base_dir>/logs/` split by level.
"""

import json
import os
import sys
import threading
import time
import traceback
from typing import Dict


_LEVEL_TO_NUM = {
    'DEBUG': 10,
    'INFO': 20,
    'WARNING': 30,
    'ERROR': 40,
}


def _now_ts() -> str:
    """Return a human-readable local timestamp with millisecond precision."""
    t = time.time()
    lt = time.localtime(t)
    ms = int((t - int(t)) * 1000)
    return time.strftime('%Y-%m-%d %H:%M:%S', lt) + f'.{ms:03d}'


def _safe_mkdir(p: str) -> None:
    """Create directory `p` if it is non-empty, ignoring if it already exists."""
    if not p:
        return
    os.makedirs(p, exist_ok=True)


class Logger:
    """Thread-safe logger that writes JSON-like structured fields per line."""
    def __init__(
        self,
        *,
        base_dir: str,
        min_level: str = 'INFO',
        name: str = 'root',
        also_console: bool = True,
    ):
        self.base_dir = os.path.abspath(base_dir or '.')
        self.min_level = (min_level or 'INFO').upper()
        self.name = name or 'root'
        self.also_console = bool(also_console)
        self._lock = threading.Lock()
        self._files: Dict[str, object] = {}

        _safe_mkdir(self.base_dir)
        _safe_mkdir(os.path.join(self.base_dir, 'logs'))

    def _enabled(self, level: str) -> bool:
        a = _LEVEL_TO_NUM.get((level or '').upper(), 999)
        b = _LEVEL_TO_NUM.get(self.min_level, 20)
        return a >= b

    def _log_path(self, level: str) -> str:
        lv = (level or 'INFO').upper()
        return os.path.join(self.base_dir, 'logs', f'{lv.lower()}.log')

    def _get_file(self, level: str):
        lv = (level or 'INFO').upper()
        fp = self._files.get(lv)
        if fp:
            return fp
        path = self._log_path(lv)
        _safe_mkdir(os.path.dirname(path))
        f = open(path, 'a', encoding='utf-8', errors='replace')
        self._files[lv] = f
        return f

    def log(self, level: str, msg: str, **fields):
        lv = (level or 'INFO').upper()
        if not self._enabled(lv):
            return
        line = f'{_now_ts()} [{lv}] {self.name} {msg or ""}'
        if fields:
            try:
                extra = json.dumps(fields, ensure_ascii=False, sort_keys=True)
            except Exception:
                extra = str(fields)
            line = line + ' ' + extra
        with self._lock:
            f = self._get_file(lv)
            f.write(line + '\n')
            f.flush()
            if self.also_console:
                try:
                    print(line)
                except Exception:
                    try:
                        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
                        data = (line + "\n").encode(enc, errors="replace")
                        buf = getattr(sys.stdout, "buffer", None)
                        if buf is not None:
                            buf.write(data)
                            buf.flush()
                        else:
                            sys.stdout.write(data.decode(enc, errors="replace"))
                            sys.stdout.flush()
                    except Exception:
                        pass

    def debug(self, msg: str, **fields):
        self.log('DEBUG', msg, **fields)

    def info(self, msg: str, **fields):
        self.log('INFO', msg, **fields)

    def warning(self, msg: str, **fields):
        self.log('WARNING', msg, **fields)

    def error(self, msg: str, **fields):
        self.log('ERROR', msg, **fields)

    def exception(self, msg: str, **fields):
        fields = dict(fields or {})
        fields['traceback'] = traceback.format_exc()
        self.log('ERROR', msg, **fields)

    def log_json(self, level: str, title: str, obj):
        try:
            txt = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
        except Exception:
            txt = str(obj)
        self.log(level, title, json=txt)

    def write_text(self, subdir: str, filename: str, text: str) -> str:
        sd = (subdir or '').strip().strip('/\\')
        fn = (filename or '').strip().strip('/\\')
        out_dir = os.path.join(self.base_dir, sd) if sd else self.base_dir
        _safe_mkdir(out_dir)
        path = os.path.join(out_dir, fn) if fn else os.path.join(out_dir, 'out.txt')
        with self._lock:
            with open(path, 'w', encoding='utf-8', errors='replace') as f:
                f.write(text or '')
        return path

    def write_json(self, subdir: str, filename: str, obj) -> str:
        try:
            txt = json.dumps(obj, ensure_ascii=False, indent=2)
        except Exception:
            txt = str(obj)
        return self.write_text(subdir, filename, txt)

    def close(self):
        with self._lock:
            for _, f in list(self._files.items()):
                try:
                    f.close()
                except Exception:
                    pass
            self._files.clear()
