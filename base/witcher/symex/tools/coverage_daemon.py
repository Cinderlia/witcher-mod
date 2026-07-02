#!/usr/bin/env python3
import argparse
import glob
import json
import os
import signal
import sys
import time
from typing import Any, Dict

def _now() -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    except Exception:
        return "unknown"


def _write_json_atomic(path: str, obj: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        pass


def _append_line(path: str, line: str) -> None:
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "a", encoding="utf-8", errors="replace") as f:
            f.write(line.rstrip("\n") + "\n")
    except Exception:
        pass

COV_DIR = "/dev/shm/coverages/"

def _ensure_writable_dir(p: str) -> bool:
    try:
        os.makedirs(p, exist_ok=True)
        test_path = os.path.join(p, ".wc_write_test")
        with open(test_path, "w") as f:
            f.write("1")
        os.remove(test_path)
        return True
    except Exception:
        return False

if not _ensure_writable_dir(COV_DIR):
    COV_DIR = "/tmp/coverages/"
    _ensure_writable_dir(COV_DIR)

START_TEST_FLAG = "/tmp/start_test.dat"

def priority(v):
    if v == 1: return 3
    if v == -1: return 2
    if v == -2: return 1
    return 0

def merge_coverage(base, delta):
    if not isinstance(base, dict): base = {}
    if not isinstance(delta, dict): return base
    for file_path, lines in delta.items():
        if not isinstance(lines, dict): continue
        if file_path not in base or not isinstance(base[file_path], dict):
            base[file_path] = lines
        else:
            for ln, val in lines.items():
                ln_str = str(ln)
                if ln_str not in base[file_path]:
                    base[file_path][ln_str] = val
                else:
                    if priority(val) > priority(base[file_path][ln_str]):
                        base[file_path][ln_str] = val
    return base

def _load_json_tolerant(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except Exception:
        return None
    try:
        return json.loads(data)
    except Exception:
        pass
    try:
        dec = json.JSONDecoder()
        idx = 0
        merged = {}
        n = len(data)
        while idx < n:
            while idx < n and data[idx].isspace():
                idx += 1
            if idx >= n:
                break
            try:
                obj, end = dec.raw_decode(data, idx)
            except Exception:
                break
            if isinstance(obj, dict):
                merged = merge_coverage(merged, obj)
            idx = end
        return merged if isinstance(merged, dict) and merged else None
    except Exception:
        return None

def get_appdir_prefix(appdir):
    if not appdir:
        return "+"
    parts = [p for p in appdir.replace('\\', '/').split('/') if p]
    return "+" + "+".join(parts)

def get_group_key(tarut_name):
    parts = [p for p in tarut_name.split('+') if p]
    first = parts[0] if len(parts) > 0 else 'root'
    second = parts[1] if len(parts) > 1 else 'root'
    return f"+{first}+{second}"

def get_global_file_for_group(group_key):
    return os.path.join(COV_DIR, f"{group_key}.cc.json")

class CoverageDaemon:
    def __init__(self, config_path, log_dir: str):
        self.log_dir = log_dir or "/tmp"
        self.status_path = os.path.join(self.log_dir, "coverage_daemon.status.json")
        self.error_path = os.path.join(self.log_dir, "coverage_daemon.error.log")
        self.appdir = ""
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    cfg = json.load(f)
                    self.appdir = cfg.get("appdir") or cfg.get("app_dir") or cfg.get("app_root") or "/app"
            except Exception:
                pass
        if not self.appdir:
            self.appdir = "/app"
        self.appdir_prefix = get_appdir_prefix(self.appdir)
        self.group_key = get_group_key(self.appdir_prefix)
        self.cov_dir = os.path.join(COV_DIR, self.group_key)
        self.global_file = os.path.join(self.cov_dir, f"{self.group_key}.cc.json")
        self.running = True
        self.merges = 0
        self.files_processed = 0

    def _status(self, event: str, **extra) -> None:
        g_exists = os.path.isfile(self.global_file)
        g_size = os.path.getsize(self.global_file) if g_exists else 0
        obj: Dict[str, Any] = {
            "ts": _now(),
            "event": event,
            "cov_root": COV_DIR,
            "cov_dir": self.cov_dir,
            "global_file": self.global_file,
            "global_exists": bool(g_exists),
            "global_size": int(g_size),
            "group_key": self.group_key,
            "appdir": self.appdir,
            "merges": int(self.merges),
            "files_processed": int(self.files_processed),
        }
        if extra:
            for k, v in extra.items():
                obj[str(k)] = v
        _write_json_atomic(self.status_path, obj)

    def _error(self, msg: str) -> None:
        _append_line(self.error_path, f"[{_now()}] {msg}")
        self._status("error", error=msg)

    def cleanup_globals(self):
        if os.path.exists(self.cov_dir):
            try:
                import shutil
                shutil.rmtree(self.cov_dir)
            except Exception as e:
                self._error(f"cleanup_failed cov_dir={self.cov_dir} error={e}")

    def handle_exit(self, signum, frame):
        self._status("exit", signum=int(signum) if signum is not None else None)
        if os.path.exists(START_TEST_FLAG):
            try:
                os.remove(START_TEST_FLAG)
            except Exception as e:
                self._error(f"remove_start_flag_failed path={START_TEST_FLAG} error={e}")
        self.cleanup_globals()
        self.running = False
        sys.exit(0)

    def run(self):
        signal.signal(signal.SIGINT, self.handle_exit)
        signal.signal(signal.SIGTERM, self.handle_exit)

        self._status("start")
        
        self.cleanup_globals()
        os.makedirs(self.cov_dir, exist_ok=True)

        try:
            with open(START_TEST_FLAG, "w") as f:
                f.write("Trace me if you can, little one.")
        except Exception as e:
            self._error(f"create_start_flag_failed path={START_TEST_FLAG} error={e}")

        global_cov = {}
        files_processed = 0
        merges = 0
        last_heartbeat = 0.0

        while self.running:
            try:
                os.makedirs(self.cov_dir, exist_ok=True)
            except Exception:
                pass
            all_files = glob.glob(os.path.join(self.cov_dir, "*.cc.json"))
            scattered_files = [f for f in all_files if f != self.global_file]

            if not scattered_files:
                now = time.time()
                if now - last_heartbeat >= 60:
                    last_heartbeat = now
                    self.merges = merges
                    self.files_processed = files_processed
                    self._status("heartbeat")
                time.sleep(1.5)
                continue

            files_to_read = scattered_files[:]
            files_to_delete = []
            merged_any = False
            
            if not global_cov and os.path.exists(self.global_file):
                try:
                    loaded = _load_json_tolerant(self.global_file)
                    if isinstance(loaded, dict):
                        global_cov = loaded
                except Exception as e:
                    self._error(f"load_global_failed path={self.global_file} error={e}")

            for f in files_to_read:
                try:
                    delta = _load_json_tolerant(f)
                    if isinstance(delta, dict):
                        global_cov = merge_coverage(global_cov, delta)
                        files_to_delete.append(f)
                        merged_any = True
                except Exception as e:
                    self._error(f"merge_scattered_failed path={f} error={e}")

            if merged_any:
                tmp_file = self.global_file + ".tmp"
                try:
                    os.makedirs(os.path.dirname(os.path.abspath(self.global_file)) or ".", exist_ok=True)
                    with open(tmp_file, 'w') as jf:
                        json.dump(global_cov, jf)
                    os.replace(tmp_file, self.global_file)
                    merges += 1
                    files_processed += len(files_to_delete)
                    self.merges = merges
                    self.files_processed = files_processed
                    self._status("merged", merged_files=int(len(files_to_delete)))
                except Exception as e:
                    self._error(f"write_global_failed path={self.global_file} error={e}")

            for f in files_to_delete:
                try:
                    os.remove(f)
                except FileNotFoundError:
                    continue
                except Exception as e:
                    self._error(f"remove_scattered_failed path={f} error={e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="Path to config.json")
    parser.add_argument("--log_dir", default="/tmp", help="Directory to save log files")
    args = parser.parse_args()
    
    daemon = CoverageDaemon(args.config, args.log_dir)
    daemon.run()
