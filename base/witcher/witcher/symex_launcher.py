import json
import os
import subprocess
import sys
from typing import Optional
import pathlib

class SymexHandle:
    def __init__(self, proc, log_fp, log_path, stop_flag_path, daemon_proc=None):
        self.proc = proc
        self.log_fp = log_fp
        self.log_path = log_path
        self.stop_flag_path = stop_flag_path
        self.daemon_proc = daemon_proc


def start_symex_hybrid(*, work_dir: str, config_path: str, request_data_path: str, trace_timeout: int = 30, enabled: bool = True) -> Optional[SymexHandle]:
    if not enabled:
        return None

    symex_root = pathlib.Path(__file__).resolve().parents[1] / "symex"
    symex_cfg_path = symex_root / "config.json"
    if symex_cfg_path.exists():
        try:
            with open(symex_cfg_path, "r", encoding="utf-8", errors="replace") as f:
                obj = json.load(f)
            if isinstance(obj, dict):
                v = obj.get("symex_enabled", True)
                if isinstance(v, bool) and not v:
                    return None
                if isinstance(v, str) and v.strip().lower() in ("0", "false", "no", "off"):
                    return None
        except Exception:
            pass
    symex_main = symex_root / "main.py"
    if not symex_main.exists():
        print(f"[WC] symex main not found at {symex_main}, skip starting symex")
        return None

    wd = os.path.realpath(work_dir)
    cfg = os.path.realpath(config_path)
    req = os.path.realpath(request_data_path)

    runtime_meta_dir = os.path.join(wd, "symex_runtime", "meta")
    os.makedirs(runtime_meta_dir, exist_ok=True)
    log_path = os.path.join(runtime_meta_dir, "symex_entry.log")
    log_fp = open(log_path, "a+", encoding="utf-8")
    stop_flag_path = os.path.join(runtime_meta_dir, "stop.flag")

    cmd = [
        sys.executable,
        str(symex_main),
        "--daemon",
        "--hybrid-work-dir",
        wd,
        "--witcher-config",
        cfg,
        "--request-data",
        req,
        "--trace-timeout",
        str(int(trace_timeout)),
    ]

    print(f"[WC] Starting symex: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        cwd=str(symex_root),
        stdout=log_fp,
        stderr=log_fp,
        env=os.environ.copy(),
        close_fds=True,
        start_new_session=(os.name != "nt"),
    )
    
    # Start coverage daemon
    daemon_proc = None
    daemon_main = symex_root / "tools" / "coverage_daemon.py"
    if daemon_main.exists():
        log_path_obj = pathlib.Path(log_path)
        daemon_log_path = log_path_obj.parent / "coverage_daemon_stdout.log"
        daemon_log_fp = open(daemon_log_path, "a", encoding="utf-8")
        daemon_cmd = [
            sys.executable,
            str(daemon_main),
            "--config",
            str(config_path),
            "--log_dir",
            str(log_path_obj.parent)
        ]
        print(f"[WC] Starting coverage daemon: {' '.join(daemon_cmd)}")
        daemon_env = os.environ.copy()
        daemon_env["WITCHER_SYMEX_META_DIR"] = str(log_path_obj.parent)
        daemon_proc = subprocess.Popen(
            daemon_cmd,
            cwd=str(symex_root),
            stdout=daemon_log_fp,
            stderr=subprocess.STDOUT,
            env=daemon_env,
            close_fds=True,
            start_new_session=(os.name != "nt"),
        )
        
    return SymexHandle(proc, log_fp, log_path, stop_flag_path, daemon_proc)


def stop_symex(handle: Optional[SymexHandle]) -> None:
    if not handle:
        return
    
    # Stop coverage daemon first
    daemon_proc = getattr(handle, "daemon_proc", None)
    if daemon_proc and daemon_proc.poll() is None:
        try:
            daemon_proc.terminate()
            daemon_proc.wait(timeout=3)
        except Exception:
            try:
                daemon_proc.kill()
                daemon_proc.wait(timeout=2)
            except Exception:
                pass
                
    proc = handle.proc
    try:
        try:
            if handle.stop_flag_path:
                with open(handle.stop_flag_path, "w") as f:
                    f.write("stop\n")
        except Exception:
            pass
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
    finally:
        try:
            handle.log_fp.close()
        except Exception:
            pass
