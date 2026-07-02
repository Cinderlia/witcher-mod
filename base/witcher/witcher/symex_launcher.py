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
    runtime_cache_dir = os.path.join(wd, "symex_runtime", "skip_cache")
    os.makedirs(runtime_cache_dir, exist_ok=True)
    if_cache_path = os.path.join(runtime_cache_dir, "if_stmt_counts.json")
    try:
        if os.path.exists(if_cache_path):
            os.remove(if_cache_path)
        if os.path.exists(if_cache_path + ".lock"):
            os.remove(if_cache_path + ".lock")
    except Exception:
        pass

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
    env = os.environ.copy()
    env["WC_IF_STMT_CACHE_PATH"] = if_cache_path
    proc = subprocess.Popen(
        cmd,
        cwd=str(symex_root),
        stdout=log_fp,
        stderr=log_fp,
        env=env,
        close_fds=True,
        start_new_session=(os.name != "nt"),
    )
    return SymexHandle(proc, log_fp, log_path, stop_flag_path, None)


def stop_symex(handle: Optional[SymexHandle]) -> None:
    if not handle:
        return
                
    proc = handle.proc
    try:
        try:
            if handle.stop_flag_path:
                with open(handle.stop_flag_path, "w") as f:
                    f.write("stop\n")
                if handle.log_fp:
                    handle.log_fp.write("[WC] stop_flag_written path=%s\n" % str(handle.stop_flag_path))
                    handle.log_fp.flush()
        except Exception:
            pass
        if proc and proc.poll() is None:
            try:
                if handle.log_fp:
                    handle.log_fp.write("[WC] wait_daemon_exit_begin pid=%s\n" % str(proc.pid))
                    handle.log_fp.flush()
                proc.wait(timeout=8)
            except Exception:
                try:
                    if handle.log_fp:
                        handle.log_fp.write("[WC] daemon_terminate pid=%s\n" % str(proc.pid))
                        handle.log_fp.flush()
                    proc.terminate()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=8)
                except Exception:
                    try:
                        if handle.log_fp:
                            handle.log_fp.write("[WC] daemon_kill pid=%s\n" % str(proc.pid))
                            handle.log_fp.flush()
                        proc.kill()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        pass
    finally:
        try:
            if handle.log_fp:
                handle.log_fp.write("[WC] stop_symex_done\n")
                handle.log_fp.flush()
        except Exception:
            pass
        try:
            handle.log_fp.close()
        except Exception:
            pass
