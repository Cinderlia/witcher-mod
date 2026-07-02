import asyncio
import json
import os
import re
import subprocess
import sys
import shutil
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

from hybrid_io.prepare_symex_inputs import prepare_inputs
from hybrid_io.seed_picker import list_queue_dirs, pick_preferred_seed


def _asyncio_run(coro):
    runner = getattr(asyncio, "run", None)
    if runner is not None:
        return runner(coro)
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(coro)


def _load_stats_enabled(cfg) -> bool:
    raw = cfg.raw if hasattr(cfg, "raw") else {}
    stats = raw.get("stats") if isinstance(raw, dict) else {}
    enabled = True
    if isinstance(stats, dict) and "enabled" in stats:
        v = stats.get("enabled")
        if isinstance(v, bool):
            enabled = v
        elif isinstance(v, str):
            enabled = v.strip().lower() in ("1", "true", "yes", "on")
        else:
            enabled = bool(v)
    return enabled


def _safe_int(v, default=0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _read_log_fields(line: str) -> Optional[dict]:
    if not isinstance(line, str):
        return None
    idx = line.rfind(" {")
    if idx < 0:
        return None
    payload = line[idx + 1 :].strip()
    if not payload.startswith("{"):
        return None
    try:
        return json.loads(payload)
    except Exception:
        return None


def _count_if_records(trace_index_records, nodes, parent_of) -> int:
    seen = set()
    for rec in trace_index_records or []:
        node_ids = rec.get("node_ids") or []
        for nid in node_ids:
            try:
                ni = int(nid)
            except Exception:
                continue
            tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
            if tt == "AST_IF":
                seen.add(int(ni))
                continue
            if tt == "AST_IF_ELEM":
                cur = parent_of.get(int(ni))
                steps = 0
                while cur is not None and steps < 8:
                    ct = ((nodes.get(int(cur)) or {}).get("type") or "").strip()
                    if ct == "AST_IF":
                        seen.add(int(cur))
                        break
                    cur = parent_of.get(int(cur))
                    steps += 1
    return len(seen)


def _collect_branch_selector_stats(log_path: str) -> dict:
    stats = {
        "coverage_skipped_seqs": set(),
        "submitted_to_llm": 0,
        "selected_for_analyze": 0,
    }
    if not os.path.exists(log_path):
        return stats
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "if_coverage_skip" in line:
                fields = _read_log_fields(line)
                if isinstance(fields, dict):
                    seq = fields.get("seq")
                    if seq is not None:
                        stats["coverage_skipped_seqs"].add(_safe_int(seq))
                continue
            if "buffer_flush_start" in line:
                fields = _read_log_fields(line)
                if isinstance(fields, dict):
                    stats["submitted_to_llm"] += _safe_int(fields.get("sections"))
                continue
            if "analyze_if_line_schedule" in line:
                fields = _read_log_fields(line)
                if isinstance(fields, dict):
                    stats["selected_for_analyze"] += _safe_int(fields.get("count"))
                continue
    return stats


def _collect_symbolic_solution_stats(test_root: str) -> dict:
    seq_count = 0
    solution_total = 0
    seq_root = os.path.join(test_root, "seqs")
    if not os.path.isdir(seq_root):
        return {"solution_if_count": 0, "solution_total": 0}
    for name in os.listdir(seq_root):
        if not name.startswith("seq_"):
            continue
        log_path = os.path.join(seq_root, name, "logs", "info.log")
        if not os.path.exists(log_path):
            continue
        max_count = 0
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "write_symbolic_solutions" not in line:
                    continue
                fields = _read_log_fields(line)
                if isinstance(fields, dict):
                    max_count = max(max_count, _safe_int(fields.get("count")))
        if max_count > 0:
            seq_count += 1
            solution_total += max_count
    return {"solution_if_count": seq_count, "solution_total": solution_total}


def _write_stats(output_dir: str, stats: dict) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "branch_selector_stats.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    return path


def _parse_arg_flag(argv: List[str], key: str) -> bool:
    if not argv:
        return False
    return any(x == key for x in argv if isinstance(x, str))


def _parse_arg_value(argv: List[str], key: str) -> Optional[str]:
    if not argv:
        return None
    for i, x in enumerate(argv):
        if not isinstance(x, str):
            continue
        if x.startswith(key + "="):
            return (x.split("=", 1)[1] or "").strip()
        if x == key and (i + 1) < len(argv):
            nxt = argv[i + 1]
            return (nxt or "").strip() if isinstance(nxt, str) else None
    return None


def _write_json(path: str, obj: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def _trace_session_capture_dir() -> str:
    return os.path.join("/tmp", "wc_session_trace")


def _load_trace_prepare_report(runtime_root: str) -> Dict[str, Any]:
    return _read_json(os.path.join(runtime_root, "meta", "prepare_report.json"))


def _trace_session_capture_filename(runtime_root: str) -> str:
    report = _load_trace_prepare_report(runtime_root)
    value = str(report.get("trace_session_capture_filename") or "").strip()
    if not value:
        return ""
    return os.path.basename(value)


def _trace_session_capture_source_path(runtime_root: str) -> str:
    filename = _trace_session_capture_filename(runtime_root)
    if not filename:
        return ""
    return os.path.join(_trace_session_capture_dir(), filename)


def _collect_trace_session_capture(runtime_root: str) -> Dict[str, Any]:
    src = _trace_session_capture_source_path(runtime_root)
    inp_dir = os.path.join(runtime_root, "input")
    dst = os.path.join(inp_dir, "session_capture.json")
    out = {
        "filename": os.path.basename(src) if src else "",
        "source_path": src,
        "source_exists": bool(src and os.path.exists(src)),
        "input_path": dst,
        "copied": False,
    }
    if not src or not os.path.exists(src):
        return out
    try:
        os.makedirs(inp_dir, exist_ok=True)
        shutil.copy2(src, dst)
        out["copied"] = True
        out["input_exists"] = bool(os.path.exists(dst))
    except Exception as ex:
        out["copy_error"] = str(ex)
        out["input_exists"] = bool(os.path.exists(dst))
    return out


def _reset_trace_session_capture(runtime_root: str) -> Dict[str, Any]:
    src = _trace_session_capture_source_path(runtime_root)
    dst = os.path.join(runtime_root, "input", "session_capture.json")
    out = {
        "filename": os.path.basename(src) if src else "",
        "source_path": src,
        "input_path": dst,
        "source_removed": False,
        "input_removed": False,
    }
    for key, path in (("source_removed", src), ("input_removed", dst)):
        if not path or not os.path.exists(path):
            continue
        try:
            os.remove(path)
            out[key] = True
        except Exception:
            continue
    return out

def _run_trace_for_seed(runtime_root: str, seed_path: str, timeout_sec: int = 30) -> Dict[str, Any]:
    commands_dir = os.path.join(runtime_root, "commands")
    traces_dir = os.path.join(runtime_root, "traces")
    os.makedirs(traces_dir, exist_ok=True)

    trace_script = os.path.join(commands_dir, "run_trace_with_seed.sh")
    if not os.path.isfile(trace_script):
        return {"ok": False, "reason": f"trace script missing: {trace_script}", "seed_path": seed_path}
    if not seed_path or not os.path.isfile(seed_path):
        return {"ok": False, "reason": f"seed missing: {seed_path}", "seed_path": seed_path}

    started_at = int(time.time())
    session_reset = _reset_trace_session_capture(runtime_root)
    try:
        proc = subprocess.run(
            ["bash", trace_script, seed_path],
            cwd=traces_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(timeout_sec)),
            check=False,
        )
    except Exception as ex:
        return {"ok": False, "reason": f"trace command failed: {ex}", "seed_path": seed_path}

    trace_path = os.path.join(traces_dir, "trace.log")
    trace_ok = False
    if os.path.exists(trace_path):
        if proc.returncode == 0:
            trace_ok = True
        else:
            try:
                with open(trace_path, "rb") as f:
                    line_count = sum(1 for _ in f)
                if line_count > 100:
                    trace_ok = True
            except Exception:
                pass
        try:
            inp = os.path.join(runtime_root, "input")
            os.makedirs(inp, exist_ok=True)
            shutil.copy2(trace_path, os.path.join(inp, "trace.log"))
        except Exception:
            pass
    session_capture = _collect_trace_session_capture(runtime_root)
    return {
        "ok": trace_ok,
        "seed_path": seed_path,
        "trace_path": trace_path if os.path.exists(trace_path) else "",
        "return_code": proc.returncode,
        "stdout_tail": (proc.stdout or "")[-1000:],
        "stderr_tail": (proc.stderr or "")[-1000:],
        "started_at": started_at,
        "finished_at": int(time.time()),
        "trace_session_capture": session_capture,
        "trace_session_capture_reset": session_reset,
    }


def _pick_latest_queue_seed(work_dir: str) -> str:
    wd = Path(work_dir or "")
    if not wd.is_dir():
        return ""
    best = ""
    best_mt = -1.0
    fuzzer_dirs = sorted(wd.glob("fuzzer-*")) + sorted(wd.glob("fuzzer-master"))
    for fd in fuzzer_dirs:
        qd = fd / "queue"
        if not qd.is_dir():
            continue
        try:
            for ent in qd.iterdir():
                try:
                    if not ent.is_file():
                        continue
                    if not ent.name.startswith("id:"):
                        continue
                    try:
                        mt = float(ent.stat().st_mtime)
                    except Exception:
                        mt = 0.0
                    if best == "" or mt > best_mt:
                        best = str(ent)
                        best_mt = float(mt)
                except Exception:
                    continue
        except Exception:
            continue
    return best


def _install_stop_handlers(state: dict) -> None:
    def _set_stop(*_args):
        state["stop"] = True
    try:
        import signal
        signal.signal(signal.SIGTERM, _set_stop)
        signal.signal(signal.SIGINT, _set_stop)
    except Exception:
        return


def _stop_flag_path(runtime_root: str) -> str:
    return os.path.join(runtime_root, "meta", "stop.flag")


def _daemon_log(runtime_root: str, msg: str) -> None:
    try:
        meta_dir = os.path.join(runtime_root, "meta")
        os.makedirs(meta_dir, exist_ok=True)
        path = os.path.join(meta_dir, "daemon.log")
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = "[%s] %s\n" % (ts, str(msg))
        with open(path, "a+", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        return


def _read_json(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _pid_alive(pid: int) -> Optional[bool]:
    try:
        pid_i = int(pid)
    except Exception:
        return None
    if pid_i <= 0:
        return None
    try:
        os.kill(pid_i, 0)
        return True
    except OSError:
        return False
    except Exception:
        return None


def _daemon_instance_path(runtime_root: str) -> str:
    return os.path.join(runtime_root, "meta", "daemon.instance.json")


def _try_acquire_daemon_instance(runtime_root: str) -> Dict[str, Any]:
    path = _daemon_instance_path(runtime_root)
    payload = {
        "pid": int(os.getpid()),
        "acquired_at": int(time.time()),
        "runtime_root": os.path.abspath(runtime_root),
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    for _ in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            current = _read_json(path)
            holder_pid = int(current.get("pid") or 0) if isinstance(current, dict) else 0
            if holder_pid > 0 and _pid_alive(holder_pid) is True:
                return {
                    "acquired": False,
                    "path": path,
                    "holder_pid": int(holder_pid),
                    "holder_info": current,
                }
            try:
                os.remove(path)
            except Exception:
                return {
                    "acquired": False,
                    "path": path,
                    "holder_pid": int(holder_pid),
                    "holder_info": current,
                }
            continue
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            out = dict(payload)
            out["acquired"] = True
            out["path"] = path
            return out
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            try:
                os.remove(path)
            except Exception:
                pass
            break
    return {"acquired": False, "path": path}


def _release_daemon_instance(runtime_root: str) -> None:
    path = _daemon_instance_path(runtime_root)
    current = _read_json(path)
    try:
        holder_pid = int(current.get("pid") or 0) if isinstance(current, dict) else 0
    except Exception:
        holder_pid = 0
    if holder_pid not in (0, int(os.getpid())):
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        return


def _global_ast_restart_request_path(runtime_root: str) -> str:
    return os.path.join(runtime_root, "meta", "global_ast_master.restart.request")


def _clear_restart_request(path: str) -> None:
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception:
        return


def _restart_global_ast_master_with_retry(*, runtime_root: str, runtime_config_path: str, shared_config_path: Optional[str], current_handle, max_attempts: int = 3):
    from shared_mem.global_ast_master import start_global_ast_master, stop_global_ast_master
    last_handle = current_handle
    for attempt in range(1, max(1, int(max_attempts)) + 1):
        _daemon_log(runtime_root, "global_ast_master_restart_attempt=%s" % str(attempt))
        try:
            if last_handle:
                stop_global_ast_master(last_handle, runtime_root=runtime_root, daemon_logger=_daemon_log)
        except Exception:
            _daemon_log(runtime_root, "global_ast_master_restart_stop_failed traceback=%s" % traceback.format_exc())
        last_handle = start_global_ast_master(
            runtime_root=runtime_root,
            runtime_config_path=runtime_config_path,
            shared_config_path=shared_config_path,
            daemon_logger=_daemon_log,
        )
        if last_handle is not None:
            _daemon_log(runtime_root, "global_ast_master_restart_ok attempt=%s" % str(attempt))
            return last_handle
        time.sleep(1.0)
    raise RuntimeError("global ast master restart failed after %d attempts" % int(max_attempts))


def _global_ast_master_unhealthy(handle) -> bool:
    if not handle:
        return False
    socket_path = str(handle.get("socket_path") or "").strip() if isinstance(handle, dict) else ""
    if not socket_path or not os.path.exists(socket_path):
        return True
    try:
        from shared_mem.ast_store import ping_global_ast_master
        ping = ping_global_ast_master(socket_path, timeout_sec=1.0)
    except Exception:
        return True
    return not (isinstance(ping, dict) and ping.get("ok") is True)


def _cleanup_runtime_dirs(runtime_root: str) -> None:
    for name in ("output", "test", "tmp"):
        p = os.path.join(runtime_root, name)
        if not os.path.exists(p):
            continue
        try:
            shutil.rmtree(p)
        except Exception:
            continue


def _run_hybrid_daemon(argv: List[str], cfg_path: Optional[str]) -> bool:
    if not _parse_arg_flag(argv, "--daemon"):
        return False

    hybrid_work_dir = _parse_arg_value(argv, "--hybrid-work-dir")
    if not hybrid_work_dir:
        raise ValueError("daemon mode requires --hybrid-work-dir")

    witcher_cfg = _parse_arg_value(argv, "--witcher-config") or cfg_path
    if not witcher_cfg:
        raise ValueError("daemon mode requires --witcher-config or positional cfg_path")
    request_data = _parse_arg_value(argv, "--request-data") or ""
    trace_timeout = int(_parse_arg_value(argv, "--trace-timeout") or 30)
    poll_sec = float(_parse_arg_value(argv, "--poll-interval") or 2.0)

    prep_meta = prepare_inputs(witcher_cfg, hybrid_work_dir, request_data)
    runtime_root = prep_meta.get("runtime_dirs", {}).get("root", "")
    if not runtime_root:
        raise ValueError("prepare_inputs did not return runtime root path")

    state = {"stop": False}
    _install_stop_handlers(state)

    try:
        os.chdir(runtime_root)
    except Exception:
        pass

    stop_path = _stop_flag_path(runtime_root)

    symex_cfg = os.path.join(os.path.dirname(os.path.abspath(witcher_cfg)), "symex_config.json")
    if not os.path.exists(symex_cfg):
        symex_cfg = None

    _daemon_log(runtime_root, "daemon_start work_dir=%s witcher_cfg=%s symex_cfg=%s poll=%s trace_timeout=%s" % (hybrid_work_dir, witcher_cfg, str(symex_cfg or ""), str(poll_sec), str(trace_timeout)))
    _daemon_log(runtime_root, "stop_flag=%s" % stop_path)
    _cleanup_runtime_dirs(runtime_root)
    instance = _try_acquire_daemon_instance(runtime_root)
    if not bool(instance.get("acquired")):
        _daemon_log(
            runtime_root,
            "daemon_start_skipped_existing_instance lock_path=%s holder_pid=%s"
            % (str(instance.get("path") or ""), str(instance.get("holder_pid") or "")),
        )
        return True

    ast_master_handle = None
    daemon = None
    stop_global_ast_master = None
    try:
        from hybrid_io.daemon_token_loop import HybridTokenDaemon
        from shared_mem.global_ast_master import should_enable_global_ast_master, start_global_ast_master, stop_global_ast_master

        runtime_cfg_path = os.path.join(runtime_root, "config.json")
        os.environ["SYMEX_RUNTIME_ROOT"] = os.path.abspath(runtime_root)
        os.environ["SYMEX_RUNTIME_CONFIG_PATH"] = os.path.abspath(runtime_cfg_path)
        if symex_cfg:
            os.environ["SYMEX_SHARED_CONFIG_PATH"] = os.path.abspath(symex_cfg)
        shared_master_enabled = bool(should_enable_global_ast_master(config_path=symex_cfg))
        if shared_master_enabled:
            ast_master_handle = _restart_global_ast_master_with_retry(
                runtime_root=runtime_root,
                runtime_config_path=runtime_cfg_path,
                shared_config_path=symex_cfg,
                current_handle=None,
                max_attempts=3,
            )
        else:
            ast_master_handle = start_global_ast_master(
                runtime_root=runtime_root,
                runtime_config_path=runtime_cfg_path,
                shared_config_path=symex_cfg,
                daemon_logger=_daemon_log,
            )
        daemon = HybridTokenDaemon(
            runtime_root=runtime_root,
            work_dir=hybrid_work_dir,
            symex_cfg_path=symex_cfg,
            trace_timeout=int(trace_timeout),
            logger=_daemon_log,
        )
        next_scan_ts = 0.0
        request_path = _global_ast_restart_request_path(runtime_root)
        while True:
            if state.get("stop"):
                _daemon_log(runtime_root, "daemon_stop signal")
                break
            if os.path.exists(stop_path):
                _daemon_log(runtime_root, "daemon_stop flag")
                break
            try:
                now = time.time()
                if float(now) >= float(next_scan_ts):
                    if shared_master_enabled and (os.path.exists(request_path) or _global_ast_master_unhealthy(ast_master_handle)):
                        reason = "request_file" if os.path.exists(request_path) else "healthcheck_failed"
                        _daemon_log(runtime_root, "global_ast_master_restart_begin reason=%s" % reason)
                        ast_master_handle = _restart_global_ast_master_with_retry(
                            runtime_root=runtime_root,
                            runtime_config_path=runtime_cfg_path,
                            shared_config_path=symex_cfg,
                            current_handle=ast_master_handle,
                            max_attempts=3,
                        )
                        _clear_restart_request(request_path)
                    daemon.scan()
                    next_scan_ts = float(now) + 5.0
                daemon.tick()
            except Exception:
                tb = traceback.format_exc()
                _daemon_log(runtime_root, "daemon_tick_error traceback=%s" % tb)
                if shared_master_enabled and ("global ast master restart failed" in tb.lower()):
                    raise
            time.sleep(1.0)
    finally:
        _daemon_log(runtime_root, "daemon_shutdown_begin")
        if daemon is not None:
            daemon.shutdown()
            _daemon_log(runtime_root, "daemon_shutdown_pipeline_done")
        if stop_global_ast_master is not None:
            stop_global_ast_master(ast_master_handle, runtime_root=runtime_root, daemon_logger=_daemon_log)
            _daemon_log(runtime_root, "daemon_shutdown_global_ast_done")
        _release_daemon_instance(runtime_root)

    return True


def _run_hybrid_input_stage(argv: List[str], cfg_path: Optional[str]) -> Optional[Dict[str, Any]]:
    hybrid_work_dir = _parse_arg_value(argv, "--hybrid-work-dir")
    if not hybrid_work_dir:
        return None

    witcher_cfg = _parse_arg_value(argv, "--witcher-config") or cfg_path
    if not witcher_cfg:
        raise ValueError("hybrid mode requires --witcher-config or positional cfg_path")
    request_data = _parse_arg_value(argv, "--request-data") or ""
    trace_timeout = int(_parse_arg_value(argv, "--trace-timeout") or 30)

    prep_meta = prepare_inputs(witcher_cfg, hybrid_work_dir, request_data)
    runtime_root = prep_meta.get("runtime_dirs", {}).get("root", "")
    if not runtime_root:
        raise ValueError("prepare_inputs did not return runtime root path")
    seed_path = _pick_latest_queue_seed(hybrid_work_dir)
    trace_meta = _run_trace_for_seed(runtime_root, seed_path, timeout_sec=trace_timeout)

    report = {
        "hybrid_work_dir": hybrid_work_dir,
        "witcher_config": witcher_cfg,
        "request_data": request_data,
        "prepare": prep_meta,
        "trace": trace_meta,
    }
    _write_json(os.path.join(runtime_root, "meta", "hybrid_stage_report.json"), report)
    return report


def _clear_test_root(test_root: str) -> None:
    if not test_root or not os.path.isdir(test_root):
        return
    for name in os.listdir(test_root):
        path = os.path.join(test_root, name)
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        except Exception:
            continue


def _clear_output_root(output_root: str) -> None:
    if not output_root or not os.path.isdir(output_root):
        return
    for name in os.listdir(output_root):
        path = os.path.join(output_root, name)
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        except Exception:
            continue


def main():
    cfg_path = None
    argv = list(sys.argv[1:])
    if argv and not argv[0].startswith("--"):
        cfg_path = argv[0]
        argv = argv[1:]
    if _run_hybrid_daemon(argv, cfg_path):
        return
    hybrid_report = _run_hybrid_input_stage(argv, cfg_path)
    if _parse_arg_flag(argv, "--hybrid-only"):
        if hybrid_report:
            print("[symex] hybrid input stage completed")
        return

    from branch_selector.core.config import load_config
    from branch_selector.pipeline import run_pipeline
    from branch_selector.trace.trace_extract import ensure_trace_index
    from common.app_config import load_app_config
    from utils.extractors.if_extract import load_ast_edges, load_nodes
    from utils.trace_utils import trace_edges as trace_edges_mod

    app_cfg = load_app_config(config_path=cfg_path, argv=argv)
    stats_enabled = _load_stats_enabled(app_cfg)
    trace_edges_path = app_cfg.tmp_path("trace_edges.csv")
    trace_index_path = app_cfg.tmp_path("trace_index.json")
    if not os.path.exists(trace_edges_path):
        trace_edges_mod.main()
    cfg = load_config(cfg_path)
    trace_path = app_cfg.find_input_file("trace.log")
    nodes_path = app_cfg.find_input_file("nodes.csv")
    if not os.path.exists(trace_index_path):
        ensure_trace_index(trace_index_path, trace_path, nodes_path, cfg.seq_limit, seq_start=cfg.seq_start)
    test_mode_override = True if _parse_arg_flag(argv, "--test-mode") else None
    analyze_llm_test_mode_override = True if _parse_arg_flag(argv, "--analyze-llm-test") else None
    effective_analyze_llm_test_mode = cfg.analyze_llm_test_mode if analyze_llm_test_mode_override is None else bool(analyze_llm_test_mode_override)
    if not effective_analyze_llm_test_mode:
        _clear_test_root(app_cfg.test_dir)
        _clear_output_root(app_cfg.output_dir)
    _asyncio_run(
        run_pipeline(
            cfg_path,
            test_mode_override=test_mode_override,
            analyze_llm_test_mode_override=analyze_llm_test_mode_override,
        )
    )
    if not stats_enabled:
        return
    trace_index_records = ensure_trace_index(trace_index_path, trace_path, nodes_path, cfg.seq_limit, seq_start=cfg.seq_start)
    nodes, _ = load_nodes(nodes_path)
    parent_of, _ = load_ast_edges(app_cfg.find_input_file("rels.csv"))
    if_count = _count_if_records(trace_index_records, nodes, parent_of)
    branch_log = os.path.join(app_cfg.test_dir, "branch_selector", "logs", "info.log")
    branch_stats = _collect_branch_selector_stats(branch_log)
    symbolic_stats = _collect_symbolic_solution_stats(app_cfg.test_dir)
    stats = {
        "trace_if_count": if_count,
        "coverage_skipped_if_count": len(branch_stats.get("coverage_skipped_seqs") or []),
        "submitted_to_llm_count": branch_stats.get("submitted_to_llm", 0),
        "llm_selected_if_count": branch_stats.get("selected_for_analyze", 0),
        "symbolic_solution_if_count": symbolic_stats.get("solution_if_count", 0),
        "symbolic_solution_total": symbolic_stats.get("solution_total", 0),
    }
    _write_stats(app_cfg.output_dir, stats)


if __name__ == "__main__":
    main()
