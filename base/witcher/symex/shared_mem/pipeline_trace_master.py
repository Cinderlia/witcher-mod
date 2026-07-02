import argparse
import concurrent.futures
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
from typing import Dict, Optional

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.logger import Logger
from common.process_kill_audit import record_process_kill, record_stop_request

try:
    from .analyze_job_protocol import send_request
    from .ast_store import ping_global_ast_master, resolve_global_ast_master_state_from_env
    from .shared_payload_store import close_attached_payloads, close_published_payloads
    from .trace_sidecar_builder import ensure_pipeline_trace_sidecar
    from .trace_store import load_pipeline_trace_master_state, pipeline_trace_state_paths, shutdown_pipeline_trace_master
except Exception:
    from shared_mem.analyze_job_protocol import send_request
    from shared_mem.ast_store import ping_global_ast_master, resolve_global_ast_master_state_from_env
    from shared_mem.shared_payload_store import close_attached_payloads, close_published_payloads
    from shared_mem.trace_sidecar_builder import ensure_pipeline_trace_sidecar
    from shared_mem.trace_store import load_pipeline_trace_master_state, pipeline_trace_state_paths, shutdown_pipeline_trace_master


def _read_json(path: str) -> Dict[str, object]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _write_json(path: str, obj: Dict[str, object]) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return path


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def _update_state_file(state_path: str, updates: Dict[str, object]) -> Dict[str, object]:
    cur = load_pipeline_trace_master_state(state_path=state_path)
    if not isinstance(cur, dict):
        cur = {}
    cur.update(updates or {})
    _write_json(state_path, cur)
    return cur


def _wait_for_pid_exit(pid: int, timeout_sec: float) -> bool:
    deadline = time.time() + max(0.5, float(timeout_sec))
    while time.time() < deadline:
        if not _pid_alive(int(pid)):
            return True
        time.sleep(0.1)
    return not _pid_alive(int(pid))


def _collect_analyze_artifacts(*, run_root: str, seq: int) -> Dict[str, object]:
    seq_root = os.path.join(os.path.abspath(run_root), "test", "seqs", "seq_%d" % int(seq))
    logs_dir = os.path.join(seq_root, "logs")
    heartbeat_status_path = os.path.join(logs_dir, "heartbeat.status.json")
    analysis_output_path = os.path.join(seq_root, "analysis_output_%d.json" % int(seq))
    payload: Dict[str, object] = {
        "seq_root": seq_root,
        "seq_root_exists": bool(os.path.isdir(seq_root)),
        "logs_dir": logs_dir,
        "logs_dir_exists": bool(os.path.isdir(logs_dir)),
        "heartbeat_status_path": heartbeat_status_path,
        "heartbeat_status_exists": bool(os.path.exists(heartbeat_status_path)),
        "analysis_output_path": analysis_output_path,
        "analysis_output_exists": bool(os.path.exists(analysis_output_path)),
    }
    if os.path.exists(heartbeat_status_path):
        hb = _read_json(heartbeat_status_path)
        if isinstance(hb, dict):
            payload["heartbeat_status"] = str(hb.get("status") or "")
            payload["heartbeat_stage"] = str(hb.get("stage") or "")
            payload["heartbeat_updated_at"] = str(hb.get("updated_at") or "")
    return payload


def _load_shared_settings_from_path(config_path: Optional[str]) -> Dict[str, object]:
    raw = _read_json(config_path or "")
    obj = raw.get("symex_shared_memory") if isinstance(raw.get("symex_shared_memory"), dict) else {}
    return obj if isinstance(obj, dict) else {}


def _read_bool(raw, default: bool) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        v = raw.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off"):
            return False
    return bool(default)


def should_enable_pipeline_trace_master(*, config_path: Optional[str]) -> bool:
    obj = _load_shared_settings_from_path(config_path)
    env_enabled = os.environ.get("SYMEX_SHARED_MEMORY_ENABLED")
    enabled = _read_bool(env_enabled, _read_bool(obj.get("enabled"), True))
    mode = str(os.environ.get("SYMEX_SHARED_MODE") or obj.get("mode") or "master_worker").strip() or "master_worker"
    require_linux = _read_bool(obj.get("require_linux"), True)
    is_linux = os.name == "posix" and sys.platform.startswith("linux")
    if not enabled:
        return False
    if mode and mode != "master_worker":
        return False
    if require_linux and not is_linux:
        return False
    return True


def _load_max_workers(*, config_path: Optional[str], default_value: int) -> int:
    obj = _load_shared_settings_from_path(config_path)
    try:
        raw = os.environ.get("SYMEX_PIPELINE_MAX_WORKERS") or obj.get("pipeline_max_workers") or default_value
        return max(1, int(raw))
    except Exception:
        return max(1, int(default_value))


def _preload_trace_cache(*, trace_path: str, trace_index_path: str, logger: Logger) -> Dict[str, object]:
    try:
        from shared_mem.providers import _preload_trace_context_cached
    except Exception:
        from .providers import _preload_trace_context_cached  # type: ignore
    stats = _preload_trace_context_cached(trace_path=trace_path, trace_index_path=trace_index_path, logger=logger)
    logger.info(
        "pipeline_trace_cache_preloaded",
        trace_record_count=int(stats.get("trace_record_count") or 0),
        seq_to_index_count=int(stats.get("seq_to_index_count") or 0),
        seq_to_loc_count=int(stats.get("seq_to_loc_count") or 0),
    )
    return stats


def _execute_analyze_job(job: Dict[str, object], logger: Optional[Logger] = None) -> Dict[str, object]:
    seq = int(job.get("seq") or 0)
    llm_test_mode = bool(job.get("llm_test_mode"))
    sql_mode = bool(job.get("sql_mode"))
    xss_mode = bool(job.get("xss_mode"))
    cmd_mode = bool(job.get("cmd_mode"))
    try:
        from analyze_if_line import run_analyze_job
        opts = {
            "debug_mode": True,
            "prompt_mode": True,
            "llm_mode": (not bool(llm_test_mode)),
            "sql_mode": bool(sql_mode),
            "xss_mode": bool(xss_mode),
            "cmd_mode": bool(cmd_mode),
            "llm_max_calls": None,
        }
        result = run_analyze_job(
            int(seq),
            argv=[],
            opts=opts,
            llm_test_mode=bool(llm_test_mode),
            release_token=False,
        )
        artifact_info = _collect_analyze_artifacts(run_root=os.getcwd(), seq=int(seq))
        if logger is not None:
            logger.info(
                "analyze_job_done",
                seq=int(seq),
                llm_test_mode=bool(llm_test_mode),
                sql_mode=bool(sql_mode),
                xss_mode=bool(xss_mode),
                cmd_mode=bool(cmd_mode),
                analysis_output_exists=bool(artifact_info.get("analysis_output_exists")),
                heartbeat_status_exists=bool(artifact_info.get("heartbeat_status_exists")),
                heartbeat_stage=str(artifact_info.get("heartbeat_stage") or ""),
                heartbeat_status=str(artifact_info.get("heartbeat_status") or ""),
            )
        return {
            "ok": True,
            "seq": int(seq),
            "result": result if isinstance(result, dict) else {},
            "artifacts": artifact_info,
        }
    except Exception as exc:
        artifact_info = _collect_analyze_artifacts(run_root=os.getcwd(), seq=int(seq))
        if logger is not None:
            logger.exception(
                "analyze_job_failed",
                seq=int(seq),
                error=str(exc),
                analysis_output_exists=bool(artifact_info.get("analysis_output_exists")),
                heartbeat_status_exists=bool(artifact_info.get("heartbeat_status_exists")),
                heartbeat_stage=str(artifact_info.get("heartbeat_stage") or ""),
                heartbeat_status=str(artifact_info.get("heartbeat_status") or ""),
            )
        return {
            "ok": False,
            "seq": int(seq),
            "error": str(exc),
            "artifacts": artifact_info,
        }


def _handle_connection(conn, *, paths: Dict[str, str], executor, logger: Logger, metrics: Dict[str, object], state_lock) -> None:
    try:
        data = conn.recv(65536)
        req = {}
        try:
            req = json.loads((data or b"{}").decode("utf-8", errors="replace"))
        except Exception:
            req = {}
        cmd = str(req.get("cmd") or "ping").strip() or "ping"
        if cmd == "ping":
            payload = load_pipeline_trace_master_state(state_path=paths["state_path"])
            payload["cmd"] = cmd
            payload["ok"] = True
            conn.sendall(json.dumps(payload, ensure_ascii=False).encode("utf-8", errors="replace"))
            return
        if cmd == "attach_trace_payloads":
            cur = load_pipeline_trace_master_state(state_path=paths["state_path"])
            attach_count = int(cur.get("attach_request_count") or 0) + 1
            active_attach_count = int(cur.get("active_attach_count") or 0) + 1
            _update_state_file(
                paths["state_path"],
                {
                    "attach_request_count": attach_count,
                    "active_attach_count": active_attach_count,
                    "last_attach_request": {
                        "cmd": cmd,
                        "at": int(time.time()),
                    },
                },
            )
            payload = {
                "ok": True,
                "cmd": cmd,
                "pid": int(os.getpid()),
                "attach_id": "%s-%d" % (str(os.getpid()), int(time.time() * 1000)),
                "payload_encoding": str(cur.get("payload_encoding") or ""),
                "shared_payload_enabled": bool(cur.get("shared_payload_enabled")),
                "shared_payload_backend": str(cur.get("shared_payload_backend") or ""),
                "shared_payloads": cur.get("shared_payloads") if isinstance(cur.get("shared_payloads"), dict) else {},
                "records_path": str(cur.get("records_path") or ""),
                "seq_index_path": str(cur.get("seq_index_path") or ""),
                "seq_loc_path": str(cur.get("seq_loc_path") or ""),
            }
            logger.info(
                "pipeline_trace_payload_attach_requested",
                attach_request_count=int(attach_count),
                active_attach_count=int(active_attach_count),
                shared_payload_enabled=bool(cur.get("shared_payload_enabled")),
            )
            conn.sendall(json.dumps(payload, ensure_ascii=False).encode("utf-8", errors="replace"))
            return
        if cmd == "release_trace_payloads":
            cur = load_pipeline_trace_master_state(state_path=paths["state_path"])
            release_count = int(cur.get("release_request_count") or 0) + 1
            active_attach_count = max(0, int(cur.get("active_attach_count") or 0) - 1)
            _update_state_file(
                paths["state_path"],
                {
                    "release_request_count": release_count,
                    "active_attach_count": active_attach_count,
                    "last_release_request": {
                        "cmd": cmd,
                        "at": int(time.time()),
                    },
                },
            )
            payload = {
                "ok": True,
                "cmd": cmd,
                "pid": int(os.getpid()),
                "release_request_count": int(release_count),
                "active_attach_count": int(active_attach_count),
            }
            logger.info(
                "pipeline_trace_payload_release_requested",
                release_request_count=int(release_count),
                active_attach_count=int(active_attach_count),
            )
            conn.sendall(json.dumps(payload, ensure_ascii=False).encode("utf-8", errors="replace"))
            return
        if cmd == "shutdown":
            logger.info("pipeline_trace_master_shutdown_requested")
            state["stop"] = True
            conn.sendall(json.dumps({"ok": True, "cmd": cmd, "pid": int(os.getpid()), "status": "shutting_down"}, ensure_ascii=False).encode("utf-8", errors="replace"))
            return
        if cmd == "submit":
            job = req.get("job") if isinstance(req.get("job"), dict) else {}
            with state_lock:
                metrics["submit_total"] = int(metrics.get("submit_total") or 0) + 1
                metrics["inflight_jobs"] = int(metrics.get("inflight_jobs") or 0) + 1
                metrics["max_inflight_jobs"] = max(
                    int(metrics.get("max_inflight_jobs") or 0),
                    int(metrics.get("inflight_jobs") or 0),
                )
                _update_state_file(
                    paths["state_path"],
                    {
                        "submit_total": int(metrics.get("submit_total") or 0),
                        "inflight_jobs": int(metrics.get("inflight_jobs") or 0),
                        "max_inflight_jobs": int(metrics.get("max_inflight_jobs") or 0),
                        "last_submit_at": int(time.time()),
                        "last_job": {
                            "seq": int(job.get("seq") or 0),
                            "sql_mode": bool(job.get("sql_mode")),
                            "xss_mode": bool(job.get("xss_mode")),
                            "cmd_mode": bool(job.get("cmd_mode")),
                            "llm_test_mode": bool(job.get("llm_test_mode")),
                            "phase": "submitted",
                            "updated_at": int(time.time()),
                        },
                    },
                )
            future = executor.submit(_execute_analyze_job, job, logger)
            result = future.result()
            with state_lock:
                metrics["inflight_jobs"] = max(0, int(metrics.get("inflight_jobs") or 0) - 1)
                if result.get("ok") is True:
                    metrics["submit_success"] = int(metrics.get("submit_success") or 0) + 1
                else:
                    metrics["submit_failure"] = int(metrics.get("submit_failure") or 0) + 1
                _update_state_file(
                    paths["state_path"],
                    {
                        "submit_total": int(metrics.get("submit_total") or 0),
                        "submit_success": int(metrics.get("submit_success") or 0),
                        "submit_failure": int(metrics.get("submit_failure") or 0),
                        "inflight_jobs": int(metrics.get("inflight_jobs") or 0),
                        "max_inflight_jobs": int(metrics.get("max_inflight_jobs") or 0),
                        "last_submit_at": int(time.time()),
                        "last_job": {
                            "seq": int(job.get("seq") or 0),
                            "sql_mode": bool(job.get("sql_mode")),
                            "xss_mode": bool(job.get("xss_mode")),
                            "cmd_mode": bool(job.get("cmd_mode")),
                            "llm_test_mode": bool(job.get("llm_test_mode")),
                            "phase": ("done" if result.get("ok") is True else "failed"),
                            "ok": bool(result.get("ok") is True),
                            "error": str(result.get("error") or ""),
                            "artifacts": (result.get("artifacts") if isinstance(result.get("artifacts"), dict) else {}),
                            "updated_at": int(time.time()),
                        },
                    },
                )
            result["cmd"] = cmd
            conn.sendall(json.dumps(result, ensure_ascii=False).encode("utf-8", errors="replace"))
            return
        conn.sendall(json.dumps({"ok": False, "cmd": cmd, "error": "unknown_command"}, ensure_ascii=False).encode("utf-8", errors="replace"))
    except Exception:
        logger.exception("pipeline_trace_master_request_failed")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _serve_loop(
    *,
    run_dir: str,
    trace_path: str,
    trace_index_path: str,
    parent_pid: int,
    owner_pid: int,
    global_ast_state_path: Optional[str],
    max_workers: int,
) -> int:
    paths = pipeline_trace_state_paths(run_dir)
    os.makedirs(paths["shared_root"], exist_ok=True)
    os.makedirs(paths["ipc_dir"], exist_ok=True)
    os.makedirs(os.path.dirname(paths["state_path"]) or ".", exist_ok=True)
    logger = Logger(base_dir=paths["shared_root"], min_level="INFO", name="pipeline_trace_master", also_console=False)
    state = {"stop": False}
    client_threads = []
    metrics = {
        "submit_total": 0,
        "submit_success": 0,
        "submit_failure": 0,
        "inflight_jobs": 0,
        "max_inflight_jobs": 0,
        "fallback_spawn_count": 0,
        "last_job": {},
    }
    state_lock = threading.Lock()

    def _set_stop(*_args):
        state["stop"] = True

    try:
        signal.signal(signal.SIGTERM, _set_stop)
        signal.signal(signal.SIGINT, _set_stop)
    except Exception:
        pass

    sock = None
    executor = None
    published_payloads = None
    try:
        try:
            os.chdir(run_dir)
        except Exception:
            pass
        sidecar = ensure_pipeline_trace_sidecar(
            run_dir=run_dir,
            trace_path=trace_path,
            trace_index_path=trace_index_path,
            logger=logger,
            global_ast_state_path=global_ast_state_path,
        )
        preload_stats = _preload_trace_cache(
            trace_path=str(sidecar.get("trace_path") or trace_path),
            trace_index_path=str(sidecar.get("trace_index_path") or trace_index_path),
            logger=logger,
        )
        if os.path.exists(paths["socket_path"]):
            try:
                os.remove(paths["socket_path"])
            except Exception:
                pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(paths["socket_path"])
        sock.listen(16)
        sock.settimeout(1.0)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(max_workers)))
        _write_json(paths["pid_path"], {"pid": int(os.getpid())})
        _write_json(
            paths["state_path"],
            {
                "status": "ready",
                "pid": int(os.getpid()),
                "parent_pid": int(parent_pid),
                "owner_pid": int(owner_pid),
                "run_dir": paths["run_dir"],
                "socket_path": paths["socket_path"],
                "state_path": paths["state_path"],
                "header_path": sidecar["header_path"],
                "sources_path": sidecar["sources_path"],
                "records_path": sidecar.get("records_path") or "",
                "seq_index_path": sidecar.get("seq_index_path") or "",
                "seq_loc_path": sidecar.get("seq_loc_path") or "",
                "payload_encoding": sidecar.get("payload_encoding") or "",
                "shared_payloads": {},
                "shared_payload_enabled": False,
                "shared_payload_backend": "processed_trace_cache",
                "shared_payload_reason": "processed_trace_preloaded",
                "attach_request_count": 0,
                "release_request_count": 0,
                "active_attach_count": 0,
                "trace_path": sidecar["trace_path"],
                "trace_index_path": sidecar["trace_index_path"],
                "global_ast_state_path": os.path.abspath(global_ast_state_path) if global_ast_state_path else "",
                "trace_preloaded": True,
                "trace_stats": preload_stats,
                "max_workers": int(max_workers),
                "submit_total": 0,
                "submit_success": 0,
                "submit_failure": 0,
                "inflight_jobs": 0,
                "max_inflight_jobs": 0,
                "fallback_spawn_count": 0,
                "last_job": {},
                "started_at": int(time.time()),
            },
        )
        os.environ["SYMEX_PIPELINE_RUN_DIR"] = paths["run_dir"]
        os.environ["SYMEX_PIPELINE_TRACE_MASTER_SOCK"] = paths["socket_path"]
        os.environ["SYMEX_PIPELINE_TRACE_MASTER_STATE"] = paths["state_path"]
        logger.info(
            "pipeline_trace_master_ready",
            pid=int(os.getpid()),
            parent_pid=int(parent_pid),
            owner_pid=int(owner_pid),
            socket_path=paths["socket_path"],
            state_path=paths["state_path"],
            trace_path=sidecar["trace_path"],
            trace_index_path=sidecar["trace_index_path"],
            records_path=sidecar.get("records_path") or "",
            seq_index_path=sidecar.get("seq_index_path") or "",
            seq_loc_path=sidecar.get("seq_loc_path") or "",
            payload_encoding=sidecar.get("payload_encoding") or "",
            share_strategy="processed_trace_cache",
            max_workers=int(max_workers),
        )
        while True:
            if state.get("stop"):
                logger.info("pipeline_trace_master_stop_signal")
                break
            if int(parent_pid) > 0 and not _pid_alive(int(parent_pid)):
                logger.warning("pipeline_trace_master_parent_gone", parent_pid=int(parent_pid))
                break
            if int(owner_pid) > 0 and not _pid_alive(int(owner_pid)):
                logger.warning("pipeline_trace_master_owner_gone", owner_pid=int(owner_pid))
                break
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except Exception:
                logger.exception("pipeline_trace_master_accept_failed")
                continue
            t = threading.Thread(
                target=_handle_connection,
                args=(conn,),
                kwargs={"paths": paths, "executor": executor, "logger": logger, "metrics": metrics, "state_lock": state_lock},
            )
            t.daemon = True
            t.start()
            client_threads.append(t)
        return 0
    except Exception:
        logger.exception("pipeline_trace_master_failed")
        _write_json(
            paths["state_path"],
            {
                "status": "failed",
                "pid": int(os.getpid()),
                "parent_pid": int(parent_pid),
                "owner_pid": int(owner_pid),
                "run_dir": paths["run_dir"],
                "socket_path": paths["socket_path"],
                "failed_at": int(time.time()),
                "error": traceback.format_exc(),
            },
        )
        return 1
    finally:
        try:
            if executor is not None:
                executor.shutdown(wait=False)
        except Exception:
            pass
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
        try:
            close_published_payloads(published_payloads, logger=logger)
        except Exception:
            logger.exception("pipeline_trace_master_shared_payload_close_failed")
        try:
            close_attached_payloads()
        except Exception:
            logger.exception("pipeline_trace_master_attached_payload_close_failed")
        try:
            if os.path.exists(paths["socket_path"]):
                os.remove(paths["socket_path"])
        except Exception:
            pass
        try:
            cur = load_pipeline_trace_master_state(state_path=paths["state_path"])
            cur["status"] = "stopped" if cur.get("status") != "failed" else cur.get("status")
            cur["stopped_at"] = int(time.time())
            _write_json(paths["state_path"], cur)
        except Exception:
            pass
        for t in list(client_threads):
            try:
                t.join(timeout=0.2)
            except Exception:
                pass
        logger.close()


def start_pipeline_trace_master(
    *,
    run_dir: str,
    trace_path: str,
    trace_index_path: str,
    shared_config_path: Optional[str],
    max_workers: int,
    allow_local_fallback: bool = True,
    logger=None,
) -> Optional[dict]:
    if not should_enable_pipeline_trace_master(config_path=shared_config_path):
        if logger is not None:
            logger.info("pipeline_trace_master_disabled", run_dir=os.path.abspath(run_dir))
        return None
    paths = pipeline_trace_state_paths(run_dir)
    existing_state = load_pipeline_trace_master_state(state_path=paths["state_path"])
    existing_ping = ping_pipeline_trace_master(paths["socket_path"], timeout_sec=1.0) if os.path.exists(paths["socket_path"]) else None
    if existing_state and str(existing_state.get("status") or "") == "ready" and isinstance(existing_ping, dict) and existing_ping.get("ok") is True:
        os.environ["SYMEX_PIPELINE_RUN_DIR"] = os.path.abspath(run_dir)
        os.environ["SYMEX_PIPELINE_TRACE_MASTER_SOCK"] = paths["socket_path"]
        os.environ["SYMEX_PIPELINE_TRACE_MASTER_STATE"] = paths["state_path"]
        os.environ["SYMEX_PIPELINE_TRACE_PATH"] = os.path.abspath(trace_path)
        os.environ["SYMEX_PIPELINE_TRACE_INDEX_PATH"] = os.path.abspath(trace_index_path)
        os.environ["SYMEX_PIPELINE_MAX_WORKERS"] = str(int(max_workers))
        if shared_config_path:
            os.environ["SYMEX_PIPELINE_SHARED_CONFIG_PATH"] = os.path.abspath(shared_config_path)
        if logger is not None:
            logger.info(
                "pipeline_trace_master_reused",
                pid=int(existing_ping.get("pid") or existing_state.get("pid") or 0),
                socket_path=paths["socket_path"],
                state_path=paths["state_path"],
            )
        return {
            "proc": None,
            "log_fp": None,
            "log_path": "",
            "socket_path": paths["socket_path"],
            "state_path": paths["state_path"],
            "pid": int(existing_ping.get("pid") or existing_state.get("pid") or 0),
            "remote_spawn": True,
        }
    os.makedirs(paths["shared_root"], exist_ok=True)
    fp = None
    proc = None
    spawned_pid = 0
    global_state = resolve_global_ast_master_state_from_env()
    global_socket = str(
        os.environ.get("SYMEX_GLOBAL_AST_MASTER_SOCK")
        or global_state.get("socket_path")
        or ""
    ).strip()
    global_ping = ping_global_ast_master(global_socket, timeout_sec=1.0) if global_socket else None
    if global_socket and isinstance(global_ping, dict) and global_ping.get("ok") is True:
        resp = send_request(
            global_socket,
            {
                "cmd": "spawn_pipeline_trace_master",
                "run_dir": os.path.abspath(run_dir),
                "trace_path": os.path.abspath(trace_path),
                "trace_index_path": os.path.abspath(trace_index_path),
                "owner_pid": int(os.getpid()),
                "max_workers": int(max_workers),
            },
            timeout_sec=15.0,
        )
        if isinstance(resp, dict) and resp.get("ok") is True:
            try:
                spawned_pid = int(resp.get("spawned_pid") or 0)
            except Exception:
                spawned_pid = 0
            if logger is not None:
                logger.info(
                    "pipeline_trace_master_spawn_requested_via_global_ast",
                    spawned_pid=int(spawned_pid),
                    socket_path=resp.get("socket_path"),
                    state_path=resp.get("state_path"),
                )
        elif logger is not None:
            logger.warning(
                "pipeline_trace_master_spawn_via_global_ast_failed",
                socket_path=global_socket,
                response=json.dumps(resp or {}, ensure_ascii=False),
            )
    if not spawned_pid and not bool(allow_local_fallback):
        if logger is not None:
            logger.warning(
                "pipeline_trace_master_local_fallback_disabled",
                run_dir=os.path.abspath(run_dir),
                trace_path=os.path.abspath(trace_path),
                trace_index_path=os.path.abspath(trace_index_path),
            )
        return None
    if not spawned_pid:
        log_path = os.path.join(paths["shared_root"], "master_stdout.log")
        fp = open(log_path, "a", encoding="utf-8", errors="replace")
        cmd = [
            sys.executable,
            os.path.abspath(__file__),
            "--serve",
            "--run-dir",
            os.path.abspath(run_dir),
            "--trace-path",
            os.path.abspath(trace_path),
            "--trace-index-path",
            os.path.abspath(trace_index_path),
            "--max-workers",
            str(int(max_workers)),
            "--parent-pid",
            str(int(os.getpid())),
            "--owner-pid",
            str(int(os.getpid())),
        ]
        global_ast_state_path = os.environ.get("SYMEX_GLOBAL_AST_MASTER_STATE") or ""
        if global_ast_state_path:
            cmd.extend(["--global-ast-state", os.path.abspath(global_ast_state_path)])
        proc = subprocess.Popen(
            cmd,
            stdout=fp,
            stderr=fp,
            close_fds=True,
            start_new_session=True,
        )
    deadline = time.time() + 8.0
    state = {}
    while time.time() < deadline:
        state = load_pipeline_trace_master_state(state_path=paths["state_path"])
        if state.get("status") == "ready" and os.path.exists(paths["socket_path"]):
            os.environ["SYMEX_PIPELINE_RUN_DIR"] = os.path.abspath(run_dir)
            os.environ["SYMEX_PIPELINE_TRACE_MASTER_SOCK"] = paths["socket_path"]
            os.environ["SYMEX_PIPELINE_TRACE_MASTER_STATE"] = paths["state_path"]
            os.environ["SYMEX_PIPELINE_TRACE_PATH"] = os.path.abspath(trace_path)
            os.environ["SYMEX_PIPELINE_TRACE_INDEX_PATH"] = os.path.abspath(trace_index_path)
            os.environ["SYMEX_PIPELINE_MAX_WORKERS"] = str(int(max_workers))
            if shared_config_path:
                os.environ["SYMEX_PIPELINE_SHARED_CONFIG_PATH"] = os.path.abspath(shared_config_path)
            _update_state_file(
                paths["state_path"],
                {
                    "spawn_source": ("global_ast_fork" if bool(spawned_pid and proc is None) else "local_subprocess"),
                    "startup_confirmed_at": int(time.time()),
                },
            )
            if logger is not None:
                logger.info(
                    "pipeline_trace_master_started",
                    pid=int(proc.pid if proc is not None else spawned_pid),
                    socket_path=paths["socket_path"],
                    state_path=paths["state_path"],
                    via_global_ast=bool(spawned_pid and proc is None),
                )
            return {
                "proc": proc,
                "log_fp": fp,
                "log_path": (os.path.join(paths["shared_root"], "master_stdout.log") if fp is not None else ""),
                "socket_path": paths["socket_path"],
                "state_path": paths["state_path"],
                "pid": int(proc.pid if proc is not None else spawned_pid),
                "run_dir": os.path.abspath(run_dir),
                "remote_spawn": bool(spawned_pid and proc is None),
            }
        if state.get("status") == "failed":
            break
        rc = proc.poll() if proc is not None else None
        if proc is not None and rc is not None:
            break
        time.sleep(0.2)
    try:
        if proc is not None:
            proc.terminate()
    except Exception:
        pass
    try:
        if proc is not None:
            proc.wait(timeout=3)
    except Exception:
        try:
            if proc is not None:
                proc.kill()
        except Exception:
            pass
        try:
            if proc is not None:
                proc.wait(timeout=3)
        except Exception:
            pass
    if proc is None and spawned_pid > 0:
        try:
            os.kill(int(spawned_pid), signal.SIGTERM)
        except Exception:
            pass
    try:
        if fp is not None:
            fp.close()
    except Exception:
        pass
    if logger is not None:
        logger.warning("pipeline_trace_master_start_failed", state=json.dumps(state or {}, ensure_ascii=False))
    return None


def stop_pipeline_trace_master(handle: Optional[dict], *, logger=None, caller: str = "", reason: str = "", extra: Optional[Dict[str, object]] = None) -> None:
    if not handle:
        return
    proc = handle.get("proc")
    pid = int(handle.get("pid") or 0)
    run_dir = os.path.abspath(str(handle.get("run_dir") or "")).strip()
    fp = handle.get("log_fp")
    socket_path = str(handle.get("socket_path") or "").strip()
    state_path = str(handle.get("state_path") or "").strip()
    runtime_root = os.path.dirname(os.path.dirname(run_dir)) if run_dir else ""
    stop_extra = {
        "caller": str(caller or ""),
        "reason": str(reason or ""),
        "socket_path": socket_path,
        "state_path": state_path,
    }
    if isinstance(extra, dict):
        stop_extra.update(extra)
    if pid > 0:
        try:
            stop_audit = record_stop_request(
                runtime_root,
                int(pid),
                source="shared_mem.pipeline_trace_master.stop_pipeline_trace_master",
                reason=str(reason or ""),
                run_dir=run_dir,
                extra=stop_extra,
            )
        except Exception:
            stop_audit = {}
    else:
        stop_audit = {}
    if logger is not None:
        try:
            logger.warning(
                "pipeline_trace_master_stop_called",
                caller=str(caller or ""),
                reason=str(reason or ""),
                socket_path=socket_path,
                state_path=state_path,
                pid=int(pid or 0),
                run_dir=run_dir,
                matched_seq_logs=int(len(stop_audit.get("matched_seq_logs") or [])),
            )
        except Exception:
            pass
    shutdown_requested = False
    if socket_path:
        try:
            shutdown_pipeline_trace_master(socket_path, timeout_sec=2.0)
            shutdown_requested = True
            if logger is not None:
                logger.info("pipeline_trace_master_shutdown_requested", socket_path=socket_path)
        except Exception:
            pass
    try:
        if proc is not None and proc.poll() is None:
            if shutdown_requested:
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
            if proc.poll() is None:
                record_process_kill(
                    os.path.dirname(os.path.dirname(run_dir)) if run_dir else "",
                    int(proc.pid),
                    source="shared_mem.pipeline_trace_master.stop_pipeline_trace_master",
                    signal_name="SIGTERM",
                    reason="pipeline_trace_master_stop",
                    run_dir=run_dir,
                )
                proc.terminate()
                proc.wait(timeout=5)
    except Exception:
        try:
            record_process_kill(
                os.path.dirname(os.path.dirname(run_dir)) if run_dir else "",
                int(proc.pid if proc is not None else pid),
                source="shared_mem.pipeline_trace_master.stop_pipeline_trace_master",
                signal_name="SIGKILL",
                reason="pipeline_trace_master_stop_exception",
                run_dir=run_dir,
            )
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
    if proc is None and pid > 0:
        try:
            if shutdown_requested and _wait_for_pid_exit(int(pid), 5.0):
                pid = 0
            elif _pid_alive(int(pid)):
                record_process_kill(
                    os.path.dirname(os.path.dirname(run_dir)) if run_dir else "",
                    int(pid),
                    source="shared_mem.pipeline_trace_master.stop_pipeline_trace_master",
                    signal_name="SIGTERM",
                    reason="pipeline_trace_master_stop_remote",
                    run_dir=run_dir,
                )
                os.kill(int(pid), signal.SIGTERM)
                if not _wait_for_pid_exit(int(pid), 5.0):
                    record_process_kill(
                        os.path.dirname(os.path.dirname(run_dir)) if run_dir else "",
                        int(pid),
                        source="shared_mem.pipeline_trace_master.stop_pipeline_trace_master",
                        signal_name="SIGKILL",
                        reason="pipeline_trace_master_stop_remote_timeout",
                        run_dir=run_dir,
                    )
                    os.kill(int(pid), signal.SIGKILL)
        except Exception:
            pass
    try:
        if fp is not None:
            fp.close()
    except Exception:
        pass
    for key in (
        "SYMEX_PIPELINE_RUN_DIR",
        "SYMEX_PIPELINE_TRACE_MASTER_SOCK",
        "SYMEX_PIPELINE_TRACE_MASTER_STATE",
        "SYMEX_PIPELINE_TRACE_PATH",
        "SYMEX_PIPELINE_TRACE_INDEX_PATH",
        "SYMEX_PIPELINE_MAX_WORKERS",
        "SYMEX_PIPELINE_SHARED_CONFIG_PATH",
    ):
        try:
            os.environ.pop(key, None)
        except Exception:
            pass
    if logger is not None:
        logger.info("pipeline_trace_master_stopped")


def submit_pipeline_trace_job(*, socket_path: str, seq: int, llm_test_mode: bool, sql_mode: bool, xss_mode: bool, cmd_mode: bool, timeout_sec: float = 1800.0) -> Optional[Dict[str, object]]:
    return send_request(
        socket_path,
        {
            "cmd": "submit",
            "job": {
                "seq": int(seq),
                "llm_test_mode": bool(llm_test_mode),
                "sql_mode": bool(sql_mode),
                "xss_mode": bool(xss_mode),
                "cmd_mode": bool(cmd_mode),
            },
        },
        timeout_sec=float(timeout_sec),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--trace-path", required=True)
    ap.add_argument("--trace-index-path", required=True)
    ap.add_argument("--parent-pid", type=int, default=0)
    ap.add_argument("--owner-pid", type=int, default=0)
    ap.add_argument("--global-ast-state", default="")
    ap.add_argument("--max-workers", type=int, default=1)
    args = ap.parse_args()
    if not args.serve:
        return 1
    return _serve_loop(
        run_dir=os.path.abspath(args.run_dir),
        trace_path=os.path.abspath(args.trace_path),
        trace_index_path=os.path.abspath(args.trace_index_path),
        parent_pid=int(args.parent_pid or 0),
        owner_pid=int(args.owner_pid or 0),
        global_ast_state_path=(os.path.abspath(args.global_ast_state) if args.global_ast_state else None),
        max_workers=max(1, int(args.max_workers or 1)),
    )


if __name__ == "__main__":
    raise SystemExit(main())
