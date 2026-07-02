import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
import traceback
from typing import Dict, Optional

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.logger import Logger
from common.process_kill_audit import record_process_kill

try:
    from .ast_sidecar_builder import resolve_ast_inputs
    from .ast_store import global_ast_state_paths, load_global_ast_master_state, ping_global_ast_master, shutdown_global_ast_master
    from .shared_payload_store import close_attached_payloads, close_published_payloads
except Exception:
    from shared_mem.ast_sidecar_builder import resolve_ast_inputs
    from shared_mem.ast_store import global_ast_state_paths, load_global_ast_master_state, ping_global_ast_master, shutdown_global_ast_master
    from shared_mem.shared_payload_store import close_attached_payloads, close_published_payloads


def _write_start_failure(paths: Dict[str, str], payload: Dict[str, object]) -> str:
    failure_path = os.path.join(os.path.dirname(paths["state_path"]) or ".", "global_ast_master.start_failure.json")
    try:
        os.makedirs(os.path.dirname(failure_path) or ".", exist_ok=True)
        with open(failure_path, "w", encoding="utf-8", errors="replace") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        return ""
    return failure_path


def _estimate_start_timeout_sec(*, runtime_root: str, runtime_config_path: str) -> float:
    base_timeout = 30.0
    try:
        env_v = float(os.environ.get("SYMEX_GLOBAL_AST_START_TIMEOUT_SEC") or 0.0)
    except Exception:
        env_v = 0.0
    if env_v > 0.0:
        return max(8.0, float(env_v))
    total_bytes = 0
    try:
        ast_inputs = resolve_ast_inputs(runtime_root=runtime_root, runtime_config_path=runtime_config_path)
        for key in ("nodes_path", "rels_path"):
            p = str(ast_inputs.get(key) or "")
            if p and os.path.exists(p):
                total_bytes += int(os.path.getsize(p))
    except Exception:
        total_bytes = 0
    # Large projects need substantially more time for sidecar build and preload.
    if total_bytes <= 0:
        return base_timeout
    total_gb = float(total_bytes) / float(1024 ** 3)
    return max(base_timeout, min(300.0, 30.0 + total_gb * 90.0))


def _preload_ast_cache(*, nodes_path: str, rels_path: str, logger: Logger) -> Dict[str, int]:
    try:
        from shared_mem.providers import _load_ast_context_cached
    except Exception:
        from .providers import _load_ast_context_cached  # type: ignore
    nodes, _top_id_to_file, parent_of, children_of = _load_ast_context_cached(nodes_path, rels_path)
    stats = {
        "node_count": len(nodes or {}),
        "parent_count": len(parent_of or {}),
        "child_count": len(children_of or {}),
        "share_strategy": "fork_ast_cache",
    }
    logger.info("global_ast_cache_preloaded", **stats)
    return stats


def _spawn_pipeline_trace_master_via_fork(
    *,
    run_dir: str,
    trace_path: str,
    trace_index_path: str,
    owner_pid: int,
    max_workers: int,
    global_ast_state_path: str,
    logger: Logger,
    inherited_listener=None,
    inherited_conn=None,
) -> Dict[str, object]:
    try:
        from shared_mem.pipeline_trace_master import _serve_loop as serve_pipeline_trace_master_loop
        from shared_mem.trace_store import pipeline_trace_state_paths
    except Exception:
        from .pipeline_trace_master import _serve_loop as serve_pipeline_trace_master_loop  # type: ignore
        from .trace_store import pipeline_trace_state_paths  # type: ignore
    paths = pipeline_trace_state_paths(run_dir)
    pid = os.fork()
    if pid == 0:
        try:
            log_path = os.path.join(paths["shared_root"], "master_stdout.log")
            try:
                os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
                log_fp = open(log_path, "a", encoding="utf-8", errors="replace")
                sys.stdout.flush()
                sys.stderr.flush()
                os.dup2(log_fp.fileno(), 1)
                os.dup2(log_fp.fileno(), 2)
            except Exception:
                log_fp = None
            if inherited_listener is not None:
                try:
                    inherited_listener.close()
                except Exception:
                    pass
            if inherited_conn is not None:
                try:
                    inherited_conn.close()
                except Exception:
                    pass
            os.environ["SYMEX_GLOBAL_AST_MASTER_STATE"] = os.path.abspath(global_ast_state_path)
            rc = serve_pipeline_trace_master_loop(
                run_dir=os.path.abspath(run_dir),
                trace_path=os.path.abspath(trace_path),
                trace_index_path=os.path.abspath(trace_index_path),
                parent_pid=int(os.getppid()),
                owner_pid=int(owner_pid),
                global_ast_state_path=os.path.abspath(global_ast_state_path),
                max_workers=max(1, int(max_workers)),
            )
        except Exception:
            try:
                sys.stderr.write(traceback.format_exc())
                sys.stderr.flush()
            except Exception:
                pass
            rc = 1
        os._exit(int(rc))
    logger.info(
        "spawn_pipeline_trace_master_forked",
        run_dir=os.path.abspath(run_dir),
        spawned_pid=int(pid),
        owner_pid=int(owner_pid),
        max_workers=int(max_workers),
    )
    return {
        "ok": True,
        "spawned_pid": int(pid),
        "state_path": paths["state_path"],
        "socket_path": paths["socket_path"],
    }


def _stop_child_master(pid: int, child_info: Dict[str, object], logger: Logger, timeout_sec: float = 5.0) -> Dict[str, object]:
    result = {
        "pid": int(pid),
        "run_dir": child_info.get("run_dir"),
        "owner_pid": child_info.get("owner_pid"),
        "terminated": False,
        "killed": False,
        "status": None,
    }
    logger.info(
        "pipeline_trace_master_shutdown_begin",
        child_pid=int(pid),
        run_dir=child_info.get("run_dir"),
        owner_pid=child_info.get("owner_pid"),
    )
    try:
        record_process_kill(
            os.path.dirname(os.path.dirname(str(child_info.get("run_dir") or ""))) if child_info.get("run_dir") else "",
            int(pid),
            source="shared_mem.global_ast_master._stop_child_master",
            signal_name="SIGTERM",
            reason="global_ast_child_master_stop",
            run_dir=str(child_info.get("run_dir") or ""),
            extra={"owner_pid": child_info.get("owner_pid")},
        )
        os.kill(int(pid), signal.SIGTERM)
        result["terminated"] = True
    except Exception:
        pass
    deadline = time.time() + max(0.5, float(timeout_sec))
    while time.time() < deadline:
        try:
            waited_pid, status = os.waitpid(int(pid), os.WNOHANG)
        except ChildProcessError:
            waited_pid, status = int(pid), 0
        except Exception:
            waited_pid, status = 0, None
        if int(waited_pid or 0) == int(pid):
            result["status"] = int(status or 0)
            logger.info(
                "pipeline_trace_master_shutdown_done",
                child_pid=int(pid),
                run_dir=child_info.get("run_dir"),
                owner_pid=child_info.get("owner_pid"),
                status=int(status or 0),
                killed=False,
            )
            return result
        time.sleep(0.1)
    try:
        record_process_kill(
            os.path.dirname(os.path.dirname(str(child_info.get("run_dir") or ""))) if child_info.get("run_dir") else "",
            int(pid),
            source="shared_mem.global_ast_master._stop_child_master",
            signal_name="SIGKILL",
            reason="global_ast_child_master_stop_timeout",
            run_dir=str(child_info.get("run_dir") or ""),
            extra={"owner_pid": child_info.get("owner_pid")},
        )
        os.kill(int(pid), signal.SIGKILL)
        result["killed"] = True
        logger.warning(
            "pipeline_trace_master_shutdown_force_kill",
            child_pid=int(pid),
            run_dir=child_info.get("run_dir"),
            owner_pid=child_info.get("owner_pid"),
        )
    except Exception:
        pass
    try:
        waited_pid, status = os.waitpid(int(pid), 0)
    except ChildProcessError:
        waited_pid, status = int(pid), 0
    except Exception:
        waited_pid, status = 0, None
    if int(waited_pid or 0) == int(pid):
        result["status"] = int(status or 0)
    logger.info(
        "pipeline_trace_master_shutdown_done",
        child_pid=int(pid),
        run_dir=child_info.get("run_dir"),
        owner_pid=child_info.get("owner_pid"),
        status=int(result.get("status") or 0),
        killed=bool(result.get("killed")),
    )
    return result


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
    cur = load_global_ast_master_state(state_path=state_path)
    if not isinstance(cur, dict):
        cur = {}
    cur.update(updates or {})
    _write_json(state_path, cur)
    return cur


def _stop_flag_path(runtime_root: str) -> str:
    return os.path.join(os.path.abspath(runtime_root), "meta", "stop.flag")


def _load_shared_settings_from_path(config_path: Optional[str]) -> Dict[str, object]:
    raw = _read_json(config_path or "")
    obj = raw.get("symex_shared_memory") if isinstance(raw.get("symex_shared_memory"), dict) else {}
    return obj if isinstance(obj, dict) else {}


def should_enable_global_ast_master(*, config_path: Optional[str]) -> bool:
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


def _serve_loop(*, runtime_root: str, runtime_config_path: str, parent_pid: int) -> int:
    paths = global_ast_state_paths(runtime_root)
    os.makedirs(paths["shared_root"], exist_ok=True)
    os.makedirs(paths["ipc_dir"], exist_ok=True)
    os.makedirs(os.path.dirname(paths["state_path"]) or ".", exist_ok=True)
    logger = Logger(base_dir=paths["shared_root"], min_level="INFO", name="global_ast_master", also_console=False)
    state = {"stop": False}
    child_masters = {}

    def _set_stop(*_args):
        state["stop"] = True

    try:
        signal.signal(signal.SIGTERM, _set_stop)
        signal.signal(signal.SIGINT, _set_stop)
    except Exception:
        pass

    sock = None
    published_payloads = None
    try:
        ast_inputs = resolve_ast_inputs(runtime_root=runtime_root, runtime_config_path=runtime_config_path)
        nodes_path = str(ast_inputs.get("nodes_path") or "")
        rels_path = str(ast_inputs.get("rels_path") or "")
        _write_json(
            paths["state_path"],
            {
                "status": "starting",
                "phase": "preload_ast",
                "pid": int(os.getpid()),
                "parent_pid": int(parent_pid),
                "runtime_root": paths["runtime_root"],
                "socket_path": paths["socket_path"],
                "state_path": paths["state_path"],
                "nodes_path": nodes_path,
                "rels_path": rels_path,
                "started_at": int(time.time()),
            },
        )
        logger.info(
            "global_ast_master_starting",
            runtime_root=paths["runtime_root"],
            nodes_path=nodes_path,
            rels_path=rels_path,
        )
        preload_stats = _preload_ast_cache(nodes_path=nodes_path, rels_path=rels_path, logger=logger)
        if os.path.exists(paths["socket_path"]):
            try:
                os.remove(paths["socket_path"])
            except Exception:
                pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(paths["socket_path"])
        sock.listen(16)
        sock.settimeout(1.0)
        _write_json(paths["pid_path"], {"pid": int(os.getpid())})
        _write_json(
            paths["state_path"],
            {
                "status": "ready",
                "pid": int(os.getpid()),
                "parent_pid": int(parent_pid),
                "runtime_root": paths["runtime_root"],
                "socket_path": paths["socket_path"],
                "state_path": paths["state_path"],
                "header_path": "",
                "sources_path": "",
                "nodes_path": nodes_path,
                "rels_path": rels_path,
                "nodes_sidecar_path": "",
                "top_files_path": "",
                "parent_of_path": "",
                "children_of_path": "",
                "payload_encoding": "",
                "shared_payloads": {},
                "shared_payload_enabled": False,
                "shared_payload_backend": "fork_cache",
                "shared_payload_reason": "fork_inherited_ast_cache",
                "attach_request_count": 0,
                "release_request_count": 0,
                "active_attach_count": 0,
                "ast_preloaded": True,
                "ast_stats": preload_stats,
                "spawned_pipeline_trace_masters": [],
                "spawned_pipeline_trace_master_count": 0,
                "reaped_pipeline_trace_master_count": 0,
                "started_at": int(time.time()),
            },
        )
        os.environ["SYMEX_SHARED_MEMORY_ENABLED"] = "1"
        os.environ["SYMEX_SHARED_MODE"] = "master_worker"
        os.environ["SYMEX_RUNTIME_ROOT"] = paths["runtime_root"]
        os.environ["SYMEX_GLOBAL_AST_MASTER_SOCK"] = paths["socket_path"]
        os.environ["SYMEX_GLOBAL_AST_MASTER_STATE"] = paths["state_path"]
        logger.info(
            "global_ast_master_ready",
            pid=int(os.getpid()),
            parent_pid=int(parent_pid),
            socket_path=paths["socket_path"],
            state_path=paths["state_path"],
            nodes_path=nodes_path,
            rels_path=rels_path,
            share_strategy="fork_ast_cache",
        )
        while True:
            while True:
                try:
                    child_pid, status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                except Exception:
                    logger.exception("global_ast_master_waitpid_failed")
                    break
                if int(child_pid or 0) <= 0:
                    break
                child_info = child_masters.pop(int(child_pid), {})
                logger.info(
                    "pipeline_trace_master_reaped",
                    child_pid=int(child_pid),
                    run_dir=child_info.get("run_dir"),
                    owner_pid=child_info.get("owner_pid"),
                    status=int(status or 0),
                )
                cur = load_global_ast_master_state(state_path=paths["state_path"])
                reaped_count = int(cur.get("reaped_pipeline_trace_master_count") or 0) + 1
                _update_state_file(
                    paths["state_path"],
                    {
                        "spawned_pipeline_trace_masters": list(child_masters.values()),
                        "spawned_pipeline_trace_master_count": len(child_masters),
                        "reaped_pipeline_trace_master_count": reaped_count,
                        "last_reaped_pipeline_trace_master": {
                            "pid": int(child_pid),
                            "run_dir": child_info.get("run_dir"),
                            "owner_pid": child_info.get("owner_pid"),
                            "status": int(status or 0),
                            "reaped_at": int(time.time()),
                        },
                    },
                )
            if state.get("stop"):
                logger.info("global_ast_master_stop_signal")
                break
            if os.path.exists(_stop_flag_path(runtime_root)):
                logger.info("global_ast_master_stop_flag")
                break
            if int(parent_pid) > 0 and not _pid_alive(int(parent_pid)):
                logger.warning("global_ast_master_parent_gone", parent_pid=int(parent_pid))
                break
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except Exception:
                logger.exception("global_ast_master_accept_failed")
                continue
            try:
                data = conn.recv(16384)
                req = {}
                try:
                    req = json.loads((data or b"{}").decode("utf-8", errors="replace"))
                except Exception:
                    req = {}
                cmd = str(req.get("cmd") or "ping").strip() or "ping"
                if cmd == "spawn_pipeline_trace_master":
                    payload = _spawn_pipeline_trace_master_via_fork(
                        run_dir=str(req.get("run_dir") or ""),
                        trace_path=str(req.get("trace_path") or ""),
                        trace_index_path=str(req.get("trace_index_path") or ""),
                        owner_pid=int(req.get("owner_pid") or 0),
                        max_workers=int(req.get("max_workers") or 1),
                        global_ast_state_path=paths["state_path"],
                        logger=logger,
                        inherited_listener=sock,
                        inherited_conn=conn,
                    )
                    if payload.get("ok") is True:
                        child_info = {
                            "pid": int(payload.get("spawned_pid") or 0),
                            "run_dir": os.path.abspath(str(req.get("run_dir") or "")),
                            "trace_path": os.path.abspath(str(req.get("trace_path") or "")),
                            "trace_index_path": os.path.abspath(str(req.get("trace_index_path") or "")),
                            "owner_pid": int(req.get("owner_pid") or 0),
                            "max_workers": int(req.get("max_workers") or 1),
                            "started_at": int(time.time()),
                        }
                        child_masters[int(child_info["pid"])] = child_info
                        _update_state_file(
                            paths["state_path"],
                            {
                                "spawned_pipeline_trace_masters": list(child_masters.values()),
                                "spawned_pipeline_trace_master_count": len(child_masters),
                                "last_spawned_pipeline_trace_master": child_info,
                            },
                        )
                    payload["cmd"] = cmd
                elif cmd == "attach_ast_payloads":
                    cur = load_global_ast_master_state(state_path=paths["state_path"])
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
                    logger.info(
                        "global_ast_payload_attach_requested",
                        attach_request_count=int(attach_count),
                        shared_payload_enabled=False,
                    )
                    payload = {
                        "ok": True,
                        "cmd": cmd,
                        "pid": int(os.getpid()),
                        "attach_id": "%s-%d" % (str(os.getpid()), int(time.time() * 1000)),
                        "payload_encoding": "",
                        "shared_payload_enabled": False,
                        "shared_payload_backend": "fork_cache",
                        "shared_payloads": {},
                        "nodes_path": str(cur.get("nodes_path") or ""),
                        "rels_path": str(cur.get("rels_path") or ""),
                    }
                elif cmd == "release_ast_payloads":
                    cur = load_global_ast_master_state(state_path=paths["state_path"])
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
                    logger.info(
                        "global_ast_payload_release_requested",
                        release_request_count=int(release_count),
                        active_attach_count=int(active_attach_count),
                    )
                    payload = {
                        "ok": True,
                        "cmd": cmd,
                        "pid": int(os.getpid()),
                        "release_request_count": int(release_count),
                        "active_attach_count": int(active_attach_count),
                    }
                elif cmd == "shutdown":
                    logger.info("global_ast_master_shutdown_requested")
                    state["stop"] = True
                    payload = {
                        "ok": True,
                        "cmd": cmd,
                        "pid": int(os.getpid()),
                        "status": "shutting_down",
                    }
                else:
                    payload = load_global_ast_master_state(state_path=paths["state_path"])
                    payload["cmd"] = cmd
                    payload["ok"] = True
                conn.sendall(json.dumps(payload, ensure_ascii=False).encode("utf-8", errors="replace"))
            except Exception:
                logger.exception("global_ast_master_request_failed")
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        return 0
    except Exception:
        logger.exception("global_ast_master_failed")
        _write_json(
            paths["state_path"],
            {
                "status": "failed",
                "pid": int(os.getpid()),
                "parent_pid": int(parent_pid),
                "runtime_root": paths["runtime_root"],
                "socket_path": paths["socket_path"],
                "failed_at": int(time.time()),
                "error": traceback.format_exc(),
            },
        )
        return 1
    finally:
        shutdown_reaped = 0
        shutdown_force_killed = 0
        for child_pid in list(child_masters.keys()):
            child_info = child_masters.pop(int(child_pid), {})
            stop_result = _stop_child_master(int(child_pid), child_info, logger)
            shutdown_reaped += 1
            if bool(stop_result.get("killed")):
                shutdown_force_killed += 1
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
        try:
            close_published_payloads(published_payloads, logger=logger)
        except Exception:
            logger.exception("global_ast_master_shared_payload_close_failed")
        try:
            close_attached_payloads()
        except Exception:
            logger.exception("global_ast_master_attached_payload_close_failed")
        try:
            if os.path.exists(paths["socket_path"]):
                os.remove(paths["socket_path"])
        except Exception:
            pass
        try:
            cur = load_global_ast_master_state(state_path=paths["state_path"])
            cur["status"] = "stopped" if cur.get("status") != "failed" else cur.get("status")
            cur["stopped_at"] = int(time.time())
            cur["spawned_pipeline_trace_masters"] = list(child_masters.values())
            cur["spawned_pipeline_trace_master_count"] = len(child_masters)
            cur["shutdown_reaped_pipeline_trace_master_count"] = int(shutdown_reaped)
            cur["shutdown_force_killed_pipeline_trace_master_count"] = int(shutdown_force_killed)
            _write_json(paths["state_path"], cur)
        except Exception:
            pass
        logger.close()


def start_global_ast_master(*, runtime_root: str, runtime_config_path: str, shared_config_path: Optional[str], daemon_logger=None) -> Optional[dict]:
    if not should_enable_global_ast_master(config_path=shared_config_path):
        if daemon_logger is not None:
            daemon_logger(runtime_root, "global_ast_master_disabled")
        return None
    paths = global_ast_state_paths(runtime_root)
    existing_state = load_global_ast_master_state(state_path=paths["state_path"])
    existing_ping = ping_global_ast_master(paths["socket_path"], timeout_sec=1.0) if os.path.exists(paths["socket_path"]) else None
    if existing_state and str(existing_state.get("status") or "") == "ready" and isinstance(existing_ping, dict) and existing_ping.get("ok") is True:
        os.environ["SYMEX_SHARED_MEMORY_ENABLED"] = "1"
        os.environ["SYMEX_SHARED_MODE"] = "master_worker"
        os.environ["SYMEX_RUNTIME_ROOT"] = os.path.abspath(runtime_root)
        os.environ["SYMEX_GLOBAL_AST_MASTER_SOCK"] = paths["socket_path"]
        os.environ["SYMEX_GLOBAL_AST_MASTER_STATE"] = paths["state_path"]
        if daemon_logger is not None:
            daemon_logger(runtime_root, "global_ast_master_reused pid=%s socket=%s state=%s" % (str(existing_ping.get("pid") or existing_state.get("pid") or ""), paths["socket_path"], paths["state_path"]))
        return {
            "proc": None,
            "log_fp": None,
            "log_path": "",
            "socket_path": paths["socket_path"],
            "state_path": paths["state_path"],
        }
    os.makedirs(paths["shared_root"], exist_ok=True)
    log_path = os.path.join(paths["shared_root"], "master_stdout.log")
    fp = open(log_path, "a", encoding="utf-8", errors="replace")
    cmd = [
        sys.executable,
        os.path.abspath(__file__),
        "--serve",
        "--runtime-root",
        os.path.abspath(runtime_root),
        "--runtime-config",
        os.path.abspath(runtime_config_path),
        "--parent-pid",
        str(int(os.getpid())),
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=fp,
        stderr=fp,
        close_fds=True,
        start_new_session=True,
    )
    timeout_sec = _estimate_start_timeout_sec(runtime_root=runtime_root, runtime_config_path=runtime_config_path)
    deadline = time.time() + float(timeout_sec)
    state = {}
    last_rc = None
    while time.time() < deadline:
        state = load_global_ast_master_state(state_path=paths["state_path"])
        if state.get("status") == "ready" and os.path.exists(paths["socket_path"]):
            os.environ["SYMEX_SHARED_MEMORY_ENABLED"] = "1"
            os.environ["SYMEX_SHARED_MODE"] = "master_worker"
            os.environ["SYMEX_RUNTIME_ROOT"] = os.path.abspath(runtime_root)
            os.environ["SYMEX_GLOBAL_AST_MASTER_SOCK"] = paths["socket_path"]
            os.environ["SYMEX_GLOBAL_AST_MASTER_STATE"] = paths["state_path"]
            if daemon_logger is not None:
                daemon_logger(
                    runtime_root,
                    "global_ast_master_started pid=%s socket=%s state=%s"
                    % (str(proc.pid), paths["socket_path"], paths["state_path"]),
                )
            return {
                "proc": proc,
                "log_fp": fp,
                "log_path": log_path,
                "socket_path": paths["socket_path"],
                "state_path": paths["state_path"],
            }
        if state.get("status") == "failed":
            break
        rc = proc.poll()
        if rc is not None:
            last_rc = int(rc)
            break
        time.sleep(0.2)
    failure_reason = "startup_timeout"
    if isinstance(state, dict) and state.get("status") == "failed":
        failure_reason = "state_failed"
    elif last_rc is not None:
        failure_reason = "process_exit"
    failure_path = _write_start_failure(
        paths,
        {
            "status": "failed",
            "reason": str(failure_reason),
            "runtime_root": paths["runtime_root"],
            "socket_path": paths["socket_path"],
            "state_path": paths["state_path"],
            "log_path": log_path,
            "pid": int(proc.pid),
            "exit_code": last_rc,
            "timeout_sec": float(timeout_sec),
            "failed_at": int(time.time()),
            "state": state if isinstance(state, dict) else {},
        },
    )
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
    try:
        fp.close()
    except Exception:
        pass
    if daemon_logger is not None:
        daemon_logger(
            runtime_root,
            "global_ast_master_start_failed reason=%s state=%s failure_path=%s log=%s"
            % (
                str(failure_reason),
                json.dumps(state or {}, ensure_ascii=False),
                str(failure_path or ""),
                str(log_path),
            ),
        )
    return None


def stop_global_ast_master(handle: Optional[dict], *, runtime_root: str, daemon_logger=None) -> None:
    if not handle:
        return
    proc = handle.get("proc")
    fp = handle.get("log_fp")
    socket_path = str(handle.get("socket_path") or "").strip()
    shutdown_requested = False
    if socket_path:
        try:
            shutdown_global_ast_master(socket_path, timeout_sec=2.0)
            shutdown_requested = True
            if daemon_logger is not None:
                daemon_logger(runtime_root, "global_ast_master_shutdown_requested socket=%s" % socket_path)
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
                proc.terminate()
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
    try:
        if fp is not None:
            fp.close()
    except Exception:
        pass
    for key in ("SYMEX_GLOBAL_AST_MASTER_SOCK", "SYMEX_GLOBAL_AST_MASTER_STATE"):
        try:
            os.environ.pop(key, None)
        except Exception:
            pass
    if daemon_logger is not None:
        daemon_logger(runtime_root, "global_ast_master_stopped")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--runtime-root", required=True)
    ap.add_argument("--runtime-config", required=True)
    ap.add_argument("--parent-pid", type=int, default=0)
    args = ap.parse_args()
    if not args.serve:
        return 1
    return _serve_loop(
        runtime_root=os.path.abspath(args.runtime_root),
        runtime_config_path=os.path.abspath(args.runtime_config),
        parent_pid=int(args.parent_pid or 0),
    )


if __name__ == "__main__":
    raise SystemExit(main())
