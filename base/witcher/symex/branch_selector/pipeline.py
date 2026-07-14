"""
Run the branch-selection pipeline: build prompt sections from trace traces, ask an LLM to pick branches,
and trigger per-seq analysis runs.
"""

import asyncio
import contextlib
import json
import os
import random
import signal
import sys
import shutil
import threading
import time
import traceback
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from dataclasses import replace
except Exception:
    from compat_dataclasses import replace

from common.logger import Logger
from common.app_config import append_app_name_to_prompt, get_app_name, load_app_config, load_symex_app_config

from llm_utils import get_default_client
from llm_utils.taint.taint_llm_calls import LLMCallFailure, chat_text_with_retries, write_llm_failure_artifact

from branch_selector.core.buffer import PromptBuffer
from branch_selector.core.config import load_config
from branch_selector.core.scope_folding import ScopeSubsetFolder
from branch_selector.prompt.llm_response import extract_llm_json_text, parse_llm_response, llm_response_has_valid_json
from branch_selector.prompt.prompt_builder import build_prompt, format_section
from branch_selector.prompt.sql_prompt_builder import build_prompt as build_sql_prompt, format_section as format_sql_section
from branch_selector.prompt.xss_prompt_builder import build_prompt as build_xss_prompt, format_section as format_xss_section
from branch_selector.prompt.cmd_prompt_builder import build_prompt as build_cmd_prompt, format_section as format_cmd_section
from branch_selector.trace.combined_sections import iter_combined_sections
from branch_selector.trace.if_scope_expand import _expand_one_seq, _precompute_expand_indices
from branch_selector.sim.test_simulator import simulate_response, write_prompt_text, write_response_json
from branch_selector.trace.trace_extract import (
    build_loc_for_seq,
    build_seq_to_index,
    iter_if_switch_records,
    ensure_trace_index,
    load_nodes_and_edges,
)
from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
from if_branch_coverage import check_if_branch_coverage, reload_if_branch_coverage
from if_branch_coverage.switch_coverage import check_switch_branch_coverage, reload_switch_branch_coverage
from utils.cpg_utils.graph_mapping import safe_int, norm_nodes_path
from if_branch_coverage.if_scope import get_if_file_path
from utils.extractors.if_extract import collect_if_ids_for_record, collect_switch_ids_for_record


def _create_task(coro):
    ct = getattr(asyncio, "create_task", None)
    if ct is not None:
        return ct(coro)
    return asyncio.ensure_future(coro)


def _get_running_loop():
    grl = getattr(asyncio, "get_running_loop", None)
    if grl is not None:
        return grl()
    return asyncio.get_event_loop()


def _asyncio_run(coro):
    runner = getattr(asyncio, "run", None)
    if runner is not None:
        return runner(coro)
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(coro)


def _token_pool_dir() -> str:
    v = os.environ.get("WC_TOKEN_POOL_DIR") or ""
    return v.strip()


def _token_release_marker_path() -> str:
    v = os.environ.get("WC_TOKEN_RELEASE_MARKER") or ""
    return v.strip()


def _mark_self_token_released() -> None:
    marker = _token_release_marker_path()
    if not marker:
        return
    try:
        os.makedirs(os.path.dirname(os.path.abspath(marker)) or ".", exist_ok=True)
        with open(marker, "w", encoding="utf-8") as f:
            json.dump({"pid": int(os.getpid()), "released_at": int(time.time())}, f, ensure_ascii=False, indent=2)
    except Exception:
        return


def _update_pipeline_trace_master_fallback_state(*, seq: int, reason: str) -> None:
    state_path = (os.environ.get("SYMEX_PIPELINE_TRACE_MASTER_STATE") or "").strip()
    if not state_path:
        return
    try:
        with open(state_path, "r", encoding="utf-8", errors="replace") as f:
            cur = json.load(f)
    except Exception:
        cur = {}
    if not isinstance(cur, dict):
        cur = {}
    cur["fallback_spawn_count"] = int(cur.get("fallback_spawn_count") or 0) + 1
    cur["last_fallback"] = {
        "seq": int(seq),
        "reason": str(reason or ""),
        "updated_at": int(time.time()),
    }
    tmp = state_path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False, indent=2)
        os.replace(tmp, state_path)
    except Exception:
        pass


def _release_self_token() -> None:
    pool_dir = _token_pool_dir()
    kind = os.environ.get("WC_TOKEN_KIND") or ""
    if not pool_dir or not kind:
        return
    try:
        from hybrid_io.token_pool import release
    except Exception:
        return
    try:
        ok = release(pool_dir, kind=str(kind))
    except Exception:
        return
    if bool(ok):
        _mark_self_token_released()


def _read_json(path: str):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            import json
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _heartbeat_ts() -> str:
    t = time.time()
    lt = time.localtime(t)
    ms = int((t - int(t)) * 1000)
    return time.strftime("%Y-%m-%d %H:%M:%S", lt) + f".{ms:03d}"


def _atomic_write_text(path: str, text: str) -> None:
    out_path = os.path.abspath(path or "")
    if not out_path:
        return
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(text or "")
    os.replace(tmp_path, out_path)


def _atomic_write_json(path: str, obj: Dict[str, object]) -> None:
    try:
        txt = json.dumps(obj or {}, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        txt = "{}"
    _atomic_write_text(path, txt)


def _write_branch_selector_process_exit(
    *,
    run_dir: str,
    status: str,
    stage: str,
    message: str = "",
    error_type: str = "",
    traceback_text: str = "",
    extra: Optional[Dict[str, object]] = None,
) -> None:
    return


class BranchSelectorHeartbeat:
    def __init__(self, *, run_dir: str, interval_seconds: int = 10):
        self.run_dir = os.path.abspath(run_dir or os.getcwd())
        self.meta_dir = os.path.join(self.run_dir, "meta")
        self.status_path = os.path.join(self.meta_dir, "branch_selector.heartbeat.status.json")
        self.interval_seconds = max(1, int(interval_seconds))
        self.pid = int(os.getpid())
        self.parent_pid = int(os.getppid())
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._state: Dict[str, object] = {
            "pid": int(self.pid),
            "parent_pid": int(self.parent_pid),
            "run_dir": self.run_dir,
            "status": "starting",
            "stage": "starting",
            "message": "",
            "tick": 0,
            "started_at": _heartbeat_ts(),
            "updated_at": _heartbeat_ts(),
            "finished_at": "",
            "seed_hash8": str(os.environ.get("WC_PARENT_SEED_HASH8") or ""),
            "token_kind": str(os.environ.get("WC_TOKEN_KIND") or ""),
        }

    def start(self) -> None:
        os.makedirs(self.meta_dir, exist_ok=True)
        self._write_snapshot(force_log=True)
        self._thread = threading.Thread(target=self._run, name="branch-selector-heartbeat", daemon=True)
        self._thread.start()

    def update(self, stage: str, *, status: Optional[str] = None, message: str = "", force_log: bool = True, **extra) -> None:
        with self._lock:
            self._state["stage"] = str(stage or "").strip() or str(self._state.get("stage") or "running")
            if status:
                self._state["status"] = str(status).strip()
            if message:
                self._state["message"] = str(message)
            self._state["updated_at"] = _heartbeat_ts()
            for k, v in (extra or {}).items():
                self._state[str(k)] = v
        self._write_snapshot(force_log=force_log)

    def finish(self, status: str, *, stage: str = "finished", message: str = "", **extra) -> None:
        with self._lock:
            self._state["status"] = str(status or "finished").strip() or "finished"
            self._state["stage"] = str(stage or "finished").strip() or "finished"
            if message:
                self._state["message"] = str(message)
            self._state["updated_at"] = _heartbeat_ts()
            self._state["finished_at"] = self._state["updated_at"]
            for k, v in (extra or {}).items():
                self._state[str(k)] = v
        self._write_snapshot(force_log=True)
        self._stop.set()
        th = self._thread
        if th is not None and th.is_alive():
            th.join(timeout=1.0)

    def _snapshot(self) -> Dict[str, object]:
        with self._lock:
            return dict(self._state)

    def _write_snapshot(self, *, force_log: bool) -> None:
        snap = self._snapshot()
        try:
            _atomic_write_json(self.status_path, snap)
        except Exception:
            pass

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            with self._lock:
                self._state["tick"] = int(self._state.get("tick") or 0) + 1
                self._state["updated_at"] = _heartbeat_ts()
            self._write_snapshot(force_log=True)


def _shared_restart_limit(cfg) -> int:
    raw = cfg.raw if hasattr(cfg, "raw") else {}
    sm = raw.get("symex_shared_memory") if isinstance(raw, dict) and isinstance(raw.get("symex_shared_memory"), dict) else {}
    try:
        return max(1, int(sm.get("restart_max_attempts") or 3))
    except Exception:
        return 3


def _pipeline_restart_request_path() -> str:
    run_dir = str(os.environ.get("SYMEX_PIPELINE_RUN_DIR") or os.getcwd() or "").strip()
    return os.path.join(os.path.abspath(run_dir), "meta", "pipeline_trace_master.restart.request")


def _clear_pipeline_restart_request() -> None:
    path = _pipeline_restart_request_path()
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception:
        return


def _pipeline_trace_master_unhealthy() -> bool:
    socket_path = (os.environ.get("SYMEX_PIPELINE_TRACE_MASTER_SOCK") or "").strip()
    if not socket_path or not os.path.exists(socket_path):
        return True
    try:
        from shared_mem.trace_store import ping_pipeline_trace_master
        ping = ping_pipeline_trace_master(socket_path, timeout_sec=1.0)
    except Exception:
        return True
    return not (isinstance(ping, dict) and ping.get("ok") is True)


def _request_pipeline_trace_master_restart(reason: str, logger: Optional[Logger] = None) -> None:
    path = _pipeline_restart_request_path()
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "kind": "pipeline_trace_master",
                    "reason": str(reason or ""),
                    "requested_at": int(time.time()),
                    "requester_pid": int(os.getpid()),
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        if logger is not None:
            logger.warning("pipeline_trace_master_restart_requested", reason=str(reason or ""), request_path=path)
    except Exception:
        if logger is not None:
            logger.exception("pipeline_trace_master_restart_request_failed")


def _restart_pipeline_trace_master_with_retry(*, cfg, trace_path: str, trace_index_path: str, max_workers: int, logger: Logger, current_handle, max_attempts: int, restart_reason: str = ""):
    try:
        from shared_mem.pipeline_trace_master import start_pipeline_trace_master, stop_pipeline_trace_master
    except Exception as exc:
        raise RuntimeError("pipeline trace master module unavailable: %s" % str(exc))
    handle = current_handle
    for attempt in range(1, max(1, int(max_attempts)) + 1):
        logger.warning("pipeline_trace_master_restart_attempt", attempt=int(attempt))
        try:
            if handle is not None:
                stop_pipeline_trace_master(
                    handle,
                    logger=logger,
                    caller="branch_selector.pipeline._restart_pipeline_trace_master_with_retry",
                    reason=("restart:%s" % str(restart_reason or "unspecified")),
                    extra={"attempt": int(attempt)},
                )
        except Exception:
            logger.exception("pipeline_trace_master_restart_stop_failed")
        handle = start_pipeline_trace_master(
            run_dir=os.getcwd(),
            trace_path=trace_path,
            trace_index_path=trace_index_path,
            shared_config_path=cfg.config_path,
            max_workers=int(max_workers),
            allow_local_fallback=True,
            logger=logger,
        )
        if handle is not None:
            logger.info("pipeline_trace_master_restart_ok", attempt=int(attempt))
            _clear_pipeline_restart_request()
            return handle
        time.sleep(1.0)
    raise RuntimeError("pipeline trace master restart failed after %d attempts" % int(max_attempts))


async def _wait_pipeline_trace_master_ready(*, timeout_sec: float, logger: Optional[Logger] = None) -> bool:
    deadline = time.time() + max(1.0, float(timeout_sec))
    while time.time() < deadline:
        if not _pipeline_trace_master_unhealthy():
            return True
        await asyncio.sleep(0.5)
    if logger is not None:
        logger.warning("pipeline_trace_master_wait_ready_timeout", timeout_sec=float(timeout_sec))
    return False


def _collect_analyze_artifacts(*, run_root: str, seq: int) -> Dict[str, object]:
    seq_root = os.path.join(os.path.abspath(run_root), "test", "seqs", "seq_%d" % int(seq))
    logs_dir = os.path.join(seq_root, "logs")
    heartbeat_status_path = os.path.join(logs_dir, "heartbeat.status.json")
    analysis_output_path = os.path.join(seq_root, "analysis_output_%d.json" % int(seq))
    exit_record_path = os.path.join(logs_dir, "exit_record.ndjson")
    exit_debug_path = os.path.join(logs_dir, "exit_debug.ndjson")
    payload: Dict[str, object] = {
        "seq_root": seq_root,
        "seq_root_exists": bool(os.path.isdir(seq_root)),
        "logs_dir": logs_dir,
        "logs_dir_exists": bool(os.path.isdir(logs_dir)),
        "heartbeat_status_path": heartbeat_status_path,
        "heartbeat_status_exists": bool(os.path.exists(heartbeat_status_path)),
        "analysis_output_path": analysis_output_path,
        "analysis_output_exists": bool(os.path.exists(analysis_output_path)),
        "exit_record_path": exit_record_path,
        "exit_record_exists": bool(os.path.exists(exit_record_path)),
        "exit_debug_path": exit_debug_path,
        "exit_debug_exists": bool(os.path.exists(exit_debug_path)),
    }
    if os.path.exists(heartbeat_status_path):
        try:
            with open(heartbeat_status_path, "r", encoding="utf-8", errors="replace") as f:
                hb = json.load(f)
            if isinstance(hb, dict):
                payload["heartbeat_status"] = str(hb.get("status") or "")
                payload["heartbeat_stage"] = str(hb.get("stage") or "")
                payload["heartbeat_updated_at"] = str(hb.get("updated_at") or "")
                payload["heartbeat_pid"] = int(hb.get("pid") or 0) if hb.get("pid") is not None else 0
        except Exception:
            pass
        try:
            payload["heartbeat_mtime"] = float(os.path.getmtime(heartbeat_status_path))
        except Exception:
            pass
    if os.path.exists(exit_record_path):
        try:
            payload["exit_record_mtime"] = float(os.path.getmtime(exit_record_path))
        except Exception:
            pass
    if os.path.exists(exit_debug_path):
        try:
            payload["exit_debug_mtime"] = float(os.path.getmtime(exit_debug_path))
        except Exception:
            pass
    return payload


def _heartbeat_is_fresh(artifact_info: Optional[Dict[str, object]], *, stale_after_sec: float = 25.0) -> bool:
    if not isinstance(artifact_info, dict):
        return False
    if not bool(artifact_info.get("heartbeat_status_exists")):
        return False
    try:
        mtime = float(artifact_info.get("heartbeat_mtime") or 0.0)
    except Exception:
        return False
    if mtime <= 0.0:
        return False
    return (time.time() - mtime) <= max(1.0, float(stale_after_sec))


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


def _probe_analyze_liveness(
    *,
    run_root: str,
    seq: int,
    socket_path: str = "",
    stale_after_sec: float = 25.0,
) -> Dict[str, object]:
    artifact_info = _collect_analyze_artifacts(run_root=run_root, seq=int(seq))
    now = time.time()
    heartbeat_age_sec = None
    try:
        mtime = float(artifact_info.get("heartbeat_mtime") or 0.0)
        if mtime > 0.0:
            heartbeat_age_sec = max(0.0, now - mtime)
    except Exception:
        heartbeat_age_sec = None
    heartbeat_pid_alive = _pid_alive(int(artifact_info.get("heartbeat_pid") or 0))
    master_state = {}
    master_ping = None
    try:
        from shared_mem.trace_store import load_pipeline_trace_master_state, ping_pipeline_trace_master
        state_path = str(os.environ.get("SYMEX_PIPELINE_TRACE_MASTER_STATE") or "").strip()
        if state_path:
            master_state = load_pipeline_trace_master_state(state_path=state_path)
        elif run_root:
            master_state = load_pipeline_trace_master_state(run_dir=os.path.abspath(run_root))
        if socket_path:
            master_ping = ping_pipeline_trace_master(socket_path, timeout_sec=1.0)
    except Exception:
        master_state = {}
        master_ping = None
    master_ping_ok = bool(isinstance(master_ping, dict) and master_ping.get("ok") is True)
    heartbeat_fresh = _heartbeat_is_fresh(artifact_info, stale_after_sec=stale_after_sec)
    inferred_status = "unknown"
    inferred_cause = "unknown"
    if bool(artifact_info.get("analysis_output_exists")):
        inferred_status = "completed"
        inferred_cause = "analysis_output_present"
    elif bool(artifact_info.get("heartbeat_status_exists")) and heartbeat_pid_alive is False and heartbeat_fresh:
        inferred_status = "dead"
        inferred_cause = "heartbeat_recent_but_pid_dead"
    elif bool(artifact_info.get("heartbeat_status_exists")) and heartbeat_pid_alive is False:
        inferred_status = "dead"
        inferred_cause = "heartbeat_stopped_and_pid_dead"
    elif heartbeat_fresh and heartbeat_pid_alive is True:
        inferred_status = "alive"
        inferred_cause = "fresh_heartbeat_and_pid_alive"
    elif heartbeat_fresh:
        inferred_status = "alive"
        inferred_cause = "fresh_heartbeat"
    elif bool(artifact_info.get("heartbeat_status_exists")) and master_ping_ok:
        inferred_status = "stalled"
        inferred_cause = "heartbeat_stale_while_master_alive"
    elif not bool(artifact_info.get("heartbeat_status_exists")) and not master_ping_ok:
        inferred_status = "dead"
        inferred_cause = "no_heartbeat_and_master_unreachable"
    elif not bool(artifact_info.get("heartbeat_status_exists")):
        inferred_status = "unknown"
        inferred_cause = "no_heartbeat"
    elif heartbeat_pid_alive is True:
        inferred_status = "stalled"
        inferred_cause = "pid_alive_but_heartbeat_stale"
    out: Dict[str, object] = {
        "seq": int(seq),
        "heartbeat_fresh": bool(heartbeat_fresh),
        "heartbeat_age_sec": heartbeat_age_sec,
        "heartbeat_pid_alive": heartbeat_pid_alive,
        "master_ping_ok": bool(master_ping_ok),
        "master_socket_path": str(socket_path or ""),
        "master_state_status": str(master_state.get("status") or "") if isinstance(master_state, dict) else "",
        "master_inflight_jobs": int(master_state.get("inflight_jobs") or 0) if isinstance(master_state, dict) else 0,
        "master_last_job": (master_state.get("last_job") if isinstance(master_state.get("last_job"), dict) else {}),
        "inferred_status": inferred_status,
        "inferred_cause": inferred_cause,
        "artifacts": artifact_info,
    }
    return out


async def _wait_for_live_heartbeat_or_output(
    *,
    run_root: str,
    seq: int,
    wait_sec: float = 5.0,
    stale_after_sec: float = 25.0,
) -> Dict[str, object]:
    deadline = time.time() + max(0.5, float(wait_sec))
    last = _collect_analyze_artifacts(run_root=run_root, seq=int(seq))
    while time.time() < deadline:
        last = _collect_analyze_artifacts(run_root=run_root, seq=int(seq))
        if bool(last.get("analysis_output_exists")):
            return last
        if _heartbeat_is_fresh(last, stale_after_sec=stale_after_sec):
            return last
        await asyncio.sleep(0.5)
    return _collect_analyze_artifacts(run_root=run_root, seq=int(seq))


def _signal_name_from_return_code(rc: Optional[int]) -> str:
    if rc is None:
        return ""
    try:
        rc_i = int(rc)
    except Exception:
        return ""
    if rc_i >= 0:
        return ""
    sig_num = abs(int(rc_i))
    try:
        return signal.Signals(sig_num).name
    except Exception:
        return "SIG%d" % int(sig_num)


def _write_parent_exit_observation(
    *,
    run_root: str,
    seq: int,
    phase: str,
    rc: Optional[int],
    artifact_info: Optional[Dict[str, object]] = None,
    note: str = "",
    inference: Optional[Dict[str, object]] = None,
    child_pid: Optional[int] = None,
    child_alive: Optional[bool] = None,
    child_status: str = "",
) -> None:
    seq_root = os.path.join(os.path.abspath(run_root), "test", "seqs", "seq_%d" % int(seq))
    logs_dir = os.path.join(seq_root, "logs")
    path = os.path.join(logs_dir, "parent_exit_observation.ndjson")
    try:
        os.makedirs(logs_dir, exist_ok=True)
    except Exception:
        pass
    payload: Dict[str, object] = {
        "ts": int(time.time()),
        "phase": str(phase or ""),
        "seq": int(seq),
        "pid": int(os.getpid()),
        "ppid": int(os.getppid()),
        "rc": (int(rc) if rc is not None else None),
        "signal_name": _signal_name_from_return_code(rc),
        "note": str(note or ""),
        "artifact_info": (artifact_info if isinstance(artifact_info, dict) else {}),
        "inference": (inference if isinstance(inference, dict) else {}),
        "child_pid": (int(child_pid) if child_pid is not None else None),
        "child_alive": child_alive,
        "child_status": str(child_status or ""),
    }
    try:
        with open(path, "a", encoding="utf-8", errors="replace") as f:
            f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception:
        return


async def _monitor_analyze_process(*, run_root: str, seq: int, proc, poll_sec: float = 0.5) -> None:
    child_pid = None
    try:
        child_pid = int(getattr(proc, "pid", 0) or 0)
    except Exception:
        child_pid = None
    if not child_pid:
        return
    last_alive = None
    while True:
        rc = proc.returncode
        if rc is None:
            try:
                rc = proc.returncode if proc.returncode is not None else proc._transport.get_returncode()  # type: ignore[attr-defined]
            except Exception:
                rc = None
        alive = (rc is None)
        if last_alive is None or bool(alive) != bool(last_alive):
            _write_parent_exit_observation(
                run_root=run_root,
                seq=int(seq),
                phase=("process_monitor_alive" if alive else "process_monitor_exit"),
                rc=(int(rc) if rc is not None else None),
                artifact_info=_collect_analyze_artifacts(run_root=run_root, seq=int(seq)),
                note=("monitor sampled child process state"),
                inference=_probe_analyze_liveness(run_root=run_root, seq=int(seq), stale_after_sec=25.0),
                child_pid=int(child_pid),
                child_alive=bool(alive),
                child_status=("alive" if alive else "exited"),
            )
            last_alive = bool(alive)
        if rc is not None:
            break
        await asyncio.sleep(max(0.1, float(poll_sec)))


async def _wait_for_analyze_startup(*, run_root: str, seq: int, proc, timeout_sec: float = 3.0) -> Tuple[bool, Dict[str, object], Optional[int]]:
    deadline = time.time() + max(0.5, float(timeout_sec))
    last = _collect_analyze_artifacts(run_root=run_root, seq=int(seq))
    while time.time() < deadline:
        rc = proc.returncode
        if rc is None:
            try:
                rc = proc.returncode if proc.returncode is not None else proc._transport.get_returncode()  # type: ignore[attr-defined]
            except Exception:
                rc = None
        last = _collect_analyze_artifacts(run_root=run_root, seq=int(seq))
        if bool(last.get("heartbeat_status_exists")) or bool(last.get("analysis_output_exists")):
            return True, last, rc
        if rc is not None:
            return False, last, int(rc)
        await asyncio.sleep(0.2)
    last = _collect_analyze_artifacts(run_root=run_root, seq=int(seq))
    rc = proc.returncode
    return bool(last.get("heartbeat_status_exists")) or bool(last.get("analysis_output_exists")), last, (int(rc) if rc is not None else None)


def _parse_emit_seqs_arg(argv: List[str]) -> Optional[str]:
    if not argv:
        return None
    for i, x in enumerate(argv):
        if x == "--emit-seqs" and (i + 1) < len(argv):
            v = argv[i + 1]
            return v.strip() if isinstance(v, str) else None
        if isinstance(x, str) and x.startswith("--emit-seqs="):
            return (x.split("=", 1)[1] or "").strip()
    return None


def _is_third_party_path(path: str) -> bool:
    s = (path or "").replace("\\", "/").lower()
    if not s:
        return False
    if s.startswith("vendor/") or s.startswith("/vendor/"):
        return True
    if s.startswith("node_modules/") or s.startswith("/node_modules/"):
        return True
    if "/vendor/" in s:
        return True
    if "/node_modules/" in s:
        return True
    return False


def _item_is_third_party(item: dict) -> bool:
    if not isinstance(item, dict):
        return False
    lines = item.get("lines") or []
    if not isinstance(lines, list):
        return False
    for it in lines:
        if not isinstance(it, dict):
            continue
        p = it.get("path")
        if isinstance(p, str) and _is_third_party_path(p):
            return True
    return False


def _safe_rmtree(p: str) -> None:
    if not p:
        return
    if not os.path.exists(p):
        return
    try:
        shutil.rmtree(p)
    except Exception:
        return


def _sanitize_debug_name(name: str) -> str:
    raw = str(name or "").strip()
    if not raw:
        raw = "prompt"
    out = []
    for ch in raw:
        if ch.isalnum() or ch in ("_", "-"):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out).strip("_") or "prompt"


def _count_grouped_seqs(resp_groups: Optional[List[List[int]]]) -> Tuple[int, int]:
    if not isinstance(resp_groups, list):
        return 0, 0
    group_count = 0
    seq_count = 0
    for group in resp_groups or []:
        if not isinstance(group, list):
            continue
        group_count += 1
        seq_count += sum(1 for item in group if isinstance(item, int))
    return int(group_count), int(seq_count)


def _write_flush_debug_state(
    *,
    logger: Optional[Logger],
    prompt_prefix: str,
    prompt_index: int,
    phase: str,
    extra: Optional[Dict[str, object]] = None,
) -> None:
    return


def _clear_branch_selector_logs(base_dir: str) -> None:
    _safe_rmtree(os.path.join(base_dir, "branch_selector", "logs"))


def _clear_branch_selector_dir(base_dir: str) -> None:
    _safe_rmtree(os.path.join(base_dir, "branch_selector"))


def _clear_seq_dirs(base_dir: str) -> None:
    if not os.path.isdir(base_dir):
        return
    seq_root = os.path.join(base_dir, "seqs")
    root = seq_root if os.path.isdir(seq_root) else base_dir
    for name in os.listdir(root):
        if not name.startswith("seq_"):
            continue
        seq_dir = os.path.join(root, name)
        if not os.path.isdir(seq_dir):
            continue
        _safe_rmtree(seq_dir)


def _collect_if_ids_in_record(record: dict, nodes: Dict, parent_of: Dict[int, int], top_id_to_file: Dict) -> List[int]:
    out: Set[int] = set()
    for nid in (record or {}).get("node_ids") or []:
        ni = safe_int(nid)
        if ni is None:
            continue
        tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
        if tt == "AST_IF":
            out.add(int(ni))
            continue
        if tt in ("AST_IF_ELEM", "AST_ELSEIF"):
            cur = parent_of.get(int(ni))
            steps = 0
            while cur is not None and steps < 12:
                ct = ((nodes.get(int(cur)) or {}).get("type") or "").strip()
                if ct == "AST_IF":
                    out.add(int(cur))
                    break
                cur = parent_of.get(int(cur))
                steps += 1
    return sorted(out)


def _collect_switch_ids_in_record(record: dict, nodes: Dict, parent_of: Dict[int, int], top_id_to_file: Dict) -> List[int]:
    out: Set[int] = set()
    for nid in (record or {}).get("node_ids") or []:
        ni = safe_int(nid)
        if ni is None:
            continue
        tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
        if tt == "AST_SWITCH":
            out.add(int(ni))
    return sorted(out)


def _load_if_branch_cache_ids(cache_path: Optional[str]) -> Set[str]:
    if not cache_path or not os.path.exists(cache_path):
        return set()
    try:
        with open(cache_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return set()
    if not isinstance(obj, dict):
        return set()
    out: Set[str] = set()
    for k in obj.keys():
        try:
            ks = str(k)
        except Exception:
            continue
        out.add(ks)
    return out


# Summary: Yield per-seq prompt sections by expanding/merging trace-derived IF/SWITCH neighborhoods.
def _iter_if_switch_sections(
    *,
    trace_index_records: List[dict],
    nodes: Dict,
    parent_of: Dict,
    children_of: Dict,
    top_id_to_file: Dict,
    seq_limit: int,
    scope_root: str,
    trace_index_path: str,
    windows_root: str,
    nearest_seq_count: int,
    farthest_seq_count: int,
    trace_path: str,
    if_branch_cache_path: Optional[str] = None,
    if_branch_cache_skip: bool = False,
    expand_workers: Optional[int] = None,
    logger: Optional[Logger] = None,
) -> Iterable[dict]:
    seq_to_index = build_seq_to_index(trace_index_records)
    cached_if_keys = _load_if_branch_cache_ids(if_branch_cache_path) if if_branch_cache_skip else set()
    if_cov_cache: Dict[int, bool] = {}
    switch_cov_cache: Dict[int, Dict[int, bool]] = {}
    if_cached_seq_count = 0
    if_cached_hit_count = 0
    if_cached_skip_count = 0
    if_cached_last_seq = None
    switch_cached_seq_count = 0
    switch_cached_hit_count = 0
    switch_cached_skip_count = 0
    switch_cached_last_seq = None
    indices = _precompute_expand_indices(trace_index_records, nodes)

    def _get_if_covered(if_id: int) -> Tuple[bool, bool]:
        if int(if_id) in if_cov_cache:
            return bool(if_cov_cache[int(if_id)]), True
        covered = check_if_branch_coverage(int(if_id))
        if_cov_cache[int(if_id)] = bool(covered)
        return bool(covered), False

    def _get_switch_cov(switch_id: int) -> Tuple[Dict[int, bool], bool]:
        if int(switch_id) in switch_cov_cache:
            return switch_cov_cache[int(switch_id)], True
        cov_map = check_switch_branch_coverage(int(switch_id))
        switch_cov_cache[int(switch_id)] = cov_map
        return cov_map, False

    processed = 0
    for seq, rec in iter_if_switch_records(
        trace_index_records=trace_index_records,
        nodes=nodes,
        parent_of=parent_of,
        top_id_to_file=top_id_to_file,
        seq_limit=seq_limit,
        logger=logger,
    ):
        processed += 1
        if_ids = _collect_if_ids_in_record(rec, nodes, parent_of, top_id_to_file)
        switch_ids = _collect_switch_ids_in_record(rec, nodes, parent_of, top_id_to_file)
        skip_due_to_if = False
        skip_due_to_switch = False
        def _if_key(iid: int) -> Optional[str]:
            nx = nodes.get(int(iid)) or {}
            ln = nx.get("lineno")
            fp = get_if_file_path(int(iid), parent_of, nodes, top_id_to_file)
            if fp and ln is not None:
                return f"{norm_nodes_path(fp)}:{int(ln)}"
            return None
        if if_branch_cache_skip and if_ids:
            hit_ids = []
            for x in if_ids:
                k = _if_key(int(x))
                if k and k in cached_if_keys:
                    hit_ids.append(int(x))
            if hit_ids:
                continue
        if if_ids:
            miss_ids = []
            covered_map: Dict[int, bool] = {}
            for if_id in if_ids:
                covered, hit = _get_if_covered(int(if_id))
                covered_map[int(if_id)] = bool(covered)
                if hit:
                    if_cached_hit_count += 1
                else:
                    miss_ids.append(int(if_id))
            all_covered = True
            for if_id in if_ids:
                covered = covered_map.get(int(if_id))
                if not bool(covered):
                    all_covered = False
            if all_covered:
                skip_due_to_if = True
            if not miss_ids:
                if_cached_seq_count += 1
                if_cached_last_seq = int(seq)
                if skip_due_to_if:
                    if_cached_skip_count += 1
        if switch_ids:
            miss_switch_ids = []
            cov_map_by_id: Dict[int, Dict[int, bool]] = {}
            for switch_id in switch_ids:
                cov_map, hit = _get_switch_cov(int(switch_id))
                cov_map_by_id[int(switch_id)] = cov_map
                if hit:
                    switch_cached_hit_count += 1
                else:
                    miss_switch_ids.append(int(switch_id))
            all_switch_covered = True
            for switch_id in switch_ids:
                cov_map = cov_map_by_id.get(int(switch_id)) or {}
                covered_all = bool(cov_map) and all(bool(v) for v in cov_map.values())
                if not covered_all:
                    all_switch_covered = False
            if all_switch_covered:
                skip_due_to_switch = True
            if not miss_switch_ids:
                switch_cached_seq_count += 1
                switch_cached_last_seq = int(seq)
                if skip_due_to_switch:
                    switch_cached_skip_count += 1
        if (if_ids and skip_due_to_if and (not switch_ids or skip_due_to_switch)) or (switch_ids and skip_due_to_switch and not if_ids):
            continue
        seq_i, rel_seqs = _expand_one_seq(
            seq=int(seq),
            rel_seqs=[int(seq)],
            trace_index_records=trace_index_records,
            nodes=nodes,
            parent_of=parent_of,
            children_of=children_of,
            top_id_to_file=top_id_to_file,
            trace_path=trace_path,
            scope_root=scope_root,
            windows_root=windows_root,
            nearest_seq_count=nearest_seq_count,
            farthest_seq_count=farthest_seq_count,
            indices=indices,
        )
        if seq_i is None:
            continue
        locs = []
        for s in (rel_seqs or []):
            loc = build_loc_for_seq(int(s), trace_index_records, seq_to_index)
            if loc:
                locs.append(loc)
        lines = map_result_set_to_source_lines(scope_root, locs, trace_index_path=trace_index_path, windows_root=windows_root)
        sig_items = []
        sig_set = set()
        for it in lines or []:
            if not isinstance(it, dict):
                continue
            p = it.get("path")
            ln = it.get("line")
            if not p or ln is None:
                continue
            key = f"{p}:{int(ln)}"
            if key in sig_set:
                continue
            sig_set.add(key)
            sig_items.append(key)
        sig_items.sort()
        sig = tuple(sig_items) if sig_items else None
        yield {"seq": int(seq_i), "lines": lines, "sig": sig, "scope_seqs": list(rel_seqs or [])}
async def _run_analyze_seq(
    seq: int,
    *,
    sem: asyncio.Semaphore,
    llm_test_mode: bool,
    sql_mode: bool,
    xss_mode: bool,
    cmd_mode: bool,
    restart_timeout_sec: float = 20.0,
    logger: Optional[Logger] = None,
):
    async with sem:
        pool_dir = _token_pool_dir()
        release_token_here = False
        if pool_dir:
            loop = _get_running_loop()
            try:
                from hybrid_io.token_pool import acquire_with_wait
            except Exception:
                acquire_with_wait = None
            if acquire_with_wait is not None:
                await loop.run_in_executor(None, lambda: acquire_with_wait(pool_dir, kind="analyze", wait_no_token_seconds=10))
                release_token_here = True

        trace_master_sock = (os.environ.get("SYMEX_PIPELINE_TRACE_MASTER_SOCK") or "").strip()
        shared_mode = (os.environ.get("SYMEX_SHARED_MODE") or "").strip()
        shared_enabled = bool((os.environ.get("SYMEX_SHARED_MEMORY_ENABLED") or "").strip() in ("1", "true", "TRUE", "yes", "on"))
        if shared_enabled and shared_mode == "master_worker" and not trace_master_sock:
            _request_pipeline_trace_master_restart("trace_master_socket_missing", logger=logger)
            if not await _wait_pipeline_trace_master_ready(timeout_sec=restart_timeout_sec, logger=logger):
                raise RuntimeError("pipeline trace master missing for seq %d" % int(seq))
            trace_master_sock = (os.environ.get("SYMEX_PIPELINE_TRACE_MASTER_SOCK") or "").strip()
            if not trace_master_sock:
                raise RuntimeError("pipeline trace master restart did not publish socket for seq %d" % int(seq))
        if trace_master_sock:
            try:
                from shared_mem.pipeline_trace_master import submit_pipeline_trace_job
            except Exception:
                submit_pipeline_trace_job = None
            if submit_pipeline_trace_job is not None:
                if logger is not None:
                    logger.info("analyze_path_selected", seq=int(seq), path="pipeline_trace_worker", socket_path=trace_master_sock)
                    logger.info("analyze_worker_submit_start", seq=int(seq), socket_path=trace_master_sock)
                worker_ok = False
                try:
                    loop = _get_running_loop()
                    for attempt in range(2):
                        current_sock = (os.environ.get("SYMEX_PIPELINE_TRACE_MASTER_SOCK") or trace_master_sock or "").strip()
                        result = await loop.run_in_executor(
                            None,
                            lambda sock=current_sock: submit_pipeline_trace_job(
                                socket_path=sock,
                                seq=int(seq),
                                llm_test_mode=bool(llm_test_mode),
                                sql_mode=bool(sql_mode),
                                xss_mode=bool(xss_mode),
                                cmd_mode=bool(cmd_mode),
                            ),
                        )
                        if isinstance(result, dict) and result.get("ok") is True:
                            worker_ok = True
                            if logger is not None:
                                event_name = "analyze_worker_submit_done" if attempt == 0 else "analyze_worker_submit_done_after_restart"
                                artifact_info = result.get("artifacts") if isinstance(result.get("artifacts"), dict) else {}
                                logger.info(
                                    event_name,
                                    seq=int(seq),
                                    socket_path=current_sock,
                                    analysis_output_exists=bool(artifact_info.get("analysis_output_exists")),
                                    heartbeat_status_exists=bool(artifact_info.get("heartbeat_status_exists")),
                                    heartbeat_stage=str(artifact_info.get("heartbeat_stage") or ""),
                                    heartbeat_status=str(artifact_info.get("heartbeat_status") or ""),
                                )
                                if not bool(artifact_info.get("analysis_output_exists")):
                                    inference = _probe_analyze_liveness(
                                        run_root=os.getcwd(),
                                        seq=int(seq),
                                        socket_path=current_sock,
                                        stale_after_sec=25.0,
                                    )
                                    _write_parent_exit_observation(
                                        run_root=os.getcwd(),
                                        seq=int(seq),
                                        phase="worker_done_without_output",
                                        rc=0,
                                        artifact_info=artifact_info,
                                        note="pipeline trace worker returned ok but analysis output is missing",
                                        inference=inference,
                                    )
                            return
                        if logger is not None:
                            artifact_info = result.get("artifacts") if isinstance((result or {}).get("artifacts"), dict) else {}
                            logger.warning(
                                "analyze_worker_submit_failed",
                                seq=int(seq),
                                socket_path=current_sock,
                                error=((result or {}).get("error") if isinstance(result, dict) else "empty_response"),
                                attempt=int(attempt + 1),
                                analysis_output_exists=bool(artifact_info.get("analysis_output_exists")),
                                heartbeat_status_exists=bool(artifact_info.get("heartbeat_status_exists")),
                                heartbeat_stage=str(artifact_info.get("heartbeat_stage") or ""),
                                heartbeat_status=str(artifact_info.get("heartbeat_status") or ""),
                            )
                        error_text = str(((result or {}).get("error") if isinstance(result, dict) else "empty_response") or "")
                        artifact_info = _wait_artifacts = await _wait_for_live_heartbeat_or_output(
                            run_root=os.getcwd(),
                            seq=int(seq),
                            wait_sec=5.0,
                            stale_after_sec=25.0,
                        )
                        inference = _probe_analyze_liveness(
                            run_root=os.getcwd(),
                            seq=int(seq),
                            socket_path=current_sock,
                            stale_after_sec=25.0,
                        )
                        if error_text == "empty_response" and (
                            bool(_wait_artifacts.get("analysis_output_exists"))
                            or _heartbeat_is_fresh(_wait_artifacts, stale_after_sec=25.0)
                        ):
                            if logger is not None:
                                logger.warning(
                                    "analyze_worker_restart_skipped_live_heartbeat",
                                    seq=int(seq),
                                    socket_path=current_sock,
                                    analysis_output_exists=bool(_wait_artifacts.get("analysis_output_exists")),
                                    heartbeat_status_exists=bool(_wait_artifacts.get("heartbeat_status_exists")),
                                    heartbeat_stage=str(_wait_artifacts.get("heartbeat_stage") or ""),
                                    heartbeat_status=str(_wait_artifacts.get("heartbeat_status") or ""),
                                    heartbeat_pid=int(_wait_artifacts.get("heartbeat_pid") or 0),
                                )
                            _write_parent_exit_observation(
                                run_root=os.getcwd(),
                                seq=int(seq),
                                phase="worker_submit_response_lost_but_alive",
                                rc=None,
                                artifact_info=_wait_artifacts,
                                note="empty_response but heartbeat/output is still alive; skip restart",
                                inference=inference,
                            )
                            worker_ok = True
                            return
                        _write_parent_exit_observation(
                            run_root=os.getcwd(),
                            seq=int(seq),
                            phase="worker_submit_failed",
                            rc=None,
                            artifact_info=_wait_artifacts,
                            note=error_text,
                            inference=inference,
                        )
                        if not (shared_enabled and shared_mode == "master_worker" and attempt == 0):
                            break
                        _request_pipeline_trace_master_restart(
                            "submit_failed:%s" % error_text,
                            logger=logger,
                        )
                        if not await _wait_pipeline_trace_master_ready(timeout_sec=restart_timeout_sec, logger=logger):
                            raise RuntimeError("pipeline trace master unavailable for seq %d" % int(seq))
                    if shared_enabled and shared_mode == "master_worker":
                        raise RuntimeError("pipeline trace master unavailable for seq %d" % int(seq))
                    _update_pipeline_trace_master_fallback_state(
                        seq=int(seq),
                        reason=((result or {}).get("error") if isinstance(result, dict) else "empty_response"),
                    )
                finally:
                    if worker_ok and release_token_here and pool_dir:
                        try:
                            from hybrid_io.token_pool import release
                            release(pool_dir, kind="analyze")
                        except Exception:
                            pass
        script_path = os.path.join(_ROOT, "analyze_if_line.py")
        if not os.path.isfile(script_path):
            script_path = os.path.join(os.getcwd(), "analyze_if_line.py")
        args = [sys.executable, script_path, str(int(seq))]
        args.extend(["--debug", "--prompt"])
        if not llm_test_mode:
            args.append("--llm")
        if sql_mode:
            args.append("--sql")
        elif xss_mode:
            args.append("--xss")
        elif cmd_mode:
            args.append("--cmd")
        proc = None
        try:
            env = None
            if pool_dir:
                env = dict(os.environ)
                env["WC_TOKEN_POOL_DIR"] = pool_dir
                env["WC_TOKEN_KIND"] = "analyze"
            if logger is not None:
                logger.info("analyze_path_selected", seq=int(seq), path="legacy_subprocess")
                logger.info("analyze_if_line_spawn_start", seq=int(seq))
                if trace_master_sock:
                    logger.info("analyze_if_line_spawn_fallback", seq=int(seq), socket_path=trace_master_sock)

            meta_dir = os.path.join(os.getcwd(), "meta")
            try:
                os.makedirs(meta_dir, exist_ok=True)
            except Exception:
                pass
            out_fp = open(os.path.join(meta_dir, "analyze_%d.out" % int(seq)), "ab")
            err_fp = open(os.path.join(meta_dir, "analyze_%d.err" % int(seq)), "ab")
            try:
                proc = await asyncio.create_subprocess_exec(*args, stdout=out_fp, stderr=err_fp, env=env)
            finally:
                try:
                    out_fp.close()
                except Exception:
                    pass
                try:
                    err_fp.close()
                except Exception:
                    pass
            if logger is not None:
                logger.info(
                    "analyze_if_line_spawned",
                    seq=int(seq),
                    pid=int(proc.pid),
                    stdout_path=os.path.join(meta_dir, "analyze_%d.out" % int(seq)),
                    stderr_path=os.path.join(meta_dir, "analyze_%d.err" % int(seq)),
                )
            _write_parent_exit_observation(
                run_root=os.getcwd(),
                seq=int(seq),
                phase="process_spawned",
                rc=None,
                artifact_info=_collect_analyze_artifacts(run_root=os.getcwd(), seq=int(seq)),
                note="legacy analyze subprocess spawned",
                inference=_probe_analyze_liveness(run_root=os.getcwd(), seq=int(seq), stale_after_sec=25.0),
                child_pid=int(proc.pid),
                child_alive=True,
                child_status="spawned",
            )
            _track_task(
                _PENDING_TASKS,
                asyncio.create_task(_monitor_analyze_process(run_root=os.getcwd(), seq=int(seq), proc=proc, poll_sec=0.5)),
                logger=logger,
                event="analyze_process_monitor_started",
                seq=int(seq),
                pid=int(proc.pid),
            )
            startup_ok, artifact_info, early_rc = await _wait_for_analyze_startup(run_root=os.getcwd(), seq=int(seq), proc=proc, timeout_sec=3.0)
            if logger is not None:
                if startup_ok:
                    logger.info(
                        "analyze_if_line_startup_ok",
                        seq=int(seq),
                        pid=int(proc.pid),
                        analysis_output_exists=bool(artifact_info.get("analysis_output_exists")),
                        heartbeat_status_exists=bool(artifact_info.get("heartbeat_status_exists")),
                        heartbeat_stage=str(artifact_info.get("heartbeat_stage") or ""),
                        heartbeat_status=str(artifact_info.get("heartbeat_status") or ""),
                    )
                else:
                    logger.warning(
                        "analyze_if_line_startup_missing_artifacts",
                        seq=int(seq),
                        pid=int(proc.pid),
                        rc=(int(early_rc) if early_rc is not None else None),
                        signal_name=_signal_name_from_return_code(early_rc),
                        analysis_output_exists=bool(artifact_info.get("analysis_output_exists")),
                        heartbeat_status_exists=bool(artifact_info.get("heartbeat_status_exists")),
                        seq_root_exists=bool(artifact_info.get("seq_root_exists")),
                        logs_dir_exists=bool(artifact_info.get("logs_dir_exists")),
                    )
                    _write_parent_exit_observation(
                        run_root=os.getcwd(),
                        seq=int(seq),
                        phase="startup_missing_artifacts",
                        rc=early_rc,
                        artifact_info=artifact_info,
                        note="process spawned but startup artifacts did not appear within timeout",
                        inference=_probe_analyze_liveness(run_root=os.getcwd(), seq=int(seq), stale_after_sec=25.0),
                    )
            rc = await proc.wait()
            artifact_info = _collect_analyze_artifacts(run_root=os.getcwd(), seq=int(seq))
            _write_parent_exit_observation(
                run_root=os.getcwd(),
                seq=int(seq),
                phase="process_wait_completed",
                rc=int(rc),
                artifact_info=artifact_info,
                note=("legacy analyze subprocess wait completed"),
                inference=_probe_analyze_liveness(run_root=os.getcwd(), seq=int(seq), stale_after_sec=25.0),
                child_pid=int(proc.pid),
                child_alive=False,
                child_status="wait_completed",
            )
            if logger is not None:
                if int(rc) == 0:
                    artifact_info = _collect_analyze_artifacts(run_root=os.getcwd(), seq=int(seq))
                    logger.info(
                        "analyze_if_line_done",
                        seq=int(seq),
                        pid=int(proc.pid),
                        rc=int(rc),
                        analysis_output_exists=bool(artifact_info.get("analysis_output_exists")),
                        heartbeat_status_exists=bool(artifact_info.get("heartbeat_status_exists")),
                        heartbeat_stage=str(artifact_info.get("heartbeat_stage") or ""),
                        heartbeat_status=str(artifact_info.get("heartbeat_status") or ""),
                    )
                    if not bool(artifact_info.get("analysis_output_exists")):
                        _write_parent_exit_observation(
                            run_root=os.getcwd(),
                            seq=int(seq),
                            phase="done_without_output",
                            rc=int(rc),
                            artifact_info=artifact_info,
                            note="process exited cleanly but analysis output is missing",
                            inference=_probe_analyze_liveness(run_root=os.getcwd(), seq=int(seq), stale_after_sec=25.0),
                        )
                else:
                    artifact_info = _collect_analyze_artifacts(run_root=os.getcwd(), seq=int(seq))
                    logger.warning(
                        "analyze_if_line_failed",
                        seq=int(seq),
                        pid=int(proc.pid),
                        rc=int(rc),
                        signal_name=_signal_name_from_return_code(int(rc)),
                        analysis_output_exists=bool(artifact_info.get("analysis_output_exists")),
                        heartbeat_status_exists=bool(artifact_info.get("heartbeat_status_exists")),
                        heartbeat_stage=str(artifact_info.get("heartbeat_stage") or ""),
                        heartbeat_status=str(artifact_info.get("heartbeat_status") or ""),
                    )
                    _write_parent_exit_observation(
                        run_root=os.getcwd(),
                        seq=int(seq),
                        phase="process_failed",
                        rc=int(rc),
                        artifact_info=artifact_info,
                        note="legacy analyze subprocess exited with non-zero return code",
                        inference=_probe_analyze_liveness(run_root=os.getcwd(), seq=int(seq), stale_after_sec=25.0),
                    )
        finally:
            if proc is None and pool_dir:
                try:
                    from hybrid_io.token_pool import release
                    release(pool_dir, kind="analyze")
                except Exception:
                    pass


def _track_task(task_set: set, task: asyncio.Task, logger: Optional[Logger] = None, event: Optional[str] = None, **fields):
    task_set.add(task)
    if logger is not None and event:
        logger.info(event, **fields)

    def _done(t: asyncio.Task):
        try:
            exc = t.exception()
        except Exception as e:
            exc = e
        if exc is not None and logger is not None:
            logger.warning("task_failed", error=str(exc), event=(event or "task"))

    task.add_done_callback(_done)
    return task


async def _await_task_set(task_set: set, *, logger: Optional[Logger] = None, task_kind: str = "task") -> None:
    if not task_set:
        return
    tasks = list(task_set)
    results = await asyncio.gather(*tasks, return_exceptions=True)
    first_error: Optional[BaseException] = None
    for idx, res in enumerate(results):
        if isinstance(res, BaseException):
            if first_error is None:
                first_error = res
            if logger is not None:
                logger.warning(
                    "task_wait_failed",
                    task_kind=str(task_kind),
                    index=int(idx),
                    error=str(res),
                    traceback="".join(traceback.format_exception(type(res), res, getattr(res, "__traceback__", None))),
                )
    for task in tasks:
        try:
            task_set.discard(task)
        except Exception:
            pass
    if first_error is not None:
        raise first_error


def _select_random_if_seqs(
    prompt_seqs: List[int],
    llm_selected_seqs: List[int],
) -> List[int]:
    prompt_unique = []
    prompt_seen = set()
    for seq in prompt_seqs or []:
        try:
            seq_i = int(seq)
        except Exception:
            continue
        if seq_i in prompt_seen:
            continue
        prompt_seen.add(seq_i)
        prompt_unique.append(seq_i)
    selected_unique = []
    selected_seen = set()
    for seq in llm_selected_seqs or []:
        try:
            seq_i = int(seq)
        except Exception:
            continue
        if seq_i in selected_seen:
            continue
        selected_seen.add(seq_i)
        selected_unique.append(seq_i)
    sample_count = min(len(prompt_unique), len(selected_unique))
    if sample_count <= 0:
        return []
    randomized = random.sample(prompt_unique, sample_count)
    return [int(x) for x in randomized]


def _write_branch_random_log(
    response_path: str,
    *,
    prompt_seqs: List[int],
    llm_selected_seqs: List[int],
    randomized_seqs: List[int],
    logger: Optional[Logger] = None,
) -> str:
    response_abs_path = os.path.abspath(response_path)
    response_dir = os.path.dirname(response_abs_path)
    response_name = os.path.basename(response_abs_path)
    stem, _ = os.path.splitext(response_name)
    log_path = os.path.join(response_dir, stem + ".branch_random.json")
    payload = {
        "response_path": response_abs_path,
        "prompt_seq_count": int(len(prompt_seqs or [])),
        "llm_seq_count": int(len(llm_selected_seqs or [])),
        "llm_selected_seqs": [int(x) for x in (llm_selected_seqs or [])],
        "random_selected_seq_count": int(len(randomized_seqs or [])),
        "random_selected_seqs": [int(x) for x in (randomized_seqs or [])],
    }
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    if logger is not None:
        logger.info(
            "branch_random_log_written",
            path=log_path,
            llm_seq_count=int(len(llm_selected_seqs or [])),
            random_selected_seq_count=int(len(randomized_seqs or [])),
        )
    return log_path


async def _handle_llm_response(
    seqs_groups: List[List[int]],
    *,
    llm_test_mode: bool,
    sql_mode: bool,
    xss_mode: bool,
    cmd_mode: bool,
    sem: asyncio.Semaphore,
    analyze_tasks: set,
    if_loc_by_seq: Optional[Dict[int, Tuple[str, int]]] = None,
    remaining_seeds: int = 0,
    emit_items: Optional[List[dict]] = None,
    logger: Optional[Logger] = None,
):
    tasks = []
    seen = set()
    total = 0
    for group in seqs_groups or []:
        for s in group or []:
            try:
                si = int(s)
            except Exception:
                continue
            if si in seen:
                continue
            seen.add(si)
            if not (sql_mode or xss_mode or cmd_mode):
                loc = (if_loc_by_seq or {}).get(int(si))
                if loc:
                    try:
                        from skip_cache.if_stmt_counter import should_skip
                        skip, cnt = should_skip(loc[0], int(loc[1]), remaining_seeds=int(remaining_seeds))
                    except Exception:
                        skip, cnt = False, 0
                    if skip:
                        if logger is not None:
                            logger.info(
                                "if_stmt_skip_due_to_cache",
                                seq=int(si),
                                path=str(loc[0]),
                                line=int(loc[1]),
                                count=int(cnt),
                                remaining_seeds=int(remaining_seeds),
                            )
                        continue
            total += 1
            if emit_items is not None:
                mode = "if"
                if sql_mode:
                    mode = "sql"
                elif xss_mode:
                    mode = "xss"
                elif cmd_mode:
                    mode = "cmd"
                emit_items.append({"seq": int(si), "mode": mode})
                continue
            task = _create_task(
                _run_analyze_seq(
                    si,
                    sem=sem,
                    llm_test_mode=llm_test_mode,
                    sql_mode=sql_mode,
                    xss_mode=xss_mode,
                    cmd_mode=cmd_mode,
                    logger=logger,
                )
            )
            _track_task(analyze_tasks, task, logger=logger, event="analyze_task_start", seq=int(si))
            tasks.append(task)
    if logger is not None:
        logger.info("analyze_if_line_schedule", count=total, llm_test_mode=llm_test_mode)


# Summary: Flush buffered sections to a prompt, get/simulate an LLM response, and schedule per-seq analysis.
async def _flush_buffer(
    *,
    sections: List[dict],
    separator: str,
    test_mode: bool,
    analyze_llm_test_mode: bool,
    base_prompt: str,
    prompt_builder,
    prompt_prefix: str,
    sql_mode: bool,
    xss_mode: bool,
    cmd_mode: bool,
    branch_random: bool,
    prompt_out_dir: str,
    response_out_dir: str,
    llm_client,
    llm_temperature: float,
    llm_max_attempts: int,
    llm_call_index: int,
    analyze_sem: asyncio.Semaphore,
    analyze_tasks: set,
    if_loc_by_seq: Optional[Dict[int, Tuple[str, int]]] = None,
    remaining_seeds: int = 0,
    emit_items: Optional[List[dict]] = None,
    logger: Optional[Logger] = None,
):
    start_ts = time.perf_counter()
    _write_flush_debug_state(
        logger=logger,
        prompt_prefix=prompt_prefix,
        prompt_index=int(llm_call_index),
        phase="start",
        extra={
            "section_count": int(len(sections or [])),
            "test_mode": bool(test_mode),
            "sql_mode": bool(sql_mode),
            "xss_mode": bool(xss_mode),
            "cmd_mode": bool(cmd_mode),
        },
    )
    prompt_text = prompt_builder(sections=sections, separator=separator, base_prompt=base_prompt, logger=logger)
    app_cfg_debug = None
    try:
        app_cfg_debug = load_symex_app_config()
        prompt_text = append_app_name_to_prompt(prompt_text, app_cfg_debug)
    except Exception:
        pass
    if logger is not None:
        app_line = ""
        app_name = ""
        cfg_path = ""
        try:
            app_name = get_app_name(app_cfg_debug)
            cfg_path = str(getattr(app_cfg_debug, "config_path", "") or "")
            app_line = "下面的代码来自" + app_name if app_name else ""
        except Exception:
            app_name = ""
            cfg_path = ""
            app_line = ""
        contains_app_name = bool(app_line and app_line in (prompt_text or ""))
        if not contains_app_name and app_name:
            logger.warning(
                "prompt_app_name_missing",
                prompt_index=int(llm_call_index),
                prompt_prefix=str(prompt_prefix or ""),
                config_path=cfg_path,
                app_name=app_name,
            )
    prompt_marked_seqs = []
    prompt_marked_seen = set()
    for sec in sections or []:
        if not isinstance(sec, dict):
            continue
        for x in sec.get("mark_seqs") or []:
            try:
                xi = int(x)
            except Exception:
                continue
            if xi in prompt_marked_seen:
                continue
            prompt_marked_seen.add(xi)
            prompt_marked_seqs.append(int(xi))
    prompt_marked_set = set(prompt_marked_seqs)

    def _normalize_llm_groups(resp_groups):
        if not resp_groups or not prompt_marked_seqs:
            return resp_groups or []
        flat = []
        for g in resp_groups or []:
            for x in g or []:
                try:
                    flat.append(int(x))
                except Exception:
                    continue
        if not flat:
            return []
        max_mark = int(len(prompt_marked_seqs))
        all_not_marked = all(int(x) not in prompt_marked_set for x in flat)
        all_in_ordinal_range = all(1 <= int(x) <= max_mark for x in flat)
        if all_not_marked and all_in_ordinal_range:
            mapped_groups = []
            for g in resp_groups or []:
                out = []
                seen = set()
                for x in g or []:
                    try:
                        xi = int(x)
                    except Exception:
                        continue
                    if not (1 <= xi <= max_mark):
                        continue
                    real = int(prompt_marked_seqs[int(xi) - 1])
                    if real in seen:
                        continue
                    seen.add(real)
                    out.append(real)
                if out:
                    mapped_groups.append(out)
            return mapped_groups
        filtered_groups = []
        for g in resp_groups or []:
            out = []
            seen = set()
            for x in g or []:
                try:
                    xi = int(x)
                except Exception:
                    continue
                if xi in prompt_marked_set:
                    if xi in seen:
                        continue
                    seen.add(xi)
                    out.append(int(xi))
                    continue
                if xi > max_mark:
                    continue
            if out:
                filtered_groups.append(out)
        return filtered_groups

    if logger is not None:
        logger.info("llm_call_start", prompt_index=llm_call_index, sections=len(sections), test_mode=bool(test_mode))
    ppath = write_prompt_text(prompt_out_dir, f"{prompt_prefix}{llm_call_index}.txt", prompt_text, logger=logger)
    _write_flush_debug_state(
        logger=logger,
        prompt_prefix=prompt_prefix,
        prompt_index=int(llm_call_index),
        phase="prompt_written",
        extra={
            "prompt_path": str(ppath or ""),
            "prompt_chars": int(len(prompt_text or "")),
            "section_count": int(len(sections or [])),
        },
    )
    failure_out_dir = os.path.join(os.path.dirname(os.path.abspath(prompt_out_dir)), "failed_responses")
    if test_mode:
        rpath = os.path.join(response_out_dir, f"{prompt_prefix}{llm_call_index}.json")
        resp = None
        if os.path.exists(rpath):
            try:
                with open(rpath, "r", encoding="utf-8", errors="replace") as f:
                    resp = json.load(f)
            except Exception:
                resp = None
            if logger is not None:
                logger.info("response_reused", path=rpath)
        if resp is None:
            resp = simulate_response(sections, pick_count=5, logger=logger)
            _ = write_response_json(response_out_dir, f"{prompt_prefix}{llm_call_index}.json", resp, logger=logger)
        _ = ppath
        resp_groups = parse_llm_response(json.dumps(resp, ensure_ascii=False), logger=logger)
        resp_groups_norm = _normalize_llm_groups(resp_groups)
        group_count, seq_count = _count_grouped_seqs(resp_groups_norm)
        _write_flush_debug_state(
            logger=logger,
            prompt_prefix=prompt_prefix,
            prompt_index=int(llm_call_index),
            phase="response_parsed",
            extra={
                "response_path": str(rpath or ""),
                "response_reused": bool(os.path.exists(rpath)),
                "group_count": int(group_count),
                "seq_count": int(seq_count),
            },
        )
        llm_groups_for_handle = resp_groups_norm
        if branch_random:
            llm_selected_seqs = [x for g in resp_groups_norm for x in (g or [])]
            random_seqs = _select_random_if_seqs(prompt_marked_seqs, llm_selected_seqs)
            _write_branch_random_log(
                str(rpath or ""),
                prompt_seqs=prompt_marked_seqs,
                llm_selected_seqs=llm_selected_seqs,
                randomized_seqs=random_seqs,
                logger=logger,
            )
            llm_groups_for_handle = [random_seqs] if random_seqs else []
        await _handle_llm_response(
            llm_groups_for_handle,
            llm_test_mode=analyze_llm_test_mode,
            sql_mode=sql_mode,
            xss_mode=xss_mode,
            cmd_mode=cmd_mode,
            sem=analyze_sem,
            analyze_tasks=analyze_tasks,
            if_loc_by_seq=if_loc_by_seq,
            remaining_seeds=int(remaining_seeds),
            emit_items=emit_items,
            logger=logger,
        )
        if logger is not None:
            elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
            logger.info("llm_call_done", prompt_index=llm_call_index, duration_ms=elapsed_ms, test_mode=True)
        return {
            "status": "success",
            "terminal": True,
            "clear_buffer": True,
            "group_count": int(group_count),
            "seq_count": int(seq_count),
            "prompt_path": str(ppath or ""),
            "response_path": str(rpath or ""),
        }
    rpath = os.path.join(response_out_dir, f"{prompt_prefix}{llm_call_index}.json")
    if os.path.exists(rpath):
        try:
            with open(rpath, "r", encoding="utf-8", errors="replace") as f:
                resp_payload = json.load(f)
        except Exception:
            resp_payload = None
        if resp_payload is not None:
            if logger is not None:
                logger.info("response_reused", path=rpath)
            resp_groups = parse_llm_response(json.dumps(resp_payload, ensure_ascii=False), logger=logger)
            resp_groups_norm = _normalize_llm_groups(resp_groups)
            group_count, seq_count = _count_grouped_seqs(resp_groups_norm)
            _write_flush_debug_state(
                logger=logger,
                prompt_prefix=prompt_prefix,
                prompt_index=int(llm_call_index),
                phase="response_reused_parsed",
                extra={
                    "response_path": str(rpath or ""),
                    "group_count": int(group_count),
                    "seq_count": int(seq_count),
                },
            )
            llm_groups_for_handle = resp_groups_norm
            if branch_random:
                llm_selected_seqs = [x for g in resp_groups_norm for x in (g or [])]
                random_seqs = _select_random_if_seqs(prompt_marked_seqs, llm_selected_seqs)
                _write_branch_random_log(
                    str(rpath or ""),
                    prompt_seqs=prompt_marked_seqs,
                    llm_selected_seqs=llm_selected_seqs,
                    randomized_seqs=random_seqs,
                    logger=logger,
                )
                llm_groups_for_handle = [random_seqs] if random_seqs else []
            await _handle_llm_response(
                llm_groups_for_handle,
                llm_test_mode=analyze_llm_test_mode,
                sql_mode=sql_mode,
                xss_mode=xss_mode,
                cmd_mode=cmd_mode,
                sem=analyze_sem,
                analyze_tasks=analyze_tasks,
                if_loc_by_seq=if_loc_by_seq,
                remaining_seeds=int(remaining_seeds),
                emit_items=emit_items,
                logger=logger,
            )
            if logger is not None:
                elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
                logger.info("llm_call_done", prompt_index=llm_call_index, duration_ms=elapsed_ms, test_mode=True)
            return {
                "status": "success",
                "terminal": True,
                "clear_buffer": True,
                "group_count": int(group_count),
                "seq_count": int(seq_count),
                "prompt_path": str(ppath or ""),
                "response_path": str(rpath or ""),
            }
    try:
        max_attempts = int(llm_max_attempts) if int(llm_max_attempts) > 0 else 3
    except Exception:
        max_attempts = 3
    max_attempts = max(1, min(3, int(max_attempts)))
    try:
        txt = await chat_text_with_retries(
            client=llm_client,
            prompt=prompt_text,
            system=None,
            temperature=llm_temperature,
            logger=logger,
            max_attempts=max_attempts,
            call_timeout_s=getattr(llm_client, "timeout_s", None) if llm_client else None,
            call_index=llm_call_index,
            response_validator=llm_response_has_valid_json,
            response_validator_name='llm_response_has_valid_json',
        )
    except LLMCallFailure as e:
        failure_path = write_llm_failure_artifact(
            failure_dir=failure_out_dir,
            failure_name=f"{prompt_prefix}{llm_call_index}",
            prompt_path=ppath,
            failure=e,
            extra={
                "prompt_index": int(llm_call_index),
                "prompt_prefix": prompt_prefix,
                "sql_mode": bool(sql_mode),
                "xss_mode": bool(xss_mode),
                "cmd_mode": bool(cmd_mode),
            },
        )
        if logger is not None:
            if failure_path:
                logger.warning("llm_call_failed", prompt_index=llm_call_index, failure_path=failure_path)
            else:
                logger.warning("llm_call_failed", prompt_index=llm_call_index)
        _write_flush_debug_state(
            logger=logger,
            prompt_prefix=prompt_prefix,
            prompt_index=int(llm_call_index),
            phase="terminal_failure",
            extra={
                "failure_path": str(failure_path or ""),
                "failure_message": str(e),
                "retryable": bool(getattr(e, "retryable", False)),
                "status_code": getattr(e, "status", None),
            },
        )
        return {
            "status": "terminal_failure",
            "terminal": True,
            "clear_buffer": True,
            "failure_path": str(failure_path or ""),
            "failure_message": str(e),
        }
    extracted = extract_llm_json_text(txt)
    if extracted:
        txt = extracted
    try:
        resp_payload = json.loads(txt)
    except Exception:
        resp_payload = {"raw": txt}
    rpath = write_response_json(response_out_dir, f"{prompt_prefix}{llm_call_index}.json", resp_payload, logger=logger)
    _ = ppath, rpath
    resp_groups = parse_llm_response(txt, logger=logger)
    resp_groups_norm = _normalize_llm_groups(resp_groups)
    group_count, seq_count = _count_grouped_seqs(resp_groups_norm)
    _write_flush_debug_state(
        logger=logger,
        prompt_prefix=prompt_prefix,
        prompt_index=int(llm_call_index),
        phase="response_parsed",
        extra={
            "response_path": str(rpath or ""),
            "group_count": int(group_count),
            "seq_count": int(seq_count),
            "response_chars": int(len(txt or "")),
        },
    )
    llm_groups_for_handle = resp_groups_norm
    if branch_random:
        llm_selected_seqs = [x for g in resp_groups_norm for x in (g or [])]
        random_seqs = _select_random_if_seqs(prompt_marked_seqs, llm_selected_seqs)
        _write_branch_random_log(
            str(rpath or ""),
            prompt_seqs=prompt_marked_seqs,
            llm_selected_seqs=llm_selected_seqs,
            randomized_seqs=random_seqs,
            logger=logger,
        )
        llm_groups_for_handle = [random_seqs] if random_seqs else []
    await _handle_llm_response(
        llm_groups_for_handle,
        llm_test_mode=analyze_llm_test_mode,
        sql_mode=sql_mode,
        xss_mode=xss_mode,
        cmd_mode=cmd_mode,
        sem=analyze_sem,
        analyze_tasks=analyze_tasks,
        if_loc_by_seq=if_loc_by_seq,
        remaining_seeds=int(remaining_seeds),
        emit_items=emit_items,
        logger=logger,
    )
    if logger is not None:
        elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
        logger.info("llm_call_done", prompt_index=llm_call_index, duration_ms=elapsed_ms, test_mode=False)
    return {
        "status": "success",
        "terminal": True,
        "clear_buffer": True,
        "group_count": int(group_count),
        "seq_count": int(seq_count),
        "prompt_path": str(ppath or ""),
        "response_path": str(rpath or ""),
    }


# Summary: Orchestrate config loading, section production, buffering, LLM calls, and analysis execution.
async def run_pipeline(
    config_path: Optional[str] = None,
    *,
    test_mode_override: Optional[bool] = None,
    analyze_llm_test_mode_override: Optional[bool] = None,
):
    trace_master_handle = None
    heartbeat = None
    pipeline_status = "failed"
    pipeline_stage = "startup"
    pipeline_message = ""
    pipeline_error_type = ""
    pipeline_traceback = ""
    logger = None
    run_dir = os.path.abspath(os.getcwd())
    cfg = load_config(config_path)
    if test_mode_override is not None or analyze_llm_test_mode_override is not None:
        cfg = replace(
            cfg,
            test_mode=cfg.test_mode if test_mode_override is None else bool(test_mode_override),
            analyze_llm_test_mode=cfg.analyze_llm_test_mode if analyze_llm_test_mode_override is None else bool(analyze_llm_test_mode_override),
        )
    app_cfg = load_app_config(config_path=config_path, argv=sys.argv[1:])
    base = app_cfg.base_dir
    test_root = app_cfg.test_dir
    tmp_root = app_cfg.tmp_dir
    _clear_branch_selector_dir(test_root)
    if cfg.test_mode:
        _clear_seq_dirs(test_root)

    def _rewrite_rooted_relative(p: str, root_name: str, root_abs: str) -> str:
        if not p:
            return p
        if os.path.isabs(p):
            return p
        norm = p.replace("/", os.sep).replace("\\", os.sep)
        parts = [x for x in norm.split(os.sep) if x]
        if parts and parts[0].lower() == root_name.lower():
            return os.path.join(root_abs, *parts[1:])
        return os.path.join(base, norm)

    prompt_out_dir = _rewrite_rooted_relative(cfg.prompt_out_dir, "test", test_root)
    response_out_dir = _rewrite_rooted_relative(cfg.response_out_dir, "test", test_root)
    trace_index_path = _rewrite_rooted_relative(cfg.trace_index_path, "tmp", tmp_root)
    if_branch_cache_path = os.path.join(tmp_root, "if_branch_coverage_cache.json")

    log_dir = os.path.join(test_root, "branch_selector")
    logger = Logger(base_dir=log_dir, min_level=cfg.log_level, name="branch_selector", also_console=True)
    logger.info("pipeline_start", config_path=(config_path or "config.json"), test_mode=cfg.test_mode)
    try:
        heartbeat = BranchSelectorHeartbeat(run_dir=run_dir, interval_seconds=10)
        heartbeat.start()
        heartbeat.update(
            "bootstrap",
            status="running",
            message="branch_selector bootstrap started",
            config_path=str(config_path or "config.json"),
            test_mode=bool(cfg.test_mode),
        )
    except Exception:
        heartbeat = None
    if_loc_by_seq: Dict[int, Tuple[str, int]] = {}
    try:
        seeds_scanned = int(os.environ.get("WC_SEED_SCANNED_COUNT") or 0)
    except Exception:
        seeds_scanned = 0
    try:
        bs_called = int(os.environ.get("WC_BRANCH_SELECTOR_CALLED_COUNT") or 0)
    except Exception:
        bs_called = 0
    remaining_seeds = max(0, int(seeds_scanned) - int(bs_called))
    trace_path = app_cfg.find_input_file("trace.log")
    nodes_path = app_cfg.find_input_file("nodes.csv")
    restart_limit = _shared_restart_limit(app_cfg)
    rels_path = app_cfg.find_input_file("rels.csv")
    trace_index_records = ensure_trace_index(
        trace_index_path,
        trace_path,
        nodes_path,
        cfg.seq_limit,
        seq_start=cfg.seq_start,
        logger=logger,
    )
    pipeline_stage = "trace_index_ready"
    if heartbeat is not None:
        heartbeat.update(
            "trace_index_ready",
            status="running",
            message="trace index prepared",
            trace_index_path=str(trace_index_path or ""),
            trace_record_count=int(len(trace_index_records or [])),
        )
    try:
        from shared_mem.pipeline_trace_master import start_pipeline_trace_master
    except Exception:
        start_pipeline_trace_master = None
    if start_pipeline_trace_master is not None:
        try:
            trace_master_handle = _restart_pipeline_trace_master_with_retry(
                cfg=app_cfg,
                trace_path=trace_path,
                trace_index_path=trace_index_path,
                max_workers=int(cfg.max_analyze_concurrency),
                logger=logger,
                current_handle=None,
                max_attempts=int(restart_limit),
                restart_reason="bootstrap",
            )
        except Exception:
            logger.exception("pipeline_trace_master_bootstrap_failed")
            raise
    if heartbeat is not None:
        heartbeat.update(
            "trace_master_ready",
            status="running",
            message="pipeline trace master ready",
            trace_master_enabled=bool(start_pipeline_trace_master is not None),
            trace_master_started=bool(trace_master_handle is not None),
        )
    nodes, parent_of, children_of, top_id_to_file = load_nodes_and_edges(nodes_path, rels_path)
    _ = top_id_to_file
    try:
        total_recs = len(trace_index_records or [])
        recs_with_nodes = sum(1 for r in (trace_index_records or []) if (r.get("node_ids") or []))
        node_id_total = sum(len(r.get("node_ids") or []) for r in (trace_index_records or []))
        logger.info(
            "trace_index_node_id_stats",
            records=int(total_recs),
            records_with_node_ids=int(recs_with_nodes),
            node_ids_total=int(node_id_total),
        )
    except Exception:
        pass
    if cfg.test_mode:
        llm_client = None
    else:
        try:
            llm_client = get_default_client()
        except Exception:
            llm_client = None
    if llm_client is None and not cfg.test_mode:
        logger.warning("llm_client_missing")
    analyze_sem = asyncio.Semaphore(int(cfg.max_analyze_concurrency))
    llm_sem = asyncio.Semaphore(max(1, int(cfg.buffer_count) + int(cfg.sql_buffer_count) + int(cfg.xss_buffer_count) + int(cfg.cmd_buffer_count)))
    pending_llm_tasks: set = set()
    pending_analyze_tasks: set = set()
    emit_path = _parse_emit_seqs_arg(list(sys.argv[1:]))
    emit_items: Optional[List[dict]] = [] if emit_path else None
    watchdog_stop = {"stop": False}

    sections_queue: asyncio.Queue = asyncio.Queue()
    sql_sections_queue: asyncio.Queue = asyncio.Queue()
    xss_sections_queue: asyncio.Queue = asyncio.Queue()
    cmd_sections_queue: asyncio.Queue = asyncio.Queue()
    done_sentinel = object()
    available_slots = None
    sql_available_slots = None
    xss_available_slots = None
    cmd_available_slots = None

    exit_state = {
        "producer_done": False,
        "if_done": False,
        "sql_done": False,
        "xss_done": False,
        "cmd_done": False,
        "scan_seq": 0,
        "scan_non_filtered_seen": 0,
        "scan_processed": 0,
        "scan_stop_limit": False,
        "scan_skipped_third_party": 0,
    }
    if heartbeat is not None:
        heartbeat.update(
            "pipeline_running",
            status="running",
            message="pipeline consumers started",
            max_analyze_concurrency=int(cfg.max_analyze_concurrency),
            emit_mode=bool(emit_path),
        )

    async def producer():
        loop = _get_running_loop()
        done_evt = threading.Event()
        stop_evt = threading.Event()
        forced_stop = False
        forced_reason = ""
        scan_stale_rounds = 0
        scan_last_seq = None
        scan_stale_check_interval_seconds = 10.0
        scan_stale_check_next_at = time.monotonic() + float(scan_stale_check_interval_seconds)
        if logger is not None:
            logger.info("producer_start")

        def _on_scan_progress(*, processed: int, non_filtered_seen: int, min_seq: Optional[int]):
            try:
                exit_state["scan_processed"] = int(processed)
            except Exception:
                pass
            try:
                exit_state["scan_non_filtered_seen"] = int(non_filtered_seen)
            except Exception:
                pass
            if min_seq is not None:
                try:
                    exit_state["scan_seq"] = int(min_seq)
                except Exception:
                    pass

        def _produce_all():
            counts = {"if": 0, "sql": 0, "xss": 0, "cmd": 0}
            err = None
            err_tb = ""
            try:
                for kind, item in iter_combined_sections(
                    trace_index_records=trace_index_records,
                    nodes=nodes,
                    parent_of=parent_of,
                    children_of=children_of,
                    top_id_to_file=top_id_to_file,
                    seq_limit=cfg.seq_limit,
                    scope_root=cfg.scope_root,
                    trace_index_path=trace_index_path,
                    windows_root=cfg.windows_root,
                    nearest_seq_count=cfg.nearest_seq_count,
                    farthest_seq_count=cfg.farthest_seq_count,
                    trace_path=trace_path,
                    enable_if=cfg.enable_if,
                    enable_switch=cfg.enable_switch,
                    enable_sql=cfg.enable_sql,
                    enable_xss=cfg.enable_xss,
                    enable_cmd=cfg.enable_cmd,
                    if_branch_cache_path=if_branch_cache_path,
                    if_branch_cache_skip=cfg.if_branch_cache_skip,
                    progress_cb=_on_scan_progress,
                    logger=logger,
                ):
                    if stop_evt.is_set():
                        break
                    try:
                        si = int((item or {}).get("seq"))
                    except Exception:
                        si = None
                    if si is not None:
                        exit_state["scan_seq"] = int(si)
                    if _item_is_third_party(item):
                        try:
                            exit_state["scan_skipped_third_party"] = int(exit_state.get("scan_skipped_third_party") or 0) + 1
                        except Exception:
                            pass
                        continue
                    if kind == "if":
                        q = sections_queue
                    elif kind == "sql":
                        q = sql_sections_queue
                    elif kind == "xss":
                        q = xss_sections_queue
                    elif kind == "cmd":
                        q = cmd_sections_queue
                    else:
                        continue
                    try:
                        counts[str(kind)] = int(counts.get(str(kind), 0)) + 1
                    except Exception:
                        pass
                    if kind == "if":
                        try:
                            ms = (item or {}).get("mark_seqs") or []
                            ms0 = int(ms[0]) if ms else None
                        except Exception:
                            ms0 = None
                        if ms0 is not None:
                            p = (item or {}).get("if_path")
                            ln = (item or {}).get("if_line")
                            try:
                                li = int(ln) if ln is not None else None
                            except Exception:
                                li = None
                            if p and li is not None:
                                if_loc_by_seq[int(ms0)] = (str(p), int(li))
                    try:
                        loop.call_soon_threadsafe(q.put_nowait, item)
                    except Exception as ex:
                        err = ex
                        err_tb = traceback.format_exc()
                        break
            except Exception as ex:
                err = ex
                err_tb = traceback.format_exc()
            finally:
                for q in (sections_queue, sql_sections_queue, xss_sections_queue, cmd_sections_queue):
                    try:
                        loop.call_soon_threadsafe(q.put_nowait, done_sentinel)
                    except Exception:
                        pass
                if logger is not None:
                    if err is not None:
                        payload_err = {"error": str(err), "traceback": err_tb}
                        loop.call_soon_threadsafe(lambda p=payload_err: logger.warning("producer_failed", **p))
                    payload_counts = dict(counts or {})
                    loop.call_soon_threadsafe(lambda p=payload_counts: logger.info("producer_done", **p))
                done_evt.set()

        t = threading.Thread(target=_produce_all, daemon=True)
        t.start()
        while not done_evt.is_set():
            try:
                scan_seen = int(exit_state.get("scan_non_filtered_seen") or 0)
                scan_seq_limit = int(cfg.seq_limit)
                if scan_seen >= scan_seq_limit:
                    exit_state["scan_stop_limit"] = True
                    stop_evt.set()
                    forced_stop = True
                    forced_reason = "limit"
                    break
            except Exception:
                pass
            now = time.monotonic()
            if now >= scan_stale_check_next_at:
                scan_stale_check_next_at = now + float(scan_stale_check_interval_seconds)
                try:
                    cur_seq = int(exit_state.get("scan_non_filtered_seen") or 0)
                except Exception:
                    cur_seq = None
                if cur_seq is None:
                    scan_stale_rounds = 0
                elif scan_last_seq is None or int(cur_seq) != int(scan_last_seq):
                    scan_stale_rounds = 0
                else:
                    scan_stale_rounds += 1
                scan_last_seq = cur_seq
                if int(scan_stale_rounds) >= 3:
                    stop_evt.set()
                    forced_stop = True
                    forced_reason = "stale"
                    break
            await asyncio.sleep(0.1)
        if forced_stop and not done_evt.is_set():
            logger.info(
                "producer_forced_stop_request",
                reason=(forced_reason or "unknown"),
                scan_seq=int(exit_state.get("scan_seq") or 0),
                scan_non_filtered_seen=int(exit_state.get("scan_non_filtered_seen") or 0),
                scan_seq_limit=int(cfg.seq_limit),
                scan_stale_rounds=int(scan_stale_rounds),
            )
            while not done_evt.is_set():
                await asyncio.sleep(0.1)
        exit_state["producer_done"] = True
        logger.info("producer_exit")

    async def _flush_with_sem(**kwargs):
        async with llm_sem:
            try:
                return await _flush_buffer(**kwargs)
            except Exception as exc:
                logger_local = kwargs.get("logger")
                if logger_local is not None:
                    logger_local.warning(
                        "buffer_flush_failed",
                        prompt_index=int(kwargs.get("llm_call_index") or 0),
                        error=str(exc),
                        traceback=traceback.format_exc(),
                    )
                raise

    slot_count = max(1, int(cfg.buffer_count))
    sql_slot_count = max(1, int(cfg.sql_buffer_count))
    xss_slot_count = max(1, int(cfg.xss_buffer_count))
    cmd_slot_count = max(1, int(cfg.cmd_buffer_count))
    available_slots: asyncio.Queue = asyncio.Queue()
    sql_available_slots: asyncio.Queue = asyncio.Queue()
    xss_available_slots: asyncio.Queue = asyncio.Queue()
    cmd_available_slots: asyncio.Queue = asyncio.Queue()
    for i in range(slot_count):
        available_slots.put_nowait(
            {"id": i + 1, "buffer": PromptBuffer(token_limit=cfg.buffer_token_limit), "sections": []}
        )
    for i in range(sql_slot_count):
        sql_available_slots.put_nowait(
            {"id": i + 1, "buffer": PromptBuffer(token_limit=cfg.sql_buffer_token_limit), "sections": []}
        )
    for i in range(xss_slot_count):
        xss_available_slots.put_nowait(
            {"id": i + 1, "buffer": PromptBuffer(token_limit=cfg.xss_buffer_token_limit), "sections": []}
        )
    for i in range(cmd_slot_count):
        cmd_available_slots.put_nowait(
            {"id": i + 1, "buffer": PromptBuffer(token_limit=cfg.cmd_buffer_token_limit), "sections": []}
        )
    flush_index = 0
    sql_flush_index = 0
    xss_flush_index = 0
    cmd_flush_index = 0

    async def _flush_slot(slot: dict, sections: List[dict], prompt_index: int):
        flush_result = await _flush_with_sem(
            sections=sections,
            separator="====",
            test_mode=cfg.test_mode,
            analyze_llm_test_mode=cfg.analyze_llm_test_mode,
            base_prompt="",
            prompt_builder=build_prompt,
            prompt_prefix="prompt_",
            sql_mode=False,
            xss_mode=False,
            cmd_mode=False,
            branch_random=cfg.branch_random,
            prompt_out_dir=prompt_out_dir,
            response_out_dir=response_out_dir,
            llm_client=llm_client,
            llm_temperature=cfg.llm_temperature,
            llm_max_attempts=cfg.llm_max_attempts,
            llm_call_index=prompt_index,
            analyze_sem=analyze_sem,
            analyze_tasks=pending_analyze_tasks,
            if_loc_by_seq=if_loc_by_seq,
            remaining_seeds=int(remaining_seeds),
            emit_items=emit_items,
            logger=logger,
        )
        flush_status = str((flush_result or {}).get("status") or "")
        clear_buffer = bool((flush_result or {}).get("clear_buffer"))
        if logger is not None:
            logger.info(
                "buffer_flush_finalized",
                kind="if",
                buffer_id=int(slot.get("id") or 0),
                prompt_index=int(prompt_index),
                sections=len(sections or []),
                flush_status=str(flush_status or ""),
                clear_buffer=bool(clear_buffer),
            )
        if not clear_buffer:
            raise RuntimeError("buffer flush ended without terminal clearable state")
        slot["sections"].clear()
        slot["buffer"].clear()
        await available_slots.put(slot)

    async def _flush_sql_slot(slot: dict, sections: List[dict], prompt_index: int):
        flush_result = await _flush_with_sem(
            sections=sections,
            separator="====",
            test_mode=cfg.test_mode,
            analyze_llm_test_mode=cfg.analyze_llm_test_mode,
            base_prompt=cfg.base_prompt,
            prompt_builder=build_sql_prompt,
            prompt_prefix="sql_prompt_",
            sql_mode=True,
            xss_mode=False,
            cmd_mode=False,
            branch_random=cfg.branch_random,
            prompt_out_dir=prompt_out_dir,
            response_out_dir=response_out_dir,
            llm_client=llm_client,
            llm_temperature=cfg.llm_temperature,
            llm_max_attempts=cfg.llm_max_attempts,
            llm_call_index=prompt_index,
            analyze_sem=analyze_sem,
            analyze_tasks=pending_analyze_tasks,
            if_loc_by_seq=if_loc_by_seq,
            remaining_seeds=int(remaining_seeds),
            emit_items=emit_items,
            logger=logger,
        )
        flush_status = str((flush_result or {}).get("status") or "")
        clear_buffer = bool((flush_result or {}).get("clear_buffer"))
        if logger is not None:
            logger.info(
                "buffer_flush_finalized",
                kind="sql",
                buffer_id=int(slot.get("id") or 0),
                prompt_index=int(prompt_index),
                sections=len(sections or []),
                flush_status=str(flush_status or ""),
                clear_buffer=bool(clear_buffer),
            )
        if not clear_buffer:
            raise RuntimeError("buffer flush ended without terminal clearable state")
        slot["sections"].clear()
        slot["buffer"].clear()
        await sql_available_slots.put(slot)

    async def _flush_xss_slot(slot: dict, sections: List[dict], prompt_index: int):
        flush_result = await _flush_with_sem(
            sections=sections,
            separator="====",
            test_mode=cfg.test_mode,
            analyze_llm_test_mode=cfg.analyze_llm_test_mode,
            base_prompt=cfg.base_prompt,
            prompt_builder=build_xss_prompt,
            prompt_prefix="xss_prompt_",
            sql_mode=False,
            xss_mode=True,
            cmd_mode=False,
            branch_random=cfg.branch_random,
            prompt_out_dir=prompt_out_dir,
            response_out_dir=response_out_dir,
            llm_client=llm_client,
            llm_temperature=cfg.llm_temperature,
            llm_max_attempts=cfg.llm_max_attempts,
            llm_call_index=prompt_index,
            analyze_sem=analyze_sem,
            analyze_tasks=pending_analyze_tasks,
            if_loc_by_seq=if_loc_by_seq,
            remaining_seeds=int(remaining_seeds),
            emit_items=emit_items,
            logger=logger,
        )
        flush_status = str((flush_result or {}).get("status") or "")
        clear_buffer = bool((flush_result or {}).get("clear_buffer"))
        if logger is not None:
            logger.info(
                "buffer_flush_finalized",
                kind="xss",
                buffer_id=int(slot.get("id") or 0),
                prompt_index=int(prompt_index),
                sections=len(sections or []),
                flush_status=str(flush_status or ""),
                clear_buffer=bool(clear_buffer),
            )
        if not clear_buffer:
            raise RuntimeError("buffer flush ended without terminal clearable state")
        slot["sections"].clear()
        slot["buffer"].clear()
        await xss_available_slots.put(slot)

    async def _flush_cmd_slot(slot: dict, sections: List[dict], prompt_index: int):
        flush_result = await _flush_with_sem(
            sections=sections,
            separator="====",
            test_mode=cfg.test_mode,
            analyze_llm_test_mode=cfg.analyze_llm_test_mode,
            base_prompt=cfg.base_prompt,
            prompt_builder=build_cmd_prompt,
            prompt_prefix="cmd_prompt_",
            sql_mode=False,
            xss_mode=False,
            cmd_mode=True,
            branch_random=cfg.branch_random,
            prompt_out_dir=prompt_out_dir,
            response_out_dir=response_out_dir,
            llm_client=llm_client,
            llm_temperature=cfg.llm_temperature,
            llm_max_attempts=cfg.llm_max_attempts,
            llm_call_index=prompt_index,
            analyze_sem=analyze_sem,
            analyze_tasks=pending_analyze_tasks,
            if_loc_by_seq=if_loc_by_seq,
            remaining_seeds=int(remaining_seeds),
            emit_items=emit_items,
            logger=logger,
        )
        flush_status = str((flush_result or {}).get("status") or "")
        clear_buffer = bool((flush_result or {}).get("clear_buffer"))
        if logger is not None:
            logger.info(
                "buffer_flush_finalized",
                kind="cmd",
                buffer_id=int(slot.get("id") or 0),
                prompt_index=int(prompt_index),
                sections=len(sections or []),
                flush_status=str(flush_status or ""),
                clear_buffer=bool(clear_buffer),
            )
        if not clear_buffer:
            raise RuntimeError("buffer flush ended without terminal clearable state")
        slot["sections"].clear()
        slot["buffer"].clear()
        await cmd_available_slots.put(slot)

    async def _dispatch_slot(slot: dict):
        nonlocal flush_index
        flush_index += 1
        sections_to_flush = list(slot["sections"])
        task = _create_task(_flush_slot(slot, sections_to_flush, flush_index))
        _track_task(
            pending_llm_tasks,
            task,
            logger=logger,
            event="buffer_flush_task_start",
            buffer_id=int(slot.get("id") or 0),
            prompt_index=flush_index,
            sections=len(sections_to_flush),
        )

    async def _dispatch_sql_slot(slot: dict):
        nonlocal sql_flush_index
        sql_flush_index += 1
        sections_to_flush = list(slot["sections"])
        task = _create_task(_flush_sql_slot(slot, sections_to_flush, sql_flush_index))
        _track_task(
            pending_llm_tasks,
            task,
            logger=logger,
            event="buffer_flush_task_start",
            buffer_id=int(slot.get("id") or 0),
            prompt_index=sql_flush_index,
            sections=len(sections_to_flush),
        )

    async def _dispatch_xss_slot(slot: dict):
        nonlocal xss_flush_index
        xss_flush_index += 1
        sections_to_flush = list(slot["sections"])
        task = _create_task(_flush_xss_slot(slot, sections_to_flush, xss_flush_index))
        _track_task(
            pending_llm_tasks,
            task,
            logger=logger,
            event="buffer_flush_task_start",
            buffer_id=int(slot.get("id") or 0),
            prompt_index=xss_flush_index,
            sections=len(sections_to_flush),
        )

    async def _dispatch_cmd_slot(slot: dict):
        nonlocal cmd_flush_index
        cmd_flush_index += 1
        sections_to_flush = list(slot["sections"])
        task = _create_task(_flush_cmd_slot(slot, sections_to_flush, cmd_flush_index))
        _track_task(
            pending_llm_tasks,
            task,
            logger=logger,
            event="buffer_flush_task_start",
            buffer_id=int(slot.get("id") or 0),
            prompt_index=cmd_flush_index,
            sections=len(sections_to_flush),
        )

    async def consumer():
        last_sig = None
        folder = ScopeSubsetFolder()
        slot = await available_slots.get()
        while True:
            item = await sections_queue.get()
            if item is done_sentinel:
                for emit in folder.flush():
                    sec = format_section(int(emit.get("seq")), emit.get("lines") or [], mark_seqs=emit.get("mark_seqs"), logger=logger)
                    sec_text = build_prompt(sections=[sec], separator="====", base_prompt=cfg.base_prompt, logger=logger)
                    if not slot["buffer"].can_add(sec_text) and slot["sections"]:
                        await _dispatch_slot(slot)
                        slot = await available_slots.get()
                    slot["sections"].append(sec)
                    slot["buffer"].add(sec, sec_text)
                if slot["sections"]:
                    await _dispatch_slot(slot)
                else:
                    await available_slots.put(slot)
                break
            sig = item.get("sig")
            if sig is None:
                last_sig = None
            else:
                if last_sig is not None and sig == last_sig:
                    continue
                last_sig = sig
            if not item.get("mark_seqs"):
                item["mark_seqs"] = [item.get("seq")]
            emits = folder.push(item)
            for emit in emits:
                sec = format_section(int(emit.get("seq")), emit.get("lines") or [], mark_seqs=emit.get("mark_seqs"), logger=logger)
                sec_text = build_prompt(sections=[sec], separator="====", base_prompt=cfg.base_prompt, logger=logger)
                if not slot["buffer"].can_add(sec_text) and slot["sections"]:
                    await _dispatch_slot(slot)
                    slot = await available_slots.get()
                slot["sections"].append(sec)
                slot["buffer"].add(sec, sec_text)
        exit_state["if_done"] = True
        logger.info("consumer_done", kind="if")

    async def sql_consumer():
        last_sig = None
        folder = ScopeSubsetFolder()
        slot = await sql_available_slots.get()
        while True:
            item = await sql_sections_queue.get()
            if item is done_sentinel:
                for emit in folder.flush():
                    sec = format_sql_section(int(emit.get("seq")), emit.get("lines") or [], mark_seqs=emit.get("mark_seqs"), logger=logger)
                    sec_text = build_sql_prompt(sections=[sec], separator="====", base_prompt="", logger=logger)
                    if not slot["buffer"].can_add(sec_text) and slot["sections"]:
                        await _dispatch_sql_slot(slot)
                        slot = await sql_available_slots.get()
                    slot["sections"].append(sec)
                    slot["buffer"].add(sec, sec_text)
                if slot["sections"]:
                    await _dispatch_sql_slot(slot)
                else:
                    await sql_available_slots.put(slot)
                break
            sig = item.get("sig")
            if sig is None:
                last_sig = None
            else:
                if last_sig is not None and sig == last_sig:
                    continue
                last_sig = sig
            if not item.get("mark_seqs"):
                item["mark_seqs"] = [item.get("seq")]
            emits = folder.push(item)
            for emit in emits:
                sec = format_sql_section(int(emit.get("seq")), emit.get("lines") or [], mark_seqs=emit.get("mark_seqs"), logger=logger)
                sec_text = build_sql_prompt(sections=[sec], separator="====", base_prompt="", logger=logger)
                if not slot["buffer"].can_add(sec_text) and slot["sections"]:
                    await _dispatch_sql_slot(slot)
                    slot = await sql_available_slots.get()
                slot["sections"].append(sec)
                slot["buffer"].add(sec, sec_text)
        exit_state["sql_done"] = True
        logger.info("consumer_done", kind="sql")

    async def xss_consumer():
        last_sig = None
        folder = ScopeSubsetFolder()
        slot = await xss_available_slots.get()
        while True:
            item = await xss_sections_queue.get()
            if item is done_sentinel:
                for emit in folder.flush():
                    sec = format_xss_section(int(emit.get("seq")), emit.get("lines") or [], mark_seqs=emit.get("mark_seqs"), logger=logger)
                    sec_text = build_xss_prompt(sections=[sec], separator="====", base_prompt="", logger=logger)
                    if not slot["buffer"].can_add(sec_text) and slot["sections"]:
                        await _dispatch_xss_slot(slot)
                        slot = await xss_available_slots.get()
                    slot["sections"].append(sec)
                    slot["buffer"].add(sec, sec_text)
                if slot["sections"]:
                    await _dispatch_xss_slot(slot)
                else:
                    await xss_available_slots.put(slot)
                break
            sig = item.get("sig")
            if sig is None:
                last_sig = None
            else:
                if last_sig is not None and sig == last_sig:
                    continue
                last_sig = sig
            if not item.get("mark_seqs"):
                item["mark_seqs"] = [item.get("seq")]
            emits = folder.push(item)
            for emit in emits:
                sec = format_xss_section(int(emit.get("seq")), emit.get("lines") or [], mark_seqs=emit.get("mark_seqs"), logger=logger)
                sec_text = build_xss_prompt(sections=[sec], separator="====", base_prompt="", logger=logger)
                if not slot["buffer"].can_add(sec_text) and slot["sections"]:
                    await _dispatch_xss_slot(slot)
                    slot = await xss_available_slots.get()
                slot["sections"].append(sec)
                slot["buffer"].add(sec, sec_text)
        exit_state["xss_done"] = True
        logger.info("consumer_done", kind="xss")

    async def cmd_consumer():
        last_sig = None
        folder = ScopeSubsetFolder()
        slot = await cmd_available_slots.get()
        while True:
            item = await cmd_sections_queue.get()
            if item is done_sentinel:
                for emit in folder.flush():
                    sec = format_cmd_section(int(emit.get("seq")), emit.get("lines") or [], mark_seqs=emit.get("mark_seqs"), logger=logger)
                    sec_text = build_cmd_prompt(sections=[sec], separator="====", base_prompt="", logger=logger)
                    if not slot["buffer"].can_add(sec_text) and slot["sections"]:
                        await _dispatch_cmd_slot(slot)
                        slot = await cmd_available_slots.get()
                    slot["sections"].append(sec)
                    slot["buffer"].add(sec, sec_text)
                if slot["sections"]:
                    await _dispatch_cmd_slot(slot)
                else:
                    await cmd_available_slots.put(slot)
                break
            sig = item.get("sig")
            if sig is None:
                last_sig = None
            else:
                if last_sig is not None and sig == last_sig:
                    continue
                last_sig = sig
            if not item.get("mark_seqs"):
                item["mark_seqs"] = [item.get("seq")]
            emits = folder.push(item)
            for emit in emits:
                sec = format_cmd_section(int(emit.get("seq")), emit.get("lines") or [], mark_seqs=emit.get("mark_seqs"), logger=logger)
                sec_text = build_cmd_prompt(sections=[sec], separator="====", base_prompt="", logger=logger)
                if not slot["buffer"].can_add(sec_text) and slot["sections"]:
                    await _dispatch_cmd_slot(slot)
                    slot = await cmd_available_slots.get()
                slot["sections"].append(sec)
                slot["buffer"].add(sec, sec_text)
        exit_state["cmd_done"] = True
        logger.info("consumer_done", kind="cmd")

    async def trace_master_watchdog():
        nonlocal trace_master_handle
        if not bool((os.environ.get("SYMEX_SHARED_MEMORY_ENABLED") or "").strip() in ("1", "true", "TRUE", "yes", "on")):
            return
        while not bool(watchdog_stop.get("stop")):
            if os.path.exists(_pipeline_restart_request_path()) or _pipeline_trace_master_unhealthy():
                reason = "request_file" if os.path.exists(_pipeline_restart_request_path()) else "healthcheck_failed"
                logger.warning("pipeline_trace_master_restart_begin", reason=reason)
                trace_master_handle = _restart_pipeline_trace_master_with_retry(
                    cfg=app_cfg,
                    trace_path=trace_path,
                    trace_index_path=trace_index_path,
                    max_workers=int(cfg.max_analyze_concurrency),
                    logger=logger,
                    current_handle=trace_master_handle,
                    max_attempts=int(restart_limit),
                    restart_reason=reason,
                )
            await asyncio.sleep(1.0)

    try:
        watchdog_task = _create_task(trace_master_watchdog())
        await asyncio.gather(producer(), consumer(), sql_consumer(), xss_consumer(), cmd_consumer())
        if logger is not None:
            logger.info(
                "consumer_gather_done",
                pending_llm_tasks=int(len(pending_llm_tasks)),
                pending_analyze_tasks=int(len(pending_analyze_tasks)),
                exit_state=dict(exit_state or {}),
            )
            _write_flush_debug_state(
                logger=logger,
                prompt_prefix="pipeline",
                prompt_index=0,
                phase="waiting_pending_llm_tasks",
                extra={
                    "pending_llm_tasks": int(len(pending_llm_tasks)),
                    "pending_analyze_tasks": int(len(pending_analyze_tasks)),
                    "exit_state": dict(exit_state or {}),
                },
            )
        await _await_task_set(pending_llm_tasks, logger=logger, task_kind="llm")
        if logger is not None:
            logger.info(
                "pending_llm_tasks_done",
                pending_llm_tasks=int(len(pending_llm_tasks)),
                pending_analyze_tasks=int(len(pending_analyze_tasks)),
            )
        if emit_path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(emit_path)) or ".", exist_ok=True)
            except Exception:
                pass
            try:
                with open(emit_path, "w", encoding="utf-8") as f:
                    json.dump({"items": emit_items or []}, f, ensure_ascii=False, indent=2)
                logger.info("emit_seqs_done", path=emit_path, count=len(emit_items or []))
            except Exception:
                logger.warning("emit_seqs_failed", path=emit_path)
        else:
            await _await_task_set(pending_analyze_tasks, logger=logger, task_kind="analyze")
        watchdog_stop["stop"] = True
        try:
            await asyncio.wait_for(watchdog_task, timeout=2.0)
        except Exception:
            try:
                watchdog_task.cancel()
            except Exception:
                pass
        pipeline_status = "finished"
        pipeline_stage = "pipeline_done"
        pipeline_message = "pipeline completed"
        if heartbeat is not None:
            heartbeat.update(
                "pipeline_done",
                status="finished",
                message="pipeline completed",
                pending_llm_tasks=int(len(pending_llm_tasks)),
                pending_analyze_tasks=int(len(pending_analyze_tasks)),
            )
        logger.info("pipeline_exit")
        logger.info("pipeline_done")
    except Exception as exc:
        pipeline_status = "failed"
        pipeline_stage = "pipeline_failed"
        pipeline_message = str(exc)
        pipeline_error_type = type(exc).__name__
        pipeline_traceback = traceback.format_exc()
        if heartbeat is not None:
            heartbeat.update(
                "pipeline_failed",
                status="failed",
                message=str(exc),
                error_type=str(type(exc).__name__),
            )
        if logger is not None:
            logger.exception("pipeline_failed")
        raise
    finally:
        watchdog_stop["stop"] = True
        if trace_master_handle is not None:
            try:
                from shared_mem.pipeline_trace_master import stop_pipeline_trace_master
            except Exception:
                stop_pipeline_trace_master = None
            if stop_pipeline_trace_master is not None:
                try:
                    stop_pipeline_trace_master(
                        trace_master_handle,
                        logger=logger,
                        caller="branch_selector.pipeline.run_pipeline.finally",
                        reason="pipeline_shutdown",
                    )
                except Exception:
                    logger.exception("pipeline_trace_master_stop_failed")
        _write_branch_selector_process_exit(
            run_dir=run_dir,
            status=pipeline_status,
            stage=pipeline_stage,
            message=pipeline_message,
            error_type=pipeline_error_type,
            traceback_text=pipeline_traceback,
            extra={
                "exit_state": dict(exit_state or {}),
                "trace_master_started": bool(trace_master_handle is not None),
                "test_mode": bool(cfg.test_mode),
                "config_path": str(config_path or "config.json"),
            },
        )
        if heartbeat is not None:
            heartbeat.finish(
                pipeline_status,
                stage=("finished" if pipeline_status == "finished" else pipeline_stage),
                message=(pipeline_message or ("pipeline completed" if pipeline_status == "finished" else "")),
                exit_state=dict(exit_state or {}),
                error_type=pipeline_error_type,
            )


def main():
    cfg_path = None
    if len(sys.argv) > 1:
        for x in sys.argv[1:]:
            if isinstance(x, str) and x.startswith("--"):
                continue
            cfg_path = x
            break
    try:
        reload_if_branch_coverage()
        reload_switch_branch_coverage()
        _asyncio_run(run_pipeline(cfg_path))
    finally:
        _release_self_token()


if __name__ == "__main__":
    main()
