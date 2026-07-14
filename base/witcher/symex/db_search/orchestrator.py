"""Standalone four-round database exploration orchestrator."""

import os
import signal
import traceback

from .config import DBSearchRuntimeConfig, build_db_search_run_dir, load_db_search_runtime_config
from .db_recover import start_db_recover_daemon
from .debug_log import append_jsonl_event, append_runtime_debug_log
from .models import DBSearchRequest, DBSearchState, PhaseName
from .phases.bootstrap import run_goal_abstraction_phase
from .phases.candidate import run_candidate_lookup_phase
from .phases.finalize import run_finalize_phase
from .phases.schema import run_schema_discovery_phase


def initialize_db_search_state(request: DBSearchRequest, runtime_cfg: DBSearchRuntimeConfig) -> DBSearchState:
    """Create the mutable state object used across the standalone DB search run."""
    state = DBSearchState()
    state.context = request.context
    state.schema_round_limit = int(runtime_cfg.schema_round_limit)
    state.candidate_schema_fallback_limit = int(runtime_cfg.candidate_schema_fallback_limit)
    state.todo_notes.append("TODO: wire transaction-aware rollback daemon into standalone runner")
    state.todo_notes.append("TODO: persist per-round prompts, responses, and filtered DB payloads")
    request.run_dir = build_db_search_run_dir(runtime_cfg, request.run_dir)
    state.run_dir = request.run_dir or ""
    append_jsonl_event(
        run_dir=state.run_dir,
        stream="events",
        payload={
            "kind": "state_initialized",
            "source_component": str(request.source_component or ""),
            "trigger_reason": str(request.trigger_reason or ""),
            "target_seq": state.context.target_seq,
            "target_loc": state.context.target_loc,
        },
    )
    return state


def run_db_search_pipeline(request: DBSearchRequest, *, config_path: str = "") -> DBSearchState:
    """Run the standalone four-round database exploration pipeline."""
    interrupted = {"flag": False, "signal": ""}
    prev_sigint = None
    prev_sigterm = None

    def _mark_interrupted(signum, frame):
        interrupted["flag"] = True
        interrupted["signal"] = "SIGINT" if int(signum) == int(signal.SIGINT) else "SIGTERM"

    try:
        prev_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, _mark_interrupted)
    except Exception:
        prev_sigint = None
    try:
        prev_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, _mark_interrupted)
    except Exception:
        prev_sigterm = None

    runtime_cfg = load_db_search_runtime_config(config_path=(config_path or request.config_path or None))
    state = initialize_db_search_state(request, runtime_cfg)
    recover_daemon = None
    work_dir = ""
    if state.run_dir:
        marker = os.path.normpath(os.path.join("symex_runtime", "runs"))
        run_norm = os.path.normpath(os.path.abspath(state.run_dir))
        idx = run_norm.find(marker)
        if idx >= 0:
            work_dir = run_norm[:idx].rstrip("\\/")
    if work_dir:
        try:
            recover_daemon = start_db_recover_daemon(runtime_cfg, work_dir)
        except Exception as ex:
            append_jsonl_event(
                run_dir=state.run_dir,
                stream="errors",
                payload={
                    "kind": "db_recover_daemon_start_failed",
                    "error": str(ex),
                    "work_dir": work_dir,
                },
            )
    try:
        if interrupted["flag"]:
            raise KeyboardInterrupt(interrupted["signal"] or "interrupt")
        state = run_goal_abstraction_phase(request, state)
        if state.fatal_error:
            return state
        if interrupted["flag"]:
            raise KeyboardInterrupt(interrupted["signal"] or "interrupt")
        state = run_schema_discovery_phase(runtime_cfg, state)
        if state.fatal_error:
            return state
        if interrupted["flag"]:
            raise KeyboardInterrupt(interrupted["signal"] or "interrupt")
        state = run_candidate_lookup_phase(runtime_cfg, state)
        if state.fatal_error:
            return state

        if state.current_phase == PhaseName.SCHEMA_DISCOVERY and state.fallback_to_schema_used:
            if interrupted["flag"]:
                raise KeyboardInterrupt(interrupted["signal"] or "interrupt")
            state = run_schema_discovery_phase(runtime_cfg, state)
            if state.fatal_error:
                return state
            if interrupted["flag"]:
                raise KeyboardInterrupt(interrupted["signal"] or "interrupt")
            state = run_candidate_lookup_phase(runtime_cfg, state)
            if state.fatal_error:
                return state

        if state.current_phase != PhaseName.FINALIZE:
            state.current_phase = PhaseName.FINALIZE
        if interrupted["flag"]:
            raise KeyboardInterrupt(interrupted["signal"] or "interrupt")
        state = run_finalize_phase(runtime_cfg, state)
        append_jsonl_event(
            run_dir=state.run_dir,
            stream="events",
            payload={
                "kind": "pipeline_finished",
                "current_phase": str(state.current_phase or ""),
                "schema_rounds": int(state.schema_rounds or 0),
                "candidate_rounds": int(state.candidate_rounds or 0),
                "finalize_rounds": int(state.finalize_rounds or 0),
                "output_ready": bool(state.output_ready),
                "candidate_found": bool(state.candidate_found),
                "candidate_impossible": bool(state.candidate_impossible),
            },
        )
        return state
    except KeyboardInterrupt as ex:
        detail = {
            "kind": "pipeline_interrupted",
            "phase": str(getattr(state, "current_phase", "") or ""),
            "signal": str(ex or interrupted.get("signal") or "SIGINT"),
        }
        state.fatal_error = "interrupted"
        state.fatal_error_detail = detail
        state.final_output = {"error": state.fatal_error, "fatal_error_detail": detail}
        append_jsonl_event(
            run_dir=state.run_dir,
            stream="errors",
            payload=detail,
        )
        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="pipeline interrupted in %s by %s" % (str(getattr(state, "current_phase", "") or "unknown"), str(ex or interrupted.get("signal") or "SIGINT")),
        )
        return state
    except Exception as ex:
        detail = {
            "kind": "pipeline_unhandled_exception",
            "phase": str(getattr(state, "current_phase", "") or ""),
            "error": str(ex),
            "traceback": traceback.format_exc(),
        }
        state.fatal_error = str(ex)
        state.fatal_error_detail = detail
        state.final_output = {"error": state.fatal_error, "fatal_error_detail": detail}
        append_jsonl_event(
            run_dir=state.run_dir,
            stream="errors",
            payload=detail,
        )
        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="pipeline unhandled exception in %s: %s" % (str(getattr(state, "current_phase", "") or "unknown"), str(ex)),
        )
        return state
    finally:
        if recover_daemon is not None:
            try:
                recover_daemon.stop()
            except Exception:
                pass
        try:
            if prev_sigint is not None:
                signal.signal(signal.SIGINT, prev_sigint)
        except Exception:
            pass
        try:
            if prev_sigterm is not None:
                signal.signal(signal.SIGTERM, prev_sigterm)
        except Exception:
            pass
