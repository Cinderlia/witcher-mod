"""Standalone four-round database exploration orchestrator."""

import traceback

from .config import DBSearchRuntimeConfig, build_db_search_run_dir, load_db_search_runtime_config
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
    runtime_cfg = load_db_search_runtime_config(config_path=(config_path or request.config_path or None))
    state = initialize_db_search_state(request, runtime_cfg)
    try:
        state = run_goal_abstraction_phase(request, state)
        if state.fatal_error:
            return state
        state = run_schema_discovery_phase(runtime_cfg, state)
        if state.fatal_error:
            return state
        state = run_candidate_lookup_phase(runtime_cfg, state)
        if state.fatal_error:
            return state

        if state.current_phase == PhaseName.SCHEMA_DISCOVERY and state.fallback_to_schema_used:
            state = run_schema_discovery_phase(runtime_cfg, state)
            if state.fatal_error:
                return state
            state = run_candidate_lookup_phase(runtime_cfg, state)
            if state.fatal_error:
                return state

        if state.current_phase != PhaseName.FINALIZE:
            state.current_phase = PhaseName.FINALIZE
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
