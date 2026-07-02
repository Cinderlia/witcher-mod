"""Candidate lookup phase for the standalone database exploration flow."""

from ..config import DBSearchRuntimeConfig
from ..executor import execute_query_plan, find_fatal_db_execution
from ..debug_log import append_jsonl_event, append_runtime_debug_log
from ..filtering import append_filtered_payload, run_llm_memory_filter, truncate_execution_pairs
from ..llm_gateway import build_phase_prompt, parse_phase_outcome, run_text_llm_call
from ..models import DBSearchState, FilteredQueryPayload, PhaseName, RoundTrace


def _can_fallback_to_schema(runtime_cfg: DBSearchRuntimeConfig, state: DBSearchState) -> bool:
    if int(runtime_cfg.candidate_schema_fallback_limit) <= 0:
        return False
    if state.fallback_to_schema_used:
        return False
    if int(state.schema_rounds) >= int(runtime_cfg.schema_round_limit):
        return False
    return True


def run_candidate_lookup_phase(runtime_cfg: DBSearchRuntimeConfig, state: DBSearchState) -> DBSearchState:
    """Run candidate lookup rounds and allow at most one fallback to schema discovery."""
    append_jsonl_event(
        run_dir=state.run_dir,
        stream="events",
        payload={
            "kind": "phase_start",
            "phase": PhaseName.CANDIDATE_LOOKUP,
            "candidate_rounds": int(state.candidate_rounds or 0),
            "schema_rounds": int(state.schema_rounds or 0),
            "schema_pair_count": len(state.schema_raw_pairs or []),
        },
    )
    while state.candidate_rounds < int(runtime_cfg.candidate_round_limit) and not state.candidate_found:
        round_index = int(state.candidate_rounds) + 1
        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="candidate round %02d start" % int(round_index),
        )
        prompt_text = build_phase_prompt(PhaseName.CANDIDATE_LOOKUP, state)
        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="candidate round %02d prompt built" % int(round_index),
        )
        response_text = run_text_llm_call(
            prompt_text,
            run_dir=state.run_dir,
            phase=PhaseName.CANDIDATE_LOOKUP,
            round_index=round_index,
            role="phase_planner",
        )
        outcome = parse_phase_outcome(response_text, phase=PhaseName.CANDIDATE_LOOKUP)
        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="candidate round %02d outcome parsed: queries=%d completed=%s fallback=%s" % (
                int(round_index),
                len(outcome.query_plans or []),
                str(bool(outcome.completed)),
                str(bool(outcome.request_schema_fallback)),
            ),
        )

        executions = []
        filtered_payloads = []
        for plan in outcome.query_plans or []:
            if isinstance(getattr(plan, "metadata", None), dict):
                plan.metadata["round_index"] = int(round_index)
            execution = execute_query_plan(plan, runtime_cfg, phase=PhaseName.CANDIDATE_LOOKUP, artifact_run_dir=state.run_dir)
            executions.append(execution)
        fatal = find_fatal_db_execution(executions)
        if fatal:
            state.candidate_rounds = round_index
            state.fatal_error = str(fatal.get("error") or "")
            state.fatal_error_detail = dict(fatal)
            state.final_output = {"error": state.fatal_error, "fatal_error_detail": dict(fatal)}
            append_jsonl_event(
                run_dir=state.run_dir,
                stream="errors",
                payload={
                    "kind": "fatal_db_runtime_error",
                    "phase": PhaseName.CANDIDATE_LOOKUP,
                    "round_index": int(round_index),
                    "detail": dict(fatal),
                },
            )
            state.round_traces.append(
                RoundTrace(
                    phase=PhaseName.CANDIDATE_LOOKUP,
                    round_index=round_index,
                    prompt_text=prompt_text,
                    llm_response_text=response_text,
                    executions=executions,
                    filtered_payloads=[],
                )
            )
            break
        if executions:
            round_payload = FilteredQueryPayload(
                phase=PhaseName.CANDIDATE_LOOKUP,
                overall_goal=state.goal.summary,
                goal=state.goal.candidate_goal or state.goal.summary,
                query_result_pairs=truncate_execution_pairs(executions, limit=10, row_limit=10),
            )
            filtered_payloads.append(round_payload)
            append_filtered_payload(state, round_payload)
            state.candidate_raw_pairs.extend(truncate_execution_pairs(executions, limit=50, row_limit=10))
            append_jsonl_event(
                run_dir=state.run_dir,
                stream="events",
                payload={
                    "kind": "candidate_round_results_accumulated",
                    "phase": PhaseName.CANDIDATE_LOOKUP,
                    "round_index": int(round_index),
                    "accumulated_pair_count": len(state.candidate_raw_pairs or []),
                },
            )

        state.candidate_rounds = round_index
        state.round_traces.append(
            RoundTrace(
                phase=PhaseName.CANDIDATE_LOOKUP,
                round_index=round_index,
                prompt_text=prompt_text,
                llm_response_text=response_text,
                executions=executions,
                filtered_payloads=filtered_payloads,
            )
        )

        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="candidate round %02d execution batch done: executions=%d" % (int(round_index), len(executions or [])),
        )
        if outcome.request_schema_fallback and _can_fallback_to_schema(runtime_cfg, state):
            state.fallback_to_schema_used = True
            state.current_phase = PhaseName.SCHEMA_DISCOVERY
            return state
        if outcome.completed:
            state.candidate_found = True
            break
        if not outcome.query_plans:
            state.candidate_impossible = True
            break

    if state.schema_raw_pairs or state.candidate_raw_pairs:
        source_payloads = []
        if state.schema_raw_pairs:
            source_payloads.append(
                FilteredQueryPayload(
                    phase=PhaseName.SCHEMA_DISCOVERY,
                    overall_goal=state.goal.summary,
                    goal=state.goal.schema_goal or state.goal.summary,
                    query_result_pairs=list(state.schema_raw_pairs[:10]),
                )
            )
        if state.candidate_raw_pairs:
            source_payloads.append(
                FilteredQueryPayload(
                    phase=PhaseName.CANDIDATE_LOOKUP,
                    overall_goal=state.goal.summary,
                    goal=state.goal.candidate_goal or state.goal.summary,
                    query_result_pairs=list(state.candidate_raw_pairs[:10]),
                )
            )
        payload = run_llm_memory_filter(
            state.goal.summary,
            state.goal.finalize_goal or state.goal.summary,
            source_payloads,
            state,
        )
        payload.phase = PhaseName.FINALIZE
        payload.goal = state.goal.finalize_goal or state.goal.summary
        state.finalize_context_payloads = [payload]

    state.current_phase = PhaseName.FINALIZE
    return state
