"""Schema discovery phase for the standalone database exploration flow."""

from ..config import DBSearchRuntimeConfig
from ..executor import execute_query_plan, find_fatal_db_execution
from ..debug_log import append_jsonl_event, append_runtime_debug_log
from ..filtering import append_filtered_payload, truncate_execution_pairs
from ..llm_gateway import build_phase_prompt, parse_phase_outcome, run_text_llm_call
from ..models import DBSearchState, FilteredQueryPayload, PhaseName, RoundTrace


def run_schema_discovery_phase(runtime_cfg: DBSearchRuntimeConfig, state: DBSearchState) -> DBSearchState:
    """Run up to five schema-discovery rounds without fallback."""
    while state.schema_rounds < int(runtime_cfg.schema_round_limit) and not state.schema_identified:
        round_index = int(state.schema_rounds) + 1
        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="schema round %02d start" % int(round_index),
        )
        prompt_text = build_phase_prompt(PhaseName.SCHEMA_DISCOVERY, state)
        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="schema round %02d prompt built" % int(round_index),
        )
        response_text = run_text_llm_call(
            prompt_text,
            run_dir=state.run_dir,
            phase=PhaseName.SCHEMA_DISCOVERY,
            round_index=round_index,
            role="phase_planner",
        )
        outcome = parse_phase_outcome(response_text, phase=PhaseName.SCHEMA_DISCOVERY)
        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="schema round %02d outcome parsed: queries=%d completed=%s" % (
                int(round_index),
                len(outcome.query_plans or []),
                str(bool(outcome.completed)),
            ),
        )

        executions = []
        filtered_payloads = []
        for plan in outcome.query_plans or []:
            if isinstance(getattr(plan, "metadata", None), dict):
                plan.metadata["round_index"] = int(round_index)
            execution = execute_query_plan(plan, runtime_cfg, phase=PhaseName.SCHEMA_DISCOVERY, artifact_run_dir=state.run_dir)
            executions.append(execution)
        fatal = find_fatal_db_execution(executions)
        if fatal:
            state.schema_rounds = round_index
            state.fatal_error = str(fatal.get("error") or "")
            state.fatal_error_detail = dict(fatal)
            state.final_output = {"error": state.fatal_error, "fatal_error_detail": dict(fatal)}
            append_jsonl_event(
                run_dir=state.run_dir,
                stream="errors",
                payload={
                    "kind": "fatal_db_runtime_error",
                    "phase": PhaseName.SCHEMA_DISCOVERY,
                    "round_index": int(round_index),
                    "detail": dict(fatal),
                },
            )
            state.round_traces.append(
                RoundTrace(
                    phase=PhaseName.SCHEMA_DISCOVERY,
                    round_index=round_index,
                    prompt_text=prompt_text,
                    llm_response_text=response_text,
                    executions=executions,
                    filtered_payloads=[],
                )
            )
            break
        if executions:
            state.schema_raw_pairs.extend(truncate_execution_pairs(executions, limit=50, row_limit=10))
            append_jsonl_event(
                run_dir=state.run_dir,
                stream="events",
                payload={
                    "kind": "schema_round_results_accumulated",
                    "phase": PhaseName.SCHEMA_DISCOVERY,
                    "round_index": int(round_index),
                    "accumulated_pair_count": len(state.schema_raw_pairs or []),
                },
            )

        state.schema_rounds = round_index
        state.round_traces.append(
            RoundTrace(
                phase=PhaseName.SCHEMA_DISCOVERY,
                round_index=round_index,
                prompt_text=prompt_text,
                llm_response_text=response_text,
                executions=executions,
                filtered_payloads=filtered_payloads,
            )
        )
        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="schema round %02d execution batch done: executions=%d" % (int(round_index), len(executions or [])),
        )
        for item in outcome.findings or []:
            if item and item not in state.schema_findings:
                state.schema_findings.append(item)
        if outcome.completed:
            state.schema_identified = True
            break
        if not outcome.query_plans:
            break

    if state.schema_raw_pairs:
        payload = FilteredQueryPayload(
            phase=PhaseName.SCHEMA_DISCOVERY,
            overall_goal=state.goal.summary,
            goal=state.goal.schema_goal or state.goal.summary,
            query_result_pairs=list(state.schema_raw_pairs[:10]),
        )
        append_filtered_payload(state, payload)

    append_jsonl_event(
        run_dir=state.run_dir,
        stream="events",
        payload={
            "kind": "phase_transition",
            "from_phase": PhaseName.SCHEMA_DISCOVERY,
            "to_phase": PhaseName.CANDIDATE_LOOKUP,
            "schema_rounds": int(state.schema_rounds or 0),
            "schema_identified": bool(state.schema_identified),
        },
    )
    state.current_phase = PhaseName.CANDIDATE_LOOKUP
    return state
