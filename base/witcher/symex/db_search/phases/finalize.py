"""Finalize/output phase for the standalone database exploration flow."""

import re
import os
import time

from analyze_if_line import _resolve_parent_seed_id_info, _write_external_seeds_from_solutions
from llm_utils.symbolic_runner import load_symbolic_solution_defaults

from ..config import DBSearchRuntimeConfig
from ..debug_log import append_jsonl_event, append_runtime_debug_log
from ..executor import execute_query_plan, find_fatal_db_execution, is_write_query
from ..filtering import append_filtered_payload, truncate_execution_pairs
from ..llm_gateway import build_phase_prompt, parse_phase_outcome, run_text_llm_call
from ..models import DBQueryExecution, DBQueryPlan, DBSearchState, FilteredQueryPayload, PhaseName, RoundTrace


class _FinalizeRetrySQLFailure(object):
    def __init__(self, executions, filtered_payload):
        self.executions = list(executions or [])
        self.filtered_payload = filtered_payload


from ..runtime_bridge import resolve_db_runtime_paths


_FINALIZE_DANGEROUS_SQL_PATTERNS = [
    re.compile(r"\bDROP\b", re.IGNORECASE),
    re.compile(r"\bALTER\b", re.IGNORECASE),
    re.compile(r"\bREVOKE\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\b", re.IGNORECASE),
    re.compile(r"\bGRANT\b", re.IGNORECASE),
    re.compile(r"\bSET\s+GLOBAL\b", re.IGNORECASE),
    re.compile(r"\bKILL\b", re.IGNORECASE),
    re.compile(r"\bUPDATE\s+mysql\.user\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\s+mysql\.user\b", re.IGNORECASE),
    re.compile(r"\bINSERT\s+INTO\s+mysql\.user\b", re.IGNORECASE),
    re.compile(r"\bREPLACE\s+INTO\s+mysql\.user\b", re.IGNORECASE),
    re.compile(r"\bCREATE\s+USER\b", re.IGNORECASE),
    re.compile(r"\bALTER\s+USER\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+USER\b", re.IGNORECASE),
    re.compile(r"\bRENAME\s+USER\b", re.IGNORECASE),
    re.compile(r"\bSET\s+PASSWORD\b", re.IGNORECASE),
    re.compile(r"\bGRANT\s+ALL\s+PRIVILEGES\b", re.IGNORECASE),
]


def _is_finalize_dangerous_sql(sql: str) -> bool:
    sql_s = str(sql or "").strip()
    if not sql_s:
        return False
    for pattern in _FINALIZE_DANGEROUS_SQL_PATTERNS:
        if pattern.search(sql_s):
            return True
    return False


def _filter_finalize_solution_sqls(solution: dict) -> dict:
    if not isinstance(solution, dict):
        return {}
    out = dict(solution)
    sql_value = out.get("SQL")
    if isinstance(sql_value, str):
        out["SQL"] = "" if _is_finalize_dangerous_sql(sql_value) else sql_value
    elif isinstance(sql_value, (list, tuple)):
        filtered = [item for item in sql_value if not _is_finalize_dangerous_sql(str((item if not isinstance(item, dict) else item.get("sql")) or ""))]
        out["SQL"] = filtered
    return out


def _filter_finalize_db_actions(db_actions):
    out = []
    for action in (db_actions or []):
        sql = str((action if isinstance(action, str) else getattr(action, "sql", "")) or "").strip()
        if not sql or _is_finalize_dangerous_sql(sql):
            continue
        out.append(action)
    return out


def _query_allowed_in_finalize(state: DBSearchState) -> bool:
    return (int(state.finalize_rounds) + 1) <= 3


def _load_parent_seed_meta(state: DBSearchState) -> dict:
    try:
        meta_path = os.path.join(state.run_dir, "meta", "parent_seed_info.json")
        if not os.path.isfile(meta_path):
            return {}
        import json
        with open(meta_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _resolve_parent_source_info(state: DBSearchState) -> dict:
    info = _resolve_parent_seed_id_info()
    meta = _load_parent_seed_meta(state)
    source_fuzzer = str(info.get("resolved_source_fuzzer") or meta.get("source_fuzzer") or "unknown").strip() or "unknown"
    parent_seed_id = str(info.get("resolved_parent_seed_id_text") or info.get("resolved_parent_seed_id") or meta.get("seed_id_text") or meta.get("seed_id") or "unknown").strip() or "unknown"
    return {
        "source_fuzzer": source_fuzzer,
        "parent_seed_id": parent_seed_id,
    }


def _resolve_sql_log_dir(runtime_cfg: DBSearchRuntimeConfig, state: DBSearchState) -> str:
    run_dir = os.path.abspath(state.run_dir) if state.run_dir else ""
    work_dir = ""
    if run_dir:
        marker = os.path.normpath(os.path.join("symex_runtime", "runs"))
        run_norm = os.path.normpath(run_dir)
        idx = run_norm.find(marker)
        if idx >= 0:
            work_dir = run_norm[:idx].rstrip("\\/")
    paths = resolve_db_runtime_paths(work_dir=work_dir)
    if paths is not None:
        return paths.runtime_dir
    if work_dir:
        return os.path.join(work_dir, "extsync", "db_runtime")
    return os.path.join(runtime_cfg.app_config.test_dir, "extsync", "db_runtime")


def _archive_sql_mutations(runtime_cfg: DBSearchRuntimeConfig, state: DBSearchState, db_actions, *, seed_id=None, undo_sqls=None) -> list:
    sqls = []
    for action in (db_actions or []):
        if isinstance(action, str):
            sql = str(action).strip()
        else:
            sql = str(getattr(action, "sql", "") or "").strip()
        if sql:
            sqls.append(sql)
    undo_sql_list = []
    for item in (undo_sqls or []):
        sql = str(item or "").strip()
        if sql:
            undo_sql_list.append(sql)
    if not sqls:
        return []
    log_dir = _resolve_sql_log_dir(runtime_cfg, state)
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        return []
    parent_source = _resolve_parent_source_info(state)
    fuzzer_name = str(parent_source.get("source_fuzzer") or "unknown").strip() or "unknown"
    seed_text = str(parent_source.get("parent_seed_id") or "unknown").strip() or "unknown"
    seq = str(state.context.target_seq if state.context.target_seq is not None else "unknown")
    new_seed_text = str(seed_id if seed_id is not None else "unknown").strip() or "unknown"
    safe_fuzzer = re.sub(r"[^A-Za-z0-9_\-]+", "_", fuzzer_name)
    safe_seed = re.sub(r"[^A-Za-z0-9_\-]+", "_", seed_text)
    safe_new_seed = re.sub(r"[^A-Za-z0-9_\-]+", "_", new_seed_text)
    safe_seq = re.sub(r"[^A-Za-z0-9_\-]+", "_", seq)
    file_path = os.path.join(log_dir, "%s_srcid-%s_newid-%s_seq-%s.sql" % (safe_fuzzer, safe_seed, safe_new_seed, safe_seq))
    lines = []
    lines.append("-- fuzzer: " + fuzzer_name)
    lines.append("-- seed_id: " + seed_text)
    lines.append("-- new_seed_id: " + new_seed_text)
    lines.append("-- target_seq: " + seq)
    lines.append("-- phase: finalize")
    lines.append("-- undo_sql_count: " + str(len(undo_sql_list)))
    for undo_sql in undo_sql_list:
        lines.append("-- undo_sql: " + undo_sql.rstrip(";") + ";")
    lines.append("")
    for sql in sqls:
        lines.append(sql.rstrip(";") + ";")
    try:
        with open(file_path, "w", encoding="utf-8", errors="replace") as f:
            f.write("\n".join(lines).rstrip() + "\n")
    except Exception:
        return []
    append_jsonl_event(
        run_dir=state.run_dir,
        stream="db_debug",
        payload={
            "kind": "finalize_sql_log_written",
            "phase": PhaseName.FINALIZE,
            "round_index": int(state.finalize_rounds or 0),
            "target_seq": state.context.target_seq,
            "log_path": file_path,
            "sql_count": len(sqls),
            "sqls": list(sqls),
            "undo_sql_count": len(undo_sql_list),
            "undo_sqls": list(undo_sql_list),
        },
    )
    return [file_path]


def _extract_solution_sqls(solution: dict) -> list:
    if not isinstance(solution, dict):
        return []
    sql_value = solution.get("SQL")
    out = []
    if isinstance(sql_value, str):
        if sql_value.strip():
            out.append(sql_value.strip())
    elif isinstance(sql_value, (list, tuple)):
        for item in sql_value:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
            elif isinstance(item, dict):
                sql = str(item.get("sql") or "").strip()
                if sql:
                    out.append(sql)
    return out

def _build_finalize_solutions(runtime_cfg: DBSearchRuntimeConfig, state: DBSearchState, outcome):
    solutions = []
    for item in outcome.output_solutions or []:
        if isinstance(item, dict):
            filtered = _filter_finalize_solution_sqls(dict(item))
            if isinstance(filtered, dict):
                solutions.append(filtered)
    if not solutions and isinstance(outcome.output_patch, dict) and outcome.output_patch:
        filtered = _filter_finalize_solution_sqls(dict(outcome.output_patch))
        if isinstance(filtered, dict):
            solutions.append(filtered)
    filtered_db_actions = _filter_finalize_db_actions(outcome.db_actions or [])
    if not solutions and filtered_db_actions:
        sqls = [str(plan.sql or "").strip() for plan in filtered_db_actions if str(plan.sql or "").strip()]
        if sqls:
            solutions.append({"SQL": sqls})
    return [dict(item) for item in solutions if isinstance(item, dict)]


def _write_external_seeds_for_finalize(runtime_cfg: DBSearchRuntimeConfig, state: DBSearchState, solutions):
    cfg = runtime_cfg.app_config
    defaults = load_symbolic_solution_defaults(cfg.find_input_file("test_command.txt"))
    seq = int(state.context.target_seq or 0)
    seed_records = _write_external_seeds_from_solutions(
        solutions or [],
        cfg=cfg,
        seq=seq,
        defaults=defaults,
        logger=None,
    )
    seed_records_out = []
    for item in (seed_records or []):
        if not isinstance(item, dict):
            continue
        seed_path = str(item.get("seed_path") or "").strip()
        if not seed_path:
            continue
        seed_records_out.append(item)
    return seed_records_out


def _execute_finalize_queries(runtime_cfg: DBSearchRuntimeConfig, state: DBSearchState, outcome) -> list:
    executions = []
    round_index = int(state.finalize_rounds) + 1
    for plan in outcome.query_plans or []:
        if isinstance(getattr(plan, "metadata", None), dict):
            plan.metadata["round_index"] = int(round_index)
        if is_write_query(plan.sql):
            executions.append(
                DBQueryExecution(
                    plan=plan,
                    raw_result={
                        "ok": False,
                        "error": "finalize_lookup_must_be_read_only_use_db_actions_for_mutation",
                        "query": plan.sql,
                    },
                    allowed=False,
                    audit_message="finalize_lookup_must_be_read_only_use_db_actions_for_mutation",
                )
            )
            continue
        executions.append(execute_query_plan(plan, runtime_cfg, phase=PhaseName.FINALIZE, artifact_run_dir=state.run_dir))
    return executions


def _execute_finalize_solution_sqls(runtime_cfg: DBSearchRuntimeConfig, state: DBSearchState, solutions) -> list:
    executions = []
    round_index = int(state.finalize_rounds)
    for idx, solution in enumerate(solutions or [], 1):
        for sql in _extract_solution_sqls(solution):
            plan = DBQueryPlan(
                sql=sql,
                purpose="finalize_solution_sql_" + str(int(idx)),
                phase=PhaseName.FINALIZE,
                allow_write=True,
                metadata={"kind": "solution_sql", "solution_index": int(idx), "round_index": int(round_index)},
            )
            executions.append(execute_query_plan(plan, runtime_cfg, phase=PhaseName.FINALIZE, artifact_run_dir=state.run_dir))
    return executions


def _build_finalize_retry_payload(state: DBSearchState, action_executions) -> FilteredQueryPayload:
    query_result_pairs = []
    for execution in action_executions or []:
        if not isinstance(execution, DBQueryExecution):
            continue
        sql = str(execution.plan.sql or "").strip()
        raw_result = execution.raw_result if isinstance(execution.raw_result, dict) else {}
        if not sql:
            continue
        if raw_result.get("ok"):
            continue
        query_result_pairs.append({"sql": sql, "result": dict(raw_result or {})})
    return FilteredQueryPayload(
        phase=PhaseName.FINALIZE,
        overall_goal=state.goal.summary,
        goal=state.goal.finalize_goal or state.goal.summary,
        query_result_pairs=query_result_pairs[:10],
    )


def _build_final_output_payload(state: DBSearchState, solutions, action_executions, sql_log_paths, external_seed_records=None) -> dict:
    solutions = [dict(item) for item in (solutions or []) if isinstance(item, dict)]
    db_action_results = []
    for execution in action_executions or []:
        db_action_results.append(
            {
                "sql": str(execution.plan.sql or ""),
                "allowed": bool(execution.allowed),
                "audit_message": str(execution.audit_message or ""),
                "raw_result": dict(execution.raw_result or {}),
            }
        )
    payload = {"solutions": solutions}
    payload["db_action_results"] = db_action_results
    payload["sql_log_paths"] = list(sql_log_paths or [])
    payload["external_seed_records"] = [dict(item) for item in (external_seed_records or []) if isinstance(item, dict)]
    return payload


def run_finalize_phase(runtime_cfg: DBSearchRuntimeConfig, state: DBSearchState) -> DBSearchState:
    """Run finalize rounds that either request more data or emit final output."""
    while state.finalize_rounds < int(runtime_cfg.finalize_round_limit) and not state.output_ready:
        round_index = int(state.finalize_rounds) + 1
        append_runtime_debug_log(
            run_dir=state.run_dir,
            message="finalize round %02d start" % int(round_index),
        )
        prompt_text = build_phase_prompt(PhaseName.FINALIZE, state)
        response_text = run_text_llm_call(
            prompt_text,
            run_dir=state.run_dir,
            phase=PhaseName.FINALIZE,
            round_index=round_index,
            role="phase_planner",
        )
        outcome = parse_phase_outcome(response_text, phase=PhaseName.FINALIZE)

        query_allowed = _query_allowed_in_finalize(state)
        executions = []
        filtered_payloads = []
        if bool(outcome.abandon):
            state.finalize_rounds = round_index
            state.output_ready = True
            state.final_output = {
                "abandon": True,
                "rationale": str(outcome.rationale or ""),
                "findings": list(outcome.findings or []),
            }
            append_jsonl_event(
                run_dir=state.run_dir,
                stream="events",
                payload={
                    "kind": "finalize_abandoned",
                    "round_index": int(round_index),
                    "rationale": str(outcome.rationale or ""),
                },
            )
            state.round_traces.append(
                RoundTrace(
                    phase=PhaseName.FINALIZE,
                    round_index=round_index,
                    prompt_text=prompt_text,
                    llm_response_text=response_text,
                    executions=[],
                    filtered_payloads=[],
                )
            )
            break
        if query_allowed:
            executions = _execute_finalize_queries(runtime_cfg, state, outcome)
        else:
            outcome.query_plans = []
        fatal = find_fatal_db_execution(executions)
        if fatal:
            state.finalize_rounds = round_index
            state.fatal_error = str(fatal.get("error") or "")
            state.fatal_error_detail = dict(fatal)
            state.final_output = {"error": state.fatal_error, "fatal_error_detail": dict(fatal)}
            append_jsonl_event(
                run_dir=state.run_dir,
                stream="errors",
                payload={
                    "kind": "fatal_db_runtime_error",
                    "phase": PhaseName.FINALIZE,
                    "round_index": int(round_index),
                    "detail": dict(fatal),
                },
            )
            state.round_traces.append(
                RoundTrace(
                    phase=PhaseName.FINALIZE,
                    round_index=round_index,
                    prompt_text=prompt_text,
                    llm_response_text=response_text,
                    executions=executions,
                    filtered_payloads=[],
                )
            )
            break
        if query_allowed and executions:
            payload = FilteredQueryPayload(
                phase=PhaseName.FINALIZE,
                overall_goal=state.goal.summary,
                goal=state.goal.finalize_goal or state.goal.summary,
                query_result_pairs=truncate_execution_pairs(executions, limit=10, row_limit=10),
            )
            filtered_payloads.append(payload)
            append_filtered_payload(state, payload)

        state.finalize_rounds = round_index
        state.round_traces.append(
            RoundTrace(
                phase=PhaseName.FINALIZE,
                round_index=round_index,
                prompt_text=prompt_text,
                llm_response_text=response_text,
                executions=executions,
                filtered_payloads=filtered_payloads,
            )
        )

        if outcome.output_solutions or (isinstance(outcome.output_patch, dict) and outcome.output_patch) or outcome.db_actions:
            solutions = _build_finalize_solutions(runtime_cfg, state, outcome)
            outcome.db_actions = _filter_finalize_db_actions(outcome.db_actions or [])
            action_executions = _execute_finalize_solution_sqls(runtime_cfg, state, solutions)
            executions.extend(action_executions)
            if state.round_traces:
                state.round_traces[-1].executions.extend(action_executions)
            fatal = find_fatal_db_execution(action_executions)
            if fatal:
                state.fatal_error = str(fatal.get("error") or "")
                state.fatal_error_detail = dict(fatal)
                state.final_output = {"error": state.fatal_error, "fatal_error_detail": dict(fatal)}
                append_jsonl_event(
                    run_dir=state.run_dir,
                    stream="errors",
                    payload={
                        "kind": "fatal_db_runtime_error",
                        "phase": PhaseName.FINALIZE,
                        "round_index": int(round_index),
                        "detail": dict(fatal),
                    },
                )
                break
            failed_action_executions = []
            for execution in action_executions or []:
                raw_result = execution.raw_result if isinstance(execution.raw_result, dict) else {}
                if not raw_result.get("ok"):
                    failed_action_executions.append(execution)
            if failed_action_executions:
                retry_payload = _build_finalize_retry_payload(state, failed_action_executions)
                append_filtered_payload(state, retry_payload)
                if state.round_traces:
                    state.round_traces[-1].filtered_payloads.append(retry_payload)
                append_jsonl_event(
                    run_dir=state.run_dir,
                    stream="events",
                    payload={
                        "kind": "finalize_output_sql_failed_retrying",
                        "round_index": int(round_index),
                        "failed_sql_count": len(failed_action_executions),
                    },
                )
                if state.finalize_rounds >= int(runtime_cfg.finalize_round_limit):
                    state.final_output = {
                        "error": "finalize_output_sql_failed",
                        "db_action_results": [
                            {
                                "sql": str(execution.plan.sql or ""),
                                "allowed": bool(execution.allowed),
                                "audit_message": str(execution.audit_message or ""),
                                "raw_result": dict(execution.raw_result or {}),
                            }
                            for execution in failed_action_executions
                        ],
                    }
                    break
                continue
            external_seed_records = _write_external_seeds_for_finalize(runtime_cfg, state, solutions)
            external_seed_paths = [str((item or {}).get("seed_path") or "") for item in (external_seed_records or []) if str((item or {}).get("seed_path") or "").strip()]
            sql_log_paths = []
            external_seed_by_index = {}
            for item in external_seed_records or []:
                if not isinstance(item, dict):
                    continue
                solution_index = item.get("solution_index")
                seed_id = item.get("seed_id")
                if solution_index is None:
                    continue
                external_seed_by_index[int(solution_index)] = seed_id
            for idx0, solution in enumerate(solutions or []):
                sqls = _extract_solution_sqls(solution)
                if not sqls:
                    continue
                undo_sqls = []
                raw_undo = solution.get("undo_sql") if isinstance(solution, dict) else []
                if isinstance(raw_undo, str):
                    if raw_undo.strip():
                        undo_sqls.append(raw_undo.strip())
                elif isinstance(raw_undo, (list, tuple)):
                    for item in raw_undo:
                        if isinstance(item, str) and item.strip():
                            undo_sqls.append(item.strip())
                cur_log_paths = _archive_sql_mutations(
                    runtime_cfg,
                    state,
                    [type("TmpPlan", (), {"sql": sql})() for sql in sqls],
                    seed_id=external_seed_by_index.get(int(idx0)),
                    undo_sqls=undo_sqls,
                )
                sql_log_paths.extend(cur_log_paths)
            append_jsonl_event(
                run_dir=state.run_dir,
                stream="events",
                payload={
                    "kind": "finalize_output_ready",
                    "round_index": int(round_index),
                    "db_action_count": len(action_executions or []),
                    "sql_log_paths": list(sql_log_paths or []),
                    "external_seed_paths": list(external_seed_paths or []),
                },
            )
            state.sql_log_paths.extend(sql_log_paths)
            state.output_ready = True
            state.final_output = _build_final_output_payload(state, solutions, action_executions, sql_log_paths, external_seed_records=external_seed_records)
            state.final_output["external_seed_paths"] = list(external_seed_paths or [])
            break
        if not query_allowed:
            break
        if not outcome.query_plans:
            break

    return state
