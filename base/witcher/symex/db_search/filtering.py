"""LLM-assisted result compression between database search rounds."""

import asyncio
import json
import re

from common.app_config import load_symex_app_config
from llm_utils import get_default_client
from llm_utils.taint.taint_llm_calls import chat_text_with_retries

from .debug_log import append_jsonl_event, archive_llm_exchange
from .models import DBQueryExecution, DBSearchState, FilteredQueryPayload


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", flags=re.IGNORECASE)


def _asyncio_run(coro):
    runner = getattr(asyncio, "run", None)
    if runner is not None:
        return runner(coro)
    created_loop = False
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        created_loop = True
    try:
        return loop.run_until_complete(coro)
    finally:
        if created_loop:
            try:
                loop.close()
            finally:
                try:
                    asyncio.set_event_loop(None)
                except Exception:
                    pass


def _load_filter_temperature() -> float:
    try:
        cfg = load_symex_app_config()
        raw = cfg.raw if hasattr(cfg, "raw") else {}
    except Exception:
        raw = {}
    sec = raw.get("db_search")
    if not isinstance(sec, dict):
        sec = {}
    v = sec.get("filter_temperature")
    if v is None:
        sym_sec = raw.get("symbolic_prompt")
        if isinstance(sym_sec, dict):
            v = sym_sec.get("llm_temperature")
    try:
        return float(v) if v is not None else 0.2
    except Exception:
        return 0.2


def _extract_json_text(text: str):
    if not isinstance(text, str):
        return None
    t = text.strip()
    if not t:
        return None
    m = _FENCE_RE.search(t)
    if m:
        inner = (m.group(1) or "").strip()
        if inner.startswith("{") and inner.endswith("}"):
            return inner
    i = t.find("{")
    j = t.rfind("}")
    if i >= 0 and j >= 0 and j > i:
        return t[i : j + 1]
    return None


def _repair_json_text(text: str) -> str:
    s = (text or "").strip()
    if not s:
        return s
    s = re.sub(r",\s*([}\]])", r"\1", s)
    s = re.sub(r"\bTrue\b", "true", s)
    s = re.sub(r"\bFalse\b", "false", s)
    s = re.sub(r"\bNone\b", "null", s)
    return s


def _parse_json_best_effort(text: str):
    if not isinstance(text, str) or not text.strip():
        return None
    raw = text.strip()
    try:
        return json.loads(raw)
    except Exception:
        pass
    js = _extract_json_text(raw)
    if js:
        try:
            return json.loads(js)
        except Exception:
            try:
                return json.loads(_repair_json_text(js))
            except Exception:
                pass
    repaired = _repair_json_text(raw)
    if repaired and repaired != raw:
        try:
            return json.loads(repaired)
        except Exception:
            pass
    return None


def _filter_response_has_valid_json(text: str) -> bool:
    obj = _parse_json_best_effort(text)
    return isinstance(obj, dict)


def _serialize_executions(executions):
    items = []
    for execution in executions or []:
        if not isinstance(execution, DBQueryExecution):
            continue
        raw_result = execution.raw_result if isinstance(execution.raw_result, dict) else {}
        items.append(
            {
                "sql": str(execution.plan.sql or ""),
                "purpose": str(execution.plan.purpose or ""),
                "ok": bool(raw_result.get("ok")),
                "columns": raw_result.get("columns") if isinstance(raw_result.get("columns"), list) else [],
                "rows": raw_result.get("rows") if isinstance(raw_result.get("rows"), list) else [],
                "row_count": int(raw_result.get("row_count") or 0) if raw_result.get("row_count") is not None else 0,
                "error": str(raw_result.get("error") or ""),
            }
        )
    return items


def _serialize_filtered_payloads(payloads):
    items = []
    for payload in payloads or []:
        if not isinstance(payload, FilteredQueryPayload):
            continue
        items.append(
            {
                "phase": str(payload.phase or ""),
                "goal": str(payload.goal or ""),
                "query_result_pairs": list(payload.query_result_pairs or [])[:10],
            }
        )
    return items


def build_filter_prompt(overall_goal: str, phase_goal: str, executions, state: DBSearchState) -> str:
    """Build a compact prompt for the inter-round result filter.

    The filter receives the overall goal, the current phase goal, and all SQL
    statements plus raw DB outputs generated in the current round.
    """
    round_items = _serialize_executions(executions)
    lines = []
    lines.append("You are a database query result filter.")
    lines.append("Your task is to filter relevant and useful information from the current round of database query results, based on the overall goal and the current round goal.")
    lines.append("You only process the current round's query set. Do not summarize historical information.")
    lines.append("This round may contain multiple SQL statements serving the same goal. Please filter them collectively rather than treating each one in isolation.")
    lines.append("Retain only useful queries and their corresponding useful results. Results include successfully returned key data, as well as database errors relevant to the goal.")
    lines.append("If you are unsure whether a result is critical, prioritize keeping it.")
    lines.append("Output only JSON.")
    lines.append("")
    lines.append("Overall goal:")
    lines.append(str(overall_goal or "<EMPTY_OVERALL_GOAL>"))
    lines.append("")
    lines.append("Current round goal:")
    lines.append(str(phase_goal or "<EMPTY_PHASE_GOAL>"))
    lines.append("")
    lines.append("Current round SQL statements and raw database responses:")
    lines.append(json.dumps(round_items, ensure_ascii=False, indent=2))
    lines.append("")
    lines.append("Please output JSON in the following format:")
    lines.append("{")
    lines.append('  "query_result_pairs": [')
    lines.append('    {"sql": "original SQL", "result": {"rows": [{"column": "value"}]}}')
    lines.append("  ]")
    lines.append("}")
    lines.append("If a result or error is retained, the corresponding original SQL must be included together in query_result_pairs. Retain only genuinely useful query-result pairs, with a maximum of 10 entries.")
    return "\n".join(lines).rstrip() + "\n"


def build_memory_filter_prompt(overall_goal: str, phase_goal: str, payloads, state: DBSearchState) -> str:
    """Build a prompt that re-filters compressed payloads from previous phases."""
    items = _serialize_filtered_payloads(payloads)
    lines = []
    lines.append("You are a database historical information filter.")
    lines.append("Your task is to re-filter the already filtered database information from previous rounds based on the overall goal, retaining only the truly useful query-result pairs.")
    lines.append("If a result is retained, the corresponding original SQL statement must be included as well.")
    lines.append("Database errors relevant to the goal, empty results, missing tables, missing columns, permission errors, queries with no matches, and similar information may all be retained.")
    lines.append("Output only JSON.")
    lines.append("")
    lines.append("Overall goal:")
    lines.append(str(overall_goal or "<EMPTY_OVERALL_GOAL>"))
    lines.append("")
    lines.append("Current round goal:")
    lines.append(str(phase_goal or "<EMPTY_PHASE_GOAL>"))
    lines.append("")
    lines.append("Previously filtered database information from earlier rounds:")
    lines.append(json.dumps(items, ensure_ascii=False, indent=2))
    lines.append("")
    lines.append("Please output JSON in the following format:")
    lines.append("{")
    lines.append('  "query_result_pairs": [')
    lines.append('    {"sql": "original SQL", "result": {"rows": [{"column": "value"}]}}')
    lines.append("  ]")
    lines.append("}")
    lines.append("If a result or error is retained, the corresponding original SQL must be included together in query_result_pairs. Retain only genuinely useful query-result pairs, with a maximum of 10 entries.")
    return "\n".join(lines).rstrip() + "\n"


def _run_filter_llm(prompt_text: str, *, state: DBSearchState, role: str, round_index: int) -> str:
    client = get_default_client()
    append_jsonl_event(
        run_dir=state.run_dir,
        stream="events",
        payload={
            "kind": "filter_llm_call_start",
            "phase": str(role or ""),
            "round_index": int(round_index or 0),
        },
    )
    try:
        response_text = _asyncio_run(
            chat_text_with_retries(
                client=client,
                prompt=prompt_text,
                system=None,
                temperature=_load_filter_temperature(),
                max_attempts=3,
                call_timeout_s=getattr(client, "timeout_s", None) if client is not None else None,
                response_validator=_filter_response_has_valid_json,
                response_validator_name="db_search_filter_response_has_valid_json",
            )
        )
    except Exception as ex:
        append_jsonl_event(
            run_dir=state.run_dir,
            stream="errors",
            payload={
                "kind": "filter_llm_call_error",
                "phase": str(role or ""),
                "round_index": int(round_index or 0),
                "error": str(ex),
            },
        )
        raise
    archive_llm_exchange(
        run_dir=state.run_dir,
        phase="filter",
        round_index=int(round_index or 0),
        role=role,
        prompt_text=prompt_text,
        response_text=response_text,
        metadata={},
    )
    append_jsonl_event(
        run_dir=state.run_dir,
        stream="events",
        payload={
            "kind": "filter_llm_call_done",
            "phase": str(role or ""),
            "round_index": int(round_index or 0),
        },
    )
    return response_text


def _fallback_memory_payload(overall_goal: str, phase_goal: str, payloads) -> FilteredQueryPayload:
    query_result_pairs = []
    for payload in payloads or []:
        if not isinstance(payload, FilteredQueryPayload):
            continue
        for pair in (payload.query_result_pairs or []):
            if not isinstance(pair, dict):
                continue
            query_result_pairs.append(dict(pair))
            if len(query_result_pairs) >= 10:
                break
        if len(query_result_pairs) >= 10:
            break
    return FilteredQueryPayload(
        phase="finalize_context",
        overall_goal=overall_goal,
        goal=phase_goal,
        query_result_pairs=query_result_pairs[:10],
    )


def _fallback_filtered_payload(overall_goal: str, phase_goal: str, executions) -> FilteredQueryPayload:
    phase = ""
    query_result_pairs = []
    for execution in executions or []:
        if not isinstance(execution, DBQueryExecution):
            continue
        phase = phase or str(execution.plan.phase or "")
        sql = str(execution.plan.sql or "").strip()
        raw_result = execution.raw_result if isinstance(execution.raw_result, dict) else {}
        if not sql:
            continue
        query_result_pairs.append({"sql": sql, "result": dict(raw_result or {})})
        if len(query_result_pairs) >= 10:
            break
    return FilteredQueryPayload(
        phase=phase,
        overall_goal=overall_goal,
        goal=phase_goal,
        query_result_pairs=query_result_pairs[:10],
    )


def run_llm_memory_filter(overall_goal: str, phase_goal: str, payloads, state: DBSearchState) -> FilteredQueryPayload:
    """Re-filter previously compressed payloads for finalize-stage prompting."""
    prompt_text = build_memory_filter_prompt(overall_goal, phase_goal, payloads, state)
    try:
        response_text = _run_filter_llm(prompt_text, state=state, role="history_filter", round_index=int(state.finalize_rounds or 0))
        obj = _parse_json_best_effort(response_text)
    except Exception:
        obj = None
    if not isinstance(obj, dict):
        return _fallback_memory_payload(overall_goal, phase_goal, payloads)
    query_result_pairs = []
    for item in (obj.get("query_result_pairs") or []):
        if isinstance(item, dict):
            query_result_pairs.append(dict(item))
        if len(query_result_pairs) >= 10:
            break
    return FilteredQueryPayload(
        phase="finalize_context",
        overall_goal=overall_goal,
        goal=phase_goal,
        query_result_pairs=query_result_pairs,
    )


def run_llm_result_filter(overall_goal: str, phase_goal: str, executions, state: DBSearchState) -> FilteredQueryPayload:
    """Filter one round of raw query results down to the database facts most relevant to the goal."""
    prompt_text = build_filter_prompt(overall_goal, phase_goal, executions, state)
    try:
        phase_name = ""
        for execution in executions or []:
            if isinstance(execution, DBQueryExecution):
                phase_name = str(execution.plan.phase or "")
                break
        if not phase_name:
            phase_name = "unknown"
        round_index = 0
        if phase_name == "schema_discovery":
            round_index = int(state.schema_rounds or 0) + 1
        elif phase_name == "candidate_lookup":
            round_index = int(state.candidate_rounds or 0) + 1
        elif phase_name == "finalize":
            round_index = int(state.finalize_rounds or 0) + 1
        response_text = _run_filter_llm(prompt_text, state=state, role=phase_name + "_filter", round_index=round_index)
        obj = _parse_json_best_effort(response_text)
    except Exception:
        obj = None
    if not isinstance(obj, dict):
        return _fallback_filtered_payload(overall_goal, phase_goal, executions)
    phase = ""
    for execution in executions or []:
        if isinstance(execution, DBQueryExecution):
            phase = str(execution.plan.phase or "")
            break
    query_result_pairs = []
    for item in (obj.get("query_result_pairs") or []):
        if isinstance(item, dict):
            query_result_pairs.append(dict(item))
        if len(query_result_pairs) >= 10:
            break
    if not query_result_pairs:
        return _fallback_filtered_payload(overall_goal, phase_goal, executions)
    return FilteredQueryPayload(
        phase=phase,
        overall_goal=overall_goal,
        goal=phase_goal,
        query_result_pairs=query_result_pairs,
    )


def truncate_execution_pairs(executions, *, limit: int = 10, row_limit: int = 10) -> list:
    pairs = []
    for execution in executions or []:
        if not isinstance(execution, DBQueryExecution):
            continue
        sql = str(execution.plan.sql or "").strip()
        raw_result = execution.raw_result if isinstance(execution.raw_result, dict) else {}
        if not sql:
            continue
        result = dict(raw_result)
        if result.get("query") == sql:
            result.pop("query", None)
        rows = result.get("rows")
        if isinstance(rows, list) and len(rows) > int(row_limit):
            result["rows"] = list(rows[: int(row_limit)])
            result["row_count_original"] = len(rows)
            result["rows_truncated_by_phase"] = True
        pairs.append({"sql": sql, "result": result})
        if len(pairs) >= int(limit):
            break
    return pairs


def append_filtered_payload(state: DBSearchState, payload: FilteredQueryPayload) -> DBSearchState:
    """Append a filtered payload to the pipeline state for use in later prompts."""
    state.filtered_memory.append(payload)
    return state
