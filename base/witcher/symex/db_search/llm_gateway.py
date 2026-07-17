"""Prompt building and LLM call adapters for the database exploration pipeline."""

import asyncio
import json
import re
from typing import Optional

from common.app_config import build_app_name_prompt_line, load_symex_app_config
from llm_utils import get_default_client
from llm_utils.taint.taint_llm_calls import chat_text_with_retries

from .debug_log import append_jsonl_event, append_runtime_debug_log, archive_llm_exchange
from .models import BranchSliceContext, DBQueryPlan, DBSearchRequest, DBSearchState, ExternalInputSnapshot, FilteredQueryPayload, PhaseName, PhaseOutcome, SearchGoal


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


def _load_goal_abstraction_temperature() -> float:
    try:
        cfg = load_symex_app_config()
        raw = cfg.raw if hasattr(cfg, "raw") else {}
    except Exception:
        raw = {}
    sec = raw.get("db_search")
    if not isinstance(sec, dict):
        sec = {}
    v = sec.get("goal_abstraction_temperature")
    if v is None:
        sym_sec = raw.get("symbolic_prompt")
        if isinstance(sym_sec, dict):
            v = sym_sec.get("llm_temperature")
    try:
        return float(v) if v is not None else 0.2
    except Exception:
        return 0.2


def _extract_json_text(text: str) -> Optional[str]:
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


def _goal_response_has_valid_json(text: str) -> bool:
    obj = _parse_json_best_effort(text)
    return isinstance(obj, dict)


def _recent_filtered_payloads(state: DBSearchState, phase: str, limit: int = 8):
    out = []
    for payload in (state.filtered_memory or []):
        if getattr(payload, "phase", "") != phase:
            continue
        out.append(payload)
    if len(out) > int(limit):
        out = out[-int(limit):]
    return out


def _candidate_fallback_available(state: DBSearchState) -> bool:
    if int(state.candidate_schema_fallback_limit or 0) <= 0:
        return False
    if state.fallback_to_schema_used:
        return False
    if int(state.schema_round_limit or 0) > 0 and int(state.schema_rounds) >= int(state.schema_round_limit):
        return False
    return True


def _format_query_result_pairs(excerpt, *, pair_limit: int = 5) -> list:
    lines = []
    pairs = []
    if isinstance(excerpt, dict):
        pairs = excerpt.get("query_result_pairs") or []
    for idx, pair in enumerate(pairs[:pair_limit], 1):
        if not isinstance(pair, dict):
            continue
        sql = str(pair.get("sql") or "").strip()
        result = pair.get("result")
        lines.append("query_result_pair_" + str(int(idx)) + ":")
        lines.append("  SQL: " + (sql or "<EMPTY_SQL>"))
        if isinstance(result, dict):
            lines.append("  result: " + json.dumps(result, ensure_ascii=False))
        else:
            lines.append("  result: " + json.dumps(result, ensure_ascii=False))
    return lines


def _format_filtered_payload_block(title: str, payloads, *, pair_limit: int = 5) -> str:
    lines = []
    if not payloads:
        return ""
    lines.append(title)
    for idx, payload in enumerate(payloads, 1):
        lines.append("[filtered result " + str(int(idx)) + "]")
        pair_lines = _format_query_result_pairs({"query_result_pairs": list(payload.query_result_pairs or [])}, pair_limit=pair_limit)
        if pair_lines:
            lines.extend(pair_lines)
    lines.append("")
    return "\n".join(lines).strip()


def _format_schema_memory(state: DBSearchState) -> str:
    lines = []
    if state.schema_findings:
        lines.append("Confirmed schema discoveries:")
        for item in state.schema_findings:
            if item:
                lines.append("- " + str(item))
        lines.append("")
    schema_payloads = list(_recent_filtered_payloads(state, PhaseName.SCHEMA_DISCOVERY, limit=8))
    if not schema_payloads and getattr(state, "schema_raw_pairs", None):
        schema_payloads = [
            FilteredQueryPayload(
                phase=PhaseName.SCHEMA_DISCOVERY,
                overall_goal=state.goal.summary,
                goal=state.goal.schema_goal or state.goal.summary,
                query_result_pairs=list((state.schema_raw_pairs or [])[:10]),
            )
        ]
    payload_block = _format_filtered_payload_block(
        "Previous schema queries:",
        schema_payloads,
        pair_limit=5,
    )
    if payload_block:
        lines.append(payload_block)
    return "\n".join(lines).strip()


def _format_candidate_memory(state: DBSearchState) -> str:
    lines = []
    if state.schema_findings:
        lines.append("Confirmed structural conclusions from the second round:")
        for item in state.schema_findings:
            if item:
                lines.append("- " + str(item))
        lines.append("")
    schema_payload_block = _format_filtered_payload_block(
        "Valid information accumulated from the second round:",
        _recent_filtered_payloads(state, PhaseName.SCHEMA_DISCOVERY, limit=8),
        pair_limit=5,
    )
    if schema_payload_block:
        lines.append(schema_payload_block)
    candidate_payload_block = _format_filtered_payload_block(
        "Valid information accumulated so far in the third round:",
        _recent_filtered_payloads(state, PhaseName.CANDIDATE_LOOKUP, limit=8),
        pair_limit=5,
    )
    if candidate_payload_block:
        lines.append(candidate_payload_block)
    return "\n".join(lines).strip()


def _format_finalize_memory(state: DBSearchState) -> str:
    lines = []
    context_block = _format_filtered_payload_block(
        "Valid information after re-filtering database information from the first two rounds:",
        state.finalize_context_payloads or [],
        pair_limit=8,
    )
    if context_block:
        lines.append(context_block)
    finalize_payload_block = _format_filtered_payload_block(
        "Valid information accumulated so far in the fourth round:",
        _recent_filtered_payloads(state, PhaseName.FINALIZE, limit=8),
        pair_limit=5,
    )
    if finalize_payload_block:
        lines.append(finalize_payload_block)
    return "\n".join(lines).strip()


def _format_input_snapshot(snapshot: ExternalInputSnapshot) -> str:
    lines = []
    lines.append("Original external input:")
    lines.append("ENV:")
    lines.append(snapshot.raw_env_block or "<EMPTY>")
    lines.append("")
    lines.append("COOKIE:")
    lines.append(snapshot.raw_cookie_block or "<EMPTY>")
    lines.append("")
    lines.append("GET:")
    lines.append(snapshot.raw_get_block or "<EMPTY>")
    lines.append("")
    lines.append("POST:")
    lines.append(snapshot.raw_post_block or "<EMPTY>")
    lines.append("")
    lines.append("COOKIE:")
    lines.append(snapshot.raw_cookie_block or "<EMPTY>")
    lines.append("")
    lines.append("SESSION:")
    lines.append(snapshot.raw_session_block or "<EMPTY>")
    return "\n".join(lines).strip()


def run_text_llm_call(
    prompt_text: str,
    *,
    temperature: float = 0.2,
    run_dir: str = "",
    phase: str = "",
    round_index: int = 0,
    role: str = "planner",
) -> str:
    """Call the configured LLM and return raw text."""
    client = get_default_client()
    append_jsonl_event(
        run_dir=run_dir,
        stream="events",
        payload={
            "kind": "llm_call_start",
            "phase": str(phase or ""),
            "round_index": int(round_index or 0),
            "role": str(role or ""),
            "temperature": float(temperature),
        },
    )
    append_runtime_debug_log(
        run_dir=run_dir,
        message="%s round %02d llm call start" % (str(phase or "unknown"), int(round_index or 0)),
    )
    try:
        response_text = _asyncio_run(
            chat_text_with_retries(
                client=client,
                prompt=prompt_text,
                system=None,
                temperature=temperature,
                max_attempts=3,
                call_timeout_s=getattr(client, "timeout_s", None) if client is not None else None,
                response_validator=_goal_response_has_valid_json,
                response_validator_name="db_search_goal_response_has_valid_json",
            )
        )
    except Exception as ex:
        append_jsonl_event(
            run_dir=run_dir,
            stream="errors",
            payload={
                "kind": "llm_call_error",
                "phase": str(phase or ""),
                "round_index": int(round_index or 0),
                "role": str(role or ""),
                "error": str(ex),
            },
        )
        append_runtime_debug_log(
            run_dir=run_dir,
            message="%s round %02d llm call error: %s" % (str(phase or "unknown"), int(round_index or 0), str(ex)),
        )
        raise
    append_runtime_debug_log(
        run_dir=run_dir,
        message="%s round %02d llm call done" % (str(phase or "unknown"), int(round_index or 0)),
    )
    archive_llm_exchange(
        run_dir=run_dir,
        phase=phase,
        round_index=int(round_index or 0),
        role=role,
        prompt_text=prompt_text,
        response_text=response_text,
        metadata={"temperature": float(temperature)},
    )
    append_jsonl_event(
        run_dir=run_dir,
        stream="events",
        payload={
            "kind": "llm_call_done",
            "phase": str(phase or ""),
            "round_index": int(round_index or 0),
            "role": str(role or ""),
        },
    )
    return response_text


def build_goal_abstraction_prompt(request: DBSearchRequest, state: DBSearchState) -> str:
    """Build the one-shot prompt that abstracts code and inputs into a database goal."""
    ctx = request.context
    snapshot = ctx.input_snapshot if isinstance(ctx.input_snapshot, ExternalInputSnapshot) else ExternalInputSnapshot()
    visible_notes = []
    for note in (ctx.notes or []):
        note_s = str(note or "").strip()
        if not note_s:
            continue
        if note_s.startswith("llm_db_request_"):
            continue
        if note_s.startswith("symbolic_objective="):
            continue
        if note_s.startswith("db_search_primary_objective="):
            continue
        visible_notes.append(note_s)
    lines = []
    lines.append("You are a database-assisted symbolic execution planner.")
    lines.append("Your sole purpose is to serve the branch direction change or execution result change of the target statement, not to perform generalized database analysis.")
    lines.append("If line " + (str(ctx.target_seq) if ctx.target_seq is not None else "?") + " is prefixed with [true], it means the true branch was actually taken, and your goal is to make it take the false branch. If prefixed with [false], your goal is to make it take the true branch.")
    lines.append("If the target statement is a switch, help it enter a currently uncovered case.")
    lines.append("Your task is to distill the current raw code and external inputs into an overall goal that can guide the subsequent three rounds of database search, along with sub-goals for each round.")
    lines.append("Subsequent components will only consume your abstract results, so please include all necessary information in the goal description to ensure that every subsequent round stays focused on the target statement's direction change for queries, filtering, and final output.")
    lines.append("The goals for the subsequent three rounds must not be vague. Key conditions, key calls, key variables in the current code, as well as key key names and value-domain clues in the current external inputs, must be distilled into the goal description.")
    lines.append("The subsequent components will continue to work in three rounds: schema discovery, candidate lookup, and finalize/output.")
    lines.append("You need to specify goals for each of these three rounds, but the priority is to first provide an overall_goal that is specific enough to directly guide the subsequent three rounds.")
    lines.append("The sub-goals and stopping conditions for the second and third rounds should lean toward exploring what actually exists in the database, which structures and records truly exist, and which query paths are worth pursuing, rather than solely focusing on confirming whether a particular hypothesis is true.")
    lines.append("Stopping conditions should also lean toward 'sufficient exploration results have been obtained to guide the next round or final output', rather than mechanically requiring confirmation of whether a given table/column/record exists or not.")
    lines.append("You must distinguish which tables/columns are directly visible in the code and which are only inferred from semantics. Subsequent rounds should prioritize exploring what is directly visible in the code; inferred items may only serve as secondary clues.")
    lines.append("If you believe database queries will be needed in subsequent rounds, specify what information needs to be explored. If you believe database modifications may be needed, specify what types of database items need to be modified and how these actions serve the target statement's direction change.")
    lines.append("Do not output explanatory text. Output only JSON.")
    lines.append("")
    try:
        app_line = build_app_name_prompt_line(load_symex_app_config(config_path=request.config_path))
    except Exception:
        app_line = ""
    if app_line:
        lines.append(app_line)
        lines.append("")
    if request.trigger_reason and str(request.trigger_reason).strip() != str(request.db_request_reason or "").strip():
        lines.append("Reason for initiating the database search component:")
        lines.append(str(request.trigger_reason))
        lines.append("")
    if request.symbolic_objective:
        lines.append("Primary goal passed from symbolic_prompt:")
        lines.append(str(request.symbolic_objective))
        lines.append("")
    lines.append("Sole acceptance criterion for database search:")
    lines.append("All queries, candidate record evaluations, and final database modifications must directly serve the execution result change of the target statement at target_seq/target_loc.")
    lines.append("")
    if request.db_request_mode or request.db_request_goal or request.db_request_reason or request.db_request_focus:
        lines.append("Database assistance request from the main workflow:")
        lines.append("mode=" + (request.db_request_mode or "<EMPTY_MODE>"))
        lines.append("goal=" + (request.db_request_goal or "<EMPTY_GOAL>"))
        lines.append("reason=" + (request.db_request_reason or "<EMPTY_REASON>"))
        if request.db_request_focus:
            lines.append("focus=" + json.dumps(list(request.db_request_focus or []), ensure_ascii=False))
        lines.append("")
    lines.append("Target branch:")
    lines.append("target_seq=" + (str(ctx.target_seq) if ctx.target_seq is not None else "?"))
    lines.append("target_loc=" + (ctx.target_loc or "?"))
    lines.append("")
    lines.append("Original code slice:")
    lines.append(ctx.code_slice.strip() or "<EMPTY_CODE_SLICE>")
    lines.append("")
    lines.append(_format_input_snapshot(snapshot))
    if visible_notes:
        lines.append("")
        lines.append("Additional notes:")
        for note in visible_notes:
            lines.append("- " + note)
    lines.append("")
    lines.append("Please output the following JSON:")
    lines.append("{")
    lines.append('  "overall_goal": "Overall goal distilled from raw code conditions, external input clues, and database requirements. Must have reversing the target statement as its sole purpose, and must be specific enough to directly guide the subsequent three rounds.",')
    lines.append('  "branch_effect": "The execution result change that the target statement needs to undergo, e.g., making verify return true, making the target if take the false branch, or making a switch enter an uncovered case.",')
    lines.append('  "db_reason": "Why database assistance is needed.",')
    lines.append('  "relevant_symbols": ["Key variables, attributes, return values, or predicates relevant to database exploration."],')
    lines.append('  "relevant_inputs": ["External input key names relevant to database exploration."],')
    lines.append('  "schema_goal": "Which tables, columns, relationships, and structural clues to prioritize exploring in the second round. Focus on discovering what actually exists in the database and which paths are worth pursuing further.",')
    lines.append('  "candidate_goal": "Which candidate records, value ranges, relationship paths, and failure reasons to continue exploring in the third round. Focus on discovering the actual current content of the database and its exploitable space.",')
    lines.append('  "finalize_goal": "Which database facts and solving clues are most critical before the fourth round output.",')
    lines.append('  "db_information_needs": ["Database information that needs to be queried in subsequent rounds."],')
    lines.append('  "db_mutation_targets": ["If database writes may eventually be needed, describe the types of database items to be modified."],')
    lines.append('  "code_seen_tables": ["Table names directly seen in the code. Only fill in tables that actually appear in the code."],')
    lines.append('  "code_seen_columns": ["Column names directly seen in the code. Only fill in columns that actually appear in the code."],')
    lines.append('  "inferred_tables": ["Table names inferred from semantics but not directly seen in the code. Leave empty if uncertain."],')
    lines.append('  "inferred_columns": ["Column names inferred from semantics but not directly seen in the code. Leave empty if uncertain."],')
    lines.append('  "schema_stop_conditions": ["When the second round can stop, e.g., key table structures, key column distributions, and main relationship paths have been mapped, or sufficient information has been obtained to guide the third round\'s exploration."],')
    lines.append('  "candidate_stop_conditions": ["When the third round can stop, e.g., the key candidate record range, key value domains, and main failure reasons have been mapped, or sufficient information has been obtained to guide the fourth round\'s output."],')
    lines.append('  "finalize_stop_conditions": ["When the fourth round can directly output a solution or SQL modification."],')
    lines.append('  "evidence": ["Key code evidence or input evidence supporting the above abstractions."],')
    lines.append('  "abstraction_warnings": ["Risks that may distort subsequent exploration. May be an empty array."]')
    lines.append("}")
    lines.append("If some fields cannot be determined, leave them as empty strings, empty objects, or empty arrays, but the fields must exist.")
    return "\n".join(lines).rstrip() + "\n"


def build_phase_prompt(phase: str, state: DBSearchState) -> str:
    """Build the prompt for one schema/candidate/finalize round."""
    if phase == PhaseName.SCHEMA_DISCOVERY:
        lines = []
        lines.append("You are a database-assisted symbolic execution planner, now in the second round of the database search component.")
        lines.append("Your task is to determine which database structural information should be queried next in order to achieve the overall goal and the current round goal, and to decisively end this round when sufficient information has been obtained.")
        lines.append("You may output only one of two types of results:")
        lines.append("1. Continue querying database information, output queries")
        lines.append("2. Determine that the current round goal has been achieved, output completed=true with queries empty")
        lines.append("This round allows only read-only database queries. The goal leans toward structure, so priority should be given to DESCRIBE, SHOW COLUMNS, SHOW CREATE TABLE, EXPLAIN, and SELECT information_schema to obtain complete table structures as quickly as possible. Only supplement with ordinary read-only SELECT after structural probing when hypotheses still need verification.")
        lines.append("The default strategy should be to converge in as few rounds as possible, but be more proactive within a single round, prioritizing gathering sufficient information in one go.")
        lines.append("The query tendency for this round is exploration: quickly identify the exact relevant tables, exact column names, exact JOIN paths, and key constraint fields. Do not stop at the confirmation level of 'whether a table exists or how many tables there are'.")
        lines.append("The task for this round is: **query only table structures, not data content.** This round only answers 'what columns does this table have', not 'what data is in this column'.")
        lines.append("This round prohibits probing the content of any business data, including but not limited to:")
        lines.append("- Any business data records, value ranges, relationship paths, failure reasons, etc.")
        lines.append("If the current sub-goal mentions a suspected column or suspected relationship field, you should proactively design exploratory queries to confirm whether it actually exists, rather than treating it as known fact.")
        lines.append("Prefer using DESCRIBE / SHOW COLUMNS to obtain the full column set first, then decide whether to use EXPLAIN, information_schema, or a small-scope SELECT to verify relationship directions.")
        lines.append("In the second round, as long as the table structures truly depended on by the overall goal have been mapped, or the existence or non-existence of a key table/key column has been confirmed, you may directly set completed=true.")
        lines.append("Even if the current schema_goal has not been completed verbatim, as long as the existing information is sufficient to serve the overall goal, or sufficient to determine that certain table items in the original goal are incorrect assumptions, you may also directly set completed=true.")
        lines.append("Do not confirm low-value details. Do not confirm data content or records. This round explores only table structures and relationships.")
        lines.append("If the information is still insufficient, output the necessary queries. Output at most 5 SQL statements per round, but try to obtain sufficient information in a single query batch.")
        lines.append("Do not output explanatory text. Output only JSON.")
        lines.append("")
        lines.append("Overall goal:")
        lines.append(state.goal.summary or "<EMPTY_OVERALL_GOAL>")
        lines.append("")
        lines.append("Second round sub-goal:")
        lines.append(state.goal.schema_goal or "<EMPTY_SCHEMA_GOAL>")
        lines.append("")
        if state.goal.relevant_symbols:
            lines.append("Key symbols:")
            for item in state.goal.relevant_symbols:
                lines.append("- " + item)
            lines.append("")
        if state.goal.relevant_inputs:
            lines.append("Key external inputs:")
            for item in state.goal.relevant_inputs:
                lines.append("- " + item)
            lines.append("")
        if state.goal.db_information_needs:
            lines.append("Database information to be queried:")
            for item in state.goal.db_information_needs:
                lines.append("- " + item)
            lines.append("")
        if state.goal.code_seen_tables:
            lines.append("Relevant tables directly seen in the code:")
            for item in state.goal.code_seen_tables:
                lines.append("- " + item)
            lines.append("")
        if state.goal.code_seen_columns:
            lines.append("Relevant columns directly seen in the code:")
            for item in state.goal.code_seen_columns:
                lines.append("- " + item)
            lines.append("")
        if state.goal.inferred_tables:
            lines.append("Inferred relevant tables (secondary clues):")
            for item in state.goal.inferred_tables:
                lines.append("- " + item)
            lines.append("")
        if state.goal.inferred_columns:
            lines.append("Inferred relevant columns (secondary clues):")
            for item in state.goal.inferred_columns:
                lines.append("- " + item)
            lines.append("")
        if state.goal.schema_stop_conditions:
            lines.append("Second round stopping conditions:")
            for item in state.goal.schema_stop_conditions:
                lines.append("- " + item)
            lines.append("")
        if state.goal.evidence:
            lines.append("Key evidence:")
            for item in state.goal.evidence:
                lines.append("- " + item)
            lines.append("")
        if state.goal.abstraction_warnings:
            lines.append("Abstraction risks:")
            for item in state.goal.abstraction_warnings:
                lines.append("- " + item)
            lines.append("")
        schema_memory = _format_schema_memory(state)
        if schema_memory:
            lines.append(schema_memory)
        lines.append("")
        lines.append("When outputting SQL, you do not need to concern yourself with database user, database address, or database name. Simply output executable and valid SQL statements directly.")
        lines.append("Please output JSON in the following format:")
        lines.append("{")
        lines.append('  "completed": false,')
        lines.append('  "rationale": "Why this round continues querying or why it can end",')
        lines.append('  "findings": ["Schema conclusions confirmed in this round"],')
        lines.append('  "queries": [')
        lines.append("    {")
        lines.append('      "sql": "SHOW COLUMNS FROM candidate_table;",')
        lines.append('      "purpose": "Quickly obtain the full column set of the candidate table to confirm whether key fields exist",')
        lines.append('      "metadata": {"kind": "schema_probe", "probe_target": "candidate_table", "probe_action": "describe_table", "verify_column": "candidate_column", "goal": "Confirm whether the suspected key field exists and obtain the complete table structure"}')
        lines.append("    },")
        lines.append("    {")
        lines.append('      "sql": "SHOW CREATE TABLE candidate_table;",')
        lines.append('      "purpose": "Obtain the CREATE TABLE statement for the candidate table to supplement index, key, and constraint information",')
        lines.append('      "metadata": {"kind": "schema_probe", "probe_target": "candidate_table", "probe_action": "show_create_table", "goal": "Supplement complete table structure and constraint information"}')
        lines.append("    },")
        lines.append("    {")
        lines.append('      "sql": "SELECT COLUMN_NAME, TABLE_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME IN (\'candidate_column\', \'join_column\');",')
        lines.append('      "purpose": "Cross-table probe for key column occurrences to assist in confirming relationship paths",')
        lines.append('      "metadata": {"kind": "schema_probe", "probe_target": "information_schema", "probe_action": "cross_table_column_lookup", "verify_columns": ["candidate_column", "join_column"], "goal": "Confirm which tables actually contain the key fields"}')
        lines.append("    }")
        lines.append("  ]")
        lines.append("}")
        lines.append("If the current round goal has been achieved, set completed=true and leave queries as an empty array.")
        lines.append("If the current round goal has not yet been achieved, set completed=false and output queries.")
        lines.append("During the schema discovery phase, metadata.kind should prefer schema_probe rather than a generic schema label.")
        lines.append("When you are verifying whether a suspected column or suspected relationship field exists, explicitly include verify_column or verify_columns in metadata. When you are probing the complete structure of a table, set probe_action to describe_table.")
        lines.append("queries is limited to a maximum of 5 entries, and all must be read-only database queries.")
        return "\n".join(lines).rstrip() + "\n"
    if phase == PhaseName.CANDIDATE_LOOKUP:
        fallback_allowed = _candidate_fallback_available(state)
        lines = []
        lines.append("You are a database-assisted symbolic execution explorer, now in the third round of the database search component.")
        lines.append("Your task is to find reusable candidate records in order to achieve the overall goal and the current round goal, or to determine that the existing database content cannot directly satisfy the goal, and to decisively end this round when sufficient evidence has been obtained.")
        lines.append("You may output only one of the following options:")
        lines.append("1. Continue querying database content, output queries")
        lines.append("2. The current round goal has been completed, output completed=true with queries empty")
        if fallback_allowed:
            lines.append("3. Additional structural information is still missing and a fallback to the second round is required, output request_schema_fallback=true with queries empty")

        lines.append("This round allows only read-only database queries, with a focus on finding candidate records that can be directly reused or that explain failure reasons. Any business data modifications such as INSERT, UPDATE, DELETE are strictly prohibited.")
        lines.append("Your default strategy should be to converge in as few rounds as possible, but be more proactive within a single round, prioritizing gathering sufficient information in one go.")
        lines.append("The query tendency for this round is also exploration: confirm exact candidate records, exact constraint fields, exact column names, and value domain sources. Do not stop at a vague confirmation level.")
        lines.append("Before constructing any queries, first review the structural information already obtained in this round (e.g., DESCRIBE results).")
        lines.append("Prefer queries that are less likely to produce errors. Only consider more complex queries after sufficient information has been obtained.")
        lines.append("The query strategy should be to use broad queries first to obtain an overview, then gradually narrow down to determine subsequent records. Do not attempt complex JOIN queries before the data distribution is clearly understood. Do not use uncertain column names in JOIN operations.")
        lines.append("Use only table names and column names that have been confirmed to exist. If a column does not appear in the structural information, do not assume it exists.")
        lines.append("If a query returns an error indicating that a field does not exist, do not use that column in subsequent queries. If a query path fails due to structural mismatch, switch to other available paths.")
        lines.append("Do not repeatedly attempt different variations on the same path—structural errors will not disappear with different syntax.")
        lines.append("In the third round, as long as candidate records sufficient to support the final solution construction have been found, or there is sufficient evidence that the current database content cannot directly satisfy the goal, directly set completed=true.")
        lines.append("Even if the current candidate_goal has not been completed verbatim, as long as the existing information is sufficient to serve the overall goal, sufficient to support the fourth round output, or sufficient to prove that the original candidate assumptions are invalid, you may also directly set completed=true.")
        lines.append("Do not continue querying merely to fill in low-value background information. However, if key fields/key records that would affect the final construction are still missing, try to fill them in within the same round.")
        lines.append("If continued queries are needed, output the necessary SQL statements, with a maximum of 5 per round. Try to obtain sufficient key exploration information in a single round.")
        lines.append("Do not output explanatory text. Output only JSON.")
        lines.append("")
        lines.append("Overall goal:")
        lines.append(state.goal.summary or "<EMPTY_OVERALL_GOAL>")
        lines.append("")
        lines.append("Third round sub-goal:")
        lines.append(state.goal.candidate_goal or "<EMPTY_CANDIDATE_GOAL>")
        lines.append("")
        if state.goal.branch_effect:
            lines.append("Target branch effect:")
            lines.append(state.goal.branch_effect)
            lines.append("")
        if state.goal.db_reason:
            lines.append("Reason for database assistance:")
            lines.append(state.goal.db_reason)
            lines.append("")
        if state.goal.relevant_symbols:
            lines.append("Relevant symbols:")
            for item in state.goal.relevant_symbols:
                lines.append("- " + item)
            lines.append("")
        if state.goal.relevant_inputs:
            lines.append("Relevant external inputs:")
            for item in state.goal.relevant_inputs:
                lines.append("- " + item)
            lines.append("")
        if state.goal.db_information_needs:
            lines.append("Database information needs:")
            for item in state.goal.db_information_needs:
                lines.append("- " + item)
            lines.append("")
        if state.goal.db_mutation_targets:
            lines.append("Database mutation targets:")
            for item in state.goal.db_mutation_targets:
                lines.append("- " + item)
            lines.append("")
        if state.goal.candidate_stop_conditions:
            lines.append("Third round candidate stop conditions:")
            for item in state.goal.candidate_stop_conditions:
                lines.append("- " + item)
            lines.append("")
        candidate_memory = _format_candidate_memory(state)
        if candidate_memory:
            lines.append(candidate_memory)

        lines.append("")
        lines.append("When outputting SQL, you do not need to concern yourself with database user, database address, or database name. Simply output executable and valid SQL statements directly.")
        lines.append("Please output JSON in the following format:")
        lines.append("{")
        lines.append('  "completed": false,')
        lines.append('  "request_schema_fallback": false,')
        lines.append('  "rationale": "Why this round continues querying or why it is completed",')
        lines.append('  "findings": ["Candidate record conclusions confirmed in this round"],')
        lines.append('  "queries": [')
        lines.append("    {")
        lines.append('      "sql": "SELECT id, username FROM users LIMIT 5;",')
        lines.append('      "purpose": "Verify whether candidate records satisfy the goal",')
        lines.append('      "metadata": {"kind": "candidate"}')
        lines.append("    }")
        lines.append("  ]")
        lines.append("}")
        lines.append("If the current round goal has been achieved, set completed=true and leave queries as an empty array.")
        if fallback_allowed:
            lines.append("If a fallback to the second round is required, set request_schema_fallback=true, completed=false, and leave queries as an empty array.")

        lines.append("If the current round goal has not yet been achieved, set completed=false and output queries.")
        lines.append("queries is limited to a maximum of 5 entries, and all must be read-only database queries.")
        return "\n".join(lines).rstrip() + "\n"
    if phase == PhaseName.FINALIZE:
        round_index = int(state.finalize_rounds) + 1
        query_allowed = round_index <= 3
        ctx = state.context if isinstance(state.context, BranchSliceContext) else BranchSliceContext()
        snapshot = ctx.input_snapshot if isinstance(ctx.input_snapshot, ExternalInputSnapshot) else ExternalInputSnapshot()
        lines = []
        lines.append("You are a database-assisted symbolic execution solver, now in the fourth round (finalize/output) of the database search component.")
        lines.append("Please follow the general workflow of symbolic execution based on the code context: symbolically execute the target statement and all preceding relevant conditional expressions, represent them using external input expressions to form constraints, and solve them in conjunction with the actual database state.")
        lines.append("Your task is to perform symbolic analysis and attempt to change the actual execution direction of the target statement, combining the raw code slice, complete external inputs, and the distilled database information from previous rounds, and directly output the final result when sufficient information is available.")
        lines.append("You may choose to modify external inputs or directly modify the database. INSERT, UPDATE, and DELETE are all legitimate means.")
        lines.append("Your task is to use the raw code slice, complete external inputs, and the actual database information obtained from previous rounds to make the target statement take the specified target branch, either by modifying external inputs or by modifying the database.")
        lines.append("Focus on solving for the target branch of the target statement. Do not output explanatory text. Output only JSON.")
        if query_allowed:
            lines.append("Additional database queries are still permitted in this round; however, the default strategy should be to output as soon as possible, rather than using up the entire query budget.")
            lines.append("If the available information is already sufficient to construct a high-confidence solution, output the final result directly. Do not continue querying merely to fill in low-value details.")
            lines.append("Only perform supplementary queries when key information that would directly affect solution construction is still missing.")
        lines.append("")
        branch_truth = _extract_branch_truth_from_code_slice(ctx.code_slice, ctx.target_seq)
        target_truth = ""
        if branch_truth == "true":
            target_truth = "false"
        elif branch_truth == "false":
            target_truth = "true"
        lines.append("Overall goal:")
        if target_truth:
            lines.append("The overall goal is to make the if statement at line " + (str(ctx.target_seq) if ctx.target_seq is not None else "?") + " evaluate to " + target_truth + ".")
        else:
            lines.append("The overall goal is to reverse the if statement at line " + (str(ctx.target_seq) if ctx.target_seq is not None else "?") + ".")
        lines.append("")
        if state.goal.finalize_stop_conditions:
            lines.append("Conditions for direct output in the fourth round:")
            for item in state.goal.finalize_stop_conditions:
                lines.append("- " + item)
            lines.append("")
        finalize_memory = _format_finalize_memory(state)
        if finalize_memory:
            lines.append(finalize_memory)
            lines.append("")
        lines.append("Target branch:")
        lines.append("target_seq=" + (str(ctx.target_seq) if ctx.target_seq is not None else "?"))
        lines.append("target_loc=" + (ctx.target_loc or "?"))
        lines.append("")
        lines.append("Raw code slice:")
        lines.append(ctx.code_slice.strip() or "<EMPTY_CODE_SLICE>")
        lines.append("")
        lines.append(_format_input_snapshot(snapshot))
        lines.append("")
        lines.append("Options:")
        lines.append("1. Directly output the final result, providing the final solution in solutions")
        lines.append("2. The target branch can only be reversed using prohibited SQL statements; abandon outputting the solution")
        if query_allowed:
            lines.append("3. Perform supplementary database queries, output queries")
        lines.append("Please modify the PHP request environment variables, POST, COOKIE, GET, and SESSION parameters as needed (corresponding JSON fields: ENV/POST/COOKIE/GET/SESSION). Output only the keys and values that need to be modified. Do not copy unmodified fields back into the JSON. Downstream will perform incremental merging based on the current inputs.")
        lines.append("If a solution only requires database modifications, output only SQL. Do not output SESSION/ENV/GET/POST/COOKIE.")
        lines.append("If a solution only requires external input modifications, output only the corresponding input keys. Do not include unmodified keys.")
        lines.append("If database modifications are needed, include an additional SQL field in the solution object.")
        lines.append("SQL can be either a string or an array of strings.")
        lines.append("If only database modifications are needed and no external input modifications are required, still output a solution object; this object may contain only the SQL field.")
        lines.append("If both input modifications and database modifications are needed, include both in the same solution object.")
        lines.append("If a solution's SQL modifies the database, you may optionally include an undo_sql field with corresponding rollback statements for later database restoration. undo_sql can be empty, a string, or an array of strings.")
        lines.append("Do not perform additional database queries solely to construct undo_sql. Only include it when it can be provided directly without any extra queries.")
        lines.append("INSERT, UPDATE, and DELETE statements on ordinary business data are permitted for database modifications.")
        lines.append("When outputting SQL, you do not need to concern yourself with database user, database address, or database name. Simply output executable and valid SQL statements directly.")
        lines.append("The following high-risk SQL statements are strictly prohibited, whether they appear at the beginning or in the middle of a statement: DROP, ALTER, REVOKE, TRUNCATE, GRANT, SET GLOBAL, KILL.")
        lines.append("The following statements that affect database users or permissions are also strictly prohibited, including but not limited to: UPDATE mysql.user, DELETE FROM mysql.user, INSERT INTO mysql.user, REPLACE INTO mysql.user, CREATE USER, ALTER USER, DROP USER, RENAME USER, SET PASSWORD, GRANT ALL PRIVILEGES.")
        lines.append("If you believe that the goal can only be achieved through the above prohibited statements, you must still not output them. You are allowed to abandon outputting the solution object.")
        lines.append("Please output JSON in the following format:")
        lines.append("{")
        lines.append('  "abandon": false,')
        lines.append('  "rationale": "Why this round performs supplementary queries, why it can output directly, or why it abandons",')
        lines.append('  "findings": ["Conclusions directly relevant to the final solving"],')
        if query_allowed:
            lines.append('  "queries": [')
            lines.append("    {")
            lines.append('      "sql": "SELECT id, role FROM users LIMIT 5;",')
            lines.append('      "purpose": "Supplementary query for final solving",')
            lines.append('      "metadata": {"kind": "finalize_lookup"}')
            lines.append("    }")
            lines.append("  ],")
        lines.append('  "solutions": [')
        lines.append("    {")
        lines.append('      "POST": {"username": "admin"},')
        lines.append('      "SQL": ["UPDATE users SET role=\'admin\' WHERE id=1;"],')
        lines.append('      "undo_sql": ["UPDATE users SET role=\'user\' WHERE id=1;"]')
        lines.append("    }")
        lines.append("  ]")
        lines.append("}")
        lines.append("Example of abandoning output:")
        lines.append("{")
        lines.append('  "abandon": true,')
        lines.append('  "rationale": "Reversing this branch would require prohibited high-risk SQL statements, so fourth round output is abandoned",')
        lines.append('  "findings": ["All feasible solutions require high-risk database statements"],')
        if query_allowed:
            lines.append('  "queries": [],')
        lines.append('  "solutions": []')
        lines.append("}")
        if query_allowed:
            lines.append("If supplementary queries are still needed, output queries; do not output solutions in this case.")
            lines.append("If direct output is already possible, do not output queries and output at least one solution.")
        lines.append("If you decide to abandon, set abandon=true and do not output queries, solutions, or db_actions.")
        return "\n".join(lines).rstrip() + "\n"
    return ""


def _extract_branch_truth_from_code_slice(code_slice: str, target_seq: Optional[int]) -> str:
    if target_seq is None:
        return ""
    seq_text = str(int(target_seq))
    for raw_line in str(code_slice or "").splitlines():
        line = str(raw_line or "")
        if not line:
            continue
        if not re.match(r"\s*" + re.escape(seq_text) + r"\|", line):
            continue
        truth_match = re.match(r"\s*" + re.escape(seq_text) + r"\|\s*\[(true|false)\]", line, re.IGNORECASE)
        if truth_match:
            return str(truth_match.group(1) or "").lower()
        break
    return ""


def parse_goal_response(response_text: str) -> SearchGoal:
    """Parse the first-round LLM output into a normalized search goal."""
    obj = _parse_json_best_effort(response_text)
    if not isinstance(obj, dict):
        return SearchGoal(
            summary="",
            abstraction_warnings=["goal_response_parse_failed"],
        )
    overall_goal = str(obj.get("overall_goal") or obj.get("summary") or "").strip()
    return SearchGoal(
        summary=overall_goal,
        branch_effect=str(obj.get("branch_effect") or "").strip(),
        db_reason=str(obj.get("db_reason") or "").strip(),
        relevant_symbols=[str(x).strip() for x in (obj.get("relevant_symbols") or []) if str(x).strip()],
        relevant_inputs=[str(x).strip() for x in (obj.get("relevant_inputs") or []) if str(x).strip()],
        evidence=[str(x).strip() for x in (obj.get("evidence") or []) if str(x).strip()],
        context_strategy="abstract_only",
        retained_code_lines=[],
        retained_inputs={},
        schema_goal=str(obj.get("schema_goal") or "").strip(),
        candidate_goal=str(obj.get("candidate_goal") or "").strip(),
        finalize_goal=str(obj.get("finalize_goal") or "").strip(),
        db_information_needs=[str(x).strip() for x in (obj.get("db_information_needs") or []) if str(x).strip()],
        db_mutation_targets=[str(x).strip() for x in (obj.get("db_mutation_targets") or []) if str(x).strip()],
        code_seen_tables=[str(x).strip() for x in (obj.get("code_seen_tables") or []) if str(x).strip()],
        code_seen_columns=[str(x).strip() for x in (obj.get("code_seen_columns") or []) if str(x).strip()],
        inferred_tables=[str(x).strip() for x in (obj.get("inferred_tables") or []) if str(x).strip()],
        inferred_columns=[str(x).strip() for x in (obj.get("inferred_columns") or []) if str(x).strip()],
        schema_stop_conditions=[str(x).strip() for x in (obj.get("schema_stop_conditions") or []) if str(x).strip()],
        candidate_stop_conditions=[str(x).strip() for x in (obj.get("candidate_stop_conditions") or []) if str(x).strip()],
        finalize_stop_conditions=[str(x).strip() for x in (obj.get("finalize_stop_conditions") or []) if str(x).strip()],
        abstraction_warnings=[str(x).strip() for x in (obj.get("abstraction_warnings") or []) if str(x).strip()],
    )


def parse_phase_outcome(response_text: str, *, phase: Optional[str] = None) -> PhaseOutcome:
    """Parse a phase-round LLM output into a structured phase outcome."""
    out_phase = phase or PhaseName.SCHEMA_DISCOVERY
    obj = _parse_json_best_effort(response_text)
    if not isinstance(obj, dict):
        return PhaseOutcome(
            phase=out_phase,
            completed=False,
            rationale="phase_response_parse_failed",
        )
    query_plans = []
    raw_queries = obj.get("queries")
    if isinstance(raw_queries, list):
        for item in raw_queries:
            if not isinstance(item, dict):
                continue
            sql = str(item.get("sql") or "").strip()
            if not sql:
                continue
            query_plans.append(
                DBQueryPlan(
                    sql=sql,
                    purpose=str(item.get("purpose") or "").strip(),
                    phase=out_phase,
                    allow_write=bool(item.get("allow_write")),
                    metadata=item.get("metadata") if isinstance(item.get("metadata"), dict) else {},
                )
            )
            if out_phase in (PhaseName.SCHEMA_DISCOVERY, PhaseName.CANDIDATE_LOOKUP, PhaseName.FINALIZE) and len(query_plans) >= 5:
                break
    db_actions = []
    raw_actions = obj.get("db_actions")
    if isinstance(raw_actions, list):
        for item in raw_actions:
            if not isinstance(item, dict):
                continue
            sql = str(item.get("sql") or "").strip()
            if not sql:
                continue
            db_actions.append(
                DBQueryPlan(
                    sql=sql,
                    purpose=str(item.get("purpose") or "").strip(),
                    phase=out_phase,
                    allow_write=bool(item.get("allow_write", True)),
                    metadata=item.get("metadata") if isinstance(item.get("metadata"), dict) else {},
                )
            )
    completed = bool(obj.get("completed"))
    output_solutions = []
    raw_solutions = obj.get("solutions")
    if isinstance(raw_solutions, list):
        for item in raw_solutions:
            if isinstance(item, dict):
                output_solutions.append(dict(item))
    elif isinstance(obj.get("solution"), dict):
        output_solutions.append(dict(obj.get("solution")))
    undo_sqls = []
    for solution in output_solutions:
        if not isinstance(solution, dict):
            continue
        raw_undo = solution.get("undo_sql")
        normalized = []
        if isinstance(raw_undo, str):
            if raw_undo.strip():
                normalized.append(raw_undo.strip())
        elif isinstance(raw_undo, (list, tuple)):
            for item in raw_undo:
                if isinstance(item, str) and item.strip():
                    normalized.append(item.strip())
        if normalized:
            solution["undo_sql"] = list(normalized)
            undo_sqls.extend(normalized)
        elif "undo_sql" in solution:
            solution["undo_sql"] = []
    abandon = bool(obj.get("abandon"))
    if abandon:
        query_plans = []
        output_solutions = []
        db_actions = []
        undo_sqls = []
    return PhaseOutcome(
        phase=out_phase,
        completed=completed,
        request_schema_fallback=bool(obj.get("request_schema_fallback")),
        abandon=abandon,
        rationale=str(obj.get("rationale") or "").strip(),
        findings=[str(x).strip() for x in (obj.get("findings") or []) if str(x).strip()],
        query_plans=query_plans,
        output_solutions=output_solutions,
        output_patch=({} if abandon else (obj.get("output_patch") if isinstance(obj.get("output_patch"), dict) else {})),
        db_actions=db_actions,
        undo_sqls=undo_sqls,
    )
