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
        lines.append("已确认的 schema 发现：")
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
        "之前 schema 查询：",
        schema_payloads,
        pair_limit=5,
    )
    if payload_block:
        lines.append(payload_block)
    return "\n".join(lines).strip()


def _format_candidate_memory(state: DBSearchState) -> str:
    lines = []
    if state.schema_findings:
        lines.append("第二轮已经确认的结构结论：")
        for item in state.schema_findings:
            if item:
                lines.append("- " + str(item))
        lines.append("")
    schema_payload_block = _format_filtered_payload_block(
        "第二轮累积筛选出的有效信息：",
        _recent_filtered_payloads(state, PhaseName.SCHEMA_DISCOVERY, limit=8),
        pair_limit=5,
    )
    if schema_payload_block:
        lines.append(schema_payload_block)
    candidate_payload_block = _format_filtered_payload_block(
        "第三轮当前已累积的有效信息：",
        _recent_filtered_payloads(state, PhaseName.CANDIDATE_LOOKUP, limit=8),
        pair_limit=5,
    )
    if candidate_payload_block:
        lines.append(candidate_payload_block)
    return "\n".join(lines).strip()


def _format_finalize_memory(state: DBSearchState) -> str:
    lines = []
    context_block = _format_filtered_payload_block(
        "前两轮数据库信息再次过滤后的有效信息：",
        state.finalize_context_payloads or [],
        pair_limit=8,
    )
    if context_block:
        lines.append(context_block)
    finalize_payload_block = _format_filtered_payload_block(
        "第四轮当前已累积的有效信息：",
        _recent_filtered_payloads(state, PhaseName.FINALIZE, limit=8),
        pair_limit=5,
    )
    if finalize_payload_block:
        lines.append(finalize_payload_block)
    return "\n".join(lines).strip()


def _format_input_snapshot(snapshot: ExternalInputSnapshot) -> str:
    lines = []
    lines.append("原始外部输入：")
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
    lines.append("你是一个数据库辅助符号执行规划器。")
    lines.append("你的唯一目的，是服务于目标语句的分支方向改变或执行结果改变，而不是做泛化的数据库分析。")
    lines.append("如果第" + (str(ctx.target_seq) if ctx.target_seq is not None else "?") + "行前面标注为[true]，表示当前实际执行到了true分支，你的目标是让它改走false分支；如果标注为[false]，则目标是让它改走true分支。")
    lines.append("如果目标语句是 switch，就要帮助它进入当前未覆盖的 case。")
    lines.append("你的任务是把当前原始代码和外部输入精炼成一个能够指导后续三轮数据库搜索的总目标和每个轮次的子目标。")
    lines.append("后续组件默认只消费你的抽象结果，所以请在目标描述中包含所有必要的信息，确保后续每一轮都始终围绕目标语句的方向改变来查询、筛选和最终输出。")
    lines.append("后续三轮的目标不能笼统，必须把当前代码中的关键判断、关键调用、关键变量，以及当前外部输入中的关键键名和值域线索，精炼进目标描述中。")
    lines.append("后续组件会继续分三轮工作：schema discovery、candidate lookup、finalize/output。")
    lines.append("你需要分别给出这三轮的目标，但重点是先给出一个足够具体、能直接指导后三轮的 overall_goal。")
    lines.append("第二轮和第三轮的子目标与停止条件，都应更偏向探索数据库里实际有什么、哪些结构和记录真实存在、哪些查询路径值得继续，而不是只围绕“确认某个猜想是否成立”。")
    lines.append("停止条件也应偏向“已经获得足够探索结果，足以指导下一轮或最终输出”，而不是机械地要求确认某个表/列/记录有或没有。")
    lines.append("你必须区分：哪些表/列是从代码中直接看到的，哪些只是根据语义推测出来的。后续轮次需要优先探索“代码中直接看到的”，推测项只能作为次要线索。")
    lines.append("如果你认为后续需要数据库查询，请明确需要去探索什么信息；如果你认为后续可能需要数据库修改，请明确需要修改哪类数据库项，以及这些动作如何服务于目标语句方向改变。")
    lines.append("不要输出解释性文字，只输出JSON。")
    lines.append("")
    try:
        app_line = build_app_name_prompt_line(load_symex_app_config(config_path=request.config_path))
    except Exception:
        app_line = ""
    if app_line:
        lines.append(app_line)
        lines.append("")
    if request.trigger_reason and str(request.trigger_reason).strip() != str(request.db_request_reason or "").strip():
        lines.append("启动数据库搜索组件的原因：")
        lines.append(str(request.trigger_reason))
        lines.append("")
    if request.symbolic_objective:
        lines.append("symbolic_prompt 传入的主目标：")
        lines.append(str(request.symbolic_objective))
        lines.append("")
    lines.append("数据库搜索的唯一验收标准：")
    lines.append("所有查询、候选记录判断和最终数据库修改，都必须直接服务于 target_seq/target_loc 对应目标语句的执行结果改变。")
    lines.append("")
    if request.db_request_mode or request.db_request_goal or request.db_request_reason or request.db_request_focus:
        lines.append("主流程给出的数据库辅助请求：")
        lines.append("mode=" + (request.db_request_mode or "<EMPTY_MODE>"))
        lines.append("goal=" + (request.db_request_goal or "<EMPTY_GOAL>"))
        lines.append("reason=" + (request.db_request_reason or "<EMPTY_REASON>"))
        if request.db_request_focus:
            lines.append("focus=" + json.dumps(list(request.db_request_focus or []), ensure_ascii=False))
        lines.append("")
    lines.append("目标分支：")
    lines.append("target_seq=" + (str(ctx.target_seq) if ctx.target_seq is not None else "?"))
    lines.append("target_loc=" + (ctx.target_loc or "?"))
    lines.append("")
    lines.append("原始代码切片：")
    lines.append(ctx.code_slice.strip() or "<EMPTY_CODE_SLICE>")
    lines.append("")
    lines.append(_format_input_snapshot(snapshot))
    if visible_notes:
        lines.append("")
        lines.append("额外说明：")
        for note in visible_notes:
            lines.append("- " + note)
    lines.append("")
    lines.append("请输出如下JSON：")
    lines.append("{")
    lines.append('  "overall_goal": "把原始代码条件、外部输入线索和数据库需求精炼后的总目标，必须以反转目标语句为唯一目的，并且足够具体，能直接指导后三轮",')
    lines.append('  "branch_effect": "目标语句需要发生的执行结果变化，例如让 verify 返回 true、让目标 if 改走 false 分支、或让 switch 进入未覆盖 case",')
    lines.append('  "db_reason": "为什么需要数据库辅助",')
    lines.append('  "relevant_symbols": ["与数据库探索有关的关键变量、属性、返回值或谓词"],')
    lines.append('  "relevant_inputs": ["与数据库探索有关的外部输入键名"],')
    lines.append('  "schema_goal": "第二轮要优先探索哪些表、列、关联和结构线索，弄清数据库里实际有什么，以及哪些路径值得继续追查",')
    lines.append('  "candidate_goal": "第三轮要继续探索哪些候选记录、值域、关联路径和失败原因，弄清数据库当前真实内容与可利用空间",')
    lines.append('  "finalize_goal": "第四轮输出前，哪些数据库事实和求解线索最关键",')
    lines.append('  "db_information_needs": ["后续需要查询的数据库信息"],')
    lines.append('  "db_mutation_targets": ["如果最终可能需要写库，描述要修改的数据库项类型"],')
    lines.append('  "code_seen_tables": ["从代码中直接看到的表名；只能填代码里真的出现过的表"],')
    lines.append('  "code_seen_columns": ["从代码中直接看到的列名；只能填代码里真的出现过的列"],')
    lines.append('  "inferred_tables": ["根据语义推测但代码中未直接出现的表名；不确定则留空"],')
    lines.append('  "inferred_columns": ["根据语义推测但代码中未直接出现的列名；不确定则留空"],')
    lines.append('  "schema_stop_conditions": ["第二轮何时可以停止，例如已经摸清关键表结构、关键列分布、主要关联路径，或已获得足够信息指导第三轮继续探索"],')
    lines.append('  "candidate_stop_conditions": ["第三轮何时可以停止，例如已经摸清关键候选记录范围、关键值域、主要失败原因，或已获得足够信息指导第四轮输出"],')
    lines.append('  "finalize_stop_conditions": ["第四轮何时可以直接输出 solution 或 SQL 修改"],')
    lines.append('  "evidence": ["支持上述抽象的关键代码证据或输入证据"],')
    lines.append('  "abstraction_warnings": ["可能导致后续探索失真的风险点，可为空数组"]')
    lines.append("}")
    lines.append("如果某些字段无法确定，保留空字符串、空对象或空数组，但字段必须存在。")
    return "\n".join(lines).rstrip() + "\n"


def build_phase_prompt(phase: str, state: DBSearchState) -> str:
    """Build the prompt for one schema/candidate/finalize round."""
    if phase == PhaseName.SCHEMA_DISCOVERY:
        lines = []
        lines.append("你是数据库辅助符号执行规划器，现在处于数据库搜索组件的第二轮。")
        lines.append("你的任务是为了实现总目标和当前轮次目标，判断接下来应该查询哪些数据库结构信息，并在信息足够时果断结束本轮。")
        lines.append("你只能输出两类结果之一：")
        lines.append("1. 继续查询数据库信息，输出 queries")
        lines.append("2. 判断当前轮次目标已达成，输出 completed=true 且 queries 为空")
        lines.append("本轮只允许只读数据库查询。目标更偏结构，应优先使用 DESCRIBE、SHOW COLUMNS、SHOW CREATE TABLE、EXPLAIN、SELECT information_schema 来尽可能快地拿到完整表结构；只有在结构探测后仍需验证假设时，才补充普通只读 SELECT。")
        lines.append("默认策略应当是尽量用更少轮次收敛，但单轮内要更主动探索，优先争取一次拿到足够信息。")
        lines.append("本轮查询倾向是探索：尽快找出确切相关表、确切列名、确切 JOIN 路径和关键约束字段，不要停留在“是否存在某张表/有几张表”的确认层面。")
        lines.append("如果当前子目标提到了某个疑似列或疑似关联字段，你应主动设计探测性查询去确认它是否真实存在，而不是把它当成已知事实。")
        lines.append("优先通过 DESCRIBE / SHOW COLUMNS 获取完整列集合，再决定后续是否需要用 EXPLAIN、information_schema 或小范围 SELECT 验证关联方向。")
        lines.append("第二轮只要已经摸清总目标真正依赖的表结构，或者已经确认某个关键表/关键列存在或不存在，就可以直接 completed=true。")
        lines.append("即使当前 schema_goal 没有逐字完成，只要现有信息已经足够服务总目标、足够支撑第三轮继续，或足够判断原目标中的某些表项是错误假设，也可以直接 completed=true。")
        lines.append("不要为了确认低价值细节而继续追问；但如果还缺少关键表名/列名/关联关系，应在同一轮内尽量补齐。")
        lines.append("如果还不够，就输出必要的查询。一轮最多输出 5 条 SQL，但应尽量一次查到足够信息。")
        lines.append("不要输出解释性文字，只输出 JSON。")
        lines.append("")
        lines.append("总目标：")
        lines.append(state.goal.summary or "<EMPTY_OVERALL_GOAL>")
        lines.append("")
        lines.append("第二轮子目标：")
        lines.append(state.goal.schema_goal or "<EMPTY_SCHEMA_GOAL>")
        lines.append("")
        if state.goal.relevant_symbols:
            lines.append("关键符号：")
            for item in state.goal.relevant_symbols:
                lines.append("- " + item)
            lines.append("")
        if state.goal.relevant_inputs:
            lines.append("关键外部输入：")
            for item in state.goal.relevant_inputs:
                lines.append("- " + item)
            lines.append("")
        if state.goal.db_information_needs:
            lines.append("需要查询的数据库信息：")
            for item in state.goal.db_information_needs:
                lines.append("- " + item)
            lines.append("")
        if state.goal.code_seen_tables:
            lines.append("代码中直接看到的相关表：")
            for item in state.goal.code_seen_tables:
                lines.append("- " + item)
            lines.append("")
        if state.goal.code_seen_columns:
            lines.append("代码中直接看到的相关列：")
            for item in state.goal.code_seen_columns:
                lines.append("- " + item)
            lines.append("")
        if state.goal.inferred_tables:
            lines.append("推测相关表（次要线索）：")
            for item in state.goal.inferred_tables:
                lines.append("- " + item)
            lines.append("")
        if state.goal.inferred_columns:
            lines.append("推测相关列（次要线索）：")
            for item in state.goal.inferred_columns:
                lines.append("- " + item)
            lines.append("")
        if state.goal.schema_stop_conditions:
            lines.append("第二轮可停止条件：")
            for item in state.goal.schema_stop_conditions:
                lines.append("- " + item)
            lines.append("")
        if state.goal.evidence:
            lines.append("关键证据：")
            for item in state.goal.evidence:
                lines.append("- " + item)
            lines.append("")
        if state.goal.abstraction_warnings:
            lines.append("抽象风险：")
            for item in state.goal.abstraction_warnings:
                lines.append("- " + item)
            lines.append("")
        schema_memory = _format_schema_memory(state)
        if schema_memory:
            lines.append(schema_memory)
        lines.append("输出 SQL 时，不需要关心数据库用户、数据库地址和数据库名，直接输出可执行的合法 SQL 语句即可。")
        lines.append("请输出如下 JSON：")
        lines.append("{")
        lines.append('  "completed": false,')
        lines.append('  "rationale": "本轮为何继续查询或为何可结束",')
        lines.append('  "findings": ["本轮已经确认的 schema 结论"],')
        lines.append('  "queries": [')
        lines.append("    {")
        lines.append('      "sql": "SHOW COLUMNS FROM candidate_table;",')
        lines.append('      "purpose": "快速获取候选表的完整列集合，确认关键字段是否存在",')
        lines.append('      "metadata": {"kind": "schema_probe", "probe_target": "candidate_table", "probe_action": "describe_table", "verify_column": "candidate_column", "goal": "确认疑似关键字段是否存在并获取完整表结构"}')
        lines.append("    },")
        lines.append("    {")
        lines.append('      "sql": "SHOW CREATE TABLE candidate_table;",')
        lines.append('      "purpose": "获取候选表的建表语句，补充索引、键与约束信息",')
        lines.append('      "metadata": {"kind": "schema_probe", "probe_target": "candidate_table", "probe_action": "show_create_table", "goal": "补充完整表结构与约束信息"}')
        lines.append("    },")
        lines.append("    {")
        lines.append('      "sql": "SELECT COLUMN_NAME, TABLE_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME IN (\'candidate_column\', \'join_column\');",')
        lines.append('      "purpose": "跨表探测关键列出现位置，辅助确认关联路径",')
        lines.append('      "metadata": {"kind": "schema_probe", "probe_target": "information_schema", "probe_action": "cross_table_column_lookup", "verify_columns": ["candidate_column", "join_column"], "goal": "确认关键字段实际位于哪些表"}')
        lines.append("    }")
        lines.append("  ]")
        lines.append("}")
        lines.append("如果已经达到当前轮次目标，则设置 completed=true，并让 queries 为空数组。")
        lines.append("如果还未达到当前轮次目标，则设置 completed=false，并输出 queries。")
        lines.append("schema discovery 阶段的 metadata.kind 应优先使用 schema_probe，而不是只有笼统的 schema。")
        lines.append("当你在验证某个疑似列/疑似关联字段是否存在时，请在 metadata 中明确写出 verify_column 或 verify_columns；当你在探测某张表完整结构时，请把 probe_action 设为 describe_table。")
        lines.append("queries 最多 5 条，且都必须是只读数据库查询。")
        return "\n".join(lines).rstrip() + "\n"
    if phase == PhaseName.CANDIDATE_LOOKUP:
        fallback_allowed = _candidate_fallback_available(state)
        lines = []
        lines.append("你是数据库辅助符号执行探索器，现在处于数据库搜索组件的第三轮。")
        lines.append("你的任务是为了实现总目标和当前轮次目标，查找可复用的候选记录，或判断现有数据库内容无法直接满足目标，并在证据足够时果断结束本轮。")
        lines.append("你只能输出以下选项中的一个：")
        lines.append("1. 继续查询数据库内容，输出 queries")
        lines.append("2. 当前轮次目标已完成，输出 completed=true 且 queries 为空")
        if fallback_allowed:
            lines.append("3. 当前仍缺少额外的结构信息，必须回退到第二轮，输出 request_schema_fallback=true 且 queries 为空")

        lines.append("本轮只允许只读数据库查询，重点围绕目标查找可直接复用或验证失败原因的候选记录。")
        lines.append("不要预设只能查某一张表，请根据已有信息选择最有帮助的查询。")
        lines.append("你的默认策略应当是尽量用更少轮次收敛，但单轮内要更主动探索，优先争取一次拿到足够信息。")
        lines.append("本轮查询倾向同样是探索：确认确切候选记录、确切约束字段、确切列名和值域来源，不要停留在模糊确认层面。")
        lines.append("查询策略是先使用宽泛查询获取全貌，再逐步收窄，确定后续记录。")
        lines.append("在构造任何查询之前，先检查本轮已获得的结构信息（如 DESCRIBE 结果）。")
        lines.append("只使用已确认存在的表名和列名，如果某列在结构信息中未出现，不要假设它存在。")
        lines.append("如果查询返回字段不存在的报错，后续查询不再使用该列，如果一条查询路径因结构不匹配而失败，切换到其他可用路径。")
        lines.append("不要在同一路径上反复尝试不同写法——结构错误不会因写法改变而消失。")
        lines.append("第三轮只要已经找到足以支持最终构造 solution 的候选记录，或者已经有足够证据说明当前数据库内容无法直接满足目标，就直接 completed=true。")
        lines.append("即使当前 candidate_goal 没有逐字完成，只要现有信息已经足够服务总目标、足够支撑第四轮输出，或足够证明原先的候选假设不成立，也可以直接 completed=true。")
        lines.append("不要为了补齐低价值背景信息而继续查询；但如果还缺少会影响最终构造的关键字段/关键记录，应在同一轮尽量补齐。")
        lines.append("如果需要继续查询，就输出必要的查询语句，一次最多输出 5 条 SQL；应尽量在同一轮把关键探索信息查够。")
        lines.append("不要输出解释性文字，只输出 JSON。")
        lines.append("")
        lines.append("总目标：")
        lines.append(state.goal.summary or "<EMPTY_OVERALL_GOAL>")
        lines.append("")
        lines.append("第三轮子目标：")
        lines.append(state.goal.candidate_goal or "<EMPTY_CANDIDATE_GOAL>")
        lines.append("")
        if state.goal.branch_effect:
            lines.append("目标分支效果：")
            lines.append(state.goal.branch_effect)
            lines.append("")
        if state.goal.db_reason:
            lines.append("需要数据库辅助的原因：")
            lines.append(state.goal.db_reason)
            lines.append("")
        if state.goal.relevant_symbols:
            lines.append("关键符号：")
            for item in state.goal.relevant_symbols:
                lines.append("- " + item)
            lines.append("")
        if state.goal.relevant_inputs:
            lines.append("关键外部输入：")
            for item in state.goal.relevant_inputs:
                lines.append("- " + item)
            lines.append("")
        if state.goal.db_information_needs:
            lines.append("数据库信息需求：")
            for item in state.goal.db_information_needs:
                lines.append("- " + item)
            lines.append("")
        if state.goal.db_mutation_targets:
            lines.append("若最终需要修改数据库，可能涉及的目标项：")
            for item in state.goal.db_mutation_targets:
                lines.append("- " + item)
            lines.append("")
        if state.goal.candidate_stop_conditions:
            lines.append("第三轮可停止条件：")
            for item in state.goal.candidate_stop_conditions:
                lines.append("- " + item)
            lines.append("")
        candidate_memory = _format_candidate_memory(state)
        if candidate_memory:
            lines.append(candidate_memory)

        lines.append("")
        lines.append("输出 SQL 时，不需要关心数据库用户、数据库地址和数据库名，直接输出可执行的合法 SQL 语句即可。")
        lines.append("请输出如下 JSON：")
        lines.append("{")
        lines.append('  "completed": false,')
        lines.append('  "request_schema_fallback": false,')
        lines.append('  "rationale": "本轮为何继续查询、为何完成",')
        lines.append('  "findings": ["本轮已经确认的候选记录结论"],')
        lines.append('  "queries": [')
        lines.append("    {")
        lines.append('      "sql": "SELECT id, username FROM users LIMIT 5;",')
        lines.append('      "purpose": "验证候选记录是否满足目标",')
        lines.append('      "metadata": {"kind": "candidate"}')
        lines.append("    }")
        lines.append("  ]")
        lines.append("}")
        lines.append("如果已经达到当前轮次目标，则设置 completed=true，并让 queries 为空数组。")
        if fallback_allowed:
            lines.append("如果必须回退到第二轮，则设置 request_schema_fallback=true、completed=false，并让 queries 为空数组。")

        lines.append("如果还未达到当前轮次目标，则设置 completed=false，并输出 queries。")
        lines.append("queries 最多 5 条，且都必须是只读数据库查询。")
        return "\n".join(lines).rstrip() + "\n"
    if phase == PhaseName.FINALIZE:
        round_index = int(state.finalize_rounds) + 1
        query_allowed = round_index <= 3
        ctx = state.context if isinstance(state.context, BranchSliceContext) else BranchSliceContext()
        snapshot = ctx.input_snapshot if isinstance(ctx.input_snapshot, ExternalInputSnapshot) else ExternalInputSnapshot()
        lines = []
        lines.append("你是数据库辅助符号执行求解器，现在处于数据库搜索组件的第四轮 finalize/output。")
        lines.append("请你根据代码上下文，严格按照符号执行的一般流程，将目标语句和它之前所有相关条件表达式符号化，使用外部输入的表达式来表示，形成约束，并结合数据库真实状态求解。")
        lines.append("你的任务是结合原始代码切片、完整外部输入、前面几轮压缩后的数据库信息，进行符号化分析并尝试改变目标语句的实际执行方向，并在信息足够时直接输出最终结果。")
        lines.append("可以选择修改外部输入，或者直接修改数据库。你被允许直接向数据库插入或修改数据，INSERT、UPDATE、DELETE 都是合法手段。")
        lines.append("你的任务是根据原始代码切片与完整外部输入，结合前面几轮得到的数据库真实信息，尝试通过修改外部输入或者修改数据库，让目标语句走向指定的目标分支。")
        lines.append("请围绕目标语句的目标分支进行求解，不要输出解释性文字，只输出 JSON。")
        if query_allowed:
            lines.append("当前仍允许补查数据库信息；但默认策略应当是尽快输出，而不是把补查预算用满。")
            lines.append("如果现有信息已经足以构造高置信度 solution，就直接输出最终结果，不要为了补齐低价值细节继续查询。")
            lines.append("只有在缺少会直接影响 solution 构造的关键信息时，才进行补查。")
        lines.append("")
        lines.append("总目标：")
        lines.append("如果第" + (str(ctx.target_seq) if ctx.target_seq is not None else "?") + "行前面标注为[true]，表示当前实际执行到了true分支，你的目标是让它改走false分支；如果标注为[false]，则目标是让它改走true分支。")
        lines.append("")
        if state.goal.finalize_stop_conditions:
            lines.append("第四轮可直接输出条件：")
            for item in state.goal.finalize_stop_conditions:
                lines.append("- " + item)
            lines.append("")
        finalize_memory = _format_finalize_memory(state)
        if finalize_memory:
            lines.append(finalize_memory)
            lines.append("")
        lines.append("目标分支：")
        lines.append("target_seq=" + (str(ctx.target_seq) if ctx.target_seq is not None else "?"))
        lines.append("target_loc=" + (ctx.target_loc or "?"))
        lines.append("")
        lines.append("原始代码切片：")
        lines.append(ctx.code_slice.strip() or "<EMPTY_CODE_SLICE>")
        lines.append("")
        lines.append(_format_input_snapshot(snapshot))
        lines.append("")
        lines.append("可选项：")
        lines.append("1. 直接输出最终结果，并在 solutions 中给出最终解")
        if query_allowed:
            lines.append("2. 补查数据库，输出 queries")
        lines.append("请根据需求修改PHP请求的环境变量、POST、COOKIE、GET、SESSION参数（对应 JSON 字段：ENV/POST/COOKIE/GET/SESSION）。只输出需要修改的键和值，不要把未修改的部分原样抄回 JSON。下游会基于当前输入做增量合并。")
        lines.append("如果某个 solution 只需要修改数据库，就只输出 SQL，不要输出 SESSION/ENV/GET/POST/COOKIE。")
        lines.append("如果某个 solution 只需要修改外部输入，就只输出对应的输入键，不要补写未修改的键。")
        lines.append("如果需要修改数据库，请在 solution 对象中额外加入 SQL 字段。")
        lines.append("SQL 可以是字符串，也可以是字符串数组。")
        lines.append("如果只需要修改数据库，不需要修改外部输入，也仍然要输出一个 solution 对象；这个对象可以只有 SQL 字段。")
        lines.append("如果既要改输入又要改数据库，就在同一个 solution 对象里同时放输入修改和 SQL。")
        lines.append("")
        lines.append("输出 SQL 时，不需要关心数据库用户、数据库地址和数据库名，直接输出可执行的合法 SQL 语句即可。")
        lines.append("请输出如下 JSON：")
        lines.append("{")
        lines.append('  "rationale": "本轮为何补查或为何能直接输出",')
        lines.append('  "findings": ["与最终求解直接相关的结论"],')
        if query_allowed:
            lines.append('  "queries": [')
            lines.append("    {")
            lines.append('      "sql": "SELECT id, role FROM users LIMIT 5;",')
            lines.append('      "purpose": "补查用于最终求解的数据库信息",')
            lines.append('      "metadata": {"kind": "finalize_lookup"}')
            lines.append("    }")
            lines.append("  ],")
        lines.append('  "solutions": [')
        lines.append("    {")
        lines.append('      "POST": {"username": "admin"},')
        lines.append('      "SQL": ["UPDATE users SET role=\'admin\' WHERE id=1;"]')
        lines.append("    }")
        lines.append("  ]")
        lines.append("}")
        if query_allowed:
            lines.append("如果还需要补查，则输出 queries；此时不要输出 solutions。")
            lines.append("如果已经可以直接输出，则不要输出 queries，并输出至少一个 solution。")
        return "\n".join(lines).rstrip() + "\n"
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
    return PhaseOutcome(
        phase=out_phase,
        completed=completed,
        request_schema_fallback=bool(obj.get("request_schema_fallback")),
        rationale=str(obj.get("rationale") or "").strip(),
        findings=[str(x).strip() for x in (obj.get("findings") or []) if str(x).strip()],
        query_plans=query_plans,
        output_solutions=output_solutions,
        output_patch=obj.get("output_patch") if isinstance(obj.get("output_patch"), dict) else {},
        db_actions=db_actions,
    )
