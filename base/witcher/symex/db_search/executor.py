"""Database execution and audit helpers for the standalone search pipeline."""

from typing import Tuple

from .config import DBSearchRuntimeConfig
from .debug_log import append_jsonl_event, append_runtime_debug_log
from .models import DBQueryExecution, DBQueryPlan, PhaseName
from db_query.query_executor import execute_database_query


FATAL_DB_RUNTIME_ERRORS = {
    "invalid_db_result",
}

_BLOCKED_IRREVERSIBLE_SQL_PREFIXES = (
    "drop ",
    "alter ",
    "revoke ",
)


def _is_blocked_irreversible_sql(sql: str) -> bool:
    text = (sql or "").strip().lower()
    return any(text.startswith(prefix) for prefix in _BLOCKED_IRREVERSIBLE_SQL_PREFIXES)


def is_write_query(sql: str) -> bool:
    """Return True when the SQL starts with a mutating statement."""
    text = (sql or "").strip().lower()
    prefixes = ("insert ", "update ", "delete ", "replace ", "alter ", "drop ", "create ")
    return any(text.startswith(prefix) for prefix in prefixes)


def audit_query_plan(plan: DBQueryPlan, *, phase: str) -> Tuple[bool, str]:
    """Validate whether a planned query is allowed in the current phase."""
    sql = (plan.sql or "").strip()
    if not sql:
        return False, "empty_sql"
    if _is_blocked_irreversible_sql(sql):
        return False, "irreversible_sql_is_blocked"
    if is_write_query(sql) and phase != PhaseName.FINALIZE:
        return False, "write_queries_are_only_allowed_in_finalize"
    if plan.allow_write and phase != PhaseName.FINALIZE:
        return False, "allow_write_flag_is_only_valid_in_finalize"
    return True, "allowed"


def execute_query_plan(plan: DBQueryPlan, runtime_cfg: DBSearchRuntimeConfig, *, phase: str, artifact_run_dir: str = "") -> DBQueryExecution:
    """Execute a planned SQL statement after audit checks.
    """
    allowed, message = audit_query_plan(plan, phase=phase)
    append_runtime_debug_log(
        run_dir=artifact_run_dir,
        message="%s round %02d sql execute start: %s" % (
            str(phase or "unknown"),
            int((plan.metadata or {}).get("round_index") or 0),
            str(plan.purpose or plan.sql or "")[:120],
        ),
    )
    append_jsonl_event(
        run_dir=artifact_run_dir,
        stream="db_events",
        payload={
            "kind": "db_query_plan",
            "phase": str(phase or ""),
            "round_index": int((plan.metadata or {}).get("round_index") or 0),
            "sql": str(plan.sql or ""),
            "purpose": str(plan.purpose or ""),
            "allow_write": bool(plan.allow_write),
            "allowed": bool(allowed),
            "audit_message": str(message or ""),
        },
    )
    if not allowed:
        append_runtime_debug_log(
            run_dir=artifact_run_dir,
            message="%s round %02d sql execute blocked: %s" % (
                str(phase or "unknown"),
                int((plan.metadata or {}).get("round_index") or 0),
                str(message or ""),
            ),
        )
        return DBQueryExecution(
            plan=plan,
            raw_result={"ok": False, "error": message, "query": plan.sql},
            allowed=False,
            audit_message=message,
        )
    result = execute_database_query(plan.sql, runtime_cfg.db_config, allow_write=bool(plan.allow_write and phase == PhaseName.FINALIZE))
    append_jsonl_event(
        run_dir=artifact_run_dir,
        stream="db_events",
        payload={
            "kind": "db_direct_result",
            "phase": str(phase or ""),
            "round_index": int((plan.metadata or {}).get("round_index") or 0),
            "sql": str(plan.sql or ""),
            "statement_type": str((result or {}).get("statement_type") or ("write" if bool(plan.allow_write) else "read")),
            "affected_rows": int((result or {}).get("affected_rows") or 0) if isinstance(result, dict) else 0,
            "result": result if isinstance(result, dict) else {},
        },
    )
    append_jsonl_event(
        run_dir=artifact_run_dir,
        stream="db_debug",
        payload={
            "kind": "db_execution_debug",
            "phase": str(phase or ""),
            "round_index": int((plan.metadata or {}).get("round_index") or 0),
            "sql": str(plan.sql or ""),
            "purpose": str(plan.purpose or ""),
            "allow_write": bool(plan.allow_write),
            "audit_message": str(message or ""),
            "statement_type": str((result or {}).get("statement_type") or ("write" if bool(plan.allow_write) else "read")),
            "affected_rows": int((result or {}).get("affected_rows") or 0) if isinstance(result, dict) else 0,
            "raw_result": result if isinstance(result, dict) else {},
        },
    )
    append_runtime_debug_log(
        run_dir=artifact_run_dir,
        message="%s round %02d sql execute done: ok=%s affected_rows=%s" % (
            str(phase or "unknown"),
            int((plan.metadata or {}).get("round_index") or 0),
            str(bool((result or {}).get("ok")) if isinstance(result, dict) else False),
            str((result or {}).get("affected_rows") if isinstance(result, dict) else ""),
        ),
    )
    return DBQueryExecution(
        plan=plan,
        raw_result=result if isinstance(result, dict) else {"ok": False, "error": "invalid_db_result"},
        allowed=True,
        audit_message=message,
    )


def find_fatal_db_execution(executions) -> dict:
    for execution in executions or []:
        if not isinstance(execution, DBQueryExecution):
            continue
        raw_result = execution.raw_result if isinstance(execution.raw_result, dict) else {}
        error_code = str(raw_result.get("error") or "").strip()
        if error_code in FATAL_DB_RUNTIME_ERRORS:
            return {
                "error": error_code,
                "sql": str(getattr(execution.plan, "sql", "") or ""),
                "phase": str(getattr(execution.plan, "phase", "") or ""),
                "raw_result": raw_result,
                "audit_message": str(execution.audit_message or ""),
            }
    return {}
