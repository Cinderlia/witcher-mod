"""
Database query execution helpers for symbolic prompt DB-assisted rounds.
"""

import json
try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class DBQueryConfig:
    engine: str = "mysql"
    host: str = "127.0.0.1"
    port: int = 3306
    database: str = ""
    username: str = "root"
    password: str = ""
    connect_timeout_sec: int = 3
    query_timeout_sec: int = 5
    max_rows: int = 50


_NON_RETRYABLE_MYSQL_ERROR_CODES = {
    1044,  # access denied for database
    1045,  # access denied for user/password
    1049,  # unknown database
    1142,  # command denied
    1143,  # column command denied
    1227,  # access denied; need super privilege
}


def _as_int(v: Any, d: int) -> int:
    try:
        return int(v) if v is not None else int(d)
    except Exception:
        return int(d)


def load_db_query_config_from_raw(raw_cfg: Dict[str, Any]) -> DBQueryConfig:
    raw = raw_cfg if isinstance(raw_cfg, dict) else {}
    sec = raw.get("symbolic_db")
    if not isinstance(sec, dict):
        sec = {}
    engine = str(sec.get("engine") or "mysql").strip().lower() or "mysql"
    return DBQueryConfig(
        engine=engine,
        host=str(sec.get("host") or "127.0.0.1").strip() or "127.0.0.1",
        port=max(1, _as_int(sec.get("port"), 3306)),
        database=str(sec.get("database") or "").strip(),
        username=str(sec.get("username") or "root").strip() or "root",
        password=str(sec.get("password") or ""),
        connect_timeout_sec=max(1, _as_int(sec.get("connect_timeout_sec"), 3)),
        query_timeout_sec=max(1, _as_int(sec.get("query_timeout_sec"), 5)),
        max_rows=max(1, _as_int(sec.get("max_rows"), 50)),
    )


def _is_readonly_query(query: str) -> bool:
    q = (query or "").strip().lstrip("(").strip().lower()
    if not q:
        return False
    prefixes = ("select ", "show ", "describe ", "desc ", "explain ", "with ")
    return any(q.startswith(p) for p in prefixes)


def _trim_cell(v: Any, max_len: int = 512) -> Any:
    if isinstance(v, (bytes, bytearray)):
        try:
            s = bytes(v).decode("utf-8", errors="replace")
        except Exception:
            s = str(v)
    elif v is None or isinstance(v, (int, float, bool)):
        return v
    else:
        s = str(v)
    if len(s) > int(max_len):
        return s[: int(max_len)] + "...<trimmed>"
    return s


def is_non_retryable_db_result(result: Dict[str, Any]) -> bool:
    if not isinstance(result, dict):
        return False
    if bool(result.get("ok")):
        return False
    return result.get("retryable") is False


def _extract_mysql_error_code(ex: Exception) -> int:
    try:
        args = getattr(ex, "args", None)
        if isinstance(args, tuple) and args:
            return int(args[0])
    except Exception:
        return 0
    return 0


def execute_database_query(query: str, cfg: DBQueryConfig, *, allow_write: bool = False) -> Dict[str, Any]:
    sql = (query or "").strip()
    if not sql:
        return {"ok": False, "error": "empty_query", "query": "", "retryable": False}
    if not bool(allow_write) and not _is_readonly_query(sql):
        return {"ok": False, "error": "only_readonly_query_allowed", "query": sql, "retryable": False}
    if (cfg.engine or "").strip().lower() != "mysql":
        return {"ok": False, "error": "unsupported_engine", "engine": cfg.engine, "query": sql, "retryable": False}

    conn = None
    cursor = None
    try:
        try:
            import pymysql  # type: ignore
        except Exception:
            return {"ok": False, "error": "pymysql_not_installed", "query": sql, "retryable": False}

        conn = pymysql.connect(
            host=cfg.host,
            port=int(cfg.port),
            user=cfg.username,
            password=cfg.password,
            database=cfg.database if cfg.database else None,
            connect_timeout=int(cfg.connect_timeout_sec),
            read_timeout=int(cfg.query_timeout_sec),
            write_timeout=int(cfg.query_timeout_sec),
            charset="utf8mb4",
            autocommit=True,
        )
        cursor = conn.cursor()
        cursor.execute(sql)
        statement_type = "write" if bool(allow_write) and not _is_readonly_query(sql) else "read"
        affected_rows = int(getattr(cursor, "rowcount", 0) or 0)
        columns = []
        rows: List[List[Any]] = []
        if getattr(cursor, "description", None):
            rows_raw = cursor.fetchmany(int(cfg.max_rows))
            for d in (cursor.description or []):
                columns.append(str((d or [None])[0] or ""))
            for r in rows_raw or []:
                rr: List[Any] = []
                for cell in (r or []):
                    rr.append(_trim_cell(cell))
                rows.append(rr)
        return {
            "ok": True,
            "engine": "mysql",
            "query": sql,
            "statement_type": statement_type,
            "autocommit": True,
            "affected_rows": affected_rows,
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "truncated": bool(len(rows) >= int(cfg.max_rows)),
        }
    except Exception as ex:
        code = _extract_mysql_error_code(ex)
        retryable = False if code in _NON_RETRYABLE_MYSQL_ERROR_CODES else True
        out = {
            "ok": False,
            "query": sql,
            "error": str(ex),
            "retryable": bool(retryable),
        }
        if code:
            out["error_code"] = int(code)
        return out
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


def db_query_result_to_text(result: Dict[str, Any]) -> str:
    try:
        return json.dumps(result if isinstance(result, dict) else {}, ensure_ascii=False, indent=2)
    except Exception:
        return str(result)
