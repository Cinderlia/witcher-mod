import os
import sys
from typing import Dict, List, Optional, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.app_config import AppConfig, load_app_config
from common.logger import Logger
from branch_selector.trace.trace_extract import build_seq_to_index
from utils.cpg_utils.graph_mapping import load_nodes, load_ast_edges, get_string_children, method_call_receiver_name
from utils.cpg_utils.trace_index import load_trace_index_records
from utils.cpg_utils.trace_call_edges import get_call_name


_SQL_FUNC_NAMES = {
    # MySQL / MySQLi
    "mysql_query",
    "mysqli_query",
    "mysqli_real_query",
    "mysqli_multi_query",
    
    # PostgreSQL
    "pg_query",
    "pg_send_query",
    "pg_query_params",
    "pg_send_query_params",
    
    # SQL Server
    "sqlsrv_query",
    
    # Oracle
    "oci_execute",
    
    # SQLite
    "sqlite_query",
    "sqlite_exec",
    "sqlite_single_query",
    "sqlite3_exec",
    "sqlite3_query",
    
    # ODBC
    "odbc_exec",
    "odbc_do",
    
    # Firebird/Interbase
    "ibase_query",
    
    # DB2
    "db2_exec",
    
    # Sybase
    "sybase_query",
    
    # Informix
    "ifx_query",
    
    # mSQL
    "msql_query",
    "msql_db_query",
    
    # Ingres
    "ingres_query",
    
    # Cubrid
    "cubrid_query",
    
    # FrontBase
    "fbsql_query",
    "fbsql_db_query",
    
    # 废弃但可能存在的
    "mssql_query",
}

_SQL_METHOD_NAMES = {
 # MySQLi
    "query",
    "real_query",
    "multi_query",
    
    # PDO
    "exec",
    "query",
    
    # SQLite3
    "exec",
    "query",
    
    # 通用的数据库抽象层方法（直接执行SQL的）
    "select",
    "insert",
    "update",
    "delete",
    "replace",
    "findBySql",
    "queryAll",
    "queryOne",
    "queryColumn",
    "queryRow",
    "queryScalar",
    "executeSql",
    "runQuery",
    "runSql",
    "doQuery",
}


def _norm_name(s: str) -> str:
    v = (s or "").strip()
    if not v:
        return ""
    if "(" in v:
        v = v.split("(", 1)[0].strip()
    if v.startswith("\\"):
        v = v[1:]
    return v.lower()


def _norm_receiver(s: str) -> str:
    v = (s or "").strip()
    if not v:
        return ""
    if v.startswith("$"):
        v = v[1:]
    if "(" in v:
        v = v.split("(", 1)[0].strip()
    if "->" in v:
        v = v.split("->", 1)[0].strip()
    if "." in v:
        v = v.split(".", 1)[0].strip()
    return v.lower()


def _sorted_children(nid: int, nodes: dict, children_of: Dict[int, List[int]]) -> List[int]:
    ch = list(children_of.get(int(nid), []) or [])
    ch.sort(
        key=lambda cid: (nodes.get(int(cid)) or {}).get("childnum")
        if (nodes.get(int(cid)) or {}).get("childnum") is not None
        else 10**9
    )
    return ch


def _method_call_parts(call_id: int, nodes: dict, children_of: Dict[int, List[int]]) -> Tuple[str, str]:
    recv = method_call_receiver_name(int(call_id), children_of, nodes) or ""
    method = ""
    for c in _sorted_children(call_id, nodes, children_of):
        cx = nodes.get(int(c)) or {}
        ct = (cx.get("type") or "").strip()
        if ct == "AST_ARG_LIST":
            continue
        if (cx.get("labels") == "string") or (ct == "string"):
            v = (cx.get("code") or cx.get("name") or "").strip()
            if v:
                method = v
                break
        if ct == "AST_NAME":
            ssc = get_string_children(int(c), children_of, nodes)
            if ssc:
                method = ssc[0][1] if isinstance(ssc[0], tuple) else ssc[0]
                if method:
                    break
    if not method:
        method = get_call_name(int(call_id), nodes, children_of) or ""
    code = (nodes.get(int(call_id)) or {}).get("code") or ""
    if not recv and "->" in code:
        head = code.split("(", 1)[0]
        left, right = head.split("->", 1)
        recv = left.strip()
        if not method:
            method = right.strip()
    return recv, method


def _record_for_seq(seq: int, trace_index_records: List[dict], seq_to_index: Dict[int, int]) -> Optional[dict]:
    idx = seq_to_index.get(int(seq))
    if isinstance(idx, int) and 0 <= idx < len(trace_index_records):
        return trace_index_records[idx]
    for r in trace_index_records or []:
        if seq in (r.get("seqs") or []):
            return r
    return None


def _load_trace_index_records(cfg: AppConfig, logger: Optional[Logger]) -> Optional[List[dict]]:
    trace_index_path = cfg.tmp_path("trace_index.json")
    recs = load_trace_index_records(trace_index_path)
    if recs is None and logger is not None:
        logger.warning("sql_trace_index_missing", path=trace_index_path)
    return recs


def _find_node_ids_for_seq(seq: int, trace_index_records: List[dict]) -> List[int]:
    seq_to_index = build_seq_to_index(trace_index_records)
    rec = _record_for_seq(int(seq), trace_index_records, seq_to_index)
    if not isinstance(rec, dict):
        return []
    out = []
    for nid in rec.get("node_ids") or []:
        try:
            out.append(int(nid))
        except Exception:
            continue
    return out


def _is_sql_call_node(nid: int, nodes: dict, children_of: Dict[int, List[int]]) -> Tuple[bool, dict]:
    nx = nodes.get(int(nid)) or {}
    t = (nx.get("type") or "").strip()
    if t in ("AST_CALL", "AST_STATIC_CALL"):
        name = _norm_name(get_call_name(int(nid), nodes, children_of))
        if name in _SQL_FUNC_NAMES:
            return True, {"id": int(nid), "type": t, "name": name}
        if name.startswith("mysqli::"):
            method = name.split("::", 1)[1]
            if method in _SQL_METHOD_NAMES:
                return True, {"id": int(nid), "type": t, "name": name}
        return False, {}
    if t == "AST_METHOD_CALL":
        recv, method = _method_call_parts(int(nid), nodes, children_of)
        recv_n = _norm_receiver(recv)
        method_n = _norm_name(method)
        if recv_n == "query" and method_n:
            return True, {"id": int(nid), "type": t, "name": method_n, "recv": recv_n}
        if method_n in _SQL_METHOD_NAMES:
            code = (nx.get("code") or "").lower()
            if recv_n or "->" in code:
                return True, {"id": int(nid), "type": t, "name": method_n, "recv": recv_n}
        return False, {}
    return False, {}


def find_sql_query_calls_in_record(record: dict, nodes: dict, children_of: Dict[int, List[int]]) -> List[dict]:
    if not isinstance(record, dict):
        return []
    hits = []
    for nid in record.get("node_ids") or []:
        try:
            nid_i = int(nid)
        except Exception:
            continue
        ok, info = _is_sql_call_node(int(nid_i), nodes, children_of)
        if ok:
            hits.append(info)
    return hits


def find_sql_query_calls_for_seq(seq: int, *, cfg: Optional[AppConfig] = None, logger: Optional[Logger] = None) -> List[dict]:
    cfg = cfg or load_app_config()
    trace_index_records = _load_trace_index_records(cfg, logger)
    if not trace_index_records:
        return []
    node_ids = _find_node_ids_for_seq(int(seq), trace_index_records)
    if not node_ids:
        return []
    nodes_path = cfg.find_input_file("nodes.csv")
    rels_path = cfg.find_input_file("rels.csv")
    nodes, _top_id_to_file = load_nodes(nodes_path)
    _parent_of, children_of = load_ast_edges(rels_path)
    hits = []
    for nid in node_ids:
        ok, info = _is_sql_call_node(int(nid), nodes, children_of)
        if ok:
            hits.append(info)
    if logger is not None:
        logger.info("sql_query_scan", seq=int(seq), hits=len(hits))
    return hits


def has_sql_query_in_seq(seq: int, *, cfg: Optional[AppConfig] = None, logger: Optional[Logger] = None) -> bool:
    hits = find_sql_query_calls_for_seq(int(seq), cfg=cfg, logger=logger)
    return bool(hits)


def _run_console_test(seq: int) -> None:
    cfg = load_app_config()
    lg = Logger(base_dir=cfg.test_dir, name="sql_query_detector", also_console=True)
    res = has_sql_query_in_seq(int(seq), cfg=cfg, logger=lg)
    print(res)


def main() -> None:
    _run_console_test(165440)


if __name__ == "__main__":
    main()
