import os
import sys
from typing import Dict, List, Optional, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.app_config import AppConfig, load_app_config
from common.logger import Logger
from branch_selector.trace.trace_extract import build_seq_to_index
from utils.cpg_utils.graph_mapping import load_nodes, load_ast_edges
from utils.cpg_utils.trace_index import load_trace_index_records
from utils.cpg_utils.trace_call_edges import get_call_name


_XSS_FUNC_NAMES = {
    "printf",
}

_XSS_OUTPUT_NODE_TYPES = {
    "AST_ECHO",
    "AST_PRINT",
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
        logger.warning("xss_trace_index_missing", path=trace_index_path)
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


def _is_xss_output_node(nid: int, nodes: dict, children_of: Dict[int, List[int]]) -> Tuple[bool, dict]:
    nx = nodes.get(int(nid)) or {}
    t = (nx.get("type") or "").strip()
    if t in _XSS_OUTPUT_NODE_TYPES:
        name = "echo" if t == "AST_ECHO" else "print"
        return True, {"id": int(nid), "type": t, "name": name}
    if t in ("AST_CALL", "AST_STATIC_CALL", "AST_METHOD_CALL"):
        name = _norm_name(get_call_name(int(nid), nodes, children_of))
        if name in _XSS_FUNC_NAMES:
            return True, {"id": int(nid), "type": t, "name": name}
        return False, {}
    return False, {}


def find_xss_output_calls_in_record(record: dict, nodes: dict, children_of: Dict[int, List[int]]) -> List[dict]:
    if not isinstance(record, dict):
        return []
    hits = []
    for nid in record.get("node_ids") or []:
        try:
            nid_i = int(nid)
        except Exception:
            continue
        ok, info = _is_xss_output_node(int(nid_i), nodes, children_of)
        if ok:
            hits.append(info)
    return hits


def find_xss_output_calls_for_seq(seq: int, *, cfg: Optional[AppConfig] = None, logger: Optional[Logger] = None) -> List[dict]:
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
        ok, info = _is_xss_output_node(int(nid), nodes, children_of)
        if ok:
            hits.append(info)
    if logger is not None:
        logger.info("xss_output_scan", seq=int(seq), hits=len(hits))
    return hits


def has_xss_output_in_seq(seq: int, *, cfg: Optional[AppConfig] = None, logger: Optional[Logger] = None) -> bool:
    hits = find_xss_output_calls_for_seq(int(seq), cfg=cfg, logger=logger)
    return bool(hits)


def _run_console_test(seq: int) -> None:
    cfg = load_app_config()
    lg = Logger(base_dir=cfg.test_dir, name="xss_output_detector", also_console=True)
    res = has_xss_output_in_seq(int(seq), cfg=cfg, logger=lg)
    print(res)


def main() -> None:
    _run_console_test(1)


if __name__ == "__main__":
    main()
