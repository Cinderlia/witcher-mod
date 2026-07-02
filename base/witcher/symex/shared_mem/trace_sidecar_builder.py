import gzip
import json
import os
import time
from typing import Dict, Optional

from utils.trace_utils.trace_edges import load_trace_index_records


_TRACE_SIDECAR_VERSION = 3


def _safe_stat(path: str) -> Dict[str, object]:
    try:
        st = os.stat(path)
        return {
            "path": os.path.abspath(path),
            "size": int(st.st_size),
            "mtime": float(st.st_mtime),
        }
    except Exception:
        return {
            "path": os.path.abspath(path),
            "size": -1,
            "mtime": 0.0,
        }


def _read_json(path: str) -> Dict[str, object]:
    if not path or not os.path.exists(path):
        return {}
    try:
        opener = gzip.open if str(path).endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _write_json(path: str, obj: Dict[str, object]) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return path


def _write_json_gz(path: str, obj: Dict[str, object]) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=6) as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)
    return path


def _build_trace_sidecar_content(trace_index_path: str) -> Dict[str, object]:
    recs = load_trace_index_records(trace_index_path)
    recs = recs if isinstance(recs, list) else []
    seq_to_index = {}
    seq_to_loc = {}
    slim_records = []
    for idx, rec in enumerate(recs):
        if not isinstance(rec, dict):
            continue
        path = str(rec.get("path") or "").strip()
        try:
            line = int(rec.get("line") or 0)
        except Exception:
            line = 0
        record_index = rec.get("index")
        try:
            record_index = int(record_index)
        except Exception:
            record_index = int(idx)
        locator = ("%s:%d" % (path, int(line))) if path and line > 0 else ""
        try:
            node_ids = [int(x) for x in (rec.get("node_ids") or [])]
        except Exception:
            node_ids = []
        try:
            seqs = [int(x) for x in (rec.get("seqs") or [])]
        except Exception:
            seqs = []
        slim_records.append(
            {
                "index": int(record_index),
                "path": path,
                "line": int(line),
                "seqs": seqs,
                "node_ids": node_ids,
            }
        )
        for seq in seqs:
            key = str(int(seq))
            if key not in seq_to_index:
                seq_to_index[key] = int(record_index)
            if locator and key not in seq_to_loc:
                seq_to_loc[key] = locator
    return {
        "record_count": len(recs),
        "seq_to_index": seq_to_index,
        "seq_to_loc": seq_to_loc,
        "records": slim_records,
    }


def ensure_pipeline_trace_sidecar(
    *,
    run_dir: str,
    trace_path: str,
    trace_index_path: str,
    logger=None,
    global_ast_state_path: Optional[str] = None,
) -> Dict[str, object]:
    run_dir = os.path.abspath(run_dir)
    trace_path = os.path.abspath(trace_path)
    trace_index_path = os.path.abspath(trace_index_path)
    if not os.path.exists(trace_path):
        raise FileNotFoundError("trace.log not found for pipeline trace sidecar: %s" % trace_path)
    if not os.path.exists(trace_index_path):
        raise FileNotFoundError("trace_index.json not found for pipeline trace sidecar: %s" % trace_index_path)
    shared_root = os.path.join(run_dir, "shared_trace")
    os.makedirs(shared_root, exist_ok=True)
    header_path = os.path.join(shared_root, "trace.header.json")
    sources_path = os.path.join(shared_root, "trace.sources.json")
    records_path = os.path.join(shared_root, "trace.records.json.gz")
    seq_index_path = os.path.join(shared_root, "trace.seq_index.json.gz")
    seq_loc_path = os.path.join(shared_root, "trace.seq_loc.json.gz")
    header = {
        "version": int(_TRACE_SIDECAR_VERSION),
        "builder_mode": "metadata_plus_trace_records_gzip_phase9",
        "run_dir": run_dir,
        "built_at": int(time.time()),
        "trace": _safe_stat(trace_path),
        "trace_index": _safe_stat(trace_index_path),
        "global_ast_state_path": os.path.abspath(global_ast_state_path) if global_ast_state_path else "",
    }
    previous = _read_json(header_path)
    reused = False
    try:
        reused = (
            previous.get("version") == header.get("version")
            and isinstance(previous.get("trace"), dict)
            and isinstance(previous.get("trace_index"), dict)
            and previous.get("trace", {}).get("path") == header.get("trace", {}).get("path")
            and previous.get("trace", {}).get("size") == header.get("trace", {}).get("size")
            and previous.get("trace", {}).get("mtime") == header.get("trace", {}).get("mtime")
            and previous.get("trace_index", {}).get("path") == header.get("trace_index", {}).get("path")
            and previous.get("trace_index", {}).get("size") == header.get("trace_index", {}).get("size")
            and previous.get("trace_index", {}).get("mtime") == header.get("trace_index", {}).get("mtime")
        )
    except Exception:
        reused = False
    header["reuse"] = bool(reused)
    if reused:
        header["previous_built_at"] = previous.get("built_at")
    sidecar_ready = (
        reused
        and os.path.exists(records_path)
        and os.path.exists(seq_index_path)
        and os.path.exists(seq_loc_path)
    )
    if sidecar_ready:
        sidecar = {
            "record_count": int(previous.get("record_count") or 0),
            "seq_to_index_count": int(previous.get("seq_to_index_count") or 0),
            "seq_to_loc_count": int(previous.get("seq_to_loc_count") or 0),
            "records": [],
        }
    else:
        sidecar = _build_trace_sidecar_content(trace_index_path)
    header["record_count"] = int(sidecar.get("record_count") or 0)
    header["seq_to_index_count"] = int(sidecar.get("seq_to_index_count") or len(sidecar.get("seq_to_index") or {}))
    header["seq_to_loc_count"] = int(sidecar.get("seq_to_loc_count") or len(sidecar.get("seq_to_loc") or {}))
    header["payload_encoding"] = "json+gzip"
    _write_json(header_path, header)
    if not sidecar_ready:
        _write_json_gz(
            records_path,
            {
                "trace_index_path": trace_index_path,
                "record_count": int(sidecar.get("record_count") or 0),
                "records": sidecar.get("records") or [],
            },
        )
        _write_json_gz(
            seq_index_path,
            {
                "trace_index_path": trace_index_path,
                "record_count": int(sidecar.get("record_count") or 0),
                "seq_to_index": sidecar.get("seq_to_index") or {},
            },
        )
        _write_json_gz(
            seq_loc_path,
            {
                "trace_index_path": trace_index_path,
                "record_count": int(sidecar.get("record_count") or 0),
                "seq_to_loc": sidecar.get("seq_to_loc") or {},
            },
        )
    _write_json(
        sources_path,
        {
            "run_dir": run_dir,
            "trace_path": trace_path,
            "trace_index_path": trace_index_path,
            "header_path": header_path,
            "records_path": records_path,
            "seq_index_path": seq_index_path,
            "seq_loc_path": seq_loc_path,
            "global_ast_state_path": os.path.abspath(global_ast_state_path) if global_ast_state_path else "",
            "reused": bool(reused),
        },
    )
    if logger is not None:
        logger.info(
            "pipeline_trace_sidecar_ready",
            run_dir=run_dir,
            trace_path=trace_path,
            trace_index_path=trace_index_path,
            header_path=header_path,
            sources_path=sources_path,
            records_path=records_path,
            seq_index_path=seq_index_path,
            seq_loc_path=seq_loc_path,
            reused=bool(reused),
            record_count=int(sidecar.get("record_count") or 0),
            seq_to_index_count=int(sidecar.get("seq_to_index_count") or len(sidecar.get("seq_to_index") or {})),
            seq_to_loc_count=int(sidecar.get("seq_to_loc_count") or len(sidecar.get("seq_to_loc") or {})),
        )
    return {
        "shared_root": shared_root,
        "header_path": header_path,
        "sources_path": sources_path,
        "records_path": records_path,
        "seq_index_path": seq_index_path,
        "seq_loc_path": seq_loc_path,
        "trace_path": trace_path,
        "trace_index_path": trace_index_path,
        "payload_encoding": "json+gzip",
        "reused": bool(reused),
    }
