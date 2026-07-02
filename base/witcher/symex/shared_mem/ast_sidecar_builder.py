import gzip
import json
import os
import time
from typing import Dict

from common.app_config import load_app_config
from utils.cpg_utils.graph_mapping import load_ast_edges, load_nodes


_AST_SIDECAR_VERSION = 3


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


def _build_ast_sidecar_content(nodes_path: str, rels_path: str) -> Dict[str, object]:
    nodes, top_id_to_file = load_nodes(nodes_path)
    parent_of, children_of = load_ast_edges(rels_path)
    nodes_json = {}
    for nid, nd in (nodes or {}).items():
        try:
            nodes_json[str(int(nid))] = {
                "type": nd.get("type") or "",
                "labels": nd.get("labels") or "",
                "flags": nd.get("flags") or "",
                "lineno": nd.get("lineno"),
                "code": nd.get("code") or "",
                "childnum": nd.get("childnum"),
                "funcid": nd.get("funcid"),
                "classname": nd.get("classname") or "",
                "namespace": nd.get("namespace") or "",
                "name": nd.get("name") or "",
                "doccomment": nd.get("doccomment") or "",
            }
        except Exception:
            continue
    top_files_json = {}
    for nid, path in (top_id_to_file or {}).items():
        try:
            top_files_json[str(int(nid))] = str(path or "")
        except Exception:
            continue
    parent_of_json = {}
    for child_id, parent_id in (parent_of or {}).items():
        try:
            parent_of_json[str(int(child_id))] = int(parent_id)
        except Exception:
            continue
    children_of_json = {}
    for parent_id, child_ids in (children_of or {}).items():
        try:
            children_of_json[str(int(parent_id))] = [int(x) for x in (child_ids or [])]
        except Exception:
            continue
    return {
        "nodes": nodes_json,
        "top_id_to_file": top_files_json,
        "parent_of": parent_of_json,
        "children_of": children_of_json,
        "node_count": len(nodes_json),
        "top_file_count": len(top_files_json),
        "parent_count": len(parent_of_json),
        "child_parent_count": len(children_of_json),
    }


def resolve_ast_inputs(*, runtime_root: str, runtime_config_path: str) -> Dict[str, str]:
    cfg = load_app_config(config_path=runtime_config_path, base_dir=runtime_root)
    nodes_path = cfg.find_input_file("nodes.csv")
    rels_path = cfg.find_input_file("rels.csv")
    return {
        "runtime_root": os.path.abspath(runtime_root),
        "runtime_config_path": os.path.abspath(runtime_config_path),
        "nodes_path": os.path.abspath(nodes_path),
        "rels_path": os.path.abspath(rels_path),
    }


def ensure_global_ast_sidecar(*, runtime_root: str, runtime_config_path: str, logger=None) -> Dict[str, object]:
    runtime_root = os.path.abspath(runtime_root)
    runtime_config_path = os.path.abspath(runtime_config_path)
    ast_inputs = resolve_ast_inputs(runtime_root=runtime_root, runtime_config_path=runtime_config_path)
    nodes_path = ast_inputs["nodes_path"]
    rels_path = ast_inputs["rels_path"]
    if not os.path.exists(nodes_path):
        raise FileNotFoundError("nodes.csv not found for global ast sidecar: %s" % nodes_path)
    if not os.path.exists(rels_path):
        raise FileNotFoundError("rels.csv not found for global ast sidecar: %s" % rels_path)

    shared_root = os.path.join(runtime_root, "shared_ast")
    os.makedirs(shared_root, exist_ok=True)
    header_path = os.path.join(shared_root, "ast.header.json")
    sources_path = os.path.join(shared_root, "ast.sources.json")
    nodes_sidecar_path = os.path.join(shared_root, "ast.nodes.json.gz")
    top_files_path = os.path.join(shared_root, "ast.top_files.json.gz")
    parent_of_path = os.path.join(shared_root, "ast.parent_of.json.gz")
    children_of_path = os.path.join(shared_root, "ast.children_of.json.gz")

    header = {
        "version": int(_AST_SIDECAR_VERSION),
        "builder_mode": "metadata_plus_ast_maps_gzip_phase9",
        "runtime_root": runtime_root,
        "runtime_config_path": runtime_config_path,
        "built_at": int(time.time()),
        "nodes": _safe_stat(nodes_path),
        "rels": _safe_stat(rels_path),
    }
    previous = _read_json(header_path)
    reused = False
    try:
        reused = (
            previous.get("version") == header.get("version")
            and isinstance(previous.get("nodes"), dict)
            and isinstance(previous.get("rels"), dict)
            and previous.get("nodes", {}).get("path") == header.get("nodes", {}).get("path")
            and previous.get("nodes", {}).get("size") == header.get("nodes", {}).get("size")
            and previous.get("nodes", {}).get("mtime") == header.get("nodes", {}).get("mtime")
            and previous.get("rels", {}).get("path") == header.get("rels", {}).get("path")
            and previous.get("rels", {}).get("size") == header.get("rels", {}).get("size")
            and previous.get("rels", {}).get("mtime") == header.get("rels", {}).get("mtime")
        )
    except Exception:
        reused = False
    if reused:
        header["reuse"] = True
        header["previous_built_at"] = previous.get("built_at")
    else:
        header["reuse"] = False
    sidecar_ready = (
        reused
        and os.path.exists(nodes_sidecar_path)
        and os.path.exists(top_files_path)
        and os.path.exists(parent_of_path)
        and os.path.exists(children_of_path)
    )
    if sidecar_ready:
        sidecar = {
            "node_count": int(previous.get("node_count") or 0),
            "top_file_count": int(previous.get("top_file_count") or 0),
            "parent_count": int(previous.get("parent_count") or 0),
            "child_parent_count": int(previous.get("child_parent_count") or 0),
        }
    else:
        sidecar = _build_ast_sidecar_content(nodes_path, rels_path)
        _write_json_gz(
            nodes_sidecar_path,
            {
                "nodes_path": nodes_path,
                "node_count": int(sidecar.get("node_count") or 0),
                "nodes": sidecar.get("nodes") or {},
            },
        )
        _write_json_gz(
            top_files_path,
            {
                "nodes_path": nodes_path,
                "top_file_count": int(sidecar.get("top_file_count") or 0),
                "top_id_to_file": sidecar.get("top_id_to_file") or {},
            },
        )
        _write_json_gz(
            parent_of_path,
            {
                "rels_path": rels_path,
                "parent_count": int(sidecar.get("parent_count") or 0),
                "parent_of": sidecar.get("parent_of") or {},
            },
        )
        _write_json_gz(
            children_of_path,
            {
                "rels_path": rels_path,
                "child_parent_count": int(sidecar.get("child_parent_count") or 0),
                "children_of": sidecar.get("children_of") or {},
            },
        )
    header["node_count"] = int(sidecar.get("node_count") or 0)
    header["top_file_count"] = int(sidecar.get("top_file_count") or 0)
    header["parent_count"] = int(sidecar.get("parent_count") or 0)
    header["child_parent_count"] = int(sidecar.get("child_parent_count") or 0)
    header["payload_encoding"] = "json+gzip"
    _write_json(header_path, header)
    _write_json(
        sources_path,
        {
            "runtime_root": runtime_root,
            "runtime_config_path": runtime_config_path,
            "nodes_path": nodes_path,
            "rels_path": rels_path,
            "nodes_sidecar_path": nodes_sidecar_path,
            "top_files_path": top_files_path,
            "parent_of_path": parent_of_path,
            "children_of_path": children_of_path,
            "header_path": header_path,
            "reused": bool(reused),
        },
    )
    if logger is not None:
        logger.info(
            "global_ast_sidecar_ready",
            nodes_path=nodes_path,
            rels_path=rels_path,
            nodes_sidecar_path=nodes_sidecar_path,
            top_files_path=top_files_path,
            parent_of_path=parent_of_path,
            children_of_path=children_of_path,
            header_path=header_path,
            sources_path=sources_path,
            reused=bool(reused),
            node_count=int(sidecar.get("node_count") or 0),
            parent_count=int(sidecar.get("parent_count") or 0),
            child_parent_count=int(sidecar.get("child_parent_count") or 0),
        )
    return {
        "shared_root": shared_root,
        "header_path": header_path,
        "sources_path": sources_path,
        "nodes_sidecar_path": nodes_sidecar_path,
        "top_files_path": top_files_path,
        "parent_of_path": parent_of_path,
        "children_of_path": children_of_path,
        "nodes_path": nodes_path,
        "rels_path": rels_path,
        "payload_encoding": "json+gzip",
        "reused": bool(reused),
    }
