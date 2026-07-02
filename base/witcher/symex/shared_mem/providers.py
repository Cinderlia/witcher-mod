import atexit
import os
import sys
import threading
import gzip
import time
from abc import ABC, abstractmethod
from typing import Optional

from common.logger import Logger
from utils.extractors.if_extract import load_ast_edges, load_nodes
from utils.trace_utils.trace_edges import load_trace_index_records

from .ast_store import ping_global_ast_master, release_global_ast_payloads, request_global_ast_payloads, resolve_global_ast_master_state_from_env
from .shared_payload_store import attach_payload_json, shared_payload_supported
from .trace_store import ping_pipeline_trace_master, release_pipeline_trace_payloads, request_pipeline_trace_payloads, resolve_pipeline_trace_master_state_from_env
from .shared_types import AnalyzeInputBundle, AstContextData, SharedMemorySettings, TraceContextData


class SharedMemoryBootstrapError(RuntimeError):
    pass


class SharedMemoryDataError(RuntimeError):
    pass


_AST_CACHE = {}
_AST_SIDECAR_CACHE = {}
_TRACE_CACHE = {}
_TRACE_SIDECAR_CACHE = {}
_TRACE_RECORDS_CACHE = {}
_CACHE_LOCK = threading.Lock()
_REGISTERED_RELEASES = set()
_REGISTERED_RELEASES_LOCK = threading.Lock()
_MASTER_ATTACH_CACHE = {}
_MASTER_ATTACH_CACHE_LOCK = threading.Lock()


def _is_linux() -> bool:
    return os.name == "posix" and sys.platform.startswith("linux")


def _read_trace_line(seq: int, trace_path: str) -> Optional[str]:
    if not trace_path or not os.path.exists(trace_path):
        return None
    try:
        seq_i = int(seq)
    except Exception:
        return None
    with open(trace_path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            if i != seq_i:
                continue
            line = (line or "").strip()
            if not line:
                return None
            prefix = line.split(" | ", 1)[0]
            if ":" not in prefix:
                return None
            path_part, line_part = prefix.rsplit(":", 1)
            try:
                ln = int(line_part)
            except Exception:
                return None
            return f"{path_part}:{ln}"
    return None


def _trace_locator_from_index(seq: int, trace_index_records, seq_to_index) -> Optional[str]:
    try:
        idx = int((seq_to_index or {}).get(int(seq)))
    except Exception:
        idx = None
    if idx is None:
        return None
    try:
        rec = (trace_index_records or [])[int(idx)] or {}
    except Exception:
        rec = {}
    path = str(rec.get("path") or "").strip()
    try:
        line = int(rec.get("line"))
    except Exception:
        line = 0
    if not path or line <= 0:
        return None
    return "%s:%d" % (path, int(line))


def _read_json(path: str):
    if not path or not os.path.exists(path):
        return {}
    try:
        import json
        opener = gzip.open if str(path).endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _read_json_from_source(*, path: str, payload_meta: Optional[dict] = None, require_shared: bool = False):
    if payload_meta:
        obj = attach_payload_json(payload_meta)
        if obj:
            return obj
        if require_shared:
            raise SharedMemoryDataError("shared payload attach failed: %s" % str(payload_meta.get("name") or path))
    obj = _read_json(path)
    if obj:
        return obj
    if require_shared and payload_meta:
        raise SharedMemoryDataError("shared payload content empty: %s" % str(payload_meta.get("name") or path))
    return {}


def _resolve_sidecar_path(*candidates: str) -> str:
    for path in candidates:
        if path and os.path.exists(path):
            return os.path.abspath(path)
    return os.path.abspath(candidates[0]) if candidates else ""


def _load_trace_sidecar_maps(trace_index_path: str, *, shared_payloads: Optional[dict] = None, require_shared: bool = False):
    trace_index_path = os.path.abspath(trace_index_path)
    shared_root = os.path.join(os.path.dirname(trace_index_path), "..", "shared_trace")
    shared_root = os.path.abspath(shared_root)
    seq_index_path = _resolve_sidecar_path(
        os.path.join(shared_root, "trace.seq_index.json.gz"),
        os.path.join(shared_root, "trace.seq_index.json"),
    )
    seq_loc_path = _resolve_sidecar_path(
        os.path.join(shared_root, "trace.seq_loc.json.gz"),
        os.path.join(shared_root, "trace.seq_loc.json"),
    )
    key = (seq_index_path, seq_loc_path)
    with _CACHE_LOCK:
        cached = _TRACE_SIDECAR_CACHE.get(key)
    if cached is not None:
        return cached
    shared_payloads = shared_payloads if isinstance(shared_payloads, dict) else {}
    seq_index_obj = _read_json_from_source(
        path=seq_index_path,
        payload_meta=(shared_payloads.get("seq_index") if isinstance(shared_payloads.get("seq_index"), dict) else None),
        require_shared=bool(require_shared and shared_payloads.get("seq_index")),
    )
    seq_loc_obj = _read_json_from_source(
        path=seq_loc_path,
        payload_meta=(shared_payloads.get("seq_loc") if isinstance(shared_payloads.get("seq_loc"), dict) else None),
        require_shared=bool(require_shared and shared_payloads.get("seq_loc")),
    )
    seq_to_index_raw = seq_index_obj.get("seq_to_index") if isinstance(seq_index_obj.get("seq_to_index"), dict) else {}
    seq_to_loc_raw = seq_loc_obj.get("seq_to_loc") if isinstance(seq_loc_obj.get("seq_to_loc"), dict) else {}
    seq_to_index = {}
    for k, v in (seq_to_index_raw or {}).items():
        try:
            seq_to_index[int(k)] = int(v)
        except Exception:
            continue
    seq_to_loc = {}
    for k, v in (seq_to_loc_raw or {}).items():
        try:
            seq_to_loc[int(k)] = str(v)
        except Exception:
            continue
    value = {
        "seq_index_path": seq_index_path,
        "seq_loc_path": seq_loc_path,
        "seq_to_index": seq_to_index,
        "seq_to_loc": seq_to_loc,
        "shared_payloads": bool(shared_payloads),
    }
    with _CACHE_LOCK:
        _TRACE_SIDECAR_CACHE[key] = value
    return value


def _load_trace_records_sidecar(trace_index_path: str, *, shared_payloads: Optional[dict] = None, require_shared: bool = False):
    trace_index_path = os.path.abspath(trace_index_path)
    shared_root = os.path.join(os.path.dirname(trace_index_path), "..", "shared_trace")
    shared_root = os.path.abspath(shared_root)
    records_path = _resolve_sidecar_path(
        os.path.join(shared_root, "trace.records.json.gz"),
        os.path.join(shared_root, "trace.records.json"),
    )
    with _CACHE_LOCK:
        cached = _TRACE_RECORDS_CACHE.get(records_path)
    if cached is not None:
        return cached
    shared_payloads = shared_payloads if isinstance(shared_payloads, dict) else {}
    obj = _read_json_from_source(
        path=records_path,
        payload_meta=(shared_payloads.get("records") if isinstance(shared_payloads.get("records"), dict) else None),
        require_shared=bool(require_shared and shared_payloads.get("records")),
    )
    records = obj.get("records") if isinstance(obj.get("records"), list) else []
    value = {
        "records_path": records_path,
        "record_count": int(obj.get("record_count") or len(records or [])),
        "records": records if isinstance(records, list) else [],
    }
    with _CACHE_LOCK:
        _TRACE_RECORDS_CACHE[records_path] = value
    return value


def _load_ast_context_cached(nodes_path: str, rels_path: str):
    key = (os.path.abspath(nodes_path), os.path.abspath(rels_path))
    with _CACHE_LOCK:
        cached = _AST_CACHE.get(key)
    if cached is not None:
        return cached
    nodes, top_id_to_file = load_nodes(nodes_path)
    parent_of, children_of = load_ast_edges(rels_path)
    value = (nodes, top_id_to_file, parent_of, children_of)
    with _CACHE_LOCK:
        _AST_CACHE[key] = value
    return value


def _load_ast_sidecar_context_cached(
    *,
    nodes_sidecar_path: str,
    top_files_path: str,
    parent_of_path: str,
    children_of_path: str,
    shared_payloads: Optional[dict] = None,
    require_shared: bool = False,
):
    key = (
        os.path.abspath(nodes_sidecar_path),
        os.path.abspath(top_files_path),
        os.path.abspath(parent_of_path),
        os.path.abspath(children_of_path),
    )
    with _CACHE_LOCK:
        cached = _AST_SIDECAR_CACHE.get(key)
    if cached is not None:
        return cached
    shared_payloads = shared_payloads if isinstance(shared_payloads, dict) else {}
    nodes_obj = _read_json_from_source(
        path=nodes_sidecar_path,
        payload_meta=(shared_payloads.get("nodes") if isinstance(shared_payloads.get("nodes"), dict) else None),
        require_shared=bool(require_shared and shared_payloads.get("nodes")),
    )
    top_files_obj = _read_json_from_source(
        path=top_files_path,
        payload_meta=(shared_payloads.get("top_files") if isinstance(shared_payloads.get("top_files"), dict) else None),
        require_shared=bool(require_shared and shared_payloads.get("top_files")),
    )
    parent_obj = _read_json_from_source(
        path=parent_of_path,
        payload_meta=(shared_payloads.get("parent_of") if isinstance(shared_payloads.get("parent_of"), dict) else None),
        require_shared=bool(require_shared and shared_payloads.get("parent_of")),
    )
    children_obj = _read_json_from_source(
        path=children_of_path,
        payload_meta=(shared_payloads.get("children_of") if isinstance(shared_payloads.get("children_of"), dict) else None),
        require_shared=bool(require_shared and shared_payloads.get("children_of")),
    )
    nodes_raw = nodes_obj.get("nodes") if isinstance(nodes_obj.get("nodes"), dict) else {}
    top_files_raw = top_files_obj.get("top_id_to_file") if isinstance(top_files_obj.get("top_id_to_file"), dict) else {}
    parent_raw = parent_obj.get("parent_of") if isinstance(parent_obj.get("parent_of"), dict) else {}
    children_raw = children_obj.get("children_of") if isinstance(children_obj.get("children_of"), dict) else {}
    nodes = {}
    for k, v in (nodes_raw or {}).items():
        try:
            nodes[int(k)] = v if isinstance(v, dict) else {}
        except Exception:
            continue
    top_id_to_file = {}
    for k, v in (top_files_raw or {}).items():
        try:
            top_id_to_file[int(k)] = str(v or "")
        except Exception:
            continue
    parent_of = {}
    for k, v in (parent_raw or {}).items():
        try:
            parent_of[int(k)] = int(v)
        except Exception:
            continue
    children_of = {}
    for k, v in (children_raw or {}).items():
        try:
            children_of[int(k)] = [int(x) for x in (v or [])]
        except Exception:
            continue
    value = (nodes, top_id_to_file, parent_of, children_of)
    with _CACHE_LOCK:
        _AST_SIDECAR_CACHE[key] = value
    return value


def _load_trace_context_cached(
    *,
    seq: int,
    trace_path: str,
    nodes_path: str,
    trace_index_path: str,
    logger: Logger,
    shared_payloads: Optional[dict] = None,
    require_shared: bool = False,
):
    key = (os.path.abspath(trace_path), os.path.abspath(trace_index_path))
    with _CACHE_LOCK:
        cached = _TRACE_CACHE.get(key)
    if cached is None:
        sidecar_records = _load_trace_records_sidecar(
            trace_index_path,
            shared_payloads=shared_payloads,
            require_shared=bool(require_shared),
        )
        trace_index_records = list(sidecar_records.get("records") or [])
        if not trace_index_records:
            trace_index_records = load_trace_index_records(trace_index_path)
            trace_index_records = trace_index_records if isinstance(trace_index_records, list) else []
        sidecar = _load_trace_sidecar_maps(
            trace_index_path,
            shared_payloads=shared_payloads,
            require_shared=bool(require_shared),
        )
        seq_to_index = dict(sidecar.get("seq_to_index") or {})
        if not seq_to_index:
            for idx, rec in enumerate(trace_index_records):
                if not isinstance(rec, dict):
                    continue
                record_index = rec.get("index")
                try:
                    record_index = int(record_index)
                except Exception:
                    record_index = int(idx)
                for raw_seq in rec.get("seqs") or []:
                    try:
                        seq_to_index[int(raw_seq)] = int(record_index)
                    except Exception:
                        continue
        cached = (list(trace_index_records or []), dict(seq_to_index or {}))
        with _CACHE_LOCK:
            _TRACE_CACHE[key] = cached
    trace_index_records, seq_to_index = cached
    sidecar = _load_trace_sidecar_maps(
        trace_index_path,
        shared_payloads=shared_payloads,
        require_shared=bool(require_shared),
    )
    trace_locator = str((sidecar.get("seq_to_loc") or {}).get(int(seq)) or "").strip()
    if not trace_locator:
        trace_locator = _trace_locator_from_index(int(seq), trace_index_records, seq_to_index)
    if not trace_locator:
        trace_locator = _read_trace_line(int(seq), trace_path)
    sidecar["records_path"] = _load_trace_records_sidecar(
        trace_index_path,
        shared_payloads=shared_payloads,
        require_shared=bool(require_shared),
    ).get("records_path")
    return trace_locator, trace_index_records, seq_to_index, sidecar


def _preload_trace_context_cached(
    *,
    trace_path: str,
    trace_index_path: str,
    logger: Optional[Logger] = None,
):
    trace_locator, trace_index_records, seq_to_index, sidecar = _load_trace_context_cached(
        seq=0,
        trace_path=trace_path,
        nodes_path="",
        trace_index_path=trace_index_path,
        logger=logger if logger is not None else Logger(base_dir=os.getcwd(), min_level="INFO", name="shared_mem_preload", also_console=False),
        shared_payloads=None,
        require_shared=False,
    )
    return {
        "trace_locator": str(trace_locator or ""),
        "trace_record_count": len(trace_index_records or []),
        "seq_to_index_count": len(seq_to_index or {}),
        "seq_to_loc_count": len((sidecar or {}).get("seq_to_loc") or {}),
        "records_path": (sidecar or {}).get("records_path") or "",
        "seq_index_path": (sidecar or {}).get("seq_index_path") or "",
        "seq_loc_path": (sidecar or {}).get("seq_loc_path") or "",
    }


def _read_bool(raw, default: bool) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        v = raw.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off"):
            return False
    return bool(default)


def _load_shared_memory_settings(cfg) -> SharedMemorySettings:
    raw = cfg.raw if hasattr(cfg, "raw") else {}
    obj = raw.get("symex_shared_memory") if isinstance(raw, dict) and isinstance(raw.get("symex_shared_memory"), dict) else {}
    enabled = _read_bool(os.environ.get("SYMEX_SHARED_MEMORY_ENABLED"), _read_bool(obj.get("enabled"), True))
    mode = str(os.environ.get("SYMEX_SHARED_MODE") or obj.get("mode") or "master_worker").strip() or "master_worker"
    require_linux = _read_bool(obj.get("require_linux"), True)
    fallback_legacy = _read_bool(obj.get("fallback_legacy"), False)
    fail_fast = _read_bool(obj.get("fail_fast_on_content_error"), True)
    return SharedMemorySettings(
        enabled=bool(enabled),
        mode=str(mode),
        require_linux=bool(require_linux),
        fallback_legacy=bool(fallback_legacy),
        fail_fast_on_content_error=bool(fail_fast),
    )


def _make_shared_logger(run_dir: str, name: str = "shared_mem") -> Logger:
    return Logger(
        base_dir=os.path.join(os.path.abspath(run_dir or "."), "shared_mem"),
        min_level="INFO",
        name=name,
        also_console=False,
    )


def _write_state(shared_logger: Logger, filename: str, obj: dict) -> None:
    try:
        shared_logger.write_json("", filename, obj)
    except Exception:
        pass


def _runtime_root_from_env(cfg) -> str:
    raw = os.environ.get("SYMEX_RUNTIME_ROOT") or ""
    if raw.strip():
        return os.path.abspath(raw.strip())
    config_path = str(getattr(cfg, "config_path", "") or "").strip()
    if config_path:
        return os.path.abspath(os.path.dirname(config_path))
    return ""


def _request_master_restart(runtime_root: str, filename: str, payload: dict, shared_logger: Logger) -> None:
    if not runtime_root:
        return
    path = os.path.join(os.path.abspath(runtime_root), "meta", filename)
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            import json
            json.dump(payload, f, ensure_ascii=False, indent=2)
        shared_logger.warning(
            "master_restart_requested",
            request_path=path,
            kind=str(payload.get("kind") or ""),
            reason=str(payload.get("reason") or ""),
        )
    except Exception:
        return


def _request_global_ast_master_restart(cfg, shared_logger: Logger, reason: str) -> None:
    runtime_root = _runtime_root_from_env(cfg)
    _request_master_restart(
        runtime_root,
        "global_ast_master.restart.request",
        {
            "kind": "global_ast_master",
            "reason": str(reason or ""),
            "requested_at": int(__import__("time").time()),
            "requester_pid": int(os.getpid()),
        },
        shared_logger,
    )


def _request_pipeline_trace_master_restart(cfg, shared_logger: Logger, reason: str) -> None:
    run_dir = str(os.environ.get("SYMEX_PIPELINE_RUN_DIR") or getattr(cfg, "base_dir", "") or "").strip()
    if not run_dir:
        return
    _request_master_restart(
        os.path.abspath(run_dir),
        "pipeline_trace_master.restart.request",
        {
            "kind": "pipeline_trace_master",
            "reason": str(reason or ""),
            "requested_at": int(__import__("time").time()),
            "requester_pid": int(os.getpid()),
        },
        shared_logger,
    )


def _master_attach_key(kind: str, socket_path: str) -> str:
    return "%s:%s" % (str(kind), os.path.abspath(socket_path or ""))


def _clear_master_attach_cache(kind: str, socket_path: str) -> None:
    key = _master_attach_key(kind, socket_path)
    with _MASTER_ATTACH_CACHE_LOCK:
        _MASTER_ATTACH_CACHE.pop(key, None)


def _get_master_attach_cached(kind: str, socket_path: str, pinger):
    key = _master_attach_key(kind, socket_path)
    with _MASTER_ATTACH_CACHE_LOCK:
        cached = _MASTER_ATTACH_CACHE.get(key)
    if not isinstance(cached, dict):
        return None
    if pinger is None:
        return cached.get("payload") if isinstance(cached.get("payload"), dict) else None
    ping = pinger(socket_path, timeout_sec=1.0)
    cached_pid = int(cached.get("master_pid") or 0)
    ping_pid = int(ping.get("pid") or 0) if isinstance(ping, dict) else 0
    if not isinstance(ping, dict) or ping.get("ok") is not True or (cached_pid > 0 and ping_pid > 0 and cached_pid != ping_pid):
        _clear_master_attach_cache(kind, socket_path)
        return None
    return cached.get("payload") if isinstance(cached.get("payload"), dict) else None


def _attach_master_payload_once(kind: str, socket_path: str, requester, releaser, pinger):
    cached = _get_master_attach_cached(kind, socket_path, pinger)
    if isinstance(cached, dict):
        return cached
    last_payload = None
    for attempt in range(3):
        attach_payload = requester(socket_path, timeout_sec=5.0 if attempt > 0 else 2.0)
        last_payload = attach_payload
        if isinstance(attach_payload, dict) and attach_payload.get("ok") is True:
            key = _master_attach_key(kind, socket_path)
            with _MASTER_ATTACH_CACHE_LOCK:
                _MASTER_ATTACH_CACHE[key] = {
                    "payload": dict(attach_payload),
                    "master_pid": int(attach_payload.get("pid") or 0),
                }
            _register_release_once(kind, socket_path, releaser)
            return attach_payload
        if attempt < 2:
            try:
                time.sleep(0.2 * float(attempt + 1))
            except Exception:
                pass
            if pinger is not None:
                ping = pinger(socket_path, timeout_sec=1.0)
                if not (isinstance(ping, dict) and ping.get("ok") is True):
                    break
    return last_payload


def _register_release_once(kind: str, socket_path: str, releaser) -> None:
    key = "%s:%s" % (str(kind), os.path.abspath(socket_path or ""))
    with _REGISTERED_RELEASES_LOCK:
        if key in _REGISTERED_RELEASES:
            return
        _REGISTERED_RELEASES.add(key)
    def _release():
        try:
            _clear_master_attach_cache(kind, socket_path)
            releaser(socket_path, timeout_sec=1.0)
        except Exception:
            return
    atexit.register(_release)


class AstStoreProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError()

    @property
    @abstractmethod
    def mode(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def load_ast_context(self, *, cfg, logger: Logger, shared_logger: Logger) -> AstContextData:
        raise NotImplementedError()


class TraceStoreProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError()

    @property
    @abstractmethod
    def mode(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def load_trace_context(self, *, seq: int, cfg, logger: Logger, shared_logger: Logger) -> TraceContextData:
        raise NotImplementedError()


class AnalyzeContextProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError()

    @property
    @abstractmethod
    def mode(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def load_inputs(self, *, seq: int, cfg, logger: Logger) -> AnalyzeInputBundle:
        raise NotImplementedError()


class FileAstStoreProvider(AstStoreProvider):
    @property
    def name(self) -> str:
        return "file_ast_provider"

    @property
    def mode(self) -> str:
        return "file"

    def load_ast_context(self, *, cfg, logger: Logger, shared_logger: Logger) -> AstContextData:
        nodes_path = cfg.find_input_file("nodes.csv")
        rels_path = cfg.find_input_file("rels.csv")
        nodes, top_id_to_file, parent_of, children_of = _load_ast_context_cached(nodes_path, rels_path)
        if not nodes:
            raise SharedMemoryDataError("nodes.csv loaded empty content")
        if not parent_of and not children_of:
            raise SharedMemoryDataError("rels.csv loaded empty content")
        logger.info(
            "ast_context_loaded",
            provider=self.name,
            mode=self.mode,
            nodes_path=nodes_path,
            rels_path=rels_path,
            node_count=len(nodes),
            parent_count=len(parent_of),
            child_count=len(children_of),
        )
        shared_logger.info(
            "ast_context_loaded",
            provider=self.name,
            mode=self.mode,
            nodes_path=nodes_path,
            rels_path=rels_path,
            node_count=len(nodes),
            parent_count=len(parent_of),
            child_count=len(children_of),
        )
        _write_state(
            shared_logger,
            "ast_provider_state.json",
            {
                "provider": self.name,
                "mode": self.mode,
                "nodes_path": nodes_path,
                "rels_path": rels_path,
                "node_count": len(nodes),
                "parent_count": len(parent_of),
                "child_count": len(children_of),
            },
        )
        return AstContextData(
            nodes_path=nodes_path,
            rels_path=rels_path,
            nodes=nodes,
            top_id_to_file=top_id_to_file,
            parent_of=parent_of,
            children_of=children_of,
        )


class SharedMasterAstStoreProvider(AstStoreProvider):
    @property
    def name(self) -> str:
        return "global_ast_master_provider"

    @property
    def mode(self) -> str:
        return "master_worker"

    def load_ast_context(self, *, cfg, logger: Logger, shared_logger: Logger) -> AstContextData:
        state = resolve_global_ast_master_state_from_env()
        socket_path = str(
            os.environ.get("SYMEX_GLOBAL_AST_MASTER_SOCK")
            or state.get("socket_path")
            or ""
        ).strip()
        if not state:
            _request_global_ast_master_restart(cfg, shared_logger, "global_ast_master_state_missing")
            raise SharedMemoryBootstrapError("global ast master state missing from environment")
        if str(state.get("status") or "") != "ready":
            _request_global_ast_master_restart(cfg, shared_logger, "global_ast_master_not_ready")
            raise SharedMemoryBootstrapError("global ast master not ready")
        ping = ping_global_ast_master(socket_path, timeout_sec=1.0)
        if not isinstance(ping, dict) or ping.get("ok") is not True:
            _request_global_ast_master_restart(cfg, shared_logger, "global_ast_master_ping_failed")
            raise SharedMemoryBootstrapError("global ast master ping failed")
        nodes_path = str(state.get("nodes_path") or "").strip()
        rels_path = str(state.get("rels_path") or "").strip()
        if not nodes_path or not os.path.exists(nodes_path):
            raise SharedMemoryDataError("global ast master nodes path missing")
        if not rels_path or not os.path.exists(rels_path):
            raise SharedMemoryDataError("global ast master rels path missing")
        nodes, top_id_to_file, parent_of, children_of = _load_ast_context_cached(nodes_path, rels_path)
        if not nodes:
            raise SharedMemoryDataError("global ast master nodes content empty")
        if not parent_of and not children_of:
            raise SharedMemoryDataError("global ast master rels content empty")
        logger.info(
            "ast_context_loaded",
            provider=self.name,
            mode=self.mode,
            nodes_path=nodes_path,
            rels_path=rels_path,
            node_count=len(nodes),
            parent_count=len(parent_of),
            child_count=len(children_of),
            socket_path=socket_path,
            shared_payload_ready=False,
            attach_via_socket=False,
            share_strategy="fork_ast_cache",
            master_ready_via_socket=True,
        )
        shared_logger.info(
            "ast_context_loaded",
            provider=self.name,
            mode=self.mode,
            nodes_path=nodes_path,
            rels_path=rels_path,
            node_count=len(nodes),
            parent_count=len(parent_of),
            child_count=len(children_of),
            socket_path=socket_path,
            shared_payload_ready=False,
            attach_via_socket=False,
            share_strategy="fork_ast_cache",
            master_ready_via_socket=True,
        )
        _write_state(
            shared_logger,
            "ast_provider_state.json",
            {
                "provider": self.name,
                "mode": self.mode,
                "nodes_path": nodes_path,
                "rels_path": rels_path,
                "socket_path": socket_path,
                "state_path": state.get("state_path"),
                "shared_payload_ready": False,
                "attach_via_socket": False,
                "share_strategy": "fork_ast_cache",
                "master_ready_via_socket": True,
                "node_count": len(nodes),
                "parent_count": len(parent_of),
                "child_count": len(children_of),
            },
        )
        return AstContextData(
            nodes_path=nodes_path,
            rels_path=rels_path,
            nodes=nodes,
            top_id_to_file=top_id_to_file,
            parent_of=parent_of,
            children_of=children_of,
        )


class FileTraceStoreProvider(TraceStoreProvider):
    @property
    def name(self) -> str:
        return "file_trace_provider"

    @property
    def mode(self) -> str:
        return "file"

    def load_trace_context(self, *, seq: int, cfg, logger: Logger, shared_logger: Logger) -> TraceContextData:
        trace_path = cfg.find_input_file("trace.log")
        trace_index_path = cfg.tmp_path("trace_index.json")
        os.makedirs(os.path.dirname(trace_index_path) or ".", exist_ok=True)
        trace_locator, trace_index_records, seq_to_index, trace_sidecar = _load_trace_context_cached(
            seq=int(seq),
            trace_path=trace_path,
            nodes_path=cfg.find_input_file("nodes.csv"),
            trace_index_path=trace_index_path,
            logger=logger,
        )
        if not trace_locator:
            raise SharedMemoryDataError("trace.log content missing for seq")
        logger.info(
            "trace_context_loaded",
            provider=self.name,
            mode=self.mode,
            seq=int(seq),
            trace_path=trace_path,
            trace_index_path=trace_index_path,
            trace_record_count=len(trace_index_records or []),
            seq_to_index_count=len(seq_to_index or {}),
            records_path=trace_sidecar.get("records_path"),
            seq_index_path=trace_sidecar.get("seq_index_path"),
            seq_loc_path=trace_sidecar.get("seq_loc_path"),
        )
        shared_logger.info(
            "trace_context_loaded",
            provider=self.name,
            mode=self.mode,
            seq=int(seq),
            trace_path=trace_path,
            trace_index_path=trace_index_path,
            trace_record_count=len(trace_index_records or []),
            seq_to_index_count=len(seq_to_index or {}),
            records_path=trace_sidecar.get("records_path"),
            seq_index_path=trace_sidecar.get("seq_index_path"),
            seq_loc_path=trace_sidecar.get("seq_loc_path"),
        )
        _write_state(
            shared_logger,
            "trace_provider_state.json",
            {
                "provider": self.name,
                "mode": self.mode,
                "seq": int(seq),
                "trace_path": trace_path,
                "trace_index_path": trace_index_path,
                "trace_locator": trace_locator,
                "trace_record_count": len(trace_index_records or []),
                "seq_to_index_count": len(seq_to_index or {}),
                "records_path": trace_sidecar.get("records_path"),
                "seq_index_path": trace_sidecar.get("seq_index_path"),
                "seq_loc_path": trace_sidecar.get("seq_loc_path"),
            },
        )
        return TraceContextData(
            trace_path=trace_path,
            trace_locator=trace_locator,
            trace_index_path=trace_index_path,
            trace_index_records=list(trace_index_records or []),
            seq_to_index=dict(seq_to_index or {}),
        )


class SharedMasterTraceStoreProvider(TraceStoreProvider):
    @property
    def name(self) -> str:
        return "pipeline_trace_master_provider"

    @property
    def mode(self) -> str:
        return "master_worker"

    def load_trace_context(self, *, seq: int, cfg, logger: Logger, shared_logger: Logger) -> TraceContextData:
        state = resolve_pipeline_trace_master_state_from_env()
        socket_path = str(
            os.environ.get("SYMEX_PIPELINE_TRACE_MASTER_SOCK")
            or state.get("socket_path")
            or ""
        ).strip()
        if not state:
            _request_pipeline_trace_master_restart(cfg, shared_logger, "pipeline_trace_master_state_missing")
            raise SharedMemoryBootstrapError("pipeline trace master state missing from environment")
        if str(state.get("status") or "") != "ready":
            _request_pipeline_trace_master_restart(cfg, shared_logger, "pipeline_trace_master_not_ready")
            raise SharedMemoryBootstrapError("pipeline trace master not ready")
        ping = ping_pipeline_trace_master(socket_path, timeout_sec=1.0)
        if not isinstance(ping, dict) or ping.get("ok") is not True:
            _request_pipeline_trace_master_restart(cfg, shared_logger, "pipeline_trace_master_ping_failed")
            raise SharedMemoryBootstrapError("pipeline trace master ping failed")
        trace_path = str(state.get("trace_path") or "").strip()
        trace_index_path = str(state.get("trace_index_path") or "").strip()
        if not trace_path or not os.path.exists(trace_path):
            raise SharedMemoryDataError("pipeline trace master trace path missing")
        if not trace_index_path or not os.path.exists(trace_index_path):
            raise SharedMemoryDataError("pipeline trace master trace_index path missing")
        trace_locator, trace_index_records, seq_to_index, trace_sidecar = _load_trace_context_cached(
            seq=int(seq),
            trace_path=trace_path,
            nodes_path=cfg.find_input_file("nodes.csv"),
            trace_index_path=trace_index_path,
            logger=logger,
            shared_payloads=None,
            require_shared=False,
        )
        if not trace_locator:
            raise SharedMemoryDataError("pipeline trace master trace content missing for seq")
        logger.info(
            "trace_context_loaded",
            provider=self.name,
            mode=self.mode,
            seq=int(seq),
            trace_path=trace_path,
            trace_index_path=trace_index_path,
            trace_record_count=len(trace_index_records or []),
            seq_to_index_count=len(seq_to_index or {}),
            socket_path=socket_path,
            records_path=trace_sidecar.get("records_path"),
            seq_index_path=trace_sidecar.get("seq_index_path"),
            seq_loc_path=trace_sidecar.get("seq_loc_path"),
            shared_payload_ready=False,
            attach_via_socket=False,
            share_strategy="processed_trace_cache",
            master_ready_via_socket=True,
        )
        shared_logger.info(
            "trace_context_loaded",
            provider=self.name,
            mode=self.mode,
            seq=int(seq),
            trace_path=trace_path,
            trace_index_path=trace_index_path,
            trace_record_count=len(trace_index_records or []),
            seq_to_index_count=len(seq_to_index or {}),
            socket_path=socket_path,
            records_path=trace_sidecar.get("records_path"),
            seq_index_path=trace_sidecar.get("seq_index_path"),
            seq_loc_path=trace_sidecar.get("seq_loc_path"),
            shared_payload_ready=False,
            attach_via_socket=False,
            share_strategy="processed_trace_cache",
            master_ready_via_socket=True,
        )
        _write_state(
            shared_logger,
            "trace_provider_state.json",
            {
                "provider": self.name,
                "mode": self.mode,
                "seq": int(seq),
                "trace_path": trace_path,
                "trace_index_path": trace_index_path,
                "trace_locator": trace_locator,
                "socket_path": socket_path,
                "state_path": state.get("state_path"),
                "trace_record_count": len(trace_index_records or []),
                "seq_to_index_count": len(seq_to_index or {}),
                "records_path": trace_sidecar.get("records_path"),
                "seq_index_path": trace_sidecar.get("seq_index_path"),
                "seq_loc_path": trace_sidecar.get("seq_loc_path"),
                "shared_payload_ready": False,
                "attach_via_socket": False,
                "share_strategy": "processed_trace_cache",
                "master_ready_via_socket": True,
            },
        )
        return TraceContextData(
            trace_path=trace_path,
            trace_locator=trace_locator,
            trace_index_path=trace_index_path,
            trace_index_records=list(trace_index_records or []),
            seq_to_index=dict(seq_to_index or {}),
        )


class DefaultAnalyzeContextProvider(AnalyzeContextProvider):
    def __init__(self, *, run_dir: str, settings: SharedMemorySettings, ast_provider: AstStoreProvider, trace_provider: TraceStoreProvider):
        self._run_dir = os.path.abspath(run_dir or ".")
        self._settings = settings
        self._ast_provider = ast_provider
        self._trace_provider = trace_provider
        self._shared_logger = _make_shared_logger(self._run_dir)

    @property
    def name(self) -> str:
        return "default_analyze_context_provider"

    @property
    def mode(self) -> str:
        return "ast=%s,trace=%s" % (self._ast_provider.mode, self._trace_provider.mode)

    def load_inputs(self, *, seq: int, cfg, logger: Logger) -> AnalyzeInputBundle:
        shared_logger = self._shared_logger
        _write_state(
            shared_logger,
            "provider_state.json",
            {
                "provider": self.name,
                "mode": self.mode,
                "ast_provider": self._ast_provider.name,
                "trace_provider": self._trace_provider.name,
                "shared_enabled": bool(self._settings.enabled),
                "shared_mode": self._settings.mode,
                "require_linux": bool(self._settings.require_linux),
                "fallback_legacy": bool(self._settings.fallback_legacy),
                "seq": int(seq),
            },
        )
        try:
            ast = self._ast_provider.load_ast_context(cfg=cfg, logger=logger, shared_logger=shared_logger)
            trace = self._trace_provider.load_trace_context(seq=int(seq), cfg=cfg, logger=logger, shared_logger=shared_logger)
            return AnalyzeInputBundle(
                seq=int(seq),
                provider_name=self.name,
                provider_mode=self.mode,
                settings=self._settings,
                ast=ast,
                trace=trace,
            )
        except Exception as exc:
            shared_logger.error(
                "provider_load_failed",
                provider=self.name,
                mode=self.mode,
                seq=int(seq),
                error=str(exc),
            )
            _write_state(
                shared_logger,
                "provider_failure.json",
                {
                    "provider": self.name,
                    "mode": self.mode,
                    "ast_provider": self._ast_provider.name,
                    "trace_provider": self._trace_provider.name,
                    "seq": int(seq),
                    "error": str(exc),
                    "shared_enabled": bool(self._settings.enabled),
                    "shared_mode": self._settings.mode,
                },
            )
            logger.error(
                "provider_load_failed",
                provider=self.name,
                mode=self.mode,
                seq=int(seq),
                error=str(exc),
            )
            raise


def build_analyze_context_provider(*, cfg, run_dir: str, logger: Logger) -> AnalyzeContextProvider:
    settings = _load_shared_memory_settings(cfg)
    shared_logger = _make_shared_logger(run_dir, name="shared_mem_bootstrap")
    shared_logger.info(
        "provider_bootstrap",
        enabled=bool(settings.enabled),
        mode=settings.mode,
        require_linux=bool(settings.require_linux),
        fallback_legacy=bool(settings.fallback_legacy),
        is_linux=bool(_is_linux()),
    )
    _write_state(
        shared_logger,
        "bootstrap_state.json",
        {
            "enabled": bool(settings.enabled),
            "mode": settings.mode,
            "require_linux": bool(settings.require_linux),
            "fallback_legacy": bool(settings.fallback_legacy),
            "is_linux": bool(_is_linux()),
        },
    )
    if settings.enabled and settings.require_linux and not _is_linux():
        msg = "shared memory mode requires linux"
        shared_logger.error("provider_bootstrap_failed", error=msg)
        if not settings.fallback_legacy:
            raise SharedMemoryBootstrapError(msg)
    ast_provider: AstStoreProvider = FileAstStoreProvider()
    if settings.enabled and settings.mode == "master_worker":
        state = resolve_global_ast_master_state_from_env()
        socket_path = str(
            os.environ.get("SYMEX_GLOBAL_AST_MASTER_SOCK")
            or state.get("socket_path")
            or ""
        ).strip()
        ping = ping_global_ast_master(socket_path, timeout_sec=1.0) if socket_path else None
        if state and str(state.get("status") or "") == "ready" and isinstance(ping, dict) and ping.get("ok") is True:
            ast_provider = SharedMasterAstStoreProvider()
            shared_logger.info(
                "shared_ast_provider_ready",
                provider=ast_provider.name,
                mode=ast_provider.mode,
                socket_path=socket_path,
                state_path=state.get("state_path"),
            )
        else:
            shared_logger.warning(
                "shared_ast_provider_unavailable",
                requested_mode=settings.mode,
                fallback_legacy=bool(settings.fallback_legacy),
                socket_path=socket_path,
                state_path=state.get("state_path") if isinstance(state, dict) else "",
            )
            if not settings.fallback_legacy:
                raise SharedMemoryBootstrapError("global ast master unavailable while fallback_legacy is disabled")
    trace_provider: TraceStoreProvider = FileTraceStoreProvider()
    if settings.enabled and settings.mode == "master_worker":
        trace_state = resolve_pipeline_trace_master_state_from_env()
        trace_socket_path = str(
            os.environ.get("SYMEX_PIPELINE_TRACE_MASTER_SOCK")
            or trace_state.get("socket_path")
            or ""
        ).strip()
        trace_ping = ping_pipeline_trace_master(trace_socket_path, timeout_sec=1.0) if trace_socket_path else None
        if trace_state and str(trace_state.get("status") or "") == "ready" and isinstance(trace_ping, dict) and trace_ping.get("ok") is True:
            trace_provider = SharedMasterTraceStoreProvider()
            shared_logger.info(
                "shared_trace_provider_ready",
                provider=trace_provider.name,
                mode=trace_provider.mode,
                socket_path=trace_socket_path,
                state_path=trace_state.get("state_path"),
            )
        else:
            shared_logger.warning(
                "shared_trace_provider_unavailable",
                requested_mode=settings.mode,
                fallback_legacy=bool(settings.fallback_legacy),
                socket_path=trace_socket_path,
                state_path=trace_state.get("state_path") if isinstance(trace_state, dict) else "",
            )
            if not settings.fallback_legacy:
                raise SharedMemoryBootstrapError("pipeline trace master unavailable while fallback_legacy is disabled")
    provider = DefaultAnalyzeContextProvider(
        run_dir=run_dir,
        settings=settings,
        ast_provider=ast_provider,
        trace_provider=trace_provider,
    )
    shared_logger.info(
        "provider_selected",
        provider=provider.name,
        mode=provider.mode,
        shared_enabled=bool(settings.enabled),
        shared_mode=settings.mode,
    )
    return provider
