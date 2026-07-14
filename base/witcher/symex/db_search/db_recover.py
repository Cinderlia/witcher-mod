import glob
import json
import logging
import os
import re
import struct
import threading
import time
from typing import Any, Dict, List, Optional

from .config import DBSearchRuntimeConfig
from .debug_log import append_jsonl_event
from .executor import execute_query_plan, find_fatal_db_execution
from .models import DBQueryPlan
from .runtime_bridge import resolve_db_runtime_paths

_LOG_PREFIX = "[db_recover]"
_SYNC_FILE_REL = os.path.join(".synced", "extsync")
_SQL_LOG_RE = re.compile(r"^(?P<fuzzer>.+?)_srcid-(?P<srcid>[^_]+)_newid-(?P<newid>[^_]+)_seq-(?P<seq>[^.]+)\.sql$")


def _safe_int(value: Any, default: int = -1) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


class DBRecoverDaemon(object):
    def __init__(self, runtime_cfg: DBSearchRuntimeConfig, work_dir: str, poll_interval: float = 5.0):
        self.runtime_cfg = runtime_cfg
        self.work_dir = os.path.abspath(work_dir or "")
        self.poll_interval = max(float(poll_interval), 0.5)
        self.paths = resolve_db_runtime_paths(work_dir=self.work_dir)
        self.runtime_dir = self.paths.runtime_dir if self.paths is not None else ""
        self.recover_dir = os.path.join(self.work_dir, "symex_runtime", "meta", "db_recover")
        self.progress_path = os.path.join(self.recover_dir, "progress.json")
        self.info_log_path = os.path.join(self.recover_dir, "info.log")
        self.error_log_path = os.path.join(self.recover_dir, "error.log")
        self._stop_event = threading.Event()
        self._thread = None
        self._logger = None
        self._error_logger = None
        self._progress = {}
        self._heartbeat_counter = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._ensure_layout()
        self._setup_logging()
        self._progress = self._load_progress()
        self._thread = threading.Thread(target=self._run, name="db_recover_daemon", daemon=True)
        self._thread.start()
        self._info("daemon_started", {"work_dir": self.work_dir, "runtime_dir": self.runtime_dir, "poll_interval": self.poll_interval})

    def stop(self, timeout: float = 5.0):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=max(float(timeout), 0.1))
        self._info("daemon_stopped", {})

    def _ensure_layout(self):
        os.makedirs(self.recover_dir, exist_ok=True)
        if self.runtime_dir:
            os.makedirs(self.runtime_dir, exist_ok=True)

    def _setup_logging(self):
        logger = logging.getLogger("witcher.db_recover.info.%s" % self.work_dir)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if not logger.handlers:
            handler = logging.FileHandler(self.info_log_path, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            logger.addHandler(handler)
        self._logger = logger
        error_logger = logging.getLogger("witcher.db_recover.error.%s" % self.work_dir)
        error_logger.setLevel(logging.INFO)
        error_logger.propagate = False
        if not error_logger.handlers:
            handler = logging.FileHandler(self.error_log_path, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            error_logger.addHandler(handler)
        self._error_logger = error_logger

    def _info(self, message: str, payload: Optional[Dict[str, Any]] = None):
        data = dict(payload or {})
        line = "%s %s %s" % (_LOG_PREFIX, str(message or "").strip(), json.dumps(data, ensure_ascii=False, sort_keys=True))
        if self._logger is not None:
            self._logger.info(line)

    def _error(self, message: str, payload: Optional[Dict[str, Any]] = None):
        data = dict(payload or {})
        line = "%s %s %s" % (_LOG_PREFIX, str(message or "").strip(), json.dumps(data, ensure_ascii=False, sort_keys=True))
        if self._error_logger is not None:
            self._error_logger.error(line)

    def _load_progress(self) -> Dict[str, Any]:
        if not os.path.isfile(self.progress_path):
            return {"applied_newid_by_fuzzer": {}}
        try:
            with open(self.progress_path, "r", encoding="utf-8", errors="replace") as f:
                obj = json.load(f)
        except Exception:
            return {"applied_newid_by_fuzzer": {}}
        if not isinstance(obj, dict):
            return {"applied_newid_by_fuzzer": {}}
        by_fuzzer = obj.get("applied_newid_by_fuzzer")
        if not isinstance(by_fuzzer, dict):
            by_fuzzer = {}
        return {"applied_newid_by_fuzzer": {str(k): _safe_int(v, -1) for k, v in by_fuzzer.items()}}

    def _save_progress(self):
        tmp_path = self.progress_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8", errors="replace") as f:
            json.dump(self._progress, f, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_path, self.progress_path)

    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._scan_once()
            except Exception as ex:
                self._error("scan_failed", {"error": str(ex)})
            self._heartbeat_counter += 1
            if self._heartbeat_counter % 12 == 1:
                self._info("heartbeat", {"known_fuzzers": sorted(list((self._progress.get("applied_newid_by_fuzzer") or {}).keys()))})
            self._stop_event.wait(self.poll_interval)

    def _scan_once(self):
        synced = self._read_synced_progresses()
        if not synced:
            self._info("no_synced_progress", {})
            return
        records = self._load_sql_records()
        if not records:
            self._info("no_sql_records", {"runtime_dir": self.runtime_dir})
            return
        for record in records:
            fuzzer = record.get("fuzzer")
            newid = _safe_int(record.get("newid"), -1)
            if not fuzzer or newid < 0:
                continue
            synced_newid = _safe_int(synced.get(fuzzer), -1)
            if synced_newid < newid:
                continue
            applied = _safe_int((self._progress.get("applied_newid_by_fuzzer") or {}).get(fuzzer), -1)
            if newid <= applied:
                continue
            self._apply_record(record)
            self._progress.setdefault("applied_newid_by_fuzzer", {})[fuzzer] = newid
            self._save_progress()

    def _read_synced_progresses(self) -> Dict[str, int]:
        out = {}
        pattern = os.path.join(self.work_dir, "fuzzer-*", _SYNC_FILE_REL)
        for path in glob.glob(pattern):
            fuzzer = os.path.basename(os.path.dirname(os.path.dirname(path)))
            value = self._read_extsync_value(path)
            if value is None:
                continue
            out[str(fuzzer)] = int(value)
        return out

    def _read_extsync_value(self, path: str) -> Optional[int]:
        try:
            with open(path, "rb") as f:
                data = f.read(4)
        except Exception as ex:
            self._error("read_extsync_failed", {"path": path, "error": str(ex)})
            return None
        if len(data) < 4:
            self._error("read_extsync_short", {"path": path, "size": len(data)})
            return None
        try:
            return int(struct.unpack("<I", data[:4])[0])
        except Exception as ex:
            self._error("read_extsync_unpack_failed", {"path": path, "error": str(ex)})
            return None

    def _load_sql_records(self) -> List[Dict[str, Any]]:
        out = []
        if not self.runtime_dir or not os.path.isdir(self.runtime_dir):
            return out
        for name in sorted(os.listdir(self.runtime_dir)):
            if not str(name).endswith(".sql"):
                continue
            match = _SQL_LOG_RE.match(str(name))
            if not match:
                continue
            path = os.path.join(self.runtime_dir, name)
            record = self._parse_sql_record(path, match.groupdict())
            if record is not None:
                out.append(record)
        out.sort(key=lambda item: (_safe_int(item.get("newid"), -1), str(item.get("fuzzer") or ""), str(item.get("path") or "")))
        return out

    def _parse_sql_record(self, path: str, meta: Dict[str, str]) -> Optional[Dict[str, Any]]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = [str(line or "").rstrip("\r\n") for line in f]
        except Exception as ex:
            self._error("read_sql_record_failed", {"path": path, "error": str(ex)})
            return None
        sqls = []
        undo_sqls = []
        section = "forward"
        for raw in lines:
            line = str(raw or "").strip()
            if not line:
                continue
            if line.startswith("-- undo_sql:"):
                value = line.split(":", 1)[1].strip()
                if value:
                    undo_sqls.append(value)
                continue
            if line == "-- undo_begin":
                section = "undo"
                continue
            if line == "-- undo_end":
                section = "forward"
                continue
            if line.startswith("--"):
                continue
            if section == "undo":
                undo_sqls.append(raw.strip())
            else:
                sqls.append(raw.strip())
        return {
            "path": path,
            "fuzzer": str(meta.get("fuzzer") or "").strip(),
            "srcid": str(meta.get("srcid") or "").strip(),
            "newid": _safe_int(meta.get("newid"), -1),
            "seq": str(meta.get("seq") or "").strip(),
            "sqls": [x for x in sqls if x],
            "undo_sqls": [x for x in undo_sqls if x],
        }

    def _apply_record(self, record: Dict[str, Any]):
        undo_sqls = [str(x or "").strip() for x in (record.get("undo_sqls") or []) if str(x or "").strip()]
        payload = {
            "fuzzer": record.get("fuzzer"),
            "newid": record.get("newid"),
            "path": record.get("path"),
            "undo_sql_count": len(undo_sqls),
        }
        if not undo_sqls:
            self._info("skip_empty_undo_sql", payload)
            return
        executions = []
        for idx, sql in enumerate(undo_sqls, 1):
            plan = DBQueryPlan(
                sql=sql,
                purpose="db_recover_undo_%d" % int(idx),
                phase="db_recover",
                allow_write=True,
                metadata={
                    "kind": "db_recover_undo",
                    "fuzzer": record.get("fuzzer"),
                    "newid": record.get("newid"),
                    "sql_log_path": record.get("path"),
                },
            )
            execution = execute_query_plan(plan, self.runtime_cfg, phase="db_recover")
            executions.append(execution)
        fatal = find_fatal_db_execution(executions)
        append_jsonl_event(
            runtime_dir=self.recover_dir,
            stream="events",
            payload={
                "kind": "db_recover_apply",
                "fuzzer": record.get("fuzzer"),
                "newid": record.get("newid"),
                "sql_log_path": record.get("path"),
                "undo_sqls": undo_sqls,
                "fatal": dict(fatal or {}),
            },
        )
        if fatal:
            self._error("apply_undo_sql_failed", {"detail": dict(fatal), **payload})
        else:
            self._info("apply_undo_sql_done", payload)


def start_db_recover_daemon(runtime_cfg: DBSearchRuntimeConfig, work_dir: str, poll_interval: float = 5.0):
    work_dir_s = os.path.abspath(work_dir or "")
    if not work_dir_s:
        return None
    daemon = DBRecoverDaemon(runtime_cfg=runtime_cfg, work_dir=work_dir_s, poll_interval=poll_interval)
    daemon.start()
    return daemon
