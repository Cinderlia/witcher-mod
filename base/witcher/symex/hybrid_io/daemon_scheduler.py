import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl

from common.process_kill_audit import record_process_kill
from hybrid_io.seed_picker import list_queue_dirs, pick_preferred_seed


_ID_RE = re.compile(r"id:(\d+)")
_SRC_RE = re.compile(r"(?:^|,)src:(\d+)(?:,|$)")
_ENV_RE = re.compile(r"env:([0-9A-Fa-f]+)")
_KV_SPLIT_RE = re.compile(r"[;&\n\r\t ]+")


def _read_json(path: str) -> Any:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def _write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def _load_prepare_report(runtime_root: str) -> Dict[str, str]:
    obj = _read_json(os.path.join(runtime_root, "meta", "prepare_report.json"))
    if not isinstance(obj, dict):
        return {}
    out: Dict[str, str] = {}
    v = obj.get("ast_dir")
    if isinstance(v, str) and v.strip():
        out["ast_dir"] = os.path.abspath(v.strip())
    c = obj.get("coverage_json_expected")
    if isinstance(c, str) and c.strip():
        out["coverage_json_path"] = c.strip()
    sc = obj.get("trace_session_capture_filename")
    if isinstance(sc, str) and sc.strip():
        out["trace_session_capture_filename"] = os.path.basename(sc.strip())
    return out


def _trace_session_capture_source_path(runtime_root: str) -> str:
    prep = _load_prepare_report(runtime_root)
    name = str(prep.get("trace_session_capture_filename") or "").strip()
    if not name:
        return ""
    return os.path.join("/tmp", "wc_session_trace", os.path.basename(name))


def _parent_seed_info_path(run_dir: str) -> str:
    return os.path.join(run_dir, "meta", "parent_seed_info.json")


def _parse_seed_id_text(path: str) -> str:
    m = _ID_RE.search(os.path.basename(path or ""))
    if not m:
        return ""
    return str(m.group(1) or "").strip()


def _parse_seed_env_id(path: str) -> str:
    m = _ENV_RE.search(os.path.basename(path or ""))
    if not m:
        return ""
    return str(m.group(1) or "").strip()


def _seed_dedupe_hash(path: str, seed_hash: str) -> str:
    base = str(seed_hash or "").strip()
    if not base:
        return ""
    env_id = _parse_seed_env_id(path).lower()
    if not env_id:
        return base
    return hashlib.sha1(("%s|env:%s" % (base, env_id)).encode("utf-8", errors="replace")).hexdigest()


def _source_fuzzer_name(queue_dir: str) -> str:
    try:
        name = os.path.basename(os.path.dirname(str(queue_dir or "").rstrip("/\\")))
    except Exception:
        name = ""
    return str(name or "").strip() or "unknown"


def _write_parent_seed_info(run_dir: str, *, seed_path: str, seed_id: Optional[int], seed_hash: str, queue_dir: str) -> str:
    path = _parent_seed_info_path(run_dir)
    seed_name = os.path.basename(str(seed_path or "").rstrip("/\\"))
    _write_json(
        path,
        {
            "seed_path": str(seed_path or ""),
            "seed_name": seed_name,
            "seed_id": (int(seed_id) if seed_id is not None else None),
            "seed_id_text": _parse_seed_id_text(seed_name),
            "seed_env_id": _parse_seed_env_id(seed_name),
            "seed_hash8": str((seed_hash or "")[:8]),
            "queue_dir": str(queue_dir or ""),
            "source_fuzzer": _source_fuzzer_name(queue_dir),
            "recorded_at": int(time.time()),
            "recorded_by_pid": int(os.getpid()),
        },
    )
    return path


def _parse_seed_id(path: str) -> Optional[int]:
    m = _ID_RE.search(os.path.basename(path or ""))
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _sha1_file(path: str, limit_bytes: int = 4 * 1024 * 1024) -> Optional[str]:
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha1()
    read_total = 0
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
                read_total += len(chunk)
                if read_total >= int(limit_bytes):
                    break
    except Exception:
        return None
    return h.hexdigest()


def _count_scanned_seeds(work_dir: str) -> int:
    total = 0
    for qd in list_queue_dirs(work_dir):
        try:
            with os.scandir(qd) as it:
                for ent in it:
                    try:
                        if ent.is_file() and ent.name.startswith("id:"):
                            total += 1
                    except Exception:
                        continue
        except Exception:
            continue
    return int(total)


def _list_new_seeds(queue_dir: str, last_id: int) -> Tuple[List[Tuple[int, str, float]], int]:
    out: List[Tuple[int, str, float]] = []
    max_id = int(last_id)
    if not queue_dir or not os.path.isdir(queue_dir):
        return out, max_id
    try:
        with os.scandir(queue_dir) as it:
            for ent in it:
                try:
                    if not ent.is_file():
                        continue
                    nm = ent.name
                    if not isinstance(nm, str) or not nm.startswith("id:"):
                        continue
                    sid = _parse_seed_id(ent.path)
                    if sid is None:
                        continue
                    sid_i = int(sid)
                    if sid_i <= int(last_id):
                        continue
                    try:
                        mt = float(ent.stat().st_mtime)
                    except Exception:
                        mt = 0.0
                    out.append((sid_i, ent.path, mt))
                    if sid_i > max_id:
                        max_id = sid_i
                except Exception:
                    continue
    except Exception:
        return out, max_id
    out.sort(key=lambda t: (int(t[0]), float(t[2])))
    return out, max_id


def _popcount(x: int) -> int:
    bc = getattr(int, "bit_count", None)
    if bc is not None:
        try:
            return int(bc(x))
        except Exception:
            return int(bin(int(x)).count("1"))
    return int(bin(int(x)).count("1"))


def _seed_signature(path: str, limit_bytes: int = 256 * 1024, bit_count: int = 2048) -> Optional[int]:
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as f:
            data = f.read(int(limit_bytes))
    except Exception:
        return None
    if not data:
        return 0
    parts = (data or b"").split(b"\x00")
    get_raw = parts[1] if len(parts) >= 2 else b""
    try:
        get_s = get_raw.decode("utf-8", errors="replace")
    except Exception:
        get_s = ""

    keys: List[str] = []
    if get_s:
        try:
            items = parse_qsl(get_s, keep_blank_values=True, strict_parsing=False)
        except Exception:
            items = []
        if items:
            for k, _v in items:
                kk = (k or "").strip()
                if kk:
                    keys.append(kk)
        else:
            for it in _KV_SPLIT_RE.split(get_s):
                if not it:
                    continue
                if "=" in it:
                    k, _v = it.split("=", 1)
                    kk = (k or "").strip()
                    if kk:
                        keys.append(kk)
                else:
                    kk = (it or "").strip()
                    if kk:
                        keys.append(kk)

    if not keys:
        return 0

    mask = int(bit_count) - 1
    sig = 0
    for k in keys:
        try:
            hb = hashlib.sha1(("g:k:%s" % k).encode("utf-8", errors="replace")).digest()
        except Exception:
            continue
        if not hb or len(hb) < 8:
            continue
        h = int.from_bytes(hb[:8], "little", signed=False)
        i1 = int(h) & mask
        i2 = int((h >> 17) & mask)
        sig |= (1 << i1)
        sig |= (1 << i2)
    return int(sig)


def _sig_distance(a: int, b: int) -> float:
    try:
        ia = int(a) & int(b)
        ua = int(a) | int(b)
        inter = _popcount(int(ia))
        union = _popcount(int(ua))
        if union <= 0:
            return 0.0
        return float(union - inter) / float(union)
    except Exception:
        return 0.0


def _safe_copy(src: str, dst: str) -> bool:
    if not src or not dst:
        return False
    try:
        os.makedirs(os.path.dirname(os.path.abspath(dst)) or ".", exist_ok=True)
        shutil.copy2(src, dst)
        return True
    except Exception:
        return False


def _safe_link_or_copy(src: str, dst: str) -> bool:
    if not src or not dst:
        return False
    if not os.path.exists(src):
        return False
    try:
        os.makedirs(os.path.dirname(os.path.abspath(dst)) or ".", exist_ok=True)
    except Exception:
        return False
    try:
        if os.path.lexists(dst):
            return True
    except Exception:
        pass
    try:
        os.symlink(src, dst)
        return True
    except Exception:
        return _safe_copy(src, dst)


def _seed_seen_path(runtime_root: str) -> str:
    return os.path.join(runtime_root, "meta", "seen_seed_hashes.json")


def _load_seen_hashes(runtime_root: str) -> Set[str]:
    obj = _read_json(_seed_seen_path(runtime_root))
    if isinstance(obj, dict) and isinstance(obj.get("hashes"), list):
        return {str(x) for x in obj.get("hashes") if isinstance(x, str)}
    if isinstance(obj, list):
        return {str(x) for x in obj if isinstance(x, str)}
    return set()


def _save_seen_hashes(runtime_root: str, hashes: Set[str]) -> None:
    _write_json(_seed_seen_path(runtime_root), {"hashes": sorted(set(hashes or set()))})


def _load_scheduler_limits(cfg_path: Optional[str]) -> Tuple[int, int]:
    obj = _read_json(cfg_path) if cfg_path else None
    if not isinstance(obj, dict):
        return 10, 1
    sec = obj.get("symex_scheduler") if isinstance(obj.get("symex_scheduler"), dict) else {}
    max_analyze = sec.get("max_analyze_procs")
    max_bs = sec.get("max_branch_selector_procs")
    try:
        max_analyze_i = int(max_analyze) if max_analyze is not None else 10
    except Exception:
        max_analyze_i = 10
    try:
        max_bs_i = int(max_bs) if max_bs is not None else 1
    except Exception:
        max_bs_i = 1
    return max(1, max_analyze_i), max(1, max_bs_i)


def _build_run_config(base_cfg_path: Optional[str], run_dir: str, extra: Optional[Dict[str, Any]] = None) -> str:
    base_obj = _read_json(base_cfg_path) if base_cfg_path else None
    if not isinstance(base_obj, dict):
        base_obj = {}
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k not in base_obj:
                base_obj[k] = v
    bs = base_obj.get("branch_selector") if isinstance(base_obj.get("branch_selector"), dict) else {}
    sch = base_obj.get("symex_scheduler") if isinstance(base_obj.get("symex_scheduler"), dict) else {}
    if "max_analyze_concurrency" not in bs:
        bs["max_analyze_concurrency"] = 10
    if "test_mode" not in bs:
        bs["test_mode"] = False
    if "analyze_llm_test_mode" not in bs:
        bs["analyze_llm_test_mode"] = False
    if "max_analyze_procs" not in sch:
        sch["max_analyze_procs"] = 10
    if "max_branch_selector_procs" not in sch:
        sch["max_branch_selector_procs"] = 1
    base_obj["branch_selector"] = bs
    base_obj["symex_scheduler"] = sch
    paths = base_obj.get("paths") if isinstance(base_obj.get("paths"), dict) else {}
    if not isinstance(paths, dict):
        paths = {}
    if "input_dir" not in paths:
        paths["input_dir"] = "input"
    if "tmp_dir" not in paths:
        paths["tmp_dir"] = "tmp"
    if "test_dir" not in paths:
        paths["test_dir"] = "test"
    if "output_dir" not in paths:
        paths["output_dir"] = "output"
    base_obj["paths"] = paths
    out_path = os.path.join(run_dir, "config.json")
    _write_json(out_path, base_obj)
    return out_path


def _symex_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _ProcInfo:
    def __init__(self, *, kind: str, popen: subprocess.Popen, run_dir: str, seed_hash: str, seed_path: str, meta: Dict[str, Any]):
        self.kind = kind
        self.popen = popen
        self.run_dir = run_dir
        self.seed_hash = seed_hash
        self.seed_path = seed_path
        self.meta = meta


class HybridDaemonScheduler:
    def __init__(
        self,
        *,
        runtime_root: str,
        work_dir: str,
        symex_cfg_path: Optional[str],
        trace_timeout: int,
        logger,
    ):
        self.runtime_root = runtime_root
        self.work_dir = work_dir
        self.symex_cfg_path = symex_cfg_path
        self.trace_timeout = int(trace_timeout)
        self.logger = logger

        self.max_analyze_procs, self.max_branch_selector_procs = _load_scheduler_limits(self.symex_cfg_path)

        self._seen_hashes = _load_seen_hashes(self.runtime_root)

        self._processed_by_queue: Dict[str, Dict[int, int]] = {}
        self._pending_analyze: List[Tuple[_ProcInfo, int, str]] = []
        self._running_pipeline: List[_ProcInfo] = []
        self._running_analyze: List[_ProcInfo] = []
        self._pending_emit: List[Tuple[_ProcInfo, int]] = []

        self._extsync_queue_dir = os.path.join(self.work_dir, "extsync", "queue")
        self._symex_dir = _symex_root()
        self._pipeline_py = os.path.join(self._symex_dir, "branch_selector", "pipeline.py")
        self._analyze_py = os.path.join(self._symex_dir, "analyze_if_line.py")
        self._last_status_ts = 0.0
        self._ast_dir = ""
        self._coverage_json_path = ""
        prep = _load_prepare_report(self.runtime_root)
        if isinstance(prep, dict):
            v = prep.get("ast_dir")
            if isinstance(v, str) and v.strip():
                self._ast_dir = os.path.abspath(v.strip())
            c = prep.get("coverage_json_path")
            if isinstance(c, str) and c.strip():
                self._coverage_json_path = c.strip()
        if not self._ast_dir and self.symex_cfg_path:
            try:
                self._ast_dir = os.path.join(os.path.dirname(os.path.abspath(self.symex_cfg_path)), "AST")
            except Exception:
                self._ast_dir = ""
        self._seed_sig_cache: Dict[str, int] = {}
        self._recent_seed_sigs: List[int] = []
        self._queue_last_id: Dict[str, int] = {}
        self._pending_seed_keys: Set[Tuple[str, int]] = set()
        self._pending_seeds: List[Tuple[int, str, str, float]] = []

    def _log(self, msg: str) -> None:
        try:
            self.logger(self.runtime_root, msg)
        except Exception:
            pass

    def _seed_run_name(self, seed_path: str, queue_dir: str, seed_hash: str) -> str:
        seed_name = os.path.basename(str(seed_path or "").rstrip("/\\")) or (seed_hash or "seed")[:8] or "seed"
        qd = os.path.abspath(str(queue_dir or ""))
        qd_base = os.path.basename(qd)
        if qd_base == "queue":
            qd_base = os.path.basename(os.path.dirname(qd))
        qd_base = str(qd_base or "").strip()
        if qd_base:
            return "%s__%s" % (qd_base, seed_name)
        return seed_name

    def _make_run_dir(self, seed_path: str, queue_dir: str, seed_hash: str) -> str:
        runs = os.path.join(self.runtime_root, "runs")
        os.makedirs(runs, exist_ok=True)
        name = self._seed_run_name(seed_path, queue_dir, seed_hash)
        run_dir = os.path.join(runs, name)
        if os.path.exists(run_dir):
            suffix = 1
            while True:
                candidate = os.path.join(runs, "%s__dup%d" % (name, int(suffix)))
                if not os.path.exists(candidate):
                    run_dir = candidate
                    break
                suffix += 1
        os.makedirs(run_dir, exist_ok=True)
        for d in ("input", "tmp", "test", "output", "meta", "traces"):
            os.makedirs(os.path.join(run_dir, d), exist_ok=True)
        return run_dir

    def _tail_text(self, s: str, limit: int = 2000) -> str:
        try:
            if s is None:
                return ""
            s = str(s)
        except Exception:
            return ""
        if limit is None or int(limit) <= 0:
            return s
        lim = int(limit)
        return s[-lim:] if len(s) > lim else s

    def _write_text(self, path: str, text: str) -> None:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(text or "")
        except Exception:
            pass

    def _read_text(self, path: str, limit: int = 2000) -> str:
        if not path or not os.path.isfile(path):
            return ""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
        except Exception:
            return ""
        return self._tail_text(data, limit=limit)

    def _run_trace_into(self, seed_path: str, run_dir: str, *, seed_id: Optional[int] = None, seed_hash: str = "") -> bool:
        trace_script = os.path.join(self.runtime_root, "commands", "run_trace_with_seed.sh")
        if not os.path.isfile(trace_script):
            self._log("trace_script_missing path=%s" % trace_script)
            return False
        inp_dir = os.path.join(run_dir, "input")
        os.makedirs(inp_dir, exist_ok=True)
        src_capture = _trace_session_capture_source_path(self.runtime_root)
        dst_capture = os.path.join(inp_dir, "session_capture.json")
        for path in (src_capture, dst_capture):
            if not path or not os.path.exists(path):
                continue
            try:
                os.remove(path)
            except Exception:
                pass
        self._log(
            "trace_start seed=%s seed_id=%s seed_hash8=%s run_dir=%s"
            % (seed_path, str(seed_id) if seed_id is not None else "", str((seed_hash or "")[:8]), run_dir)
        )
        try:
            proc = subprocess.run(
                ["bash", trace_script, seed_path],
                cwd=inp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(1, int(self.trace_timeout)),
                check=False,
            )
        except Exception as ex:
            self._log("trace_fail seed=%s error=%s" % (seed_path, str(ex)))
            return False
        trace_path = os.path.join(inp_dir, "trace.log")
        trace_ok = False
        if os.path.exists(trace_path):
            if proc.returncode == 0:
                trace_ok = True
            else:
                try:
                    with open(trace_path, "rb") as f:
                        line_count = sum(1 for _ in f)
                    if line_count > 100:
                        trace_ok = True
                except Exception:
                    pass
        if not trace_ok:
            out_path = os.path.join(inp_dir, "trace_stdout.log")
            err_path = os.path.join(inp_dir, "trace_stderr.log")
            self._write_text(out_path, proc.stdout or "")
            self._write_text(err_path, proc.stderr or "")
            stdout_tail = self._tail_text(proc.stdout or "")
            stderr_tail = self._tail_text(proc.stderr or "")
            cmd_out = os.path.join(inp_dir, "trace_cmd.stdout")
            cmd_err = os.path.join(inp_dir, "trace_cmd.stderr")
            cmd_rc = os.path.join(inp_dir, "trace_cmd.rc")
            cmd_env = os.path.join(inp_dir, "trace_cmd.env")
            cmd_stdout_tail = self._read_text(cmd_out)
            cmd_stderr_tail = self._read_text(cmd_err)
            cmd_rc_val = self._read_text(cmd_rc, limit=64)
            cmd_env_tail = self._read_text(cmd_env)
            self._log(
                "trace_fail seed=%s rc=%s trace_script=%s cwd=%s trace_log=%s stdout_log=%s stderr_log=%s trace_cmd_rc=%s trace_cmd_env=%s trace_cmd_stdout_tail=%s trace_cmd_stderr_tail=%s stdout_tail=%s stderr_tail=%s"
                % (
                    seed_path,
                    str(proc.returncode),
                    trace_script,
                    inp_dir,
                    trace_path,
                    out_path,
                    err_path,
                    cmd_rc_val.replace("\n", "\\n"),
                    cmd_env_tail.replace("\n", "\\n"),
                    cmd_stdout_tail.replace("\n", "\\n"),
                    cmd_stderr_tail.replace("\n", "\\n"),
                    stdout_tail.replace("\n", "\\n"),
                    stderr_tail.replace("\n", "\\n"),
                )
            )
            return False
        try:
            seed_dst = os.path.join(inp_dir, "seed.bin")
            _safe_copy(seed_path, seed_dst)
        except Exception:
            pass
        try:
            cmd_src = os.path.join(self.runtime_root, "commands", "test_command.txt")
            cmd_dst = os.path.join(inp_dir, "test_command.txt")
            cmd_txt = ""
            try:
                with open(cmd_src, "r", encoding="utf-8", errors="replace") as f:
                    cmd_txt = f.read()
            except Exception:
                cmd_txt = ""
            cookie_s = ""
            get_s = ""
            post_s = ""
            try:
                with open(seed_path, "rb") as f:
                    data = f.read()
                parts = (data or b"").split(b"\x00")
                cookie_s = (parts[0] if len(parts) > 0 else b"").decode("utf-8", errors="replace")
                get_s = (parts[1] if len(parts) > 1 else b"").decode("utf-8", errors="replace")
                post_s = (parts[2] if len(parts) > 2 else b"").decode("utf-8", errors="replace")
            except Exception:
                pass
            with open(cmd_dst, "w", encoding="utf-8", errors="replace") as f:
                if cmd_txt:
                    f.write(cmd_txt.rstrip() + "\n")
                f.write("COOKIE:" + (cookie_s or "").strip() + "\n")
                f.write("GET:" + (get_s or "").strip() + "\n")
                f.write("POST:" + (post_s or "").strip() + "\n")
        except Exception:
            pass
        if not src_capture:
            self._log("trace_session_capture_skip reason=missing_filename run_dir=%s" % run_dir)
        elif not os.path.exists(src_capture):
            self._log("trace_session_capture_missing source=%s run_dir=%s" % (src_capture, run_dir))
        else:
            try:
                _safe_copy(src_capture, dst_capture)
                self._log("trace_session_capture_copied source=%s dest=%s run_dir=%s" % (src_capture, dst_capture, run_dir))
            except Exception as ex:
                self._log("trace_session_capture_copy_failed source=%s dest=%s run_dir=%s error=%s" % (src_capture, dst_capture, run_dir, str(ex)))
        return True

    def _spawn_pipeline(self, seed_path: str, seed_hash: str, run_dir: str) -> Optional[_ProcInfo]:
        emit_path = os.path.join(run_dir, "meta", "emit_seqs.json")
        cfg_path = os.path.join(self.runtime_root, "config.json")
        bs_cfg_path = self.symex_cfg_path or os.path.join(self._symex_dir, "config.json")
        env = dict(os.environ)
        env["JOERNTRACE_CONFIG"] = cfg_path
        env["WC_EXTERNAL_SEED_DIR"] = self._extsync_queue_dir
        try:
            env["WC_SEED_SCANNED_COUNT"] = str(int(_count_scanned_seeds(self.work_dir)))
        except Exception:
            env["WC_SEED_SCANNED_COUNT"] = "0"
        try:
            env["WC_BRANCH_SELECTOR_CALLED_COUNT"] = str(int(len(self._seen_hashes)))
        except Exception:
            env["WC_BRANCH_SELECTOR_CALLED_COUNT"] = "0"
        out_fp = open(os.path.join(run_dir, "meta", "branch_selector.out"), "a", encoding="utf-8", errors="replace")
        err_fp = open(os.path.join(run_dir, "meta", "branch_selector.err"), "a", encoding="utf-8", errors="replace")
        try:
            p = subprocess.Popen(
                [sys.executable, self._pipeline_py, bs_cfg_path, "--config", cfg_path, "--emit-seqs", emit_path],
                cwd=run_dir,
                stdout=out_fp,
                stderr=err_fp,
                env=env,
            )
        except Exception:
            try:
                out_fp.close()
                err_fp.close()
            except Exception:
                pass
            return None
        info = _ProcInfo(
            kind="branch_selector",
            popen=p,
            run_dir=run_dir,
            seed_hash=seed_hash,
            seed_path=seed_path,
            meta={"emit_path": emit_path, "cfg_path": cfg_path},
        )
        self._log("branch_selector_start seed=%s run_dir=%s pid=%s" % (seed_path, run_dir, str(p.pid)))
        return info

    def _spawn_analyze(self, parent: _ProcInfo, seq: int, mode: str) -> Optional[_ProcInfo]:
        env = dict(os.environ)
        env["JOERNTRACE_CONFIG"] = cfg_path
        env["WC_EXTERNAL_SEED_DIR"] = self._extsync_queue_dir
        cfg_path = os.path.join(self.runtime_root, "config.json")
        args = [sys.executable, self._analyze_py, str(int(seq)), "--config", cfg_path, "--debug", "--prompt", "--llm"]
        if mode == "sql":
            args.append("--sql")
        elif mode == "xss":
            args.append("--xss")
        elif mode == "cmd":
            args.append("--cmd")
        out_fp = open(os.path.join(parent.run_dir, "meta", "analyze_%d.out" % int(seq)), "a", encoding="utf-8", errors="replace")
        err_fp = open(os.path.join(parent.run_dir, "meta", "analyze_%d.err" % int(seq)), "a", encoding="utf-8", errors="replace")
        try:
            p = subprocess.Popen(args, cwd=parent.run_dir, stdout=out_fp, stderr=err_fp, env=env)
        except Exception:
            try:
                out_fp.close()
                err_fp.close()
            except Exception:
                pass
            return None
        info = _ProcInfo(
            kind="analyze",
            popen=p,
            run_dir=parent.run_dir,
            seed_hash=parent.seed_hash,
            seed_path=parent.seed_path,
            meta={"seq": int(seq), "mode": mode},
        )
        self._log("analyze_start seq=%d mode=%s seed_hash=%s pid=%s" % (int(seq), mode, (parent.seed_hash or "")[:8], str(p.pid)))
        try:
            logs_dir = os.path.join(parent.run_dir, "test", "seqs", "seq_%d" % int(seq), "logs")
            os.makedirs(logs_dir, exist_ok=True)
            with open(os.path.join(logs_dir, "parent_exit_observation.ndjson"), "a", encoding="utf-8", errors="replace") as f:
                f.write(json.dumps({
                    "ts": int(time.time()),
                    "phase": "daemon_scheduler_analyze_spawned",
                    "seq": int(seq),
                    "pid": int(os.getpid()),
                    "ppid": int(os.getppid()),
                    "rc": None,
                    "child_pid": int(p.pid),
                    "child_alive": True,
                    "child_status": "spawned",
                    "note": "daemon scheduler spawned analyze",
                    "seed_hash": str((parent.seed_hash or "")[:8]),
                }, ensure_ascii=False, sort_keys=True) + "\n")
        except Exception:
            pass
        return info

    def _poll_finished(self, procs: List[_ProcInfo]) -> Tuple[List[_ProcInfo], List[_ProcInfo]]:
        done = []
        alive = []
        for p in procs:
            rc = p.popen.poll()
            if rc is None:
                alive.append(p)
                continue
            done.append(p)
        return alive, done

    def _load_emit_items(self, proc: _ProcInfo) -> List[dict]:
        emit_path = proc.meta.get("emit_path")
        if not isinstance(emit_path, str) or not os.path.exists(emit_path):
            return []
        obj = _read_json(emit_path)
        items = obj.get("items") if isinstance(obj, dict) else None
        return items if isinstance(items, list) else []

    def _drain_pending_emit(self) -> None:
        if not self._pending_emit:
            return
        keep: List[Tuple[_ProcInfo, int]] = []
        for proc, tries in list(self._pending_emit):
            emit_path = proc.meta.get("emit_path")
            if not isinstance(emit_path, str):
                continue
            if not os.path.exists(emit_path):
                if int(tries) < 20:
                    keep.append((proc, int(tries) + 1))
                else:
                    self._log("emit_seqs_missing run_dir=%s seed_hash=%s" % (proc.run_dir, (proc.seed_hash or "")[:8]))
                continue
            items = self._load_emit_items(proc)
            if not items:
                if int(tries) < 20:
                    keep.append((proc, int(tries) + 1))
                else:
                    self._log("emit_seqs_empty path=%s seed_hash=%s" % (emit_path, (proc.seed_hash or "")[:8]))
                continue
            enq = 0
            for it in items:
                if not isinstance(it, dict):
                    continue
                seq = it.get("seq")
                mode = it.get("mode") or "if"
                try:
                    self._pending_analyze.append((proc, int(seq), str(mode)))
                    enq += 1
                except Exception:
                    continue
            self._log("emit_seqs_loaded path=%s count=%d seed_hash=%s" % (emit_path, int(enq), (proc.seed_hash or "")[:8]))
        self._pending_emit = keep

    def _estimate_child_count(self, queue_dir: str, seed_id: int) -> int:
        try:
            qd = queue_dir
            cnt = 0
            for nm in os.listdir(qd):
                if not isinstance(nm, str):
                    continue
                m = _SRC_RE.search(nm)
                if not m:
                    continue
                try:
                    if int(m.group(1)) == int(seed_id):
                        cnt += 1
                except Exception:
                    continue
            return int(cnt)
        except Exception:
            return 0

    def _refresh_pending_seeds(self) -> None:
        for qd in list_queue_dirs(self.work_dir):
            last_id = int(self._queue_last_id.get(qd, -1))
            seeds, new_last = _list_new_seeds(qd, last_id)
            if int(new_last) > int(last_id):
                self._queue_last_id[qd] = int(new_last)
            for sid, path, mt in seeds:
                key = (str(qd), int(sid))
                if key in self._pending_seed_keys:
                    continue
                self._pending_seed_keys.add(key)
                self._pending_seeds.append((int(sid), str(path), str(qd), float(mt)))

    def _remove_pending(self, qd: str, sid: int) -> None:
        qd_s = str(qd)
        sid_i = int(sid)
        self._pending_seed_keys.discard((qd_s, sid_i))
        self._pending_seeds = [t for t in self._pending_seeds if not (str(t[2]) == qd_s and int(t[0]) == sid_i)]

    def _pick_pending_seed(self) -> Optional[Tuple[str, str, Optional[int], float]]:
        if not self._pending_seeds:
            return None
        exts = []
        for sid, path, qd, mt in self._pending_seeds:
            nm = os.path.basename(path or "")
            if "extsync" in (nm or "").lower():
                exts.append((int(sid), float(mt), str(path), str(qd)))
        if exts:
            exts.sort(key=lambda t: (int(t[0]), float(t[1])))
            sid, mt, path, qd = exts[-1]
            self._remove_pending(qd, sid)
            return path, qd, int(sid), float(mt)

        best = None
        best_key = None
        for sid, path, qd, mt in self._pending_seeds:
            sig2 = _seed_signature(path, limit_bytes=64 * 1024, bit_count=2048)
            sig = int(sig2) if sig2 is not None else 0
            if self._recent_seed_sigs:
                try:
                    div = min(_sig_distance(sig, int(x)) for x in self._recent_seed_sigs)
                except Exception:
                    div = 0.0
            else:
                div = 1.0
            div_score = int(max(0.0, min(1.0, float(div))) * 10000.0)
            key = (int(div_score), float(mt), int(sid))
            if best is None or key > best_key:
                best = (str(path), str(qd), int(sid), float(mt), int(sig))
                best_key = key
        if not best:
            sid, path, qd, mt = self._pending_seeds.pop(0)
            self._pending_seed_keys.discard((str(qd), int(sid)))
            return str(path), str(qd), int(sid), float(mt)
        path, qd, sid, mt, _sig = best
        self._remove_pending(qd, sid)
        return str(path), str(qd), int(sid), float(mt)

    def _pick_next_seed(self) -> Optional[Tuple[str, str, str, Optional[int], int, int, str]]:
        self._refresh_pending_seeds()
        if not self._pending_seeds:
            return None
        attempts = 0
        while attempts < 50:
            attempts += 1
            picked = self._pick_pending_seed()
            if not picked:
                return None
            cand, qd, sid, mt = picked
            sh = _sha1_file(cand)
            dedupe_hash = _seed_dedupe_hash(cand, sh or "")
            if not sh:
                continue
            if not dedupe_hash:
                continue
            if dedupe_hash in self._seen_hashes:
                proc_map = self._processed_by_queue.setdefault(qd, {})
                if sid is not None:
                    proc_map[int(sid)] = int(proc_map.get(int(sid), 0)) + 1
                continue
            child_cnt = int(self._estimate_child_count(qd, int(sid))) if sid is not None else 0
            sig = self._seed_sig_cache.get(sh)
            if sig is None:
                sig2 = _seed_signature(cand, limit_bytes=64 * 1024, bit_count=2048)
                sig = int(sig2) if sig2 is not None else 0
                self._seed_sig_cache[str(sh)] = int(sig)
            return cand, sh, qd, sid, int(child_cnt), int(sig), dedupe_hash
        return None

    def tick(self) -> None:
        now = time.time()
        if (now - float(self._last_status_ts)) >= 10.0:
            self._last_status_ts = float(now)
            self._log(
                "sched_status running_pipeline=%d running_analyze=%d pending_analyze=%d pending_emit=%d"
                % (
                    len(self._running_pipeline),
                    len(self._running_analyze),
                    len(self._pending_analyze),
                    len(self._pending_emit),
                )
            )
        self._running_pipeline, done_pipes = self._poll_finished(self._running_pipeline)
        for p in done_pipes:
            rc = p.popen.returncode
            self._log("branch_selector_done rc=%s seed_hash=%s run_dir=%s" % (str(rc), (p.seed_hash or "")[:8], p.run_dir))
            self._pending_emit.append((p, 0))
        self._drain_pending_emit()

        self._running_analyze, done_an = self._poll_finished(self._running_analyze)
        for a in done_an:
            rc = a.popen.returncode
            self._log("analyze_done rc=%s seq=%s seed_hash=%s" % (str(rc), str(a.meta.get("seq")), (a.seed_hash or "")[:8]))
            try:
                logs_dir = os.path.join(a.run_dir, "test", "seqs", "seq_%d" % int(a.meta.get("seq") or 0), "logs")
                os.makedirs(logs_dir, exist_ok=True)
                with open(os.path.join(logs_dir, "parent_exit_observation.ndjson"), "a", encoding="utf-8", errors="replace") as f:
                    f.write(json.dumps({
                        "ts": int(time.time()),
                        "phase": "daemon_scheduler_analyze_done",
                        "seq": int(a.meta.get("seq") or 0),
                        "pid": int(os.getpid()),
                        "ppid": int(os.getppid()),
                        "rc": (int(rc) if rc is not None else None),
                        "child_pid": int(getattr(a.popen, "pid", 0) or 0),
                        "child_alive": False,
                        "child_status": "poll_finished",
                        "note": "daemon scheduler observed analyze completion",
                        "seed_hash": str((a.seed_hash or "")[:8]),
                    }, ensure_ascii=False, sort_keys=True) + "\n")
            except Exception:
                pass

        while self._pending_analyze and len(self._running_analyze) < int(self.max_analyze_procs):
            parent, seq, mode = self._pending_analyze.pop(0)
            info = self._spawn_analyze(parent, int(seq), str(mode))
            if info is not None:
                self._running_analyze.append(info)

        if len(self._running_pipeline) >= int(self.max_branch_selector_procs):
            return
        if len(self._running_analyze) >= int(self.max_analyze_procs):
            return

        picked = self._pick_next_seed()
        if not picked:
            return
        seed_path, seed_hash, seed_qd, seed_id, child_cnt, seed_sig, seed_dedupe_hash = picked
        if seed_id is not None:
            proc_map = self._processed_by_queue.setdefault(seed_qd, {})
            proc_map[int(seed_id)] = int(proc_map.get(int(seed_id), 0)) + 1
        run_dir = self._make_run_dir(seed_path, seed_qd, seed_hash)
        self._log(
            "seed_selected path=%s seed_id=%s hash=%s child_cnt=%s run_dir=%s"
            % (seed_path, str(seed_id) if seed_id is not None else "", seed_hash[:8], str(int(child_cnt)), run_dir)
        )
        parent_seed_meta_path = _write_parent_seed_info(
            run_dir,
            seed_path=seed_path,
            seed_id=seed_id,
            seed_hash=seed_hash,
            queue_dir=seed_qd,
        )
        self._log(
            "parent_seed_info_written path=%s seed=%s seed_id=%s hash=%s"
            % (parent_seed_meta_path, seed_path, str(seed_id) if seed_id is not None else "", seed_hash[:8])
        )
        if not self._run_trace_into(seed_path, run_dir, seed_id=seed_id, seed_hash=seed_hash):
            self._log("seed_trace_failed path=%s hash=%s" % (seed_path, seed_hash[:8]))
            return
        if seed_sig is not None:
            try:
                self._recent_seed_sigs.append(int(seed_sig))
            except Exception:
                pass
        p = self._spawn_pipeline(seed_path, seed_hash, run_dir)
        if p is None:
            self._log("branch_selector_spawn_failed seed=%s" % seed_path)
            return
        self._running_pipeline.append(p)
        self._seen_hashes.add(seed_dedupe_hash)
        _save_seen_hashes(self.runtime_root, self._seen_hashes)

    def shutdown(self, timeout_s: float = 5.0) -> None:
        procs = list(self._running_pipeline) + list(self._running_analyze)
        for p in procs:
            try:
                record_process_kill(
                    self.runtime_root,
                    int(p.popen.pid),
                    source="hybrid_io.daemon_scheduler.shutdown",
                    signal_name="SIGTERM",
                    reason="scheduler_shutdown",
                    run_dir=p.run_dir,
                    extra={"kind": str(getattr(p, "kind", "") or "")},
                )
                p.popen.terminate()
            except Exception:
                continue
        deadline = time.time() + float(timeout_s)
        for p in procs:
            while time.time() < deadline:
                if p.popen.poll() is not None:
                    break
                time.sleep(0.1)
        for p in procs:
            if p.popen.poll() is None:
                try:
                    record_process_kill(
                        self.runtime_root,
                        int(p.popen.pid),
                        source="hybrid_io.daemon_scheduler.shutdown",
                        signal_name="SIGKILL",
                        reason="scheduler_shutdown_timeout",
                        run_dir=p.run_dir,
                        extra={"kind": str(getattr(p, "kind", "") or "")},
                    )
                    p.popen.kill()
                except Exception:
                    pass
        _save_seen_hashes(self.runtime_root, self._seen_hashes)
