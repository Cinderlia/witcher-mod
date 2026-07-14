import stat
import os
import sys
import base64

from phuzzer.reporter import Reporter
if os.path.isdir("/xss_reflection") and "/" not in sys.path:
    sys.path.insert(0, "/")
from xss_reflection.wrapper import run_xss_flow
from .symex_launcher import start_symex_hybrid, stop_symex
from .db_manager import DBBackupManager
from urllib.parse import urlparse, urlunparse, unquote, parse_qsl, urlencode, urljoin
import urllib.request
import http.cookiejar
from datetime import datetime
from phuzzer import Phuzzer
import subprocess
import ctypes
import pathlib
import random
import shutil
import signal
import time
import json
import glob
import pwd
import sys
import os
import re
from typing import Optional
from collections import Counter

WITCH_FAIL = "[\033[31mWitcher\033[0m]"
WITCH_GO = "[\033[32mWitcher\033[0m]"

class Witcher():
    AFLR, AFLHR, WICH, WICR, WICHR, EXWIC, EXWICH, EXWICHR, DEV = "AFLR", "AFLHR", "WICH", "WICR", "WICHR", "EXWIC", "EXWICH", "EXWICHR", "DEV"
    CONFIGURATIONS = ["AFLR", "AFLHR", "WICH", "WICR", "WICHR", "EXWIC", "EXWICH", "EXWICHR", "DEV"]
    WORKING_DIR = os.path.join("/tmp", "output")



    def __init__(self, args):
        random.seed(90210)
        self.testloc = os.path.realpath(args.testloc) # replaced BASETESTDIR
        self.testver = args.testver
        self.dictionary_fn = os.path.join(self.testloc, self.testver,"dict.txt")
        self.seed_path = os.path.join(self.testloc, self.testver, "input")
        self.work_dir = os.path.join(self.testloc, self.testver, "work")
        self.appdir = args.appdir

        path = pathlib.Path(self.seed_path)
        path.mkdir(parents=True, exist_ok=True)
        self.config_loc = os.path.join(self.testloc,args.config)
        if not os.path.isfile(self.config_loc):
            raise ValueError(f"The configuration does not exist at {self.config_loc}, a configuration file is required")

        self.jconfig = json.load(open(self.config_loc,"r"))
        if not self.appdir:
            self.appdir = self.jconfig.get("appdir") or self.jconfig.get("app_dir") or self.jconfig.get("app_root") or "/app"
        self.fuzzer_target_binary = ""
        self.single_target = args.target
        self.use_reqr = False
        self.affinity = args.affinity

        self.no_fault_escalation = args.no_fault_escalation

        self.env = self.initialize_env()
        self._setup_reaper()

        self.report_dir = "/results" if os.path.exists("/results") else os.path.join(self.testloc, self.testver)
        self.report_dir = os.path.join(self.report_dir,f"{self.jconfig['testname']}-{self.testver}")
        path = pathlib.Path(self.report_dir)
        path.mkdir(parents=True, exist_ok=True)

        self.fuzz_campaign_status_fn = os.path.join(self.report_dir, "fuzz_campaign_status.json")
        self.fuzz_campaign_status = None
        if os.path.exists(self.fuzz_campaign_status_fn):
            self.fuzz_campaign_status = json.load(open(self.fuzz_campaign_status_fn,"r"))

        self.request_data_fn = os.path.join(self.testloc,"request_data.json")
        self.request_data = json.load(open(self.request_data_fn,"r", encoding='latin-1'))
        self.merge_seed_requests = self._seed_request_merge_enabled()
        self._merge_seed_requests_into_main()
        self._seed_login_cookie_blacklist = set()

        self.cores = int(self.jconfig.get("cores", args.cores))
        self.timeout = self.jconfig.get("timeout", args.timeout)
        self.memory = self.jconfig.get("memory", args.memory)
        self.first_crash = self.jconfig.get("first_crash", args.first_crash)
        self.max_initial_seeds = self._read_max_initial_seeds()
        # AFL -t (child timeout) uses milliseconds.
        # Prefer explicit run_timeout_ms; keep backward-compatible run_timeout as ms.
        rt_ms = self.jconfig.get("run_timeout_ms", None)
        if rt_ms is None:
            rt_ms = self.jconfig.get("run_timeout", 200)
        self.run_timeout = int(rt_ms)
        self.use_qemu = self.jconfig.get("use_qemu")
        self.server_cmd = self.jconfig.get("server_cmd", None)
        self.init_info_shm = self.jconfig.get("init_info_shm", None)
        self.war_path = self.jconfig.get("war_path",None)
        self.server_base_port = self.jconfig.get("server_base_port", 14000)

        self.server_env_vars = self.jconfig.get("server_env_vars", {})
        print(self.server_env_vars)
        self.binary_options = self.jconfig.get("binary_options").split(" ")
        self.server_up_msg = self.jconfig.get("server_up_msg")
        self.server_procs = []
        self.kill = False

        self.saved_seeds = set()
        self._pending_seed_processing_logs = []
        self.symex_handle = None
        self.db_backup_manager = None
        self.coverage_daemon_proc = None
        self.coverage_daemon_log_fp = None
        # Global wall-clock timer for global_timeout accounting across retries/reallocations.
        self._campaign_start_monotonic = time.monotonic()

        if args.container_name:
            self.container_info = {'name': args.container_name}
        else:
            self.container_info = None

        self.create_war_filter()
        self.url_filter = args.url_filter


    def _seed_request_merge_enabled(self):
        if not isinstance(self.jconfig, dict):
            return False
        return bool(self.jconfig.get("merge_seed_requests", False))

    def _merge_seed_requests_into_main(self):
        if not isinstance(self.request_data, dict):
            self.request_data = {"requestsFound": {}}
            return
        main_reqs = self.request_data.get("requestsFound")
        if not isinstance(main_reqs, dict):
            main_reqs = {}
            self.request_data["requestsFound"] = main_reqs
        if not self.merge_seed_requests:
            return
        seed_reqs = self.request_data.get("seedRequestsFound")
        if not isinstance(seed_reqs, dict) or len(seed_reqs) == 0:
            return
        for reqkey, req in seed_reqs.items():
            if reqkey not in main_reqs:
                main_reqs[reqkey] = req

    def _read_max_initial_seeds(self):
        if "max_initial_seeds" not in self.jconfig:
            return None
        try:
            value = int(self.jconfig.get("max_initial_seeds"))
        except Exception:
            return None
        if value <= 0:
            return None
        return value

    def _full_param_seed_enabled(self):
        if not isinstance(self.jconfig, dict):
            return False
        return bool(self.jconfig.get("enable_full_param_seed", False))

    def _initial_params_path(self):
        candidates = []
        configured = ""
        if isinstance(self.jconfig, dict):
            configured = str(self.jconfig.get("initial_params_json", "") or "").strip()
        if configured:
            if os.path.isabs(configured):
                candidates.append(configured)
            else:
                candidates.append(os.path.join(self.testloc, configured))
                candidates.append(os.path.join(self.testloc, self.testver, configured))
        candidates.append(os.path.join(self.testloc, "initial_params.json"))
        candidates.append(os.path.join(self.testloc, self.testver, "initial_params.json"))
        seen = set()
        for cand in candidates:
            norm = os.path.realpath(cand)
            if norm in seen:
                continue
            seen.add(norm)
            if os.path.isfile(norm):
                return norm
        return candidates[0] if candidates else os.path.join(self.testloc, "initial_params.json")

    def _load_initial_params_for_full_seed(self):
        cached = getattr(self, "_cached_initial_params_for_full_seed", None)
        if isinstance(cached, dict):
            return cached
        out = {"GET": {}, "POST": {}, "COOKIE": {}}
        fn = self._initial_params_path()
        try:
            with open(fn, "r", encoding="utf-8", errors="replace") as rf:
                obj = json.load(rf)
            if isinstance(obj, dict):
                for sec in ("GET", "POST", "COOKIE"):
                    val = obj.get(sec)
                    out[sec] = val if isinstance(val, dict) else {}
        except Exception:
            out = {"GET": {}, "POST": {}, "COOKIE": {}}
        self._cached_initial_params_for_full_seed = out
        return out

    def _seed_processing_log_path(self):
        return os.path.join(self.work_dir, "initial_seed_processing.log")

    def _append_seed_processing_log(self, message: str):
        try:
            if not isinstance(self._pending_seed_processing_logs, list):
                self._pending_seed_processing_logs = []
            self._pending_seed_processing_logs.append(str(message))
        except Exception:
            pass
        try:
            os.makedirs(self.work_dir, exist_ok=True)
            with open(self._seed_processing_log_path(), "a", encoding="utf-8", errors="replace") as wf:
                wf.write(str(message))
                if not str(message).endswith("\n"):
                    wf.write("\n")
        except Exception:
            pass

    def _flush_seed_processing_logs(self):
        try:
            pending = list(self._pending_seed_processing_logs or [])
        except Exception:
            pending = []
        if not pending:
            return
        try:
            os.makedirs(self.work_dir, exist_ok=True)
            with open(self._seed_processing_log_path(), "a", encoding="utf-8", errors="replace") as wf:
                for message in pending:
                    wf.write(str(message))
                    if not str(message).endswith("\n"):
                        wf.write("\n")
            self._pending_seed_processing_logs = []
        except Exception:
            pass

    def _initial_seed_limit(self):
        if self.max_initial_seeds is not None:
            return int(self.max_initial_seeds)
        return 50

    @staticmethod
    def _encode_initial_seed_override(seeds):
        encoded = []
        for seed in seeds or []:
            if isinstance(seed, bytes):
                encoded.append(base64.b64encode(seed).decode("ascii"))
        return encoded

    @staticmethod
    def _decode_initial_seed_override(encoded_seeds):
        decoded = []
        for seed in encoded_seeds or []:
            try:
                decoded.append(base64.b64decode(str(seed).encode("ascii")))
            except Exception:
                continue
        return decoded

    def _get_target_initial_seeds(self, target):
        if isinstance(target, dict):
            encoded = target.get("_initial_seed_override_b64")
            if isinstance(encoded, list):
                decoded = self._decode_initial_seed_override(encoded)
                if decoded:
                    return decoded
        requests = []
        if isinstance(target, dict):
            requests = target.get("requests", [])
        return self.create_seeds(requests)

    def _split_targets_by_initial_seeds(self, targets):
        if self.max_initial_seeds is None:
            return targets

        limit = int(self.max_initial_seeds)
        expanded_targets = []
        changed = False

        for target in targets or []:
            if not isinstance(target, dict):
                continue

            if int(target.get("_max_initial_seeds_applied") or 0) == limit:
                expanded_targets.append(target)
                continue

            seed_entries = self.create_seeds(target.get("requests", []), max_seeds=0, return_entries=True)
            total_seeds = len(seed_entries)
            target["_max_initial_seeds_applied"] = limit

            if total_seeds <= limit:
                target["_seed_count"] = total_seeds
                target["_effective_seed_count"] = int(target.get("_effective_seed_count") or total_seeds)
                expanded_targets.append(target)
                continue

            changed = True
            split_count = (total_seeds + limit - 1) // limit
            base_chunk_size = total_seeds // split_count
            remainder = total_seeds % split_count
            source_target_path = target.get("target_path")
            real_target_path = target.get("_real_target_path") or source_target_path
            offset = 0

            print(
                f"[*] Splitting {source_target_path} into {split_count} targets "
                f"because initial seeds={total_seeds} exceeds max_initial_seeds={limit}"
            )

            for split_index in range(split_count):
                chunk_size = base_chunk_size + (1 if split_index < remainder else 0)
                chunk_entries = seed_entries[offset: offset + chunk_size]
                offset += chunk_size

                chunk = [entry.get("strout") for entry in chunk_entries if isinstance(entry, dict) and entry.get("strout")]
                chunk_requests = []
                seen_reqkeys = set()
                chunk_methods = {}
                for entry in chunk_entries:
                    if not isinstance(entry, dict):
                        continue
                    reqkey = entry.get("reqkey")
                    if reqkey is None or reqkey in seen_reqkeys:
                        continue
                    seen_reqkeys.add(reqkey)
                    chunk_requests.append(reqkey)
                    req = self.request_data["requestsFound"].get(reqkey) if isinstance(self.request_data, dict) else None
                    method = str((req or {}).get("_method", "GET") or "GET").upper()
                    chunk_methods[method] = int(chunk_methods.get(method, 0)) + 1

                split_target = dict(target)
                split_target["target_path"] = f"{source_target_path}-{split_index + 1}"
                split_target["_real_target_path"] = real_target_path
                split_target["_split_source_target_path"] = source_target_path
                split_target["_split_part_index"] = split_index + 1
                split_target["_split_part_total"] = split_count
                split_target["requests"] = chunk_requests
                split_target["methods"] = chunk_methods
                split_target["_initial_seed_override_b64"] = self._encode_initial_seed_override(chunk)
                split_target["_seed_count"] = len(chunk)
                split_target["_effective_seed_count"] = len(chunk)
                split_target["_weak_seed_count"] = 0
                split_target["last_completed_trial"] = -1
                split_target["last_completed_refuzz"] = -1
                for transient_key in ("_allocated_time", "_budget_total", "_used_time", "_completed"):
                    if transient_key in split_target:
                        del split_target[transient_key]
                expanded_targets.append(split_target)

        return expanded_targets if changed else targets

    def save_filesdata(self):
        json.dump(self.fuzz_campaign_status,open(self.fuzz_campaign_status_fn,"w"))

    def _setup_reaper(self):
        if os.name == "nt":
            return
        try:
            libc = ctypes.CDLL("libc.so.6")
            libc.prctl(36, 1, 0, 0, 0)
        except Exception:
            pass
        try:
            signal.signal(signal.SIGCHLD, self._reap_children)
        except Exception:
            pass

    def _reap_children(self, signum=None, frame=None):
        if os.name == "nt":
            return
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
            except ChildProcessError:
                break
            except Exception:
                break

    def initialize_env(self):
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = self.jconfig["ld_library_path"] if "ld_library_path" in self.jconfig else ""
        env["AFL_PRELOAD"] = self.jconfig["afl_preload"] if "afl_preload" in self.jconfig else ""
        env["DOCUMENT_ROOT"] = self.appdir
        if self.affinity is not None:
            env["AFL_SET_AFFINITY"] = self.affinity

        direct = self.jconfig.get("direct",{})
        if "mandatory_cookie" in direct:
            env["MANDATORY_COOKIE"] = direct["mandatory_cookie"]
        if "mandatory_get" in direct:
            env["MANDATORY_GET"] = direct["mandatory_get"]
        if "mandatory_post" in direct:
            env["MANDATORY_POST"] = direct["mandatory_post"]

        env["SERVER_NAME"] = env.get("SERVER_NAME","witcher")
        if not self.no_fault_escalation:
            env["STRICT"] = "1"
        self.use_reqr = True if "R" in self.testver else False
        env["AFL_PATH"] = self.jconfig.get("afl_path", "/afl")
        if "H" in self.testver:
            env["AFL_HTTP_DICT"] = "1"
        if self.testver == Witcher.AFLR or self.testver == Witcher.AFLHR:
            if "afl_inst_interpreter_binary" not in self.jconfig:
                raise ValueError("Configuration file is missing 'afl_inst_interpreter_binary'")
            self.fuzzer_target_binary = self.jconfig["afl_inst_interpreter_binary"]
            env["NO_WC_EXTRA"] = "1"
        else:
            if "wc_inst_interpreter_binary" not in self.jconfig:
                raise ValueError("Configuration file is missing 'wc_inst_interpreter_binary'")
            self.fuzzer_target_binary = self.jconfig["wc_inst_interpreter_binary"]
            if self.testver.startswith("WIC"):
                env["WC_INSTRUMENTATION"] = "1"
                env["NO_WC_EXTRA"] = "1"
            elif self.testver.startswith("EX"):
                env["WC_INSTRUMENTATION"] = "1"
        return env

    @staticmethod
    def _seed_cookie_blacklist_from_header(cookie_header: str):
        ignore = {"path", "expires", "max-age", "domain", "secure", "httponly", "samesite", "priority"}
        names = set()
        s = str(cookie_header or "").strip()
        if not s:
            return names
        for part in s.split(";"):
            p = str(part or "").strip()
            if not p or "=" not in p:
                continue
            k, _v = p.split("=", 1)
            k = str(k or "").strip().lower()
            if not k or k in ignore:
                continue
            names.add(k)
        return names

    @staticmethod
    def _preset_login_cookie_from_direct(direct: dict) -> str:
        raw = str((direct or {}).get("loginSessionCookie", "") or "").strip()
        if not raw or "=" not in raw:
            return ""
        parts = []
        ignore = {"path", "expires", "max-age", "domain", "secure", "httponly", "samesite", "priority"}
        for part in raw.split(";"):
            item = str(part or "").strip()
            if not item or "=" not in item:
                continue
            key, value = item.split("=", 1)
            key = str(key or "").strip()
            value = str(value or "").strip()
            if not key or key.lower() in ignore:
                continue
            parts.append(f"{key}={value}")
        return "; ".join(parts)

    def _capture_login_cookie_blacklist(self):
        names = set()
        try:
            direct = self.jconfig.get("direct", {}) if isinstance(self.jconfig, dict) else {}
            if not isinstance(direct, dict):
                direct = {}
            names.update(self._seed_cookie_blacklist_from_header(direct.get("mandatory_cookie", "")))
            names.update(self._seed_cookie_blacklist_from_header(direct.get("login_cookie", "")))
            preset_login_cookie = self._preset_login_cookie_from_direct(direct)
            if preset_login_cookie:
                names.update(self._seed_cookie_blacklist_from_header(preset_login_cookie))
                return names
            login_url = str(direct.get("url", "") or "").strip()
            pre_login_url = str(direct.get("pre_login", "") or direct.get("preLoginPage", "") or "").strip()
            if not login_url and not pre_login_url:
                return names
            if login_url == "NO_LOGIN":
                return names
            is_http = str(login_url).lower().startswith(("http://", "https://")) or str(pre_login_url).lower().startswith(("http://", "https://"))
            if not is_http:
                return names
            if (not str(login_url).lower().startswith(("http://", "https://"))) and str(pre_login_url).lower().startswith(("http://", "https://")):
                try:
                    pu = urlparse(pre_login_url)
                    origin = f"{pu.scheme}://{pu.netloc}"
                    login_url = urljoin(origin + "/", login_url.lstrip("/"))
                except Exception:
                    pass
            login_url = login_url.replace("@@PORT_INCREMENT@@", str(18080))
            pre_login_url = pre_login_url.replace("@@PORT_INCREMENT@@", str(18080))
            if direct.get("getData"):
                joiner = "&" if ("?" in login_url) else "?"
                login_url = f"{login_url}{joiner}{direct.get('getData')}"
            post_data = str(direct.get("postData", "") or "").encode("ascii", errors="ignore")
            req_headers = direct.get("headers", {}) if isinstance(direct.get("headers", {}), dict) else {}
            method = str(direct.get("method", "GET") or "GET").upper()
            cookie_jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
            if pre_login_url:
                try:
                    pre_req = urllib.request.Request(pre_login_url, method="GET")
                    pre_resp = opener.open(pre_req, timeout=10)
                    try:
                        pre_headers = pre_resp.getheaders()
                    finally:
                        pre_resp.read()
                    for hn, hv in pre_headers:
                        if str(hn or "").lower() == "set-cookie":
                            names.update(self._seed_cookie_blacklist_from_header(hv))
                except Exception as ex:
                    print(f"[*] Pre-login cookie capture failed: {ex}")
            login_req = urllib.request.Request(login_url, post_data, req_headers, method=method)
            login_resp = opener.open(login_req, timeout=15)
            try:
                login_headers = login_resp.getheaders()
            finally:
                login_resp.read()
            for ck in cookie_jar:
                try:
                    names.add(str(ck.name or "").strip().lower())
                except Exception:
                    pass
            for hn, hv in login_headers:
                if str(hn or "").lower() == "set-cookie":
                    names.update(self._seed_cookie_blacklist_from_header(hv))
        except Exception as ex:
            print(f"[*] Failed to capture login cookie blacklist: {ex}")
        return names

    @staticmethod
    def find_path(urlpath, prior_rootpaths, search_root=None):
        fname = os.path.basename(urlpath)

        for rootpath in prior_rootpaths:
            tmppath = os.path.join(rootpath, urlpath)
            if os.path.exists(tmppath):
                return tmppath

        if search_root:
            cmd = ["find", search_root, "-name", fname]
        else:
            cmd = ["find", "/", "-path", "/p", "-prune", "-o", "-path", "/proc", "-prune",
                   "-o", "-path", "/test", "-prune", "-o", "-path", "/etc", "-prune",
                   "-o", "-path", "/var/log", "-prune", "-o", "-path", "/var/spool", "-prune",
                   "-o", "-path", "/var/cache", "-prune",
                   "-o", "-path", "/var/lib", "-prune", "-o", "-path", "/root", "-prune",
                   "-o", "-name", fname]

        #print(f"Command = {' '.join(cmd)}")

        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        results, _ = p.communicate()
        #print(f"RESULTS from find = {results}")
        for fpath in sorted(results.split(b'\n'), key=len):
            fpath = fpath.decode("latin-1")
            if fpath.find(urlpath) > -1:
                return fpath
        return ""


    def init_fuzz_campaign_status(self, trial_index):
        if self.fuzz_campaign_status is None:
            self.fuzz_campaign_status = []

        assert (trial_index <= len(self.fuzz_campaign_status))

        if len(self.fuzz_campaign_status) == trial_index:
            last_rootpath = set()
            fcnt = 0
            targets_added = {}
            start_time = datetime.now().strftime("%Y_%m_%d_%H_%M")
            self.fuzz_campaign_status.append({"trial_start": start_time, "trial_complete": False, "targets": []})
            trial = self.fuzz_campaign_status[trial_index]

            probe_flag_file = "/tmp/witcher_route_probe.flag"
            # We must use /tmp for the log file because the PHP process (e.g. www-data) might not have write access to the specific workspace directory
            probe_log_file = "/tmp/witcher_url_mapping.log"
            route_map = {}

            def _merge_param_strings(existing, extra):
                existing_s = str(existing or "").strip()
                extra_s = str(extra or "").strip()
                if not extra_s:
                    return existing_s
                if not existing_s:
                    return extra_s
                try:
                    merged = []
                    seen = set()
                    for source in (existing_s, extra_s):
                        for k, v in parse_qsl(source, keep_blank_values=True):
                            pair = (str(k), str(v))
                            if pair in seen:
                                continue
                            seen.add(pair)
                            merged.append(pair)
                    if merged:
                        return urlencode(merged, doseq=True)
                except Exception:
                    pass
                return existing_s

            def _merge_probe_headers(existing, extra):
                merged = {}
                for source in (existing, extra):
                    if not isinstance(source, dict):
                        continue
                    for hk, hv in source.items():
                        hks = str(hk or "")
                        lhk = hks.lower()
                        if not hks or lhk in {"host", "content-length", "connection"}:
                            continue
                        if hks not in merged or not str(merged.get(hks, "")).strip():
                            merged[hks] = str(hv if hv is not None else "")
                return merged

            def _merge_probe_body(existing, extra):
                existing_s = str(existing or "")
                extra_s = str(extra or "")
                if not extra_s:
                    return existing_s
                if not existing_s:
                    return extra_s
                complex_markers = ("Content-Disposition:", "------WebKitFormBoundary", "{", "[")
                if any(marker in existing_s for marker in complex_markers):
                    return existing_s
                if any(marker in extra_s for marker in complex_markers):
                    return existing_s
                return _merge_param_strings(existing_s, extra_s)

            # Fallback to wc_inst_interpreter_binary if afl_inst_interpreter_binary is not set or empty
            interpreter_bin = self.jconfig.get("afl_inst_interpreter_binary", "")
            if not interpreter_bin:
                interpreter_bin = self.jconfig.get("wc_inst_interpreter_binary", "")

            if interpreter_bin.find("php-cgi") > -1:
                print(f"[WC] Enabling PHP route probe for {self.appdir}, saving to {probe_log_file}")
                with open(probe_flag_file, "w") as f:
                    # Write just the app directory for filtering
                    f.write(self.appdir)
                
                if os.path.exists(probe_log_file):
                    os.remove(probe_log_file)
                
                import requests
                session = requests.Session()
                probe_groups = {}
                probe_group_order = []
                for reqkey, req in self.request_data["requestsFound"].items():
                    probe_method = str(req.get("_method", "GET") or "GET").upper()
                    probe_url = str(req.get("_url", "") or "").strip()
                    if not probe_url:
                        continue
                    parsed_probe_url = urlparse(probe_url)
                    probe_base_url = urlunparse(parsed_probe_url._replace(query="", fragment=""))
                    probe_headers = {}
                    raw_headers = req.get("_headers", {})
                    if isinstance(raw_headers, dict):
                        for hk, hv in raw_headers.items():
                            hks = str(hk or "")
                            lhk = hks.lower()
                            if not hks or lhk in {"host", "content-length", "connection"}:
                                continue
                            probe_headers[hks] = str(hv if hv is not None else "")
                    group = probe_groups.get(probe_base_url)
                    if group is None:
                        group = {
                            "base_url": probe_base_url,
                            "route_key": parsed_probe_url.path or "/",
                            "query": "",
                            "post_data": "",
                            "headers": {},
                            "request_count": 0,
                            "sample_reqkey": reqkey,
                        }
                        probe_groups[probe_base_url] = group
                        probe_group_order.append(probe_base_url)
                    group["request_count"] += 1
                    group["headers"] = _merge_probe_headers(group.get("headers", {}), probe_headers)

                total_probe_requests = len(self.request_data["requestsFound"])
                total_probe_groups = len(probe_group_order)
                print(
                    f"[WC] Sending merged base URLs to trigger probe (no query/POST): "
                    f"{total_probe_requests} original -> {total_probe_groups} unique base URLs"
                )
                if total_probe_groups == 0:
                    print("[WC] Probe skipped: no valid requests found.")

                for probe_idx, probe_base_url in enumerate(probe_group_order, 1):
                    group = probe_groups[probe_base_url]
                    try:
                        probe_method = "GET"
                        probe_url = probe_base_url
                        print(
                            f"[WC] Probe {probe_idx}/{total_probe_groups}: {probe_method} {probe_base_url} "
                            f"(merged {group.get('request_count', 0)} requests)"
                        )
                        request_kwargs = {
                            "timeout": 2,
                            "verify": False,
                            "allow_redirects": False,
                        }
                        if group.get("headers"):
                            request_kwargs["headers"] = group["headers"]
                        session.request(probe_method, probe_url, **request_kwargs)
                    except requests.exceptions.Timeout:
                        print(f"[WC] Probe timeout {probe_idx}/{total_probe_groups}: {probe_method} {probe_base_url}")
                    except requests.exceptions.RequestException:
                        print(f"[WC] Probe request failed {probe_idx}/{total_probe_groups}: {probe_method} {probe_base_url}")
                
                if os.path.exists(probe_log_file):
                    with open(probe_log_file, "r") as f:
                        for line in f:
                            try:
                                data = json.loads(line.strip())
                                uri = str(data.get('uri') or '').strip()
                                script = str(data.get('script') or '').strip()
                                if not uri or not script:
                                    continue
                                if uri not in route_map or not isinstance(route_map.get(uri), dict):
                                    route_map[uri] = {"script": script, "get": "", "post": ""}
                                route_map[uri]["script"] = route_map[uri].get("script") or script
                                route_map[uri]["get"] = _merge_param_strings(route_map[uri].get("get", ""), data.get("get", ""))
                                route_map[uri]["post"] = _merge_param_strings(route_map[uri].get("post", ""), data.get("post", ""))
                            except Exception:
                                pass
                    for probe_base_url in probe_group_order:
                        group = probe_groups.get(probe_base_url, {})
                        route_key = str(group.get("route_key") or "").strip()
                        if not route_key:
                            continue
                        if route_key not in route_map or not isinstance(route_map.get(route_key), dict):
                            continue
                    print(f"[WC] Probe collected {len(route_map)} mappings.")
                else:
                    print(f"[WC] Warning: Probe log {probe_log_file} was not created.")
                
                if os.path.exists(probe_flag_file):
                    os.remove(probe_flag_file)
                
                # Delete the mapping log after reading it to keep the environment clean
                if os.path.exists(probe_log_file):
                    os.remove(probe_log_file)

            self._seed_login_cookie_blacklist = self._capture_login_cookie_blacklist()
            if self._seed_login_cookie_blacklist:
                print(f"[WC] Pre-login cookie blacklist keys: {sorted(self._seed_login_cookie_blacklist)}")
            else:
                print("[WC] Pre-login cookie blacklist keys: []")

            for reqkey, req in self.request_data["requestsFound"].items():

                if self.url_filter and re.search(self.url_filter, req["_url"]):
                    pass
                elif not self.url_filter:
                    pass
                else:
                    # did not match filter, will not add url
                    continue

                match_found = False

                is_soapaction = False
                if match_found:
                    url = urlparse(req["_url"])
                else:
                    if re.match(r"http://.*/[a-zA-Z0-9_\-\.]+\.(css|js|toff|woff|jpg|gif|png)\?[0-9a-zA-Z ]*", req["_url"]):
                        print(f"[*] Skipping {req['_url']} b/c static extension")
                        continue

                    if "_headers" in req and ("soapaction" in req["_headers"] or "SOAPACTION" in req["_headers"]):
                        retr_url = req["_headers"].get("soapaction", None)
                        if retr_url is None:
                            retr_url = req["_headers"].get("SOAPACTION", None)
                        url = urlparse(retr_url)
                        is_soapaction = True
                    else:
                        url = urlparse(req["_url"])

                    # if req["_method"].upper() == "GET":
                    #     if len(url.query) + len(req.get("_postData",[])) < 1 :
                    #         print(f"[*] Skipping {reqkey} b/c {url.query} is {len(url.query)} and less than 1")
                    #         continue

                    if url.path.endswith("/") and req["_url"].find("/?") > -1:
                        print(f"[*] Skipping {reqkey} b/c looks like dir listing")
                        continue

                    if req.get("response_status", 200) == 999:
                        print(f"[*] Skipping {reqkey} response status was set to 999")
                        continue


                    if req["_method"].upper() == "POST":
                        if len(url.query) + len(req.get("_postData",[])) < 1:
                            print(f"[*] Skipping {reqkey} b/c no post Data")
                            continue

                if self.container_info:
                    target_path = urlunparse(url)
                else:
                    if self.server_cmd:
                        url = url._replace(query="")
                        target_path = urlunparse(url)

                    else:
                        # if self.jconfig.get("afl_inst_interpreter_binary", "").find("php-cgi") > -1:
                        #     url = urlparse(req["_url"])
                        #     urlpath = url.path
                        #     if urlpath.startswith("/"):
                        #         urlpath = urlpath[1:]

                        #     target_path = os.path.join(self.appdir, urlpath)
                        #     print(f"target_path={target_path}")
                        #     if not os.path.exists(target_path):
                        #         target_path = Witcher.find_path(urlpath, last_rootpath)
                        #         last_rootpath.add(target_path.replace(urlpath,""))

                        #     if url.path.find(".php") == -1 and not url.path.endswith("/"):
                        #         print(
                        #             f"Skipping {url} because php-cgi being used to evaluate but request url is for non php item target_path={target_path}")
                        #         continue
                        if interpreter_bin.find("php-cgi") > -1:
                            url = urlparse(req["_url"])
                            urlpath = url.path
                            urlpath_u = unquote(urlpath or "")
                            try:
                                urlpath_u = urlpath_u.replace("\\", "/")
                            except Exception:
                                pass
                            php_idx = urlpath_u.lower().find(".php")
                            urlpath_script = urlpath
                            urlpath_script_u = urlpath_u
                            path_info = ""
                            if php_idx != -1:
                                urlpath_script = urlpath[:php_idx + 4]
                                urlpath_script_u = urlpath_u[:php_idx + 4]
                                path_info = urlpath_u[php_idx + 4:]
                                if not path_info:
                                    path_info = "/"
                            
                            # mod: Check if the probe found the correct script path
                            route_key = None
                            if urlpath_script in route_map:
                                route_key = urlpath_script
                            elif urlpath in route_map:
                                route_key = urlpath
                            if route_key is not None:
                                route_entry = route_map[route_key]
                                if isinstance(route_entry, dict):
                                    raw_target = route_entry.get("script", "")
                                    extra_probe_get = route_entry.get("get", "")
                                    extra_probe_post = route_entry.get("post", "")
                                else:
                                    raw_target = route_entry
                                    extra_probe_get = ""
                                    extra_probe_post = ""
                                app_base_name = os.path.basename(self.appdir.rstrip('/'))
                                
                                # Map the absolute server path (e.g. /var/www/html/joomla/index.php) 
                                # back to the Witcher container path (e.g. /app/joomla/index.php)
                                idx = raw_target.find(f"/{app_base_name}/")
                                if idx != -1:
                                    target_path = os.path.join(self.appdir, raw_target[idx + len(f"/{app_base_name}/"):])
                                else:
                                    target_path = raw_target
                                    
                                # print(f"[WC] Probed target_path={target_path}")
                                last_rootpath.add(os.path.dirname(target_path))
                                is_front_controller = (target_path.endswith("index.php") or target_path.endswith("app.php") or target_path.endswith("router.php"))
                                if extra_probe_get:
                                    try:
                                        req["_wc_route_probe_get"] = _merge_param_strings(
                                            req.get("_wc_route_probe_get", ""),
                                            extra_probe_get
                                        )
                                    except Exception:
                                        pass
                                if extra_probe_post:
                                    req["_wc_route_probe_post"] = _merge_param_strings(
                                        req.get("_wc_route_probe_post", ""),
                                        extra_probe_post
                                    )
                            else:
                                # Compatibility fallback: if route mapping is missing, try resolving under /app prefix.
                                fallback_target = os.path.join("/app", str(urlpath_script).lstrip("/\\"))
                                if os.path.isfile(fallback_target):
                                    target_path = fallback_target
                                    last_rootpath.add(os.path.dirname(target_path))
                                    is_front_controller = (target_path.endswith("index.php") or target_path.endswith("app.php") or target_path.endswith("router.php"))
                                    print(f"[WC] route_map miss fallback hit: urlpath_script={urlpath_script} -> target_path={target_path}")
                                else:
                                    print(f"Skipping {url} because no server route mapping found. Debug Info: urlpath={urlpath}, urlpath_script={urlpath_script}, fallback_target={fallback_target}, route_map_keys_sample={list(route_map.keys())[:5] if route_map else []}")
                                    continue
                            try:
                                if isinstance(target_path, str):
                                    target_path = target_path.replace("\\", "/").rstrip("/\\")
                            except Exception:
                                pass
                            if not (target_path and str(target_path).lower().endswith(".php")):
                                if urlpath_script in route_map and route_key != urlpath_script:
                                    raw_target = route_map[urlpath_script]
                                    app_base_name = os.path.basename(self.appdir.rstrip('/'))
                                    idx = raw_target.find(f"/{app_base_name}/")
                                    if idx != -1:
                                        target_path = os.path.join(self.appdir, raw_target[idx + len(f"/{app_base_name}/"):])
                                    else:
                                        target_path = raw_target
                                    try:
                                        if isinstance(target_path, str):
                                            target_path = target_path.replace("\\", "/").rstrip("/\\")
                                    except Exception:
                                        pass
                                
                                if not (target_path and str(target_path).lower().endswith(".php")):
                                    # Try to extract .php path from target_path if it doesn't end with .php
                                    php_idx = str(target_path).lower().find(".php")
                                    if php_idx != -1:
                                        target_path = target_path[:php_idx + 4]
                                    else:
                                        print(f"Skipping {url} because php entry is not .php after compat: target_path={target_path}")
                                        continue
                        else:
                            target_path = req['_url']


                method = req.get("_method", "GET").upper()
                if 400 <= req.get("response_status", 200) < 500:
                    print(f"[WC] Skipping {req['_url']} b/c of response status during crawling")
                    continue

                if target_path:
                    if target_path.find("HNAP1/Login") > -1:
                        continue
                else:
                    target_path = req["_url"]

                # if request has user input, this only checks if query params or post data is passed in
                if req["_url"].find("?") or req["_url"].find("&") or len(req["_postData"]) > 0:
                    print(f" Fuzzing #{fcnt} at '{target_path}'")
                    fcnt += 1
                    if not self.single_target or target_path.find(self.single_target) > -1:
                        if target_path in targets_added:
                            index = targets_added[target_path]
                            trial["targets"][index]["requests"].append(reqkey)
                            trial["targets"][index]["is_soapaction"] = is_soapaction
                            if method in trial["targets"][index]["methods"]:
                                trial["targets"][index]["methods"][method] += 1
                        else:
                            targets_added[target_path] = len(trial["targets"])
                            trial["targets"].append({"target_path": target_path, "requests": [reqkey],
                                                     "methods": {method: 1}, "is_soapaction": is_soapaction,
                                                     "last_completed_trial": -1, "last_completed_refuzz": -1})
                else:
                    print(f"Skipping {req['_url']} b/c no query or post data.")

            self.save_campaign_status()

    def save_campaign_status(self):

        json.dump(self.fuzz_campaign_status, open(self.fuzz_campaign_status_fn, "w"))

    def _time_allocations_path(self, trial_index: int) -> str:
        return os.path.join(self.report_dir, f"time_allocations_trial_{int(trial_index)}.json")

    def _save_time_allocations(self, trial_index: int, targets: list, *, nbr_refuzzes: int) -> None:
        try:
            out = {
                "trial_index": int(trial_index),
                "allocation_mode": "per_trial_total",
                "global_timeout": int(getattr(self, "global_timeout", 0) or 0),
                "global_min_fuzz_time": int(self.jconfig.get("global_min_fuzz_time", 300)),
                "number_of_refuzzes": int(nbr_refuzzes),
                "targets": [
                    {
                        "target_path": t.get("target_path"),
                        "seed_count": int(t.get("_seed_count") or 0),
                        "effective_seed_count": int(t.get("_effective_seed_count") or int(t.get("_seed_count") or 0)),
                        "weak_seed_count": int(t.get("_weak_seed_count") or 0),
                        "allocated_time": float(t.get("_allocated_time") or 0.0),
                        "budget_total": float(t.get("_budget_total") or 0.0),
                        "used_time": float(t.get("_used_time") or 0.0),
                        "completed": bool(t.get("_completed") or False),
                    }
                    for t in (targets or [])
                    if isinstance(t, dict) and t.get("target_path")
                ],
            }
            with open(self._time_allocations_path(trial_index), "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[*] Failed to save time allocations: {e}")

    def _load_time_allocations(self, trial_index: int, *, nbr_refuzzes: int) -> Optional[list]:
        p = self._time_allocations_path(trial_index)
        if not os.path.isfile(p):
            return None
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                obj = json.load(f)
        except Exception:
            return None
        if not isinstance(obj, dict):
            return None
        if obj.get("allocation_mode") != "per_trial_total":
            return None
        if int(obj.get("trial_index", -1)) != int(trial_index):
            return None
        if int(obj.get("global_timeout", 0)) != int(getattr(self, "global_timeout", 0) or 0):
            return None
        if int(obj.get("global_min_fuzz_time", 300)) != int(self.jconfig.get("global_min_fuzz_time", 300)):
            return None
        if int(obj.get("number_of_refuzzes", 1)) != int(nbr_refuzzes):
            return None
        ts = obj.get("targets")
        if not isinstance(ts, list) or not ts:
            return None
        out = []
        for t in ts:
            if not isinstance(t, dict):
                continue
            tp = t.get("target_path")
            if not isinstance(tp, str) or not tp:
                continue
            out.append(
                {
                    "target_path": tp,
                    "_seed_count": int(t.get("seed_count") or 0),
                    "_effective_seed_count": int(t.get("effective_seed_count") or int(t.get("seed_count") or 0)),
                    "_weak_seed_count": int(t.get("weak_seed_count") or 0),
                    "_allocated_time": float(t.get("allocated_time") or 0.0),
                    "_budget_total": float(t.get("budget_total") or float(t.get("allocated_time") or 0.0)),
                    "_used_time": float(t.get("used_time") or 0.0),
                    "_completed": bool(t.get("completed") or False),
                }
            )
        return out if out else None

    def _remaining_global_timeout_seconds(self) -> float:
        try:
            total = float(self.global_timeout or 0.0)
        except Exception:
            total = 0.0
        if total <= 0.0:
            return 0.0
        try:
            elapsed = float(time.monotonic() - float(self._campaign_start_monotonic or time.monotonic()))
        except Exception:
            elapsed = 0.0
        return max(0.0, float(total) - max(0.0, elapsed))

    def _rebalance_remaining_allocations(
        self,
        *,
        targets: list,
        current_index: int,
        current_weak_seed_count: int,
        trial_index: int,
        nbr_refuzzes: int,
    ) -> float:
        """
        Rebalance timeout across current + remaining uncompleted targets using
        effective seed counts. Current target effective seeds = seed_count - weak.
        """
        if not isinstance(targets, list) or current_index < 0 or current_index >= len(targets):
            return 0.0
        remaining_budget = self._remaining_global_timeout_seconds()
        if remaining_budget <= 0.0:
            return 0.0

        candidates = []
        for idx in range(current_index, len(targets)):
            t = targets[idx]
            if not isinstance(t, dict):
                continue
            if bool(t.get("_completed")):
                continue
            seed_cnt = int(t.get("_seed_count") or 0)
            if idx == current_index:
                weak = max(0, int(current_weak_seed_count or 0))
                t["_weak_seed_count"] = weak
                eff = max(1, int(seed_cnt) - weak)
            else:
                eff = max(1, int(seed_cnt))
            t["_effective_seed_count"] = int(eff)
            candidates.append(t)
        if not candidates:
            return 0.0

        total_eff = 0
        for t in candidates:
            total_eff += int(t.get("_effective_seed_count") or 1)
        total_eff = max(1, int(total_eff))

        for t in candidates:
            share = float(int(t.get("_effective_seed_count") or 1)) / float(total_eff)
            alloc = float(remaining_budget) * share
            t["_allocated_time"] = float(alloc)
            t["_budget_total"] = float(alloc)
            # _used_time is historical for completed accounting; keep uncompleted at 0.
            if not bool(t.get("_completed")):
                t["_used_time"] = 0.0

        # Enforce per-target minimum allocation for rebalancing too.
        min_fuzz_time = int(self.jconfig.get("global_min_fuzz_time", 300))
        if min_fuzz_time > 0 and len(candidates) > 0:
            budget = float(remaining_budget)
            min_total = float(min_fuzz_time) * float(len(candidates))
            if budget < min_total:
                # Budget cannot satisfy min for all: evenly split remaining budget.
                effective_min = budget / float(len(candidates))
                for t in candidates:
                    t["_allocated_time"] = float(effective_min)
                    t["_budget_total"] = float(effective_min)
            else:
                deficit = 0.0
                for t in candidates:
                    cur = float(t.get("_allocated_time") or 0.0)
                    if cur < float(min_fuzz_time):
                        deficit += float(min_fuzz_time) - cur
                        t["_allocated_time"] = float(min_fuzz_time)
                        t["_budget_total"] = float(min_fuzz_time)
                    else:
                        t["_allocated_time"] = cur
                        t["_budget_total"] = cur
                if deficit > 0.0:
                    donors = [t for t in candidates if float(t.get("_allocated_time") or 0.0) > float(min_fuzz_time)]
                    total_slack = 0.0
                    for t in donors:
                        total_slack += float(t["_allocated_time"]) - float(min_fuzz_time)
                    remaining = deficit
                    if total_slack > 0.0:
                        for idx, t in enumerate(donors):
                            slack = float(t["_allocated_time"]) - float(min_fuzz_time)
                            if slack <= 0.0:
                                continue
                            if idx == len(donors) - 1:
                                cut = remaining
                            else:
                                cut = deficit * (slack / total_slack)
                            if cut > remaining:
                                cut = remaining
                            max_cut = float(t["_allocated_time"]) - float(min_fuzz_time)
                            if cut > max_cut:
                                cut = max_cut
                            if cut > 0.0:
                                t["_allocated_time"] = float(t["_allocated_time"]) - cut
                                t["_budget_total"] = float(t["_allocated_time"])
                                remaining -= cut
                            if remaining <= 0.0:
                                break

        # Current target keeps position; remaining targets follow large->small.
        cur = targets[current_index]
        tail = [x for x in targets[current_index + 1 :] if isinstance(x, dict)]
        tail.sort(key=lambda x: float(x.get("_allocated_time") or 0.0), reverse=True)
        targets[current_index] = cur
        targets[current_index + 1 :] = tail

        # Reset extra pool after explicit reallocation.
        self.time_pool = 0.0
        self._save_time_allocations(trial_index, targets, nbr_refuzzes=nbr_refuzzes)
        try:
            return float(cur.get("_allocated_time") or 0.0)
        except Exception:
            return 0.0

    def create_seeds(self, requests, max_seeds=None, return_entries=False):
        seed_name_stub = os.path.join(self.seed_path,"seed-")
        seeds = []
        
        # Parse all requests to filter out >10KB and compute parameter diversity
        from urllib.parse import parse_qsl, urlencode
        from difflib import SequenceMatcher
        from typing import Dict, List, Optional, Tuple

        log_lines = []

        def _log(msg: str):
            log_lines.append(str(msg))

        def _preview(s, limit: int = 600) -> str:
            try:
                out = s if isinstance(s, str) else str(s)
            except Exception:
                out = ""
            out = out.replace("\r", "\\r").replace("\n", "\\n")
            if len(out) > int(limit):
                return out[: int(limit)] + f"... [truncated total={len(out)}]"
            return out

        def _to_str(x) -> str:
            try:
                return x if isinstance(x, str) else str(x)
            except Exception:
                return ""

        def _parse_kv(s: str):
            s = _to_str(s).strip()
            if not s:
                return []
            try:
                items = parse_qsl(s, keep_blank_values=True)
            except Exception:
                items = []
            if items:
                return items
            if ";" in s and "=" in s:
                try:
                    s2 = s.replace(";", "&").replace(" ", "")
                    return parse_qsl(s2, keep_blank_values=True)
                except Exception:
                    return []
            return []

        def _merge_kv_strings(existing: str, extra: str) -> str:
            existing_s = _to_str(existing).strip()
            extra_s = _to_str(extra).strip()
            if not extra_s:
                return existing_s
            existing_items = _parse_kv(existing_s)
            extra_items = _parse_kv(extra_s)
            if not existing_items and not extra_items:
                return existing_s or extra_s
            if not existing_items:
                try:
                    return urlencode(extra_items, doseq=True)
                except Exception:
                    return extra_s
            merged = []
            seen = set()
            for k, v in existing_items + extra_items:
                pair = (_to_str(k), _to_str(v))
                if pair in seen:
                    continue
                seen.add(pair)
                merged.append(pair)
            try:
                return urlencode(merged, doseq=True)
            except Exception:
                return existing_s or extra_s

        def _merge_probe_kv_for_seed(existing: str, extra: str) -> str:
            existing_s = _to_str(existing).strip()
            extra_s = _to_str(extra).strip()
            if not extra_s:
                return existing_s
            existing_items = _parse_kv(existing_s)
            extra_items = _parse_kv(extra_s)
            if not extra_items:
                return existing_s or extra_s
            if not existing_items:
                try:
                    return urlencode(extra_items, doseq=True)
                except Exception:
                    return extra_s

            existing_keys = {str(k) for k, _v in existing_items}
            merged = []
            seen = set()
            for k, v in existing_items:
                pair = (_to_str(k), _to_str(v))
                if pair in seen:
                    continue
                seen.add(pair)
                merged.append(pair)
            for k, v in extra_items:
                ks = _to_str(k)
                pair = (ks, _to_str(v))
                # Probe params are only used to backfill missing keys for front-controller style routes.
                # Never append additional values for a key that already exists in the original request.
                if ks in existing_keys or pair in seen:
                    continue
                seen.add(pair)
                merged.append(pair)
            try:
                return urlencode(merged, doseq=True)
            except Exception:
                return existing_s or extra_s

        def _parse_cookie_names(cookie_s: str):
            raw = _to_str(cookie_s).strip()
            names = set()
            if not raw:
                return names
            for part in raw.split(";"):
                item = _to_str(part).strip()
                if not item or "=" not in item:
                    continue
                key, _ = item.split("=", 1)
                key = _to_str(key).strip()
                if key:
                    names.add(key.lower())
            return names

        def _get_login_cookie_blacklist():
            names = set()
            try:
                names.update({str(x).strip().lower() for x in (getattr(self, "_seed_login_cookie_blacklist", set()) or set()) if str(x).strip()})
            except Exception:
                pass
            direct = self.jconfig.get("direct", {}) if isinstance(self.jconfig, dict) else {}
            if isinstance(direct, dict):
                names.update(_parse_cookie_names(direct.get("mandatory_cookie", "")))
                names.update(_parse_cookie_names(direct.get("login_cookie", "")))
            meta = self.request_data.get("_witcher_meta") if isinstance(self.request_data, dict) else None
            init_meta = meta.get("init") if isinstance(meta, dict) else None
            if isinstance(init_meta, dict):
                names.update(_parse_cookie_names(init_meta.get("mandatory_cookie", "")))
                names.update(_parse_cookie_names(init_meta.get("login_cookie", "")))
            return names

        login_cookie_blacklist = _get_login_cookie_blacklist()

        def _filter_cookie_string(cookie_s: str) -> str:
            raw = _to_str(cookie_s).strip()
            if not raw:
                return ""
            kept = []
            for part in raw.split(";"):
                item = _to_str(part).strip()
                if not item or "=" not in item:
                    continue
                key, value = item.split("=", 1)
                key = _to_str(key).strip()
                value = _to_str(value).strip()
                if not key:
                    continue
                lk = key.lower()
                if lk in login_cookie_blacklist:
                    continue
                # Redirect / upload temp / analytics cookies are unstable and low value for seed fuzzing.
                if lk in {
                    "route_backward",
                    "return-path", "return_path", "redirect", "redirect_to", "redirect_url",
                    "__cf_bm", "_ga", "_gid", "_gat",
                }:
                    continue
                if lk.endswith("_tmp") or lk.endswith("_target_tmp"):
                    continue
                kept.append(f"{key}={value}")
            return "; ".join(kept)

        def _parse_multipart_formdata(body: str, content_type: str):
            text = _to_str(body)
            ctype = _to_str(content_type)
            if not text or "multipart/form-data" not in ctype.lower():
                return []
            m = re.search(r'boundary="?([^";]+)"?', ctype, flags=re.I)
            if not m:
                return []
            boundary = m.group(1)
            if not boundary:
                return []
            marker = "--" + boundary
            parts = text.split(marker)
            pairs = []
            for raw_part in parts:
                part = raw_part.strip("\r\n")
                if not part or part == "--":
                    continue
                header_blob = ""
                content = ""
                if "\r\n\r\n" in part:
                    header_blob, content = part.split("\r\n\r\n", 1)
                elif "\n\n" in part:
                    header_blob, content = part.split("\n\n", 1)
                else:
                    continue
                headers_local = {}
                for line in header_blob.replace("\r\n", "\n").split("\n"):
                    if ":" not in line:
                        continue
                    hk, hv = line.split(":", 1)
                    headers_local[hk.strip().lower()] = hv.strip()
                cd = headers_local.get("content-disposition", "")
                if not cd:
                    continue
                name_match = re.search(r'name="([^"]+)"', cd)
                if not name_match:
                    continue
                field_name = name_match.group(1)
                filename_match = re.search(r'filename="([^"]*)"', cd)
                field_value = content.rstrip("\r\n")
                if filename_match:
                    field_value = ""
                pairs.append((field_name, field_value))
            return pairs

        def _should_drop_all_seed_cookies(req_obj) -> bool:
            if not isinstance(req_obj, dict):
                return False
            source = _to_str(req_obj.get("from", "")).lower()
            if source.startswith("xmlreplay:") or source.startswith("burpxml:") or source == "burpxmlimport":
                return True
            meta = self.request_data.get("_witcher_meta") if isinstance(self.request_data, dict) else None
            init_meta = meta.get("init") if isinstance(meta, dict) else None
            if isinstance(init_meta, dict):
                if init_meta.get("xml_driver") or init_meta.get("burp_xml_import"):
                    return True
            return False

        def _similarity(a: str, b: str) -> float:
            a = _to_str(a).strip().lower()
            b = _to_str(b).strip().lower()
            if not a or not b:
                return 0.0
            if a == b:
                return 1.0
            if len(a) > 256:
                a = a[:256]
            if len(b) > 256:
                b = b[:256]
            try:
                return float(SequenceMatcher(None, a, b).ratio())
            except Exception:
                return 0.0

        def _is_fuzzy_seen(rep_list: List[str], s: str, threshold: float = 0.3) -> bool:
            sv = _to_str(s).strip()
            if not sv:
                return True
            for r in rep_list:
                if _similarity(r, sv) >= float(threshold):
                    return True
            return False

        def _fuzzy_add(rep_list: List[str], s: str, threshold: float = 0.3) -> bool:
            sv = _to_str(s).strip()
            if not sv:
                return False
            if _is_fuzzy_seen(rep_list, sv, threshold=float(threshold)):
                return False
            rep_list.append(sv)
            return True

        def _trim_params(s: str, *, max_keys: Optional[int] = None, max_val_len: Optional[int] = None, fuzzy_keys: bool = False) -> str:
            items = _parse_kv(s)
            if not items:
                return _to_str(s)
            if max_keys is not None and max_keys > 0 and len(items) > int(max_keys):
                if fuzzy_keys:
                    kept = []
                    seen_key_reps: List[str] = []
                    for k, v in items:
                        ks = _to_str(k)
                        if not _is_fuzzy_seen(seen_key_reps, ks, threshold=0.3):
                            seen_key_reps.append(ks)
                            kept.append((k, v))
                            if len(kept) >= int(max_keys):
                                break
                    if len(kept) < int(max_keys):
                        for k, v in items:
                            if (k, v) in kept:
                                continue
                            kept.append((k, v))
                            if len(kept) >= int(max_keys):
                                break
                    items = kept
                else:
                    items = items[: int(max_keys)]
            if max_val_len is not None and max_val_len > 0:
                out_items = []
                lim = int(max_val_len)
                for k, v in items:
                    vs = _to_str(v)
                    if len(vs) > lim:
                        vs = vs[:lim]
                    out_items.append((_to_str(k), vs))
                items = out_items
            try:
                return urlencode(items)
            except Exception:
                return _to_str(s)

        def _encode_seed(cookie_s: str, get_s: str, post_s: str, headers_s: str) -> bytes:
            return b"%s\x00%s\x00%s\x00%s" % (
                _to_str(cookie_s).encode("utf-8", errors="replace"),
                _to_str(get_s).encode("utf-8", errors="replace"),
                _to_str(post_s).encode("utf-8", errors="replace"),
                _to_str(headers_s).encode("utf-8", errors="replace"),
            )

        def _full_seed_param_value(raw) -> str:
            candidate = raw
            if isinstance(candidate, list):
                candidate = candidate[0] if candidate else ""
            elif isinstance(candidate, tuple):
                candidate = candidate[0] if candidate else ""
            elif isinstance(candidate, dict):
                candidate = ""
            return _to_str(candidate)

        def _build_full_seed_pairs(section_name: str):
            params_obj = self._load_initial_params_for_full_seed()
            sec = params_obj.get(section_name) if isinstance(params_obj, dict) else {}
            pairs = []
            keys = set()
            if not isinstance(sec, dict):
                return pairs, keys
            for raw_k, raw_v in sec.items():
                key = _to_str(raw_k).strip()
                if not key:
                    continue
                pairs.append((key, _full_seed_param_value(raw_v)))
                keys.add(key)
            return pairs, keys

        def _encode_pairs(pairs):
            if not pairs:
                return ""
            try:
                return urlencode(pairs, doseq=True)
            except Exception:
                parts = []
                for k, v in pairs:
                    parts.append(f"{_to_str(k)}={_to_str(v)}")
                return "&".join(parts)

        def _encode_cookie_pairs(pairs):
            if not pairs:
                return ""
            return "; ".join([f"{_to_str(k)}={_to_str(v)}" for k, v in pairs])

        def _build_full_param_seed_entry():
            if not self._full_param_seed_enabled():
                _log("full_param_seed_enabled=false")
                return None
            initial_params_path = self._initial_params_path()
            _log(f"full_param_seed_path={initial_params_path}")
            all_params = self._load_initial_params_for_full_seed()
            if not isinstance(all_params, dict):
                _log("full_param_seed_skip=initial_params_not_dict")
                return None
            get_pairs, keys_get = _build_full_seed_pairs("GET")
            post_pairs, keys_post = _build_full_seed_pairs("POST")
            cookie_pairs, keys_cookie = _build_full_seed_pairs("COOKIE")
            if not (keys_get or keys_post or keys_cookie):
                _log("full_param_seed_skip=no_keys")
                return None
            cookie_s = _encode_cookie_pairs(cookie_pairs)
            get_s = _encode_pairs(get_pairs)
            post_s = _encode_pairs(post_pairs)
            headers_out = ""
            strout = _encode_seed(cookie_s, get_s, post_s, headers_out)
            _log(f"full_param_seed_cookie={_preview(cookie_s)}")
            _log(f"full_param_seed_get={_preview(get_s)}")
            _log(f"full_param_seed_post={_preview(post_s)}")
            _log(f"full_param_seed_len={len(strout)}")
            if len(strout) <= 3 or len(strout) > 10240:
                _log(f"full_param_seed_skip=seed_size_invalid len={len(strout)}")
                return None
            if strout in seen_seed_bytes:
                _log("full_param_seed_skip=duplicate_seed_bytes")
                return None
            seen_seed_bytes.add(strout)
            keys = set(keys_get) | set(keys_post) | set(keys_cookie)
            return {
                'reqkey': '__full_param_seed__',
                'strout': strout,
                'keys': keys,
                'key_count': len(keys),
                'keys_get': keys_get,
                'get_pairs': [(str(k), str(v)) for k, v in get_pairs],
                'get_value_reps_by_key': {str(k): [str(v)] for k, v in get_pairs},
                'get_value_rep_count': len(get_pairs),
                'keys_cookie': keys_cookie,
                'keys_post': keys_post,
                'post_key_reps': [str(k) for k, _v in post_pairs],
                'seed_len': len(strout),
                'force_keep': True,
            }

        _log("")
        _log("=" * 120)
        _log(f"[{datetime.utcnow().isoformat()}Z] create_seeds start requests={len(requests or [])} max_seeds={max_seeds} return_entries={return_entries}")
        _log(f"work_dir={self.work_dir}")
        _log(f"log_file={self._seed_processing_log_path()}")

        def _shrink_to_limit(cookie_s: str, get_s: str, post_s: str, headers_s: str, limit: int) -> Optional[Tuple[str, str, str, str]]:
            cookie_s = _to_str(cookie_s)
            get_s = _to_str(get_s)
            post_s = _to_str(post_s)
            headers_s = _to_str(headers_s)

            post_s = _trim_params(post_s, max_keys=10, max_val_len=64, fuzzy_keys=True)
            cur = _encode_seed(cookie_s, get_s, post_s, headers_s)
            if len(cur) <= int(limit):
                return cookie_s, get_s, post_s, headers_s

            headers_s = ""
            cur = _encode_seed(cookie_s, get_s, post_s, headers_s)
            if len(cur) <= int(limit):
                return cookie_s, get_s, post_s, headers_s

            cookie_s = _trim_params(cookie_s, max_keys=None, max_val_len=64)
            cur = _encode_seed(cookie_s, get_s, post_s, headers_s)
            if len(cur) <= int(limit):
                return cookie_s, get_s, post_s, headers_s

            get_s = _trim_params(get_s, max_keys=None, max_val_len=128)
            cur = _encode_seed(cookie_s, get_s, post_s, headers_s)
            if len(cur) <= int(limit):
                return cookie_s, get_s, post_s, headers_s

            get_items = _parse_kv(get_s)
            if get_items:
                low = 0
                high = len(get_items)
                while low < high:
                    mid = (low + high) // 2
                    g2 = ""
                    try:
                        g2 = urlencode(get_items[:mid])
                    except Exception:
                        g2 = get_s
                    if len(_encode_seed(cookie_s, g2, post_s, headers_s)) <= int(limit):
                        low = mid + 1
                    else:
                        high = mid
                keep = max(0, low - 1)
                try:
                    get_s = urlencode(get_items[:keep])
                except Exception:
                    pass
                cur = _encode_seed(cookie_s, get_s, post_s, headers_s)
                if len(cur) <= int(limit):
                    return cookie_s, get_s, post_s, headers_s

            return None

        parsed_reqs = []
        seen_seed_bytes = set()
        for reqkey in requests:
            _log("-" * 120)
            _log(f"REQKEY={reqkey}")
            req = self.request_data["requestsFound"].get(reqkey,None)
            if req is None:
                print(f"[Witcher]\033[32m Did not find {reqkey} in request data. \033[0m")
                _log("missing_in_request_data=true")
                continue

            url = urlparse(req["_url"])
            _log(f"raw_url={_preview(req.get('_url', ''))}")
            cookie_s = _filter_cookie_string(req.get('_cookieData',''))
            get_s = url.query
            post_s = req.get('_postData','')
            probe_get_s = _to_str(req.get('_wc_route_probe_get', ''))
            probe_post_s = _to_str(req.get('_wc_route_probe_post', ''))
            headers = req.get('_headers', {})
            content_type_header = _to_str(req.get('_originalContentType') or headers.get('content-type') or headers.get('Content-Type') or "")
            _log(f"raw_cookie={_preview(req.get('_cookieData', ''))}")
            _log(f"filtered_cookie={_preview(cookie_s)}")
            _log(f"raw_get={_preview(url.query)}")
            _log(f"raw_post={_preview(req.get('_postData', ''))}")
            _log(f"probe_get={_preview(probe_get_s)}")
            _log(f"probe_post={_preview(probe_post_s)}")
            _log(f"content_type={_preview(content_type_header)}")
            if probe_get_s:
                get_s = _merge_probe_kv_for_seed(get_s, probe_get_s)
                _log(f"after_probe_get_merge={_preview(get_s)}")
            multipart_pairs = _parse_multipart_formdata(post_s, content_type_header)
            if multipart_pairs:
                try:
                    post_s = urlencode(multipart_pairs, doseq=True)
                    _log(f"after_multipart_parse={_preview(post_s)}")
                except Exception:
                    pass
            if probe_post_s:
                post_s = _merge_probe_kv_for_seed(post_s, probe_post_s)
                _log(f"after_probe_post_merge={_preview(post_s)}")

            post_s = _trim_params(post_s, max_keys=10, max_val_len=64, fuzzy_keys=True)
            _log(f"after_post_trim={_preview(post_s)}")

            headers_out = ""
            # Keep seeds focused on mutable data. Fixed transport/browser headers are better as env context.
            ignore_headers = {
                "HOST", "CONTENT-LENGTH", "CONNECTION", "COOKIE", "SET-COOKIE", "CONTENT-TYPE", "ACCEPT-ENCODING", "AUTHORIZATION",
                "USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET",
                "CACHE-CONTROL", "PRAGMA", "UPGRADE-INSECURE-REQUESTS", "TE",
                "DNT", "SEC-GPC", "REFERER", "ORIGIN", "X-REQUESTED-WITH",
                "X-POWERED-BY", "SERVER", "DATE",
                "SEC-FETCH-SITE", "SEC-FETCH-MODE", "SEC-FETCH-USER", "SEC-FETCH-DEST",
                "SEC-CH-UA", "SEC-CH-UA-MOBILE", "SEC-CH-UA-PLATFORM",
            }
            for k,v in headers.items():
                if k.upper() not in ignore_headers:
                    headers_out += f"{k}: {v}\n"
            _log(f"headers_out={_preview(headers_out)}")

            shrunk = _shrink_to_limit(cookie_s, get_s, post_s, headers_out, 10240)
            if not shrunk:
                _log("drop_reason=shrink_to_limit_failed")
                continue
            cookie_s, get_s, post_s, headers_out = shrunk
            _log(f"after_shrink_cookie={_preview(cookie_s)}")
            _log(f"after_shrink_get={_preview(get_s)}")
            _log(f"after_shrink_post={_preview(post_s)}")
            _log(f"after_shrink_headers={_preview(headers_out)}")
            if not (str(cookie_s or "").strip() or str(get_s or "").strip() or str(post_s or "").strip() or str(headers_out or "").strip()):
                _log("drop_reason=all_fields_empty_after_shrink")
                continue
            strout = _encode_seed(cookie_s, get_s, post_s, headers_out)
            _log(f"encoded_seed_preview={_preview(strout.decode('utf-8', errors='replace'))}")
            _log(f"encoded_seed_len={len(strout)}")
            
            # Filter out seeds that are > 10KB or empty
            if len(strout) <= 3 or len(strout) > 10240:
                _log(f"drop_reason=seed_size_invalid len={len(strout)}")
                continue
            if strout in seen_seed_bytes:
                _log("drop_reason=duplicate_seed_bytes")
                continue
            seen_seed_bytes.add(strout)
                
            # Extract keys for diversity scoring
            get_pairs = [(str(k), str(v)) for k, v in _parse_kv(get_s)]
            keys_get = {k for k, _ in get_pairs}
            keys_cookie = {k for k, _ in _parse_kv(cookie_s)}
            post_pairs = [(str(k), str(v)) for k, v in _parse_kv(post_s)]
            post_key_reps: List[str] = []
            for k, _v in post_pairs:
                _fuzzy_add(post_key_reps, k, threshold=0.3)
            keys_post = set(post_key_reps)
            get_value_reps_by_key: Dict[str, List[str]] = {}
            for k, v in get_pairs:
                lst = get_value_reps_by_key.get(k)
                if lst is None:
                    lst = []
                    get_value_reps_by_key[k] = lst
                _fuzzy_add(lst, v, threshold=0.3)
            get_value_rep_count = 0
            for _k, lst in get_value_reps_by_key.items():
                get_value_rep_count += len(lst or [])
            keys = set(keys_get) | set(keys_cookie) | set(keys_post)
            _log(f"keys_get={sorted(keys_get)}")
            _log(f"keys_cookie={sorted(keys_cookie)}")
            _log(f"keys_post={sorted(keys_post)}")
            _log(f"keys_all={sorted(keys)}")
            
            # Skip requests with absolutely no parameters
            if len(keys) == 0:
                _log("drop_reason=no_parameters")
                continue
                
            parsed_reqs.append({
                'reqkey': reqkey,
                'strout': strout,
                'keys': keys,
                'key_count': len(keys),
                'keys_get': keys_get,
                'get_pairs': get_pairs,
                'get_value_reps_by_key': get_value_reps_by_key,
                'get_value_rep_count': int(get_value_rep_count),
                'keys_cookie': keys_cookie,
                'keys_post': keys_post,
                'post_key_reps': post_key_reps,
                'seed_len': len(strout),
            })
            _log("accepted_for_selection=true")

        full_param_entry = _build_full_param_seed_entry()
        if full_param_entry is not None:
            parsed_reqs.append(full_param_entry)
            _log("full_param_seed_added=true")
        else:
            _log("full_param_seed_added=false")

        seed_limit = max_seeds
        if seed_limit is None:
            seed_limit = self._initial_seed_limit()
        try:
            seed_limit = int(seed_limit)
        except Exception:
            seed_limit = self._initial_seed_limit()
        _log(f"parsed_seed_candidates={len(parsed_reqs)}")
        _log(f"seed_limit={seed_limit}")

        forced_reqs = [req for req in parsed_reqs if bool(req.get("force_keep"))]
        regular_reqs = [req for req in parsed_reqs if not bool(req.get("force_keep"))]
        if forced_reqs:
            _log(f"forced_seed_candidates={len(forced_reqs)}")

        # If we have more than the allowed number of seeds, select the most diverse subset.
        if seed_limit > 0 and len(regular_reqs) > seed_limit:
            _log("selection_mode=diverse_subset")
            regular_reqs.sort(
                key=lambda x: (
                    len(x.get('keys_get') or []),
                    int(x.get('get_value_rep_count') or 0),
                    len(x.get('keys_cookie') or []),
                    len(x.get('keys_post') or []),
                    x['key_count'],
                    -int(x.get('seed_len') or 0),
                ),
                reverse=True,
            )
            _log("selection_sorted_candidates=")
            for idx, cand in enumerate(regular_reqs):
                _log(
                    f"  cand[{idx}] reqkey={cand.get('reqkey')} "
                    f"keys_get={sorted(cand.get('keys_get') or [])} "
                    f"keys_cookie={sorted(cand.get('keys_cookie') or [])} "
                    f"keys_post={sorted(cand.get('keys_post') or [])} "
                    f"seed_len={cand.get('seed_len')}"
                )
            
            selected_reqs = [regular_reqs[0]] # Always take the one with the most keys
            _log(f"selected_initial={regular_reqs[0].get('reqkey')}")
            seen_get = set(regular_reqs[0].get('keys_get') or set())
            seen_get_value_reps: Dict[str, List[str]] = {}
            for k, lst in (regular_reqs[0].get('get_value_reps_by_key') or {}).items():
                if not isinstance(k, str):
                    continue
                if not isinstance(lst, list):
                    continue
                seen_get_value_reps[str(k)] = [str(x) for x in lst if isinstance(x, str)]
            seen_cookie = set(regular_reqs[0].get('keys_cookie') or set())
            seen_post_reps: List[str] = []
            for k in (regular_reqs[0].get('post_key_reps') or []):
                if isinstance(k, str):
                    _fuzzy_add(seen_post_reps, k, threshold=0.3)
            
            # Greedily select seeds that add the most NEW keys
            while len(selected_reqs) < seed_limit:
                best_req = None
                best_new_keys_count = -1
                
                for req in regular_reqs:
                    if req in selected_reqs:
                        continue
                    ng = (req.get('keys_get') or set()) - seen_get
                    nc = (req.get('keys_cookie') or set()) - seen_cookie
                    new_get_vals = 0
                    gv = req.get('get_value_reps_by_key') or {}
                    if isinstance(gv, dict):
                        for k, lst in gv.items():
                            if not isinstance(k, str) or not isinstance(lst, list):
                                continue
                            seen_lst = seen_get_value_reps.get(k) or []
                            for v in lst:
                                if not isinstance(v, str):
                                    continue
                                if not _is_fuzzy_seen(seen_lst, v, threshold=0.3):
                                    new_get_vals += 1
                    new_post_keys = 0
                    for pk in (req.get('post_key_reps') or []):
                        if isinstance(pk, str) and not _is_fuzzy_seen(seen_post_reps, pk, threshold=0.3):
                            new_post_keys += 1
                    score = len(ng) * 100000000 + int(new_get_vals) * 10000 + len(nc) * 100 + int(new_post_keys)
                    if (
                        int(score) > best_new_keys_count or
                        (
                            int(score) == best_new_keys_count and best_req is not None and
                            int(req.get('seed_len') or 0) < int(best_req.get('seed_len') or 0)
                        ) or
                        (best_req is None)
                    ):
                        best_new_keys_count = int(score)
                        best_req = req
                        
                # If no new keys can be found, keep the shortest remaining seed.
                if best_req is None or best_new_keys_count == 0:
                    remaining = [req for req in regular_reqs if req not in selected_reqs]
                    if remaining:
                        best_req = min(remaining, key=lambda r: int(r.get('seed_len') or 0))
                            
                if best_req is None:
                    break
                selected_reqs.append(best_req)
                _log(f"selected_next={best_req.get('reqkey')} score={best_new_keys_count}")
                seen_get.update(best_req.get('keys_get') or set())
                for k, lst in (best_req.get('get_value_reps_by_key') or {}).items():
                    if not isinstance(k, str) or not isinstance(lst, list):
                        continue
                    bucket = seen_get_value_reps.get(k)
                    if bucket is None:
                        bucket = []
                        seen_get_value_reps[k] = bucket
                    for v in lst:
                        if isinstance(v, str):
                            _fuzzy_add(bucket, v, threshold=0.3)
                seen_cookie.update(best_req.get('keys_cookie') or set())
                for pk in (best_req.get('post_key_reps') or []):
                    if isinstance(pk, str):
                        _fuzzy_add(seen_post_reps, pk, threshold=0.3)
                
            regular_reqs = selected_reqs
            _log(f"selected_total={len(regular_reqs)}")

        parsed_reqs = list(regular_reqs) + list(forced_reqs)
        _log(f"final_selected_with_forced={len(parsed_reqs)}")

        if return_entries:
            _log(f"return_entries_count={len(parsed_reqs)}")
            self._append_seed_processing_log("\n".join(log_lines))
            return parsed_reqs

        seeds = [req['strout'] for req in parsed_reqs]
        _log(f"final_seed_count={len(seeds)}")
        for idx, req in enumerate(parsed_reqs):
            _log(f"final_seed[{idx}] reqkey={req.get('reqkey')} seed_len={req.get('seed_len')} keys={sorted(req.get('keys') or [])}")
        
        if len(seeds) == 0:
            seeds.append(b"cookie=flour\x00query=search\x00post=hole")
            _log("fallback_seed_inserted=true")
        self._append_seed_processing_log("\n".join(log_lines))
        return seeds

    def _extract_fixed_header_env(self, requests):
        """
        Extract stable headers from request_data and map them to CGI-style env vars.
        If multiple values appear, keep the most frequent non-empty one.
        """
        from collections import Counter
        header_to_env = {
            "USER-AGENT": "HTTP_USER_AGENT",
            "ACCEPT": "HTTP_ACCEPT",
            "ACCEPT-LANGUAGE": "HTTP_ACCEPT_LANGUAGE",
            "ACCEPT-CHARSET": "HTTP_ACCEPT_CHARSET",
            "REFERER": "HTTP_REFERER",
            "ORIGIN": "HTTP_ORIGIN",
            "X-REQUESTED-WITH": "HTTP_X_REQUESTED_WITH",
        }
        buckets = {k: Counter() for k in header_to_env.keys()}
        for reqkey in requests or []:
            req = self.request_data["requestsFound"].get(reqkey, None)
            if not req:
                continue
            headers = req.get("_headers", {}) or {}
            for hk, hv in headers.items():
                key = str(hk or "").strip().upper()
                if key not in buckets:
                    continue
                val = str(hv or "").strip()
                if not val:
                    continue
                buckets[key][val] += 1
        out = {}
        for hk, env_name in header_to_env.items():
            counter = buckets.get(hk)
            if not counter:
                continue
            most_common = counter.most_common(1)
            if most_common and most_common[0][0]:
                out[env_name] = str(most_common[0][0])
        return out

    def create_dictionary(self, target):
        dictionary_vars = []
        inputlist = self.request_data["inputSet"]
        if f"inputSet-{target}" in self.request_data:
            inputlist = inputlist + self.request_data[f"inputSet-{target}"]
        extras = set()
        skipped_reason_counts = Counter()

        def _normalize_token_parts(token):
            try:
                s = token if isinstance(token, str) else str(token)
            except Exception:
                skipped_reason_counts["coerce_error"] += 1
                return None
            s = (s or "").strip()
            if not s:
                skipped_reason_counts["empty"] += 1
                return None
            if s.find("&") == len(s) - 1:
                s = s[:-1]
            key = s
            value = ""
            if "=" in s:
                key, value = s.split("=", 1)
            return s, (key or "").strip(), (value or "").strip()

        def _should_skip_dictionary_entry(key, value):
            lk = (key or "").strip().lower()
            lv = (value or "").strip().lower()
            if not lk:
                return "empty_key"
            # Serialized back/redirect context is large, unstable, and not useful for mutation.
            if lk in {"route_backward", "return-path", "return_path", "redirect", "redirect_to", "redirect_url"}:
                return "unstable_redirect_param"
            if lk.startswith("submit_") and len(value or "") > 48:
                return "long_submit_label"
            if len(value or "") > 96 and ("http%3a%2f%2f" in lv or "https%3a%2f%2f" in lv or "ytox" in lv):
                return "serialized_or_url_value"
            return None

        def _append_dictionary_bytes(raw_text):
            payload = raw_text.encode("utf-8", errors="replace") + b"&"
            if len(payload) > 128:
                skipped_reason_counts["too_long_bytes"] += 1
                return
            dictionary_vars.append(payload)

        req_keys = (target or {}).get("requests") if isinstance(target, dict) else None
        for reqkey in req_keys or []:
            req = self.request_data["requestsFound"].get(reqkey)
            if not isinstance(req, dict):
                continue
            try:
                url = urlparse(req.get("_url") or "")
            except Exception:
                continue
            for q in ((url.query or "").strip(), str(req.get("_wc_route_probe_post") or "").strip()):
                if not q:
                    continue
                q2 = q.replace(";", "&")
                for part in q2.split("&"):
                    s = (part or "").strip()
                    if not s:
                        continue
                    if "=" in s:
                        ks, vs = s.split("=", 1)
                    else:
                        ks, vs = s, ""
                    ks = (ks or "").strip()
                    vs = (vs or "").strip()
                    if ks:
                        extras.add(ks)
                        extras.add(ks + "=")
                    if vs:
                        if len(vs) > 64:
                            vs = vs[:64]
                        extras.add(vs)
                    if ks and vs:
                        extras.add(f"{ks}={vs}")

        for inputvar in list(inputlist or []) + sorted(extras):
            normalized = _normalize_token_parts(inputvar)
            if not normalized:
                continue
            s, key, value = normalized
            skip_reason = _should_skip_dictionary_entry(key, value)
            if skip_reason:
                skipped_reason_counts[skip_reason] += 1
                continue
            _append_dictionary_bytes(s)
        if dictionary_vars:
            print(f"Wrote out dictionary vars {len(inputlist)} totals bytes {len(dictionary_vars)} {dictionary_vars[0]}")
        else:
            print(f"Wrote out dictionary vars {len(inputlist)} totals bytes 0 b''")
        if skipped_reason_counts:
            print(f"Skipped dictionary entries by reason: {dict(skipped_reason_counts)}")

        #open(self.dictionary_fn,"w").write(dictionary_vars)
        return dictionary_vars

    def init_shared_memory(self):
        if self.init_info_shm:
            subprocess.check_call(self.init_info_shm.split(" "))
            print(f"Initalized Shared Memory using '{self.init_info_shm}'")

    def _terminate_and_reap(self, proc):
        if not proc:
            return
        try:
            if os.name != "nt":
                os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            pass
        try:
            if proc.poll() is None:
                proc.terminate()
        except Exception:
            pass
        try:
            if proc.poll() is None:
                proc.wait(timeout=5)
        except Exception:
            pass
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    def start_external_servers(self):
        print(f"cmd={self.server_cmd}")

        if self.server_cmd is not None and len(self.server_cmd) > 1:
            print("Starting up servers")
            increasing_port = self.server_base_port

            for icnt in range(0, self.cores):
                server_cmd = []
                for cmd in self.server_cmd:
                    cmd = cmd.replace("@@PORT@@", str(self.server_base_port))
                    cmd = cmd.replace("@@PORT_INCREMENT@@", str(increasing_port))

                    server_cmd.append(cmd)

                server_env_vars = os.environ.copy()

                for envkey, envval in self.server_env_vars.items():
                    if "@@PORT_INCREMENT@@" in envval:
                        envval = envval.replace("@@PORT_INCREMENT@@", str(increasing_port))
                    server_env_vars[envkey] = envval
                print(f"CMD = {' '.join(server_cmd)}")
                #print(f"SERVER_ENV_VARS={server_env_vars}")
                logfpath = f"/tmp/server_{increasing_port}.out"
                outfile = open(logfpath,"w")

                proc_info = {"server_cmd":server_cmd, "logfile": logfpath, "port":increasing_port, "attempts":0,
                             "up":False, "env": server_env_vars, "outfile": outfile}

                preexec_fn = None if os.name == "nt" else (lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN))
                proc_info["proc"] = subprocess.Popen(
                    server_cmd,
                    env=server_env_vars,
                    stdout=outfile,
                    stderr=outfile,
                    close_fds=True,
                    preexec_fn=preexec_fn,
                    start_new_session=(os.name != "nt"),
                )
                #print(f"Starting up {proc_info}")
                self.server_procs.append(proc_info)
                increasing_port = increasing_port + 1

            wait_cnt = 0
            all_servers_up = False
            time.sleep(2)
            while not all_servers_up:
                all_servers_up = True
                for si in self.server_procs:
                    if si["attempts"] > 3:
                        print("Error trying to bring up servers, exiting...")
                        exit(99)
                    p = si["proc"]
                    if si["up"]:
                        continue
                    if p.poll() is None:  # process is still running
                        if os.path.exists(si["logfile"]):
                            with open(si["logfile"], "r") as lf:
                                data = lf.read()
                                if data.find(self.server_up_msg) > -1:
                                    si["up"] = True
                    else: # process is stopped
                        if not si["up"]:
                            print(f"DOING: pkill -P {p.pid}")
                            os.system(f"pkill -P {p.pid}")
                            print(f"DOING: pkill -9 -f {si['port']}")
                            os.system(f"pkill -9 -f {si['port']}")
                            try:
                                p.wait(timeout=1)
                            except Exception:
                                pass
                            print("attempting to bring up again.")
                            try:
                                si["outfile"].close()
                            except Exception:
                                pass
                            outfile = open(si["logfile"], "a")
                            si["outfile"] = outfile
                            preexec_fn = None if os.name == "nt" else (lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN))
                            si["proc"] = subprocess.Popen(
                                si["server_cmd"],
                                env=si["env"],
                                stdout=outfile,
                                stderr=outfile,
                                close_fds=True,
                                preexec_fn=preexec_fn,
                                start_new_session=(os.name != "nt"),
                            )
                        else:
                            assert(not si["up"])

                    all_servers_up = all_servers_up and si["up"]

                if wait_cnt > 120:
                    print("Error, waited for too long, exiting")
                    exit(98)
                if not all_servers_up:
                    print("All the servers are not up, sleeping and will try again")
                    time.sleep(2)
                wait_cnt += 1

            if len(self.server_up_msg) == 0:
                print("Giving servers a chance to come up")
                time.sleep(10)

            print("Servers, should be up")

    def kill_servers(self):
        print("Bringing down external servers")

        for si in self.server_procs:
            p = si["proc"]
            if p:
                print(f"\tDOING: pkill -P {p.pid}")
                os.system(f"pkill -P {p.pid}")
            if p and p.poll() is None:
                try:
                    self._terminate_and_reap(p)
                except Exception as ex:
                    print(f"ERROR with bringing down {ex}")
            else:
                try:
                    p.wait(timeout=1)
                except Exception:
                    pass
            print(f"\tDOING: pkill -9 -f {si['port']}")
            os.system(f"pkill -f {si['port']}")
            os.system(f"pkill -9 -f 'port={si['port']}'") # just to be sure!
            try:
                si["outfile"].close()
            except Exception:
                pass

        self.server_procs = []



    #def start_fuzzer(self, do_resume, target_path, method_map, dictionary_str, seeds):
    #mod
    def start_fuzzer(
        self,
        do_resume,
        target_path,
        method_map,
        dictionary_str,
        seeds,
        requests=None,
        result_storage_pathname=None,
        budget_target=None,
        attempt_timeout_cap=None,
        weak_rebalance_fn=None,
    ):
        if requests is None:
            requests = []

        os.environ["method_map"] = method_map
        # Prefer env for stable HTTP headers; avoid wasting AFL mutations on fixed headers in seed payload.
        try:
            fixed_header_env = self._extract_fixed_header_env(requests)
            for ek, ev in fixed_header_env.items():
                os.environ[str(ek)] = str(ev)
        except Exception:
            pass
        #os.environ["SCRIPT_FILENAME"] = target_path
        # mod
        if target_path.startswith("http"):
            url_obj = urlparse(target_path)
            script_filename = url_obj.path
            path_info = ""
        else:
            # mod
            script_filename = target_path
            path_info = ""
            
            # mod
            for reqkey in requests:
                req = self.request_data["requestsFound"].get(reqkey)
                if req:
                    original_url = urlparse(req["_url"])
                    original_path = unquote(original_url.path or "")
                    php_idx = original_path.lower().find(".php")
                    if php_idx != -1:
                        script_part = original_path[:php_idx + 4]
                        rest = original_path[php_idx + 4:]
                        if not rest:
                            rest = "/"
                        try:
                            if os.path.basename(script_part).lower() == os.path.basename(script_filename).lower():
                                path_info = rest
                                break
                        except Exception:
                            pass
                    
                    # mod
                    front_controllers = ['app.php', 'index.php', 'router.php']
                    for controller in front_controllers:
                        if f'/{controller}' in original_path:
                            controller_index = original_path.find(f'/{controller}')
                            if controller_index != -1:
                                # mod
                                path_info = original_path[controller_index + len(f'/{controller}'):]
                                if not path_info:
                                    path_info = "/"
                                break

        os.environ["SCRIPT_FILENAME"] = script_filename
        if path_info:
            os.environ["PATH_INFO"] = path_info
            print(f"Setting PATH_INFO: {path_info}")

        if target_path.startswith("http"):
            binary_options = self.change_url_to_target(target_path)
            print(f"NEW BIN OPTS {binary_options}")
        else:
            binary_options = self.binary_options

        # --- Dynamic Fuzz Time Initialization ---
        base_time = self.timeout
        num_seeds = len(seeds) if seeds else 0
        pool_snapshot = 0.0

        if hasattr(self, 'global_timeout') and self.global_timeout > 0 and getattr(self, 'current_allocated_time', None) is not None:
            dynamic_timeout = float(self.current_allocated_time or 0.0)
            check_interval = dynamic_timeout * 0.1
            half_check_interval = dynamic_timeout * 0.05
            time_adjustment = dynamic_timeout * 0.05
            try:
                pool_snapshot = float(getattr(self, "time_pool", 0.0) or 0.0)
            except Exception:
                pool_snapshot = 0.0
            max_allowed_time = float(dynamic_timeout or 0.0) + float(pool_snapshot or 0.0)
        else:
            # 初始分配：1个seed给10%，但保底20%（防止AFL还没校准完就被杀），上限150%
            initial_ratio = min(max(0.1 * num_seeds, 0.2), 1.5)
            dynamic_timeout = base_time * initial_ratio
            check_interval = base_time * 0.1
            half_check_interval = base_time * 0.05
            time_adjustment = base_time * 0.05
            max_allowed_time = base_time * 2.5

        attempt_timeout_cap_f = None
        if attempt_timeout_cap is not None:
            try:
                attempt_timeout_cap_f = max(1.0, float(attempt_timeout_cap))
                dynamic_timeout = min(float(dynamic_timeout or 0.0), attempt_timeout_cap_f)
                max_allowed_time = min(float(max_allowed_time or 0.0), attempt_timeout_cap_f)
            except Exception:
                attempt_timeout_cap_f = None

        last_paths_total = None
        phase_start_run_time = 0.0
        phase_timeout = float(dynamic_timeout or 0.0)
        phase_baseline_time = float(phase_start_run_time) + max(1.0, float(phase_timeout) * 0.05)
        phase_compare_interval = max(1.0, float(phase_timeout) * 0.10)
        phase_next_compare_time = float(phase_start_run_time) + float(phase_compare_interval)
        weak_rebalanced_in_run = False
        weak_time_checks_done = set()
        def _maybe_rebalance_by_weak(reason: str, weak_cnt_hint=None):
            nonlocal weak_rebalanced_in_run, check_interval, time_adjustment, run_time
            nonlocal phase_start_run_time, phase_timeout, phase_baseline_time, phase_compare_interval, phase_next_compare_time, last_paths_total
            if (not callable(weak_rebalance_fn)) or weak_rebalanced_in_run:
                return
            if not (hasattr(self, 'global_timeout') and self.global_timeout > 0):
                return
            weak_cnt = 0
            try:
                if weak_cnt_hint is None:
                    weak_probe = fuzzer.startup_status()
                    weak_cnt = len(weak_probe.get("weakseeds", []) or [])
                else:
                    weak_cnt = int(weak_cnt_hint or 0)
            except Exception:
                weak_cnt = 0
            current_paths_total = 0
            try:
                stats = fuzzer.stats
                current_paths_total = sum(int(f.get('paths_total', 0)) for f in stats.values())
            except Exception:
                current_paths_total = 0
            if int(weak_cnt) > 0 and int(current_paths_total) <= 0:
                print(f"[*] Weak-seed check skipped during {reason}: weak={int(weak_cnt)} but paths_total=0")
                return
            if int(weak_cnt) <= 1:
                return
            try:
                new_timeout_cap = weak_rebalance_fn(int(weak_cnt))
            except Exception:
                new_timeout_cap = None
            if new_timeout_cap is not None:
                old_to = float(fuzzer.timeout or 0.0)
                cap = max(1.0, float(new_timeout_cap))
                if attempt_timeout_cap_f is not None:
                    cap = min(cap, float(attempt_timeout_cap_f))
                fuzzer.timeout = cap
                # Refresh dynamic-adjustment 10% interval after rebalance.
                check_interval = max(1.0, float(fuzzer.timeout or 0.0) * 0.1)
                time_adjustment = max(1.0, float(fuzzer.timeout or 0.0) * 0.05)
                # Re-slice absolute checkpoints from rebalance moment based on the new timeout.
                phase_start_run_time = float(run_time or 0.0)
                phase_timeout = float(fuzzer.timeout or 0.0)
                phase_baseline_time = float(phase_start_run_time) + max(1.0, float(phase_timeout) * 0.05)
                phase_compare_interval = max(1.0, float(phase_timeout) * 0.10)
                phase_next_compare_time = float(phase_start_run_time) + float(phase_compare_interval)
                last_paths_total = None
                weak_rebalanced_in_run = True
                print(
                    f"[*] Weak-seed rebalance applied during {reason} for {target_path}: "
                    f"weak={int(weak_cnt)}, timeout {old_to:.0f}s -> {float(fuzzer.timeout or 0.0):.0f}s, "
                    f"baseline_at=+{max(1.0, float(phase_timeout) * 0.05):.0f}s, compare_every=+{float(phase_compare_interval):.0f}s"
                )
        # ----------------------------------------

        def _pre_afl_instance_start(instance_cnt):
            if self.db_backup_manager is not None:
                self.db_backup_manager.restore_from_backup()

        fuzzer = Phuzzer.phactory(phuzzer_type=Phuzzer.WITCHER_AFL, target=self.fuzzer_target_binary, target_opts=binary_options,
                                  work_dir=self.work_dir, seeds=seeds, afl_count=self.cores,
                                  create_dictionary=False, timeout=dynamic_timeout, memory=self.memory,
                                  run_timeout=self.run_timeout, dictionary=dictionary_str,
                                  use_qemu=self.use_qemu, resume=do_resume, login_json_fn=self.config_loc,
                                  base_port=self.server_base_port, container_info=self.container_info,
                                  fault_escalation=not self.no_fault_escalation,
                                  pre_instance_callback=_pre_afl_instance_start)
        self._flush_seed_processing_logs()

        def chown_files():
            # by default, AFL creates all files and dirs with permissions of 700
            # as a result, unless running witcher as root, it cannot access the files unless they are
            # owned by the current user, which is what this is meant to do. It runs in reporter,
            if self.container_info:

                fuzzer.chown_container_files(pwd.getpwuid( os.getuid() ).pw_uid)

        start_results = {"totalfail": False, "timeout": False }
        reporter = Reporter(self.fuzzer_target_binary, self.report_dir, self.cores, self.first_crash, self.timeout,
                            fuzzer.work_dir, chown_files=chown_files, fuzzer=fuzzer)

        reporter.set_script_filename(target_path)

        # Coverage daemon entry disabled (keep implementation for later restore).
        # self._start_coverage_daemon()
        db_backup_enabled = bool(self.jconfig.get("witcher_db_backup_enabled", True))
        try:
            self.db_backup_manager = DBBackupManager(
                config_path=self.config_loc,
                work_dir=self.work_dir,
                enabled=db_backup_enabled,
            )
        except Exception as ex:
            self.db_backup_manager = None
            try:
                os.makedirs(self.work_dir, exist_ok=True)
                with open(os.path.join(self.work_dir, "db_backup.log"), "a", encoding="utf-8", errors="replace") as wf:
                    wf.write("[%s] [ERROR] 初始化数据库备份管理失败，已跳过数据库备份/恢复: %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), str(ex)))
            except Exception:
                pass
        fuzzer.start()
        self.symex_handle = start_symex_hybrid(
            work_dir=self.work_dir,
            config_path=self.config_loc,
            request_data_path=self.request_data_fn,
            trace_timeout=int(self.jconfig.get("symex_trace_timeout", 30)),
            enabled=bool(self.jconfig.get("symex_enabled", True)),
        )

        reporter.start()
        print("Starting Reporter...")
        # Monitor phuzzer's execution
        try:
            crash_seen = False
            reporter.enable_printing()
            verified_start = False
            start_mon = time.monotonic()
            run_time = 0

            while True:
                try:
                    run_time = time.monotonic() - start_mon
                except Exception:
                    pass
                if fuzzer.timeout is not None and run_time >= float(fuzzer.timeout):
                    reporter.set_timeout_seen()
                    start_results["timeout"] = True
                    print("\n[*] Timeout reached.")
                    break
                # Extra weak-seed checks at fuzz start, 30s and 60s.
                for weak_t in (0.0, 30.0, 60.0, 120.0, 300.0):
                    if weak_t not in weak_time_checks_done and float(run_time or 0.0) >= weak_t:
                        _maybe_rebalance_by_weak(f"time-{int(weak_t)}s")
                        weak_time_checks_done.add(weak_t)

                if not verified_start:
                    chown_files()
                    start_results = fuzzer.startup_status()
                    totalcnt = start_results["totalcnt"]
                    successcnt = start_results["successcnt"]
                    forkfailcnt = start_results["forkfail"]
                    failedseeds = start_results['failedseeds']
                    weakseeds = start_results['weakseeds']
                    logfilesize = start_results['logfilesize']
                    reporter.set_startup_values(successcnt, len(failedseeds), len(weakseeds), logfilesize)
                    if forkfailcnt >= 1:
                        print(f"[*]\033[31mError at least 1 instance failed to communicate with fork server \033[0m")
                        import ipdb
                        ipdb.set_trace()
                        raise Exception("Fork server handshake failure count too high")

                    if successcnt + len(start_results['failedseeds']) == self.cores or (run_time > 120 and logfilesize > 0) or run_time > 300:
                        verified_start = True
                        # Startup weak-seed check: run once at project start.
                        _maybe_rebalance_by_weak("startup", len(weakseeds or []))
                        if result_storage_pathname and (failedseeds or weakseeds):
                            for fn in set(failedseeds or []):
                                seedpath = f"{self.work_dir}/initial_seeds/{fn}"
                                if os.path.exists(seedpath):
                                    self.save_crashing_seed(seedpath, result_storage_pathname, "bad-seed")
                            for fn in set(weakseeds or []):
                                seedpath = f"{self.work_dir}/initial_seeds/{fn}"
                                if os.path.exists(seedpath):
                                    self.save_crashing_seed(seedpath, result_storage_pathname, "weak-seed")
                        success_percent = (float(successcnt) / float(totalcnt)) * 100 if totalcnt > 0 else 0
                        if success_percent < 80:
                            print(f"[*] Error less than 80% ({successcnt}/{totalcnt} = {success_percent:3.2f})of the fuzzers started up successfully please investigate")
                            start_results["totalfail"] = True

                            break
                        else:
                            start_results["totalfail"] = False
                    else:
                        start_results["totalfail"] = False

                else:
                    # --- Dynamic Fuzz Time Adjustment ---
                    if run_time >= float(phase_baseline_time or 0.0) and last_paths_total is None:
                        current_paths_total = 0
                        try:
                            stats = fuzzer.stats
                            current_paths_total = sum(int(f.get('paths_total', 0)) for f in stats.values())
                        except Exception:
                            current_paths_total = 0
                        last_paths_total = current_paths_total
                        print(f"\n[*] Dynamic Fuzz: 5% checkpoint. Initial paths = {last_paths_total}")
                        _maybe_rebalance_by_weak("dynamic-5%")

                    if last_paths_total is not None and run_time >= float(phase_next_compare_time or 0.0):
                        current_paths_total = last_paths_total
                        try:
                            stats = fuzzer.stats
                            current_paths_total = sum(int(f.get('paths_total', 0)) for f in stats.values())
                        except Exception:
                            current_paths_total = last_paths_total
                        # 10% cadence: compare path growth and adjust by current timeout's 5%.
                        time_adjustment = max(1.0, float(fuzzer.timeout or 0.0) * 0.05)
                        if current_paths_total > last_paths_total:
                            if hasattr(self, 'global_timeout') and self.global_timeout > 0:
                                try:
                                    pool = float(getattr(self, "time_pool", 0.0) or 0.0)
                                except Exception:
                                    pool = 0.0
                                if pool > 0.0:
                                    take = min(float(time_adjustment or 0.0), float(pool or 0.0))
                                    try:
                                        fuzzer.timeout = float(fuzzer.timeout or 0.0) + float(take)
                                    except Exception:
                                        fuzzer.timeout = float(fuzzer.timeout or 0.0) + float(take)
                                    try:
                                        self.time_pool = float(getattr(self, "time_pool", 0.0) or 0.0) - float(take)
                                    except Exception:
                                        self.time_pool = 0.0
                                    if budget_target is not None and isinstance(budget_target, dict):
                                        try:
                                            budget_target["_budget_total"] = float(budget_target.get("_budget_total") or 0.0) + float(take)
                                        except Exception:
                                            pass
                                    print(f"\n[*] Dynamic Fuzz: Paths grew ({last_paths_total} -> {current_paths_total}). Timeout increased by {take:.0f}s to {fuzzer.timeout:.0f}s (Pool {getattr(self,'time_pool',0.0):.0f}s)")
                                else:
                                    print(f"\n[*] Dynamic Fuzz: Paths grew ({last_paths_total} -> {current_paths_total}). No pool time available, timeout unchanged.")
                            else:
                                fuzzer.timeout = min(fuzzer.timeout + time_adjustment, max_allowed_time)
                                print(f"\n[*] Dynamic Fuzz: Paths grew ({last_paths_total} -> {current_paths_total}). Timeout increased to {fuzzer.timeout:.0f}s (Max {max_allowed_time:.0f}s)")
                        else:
                            if hasattr(self, 'global_timeout') and self.global_timeout > 0:
                                dec = min(float(time_adjustment or 0.0), max(0.0, float(fuzzer.timeout or 0.0) - 1.0))
                                if dec > 0.0:
                                    fuzzer.timeout = float(fuzzer.timeout or 0.0) - float(dec)
                                    try:
                                        self.time_pool = float(getattr(self, "time_pool", 0.0) or 0.0) + float(dec)
                                    except Exception:
                                        self.time_pool = float(dec)
                                    if budget_target is not None and isinstance(budget_target, dict):
                                        try:
                                            budget_target["_budget_total"] = max(0.0, float(budget_target.get("_budget_total") or 0.0) - float(dec))
                                        except Exception:
                                            pass
                                    print(f"\n[*] Dynamic Fuzz: Paths stalled at {current_paths_total}. Timeout decreased by {dec:.0f}s to {fuzzer.timeout:.0f}s (Pool {getattr(self,'time_pool',0.0):.0f}s)")
                            else:
                                fuzzer.timeout = max(1.0, float(fuzzer.timeout or 0.0) - float(time_adjustment))
                                print(f"\n[*] Dynamic Fuzz: Paths stalled at {current_paths_total}. Timeout decreased to {fuzzer.timeout:.0f}s")

                        if attempt_timeout_cap_f is not None:
                            fuzzer.timeout = min(float(fuzzer.timeout or 0.0), float(attempt_timeout_cap_f))
                        # Force weak-seed check at each path-count compare checkpoint.
                        _maybe_rebalance_by_weak("dynamic-10%")
                        last_paths_total = current_paths_total
                        check_interval = max(1.0, float(fuzzer.timeout or 0.0) * 0.1)
                        phase_compare_interval = float(check_interval)
                        phase_next_compare_time = float(run_time or 0.0) + float(phase_compare_interval)
                        # ------------------------------------

                if not crash_seen and fuzzer.found_crash():
                    chown_files()
                    # print ("\n[*] Crash found!")
                    crash_seen = True
                    reporter.set_crash_seen()
                    if result_storage_pathname:
                        self.harvest_afl_crashes(result_storage_pathname)
                    if self.first_crash:
                        break
                time.sleep(1)

        except KeyboardInterrupt:
            end_reason = "Keyboard Interrupt"
            print("\n[*] Aborting wait. Ctrl-C again for KeyboardInterrupt.")
            self.kill = True
            if self.db_backup_manager is not None:
                try:
                    self.db_backup_manager.cleanup_on_interrupt()
                except Exception:
                    pass

        except Exception as e:
            import traceback
            os.makedirs(self.work_dir, exist_ok=True)
            with open(os.path.join(self.work_dir, "witcher_error.log"), "a", encoding="utf-8", errors="replace") as err_fp:
                traceback.print_exc(file=err_fp)
            traceback.print_exc()
            end_reason = "Exception occurred"
            print("\n[*] Unknown exception received (%s). Terminating fuzzer." % e)
            self.kill = True
            raise
        finally:
            print("[*] Terminating fuzzer.")
            try:
                start_results["run_time_seconds"] = float(run_time or 0.0)
            except Exception:
                start_results["run_time_seconds"] = 0.0
            try:
                start_results["timeout_cap_seconds"] = float(fuzzer.timeout or 0.0)
            except Exception:
                start_results["timeout_cap_seconds"] = 0.0
            if hasattr(self, 'global_timeout') and self.global_timeout > 0 and budget_target is not None and isinstance(budget_target, dict):
                try:
                    unused = max(0.0, float(fuzzer.timeout or 0.0) - float(run_time or 0.0))
                except Exception:
                    unused = 0.0
                if unused > 0.0:
                    try:
                        self.time_pool = float(getattr(self, "time_pool", 0.0) or 0.0) + float(unused)
                    except Exception:
                        self.time_pool = float(unused)
                    try:
                        budget_target["_budget_total"] = max(0.0, float(budget_target.get("_budget_total") or 0.0) - float(unused))
                    except Exception:
                        pass
            chown_files()
            # Coverage snapshot entry disabled (keep implementation for later restore).
            # self._snapshot_and_stop_coverage_daemon(result_storage_pathname or target_path)
            stop_symex(self.symex_handle)
            self.symex_handle = None
            reporter.stop()
            fuzzer.stop()
            if self.db_backup_manager is not None:
                self.db_backup_manager.cleanup_backup()
                self.db_backup_manager = None
            if self.kill:
                exit(199)
        return start_results

    def _get_coverage_group_key(self) -> str:
        appdir = self.jconfig.get("appdir") or self.jconfig.get("app_dir") or self.jconfig.get("app_root") or self.appdir or "/app"
        parts = [p for p in str(appdir).replace("\\", "/").split("/") if p]
        names = parts if parts else []
        first = names[0] if len(names) > 0 else "root"
        second = names[1] if len(names) > 1 else "root"
        return f"+{first}+{second}"

    def _find_global_coverage_file(self) -> str:
        group_key = self._get_coverage_group_key()
        p1 = f"/dev/shm/coverages/{group_key}/{group_key}.cc.json"
        p2 = f"/tmp/coverages/{group_key}/{group_key}.cc.json"
        if os.path.isfile(p1):
            return p1
        if os.path.isfile(p2):
            return p2
        return p1

    def _start_coverage_daemon(self) -> None:
        if self.coverage_daemon_proc and self.coverage_daemon_proc.poll() is None:
            return
        symex_root = pathlib.Path(__file__).resolve().parents[1] / "symex"
        daemon_main = symex_root / "tools" / "coverage_daemon.py"
        if not daemon_main.exists():
            return
        runtime_meta_dir = os.path.join(self.work_dir, "symex_runtime", "meta")
        os.makedirs(runtime_meta_dir, exist_ok=True)
        self.coverage_daemon_log_fp = None
        cmd = [
            sys.executable,
            str(daemon_main),
            "--config",
            str(self.config_loc),
            "--log_dir",
            str(runtime_meta_dir),
        ]
        env = os.environ.copy()
        env["WITCHER_SYMEX_META_DIR"] = str(runtime_meta_dir)
        try:
            self.coverage_daemon_proc = subprocess.Popen(
                cmd,
                cwd=str(symex_root),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                close_fds=True,
                start_new_session=(os.name != "nt"),
            )
            print(f"[WC] Starting coverage daemon: {' '.join(cmd)}")
        except Exception as e:
            print(f"[WC] Failed to start coverage daemon: {e}")
            self.coverage_daemon_proc = None

    def _snapshot_and_stop_coverage_daemon(self, tag: str) -> None:
        src = self._find_global_coverage_file()
        runtime_meta_dir = os.path.join(self.work_dir, "symex_runtime", "meta")
        os.makedirs(runtime_meta_dir, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(tag or "target"))[:160]
        dst_dir = os.path.join(self.work_dir, "coverage_snapshots")
        os.makedirs(dst_dir, exist_ok=True)
        dst = os.path.join(dst_dir, f"coverage_{safe}_{int(time.time())}.cc.json")
        if os.path.isfile(src):
            try:
                shutil.copy2(src, dst)
                print(f"[WC] Saved coverage snapshot: {dst}")
            except Exception as e:
                print(f"[WC] Failed to save coverage snapshot from {src}: {e}")
        else:
            print(f"[WC] No global coverage file found at {src}")

        proc = self.coverage_daemon_proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except Exception:
                    pass
        self.coverage_daemon_proc = None
        try:
            if self.coverage_daemon_log_fp:
                self.coverage_daemon_log_fp.close()
        except Exception:
            pass
        self.coverage_daemon_log_fp = None


    def results_target_dir(self, trial_index, target_path):
        encoded_path = target_path.replace(self.appdir + '/', '').replace('/', '+')
        targets_dir = f"tr{trial_index}_{encoded_path}"
        results_dir = os.path.join(self.report_dir, targets_dir)
        return results_dir

    def fix_perms_in_dir(self, tdir):
        if not os.path.exists(tdir):
            print(f"Target dir {tdir} does not exist.")
            return

        # this is only a problem for qemu-user targets running in a docker container
        if self.container_info:
            perm_id = pwd.getpwuid( os.getuid() ).pw_uid

            perm_cmd = f"cd {tdir}/.. && /bin/chown {perm_id}:{perm_id} -R . && find . -type d -exec chmod +rx {{}} \; " \
                       f"&& find . -type f -exec chmod +r {{}} \;"

            volume = f"{tdir}:{tdir}"
            perm_cmd = ["docker", "run", "--rm", "-v", volume, "ubuntu:20.04", "/bin/bash", "-c", perm_cmd]

            subprocess.check_output(perm_cmd)


    # it uses this method b/c with qemu-user running as root, AFL creates unreadble file permissions
    def docker_copy(self, from_dir, to_dir):
        if not os.path.exists(from_dir):
            print(f"From dir {from_dir} does not exist, cannot copy.")
            return

        os.makedirs(to_dir, exist_ok=True)

        from_volume = f"{from_dir}:/from"
        to_volume = f"{to_dir}:/to"
        cp_cmd = ["docker", "run", "--rm", "-v", from_volume,"-v", to_volume, "ubuntu:20.04",
                  "/bin/cp", "-a", "/from/.", "/to"]

        subprocess.check_output(cp_cmd)

        # just in case a rouge file gets created between last permission set and the copy, make sure all the files in
        # in the to directory have acceptable permissions
        self.fix_perms_in_dir(to_dir)

    def copy_fuzzer_output_to_results(self, trial_index, target_path):
        if self.container_info:
            self.fix_perms_in_dir(self.work_dir)

        dst = self.results_target_dir(trial_index, target_path)

        print(f"Copy from {self.work_dir} to dst={dst}")

        if os.path.exists(dst):
            shutil.rmtree(dst)

        if self.container_info:
            self.docker_copy(self.work_dir, dst)
        else:
            try:
                shutil.copytree(self.work_dir, dst)
            except Exception as first_err:
                print(f"\033[33mWarning first copy from {self.work_dir} to {dst} failed: {first_err!r}\033[0m")
                time.sleep(10)
                if os.path.exists(dst):
                    try:
                        shutil.rmtree(dst)
                    except Exception as cleanup_err:
                        print(f"\033[33mWarning couldn't remove partial results at {dst}: {cleanup_err!r}\033[0m")
                try:
                    shutil.copytree(self.work_dir, dst)
                except Exception as second_err:
                    print(
                        f"\033[31mError couldn't copy results from {self.work_dir} to {dst}. "
                        f"first_error={first_err!r}; retry_error={second_err!r}\033[0m\n"
                    )

    def copy_fuzzer_results_to_output(self, trial_index, target_path):

        src = self.results_target_dir(trial_index, target_path)
        print(f"Copy from src-{src} to {Witcher.WORKING_DIR}")
        if os.path.exists(Witcher.WORKING_DIR):
            shutil.rmtree(Witcher.WORKING_DIR)
        shutil.copytree(src, Witcher.WORKING_DIR)

    def build_methd_map(self, methods):
        tot = sum(methods.values())
        outlist = []

        for k, v in sorted(methods.items(), key=lambda item:item[1]):
            cnt = max(int(round(v / tot * 16)), 1)
            for _ in range(0, cnt):
                outlist.append(k)

        if len(outlist) < 16:
            outlist = outlist[:16 - len(outlist)]

        outlist = outlist[:-1] if len(outlist) > 16 else outlist

        return ",".join(outlist)

    def target_contains_skiplist_value(self, target_path):
        for skipper in self.jconfig["script_skip_list"]:
            if target_path.find(skipper) > -1:
                return True
        return False

    def change_url_to_target(self, target):
        url = urlparse(target)
        netloc = url.netloc

        if ":" in netloc:
            netloc = netloc[0: netloc.find(":")]
        netloc = f"{netloc}:@@PORT_INCREMENT@@"
        url = url._replace(netloc=netloc)
        strurl=urlunparse(url)
        out_opts = []

        for cmdopt in self.binary_options:
            out_opts.append(cmdopt.replace("@@url@@", strurl))
        return out_opts


    def create_war_filter(self):
        if self.war_path:
            filelist = subprocess.check_output(["jar","-tf",self.war_path])
            filelist = filelist.decode().split("\n")
            print(filelist)
            with open("/dev/shm/javafilters.dat", "w") as jfilters:
                for f in filelist:
                    if f.endswith(".class"):
                        classfn = f.replace("WEB-INF/", "").replace("classes/","").replace("/",".").replace(".class","")
                        jfilters.write(classfn + "\n")
                        print(classfn)
                    if f.endswith(".jsp"):
                        jspclassfn = f.replace(".jsp","_jsp").replace("/",".")
                        jspclassfn = f"org.apache.jsp.{jspclassfn}"
                        jfilters.write(jspclassfn + "\n")
                        print(jspclassfn)
        # for dirpath in glob.iglob(os.path.join(TOMCAT_PATH, "webapps")):
        #     with open("/dev/shm/javafilters.dat", "w") as jfilters:
        #         if os.path.isdir(dirpath):
        #             appdirname = os.path.basename(dirpath)
        #             classpath = os.path.join(dirpath, "WEB-INF", "classes")
        #             for webfile in glob.iglob(classpath + "/*.class", recursive=True):
        #                 if os.path.isfile(webfile):
        #                     class_fn = webfile.replace(classpath, "")
        #                     class_fn = class_fn.replace(".class","")
        #                     class_fn = class_fn.replace("/",".")
        #                     jfilters.write(class_fn + "\n")
        #                     print(class_fn)
        #             workpath = os.path.join(TOMCAT_PATH, "work","Catalina","localhost", appdirname)
        #             for webfile in glob.iglob(workpath + "/*.class", recursive=True):
        #                 if os.path.isfile(webfile):
        #                     class_fn = webfile.replace(classpath, "")
        #                     class_fn = class_fn.replace(".class", "")
        #                     class_fn = class_fn.replace("/", ".")
        #                     print(class_fn)
        #                     jfilters.write(class_fn + "\n")

    def save_crashing_seed(self, seedpath: str, url_path: str, seed_kind: str = "bad-seed") -> None:
        """
        Saves a seed that AFL reported as crashing

        """
        seed_kind = str(seed_kind or "bad-seed").strip() or "bad-seed"
        save_key = f"{seed_kind}:{seedpath}{url_path}"
        if save_key in self.saved_seeds:
            print(f"{WITCH_GO} Not saving for {url_path} {seedpath}")
            return

        encoded_url_path = url_path.replace(self.appdir + '/', '').replace('/', '+')

        crash_file_dpath = os.path.join(self.report_dir, 'seed-crashes', seed_kind)
        os.makedirs(crash_file_dpath, exist_ok=True)

        fid = len(glob.glob(os.path.join(crash_file_dpath, "id:*")))

        crash_fname = os.path.join(crash_file_dpath, f"id:{fid:06},{encoded_url_path},src:{os.path.basename(seedpath)},crash")
        crash_fname = os.path.realpath(crash_fname)
        print(f"[Witcher] Saved potential crashing input seed at {os.path.basename(crash_fname)}")
        shutil.copyfile(seedpath, crash_fname)
        self.saved_seeds.add(save_key)

        fuzz_scr_fpath = os.path.join(self.work_dir, "fuzz-0.sh")
        with open(fuzz_scr_fpath, "r") as rf:
            scr = rf.read()

        cat_str = f'cat "$SCRIPT_DIR/{os.path.basename(crash_fname)}"'

        out_scr = ""
        for line in scr.split("\n"):
            if line.find("afl-fuzz") > -1:
                out_scr += """SCRIPT_DIR="$(cd "$(dirname $0)" > /dev/null && pwd)" \n"""
                args = line.split(" ")

                out_args = [f"{os.path.dirname(args[0])}/afl-showmap", "-o", f"/tmp/map-{os.path.basename(seedpath)}"]
                argindex = 1
                while argindex < len(args):
                    arg = args[argindex]
                    if arg == "-i" or arg == "-o" or arg == "-x" or arg == "-M":
                        argindex += 2
                    else:
                        out_args.append(arg)
                        argindex += 1
                out_scr += cat_str + " | " + " ".join(out_args) + "\n"

            else:
                out_scr += line + "\n"

        exec_fpath = f"{crash_fname}.sh"
        with open(exec_fpath, "w") as wf:
            wf.write(out_scr)

        os.chmod(exec_fpath, stat.S_IRWXU | stat.S_IRWXG | stat.S_IWOTH | stat.S_IROTH)

    def harvest_afl_crashes(self, url_path: str) -> None:
        encoded_url_path = url_path.replace(self.appdir + '/', '').replace('/', '+')
        crash_file_dpath = os.path.join(self.report_dir, 'seed-crashes')
        os.makedirs(crash_file_dpath, exist_ok=True)
        for fuzzer_dir in os.listdir(self.work_dir):
            cdir = os.path.join(self.work_dir, fuzzer_dir, 'crashes')
            if not os.path.isdir(cdir):
                continue
            for src in glob.glob(os.path.join(cdir, 'id:*')):
                if src+url_path in self.saved_seeds:
                    continue
                fid = len(glob.glob(os.path.join(crash_file_dpath, "id:*")))
                src_label = f"{fuzzer_dir}__{os.path.basename(src)}"
                dst = os.path.join(crash_file_dpath, f"id:{fid:06},{encoded_url_path},src:{src_label},crash")
                dst = os.path.realpath(dst)
                shutil.copyfile(src, dst)
                fuzz_scr_fpath = os.path.join(self.work_dir, "fuzz-0.sh")
                with open(fuzz_scr_fpath, "r") as rf:
                    scr = rf.read()
                cat_str = f'cat "$SCRIPT_DIR/{os.path.basename(dst)}"'
                out_scr = ""
                for line in scr.split("\n"):
                    if line.find("afl-fuzz") > -1:
                        out_scr += """SCRIPT_DIR="$(cd "$(dirname $0)" > /dev/null && pwd)" \n"""
                        args = line.split(" ")
                        out_args = [f"{os.path.dirname(args[0])}/afl-showmap", "-o", f"/tmp/map-{os.path.basename(src)}"]
                        argindex = 1
                        while argindex < len(args):
                            arg = args[argindex]
                            if arg == "-i" or arg == "-o" or arg == "-x" or arg == "-M":
                                argindex += 2
                            else:
                                out_args.append(arg)
                                argindex += 1
                        out_scr += cat_str + " | " + " ".join(out_args) + "\n"
                    else:
                        out_scr += line + "\n"
                exec_fpath = f"{dst}.sh"
                with open(exec_fpath, "w") as wf:
                    wf.write(out_scr)
                os.chmod(exec_fpath, stat.S_IRWXU | stat.S_IRWXG | stat.S_IWOTH | stat.S_IROTH)
                self.saved_seeds.add(src+url_path)


    def start_fuzz_campaign(self):
        _environ_backup = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update(self.env)

            nbr_trials = int(self.jconfig.get("number_of_trials", "1"))
            nbr_refuzzes = int(self.jconfig.get("number_of_refuzzes", "1"))

            for trial_index in range(0, nbr_trials):
                self.init_shared_memory()
                # Keep monotonic global timer from Witcher startup; do not reset per trial.

                print(f"TRIAL INDEX = {trial_index}")
                self.init_fuzz_campaign_status(trial_index)
                trial = self.fuzz_campaign_status[trial_index]
                expanded_targets = self._split_targets_by_initial_seeds(trial["targets"])
                if expanded_targets is not trial["targets"]:
                    trial["targets"] = expanded_targets
                    self.save_campaign_status()
                targets = trial["targets"].copy()
                print(f"Trial start = {trial['trial_start']}")

                valid_targets = []
                t_start = self.jconfig.get("script_start_index", 0)
                t_end = self.jconfig.get("script_end_index", len(targets))
                for t in targets[t_start:t_end]:
                    if self.single_target and t['target_path'].find(self.single_target) == -1:
                        continue
                    if self.target_contains_skiplist_value(t['target_path']):
                        continue
                    valid_targets.append(t)
                try:
                    timeout_per_target = float(self.timeout or 0.0)
                except Exception:
                    timeout_per_target = 0.0
                self.global_timeout = int(max(0.0, timeout_per_target) * float(len(valid_targets)))
                if self.global_timeout > 0:
                    self.time_pool = 0.0

                    loaded = self._load_time_allocations(trial_index, nbr_refuzzes=nbr_refuzzes)
                    if loaded:
                        alloc_map = {x.get("target_path"): x for x in loaded if isinstance(x, dict) and x.get("target_path")}
                        missing = False
                        for t in valid_targets:
                            tp = t.get("target_path")
                            if not tp or tp not in alloc_map:
                                missing = True
                                break
                        if not missing:
                            for t in valid_targets:
                                tp = t.get("target_path")
                                ent = alloc_map.get(tp) or {}
                                t["_allocated_time"] = float(ent.get("_allocated_time") or 0.0)
                                if "_seed_count" in ent:
                                    t["_seed_count"] = int(ent.get("_seed_count") or 0)
                                if "_effective_seed_count" in ent:
                                    t["_effective_seed_count"] = int(ent.get("_effective_seed_count") or int(t.get("_seed_count") or 0))
                                if "_weak_seed_count" in ent:
                                    t["_weak_seed_count"] = int(ent.get("_weak_seed_count") or 0)
                                if "_budget_total" in ent:
                                    t["_budget_total"] = float(ent.get("_budget_total") or float(t.get("_allocated_time") or 0.0))
                                if "_used_time" in ent:
                                    t["_used_time"] = float(ent.get("_used_time") or 0.0)
                                if "_completed" in ent:
                                    t["_completed"] = bool(ent.get("_completed") or False)
                            print(f"[*] Loaded time allocations from {self._time_allocations_path(trial_index)} ({len(valid_targets)} targets)")
                        else:
                            loaded = None

                    if not loaded:
                        for t in valid_targets:
                            t['_seed_count'] = len(self._get_target_initial_seeds(t))
                        
                        valid_targets.sort(key=lambda x: x['_seed_count'])
                        
                        total_seeds = sum(t['_seed_count'] for t in valid_targets)
                        effective_global_timeout = self.global_timeout
                        if total_seeds == 0:
                            total_seeds = max(1, len(valid_targets))
                            for t in valid_targets:
                                t['_allocated_time'] = effective_global_timeout / total_seeds
                        else:
                            for t in valid_targets:
                                t['_allocated_time'] = (t['_seed_count'] / total_seeds) * effective_global_timeout
                        
                        min_fuzz_time = int(self.jconfig.get("global_min_fuzz_time", 300))
                        if min_fuzz_time > 0 and len(valid_targets) > 0:
                            budget = float(effective_global_timeout)
                            min_total = float(min_fuzz_time) * float(len(valid_targets))
                            if budget < min_total:
                                effective_min = budget / float(len(valid_targets))
                                print(f"[*] global_timeout too small for {min_fuzz_time}s minimum per target ({len(valid_targets)} targets, budget={budget:.0f}s). Using {effective_min:.0f}s minimum instead.")
                                for t in valid_targets:
                                    t['_allocated_time'] = effective_min
                            else:
                                deficit = 0.0
                                for t in valid_targets:
                                    cur = float(t.get('_allocated_time') or 0.0)
                                    if cur < float(min_fuzz_time):
                                        deficit += float(min_fuzz_time) - cur
                                        t['_allocated_time'] = float(min_fuzz_time)
                                    else:
                                        t['_allocated_time'] = cur
                                
                                if deficit > 0.0:
                                    donors = [t for t in valid_targets if float(t.get('_allocated_time') or 0.0) > float(min_fuzz_time)]
                                    total_slack = 0.0
                                    for t in donors:
                                        total_slack += float(t['_allocated_time']) - float(min_fuzz_time)
                                    remaining = deficit
                                    if total_slack > 0.0:
                                        for idx, t in enumerate(donors):
                                            slack = float(t['_allocated_time']) - float(min_fuzz_time)
                                            if slack <= 0.0:
                                                continue
                                            if idx == len(donors) - 1:
                                                cut = remaining
                                            else:
                                                cut = deficit * (slack / total_slack)
                                            if cut > remaining:
                                                cut = remaining
                                            max_cut = float(t['_allocated_time']) - float(min_fuzz_time)
                                            if cut > max_cut:
                                                cut = max_cut
                                            if cut > 0.0:
                                                t['_allocated_time'] = float(t['_allocated_time']) - cut
                                                remaining -= cut
                                            if remaining <= 0.0:
                                                break
                                    if remaining > 0.0:
                                        print(f"[*] global_min_fuzz_time redistribution left {remaining:.0f}s unmet; keeping total budget consistent.")

                        self._save_time_allocations(trial_index, valid_targets, nbr_refuzzes=nbr_refuzzes)
                    
                    targets = valid_targets
                    for t in targets:
                        if "_budget_total" not in t:
                            try:
                                t["_budget_total"] = float(t.get("_allocated_time") or 0.0)
                            except Exception:
                                t["_budget_total"] = 0.0
                        if "_used_time" not in t:
                            t["_used_time"] = 0.0
                        if "_completed" not in t:
                            t["_completed"] = bool(
                                int(t.get("last_completed_trial") or -1) == int(trial_index)
                                and int(t.get("last_completed_refuzz") or -1) >= 0
                            )
                    # Always start by largest timeout first (loaded or freshly computed).
                    targets.sort(key=lambda x: float(x.get("_allocated_time") or 0.0), reverse=True)
                    self.jconfig["script_start_index"] = 0
                    self.jconfig["script_end_index"] = len(targets)
                    if self.jconfig.get("script_random_order"):
                        print("[*] global_timeout is set, disabling script_random_order to prioritize fewer seeds first.")
                        self.jconfig["script_random_order"] = 0

                if self.jconfig.get("script_random_order") == 1:
                    random.shuffle(targets)

                self.start_external_servers()

                for refuzz_index in range(0, nbr_refuzzes):
                    if self.jconfig["script_random_order"] == 2:
                        random.shuffle(targets)
                    target_start = self.jconfig.get("script_start_index", 0)
                    target_end = self.jconfig.get("script_end_index", len(targets))

                    sliced_targets = targets[target_start: target_end]
                    for i, target in enumerate(sliced_targets):
                        self.is_last_target = (i == len(sliced_targets) - 1)
                        if self.global_timeout > 0:
                            try:
                                budget_total = float(target.get("_budget_total") or 0.0)
                            except Exception:
                                budget_total = 0.0
                            try:
                                used_so_far = float(target.get("_used_time") or 0.0)
                            except Exception:
                                used_so_far = 0.0
                            remaining_total = float(budget_total) - float(used_so_far)
                            # Clamp by global wall-clock remaining budget.
                            remaining_total = min(float(remaining_total), float(self._remaining_global_timeout_seconds()))
                            if remaining_total <= 0.0:
                                print(f"Skipping {target.get('target_path')} b/c no remaining budget: {budget_total:.0f}-{used_so_far:.0f}=0")
                                continue
                            self.current_allocated_time = remaining_total
                        else:
                            self.current_allocated_time = target.get('_allocated_time')
                        if "last_completed_trial" not in target:
                            target["last_completed_trial"] = -1
                        if "last_completed_refuzz" not in target:
                            target["last_completed_refuzz"] = -1

                        if self.single_target and target['target_path'].find(self.single_target) == -1: # if using single target and not in target name then skip
                            continue
                        if self.target_contains_skiplist_value(target['target_path']):
                            print("SKIPPING B/C in SKIPLIST")
                            continue
                        if trial_index < target["last_completed_trial"] or (trial_index == target["last_completed_trial"] and refuzz_index <= target["last_completed_refuzz"] ):
                            print(f"Skipping {target['target_path']} Trial={trial_index}, Refuzz={refuzz_index} last_completed_refuzz={target['last_completed_refuzz']}")
                            continue

                        regex = re.compile(r"(?P<prefix>http://)([0-9\.]+)(?P<postfix>.*)")

                        logical_target_path = target['target_path']
                        runtime_target_path = target.get("_real_target_path") or logical_target_path
                        target_url = runtime_target_path
                        result_storage_pathname = logical_target_path

                        do_resume = refuzz_index > 0

                        # if soapaction, then go to url of first request if exists else default

                        if target['is_soapaction']:
                            if len(target['requests']) > 0 :
                                req0 = target['requests'][0]

                                trequest = self.request_data['requestsFound'][req0]
                                target_url = trequest["_url"]
                                soap_urlstr = None
                                if "soapaction" in trequest["_headers"]:
                                    soap_urlstr = trequest["_headers"]["soapaction"]
                                elif "SOAPACTION" in trequest["_headers"]:
                                    soap_urlstr = trequest["_headers"]["SOAPACTION"]

                                if soap_urlstr:
                                    soap_urlstr = soap_urlstr.replace('"', "")
                                    if not target.get("_split_source_target_path"):
                                        result_storage_pathname = urlparse(soap_urlstr).path
                            else:
                                target_url = "http://127.0.0.1/HNAP1"

                        urlmatch = regex.match(target_url)
                        if urlmatch:
                            if self.container_info:
                                target_url = regex.sub(r'\g<prefix>127.0.0.1\g<postfix>', target_url)
                            if not target["is_soapaction"] and not target.get("_split_source_target_path"):
                                result_storage_pathname = urlparse(target_url).path

                        print(f"FUZZING \033[33m{target['target_path']}\033[0m Trial={trial_index}, Refuzz={refuzz_index} last_completed_refuzz={target['last_completed_refuzz']} result_path={result_storage_pathname}")

                        if do_resume:
                            self.copy_fuzzer_results_to_output(trial_index, result_storage_pathname)

                        seeds = self._get_target_initial_seeds(target)
                        dictionary_str = self.create_dictionary(target)

                        method_map = self.build_methd_map(target["methods"])
                        #start_results = self.start_fuzzer(do_resume, target_url, method_map, dictionary_str, seeds)
                        #mod
                        retry_budget_left = None
                        if self.global_timeout > 0:
                            try:
                                retry_budget_left = max(0.0, float(self.current_allocated_time or 0.0))
                            except Exception:
                                retry_budget_left = None
                        total_fuzz_used = 0.0
                        observed_weak_seed_count = 0
                        weak_rebalance_state = {"done": False}

                        def _weak_rebalance_once(weak_cnt: int):
                            nonlocal retry_budget_left, observed_weak_seed_count
                            try:
                                observed_weak_seed_count = max(int(observed_weak_seed_count), int(weak_cnt or 0))
                            except Exception:
                                pass
                            if self.global_timeout <= 0 or weak_rebalance_state.get("done"):
                                return None
                            if int(observed_weak_seed_count) <= 1:
                                return None
                            new_alloc = self._rebalance_remaining_allocations(
                                targets=sliced_targets,
                                current_index=i,
                                current_weak_seed_count=int(observed_weak_seed_count),
                                trial_index=trial_index,
                                nbr_refuzzes=nbr_refuzzes,
                            )
                            if new_alloc > 0.0:
                                retry_budget_left = float(new_alloc)
                                self.current_allocated_time = float(new_alloc)
                                weak_rebalance_state["done"] = True
                                print(
                                    f"[*] Rebalanced by weak seeds for {target.get('target_path')}: "
                                    f"weak={observed_weak_seed_count}, new_timeout={new_alloc:.0f}s; "
                                    f"remaining targets now run large->small."
                                )
                                return float(new_alloc)
                            return None

                        start_results = self.start_fuzzer(
                            do_resume, target_url, method_map, dictionary_str, seeds, target["requests"],
                            result_storage_pathname=result_storage_pathname, budget_target=target,
                            attempt_timeout_cap=retry_budget_left,
                            weak_rebalance_fn=_weak_rebalance_once,
                        )
                        try:
                            total_fuzz_used += max(0.0, float(start_results.get("run_time_seconds") or 0.0))
                        except Exception:
                            pass
                        #return {"successcnt":success, "totalcnt":totallogs, "testfailed":testfailed, "failedseeds": failedseeds}
                        # if startup fails (in other words there's more fuzzers that failed to come up than successful ones.

                        while len(seeds) > 0 and (start_results.get("totalfail", True)):
                            if self.global_timeout > 0 and retry_budget_left is not None:
                                try:
                                    retry_budget_left = max(0.0, float(retry_budget_left) - float(start_results.get("run_time_seconds") or 0.0))
                                except Exception:
                                    pass
                                if retry_budget_left <= 0.0:
                                    print(f"\033[36mNo remaining timeout budget for retry of {target['target_path']}; stop retrying.\033[0m")
                                    break
                            failed_seeds = start_results.get("failedseeds", [])
                            weak_seeds = start_results.get("weakseeds", [])
                            try:
                                observed_weak_seed_count = max(int(observed_weak_seed_count), len(weak_seeds or []))
                            except Exception:
                                pass
                            # Rebalance once using (seed_count - weak_seed_count) for current target.
                            if self.global_timeout > 0 and (not weak_rebalance_state.get("done")) and int(observed_weak_seed_count) > 1:
                                _weak_rebalance_once(int(observed_weak_seed_count))
                            print(f"Startup info {start_results} {weak_seeds} {failed_seeds}")
                            if failed_seeds or weak_seeds:
                                print(f"{WITCH_FAIL} {len(failed_seeds)} seeds caused a failure and {len(weak_seeds)} resulted in known execution path ")
                                seeds_to_scan = set(failed_seeds or []) | set(weak_seeds or [])
                                for fn in seeds_to_scan:
                                    seedpath = f"{self.work_dir}/initial_seeds/{fn}"

                                    if os.path.exists(seedpath):
                                        seed_kind = "weak-seed" if fn in set(weak_seeds or []) else "bad-seed"
                                        self.save_crashing_seed(seedpath, result_storage_pathname, seed_kind)

                                        with open(seedpath,"rb") as rf:
                                            filedata = rf.read()
                                        rep_regex = rb"[\x01-\x19'\x7f-\xff]"

                                        if re.match(rep_regex, filedata):
                                            print(f"[Witcher] seed has odd characters, replacing with all with 'a'")
                                            filedata = re.sub(rep_regex, repl=b"a", string=filedata)
                                            with open(seedpath, "wb") as wf:
                                                wf.write(filedata)
                                        else:
                                            print(f"[Witcher] No odd characters, deleting seed")
                                            os.remove(seedpath)
                                seeds = []
                                for fn in glob.iglob(f"{self.work_dir}/initial_seeds/*"):
                                    with open(fn,"rb") as rf:
                                        seeds.append(rf.read())
                            else:
                                print("\033[36mCould not find any failed or weak seeds, so removing last seed")
                                seeds.remove(seeds[len(seeds)-1])

                            print(f"\033[33mAttempting to fuzz again {target['target_path']}\033[0m with {len(seeds)} seeds and {start_results}")
                            #start_results = self.start_fuzzer(do_resume, target_url, method_map, dictionary_str, seeds)
                            start_results = self.start_fuzzer(
                                do_resume, target_url, method_map, dictionary_str, seeds, target["requests"],
                                result_storage_pathname=result_storage_pathname, budget_target=target,
                                attempt_timeout_cap=retry_budget_left
                            )
                            try:
                                total_fuzz_used += max(0.0, float(start_results.get("run_time_seconds") or 0.0))
                            except Exception:
                                pass

                        if start_results.get("totalfail", True):
                            print(f"EXITING while but total fail still True with {start_results}")

                        if self.global_timeout > 0:
                            target["_used_time"] = float(target.get("_used_time") or 0.0) + float(total_fuzz_used or 0.0)
                            target["_weak_seed_count"] = int(observed_weak_seed_count or 0)
                            target["_effective_seed_count"] = max(1, int(target.get("_seed_count") or 0) - int(observed_weak_seed_count or 0))

                        if start_results.get("timeout", False):
                            target["last_completed_trial"] = trial_index
                            target["last_completed_refuzz"] = refuzz_index
                            target["_completed"] = True
                        else:
                            target["_completed"] = True
                            print(f"\033[31mFailed to FUZZ {target['target_path']}\033[0m")

                        #os.system(f"sudo chown etrickel:etrickel {self.work_dir}/. -R")

                        xss_t0 = time.monotonic()
                        try:
                            run_xss_flow(
                                self.work_dir,
                                output_dir_name="xss_queue",
                                result_storage_pathname=result_storage_pathname,
                                appdir=self.appdir,
                                config_path=self.config_loc,
                            )
                        finally:
                            if self.global_timeout > 0:
                                try:
                                    xss_used = float(time.monotonic() - xss_t0)
                                except Exception:
                                    xss_used = 0.0
                                target["_used_time"] = float(target.get("_used_time") or 0.0) + xss_used
                                # Persist live allocation/runtime/completion state after each target.
                                self._save_time_allocations(trial_index, targets, nbr_refuzzes=nbr_refuzzes)

                        self.copy_fuzzer_output_to_results(trial_index, result_storage_pathname)
                        # Coverage merge entry disabled (keep implementation for later restore).
                        # try:
                        #     merger_script = os.path.normpath(
                        #         os.path.join(os.path.dirname(__file__), "..", "symex", "tools", "coverage_results_merger.py")
                        #     )
                        #     if os.path.isfile(merger_script):
                        #         subprocess.run(
                        #             [sys.executable, merger_script, self.report_dir],
                        #             stdout=subprocess.DEVNULL,
                        #             stderr=subprocess.DEVNULL,
                        #             check=False,
                        #         )
                        # except Exception:
                        #     pass
                        self.save_campaign_status()
                        sys.stdout.flush()
                        time.sleep(1)
                        self.kill_servers()
                        print("Sleeping a few and then will start up external servers ")
                        time.sleep(10)

                        self.fix_perms_in_dir(self.work_dir) # extra precaution for perms, I'm tired of these exceptions coming at the end of the loop!

                        self.start_external_servers()
                self.kill_servers()

        except Exception as exp:
            import traceback
            traceback.print_exc()

        finally:
            self.kill_servers()
            os.environ.clear()
            os.environ.update(_environ_backup)
            # kill supervisor to shutdown container, if its parent is supervisord (pid == 1)
            if os.getppid() == 1:
                try:
                    os.kill(1, signal.SIGQUIT)
                except Exception as e:
                    print('Could not kill supervisor: ' + e + '\n')
