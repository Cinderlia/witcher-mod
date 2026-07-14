
from queue import Queue, Empty
from threading import Thread
from .afl import AFL
import archr
import json
import os
import re
import subprocess
import shutil
import time
import stat
import glob
import logging
import urllib.request
import http.cookiejar
#import ipdb

from ctypes import c_bool
from multiprocessing import Process, Value

l = logging.getLogger("phuzzer.phuzzers.wafl")
l.setLevel(logging.INFO)

class WitcherAFL(AFL):
    """ WitcherAFL launches the web fuzzer building on the AFL object """

    def __init__(
        self, target, seeds=None, dictionary=None, create_dictionary=None,
        work_dir=None, resume=False,
        afl_count=1, memory="8G", timeout=None,
        target_opts=None, extra_opts=None,
        crash_mode=False, use_qemu=True,
        run_timeout=None, login_json_fn="",
        server_cmd=None, server_env_vars=None,
        base_port=None, container_info=None, fault_escalation=True,
        pre_instance_callback=None,
    ):
        """
        :param target: path to the script to fuzz (from AFL)
        :param seeds: list of inputs to seed fuzzing with (from AFL)
        :param dictionary: a list of bytes objects to seed the dictionary with (from AFL)
        :param create_dictionary: create a dictionary from the string references in the binary (from AFL)
        :param work_dir: the work directory which contains fuzzing jobs, our job directory will go here (from AFL)

        :param resume: resume the prior run, if possible (from AFL)
        :param afl_count:

        :param memory: AFL child process memory limit (default: "8G")
        :param afl_count: number of AFL jobs total to spin up for the binary
        :param timeout: timeout for individual runs within AFL

        :param library_path: library path to use, if none is specified a default is chosen
        :param target_opts: extra options to pass to the target
        :param extra_opts: extra options to pass to AFL when starting up

        :param crash_mode: if set to True AFL is set to crash explorer mode, and seed will be expected to be a crashing input
        :param use_qemu: Utilize QEMU for instrumentation of binary.

        :param run_timeout: amount of time for AFL to wait for a single execution to finish
        :param login_json_fn: login configuration file path for automatically craeting a login session and performing other initial tasks

        """

        self.container_info = None

        if container_info:
            self.container_info = container_info
            self.afl_path = os.path.join("/afl", "afl-fuzz")

        elif "AFL_PATH" in os.environ:
            afl_fuzz_bin = os.path.join(os.environ['AFL_PATH'], "afl-fuzz")
            if os.path.exists(afl_fuzz_bin):
                self.afl_path = afl_fuzz_bin
            else:
                raise ValueError(
                    f"error, have AFL_PATH but cannot find afl-fuzz at {os.environ['AFL_PATH']} with {afl_fuzz_bin}")

        super().__init__(
            target=target, work_dir=work_dir, seeds=seeds, afl_count=afl_count,
            create_dictionary=create_dictionary, timeout=timeout,
            memory=memory, dictionary=dictionary, use_qemu=use_qemu,
            target_opts=target_opts, resume=resume, crash_mode=crash_mode, extra_opts=extra_opts,
            run_timeout=run_timeout, container_info=container_info
        )

        self.login_json_fn = login_json_fn

        self.used_sessions = set()
        self.session_name = ""
        self.bearer = ""

        self.server_cmd = server_cmd
        self.server_env_vars = server_env_vars
        self.server_procs = []
        self.base_port = base_port if base_port is not None else os.environ.get("PORT",14000)
        self.pre_instance_callback = pre_instance_callback
        self.container_targets = []
        self.running_flag = Value(c_bool, True)
        self.relog = False
        print(f"\033[38;5;11mFAULT ESCALATION is {fault_escalation}")
        self.fault_escalation = fault_escalation
        if container_info:
            self.relog = True

    def _auth_snapshot_path(self):
        try:
            return os.path.join(self.work_dir, "symex_runtime", "meta", "auth_snapshot.json")
        except Exception:
            return ""

    def _seed_env_runtime_paths(self):
        root = os.path.join(self.work_dir, "seed_env_profiles")
        return {
            "root": root,
            "parent": os.path.join(root, "parent"),
            "child": os.path.join(root, "child"),
        }

    @staticmethod
    def _collect_seed_env_keys(env_obj):
        explicit = {
            "AUTHORIZATION",
            "CONTENT_LENGTH",
            "CONTENT_TYPE",
            "DOCUMENT_ROOT",
            "HTTP_AUTHORIZATION",
            "HTTPS",
            "LOGIN_COOKIE",
            "MANDATORY_COOKIE",
            "MANDATORY_GET",
            "MANDATORY_POST",
            "METHOD",
            "PATH_INFO",
            "PHP_ADMIN_VALUE",
            "PHP_VALUE",
            "QUERY_STRING",
            "REDIRECT_STATUS",
            "REQUEST_METHOD",
            "REQUEST_URI",
            "SCRIPT_FILENAME",
            "SCRIPT_NAME",
            "SERVER_NAME",
            "SERVER_PORT",
            "SERVER_PROTOCOL",
        }
        keys = []
        for key in sorted(env_obj.keys()):
            if key in explicit or key.startswith("HTTP_"):
                keys.append(str(key))
        return keys

    def _configure_seed_env_runtime(self, my_env):
        paths = self._seed_env_runtime_paths()
        os.makedirs(paths["parent"], exist_ok=True)
        os.makedirs(paths["child"], exist_ok=True)
        keys = self._collect_seed_env_keys(my_env)
        my_env["WC_ENV_PARENT_DIR"] = paths["parent"]
        my_env["WC_ENV_CHILD_DIR"] = paths["child"]
        my_env["WC_SEED_ENV_KEYS"] = ",".join(keys)
        os.environ["WC_ENV_PARENT_DIR"] = paths["parent"]
        os.environ["WC_ENV_CHILD_DIR"] = paths["child"]
        os.environ["WC_SEED_ENV_KEYS"] = my_env["WC_SEED_ENV_KEYS"]

    def _write_auth_snapshot(self, env_obj=None, *, source=""):
        path = self._auth_snapshot_path()
        if not path:
            return
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except Exception:
            return
        env_obj = env_obj if isinstance(env_obj, dict) else {}
        prev = {}
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8", errors="replace") as rf:
                    obj = json.load(rf)
                    if isinstance(obj, dict):
                        prev = obj
        except Exception:
            prev = {}

        payload = {
            "source": source or "",
            "updated_at": int(time.time()),
            "LOGIN_COOKIE": str(env_obj.get("LOGIN_COOKIE", "") or ""),
            "MANDATORY_COOKIE": str(env_obj.get("MANDATORY_COOKIE", "") or ""),
            "MANDATORY_GET": str(env_obj.get("MANDATORY_GET", "") or ""),
            "MANDATORY_POST": str(env_obj.get("MANDATORY_POST", "") or ""),
            "AUTHORIZATION": str(env_obj.get("AUTHORIZATION", "") or ""),
            "HTTP_AUTHORIZATION": str(env_obj.get("HTTP_AUTHORIZATION", "") or ""),
            "HTTP_HOST": str(env_obj.get("HTTP_HOST", "") or ""),
            "SERVER_NAME": str(env_obj.get("SERVER_NAME", "") or ""),
        }
        # Never let an empty update erase a previously captured auth value.
        for key in ("LOGIN_COOKIE", "MANDATORY_COOKIE", "MANDATORY_GET", "MANDATORY_POST", "AUTHORIZATION", "HTTP_AUTHORIZATION"):
            cur = str(payload.get(key, "") or "")
            if cur:
                continue
            old = str(prev.get(key, "") or "")
            if old:
                payload[key] = old
        try:
            with open(path, "w", encoding="utf-8") as wf:
                json.dump(payload, wf, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _login_debug_path(self):
        try:
            return os.path.join(self.work_dir, "login_debug.log")
        except Exception:
            return "/tmp/login_debug.log"

    @staticmethod
    def _login_debug_s(val, limit=4000):
        try:
            if isinstance(val, bytes):
                out = val.decode("latin-1", errors="replace")
            elif isinstance(val, str):
                out = val
            else:
                out = json.dumps(val, ensure_ascii=False)
        except Exception:
            try:
                out = str(val)
            except Exception:
                out = "<unprintable>"
        if out is None:
            out = ""
        if len(out) > int(limit):
            return out[: int(limit)] + f"\n...[truncated {len(out) - int(limit)} chars]"
        return out

    def _login_debug_write(self, stage, **fields):
        try:
            path = self._login_debug_path()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            ts = int(time.time())
            with open(path, "a", encoding="utf-8", errors="replace") as wf:
                wf.write(f"\n===== [{ts}] {stage} =====\n")
                for k, v in fields.items():
                    wf.write(f"{k}:\n{self._login_debug_s(v)}\n")
        except Exception:
            pass

    @staticmethod
    def _debug_env_subset(env_obj):
        env_obj = env_obj if isinstance(env_obj, dict) else {}
        keys = (
            "HTTP_HOST",
            "SERVER_NAME",
            "REQUEST_URI",
            "REQUEST_METHOD",
            "METHOD",
            "SCRIPT_FILENAME",
            "SCRIPT_NAME",
            "PATH_INFO",
            "DOCUMENT_ROOT",
            "REDIRECT_STATUS",
            "HTTP_REDIRECT_STATUS",
            "CONTENT_TYPE",
            "CONTENT_LENGTH",
            "QUERY_STRING",
            "LOGIN_COOKIE",
            "MANDATORY_COOKIE",
            "MANDATORY_GET",
            "MANDATORY_POST",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "STRICT",
            "WC_INSTRUMENTATION",
            "NO_WC_EXTRA",
            "AFL_PRELOAD",
            "DO_JSON",
            "WITCHER_PRINT_OP",
        )
        return {k: str(env_obj.get(k, "") or "") for k in keys}

    @staticmethod
    def _parse_cgi_response(text: str):
        """
        Parse php-cgi style stdout into (status_line, headers_list, body_text).
        We keep it tolerant because some apps omit an explicit Status line.
        """
        headers = []
        body_lines = []
        in_body = False
        status_line = ""
        for raw in (text or "").splitlines():
            line = raw.rstrip("\r\n")
            if not in_body and line.strip() == "":
                in_body = True
                continue
            if in_body:
                body_lines.append(raw)
                continue
            if ":" in line:
                hn, hv = line.split(":", 1)
                headers.append((hn.strip(), hv.strip()))
                if hn.strip().lower() == "status" and not status_line:
                    status_line = hv.strip()
        return status_line, headers, "\n".join(body_lines)

    def _cgi_followup_check(self, *, loginconfig: dict, cookie_value: str, script_filename: str, get_qs: str = ""):
        """
        Run a GET request via php-cgi to the given script using the provided cookie,
        and log the outcome. This helps verify whether login actually sticks.
        """
        try:
            cgi_bin = (loginconfig or {}).get("cgiBinary") or ""
            if not cgi_bin:
                return
            env = os.environ.copy()
            if "afl_preload" in loginconfig:
                env["LD_PRELOAD"] = loginconfig.get("afl_preload") or env.get("LD_PRELOAD", "")
            if "ld_library_path" in loginconfig:
                env["LD_LIBRARY_PATH"] = loginconfig.get("ld_library_path") or env.get("LD_LIBRARY_PATH", "")
            env["METHOD"] = "GET"
            if self.fault_escalation:
                env["STRICT"] = "3"
            elif "STRICT" in env:
                del env["STRICT"]
            env["SCRIPT_FILENAME"] = script_filename
            env["SCRIPT_NAME"] = script_filename
            if env["SCRIPT_NAME"].startswith("/app"):
                env["SCRIPT_NAME"] = env["SCRIPT_NAME"].replace("/app", "")
            if "PATH_INFO" not in env or not env.get("PATH_INFO"):
                env["PATH_INFO"] = "/"
            httpdata = f'{cookie_value}\x00{get_qs}\x00\x00'
            p = subprocess.Popen(
                [cgi_bin],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                env=env,
                close_fds=True,
            )
            stdout_b, stderr_b = p.communicate(input=httpdata.encode("utf-8", errors="replace"), timeout=6)
            stdout = stdout_b.decode("latin-1", errors="replace")
            stderr = stderr_b.decode("latin-1", errors="replace") if isinstance(stderr_b, (bytes, bytearray)) else str(stderr_b)
            status_line, headers, body = self._parse_cgi_response(stdout)
            loc = ""
            for hn, hv in headers:
                if (hn or "").strip().lower() == "location":
                    loc = hv
                    break
            # Print a larger body snippet to the debug file for manual inspection.
            self._login_debug_write(
                "post_login_followup",
                follow_script=script_filename,
                follow_get=get_qs,
                stdin_payload=httpdata,
                env_subset=self._debug_env_subset(env),
                status=status_line,
                location=loc,
                headers=headers,
                stderr=stderr,
                body_preview=self._login_debug_s(body, limit=20000),
            )
        except Exception as ex:
            self._login_debug_write("post_login_followup_error", error=str(ex), follow_script=script_filename, follow_get=get_qs)

    @staticmethod
    def _split_cgi_url(url_or_path):
        s = (url_or_path or "").strip()
        if not s:
            return "", ""
        if s.startswith("http://") or s.startswith("https://"):
            from urllib.parse import urlparse
            u = urlparse(s)
            return (u.path or ""), (u.query or "")
        if "?" in s:
            p, q = s.split("?", 1)
            return p.strip(), q.strip()
        return s, ""

    @staticmethod
    def _merge_query_strings(a, b):
        sa = (a or "").strip().lstrip("?")
        sb = (b or "").strip().lstrip("?")
        if sa and sb:
            return sa + "&" + sb
        return sa or sb

    @staticmethod
    def _cookie_name_value_only(cookie_value):
        s = (cookie_value or "").strip()
        if not s:
            return ""
        first = s.split(";", 1)[0].strip()
        if "=" not in first:
            return ""
        return first

    @classmethod
    def _normalize_set_cookie_values(cls, cookie_values):
        vals = []
        for raw in cookie_values or []:
            cv = cls._cookie_name_value_only(raw)
            if cv:
                vals.append(cv)
        return "; ".join(vals)

    @staticmethod
    def _cookie_map_from_cookie_header(cookie_header: str):
        """
        Parse a Cookie header string into {name: value}.
        Conservative: ignores common cookie attributes (path/expires/etc).
        """
        s = (cookie_header or "").strip()
        if not s:
            return {}
        ignore = {"path", "expires", "max-age", "domain", "secure", "httponly", "samesite", "priority"}
        out = {}
        for part in s.split(";"):
            p = (part or "").strip()
            if not p or "=" not in p:
                continue
            k, v = p.split("=", 1)
            k = (k or "").strip()
            v = (v or "").strip()
            if not k or k.lower() in ignore:
                continue
            out[k] = v
        return out

    @staticmethod
    def _cookie_map_to_header(cookie_map):
        if not isinstance(cookie_map, dict) or not cookie_map:
            return ""
        parts = []
        for k, v in cookie_map.items():
            ks = (k or "").strip()
            if not ks:
                continue
            parts.append(f"{ks}={'' if v is None else str(v)}")
        return "; ".join(parts)

    @staticmethod
    def _login_session_cookie_specs(loginconfig: dict):
        specs = []
        raw = (loginconfig or {}).get("loginSessionCookie", "")
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            s = str(item or "").strip()
            if s:
                specs.append(s)
        return specs

    @classmethod
    def _preset_login_cookie_from_config(cls, loginconfig: dict) -> str:
        merged = {}
        for raw in cls._login_session_cookie_specs(loginconfig):
            if "=" not in raw:
                continue
            merged.update(cls._cookie_map_from_cookie_header(raw))
        return cls._cookie_map_to_header(merged)

    @classmethod
    def _merge_cookie_headers(cls, pre_cookie: str, login_cookie: str):
        """
        Merge 2 Cookie header strings. If same key has different values, login wins.
        """
        pre_map = cls._cookie_map_from_cookie_header(pre_cookie)
        login_map = cls._cookie_map_from_cookie_header(login_cookie)
        merged = dict(pre_map)
        merged.update(login_map)  # login wins
        return cls._cookie_map_to_header(merged)

    @staticmethod
    def _is_http_url(s: str):
        t = (s or "").strip().lower()
        return t.startswith("http://") or t.startswith("https://")

    def _should_use_http_login(self, loginconfig: dict):
        url = (loginconfig or {}).get("url", "")
        pre = (loginconfig or {}).get("pre_login", "") or (loginconfig or {}).get("preLoginPage", "")
        return self._is_http_url(url) or self._is_http_url(pre)

    def _strip_login_cookies_from_seeds(self, login_cookie: str):
        """
        Remove login/session cookie keys from the seed cookie segment after login completes.
        seed format is expected as COOKIE\\x00GET\\x00POST\\x00...
        """
        cookie = (login_cookie or "").strip()
        if not cookie:
            return
        if not self.in_dir or self.in_dir == "-" or not os.path.isdir(self.in_dir):
            return
        login_cookie_names = {
            str(k or "").strip().lower()
            for k in self._cookie_map_from_cookie_header(cookie).keys()
            if str(k or "").strip()
        }
        if not login_cookie_names:
            return
        low_value_names = {
            "route_backward",
            "return-path",
            "return_path",
            "redirect",
            "redirect_to",
            "redirect_url",
            "__cf_bm",
            "_ga",
            "_gid",
            "_gat",
        }
        try:
            names = sorted(os.listdir(self.in_dir))
        except Exception:
            return
        for fn in names:
            path = os.path.join(self.in_dir, fn)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as rf:
                    data = rf.read()
                if b"\x00" not in data:
                    continue
                parts = data.split(b"\x00")
                if len(parts) < 3:
                    continue
                try:
                    seed_cookie = parts[0].decode("latin-1", errors="replace")
                except Exception:
                    seed_cookie = ""
                cookie_map = self._cookie_map_from_cookie_header(seed_cookie)
                if not cookie_map:
                    continue
                filtered = {}
                for ck, cv in cookie_map.items():
                    lck = str(ck or "").strip().lower()
                    if not lck:
                        continue
                    if lck in login_cookie_names or lck in low_value_names:
                        continue
                    if lck.endswith("_tmp") or lck.endswith("_target_tmp"):
                        continue
                    filtered[ck] = cv
                new_cookie = self._cookie_map_to_header(filtered)
                parts[0] = new_cookie.encode("latin-1", errors="ignore")
                new_data = b"\x00".join(parts)
                if new_data != data:
                    with open(path, "wb") as wf:
                        wf.write(new_data)
            except Exception:
                continue

    def _inject_login_session_cookie_into_seeds(self, login_cookie: str, loginconfig: dict):
        """
        If loginSessionCookie is configured, force those cookie key/value pairs back into
        the seed cookie segment after generic login-cookie stripping completes.
        """
        cookie = (login_cookie or "").strip()
        if not cookie:
            return
        if not self.in_dir or self.in_dir == "-" or not os.path.isdir(self.in_dir):
            return
        session_cookie_specs = self._login_session_cookie_specs(loginconfig)
        if not session_cookie_specs:
            return
        login_cookie_map = self._cookie_map_from_cookie_header(cookie)
        forced_pairs = {}
        for session_cookie_name in session_cookie_specs:
            forced_value = None
            forced_key = session_cookie_name
            configured_cookie_map = self._cookie_map_from_cookie_header(session_cookie_name)
            if configured_cookie_map:
                forced_key, forced_value = next(iter(configured_cookie_map.items()))
            else:
                for ck, cv in login_cookie_map.items():
                    if str(ck or "").strip().lower() == session_cookie_name.lower():
                        forced_key = ck
                        forced_value = cv
                        break
            if forced_value is None:
                continue
            forced_pairs[forced_key] = forced_value
        if not forced_pairs:
            return
        try:
            names = sorted(os.listdir(self.in_dir))
        except Exception:
            return
        for fn in names:
            path = os.path.join(self.in_dir, fn)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as rf:
                    data = rf.read()
                parts = data.split(b"\x00")
                if len(parts) < 3:
                    continue
                try:
                    seed_cookie = parts[0].decode("latin-1", errors="replace")
                except Exception:
                    seed_cookie = ""
                cookie_map = self._cookie_map_from_cookie_header(seed_cookie)
                cookie_map.update(forced_pairs)
                new_cookie = self._cookie_map_to_header(cookie_map)
                parts[0] = new_cookie.encode("latin-1", errors="ignore")
                new_data = b"\x00".join(parts)
                if new_data != data:
                    with open(path, "wb") as wf:
                        wf.write(new_data)
            except Exception:
                continue


    def check_environment(self):
        if self.container_info:
            return True
        return super().check_environment

    def _start_container(self, scr_fn, log_fpath, fuzzer_id, instance_cnt):
        t: archr.targets.DockerImageTarget = archr.targets.DockerImageTarget(
            image_name=self.container_info["name"],
        )

        # t.volumes["/p"] = {'bind': "/p", 'mode': 'rw'}
        # t.volumes[self.work_dir] = {'bind': self.work_dir, 'mode': 'rw'}
        t.volumes[self.work_dir] = {'bind': self.work_dir, 'mode': 'rw'}


        print(f"mounted workdir {self.work_dir}")
        t.build()

        t.start(
            labels=[f"witcher-iot-{fuzzer_id}"]
        )
        self._configure_container(t)

        self.container_targets.append(t)

        p = t.run_command(["/bin/sh", "-c", 'echo 1 >/proc/sys/kernel/sched_child_runs_first && echo core > /proc/sys/kernel/core_pattern'])
        p.communicate()
        p = t.run_command(["/bin/sh", "-c", "for fn in /sys/devices/system/cpu/cpu*/cpufreq/scaling_gov*; do echo performance > $fn; done"])
        p.communicate()
        t.run_command(["/bin/sh", "/entrypoint.sh"])
        #t.run_command(["/bin/ash", "-c", f"while /bin/true; do AFL_META_INFO_ID=80 /sbin/httpd; done"])
        time.sleep(4)
        import tarfile
        tar_fpath = os.path.join("/tmp","witcher.tar")
        #with tarfile.open(tar_fpath, "w") as tar:
        #    tar.add("/lib/x86_64-linux-gnu/libdl-2.31.so", arcname="libdl-2.31.so")
        t.inject_tarball("/tmp", tar_fpath)
        #t.run_command(["ln", "-s", "/tmp/libdl-2.31.so","/lib/x86_64-linux-gnu/libdl.so.2"])
        t.run_command(["/bin/sh", "-c", "cd /bin && rm -f sh && ln -s /bin/dash /bin/sh"])


        # run fuzzer
        print("started qemu-user server...")
        return t.ipv4_address



    def _start_afl_instance(self, instance_cnt=0):

        if callable(self.pre_instance_callback):
            self.pre_instance_callback(instance_cnt)

        args, fuzzer_id = self.build_args()

        logpath = os.path.join(self.work_dir, fuzzer_id + ".log")

        my_env = os.environ.copy()

        final_args = []

        for op in args:
            target_var = op.replace("~~", "--").replace("@@PORT@@", str(self.base_port))
            increasing_port = self.base_port + instance_cnt

            if "@@PORT_INCREMENT@@" in target_var:
                target_var = target_var.replace("@@PORT_INCREMENT@@", str(increasing_port))
                my_env["PORT"] = str(increasing_port)
                my_env["AFL_META_INFO_ID"] = str(increasing_port)
            final_args.append(target_var)

        theip = None
        with open(logpath, "w") as fp:
            if self.container_info and self.container_info.get("name", None):
                theip = self._start_container("", fp, fuzzer_id, instance_cnt)

        #print(f"TARGET OPTS::::: {final_args}")

        self._get_login(my_env, theip)

        my_env["AFL_BASE"] = os.path.join(self.work_dir, fuzzer_id)
        if self.fault_escalation:
            my_env["STRICT"] = "3"
        elif "STRICT" in my_env:
            del my_env["STRICT"]

        my_env["SCRIPT_NAME"] = my_env.get("SCRIPT_FILENAME","")
        if my_env["SCRIPT_NAME"].startswith("/app"):
            my_env["SCRIPT_NAME"] = my_env.get("SCRIPT_FILENAME","").replace("/app","")

        if "METHOD" not in my_env:
            my_env["METHOD"] = "POST"
        self._configure_seed_env_runtime(my_env)

        # print(f"[WC] my word dir {self.work_dir} AFL_BASE={my_env['AFL_BASE']}")

        self.log_command(final_args, fuzzer_id, my_env)

        l.debug("execing: %s > %s", ' '.join(final_args), logpath)

        # set core affinity if environment variable is set
        if "AFL_SET_AFFINITY" in my_env:
            tempint = int(my_env["AFL_SET_AFFINITY"])
            tempint += instance_cnt
            my_env["AFL_SET_AFFINITY"] = str(tempint)

        scr_fn = f"{self.work_dir}/fuzz-{instance_cnt}.sh"
        with open(scr_fn, "w") as scr:
            if self.container_info:
                scr.write("#! /bin/sh \n")
            else:
                scr.write("#! /bin/bash \n")
                # this will prevent multiple fuzzers running at once, should make it appear in work dir
                scr.write("rm -f /tmp/httpreqr.pid || sudo rm -f /tmp/httpreqr.pid \n")
            for key, val in my_env.items():
                scr.write(f'export {key}="{val}"\n')
            scr.write("exec " + " ".join(final_args) + "\n")
            scr.write("rm -f /tmp/httpreqr.pid || sudo rm -f /tmp/httpreqr.pid \n")
            #scr.write(f"{final_args[0].replace('afl-fuzz','afl-showmap')} -o /tmp/outmap ")


        l.info(f"Fuzz command written out to {scr_fn}")
        os.chmod(scr_fn, mode=0o774)

        with open(logpath, "w") as fp:
            if self.container_info and self.container_info.get("name",None):
                most_recent_index = len(self.container_targets) - 1
                run_cmd = [scr_fn]
                print(f"{run_cmd}")

                proc = self.container_targets[most_recent_index].run_command(run_cmd, stdout=fp, stderr=fp)

                time.sleep(1)

                if proc.returncode and proc.returncode != 0:
                    import ipdb
                    ipdb.set_trace()
                    raise Exception("Error fuzzer failed to start")

                return proc

            else:
                return subprocess.Popen([scr_fn], stdout=fp, stderr=fp, close_fds=True)

        # with open(logpath, "w") as fp:
        #     return subprocess.Popen(final_args, stdout=fp, stderr=fp, close_fds=True, env=my_env)

    @staticmethod
    def _check_for_authorized_response(body, headers, loginconfig):
        return WitcherAFL._check_body(body, loginconfig) and WitcherAFL._check_headers(headers, loginconfig)

    @staticmethod
    def _check_body(body, loginconfig):
        try:
            body = body.decode()
        except (UnicodeDecodeError, AttributeError):
            pass
        if "positiveBody" in loginconfig and len(loginconfig["positiveBody"]) > 1:
            pattern = re.compile(loginconfig["positiveBody"])
            res = pattern.search(body)
            test = res is not None
            return test
        return True

    @staticmethod
    def _check_headers(headers, loginconfig):

        if "positiveHeaders" in loginconfig:
            posHeaders = loginconfig.get("positiveHeaders",[])
            print(posHeaders)
            print(headers)
            for posname, posvalue in posHeaders.items():
                found = False
                for headername, headervalue in headers:
                    if posname == headername and posvalue in headervalue:
                        found = True
                        break
                if not found:
                    return False
        return True

    def _contains_session_cookie(self, session_cookie, loginconfig):

        session_name = loginconfig.get("loginSessionCookie",".*")
        if len(session_name) == "":
            session_name = ".*"

        import ipdb
        ipdb.set_trace()
        sessidrex = re.compile(rf"({session_name})=(?P<sessid>[a-z0-9_\-A-Z\%]{{24,256}})")


        session_match = sessidrex.match(session_cookie)
        if not session_match:
            return None

        sessid = session_match.group("sessid")
        print(f"COOKIE seen is {sessid}")
        return sessid

    def _save_session_data(self, loginconfig, sessid):
        session_cookie_locations = ["/tmp", "/var/lib/php/sessions"]
        if "cookieLocations" in loginconfig:
            for cl in loginconfig["cookeLocations"]:
                session_cookie_locations.append(cl)

        actual_sess_fn = ""
        for f in session_cookie_locations:

            sfile = f"*{sessid}"
            sesmask = os.path.join(f,sfile)
            for sfn in glob.glob(sesmask):
                if os.path.isfile(sfn):
                    actual_sess_fn = sfn
                    break
            if len(actual_sess_fn) > 0:
                break

        if len(actual_sess_fn) == 0:
            return True

        saved_sess_fn = f"/tmp/save_{sessid}"
        if os.path.isfile(actual_sess_fn):
            shutil.copyfile(actual_sess_fn, saved_sess_fn)
            os.chmod(saved_sess_fn, stat.S_IRWXO | stat.S_IRWXG | stat.S_IRWXU)
            self.used_sessions.add(saved_sess_fn)
            return True
        return True

    def _extract_authdata(self, headers, loginconfig, pre_login_cookie: str = ""):
        authdata = []
        login_auth_cookies = []
        for headername, headervalue in headers:
            if headername.upper() == "SET-COOKIE":
                # Uses special authdata header so that the value prepends all other cookie values and
                # random data from AFL does not interfere
                login_auth_cookies.append(headervalue)
                # cookie_dat = self._contains_session_cookie(headervalue, loginconfig)
                # if sessid:
                #     authdata.append(("LOGIN_COOKIE", headervalue))
                #     self._save_session_data(headervalue, loginconfig)


            if headername.upper() == "AUTHORIZATION":
                self.bearer = [(headername, headervalue)]
                authdata.append((headername, headervalue))

        merged_cookie = self._merge_cookie_headers(
            pre_login_cookie,
            self._normalize_set_cookie_values(login_auth_cookies),
        )
        if merged_cookie:
            if login_auth_cookies:
                print(login_auth_cookies)
            authdata.append(("LOGIN_COOKIE", merged_cookie))

        return authdata

    def _do_local_cgi_req_login(self, loginconfig):

        login_cmd = [loginconfig["cgiBinary"]]

        # print("[WC] \033[34m starting with command " + str(login_cmd) + "\033[0m")
        myenv = os.environ.copy()
        if "AFL_BASE" in myenv:
            del myenv["AFL_BASE"]

        myenv["METHOD"] = loginconfig["method"]
        if self.fault_escalation:
            myenv["STRICT"] = "3"
        elif "STRICT" in myenv:
            del myenv["STRICT"]
        login_script_filename, login_get_in_url = self._split_cgi_url(loginconfig.get("url", ""))
        myenv["SCRIPT_FILENAME"] = login_script_filename
        myenv["SCRIPT_NAME"] = login_script_filename
        if myenv["SCRIPT_NAME"].startswith("/app"):
            myenv["SCRIPT_NAME"] = myenv["SCRIPT_NAME"].replace("/app","")

        print(f"SCRIPT_NAME = {myenv['SCRIPT_NAME']}")

        if "afl_preload" in loginconfig:
            myenv["LD_PRELOAD"] = loginconfig["afl_preload"]
        if "ld_library_path" in loginconfig:
            myenv["LD_LIBRARY_PATH"] = loginconfig["ld_library_path"]

        extra_form_data = ""
        cookieData = ""
        pre_login_url = loginconfig.get("pre_login", "") or loginconfig.get("preLoginPage", "")
        if pre_login_url:

            pl_env = myenv.copy()
            pl_script_filename, pl_get_in_url = self._split_cgi_url(pre_login_url)
            pl_env["SCRIPT_FILENAME"] = pl_script_filename
            pl_env["SCRIPT_NAME"] = pl_script_filename

            if pl_env["SCRIPT_NAME"].startswith("/app"):
                pl_env["SCRIPT_NAME"] = pl_env["SCRIPT_NAME"].replace("/app", "")

            pl_env["METHOD"] = "GET"
            pre_httpdata = f'{cookieData}\x00{pl_get_in_url}\x00\x00'
            with open("/tmp/pre_login_req.dat","wb") as wf:
                wf.write(pre_httpdata.encode("utf-8", errors="replace"))
            infile = open("/tmp/pre_login_req.dat", "rb")
            self._login_debug_write(
                "local_cgi_pre_login_request",
                pre_login_url=pre_login_url,
                pre_login_script=pl_script_filename,
                pre_login_get=pl_get_in_url,
                env_subset={
                    "SCRIPT_FILENAME": pl_env.get("SCRIPT_FILENAME", ""),
                    "SCRIPT_NAME": pl_env.get("SCRIPT_NAME", ""),
                    "METHOD": pl_env.get("METHOD", ""),
                },
            )

            p = subprocess.Popen(login_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=infile, env=pl_env, close_fds=True)

            stdout, stderr = p.communicate(timeout=5)
            stdout = stdout.decode('latin-1')
            self._login_debug_write(
                "local_cgi_pre_login_response",
                returncode=p.returncode,
                stderr=stderr,
                raw_stdout=stdout,
            )
            set_cookies = []
            for respline in stdout.splitlines():
                if respline.lower().startswith("set-cookie:"):
                    val = respline.split(":", 1)[1].strip()
                    if val:
                        set_cookies.append(val)
            normalized = self._normalize_set_cookie_values(set_cookies)
            if normalized:
                cookieData = normalized

            print(f"Pre login cookies = {cookieData}, pre_login={pre_login_url}")

            rx = re.compile(r"(formid).*([a-f0-9]{32})")
            match = rx.search(stdout)
            if match:
                extra_form_data = f"{match.group(1)}={match.group(2)}"

        else:
            cookieData = loginconfig["cookieData"] if "cookieData" in loginconfig else ""


        getData = loginconfig["getData"] if "getData" in loginconfig else ""
        getData = self._merge_query_strings(login_get_in_url, getData)
        postData = loginconfig["postData"] if "postData" in loginconfig else ""

        if len(getData) > len(postData):
            getData += "&" + extra_form_data
        else:
            if len(extra_form_data) > 0:
                postData += "&" + extra_form_data
        print(f"cookiedData2={cookieData}")
        httpdata = f'{cookieData}\x00{getData}\x00{postData}\x00'

        with open("/tmp/login_req.dat", "wb") as wf:
            wf.write(httpdata.encode())

        env_str = ""
        for k, v in myenv.items():
            if k in "LD_LIBRARY_PATH,DOCUMENT_ROOT,AFL_SET_AFFINITY,SERVER_NAME,STRICT,WC_INSTRUMENTATION,NO_WC_EXTRA,SCRIPT_FILENAME,METHOD,SCRIPT_NAME":
                env_str += f"export {k}='{v}';"
        print(f"\033[33m{' '.join(login_cmd)}\n{env_str}\033[0m")
        self._login_debug_write(
            "local_cgi_login_request",
            url=loginconfig.get("url", ""),
            method=loginconfig.get("method", ""),
            getData=loginconfig.get("getData", ""),
            postData=loginconfig.get("postData", ""),
            cookieData=cookieData,
            stdin_payload=httpdata,
            env_subset=self._debug_env_subset(myenv),
        )

        login_req_file = open("/tmp/login_req.dat", "r")

        p = subprocess.Popen(login_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=login_req_file, env=myenv)

        strout, stderr = p.communicate()
        login_req_file.close()

        if stderr:
            print(f"stderr = {stderr}")
        self._login_debug_write(
            "local_cgi_login_response",
            returncode=p.returncode,
            stderr=stderr,
            raw_stdout=strout,
        )
        byteout = strout
        strout = strout.decode('latin-1')

        headers = []
        body = ""
        inbody = False
        #start = False
        extra_wait = False
        for respline in strout.splitlines():
            # if "END webcam_trace_init" in respline:
            #     start = True
            #     continue
            if respline.find("@@@@@@@@@@@@@") > -1:
                extra_wait = True 
            if len(respline) == 0:# and start:
                if extra_wait:
                    extra_wait=False
                    continue
                inbody = True
                continue
            if inbody:
                body += respline + "\n"
            else:
                header = respline.split(":")
                if len(header) > 1:
                    headername = header[0].strip()
                    headerval = ":".join(header[1:])
                    headerval = headerval.lstrip()
                    headers.append((headername, headerval))
        
        # Some apps only set session cookies in pre_login, and login itself may not emit Set-Cookie.
        # Merge pre_login cookies with login cookies (login wins on key conflicts).
        login_set_cookies = []
        try:
            for hn, hv in headers:
                if (hn or "").strip().lower() == "set-cookie" and hv:
                    login_set_cookies.append(hv)
        except Exception:
            login_set_cookies = []
        login_cookie_norm = self._normalize_set_cookie_values(login_set_cookies)
        merged_cookie = self._merge_cookie_headers(cookieData, login_cookie_norm)

        authorized = self._check_for_authorized_response(body, headers, loginconfig)
        self._login_debug_write(
            "local_cgi_login_parsed_response",
            authorized=authorized,
            headers=headers,
            body_preview=body,
            pre_login_cookie=cookieData,
            login_set_cookie_normalized=login_cookie_norm,
            merged_cookie=merged_cookie,
        )
        if not authorized:
            print("\033[31mFailed to get authorization\033[0m")
            print(f"headers={headers}")
            #print(f"body={body}")
            print(f"strout={byteout}")
            exit(33)
            #raise Exception("Failed to get authorization")
            #return []

        if merged_cookie:
            return [("LOGIN_COOKIE", merged_cookie)]
        return self._extract_authdata(headers, loginconfig)

    def _do_httpreqr_login(self, loginconfig, ipaddress=None, relogging=False):

        url = loginconfig["url"]
        url = url.replace("@@PORT_INCREMENT@@", str(18080))

        if "getData" in loginconfig and loginconfig['getData']:
            url += f"?{loginconfig['getData']}"

        # if ipaddress:
        #     url = url.replace("127.0.0.1", ipaddress)

        post_data = loginconfig["postData"] if "postData" in loginconfig else ""
        post_data = post_data.encode('ascii')

        req_headers = loginconfig["headers"] if "headers" in loginconfig else {}
        method = loginconfig.get("method","GET")

        #opener = urllib.request.build_opener(NoRedirection)
        #urllib.request.install_opener(opener)

        #req = urllib.request.Request(url, post_data, req_headers, method=method)

        #response = urllib.request.urlopen(req)
        #headers = response.getheaders()
        #body = response.read()

        for t in self.container_targets:

            p = t.run_command(["/httpreqr","--url",url], env=["AFL_META_INFO_ID=80"])
            stdout, stderr = p.communicate(input=b'\x00\x00' + post_data + b'\x00')

            body = stdout.decode('latin-1')
            headers = body
            if not WitcherAFL._check_for_authorized_response(body, headers, loginconfig):
                print("[Witcher] \033[31mFAILED to get AUTHORIZATION\033[0m")
                print(f"\tURL = {url}")
                print(f"\tresponse={body}")
                if not relogging:
                    exit(33)

    def _do_http_req_login(self, loginconfig, ipaddress=None, relogging=False):

        url = loginconfig["url"]
        url = url.replace("@@PORT_INCREMENT@@", str(18080))
        pre_login_url = loginconfig.get("pre_login", "") or loginconfig.get("preLoginPage", "")
        pre_login_url = (pre_login_url or "").replace("@@PORT_INCREMENT@@", str(18080))

        # If pre_login is http(s) but login url is a local path, reuse pre_login origin.
        if (not self._is_http_url(url)) and self._is_http_url(pre_login_url):
            try:
                from urllib.parse import urlparse, urljoin
                pu = urlparse(pre_login_url)
                origin = f"{pu.scheme}://{pu.netloc}"
                url = urljoin(origin + "/", (url or "").lstrip("/"))
            except Exception:
                pass

        if "getData" in loginconfig and loginconfig['getData']:
            url += f"?{loginconfig['getData']}"

        if ipaddress:
            url = url.replace("127.0.0.1", ipaddress)

        post_data = loginconfig["postData"] if "postData" in loginconfig else ""
        post_data = post_data.encode('ascii')

        req_headers = loginconfig["headers"] if "headers" in loginconfig else {}
        method = loginconfig.get("method", "GET")
        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar), NoRedirection)
        urllib.request.install_opener(opener)
        print(f"headers={req_headers}")
        print(f"post={post_data}")
        self._login_debug_write(
            "http_login_request",
            url=url,
            method=method,
            headers=req_headers,
            postData=post_data,
            env_subset={
                "LD_LIBRARY_PATH": os.environ.get("LD_LIBRARY_PATH", ""),
                "DOCUMENT_ROOT": os.environ.get("DOCUMENT_ROOT", ""),
                "AFL_SET_AFFINITY": os.environ.get("AFL_SET_AFFINITY", ""),
                "SERVER_NAME": os.environ.get("SERVER_NAME", ""),
                "STRICT": os.environ.get("STRICT", ""),
                "WC_INSTRUMENTATION": os.environ.get("WC_INSTRUMENTATION", ""),
                "NO_WC_EXTRA": os.environ.get("NO_WC_EXTRA", ""),
                "SCRIPT_FILENAME": os.environ.get("SCRIPT_FILENAME", ""),
                "SCRIPT_NAME": os.environ.get("SCRIPT_NAME", ""),
                "METHOD": os.environ.get("METHOD", ""),
                "LOGIN_COOKIE": os.environ.get("LOGIN_COOKIE", ""),
                "MANDATORY_COOKIE": os.environ.get("MANDATORY_COOKIE", ""),
            },
            pre_login_url=pre_login_url,
        )
        pre_login_cookie = ""
        if pre_login_url:
            try:
                pre_req = urllib.request.Request(pre_login_url, method="GET")
                pre_resp = urllib.request.urlopen(pre_req)
                pre_code = pre_resp.getcode()
                pre_headers = pre_resp.getheaders()
                pre_body = pre_resp.read()
                pre_login_cookie = self._normalize_set_cookie_values(
                    [hv for hn, hv in pre_headers if (hn or "").strip().lower() == "set-cookie" and hv]
                )
                self._login_debug_write(
                    "http_pre_login_response",
                    status_code=pre_code,
                    headers=pre_headers,
                    body_preview=pre_body,
                    pre_login_cookie=pre_login_cookie,
                )
            except Exception as ex:
                self._login_debug_write("http_pre_login_error", error=str(ex), pre_login_url=pre_login_url)
        req = urllib.request.Request(url, post_data, req_headers, method=method)

        response = urllib.request.urlopen(req)
        headers = response.getheaders()
        body = response.read()
        code = response.getcode()
        self._login_debug_write(
            "http_login_response",
            status_code=code,
            headers=headers,
            body_preview=body,
        )

        # ipdb.set_trace()

        authorized = WitcherAFL._check_for_authorized_response(body, headers, loginconfig)
        self._login_debug_write(
            "http_login_authorization_check",
            authorized=authorized,
            positiveBody=loginconfig.get("positiveBody", ""),
            positiveHeaders=loginconfig.get("positiveHeaders", {}),
        )
        if not authorized:
            print("[Witcher] \033[31mFAILED to get AUTHORIZATION\033[0m")
            print(f"\tURL = {url}")
            #print(f"\tresponse={body}")
            print(f"\tresponse={response.getcode()}")
            print(f"\tresponse={response.getheaders()}")
            if not relogging:
                exit(33)


        return body, headers, code, pre_login_cookie

    @staticmethod
    def _do_authorized_requests(loginconfig, authdata):
        extra_requests = loginconfig["extra_authorized_requests"] if "postData" in loginconfig else []

        for auth_request in extra_requests:

            url = auth_request["url"]
            if not url:
                continue

            if "getData" in auth_request:
                url += f"?{auth_request['getData']}"

            post_data = auth_request["postData"] if "postData" in auth_request else ""
            post_data = post_data.encode('ascii')

            req_headers = auth_request["headers"] if "headers" in auth_request else {}
            for adname, advalue in authdata:
                adname = adname.replace("LOGIN_COOKIE","Cookie")
                req_headers[adname] = advalue
                req = urllib.request.Request(url, post_data, req_headers)
                urllib.request.urlopen(req)

    def _get_login(self, my_env, ipaddress=None):

        if self.login_json_fn == "":
            self._write_auth_snapshot(my_env, source="no_login_json")
            return

        if len(self.bearer) > 0:
            for bname, bvalue in self.bearer:
                my_env[bname] = bvalue
            self._write_auth_snapshot(my_env, source="cached_bearer")
            return

        with open(self.login_json_fn, "r") as jfile:
            jdata = json.load(jfile)
        if jdata["direct"]["url"] == "NO_LOGIN":
            self._write_auth_snapshot(my_env, source="direct_no_login")
            return
        loginconfig = jdata["direct"]
        preset_login_cookie = self._preset_login_cookie_from_config(loginconfig)
        if preset_login_cookie:
            my_env["LOGIN_COOKIE"] = preset_login_cookie
            self._strip_login_cookies_from_seeds(my_env.get("LOGIN_COOKIE", ""))
            self._inject_login_session_cookie_into_seeds(my_env.get("LOGIN_COOKIE", ""), loginconfig)
            self._write_auth_snapshot(my_env, source="preset_login_cookie")
            return
        if not loginconfig["url"]:
            self._write_auth_snapshot(my_env, source="direct_url_empty")
            return
        self._login_debug_write(
            "get_login_start",
            login_url=loginconfig.get("url", ""),
            method=loginconfig.get("method", ""),
            getData=loginconfig.get("getData", ""),
            postData=loginconfig.get("postData", ""),
            headers=loginconfig.get("headers", {}),
            env_subset={
                "LD_LIBRARY_PATH": my_env.get("LD_LIBRARY_PATH", ""),
                "DOCUMENT_ROOT": my_env.get("DOCUMENT_ROOT", ""),
                "AFL_SET_AFFINITY": my_env.get("AFL_SET_AFFINITY", ""),
                "SERVER_NAME": my_env.get("SERVER_NAME", ""),
                "STRICT": my_env.get("STRICT", ""),
                "WC_INSTRUMENTATION": my_env.get("WC_INSTRUMENTATION", ""),
                "NO_WC_EXTRA": my_env.get("NO_WC_EXTRA", ""),
                "SCRIPT_FILENAME": my_env.get("SCRIPT_FILENAME", ""),
                "SCRIPT_NAME": my_env.get("SCRIPT_NAME", ""),
                "METHOD": my_env.get("METHOD", ""),
                "LOGIN_COOKIE": my_env.get("LOGIN_COOKIE", ""),
                "MANDATORY_COOKIE": my_env.get("MANDATORY_COOKIE", ""),
                "MANDATORY_GET": my_env.get("MANDATORY_GET", ""),
                "MANDATORY_POST": my_env.get("MANDATORY_POST", ""),
            },
        )

        saved_session_id = self._get_saved_session()
        #my_env["LOGIN_COOKIE"]="csrftoken=aaa; password=bbb"
        if len(saved_session_id) > 0:
            saved_session_name = loginconfig["loginSessionCookie"]
            my_env["LOGIN_COOKIE"] = f"{saved_session_name}:{saved_session_id}"
            self._write_auth_snapshot(my_env, source="saved_session")
            return

        authdata = None
        for _ in range(0, 10):
            if self._should_use_http_login(loginconfig):

                _, headers, code, pre_login_cookie = self._do_http_req_login(loginconfig, ipaddress)

                authdata = self._extract_authdata(headers, loginconfig, pre_login_cookie=pre_login_cookie)
                self._login_debug_write(
                    "http_login_extracted_auth",
                    status_code=code,
                    pre_login_cookie=pre_login_cookie,
                    authdata=authdata,
                )

                if self.relog:
                    rp = getattr(self, "relog_process", None)
                    alive = False
                    try:
                        alive = bool(rp is not None and rp.is_alive())
                    except Exception:
                        alive = False
                    if not alive:
                        p = Process(target=self._do_relog, args=(loginconfig, ipaddress, self.running_flag))
                        p.start()
                        print("[Witcher] Started relog process")
                        self.relog_process = p

                print(f"[*] Authorized data = {authdata}")
                WitcherAFL._do_authorized_requests(loginconfig, authdata)
            else:
                authdata = self._do_local_cgi_req_login(loginconfig)
            if authdata is not None:
                break
            time.sleep(5)

        if authdata is None:
            raise ValueError("Login failed to return authenticated cookie/bearer value")

        for authname, authvalue in authdata:

            my_env[authname] = authvalue
        self._strip_login_cookies_from_seeds(my_env.get("LOGIN_COOKIE", ""))
        self._inject_login_session_cookie_into_seeds(my_env.get("LOGIN_COOKIE", ""), loginconfig)
        self._login_debug_write(
            "get_login_done",
            authdata=authdata,
            env_subset=self._debug_env_subset(my_env),
            final_LOGIN_COOKIE=my_env.get("LOGIN_COOKIE", ""),
            final_AUTHORIZATION=my_env.get("AUTHORIZATION", ""),
            final_HTTP_AUTHORIZATION=my_env.get("HTTP_AUTHORIZATION", ""),
        )
        self._write_auth_snapshot(my_env, source="fresh_login")

        # Best-effort: verify login by requesting the fuzzer's target SCRIPT_FILENAME via php-cgi,
        # using the freshly captured cookie. This should match symex trace behavior.
        try:
            target_script = str(my_env.get("SCRIPT_FILENAME", "") or "").strip()
            cookie_val = str(my_env.get("LOGIN_COOKIE", "") or "").strip()
            get_qs = str(my_env.get("MANDATORY_GET", "") or "").strip().lstrip("?")
            if target_script and cookie_val and (not (loginconfig.get("url") or "").startswith("http")):
                self._cgi_followup_check(loginconfig=loginconfig, cookie_value=cookie_val, script_filename=target_script, get_qs=get_qs)
        except Exception:
            pass

    def _do_relog(self, loginconfig, ipaddress, running_flag):
        while bool(getattr(running_flag, "value", running_flag)):
            self._do_httpreqr_login(loginconfig, ipaddress, relogging=True)
            time.sleep(30)

    def _get_saved_session(self):
        # if we have an unused session file, we are done for this worker.
        for saved_sess_fn in glob.iglob("/tmp/save_????????????????????*"):
            if saved_sess_fn not in self.used_sessions:
                sess_fn = saved_sess_fn.replace("save", "sess")
                # print("sess_fn=" + sess_fn)
                self.used_sessions.add(saved_sess_fn)
                shutil.copyfile(saved_sess_fn, sess_fn)

                saved_session_id = saved_sess_fn.split("_")[1]
                return saved_session_id
        return ""

    def stop(self):
        try:
            self.running_flag.value = False
        except Exception:
            self.running_flag = False
        try:
            p = getattr(self, "relog_process", None)
            if p is not None:
                try:
                    if p.is_alive():
                        p.join(timeout=2)
                except Exception:
                    pass
                try:
                    if p.is_alive():
                        p.terminate()
                        p.join(timeout=2)
                except Exception:
                    pass
        except Exception:
            pass
        super().stop()


class NoRedirection(urllib.request.HTTPErrorProcessor):

    def http_response(self, request, response):
        return response

    https_response = http_response


class NonBlockingStreamReader:

    def __init__(self, stream):
        '''
        stream: the stream to read from.
                Usually a process' stdout or stderr.
        '''

        self._s = stream
        self._q = Queue()
        self._finished = False

        def _populateQueue(stream, queue):
            '''
            Collect lines from 'stream' and put them in 'quque'.
            '''

            while True:
                line = stream.readline()
                if line:
                    queue.put(line)
                else:
                    self._finished = True
                    #raise UnexpectedEndOfStream

        self._t = Thread(target = _populateQueue,
                         args = (self._s, self._q))
        self._t.daemon = True
        self._t.start() #start collecting lines from the stream

    @property
    def is_finished(self):
        return self._finished

    def readline(self, timeout = None):
        try:
            if self._finished:
                return None
            return self._q.get(block = timeout is not None,
                    timeout = timeout)
        except Empty:
            return None


class UnexpectedEndOfStream(Exception):
    pass
