import os
import shlex
import subprocess
import signal
from typing import Dict, List, Optional, Tuple


class CGIRunner:
    def __init__(self, work_dir: str):
        self.work_dir = work_dir

    def find_script(self) -> Optional[str]:
        candidates = []
        for name in os.listdir(self.work_dir):
            if name.startswith("fuzz-") and name.endswith(".sh"):
                path = os.path.join(self.work_dir, name)
                if os.path.isfile(path):
                    candidates.append(path)
        if not candidates:
            return None
        candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return candidates[0]

    def parse_script(self, script_path: str) -> Tuple[Dict[str, str], List[str]]:
        env = os.environ.copy()
        cmd = []
        with open(script_path, "r", encoding="utf-8", errors="ignore") as rf:
            for raw in rf:
                line = raw.strip()
                if line.startswith("export "):
                    kv = line[len("export "):]
                    if "=" in kv:
                        key, value = kv.split("=", 1)
                        env[key] = self._strip_quotes(value)
                if "afl-fuzz" in line and " -- " in line:
                    tokens = shlex.split(line)
                    if "--" in tokens:
                        cmd = tokens[tokens.index("--") + 1:]
        return env, cmd

    def execute(self, cmd: List[str], env: Dict[str, str], seed_path: str, timeout: int = 10) -> str:
        with open(seed_path, "rb") as rf:
            seed = rf.read()
        env = dict(env)
        env["AFL_FILE"] = seed_path
        try:
            close_fds = os.name != "nt"
            preexec_fn = None if os.name == "nt" else (lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN))
            proc = subprocess.run(
                cmd,
                input=seed,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=timeout,
                close_fds=close_fds,
                preexec_fn=preexec_fn,
            )
            output = proc.stdout.decode("latin-1", errors="ignore")
            return self._extract_body(output)
        except Exception:
            return ""

    def _extract_body(self, output: str) -> str:
        if "\r\n\r\n" in output:
            return output.split("\r\n\r\n", 1)[1]
        if "\n\n" in output:
            return output.split("\n\n", 1)[1]
        return output

    def _strip_quotes(self, value: str) -> str:
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1]
        return value
