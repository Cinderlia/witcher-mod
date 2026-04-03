import os
import subprocess
import time
import signal
from typing import Optional, Dict, Tuple, List

from .executor import SeedExecutor
from ..core.seed_parser import SeedParser
from ..core.types import ExecutionResult


class CGIBinaryExecutor(SeedExecutor):
    def __init__(
        self,
        binary_path: str,
        script_filename: str,
        document_root: Optional[str] = None,
        method: str = "AUTO",
        path_info: str = "",
        content_type: str = "application/x-www-form-urlencoded",
        timeout_seconds: float = 5.0,
        extra_env: Optional[Dict[str, str]] = None,
        binary_args: Optional[List[str]] = None,
    ):
        self.binary_path = binary_path
        self.script_filename = script_filename
        self.document_root = document_root
        self.method = method
        self.path_info = path_info
        self.content_type = content_type
        self.timeout_seconds = timeout_seconds
        self.extra_env = extra_env or {}
        self.binary_args = binary_args or []
        self.parser = SeedParser()

    def execute(self, seed: bytes) -> ExecutionResult:
        seed_input = self.parser.parse_seed(seed)
        method = self._resolve_method(seed_input.post)
        env = self._build_env(method, seed_input.query, seed_input.post, seed_input.cookies, seed_input.headers)
        cmd = [self.binary_path] + self.binary_args
        start = time.time()
        try:
            close_fds = os.name != "nt"
            preexec_fn = None if os.name == "nt" else (lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN))
            proc = subprocess.run(
                cmd,
                input=seed_input.post.encode("latin-1", errors="ignore"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=self.timeout_seconds,
                close_fds=close_fds,
                preexec_fn=preexec_fn,
            )
            duration_ms = (time.time() - start) * 1000.0
            stdout = proc.stdout.decode("latin-1", errors="ignore")
            response_text, status_code = self._extract_body(stdout)
            error = proc.stderr.decode("latin-1", errors="ignore") if proc.stderr else None
            return ExecutionResult(
                seed=seed,
                response_text=response_text,
                status_code=status_code,
                error=error if error else None,
                duration_ms=duration_ms,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                seed=seed,
                response_text="",
                status_code=None,
                error="timeout",
                duration_ms=None,
            )

    def _resolve_method(self, post: str) -> str:
        if self.method and self.method != "AUTO":
            return self.method.upper()
        return "POST" if post else "GET"

    def _build_env(self, method: str, query: str, post: str, cookies: str, headers: str) -> Dict[str, str]:
        env = os.environ.copy()
        env.update(self.extra_env)
        env["AFL_NO_FORKSRV"] = "1"
        env["SCRIPT_FILENAME"] = self.script_filename
        env["SCRIPT_NAME"] = self.script_filename
        if self.document_root:
            env["DOCUMENT_ROOT"] = self.document_root
        if self.path_info:
            env["PATH_INFO"] = self.path_info
        env["REQUEST_METHOD"] = method
        env["METHOD"] = method
        env["QUERY_STRING"] = query
        if cookies:
            env["HTTP_COOKIE"] = cookies
            env["COOKIE"] = cookies
        if post:
            env["CONTENT_LENGTH"] = str(len(post.encode("latin-1", errors="ignore")))
            env["CONTENT_TYPE"] = self.content_type
        for hk, hv in self._parse_headers(headers):
            key = "HTTP_" + hk.upper().replace("-", "_")
            env[key] = hv
        return env

    def _parse_headers(self, headers: str) -> List[Tuple[str, str]]:
        items = []
        for line in headers.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            items.append((k.strip(), v.strip()))
        return items

    def _extract_body(self, stdout: str) -> Tuple[str, Optional[int]]:
        status_code = None
        header, body = self._split_headers_body(stdout)
        for line in header.splitlines():
            if line.lower().startswith("status:"):
                parts = line.split(":", 1)[1].strip().split(" ", 1)
                if parts and parts[0].isdigit():
                    status_code = int(parts[0])
        return body, status_code

    def _split_headers_body(self, stdout: str) -> Tuple[str, str]:
        if "\r\n\r\n" in stdout:
            header, body = stdout.split("\r\n\r\n", 1)
            return header, body
        if "\n\n" in stdout:
            header, body = stdout.split("\n\n", 1)
            return header, body
        return "", stdout
