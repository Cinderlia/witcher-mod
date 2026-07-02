import json
import os
import re
import shutil
import time
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from .cgi_runner import CGIRunner


class CGISeedValidator:
    def __init__(self, work_dir: str, output_dir_name: str = "xss_queue", log_path: Optional[str] = None):
        self.work_dir = work_dir
        self.output_dir_name = output_dir_name
        self.log_path = log_path or os.path.join(work_dir, "xss_reflection.log")
        self.token_pattern = re.compile(r"witcher_xss_\d{4}")
        self.runner = CGIRunner(work_dir)
        self._log_lock = threading.Lock()

    def run(self, deadline: float = None) -> Dict[str, int]:
        script_path = self.runner.find_script()
        if not script_path:
            self._log("Witcher-XSS CGI script not found")
            return {"executed": 0, "reflected": 0}
        env, cmd = self.runner.parse_script(script_path)
        if not cmd:
            self._log("Witcher-XSS CGI command not found")
            return {"executed": 0, "reflected": 0}
        queue_roots = self._queue_roots()

        def one(queue_root: str):
            executed = 0
            reflected = 0
            if not os.path.isdir(queue_root):
                return 0, 0
            for seed_dir in self._seed_dirs(queue_root):
                if deadline is not None and time.monotonic() >= deadline:
                    break
                hits_dir = os.path.join(seed_dir, "hits")
                responses_dir = os.path.join(seed_dir, "responses")
                if os.path.isdir(hits_dir):
                    shutil.rmtree(hits_dir)
                os.makedirs(hits_dir, exist_ok=True)
                if os.path.isdir(responses_dir):
                    shutil.rmtree(responses_dir)
                os.makedirs(responses_dir, exist_ok=True)
                token_map = self._load_map(seed_dir)
                seen_hits = set()
                for seed_path in self._seed_files(seed_dir):
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                    if deadline is not None:
                        per_timeout = max(1, min(10, int(remaining)))
                    else:
                        per_timeout = 10
                    body = self.runner.execute(cmd, env, seed_path, timeout=per_timeout)
                    executed += 1
                    self._write_response(responses_dir, seed_path, body)
                    reflected_tokens = self._extract_response_tokens(body)
                    if not reflected_tokens:
                        continue
                    hit_seeds = self._resolve_hit_seeds(seed_dir, seed_path, reflected_tokens, token_map)
                    for hit_seed_path in hit_seeds:
                        hit_name = os.path.basename(hit_seed_path)
                        shutil.copy2(hit_seed_path, hits_dir)
                        self._write_response(hits_dir, hit_seed_path, body)
                        if hit_name not in seen_hits:
                            seen_hits.add(hit_name)
                            reflected += 1
                    self._log(
                        "Witcher-XSS reflected seed=%s tokens=%s hits=%s"
                        % (
                            os.path.basename(seed_path),
                            sorted(reflected_tokens),
                            sorted([os.path.basename(p) for p in hit_seeds]),
                        )
                    )
                self._log(f"Witcher-XSS validated {seed_dir} executed={executed} reflected={reflected}")
            return executed, reflected

        total_executed = 0
        total_reflected = 0
        max_workers = max(1, min(len(queue_roots), os.cpu_count() or 4))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(one, qr) for qr in (queue_roots or [])]
            for fu in as_completed(futs):
                try:
                    exed, refl = fu.result()
                except Exception:
                    continue
                total_executed += int(exed)
                total_reflected += int(refl)
        return {"executed": total_executed, "reflected": total_reflected}

    def _seed_dirs(self, queue_root: str) -> List[str]:
        items = []
        for name in sorted(os.listdir(queue_root)):
            path = os.path.join(queue_root, name)
            if os.path.isdir(path):
                items.append(path)
        return items

    def _seed_files(self, seed_dir: str) -> List[str]:
        files = []
        for name in sorted(os.listdir(seed_dir)):
            if name in {"xss_map.json", "hits", "responses", "confirmed", "attempts"}:
                continue
            path = os.path.join(seed_dir, name)
            if os.path.isfile(path):
                files.append(path)
        return files

    def _load_map(self, seed_dir: str) -> Dict[str, str]:
        map_path = os.path.join(seed_dir, "xss_map.json")
        if not os.path.isfile(map_path):
            return {}
        with open(map_path, "r", encoding="utf-8") as rf:
            data = json.load(rf)
        return {item.get("output_seed"): item.get("token") for item in data if "output_seed" in item}

    def _token_for_seed(self, seed_path: str, token_map: Dict[str, str]) -> Optional[str]:
        name = os.path.basename(seed_path)
        match = self.token_pattern.search(name)
        if match:
            return match.group(0)
        return token_map.get(name)

    def _extract_response_tokens(self, body: str) -> List[str]:
        return sorted(set(self.token_pattern.findall(body or "")))

    def _resolve_hit_seeds(
        self,
        seed_dir: str,
        seed_path: str,
        reflected_tokens: List[str],
        token_map: Dict[str, str],
    ) -> List[str]:
        hits = []
        seen = set()
        for token in reflected_tokens:
            matched = False
            for output_seed, mapped_token in (token_map or {}).items():
                if mapped_token != token:
                    continue
                candidate = os.path.join(seed_dir, output_seed)
                if os.path.isfile(candidate) and candidate not in seen:
                    hits.append(candidate)
                    seen.add(candidate)
                    matched = True
            if matched:
                continue
            if seed_path not in seen:
                hits.append(seed_path)
                seen.add(seed_path)
        return hits

    def _write_response(self, hits_dir: str, seed_path: str, body: str) -> None:
        base = os.path.basename(seed_path)
        out_path = os.path.join(hits_dir, base + ".html")
        with open(out_path, "w", encoding="utf-8") as wf:
            wf.write(body)

    def _queue_roots(self) -> List[str]:
        modern_root = os.path.join(self.work_dir, self.output_dir_name)
        if os.path.isdir(modern_root):
            return [modern_root]
        items = []
        for name in sorted(os.listdir(self.work_dir)):
            if name == "fuzzer-master" or (name.startswith("fuzzer-") and name != "extsync"):
                queue_root = os.path.join(self.work_dir, name, self.output_dir_name)
                if os.path.isdir(queue_root):
                    items.append(queue_root)
        return items

    def _log(self, message: str) -> None:
        print(f"[Witcher-XSS] {message}")
        with self._log_lock:
            with open(self.log_path, "a", encoding="utf-8") as wf:
                wf.write(message + "\n")


def validate_xss_seeds(work_dir: str, output_dir_name: str = "xss_queue", deadline: float = None) -> Dict[str, int]:
    validator = CGISeedValidator(work_dir=work_dir, output_dir_name=output_dir_name)
    return validator.run(deadline=deadline)
