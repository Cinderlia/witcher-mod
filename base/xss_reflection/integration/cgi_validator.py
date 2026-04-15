import json
import os
import re
import shutil
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

    def run(self) -> Dict[str, int]:
        script_path = self.runner.find_script()
        if not script_path:
            self._log("Witcher-XSS CGI script not found")
            return {"executed": 0, "reflected": 0}
        env, cmd = self.runner.parse_script(script_path)
        if not cmd:
            self._log("Witcher-XSS CGI command not found")
            return {"executed": 0, "reflected": 0}
        fuzzer_dirs = self._fuzzer_dirs()

        def one(fuzzer_dir: str):
            executed = 0
            reflected = 0
            queue_root = os.path.join(fuzzer_dir, self.output_dir_name)
            if not os.path.isdir(queue_root):
                return 0, 0
            for seed_dir in self._seed_dirs(queue_root):
                hits_dir = os.path.join(seed_dir, "hits")
                responses_dir = os.path.join(seed_dir, "responses")
                if os.path.isdir(hits_dir):
                    shutil.rmtree(hits_dir)
                os.makedirs(hits_dir, exist_ok=True)
                if os.path.isdir(responses_dir):
                    shutil.rmtree(responses_dir)
                os.makedirs(responses_dir, exist_ok=True)
                token_map = self._load_map(seed_dir)
                for seed_path in self._seed_files(seed_dir):
                    token = self._token_for_seed(seed_path, token_map)
                    body = self.runner.execute(cmd, env, seed_path)
                    executed += 1
                    self._write_response(responses_dir, seed_path, body)
                    if token and token in body:
                        shutil.copy2(seed_path, hits_dir)
                        self._write_response(hits_dir, seed_path, body)
                        reflected += 1
                self._log(f"Witcher-XSS validated {seed_dir} executed={executed} reflected={reflected}")
            return executed, reflected

        total_executed = 0
        total_reflected = 0
        max_workers = max(1, min(len(fuzzer_dirs), os.cpu_count() or 4))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(one, fd) for fd in (fuzzer_dirs or [])]
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
            if name == "xss_map.json" or name == "hits":
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

    def _write_response(self, hits_dir: str, seed_path: str, body: str) -> None:
        base = os.path.basename(seed_path)
        out_path = os.path.join(hits_dir, base + ".html")
        with open(out_path, "w", encoding="utf-8") as wf:
            wf.write(body)

    def _fuzzer_dirs(self) -> List[str]:
        items = []
        for name in sorted(os.listdir(self.work_dir)):
            if name == "fuzzer-master" or (name.startswith("fuzzer-") and name != "extsync"):
                path = os.path.join(self.work_dir, name)
                if os.path.isdir(path):
                    items.append(path)
        return items

    def _log(self, message: str) -> None:
        print(f"[Witcher-XSS] {message}")
        with self._log_lock:
            with open(self.log_path, "a", encoding="utf-8") as wf:
                wf.write(message + "\n")


def validate_xss_seeds(work_dir: str, output_dir_name: str = "xss_queue") -> Dict[str, int]:
    validator = CGISeedValidator(work_dir=work_dir, output_dir_name=output_dir_name)
    return validator.run()
