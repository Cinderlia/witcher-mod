import json
import os
import re
import shutil
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from ..core.config import XSSConfig
from ..core.seed_parser import SeedParser
from ..core.seed_mutator import SeedMutator
from ..core.payloads import PayloadFactory
from ..core.deduper import SeedDeduper


class XSSSeedGenerator:
    def __init__(self, work_dir: str, output_dir_name: str = "xss_queue", log_path: Optional[str] = None):
        self.work_dir = work_dir
        self.output_dir_name = output_dir_name
        self.log_path = log_path or os.path.join(work_dir, "xss_reflection.log")
        self.parser = SeedParser()
        self.mutator = SeedMutator()
        self.payloads = PayloadFactory(XSSConfig(seed_dir=work_dir, output_dir=work_dir))
        self.deduper = SeedDeduper()
        self._dedupe_lock = threading.Lock()
        self._log_lock = threading.Lock()

    def run(self) -> Dict[str, int]:
        fuzzer_dirs = self._fuzzer_dirs()
        total_seeds = 0
        total_generated = 0

        def one(fuzzer_dir: str):
            queue_dir = os.path.join(fuzzer_dir, "queue")
            if not os.path.isdir(queue_dir):
                return 0, 0
            seed_files = self._queue_files(queue_dir)
            generated = self._process_queue(queue_dir, seed_files)
            return len(seed_files), generated

        max_workers = max(1, min(len(fuzzer_dirs), os.cpu_count() or 4))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(one, fd) for fd in (fuzzer_dirs or [])]
            for fu in as_completed(futs):
                try:
                    scanned, gen = fu.result()
                except Exception:
                    continue
                total_seeds += int(scanned)
                total_generated += int(gen)
        self._log(f"Witcher-XSS seeds generated={total_generated} in {self.output_dir_name}")
        return {"seeds_scanned": total_seeds, "seeds_generated": total_generated}

    def _process_queue(self, queue_dir: str, seed_files: List[str]) -> int:
        output_dir = os.path.join(os.path.dirname(queue_dir), self.output_dir_name)
        os.makedirs(output_dir, exist_ok=True)

        generated = 0
        for seed_path in seed_files:
            seed_id = self._seed_id(seed_path)
            seed_output_dir = os.path.join(output_dir, seed_id)
            if os.path.isdir(seed_output_dir):
                shutil.rmtree(seed_output_dir)
            os.makedirs(seed_output_dir, exist_ok=True)

            records: List[Dict[str, str]] = []
            with open(seed_path, "rb") as rf:
                seed = rf.read()
            seed_input = self.parser.parse_seed(seed)
            params = self.parser.extract_params(seed_input)
            for param in params:
                payload = self.payloads.random_payload(param)
                mutated = self.mutator.replace_param(seed_input, param, payload.value)
                with self._dedupe_lock:
                    if self.deduper.is_duplicate(mutated):
                        continue
                name = self._seed_name(seed_path, param.location, param.index, payload.token)
                out_path = os.path.join(seed_output_dir, name)
                with open(out_path, "wb") as wf:
                    wf.write(mutated)
                records.append({
                    "token": payload.token,
                    "source_seed": os.path.basename(seed_path),
                    "output_seed": name,
                    "location": param.location,
                    "key": param.key,
                    "index": str(param.index),
                })
                generated += 1
            self._write_map(seed_output_dir, records)
        self._log(f"Witcher-XSS queue={queue_dir} generated={generated}")
        return generated

    def _queue_files(self, queue_dir: str) -> List[str]:
        files = []
        for name in sorted(os.listdir(queue_dir)):
            if name == ".state" or name == "README.txt":
                continue
            path = os.path.join(queue_dir, name)
            if os.path.isfile(path):
                files.append(path)
        return files

    def _seed_name(self, seed_path: str, location: str, index: int, token: str) -> str:
        base = os.path.basename(seed_path)
        base = re.sub(r"[^a-zA-Z0-9._-]", "_", base)
        return f"xss-{base}-{location.lower()}-{index}-{token}"

    def _seed_id(self, seed_path: str) -> str:
        base = os.path.basename(seed_path)
        match = re.search(r"(id:\d+)", base)
        if match:
            return match.group(1)
        base = re.sub(r"[^a-zA-Z0-9._-]", "_", base)
        return base

    def _write_map(self, output_dir: str, records: List[Dict[str, str]]) -> None:
        map_path = os.path.join(output_dir, "xss_map.json")
        with open(map_path, "w", encoding="utf-8") as wf:
            json.dump(records, wf, ensure_ascii=False, indent=2)

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


def generate_xss_seeds(work_dir: str, output_dir_name: str = "xss_queue") -> Dict[str, int]:
    generator = XSSSeedGenerator(work_dir=work_dir, output_dir_name=output_dir_name)
    return generator.run()
