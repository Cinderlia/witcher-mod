import json
import os
import shutil
from typing import Dict, List, Optional

from ..analysis.context_locator import ContextLocator
from ..attack.dispatcher import get_handler
from ..core.seed_parser import SeedParser
from ..core.seed_mutator import SeedMutator
from ..core.types import Param
from .cgi_runner import CGIRunner


class TargetedAttackRunner:
    def __init__(self, work_dir: str, output_dir_name: str = "xss_queue", log_path: Optional[str] = None):
        self.work_dir = work_dir
        self.output_dir_name = output_dir_name
        self.log_path = log_path or os.path.join(work_dir, "xss_reflection.log")
        self.locator = ContextLocator()
        self.parser = SeedParser()
        self.mutator = SeedMutator()
        self.runner = CGIRunner(work_dir)
        self._confirm_index = 0

    def run(self) -> Dict[str, int]:
        script_path = self.runner.find_script()
        if not script_path:
            self._log("Witcher-XSS attack script not found")
            return {"attack_executed": 0, "attack_confirmed": 0}
        env, cmd = self.runner.parse_script(script_path)
        if not cmd:
            self._log("Witcher-XSS attack command not found")
            return {"attack_executed": 0, "attack_confirmed": 0}
        executed = 0
        confirmed = 0
        total_contexts: Dict[str, int] = {}
        total_confirmed: Dict[str, int] = {}
        for fuzzer_dir in self._fuzzer_dirs():
            queue_root = os.path.join(fuzzer_dir, self.output_dir_name)
            if not os.path.isdir(queue_root):
                continue
            for seed_dir in self._seed_dirs(queue_root):
                hits_dir = os.path.join(seed_dir, "hits")
                if not os.path.isdir(hits_dir):
                    continue
                confirmed_dir = os.path.join(seed_dir, "confirmed")
                attempts_dir = os.path.join(seed_dir, "attempts")
                if os.path.isdir(confirmed_dir):
                    shutil.rmtree(confirmed_dir)
                os.makedirs(confirmed_dir, exist_ok=True)
                if os.path.isdir(attempts_dir):
                    shutil.rmtree(attempts_dir)
                os.makedirs(attempts_dir, exist_ok=True)
                token_map = self._load_map(seed_dir)
                seed_contexts: Dict[str, int] = {}
                seed_confirmed: Dict[str, int] = {}
                for seed_path in self._seed_files(hits_dir):
                    response_path = seed_path + ".html"
                    if not os.path.isfile(response_path):
                        continue
                    record = token_map.get(os.path.basename(seed_path))
                    if not record:
                        continue
                    token = record.get("token")
                    if not token:
                        continue
                    with open(response_path, "r", encoding="utf-8", errors="ignore") as rf:
                        body = rf.read()
                    contexts = self.locator.locate(body, token)
                    if not contexts:
                        continue
                    for ctx in contexts:
                        seed_contexts[ctx.context_type] = seed_contexts.get(ctx.context_type, 0) + 1
                    with open(seed_path, "rb") as rf:
                        base_seed = rf.read()
                    seed_input = self.parser.parse_seed(base_seed)
                    param = Param(
                        location=record.get("location", ""),
                        key=record.get("key", ""),
                        value=token,
                        index=int(record.get("index", 0)),
                    )
                    for ctx in contexts:
                        handler = get_handler(ctx.context_type)
                        if not handler:
                            continue
                        payloads = handler.build_payloads(ctx.quote)
                        self._write_attempts(attempts_dir, seed_path, ctx.context_type, payloads)
                        for payload in payloads:
                            mutated = self.mutator.replace_param(seed_input, param, payload)
                            tmp_seed_path = os.path.join(confirmed_dir, "attack.tmp")
                            with open(tmp_seed_path, "wb") as wf:
                                wf.write(mutated)
                            body = self.runner.execute(cmd, env, tmp_seed_path)
                            executed += 1
                            if handler.is_success(body):
                                confirmed += 1
                                seed_confirmed[ctx.context_type] = seed_confirmed.get(ctx.context_type, 0) + 1
                                self._save_confirmed(
                                    confirmed_dir,
                                    mutated,
                                    ctx.context_type,
                                    payload,
                                    body,
                                )
                for key, value in seed_contexts.items():
                    total_contexts[key] = total_contexts.get(key, 0) + value
                for key, value in seed_confirmed.items():
                    total_confirmed[key] = total_confirmed.get(key, 0) + value
                self._log(
                    f"Witcher-XSS attack validated {seed_dir} executed={executed} confirmed={confirmed} "
                    f"contexts={seed_contexts} confirmed_types={seed_confirmed}"
                )
        self._log(f"Witcher-XSS attack summary contexts={total_contexts} confirmed_types={total_confirmed}")
        return {"attack_executed": executed, "attack_confirmed": confirmed}

    def _save_confirmed(self, confirmed_dir: str, seed_bytes: bytes, context_type: str, payload: str, body: str) -> None:
        self._confirm_index += 1
        name = f"{context_type}-attack-{self._confirm_index}"
        out_seed = os.path.join(confirmed_dir, name)
        with open(out_seed, "wb") as wf:
            wf.write(seed_bytes)
        with open(out_seed + ".html", "w", encoding="utf-8") as wf:
            wf.write(body)
        meta = {
            "context": context_type,
            "payload": payload,
        }
        with open(out_seed + ".json", "w", encoding="utf-8") as wf:
            json.dump(meta, wf, ensure_ascii=False, indent=2)

    def _write_attempts(self, attempts_dir: str, seed_path: str, context_type: str, payloads: List[str]) -> None:
        base = os.path.basename(seed_path)
        out_path = os.path.join(attempts_dir, f"{context_type}-{base}.json")
        meta = {
            "context": context_type,
            "payloads": payloads,
        }
        with open(out_path, "w", encoding="utf-8") as wf:
            json.dump(meta, wf, ensure_ascii=False, indent=2)

    def _seed_dirs(self, queue_root: str) -> List[str]:
        items = []
        for name in sorted(os.listdir(queue_root)):
            path = os.path.join(queue_root, name)
            if os.path.isdir(path):
                items.append(path)
        return items

    def _seed_files(self, hits_dir: str) -> List[str]:
        files = []
        for name in sorted(os.listdir(hits_dir)):
            if name.endswith(".html") or name.endswith(".json"):
                continue
            path = os.path.join(hits_dir, name)
            if os.path.isfile(path):
                files.append(path)
        return files

    def _load_map(self, seed_dir: str) -> Dict[str, dict]:
        map_path = os.path.join(seed_dir, "xss_map.json")
        if not os.path.isfile(map_path):
            return {}
        with open(map_path, "r", encoding="utf-8") as rf:
            data = json.load(rf)
        return {item.get("output_seed"): item for item in data if "output_seed" in item}

    def _fuzzer_dirs(self) -> List[str]:
        items = []
        for name in sorted(os.listdir(self.work_dir)):
            if name == "fuzzer-master" or name.startswith("fuzzer-"):
                path = os.path.join(self.work_dir, name)
                if os.path.isdir(path):
                    items.append(path)
        return items

    def _log(self, message: str) -> None:
        print(f"[Witcher-XSS] {message}")
        with open(self.log_path, "a", encoding="utf-8") as wf:
            wf.write(message + "\n")


def run_targeted_attacks(work_dir: str, output_dir_name: str = "xss_queue") -> Dict[str, int]:
    runner = TargetedAttackRunner(work_dir=work_dir, output_dir_name=output_dir_name)
    return runner.run()
