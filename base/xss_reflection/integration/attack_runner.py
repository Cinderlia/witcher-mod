import json
import os
import re
import shutil
import time
import hashlib
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from ..analysis.context_locator import ContextLocator
from ..attack.common import WITCHER_MARKER
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
        self._confirm_lock = threading.Lock()
        self._log_lock = threading.Lock()

    def run(self, deadline: float = None) -> Dict[str, int]:
        script_path = self.runner.find_script()
        if not script_path:
            self._log("Witcher-XSS attack script not found")
            return {"attack_executed": 0, "attack_confirmed": 0, "attack_confirmed_unique": 0}
        env, cmd = self.runner.parse_script(script_path)
        if not cmd:
            self._log("Witcher-XSS attack command not found")
            return {"attack_executed": 0, "attack_confirmed": 0, "attack_confirmed_unique": 0}
        executed = 0
        confirmed_hits = 0
        confirmed_unique = 0
        total_contexts: Dict[str, int] = {}
        total_confirmed_hits: Dict[str, int] = {}
        total_confirmed_unique: Dict[str, int] = {}
        queue_roots = self._queue_roots()

        def one(queue_root: str):
            executed = 0
            confirmed_hits = 0
            confirmed_unique = 0
            total_contexts: Dict[str, int] = {}
            total_confirmed_hits: Dict[str, int] = {}
            total_confirmed_unique: Dict[str, int] = {}
            if not os.path.isdir(queue_root):
                return 0, 0, 0, total_contexts, total_confirmed_hits, total_confirmed_unique
            for seed_dir in self._seed_dirs(queue_root):
                if deadline is not None and time.monotonic() >= deadline:
                    break
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
                seed_confirmed_hits: Dict[str, int] = {}
                seed_confirmed_unique: Dict[str, int] = {}
                seen_confirmed = set()
                saved_seed_hashes = set()
                for seed_path in self._seed_files(hits_dir):
                    if deadline is not None and time.monotonic() >= deadline:
                        break
                    response_path = seed_path + ".html"
                    if not os.path.isfile(response_path):
                        continue
                    record = token_map.get(os.path.basename(seed_path))
                    if not record:
                        continue
                    with open(response_path, "r", encoding="utf-8", errors="ignore") as rf:
                        body = rf.read()
                    token = self._extract_reflected_token(body, record.get("token"))
                    if not token:
                        continue
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
                            if deadline is not None:
                                remaining = deadline - time.monotonic()
                                if remaining <= 0:
                                    break
                            mutated = self.mutator.replace_param(seed_input, param, payload)
                            tmp_seed_path = os.path.join(confirmed_dir, "attack.tmp")
                            with open(tmp_seed_path, "wb") as wf:
                                wf.write(mutated)
                            if deadline is not None:
                                per_timeout = max(1, min(10, int(remaining)))
                            else:
                                per_timeout = 10
                            body = self.runner.execute(cmd, env, tmp_seed_path, timeout=per_timeout)
                            executed += 1
                            matched = self._find_attack_match(body, ctx)
                            if matched is None:
                                continue
                            success_view = self._success_view(matched, ctx.context_type)
                            if not handler.is_success(success_view):
                                continue
                            confirmed_hits += 1
                            seed_confirmed_hits[ctx.context_type] = seed_confirmed_hits.get(ctx.context_type, 0) + 1
                            unique_key = self._confirmed_key(record, ctx)
                            if unique_key in seen_confirmed:
                                continue
                            seen_confirmed.add(unique_key)
                            confirmed_unique += 1
                            seed_confirmed_unique[ctx.context_type] = seed_confirmed_unique.get(ctx.context_type, 0) + 1
                            seed_hash = hashlib.sha1(mutated).hexdigest()
                            if seed_hash in saved_seed_hashes:
                                continue
                            saved_seed_hashes.add(seed_hash)
                            self._save_confirmed(
                                confirmed_dir,
                                mutated,
                                ctx.context_type,
                                payload,
                                body,
                                unique_key,
                                matched,
                            )
                for key, value in seed_contexts.items():
                    total_contexts[key] = total_contexts.get(key, 0) + value
                for key, value in seed_confirmed_hits.items():
                    total_confirmed_hits[key] = total_confirmed_hits.get(key, 0) + value
                for key, value in seed_confirmed_unique.items():
                    total_confirmed_unique[key] = total_confirmed_unique.get(key, 0) + value
                self._log(
                    f"Witcher-XSS attack validated {seed_dir} executed={executed} "
                    f"confirmed_hits={confirmed_hits} confirmed_unique={confirmed_unique} "
                    f"contexts={seed_contexts} confirmed_hits_types={seed_confirmed_hits} "
                    f"confirmed_unique_types={seed_confirmed_unique}"
                )
            return executed, confirmed_hits, confirmed_unique, total_contexts, total_confirmed_hits, total_confirmed_unique

        max_workers = max(1, min(len(queue_roots), os.cpu_count() or 4))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(one, qr) for qr in (queue_roots or [])]
            for fu in as_completed(futs):
                try:
                    exed, conf_hits, conf_unique, ctx_map, conf_hits_map, conf_unique_map = fu.result()
                except Exception:
                    continue
                executed += int(exed)
                confirmed_hits += int(conf_hits)
                confirmed_unique += int(conf_unique)
                for k, v in (ctx_map or {}).items():
                    total_contexts[k] = total_contexts.get(k, 0) + int(v)
                for k, v in (conf_hits_map or {}).items():
                    total_confirmed_hits[k] = total_confirmed_hits.get(k, 0) + int(v)
                for k, v in (conf_unique_map or {}).items():
                    total_confirmed_unique[k] = total_confirmed_unique.get(k, 0) + int(v)
        self._log(
            f"Witcher-XSS attack summary contexts={total_contexts} "
            f"confirmed_hits_types={total_confirmed_hits} confirmed_unique_types={total_confirmed_unique}"
        )
        return {
            "attack_executed": executed,
            "attack_confirmed": confirmed_hits,
            "attack_confirmed_unique": confirmed_unique,
        }

    def _save_confirmed(
        self,
        confirmed_dir: str,
        seed_bytes: bytes,
        context_type: str,
        payload: str,
        body: str,
        unique_key: str,
        matched_ctx,
    ) -> None:
        with self._confirm_lock:
            self._confirm_index += 1
            idx = int(self._confirm_index)
        name = f"{context_type}-attack-{idx}"
        out_seed = os.path.join(confirmed_dir, name)
        with open(out_seed, "wb") as wf:
            wf.write(seed_bytes)
        with open(out_seed + ".html", "w", encoding="utf-8") as wf:
            wf.write(body)
        meta = {
            "context": context_type,
            "payload": payload,
            "unique_key": unique_key,
            "matched_context": getattr(matched_ctx, "context_type", None),
            "matched_tag": getattr(matched_ctx, "tag_name", None),
            "matched_attr": getattr(matched_ctx, "attr_name", None),
            "matched_position": getattr(matched_ctx, "position", None),
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

    def _extract_reflected_token(self, body: str, fallback: Optional[str]) -> Optional[str]:
        matches = sorted(set(re.findall(r"witcher_xss_\d{4}", body or "")))
        if matches:
            return matches[0]
        token = str(fallback or "").strip()
        if token:
            return token
        return None

    def _find_attack_match(self, body: str, original_ctx):
        candidates = self.locator.locate(body, WITCHER_MARKER)
        if not candidates:
            return None
        best = None
        best_distance = None
        for candidate in candidates:
            if not self._candidate_matches(original_ctx, candidate):
                continue
            distance = abs(int(candidate.position) - int(original_ctx.position))
            if best is None or best_distance is None or distance < best_distance:
                best = candidate
                best_distance = distance
        return best

    def _candidate_matches(self, original_ctx, candidate) -> bool:
        if abs(int(candidate.position) - int(original_ctx.position)) > 1024:
            return False
        if original_ctx.context_type in {"attr_value", "attr_name", "url"}:
            if original_ctx.tag_name and candidate.tag_name and original_ctx.tag_name != candidate.tag_name:
                return False
        return True

    def _success_view(self, matched_ctx, original_context_type: str) -> str:
        if original_context_type in {"attr_value", "attr_name", "url"} and matched_ctx.tag_html:
            return matched_ctx.tag_html
        return matched_ctx.snippet

    def _confirmed_key(self, record: dict, ctx) -> str:
        parts = {
            "source_seed": record.get("source_seed"),
            "output_seed": record.get("output_seed"),
            "location": record.get("location"),
            "key": record.get("key"),
            "index": record.get("index"),
            "context": ctx.context_type,
            "tag_name": ctx.tag_name,
            "position": int(ctx.position),
        }
        return json.dumps(parts, sort_keys=True, ensure_ascii=False)

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


def run_targeted_attacks(work_dir: str, output_dir_name: str = "xss_queue", deadline: float = None) -> Dict[str, int]:
    runner = TargetedAttackRunner(work_dir=work_dir, output_dir_name=output_dir_name)
    return runner.run(deadline=deadline)
