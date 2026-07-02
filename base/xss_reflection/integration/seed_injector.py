import json
import os
import re
import shutil
import time
import hashlib
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from ..core.config import XSSConfig
from ..core.seed_parser import SeedParser
from ..core.seed_mutator import SeedMutator
from ..core.payloads import PayloadFactory
from ..core.deduper import SeedDeduper


class XSSSeedGenerator:
    def __init__(
        self,
        work_dir: str,
        output_dir_name: str = "xss_queue",
        log_path: Optional[str] = None,
        session_cookie_name: str = "",
        session_cookie_value: str = "",
    ):
        self.work_dir = work_dir
        self.output_dir_name = output_dir_name
        self.log_path = log_path or os.path.join(work_dir, "xss_reflection.log")
        self.session_cookie_name = str(session_cookie_name or "").strip()
        self.session_cookie_value = str(session_cookie_value or "").strip()
        self.parser = SeedParser()
        self.mutator = SeedMutator()
        self.payloads = PayloadFactory(XSSConfig(seed_dir=work_dir, output_dir=work_dir))
        self.deduper = SeedDeduper()
        self._dedupe_lock = threading.Lock()
        self._log_lock = threading.Lock()

    def run(self, deadline: float = None) -> Dict[str, int]:
        fuzzer_dirs = self._fuzzer_dirs()
        total_seeds = 0
        total_generated = 0

        def one(fuzzer_dir: str):
            if deadline is not None and time.monotonic() >= deadline:
                return 0, 0
            scanned = 0
            generated = 0
            for source_dir in self._seed_source_dirs(fuzzer_dir):
                if deadline is not None and time.monotonic() >= deadline:
                    break
                seed_files = self._seed_files(source_dir)
                if not seed_files:
                    continue
                scanned += len(seed_files)
                generated += self._process_queue(source_dir, seed_files, deadline=deadline)
            return scanned, generated

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

    def _process_queue(self, queue_dir: str, seed_files: List[str], deadline: float = None) -> int:
        fuzzer_dir = os.path.dirname(queue_dir)
        source_kind = os.path.basename(queue_dir)
        output_dir = os.path.join(self.work_dir, self.output_dir_name)
        mirror_root = os.path.join(fuzzer_dir, self.output_dir_name)
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(mirror_root, exist_ok=True)

        generated = 0
        for seed_path in seed_files:
            if deadline is not None and time.monotonic() >= deadline:
                break
            seed_id = self._seed_id(seed_path, queue_dir)
            seed_output_dir = os.path.join(output_dir, seed_id)
            mirror_seed_output_dir = os.path.join(mirror_root, seed_id)
            if os.path.isdir(seed_output_dir):
                shutil.rmtree(seed_output_dir)
            if os.path.isdir(mirror_seed_output_dir):
                shutil.rmtree(mirror_seed_output_dir)
            os.makedirs(seed_output_dir, exist_ok=True)
            os.makedirs(mirror_seed_output_dir, exist_ok=True)

            records: List[Dict[str, str]] = []
            seen_param_slots = set()
            seen_saved_hashes = set()
            with open(seed_path, "rb") as rf:
                seed = rf.read()
            seed = self._apply_session_cookie_override(seed)
            seed_input = self.parser.parse_seed(seed)
            params = self.parser.extract_params(seed_input)
            for param in params:
                if deadline is not None and time.monotonic() >= deadline:
                    break
                slot_key = (str(param.location).lower(), str(param.key), int(param.index))
                if slot_key in seen_param_slots:
                    continue
                seen_param_slots.add(slot_key)
                payload = self.payloads.random_payload(param)
                mutated = self.mutator.replace_param(seed_input, param, payload.value)
                seed_hash = hashlib.sha1(mutated).hexdigest()
                if seed_hash in seen_saved_hashes:
                    continue
                seen_saved_hashes.add(seed_hash)
                with self._dedupe_lock:
                    if self.deduper.is_duplicate(mutated):
                        continue
                name = self._seed_name(seed_path, param.location, param.index, payload.token)
                out_path = os.path.join(seed_output_dir, name)
                mirror_out_path = os.path.join(mirror_seed_output_dir, name)
                with open(out_path, "wb") as wf:
                    wf.write(mutated)
                with open(mirror_out_path, "wb") as wf:
                    wf.write(mutated)
                records.append({
                    "token": payload.token,
                    "source_seed": os.path.basename(seed_path),
                    "source_seed_path": seed_path,
                    "source_kind": source_kind,
                    "output_seed": name,
                    "location": param.location,
                    "key": param.key,
                    "index": str(param.index),
                    "fuzzer_dir": fuzzer_dir,
                    "queue_dir": queue_dir,
                    "primary_seed_path": out_path,
                    "mirror_seed_path": mirror_out_path,
                })
                generated += 1
            self._write_map(seed_output_dir, records)
            self._write_map(mirror_seed_output_dir, records)
        self._log(f"Witcher-XSS source={queue_dir} generated={generated}")
        return generated

    def _seed_files(self, queue_dir: str) -> List[str]:
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

    def _seed_id(self, seed_path: str, queue_dir: str) -> str:
        fuzzer_name = os.path.basename(os.path.dirname(queue_dir))
        source_kind = os.path.basename(queue_dir)
        base = os.path.basename(seed_path)
        base_clean = re.sub(r"[^a-zA-Z0-9._-]", "_", base)
        base_stem = os.path.splitext(base_clean)[0]
        if len(base_stem) > 80:
            base_stem = base_stem[:80]
        match = re.search(r"(id:\d+)", base)
        if match:
            core = f"{fuzzer_name}__{match.group(1)}__src_{base_stem}"
        else:
            core = f"{fuzzer_name}__src_{base_stem}"
        if source_kind != "queue":
            return f"{core}__{source_kind}"
        return core

    def _write_map(self, output_dir: str, records: List[Dict[str, str]]) -> None:
        map_path = os.path.join(output_dir, "xss_map.json")
        with open(map_path, "w", encoding="utf-8") as wf:
            json.dump(records, wf, ensure_ascii=False, indent=2)

    def _apply_session_cookie_override(self, seed: bytes) -> bytes:
        if not self.session_cookie_name or not self.session_cookie_value:
            return seed
        try:
            parts = seed.split(b"\x00")
            if len(parts) < 3:
                return seed
            cookie_header = parts[0].decode("latin-1", errors="replace")
            cookie_map = self._cookie_map_from_cookie_header(cookie_header)
            cookie_map[self.session_cookie_name] = self.session_cookie_value
            parts[0] = self._cookie_map_to_header(cookie_map).encode("latin-1", errors="ignore")
            return b"\x00".join(parts)
        except Exception:
            return seed

    @staticmethod
    def _cookie_map_from_cookie_header(cookie_header: str) -> Dict[str, str]:
        raw_cookie = str(cookie_header or "").strip()
        if not raw_cookie:
            return {}
        ignore = {"path", "expires", "max-age", "domain", "secure", "httponly", "samesite", "priority"}
        out = {}
        for part in raw_cookie.split(";"):
            piece = str(part or "").strip()
            if not piece or "=" not in piece:
                continue
            key, value = piece.split("=", 1)
            key = str(key or "").strip()
            value = str(value or "").strip()
            if not key or key.lower() in ignore:
                continue
            out[key] = value
        return out

    @staticmethod
    def _cookie_map_to_header(cookie_map: Dict[str, str]) -> str:
        parts = []
        for key, value in (cookie_map or {}).items():
            name = str(key or "").strip()
            if not name:
                continue
            parts.append("%s=%s" % (name, "" if value is None else str(value)))
        return "; ".join(parts)

    def _fuzzer_dirs(self) -> List[str]:
        items = []
        for name in sorted(os.listdir(self.work_dir)):
            if name == "fuzzer-master" or (name.startswith("fuzzer-") and name != "extsync"):
                path = os.path.join(self.work_dir, name)
                if os.path.isdir(path):
                    items.append(path)
        return items

    def _seed_source_dirs(self, fuzzer_dir: str) -> List[str]:
        items = []
        for name in ("queue", "crashes"):
            path = os.path.join(fuzzer_dir, name)
            if os.path.isdir(path):
                items.append(path)
        return items

    def _log(self, message: str) -> None:
        print(f"[Witcher-XSS] {message}")
        with self._log_lock:
            with open(self.log_path, "a", encoding="utf-8") as wf:
                wf.write(message + "\n")


def generate_xss_seeds(
    work_dir: str,
    output_dir_name: str = "xss_queue",
    deadline: float = None,
    session_cookie_name: str = "",
    session_cookie_value: str = "",
) -> Dict[str, int]:
    generator = XSSSeedGenerator(
        work_dir=work_dir,
        output_dir_name=output_dir_name,
        session_cookie_name=session_cookie_name,
        session_cookie_value=session_cookie_value,
    )
    return generator.run(deadline=deadline)
