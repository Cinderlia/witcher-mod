import hashlib
import os
import re
import threading
import time
from typing import Dict, Optional, Set, Tuple


class ExternalSeedSync:
    """
    Bridge external seed files into AFL sync queue at runtime.

    AFL workers with -M/-S automatically sync from sibling directories under
    work_dir that contain queue/id:* files.
    """

    def __init__(
        self,
        work_dir: str,
        external_seed_dir: str,
        sync_name: str = "extsync",
        poll_interval: float = 2.0,
        max_seed_size: int = 1024 * 1024,
        logger=print,
    ):
        self.work_dir = work_dir
        self.external_seed_dir = external_seed_dir
        self.sync_name = sync_name
        self.poll_interval = max(float(poll_interval), 0.2)
        self.max_seed_size = max(1, int(max_seed_size))
        self.logger = logger

        self.sync_queue_dir = os.path.join(self.work_dir, self.sync_name, "queue")
        env_root = os.path.join(self.work_dir, "seed_env_profiles")
        self.parent_env_dir = os.path.abspath(os.environ.get("WC_ENV_PARENT_DIR") or os.path.join(env_root, "parent"))
        self.child_env_dir = os.path.abspath(os.environ.get("WC_ENV_CHILD_DIR") or os.path.join(env_root, "child"))
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen_hashes: Set[str] = set()
        self._seen_paths: Dict[str, float] = {}
        self._next_id = self._init_next_id()

    @staticmethod
    def _extract_env_id(name: str) -> str:
        match = re.search(r"(?:^|,)env:([^,]+)", name or "")
        if not match:
            return ""
        return str(match.group(1) or "").strip()

    @staticmethod
    def _load_env_profile(path: str) -> Dict[str, Optional[str]]:
        out: Dict[str, Optional[str]] = {}
        if not path or not os.path.isfile(path):
            return out
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as rf:
                for raw_line in rf:
                    line = str(raw_line or "").rstrip("\r\n")
                    if not line:
                        continue
                    if "=" in line:
                        key, val = line.split("=", 1)
                        parsed_val: Optional[str] = str(val or "")
                    else:
                        key = line
                        parsed_val = None
                    key = str(key or "").strip()
                    if not key:
                        continue
                    out[key] = parsed_val
        except Exception:
            return {}
        return out

    @staticmethod
    def _env_signature(env_map: Dict[str, Optional[str]]) -> Tuple[Tuple[str, str], ...]:
        if not isinstance(env_map, dict) or not env_map:
            return tuple()
        items = []
        for key in sorted(env_map.keys()):
            key_s = str(key or "").strip()
            if not key_s:
                continue
            value = env_map.get(key_s)
            items.append((key_s, "__WC_NONE__" if value is None else str(value)))
        return tuple(items)

    def _resolve_child_env_id(self, env_id: str) -> str:
        env_id = str(env_id or "").strip()
        if not env_id:
            return ""
        parent_path = os.path.join(self.parent_env_dir, f"{env_id}.env")
        parent_env = self._load_env_profile(parent_path)
        if not parent_env:
            return env_id
        wanted_sig = self._env_signature(parent_env)
        if not wanted_sig:
            return env_id
        try:
            os.makedirs(self.child_env_dir, exist_ok=True)
        except Exception:
            return env_id
        try:
            child_names = sorted(os.listdir(self.child_env_dir))
        except Exception:
            return env_id
        for name in child_names:
            if not str(name).endswith(".env"):
                continue
            child_id = str(name[:-4] or "").strip()
            if not child_id:
                continue
            child_path = os.path.join(self.child_env_dir, name)
            child_sig = self._env_signature(self._load_env_profile(child_path))
            if child_sig and child_sig == wanted_sig:
                return child_id
        return env_id

    def _init_next_id(self) -> int:
        os.makedirs(self.sync_queue_dir, exist_ok=True)
        max_id = -1
        id_re = re.compile(r"^id:(\d+),")
        for name in os.listdir(self.sync_queue_dir):
            match = id_re.match(name)
            if not match:
                continue
            try:
                max_id = max(max_id, int(match.group(1)))
            except ValueError:
                continue
        return max_id + 1

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.logger(
            f"[WC] External seed sync enabled: source={self.external_seed_dir}, "
            f"target={self.sync_queue_dir}"
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._scan_once()
            except Exception as ex:
                self.logger(f"[WC] External seed sync warning: {ex}")
            self._stop_event.wait(self.poll_interval)

    def _scan_once(self) -> None:
        if not self.external_seed_dir or not os.path.isdir(self.external_seed_dir):
            return

        for entry in os.listdir(self.external_seed_dir):
            if entry.startswith("."):
                continue
            fpath = os.path.join(self.external_seed_dir, entry)
            if not os.path.isfile(fpath):
                continue

            try:
                mtime = os.path.getmtime(fpath)
            except OSError:
                continue

            last_mtime = self._seen_paths.get(fpath)
            if last_mtime is not None and mtime <= last_mtime:
                continue

            try:
                with open(fpath, "rb") as rf:
                    data = rf.read()
            except OSError:
                continue

            self._seen_paths[fpath] = mtime
            if not data or len(data) > self.max_seed_size:
                continue

            env_id = self._extract_env_id(entry)
            resolved_env_id = self._resolve_child_env_id(env_id) if env_id else ""
            digest = hashlib.sha1(data + resolved_env_id.encode("utf-8", errors="ignore")).hexdigest()
            if digest in self._seen_hashes:
                continue

            self._seen_hashes.add(digest)
            out_name = f"id:{self._next_id:06d},src:extseed"
            if resolved_env_id:
                out_name += f",env:{resolved_env_id}"
            self._next_id += 1
            out_path = os.path.join(self.sync_queue_dir, out_name)
            with open(out_path, "wb") as wf:
                wf.write(data)
            if env_id and resolved_env_id and env_id != resolved_env_id:
                self.logger(f"[WC] Imported external seed -> {out_path} (env dedup {env_id} -> {resolved_env_id})")
            else:
                self.logger(f"[WC] Imported external seed -> {out_path}")


def start_external_seed_sync(work_dir: str, config: dict, logger=print) -> Optional[ExternalSeedSync]:
    external_seed_dir = (
        os.environ.get("WC_EXTERNAL_SEED_DIR")
        or config.get("external_seed_dir")
        or ""
    )
    if not external_seed_dir:
        return None

    sync_name = config.get("external_seed_sync_name", "extsync")
    poll_interval = config.get("external_seed_poll_interval", 2.0)
    max_seed_size = config.get("external_seed_max_size", 1024 * 1024)

    syncer = ExternalSeedSync(
        work_dir=work_dir,
        external_seed_dir=external_seed_dir,
        sync_name=sync_name,
        poll_interval=poll_interval,
        max_seed_size=max_seed_size,
        logger=logger,
    )
    syncer.start()
    return syncer
