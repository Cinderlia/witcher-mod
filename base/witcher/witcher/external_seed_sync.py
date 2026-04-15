import hashlib
import os
import re
import threading
import time
from typing import Dict, Optional, Set


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
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen_hashes: Set[str] = set()
        self._seen_paths: Dict[str, float] = {}
        self._next_id = self._init_next_id()

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

            digest = hashlib.sha1(data).hexdigest()
            if digest in self._seen_hashes:
                continue

            self._seen_hashes.add(digest)
            out_name = f"id:{self._next_id:06d},src:extseed"
            self._next_id += 1
            out_path = os.path.join(self.sync_queue_dir, out_name)
            with open(out_path, "wb") as wf:
                wf.write(data)
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
