import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


_ID_RE = re.compile(r"id:(\d+)")
_SRC_RE = re.compile(r"(?:^|,)src:(\d+)(?:,|$)")


def _parse_int(m) -> Optional[int]:
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _parse_seed_id(name: str) -> Optional[int]:
    return _parse_int(_ID_RE.search(name or ""))


def _parse_src_id(name: str) -> Optional[int]:
    return _parse_int(_SRC_RE.search(name or ""))


def list_queue_dirs(work_dir: str) -> List[str]:
    wd = Path(work_dir)
    out = []
    for p in sorted(wd.glob("fuzzer-*")) + sorted(wd.glob("fuzzer-master")):
        qd = p / "queue"
        if qd.is_dir():
            out.append(str(qd))
    return out


def _iter_queue_entries(queue_dir: str) -> List[Tuple[str, float]]:
    qd = Path(queue_dir)
    out = []
    if not qd.is_dir():
        return out
    for p in qd.iterdir():
        if not p.is_file():
            continue
        nm = p.name
        if not nm.startswith("id:"):
            continue
        try:
            mt = p.stat().st_mtime
        except Exception:
            mt = 0.0
        out.append((str(p), float(mt)))
    return out


def pick_preferred_seed(queue_dir: str, processed_ids: Optional[Dict[int, int]] = None) -> Optional[str]:
    processed_ids = processed_ids or {}
    entries = _iter_queue_entries(queue_dir)
    if not entries:
        return None

    by_id: Dict[int, Tuple[str, float]] = {}
    src_counts: Dict[int, int] = {}
    src_newest_child_mtime: Dict[int, float] = {}

    for path, mt in entries:
        name = os.path.basename(path)
        sid = _parse_seed_id(name)
        if sid is not None and sid not in by_id:
            by_id[sid] = (path, mt)
        src = _parse_src_id(name)
        if src is None:
            continue
        src_counts[src] = int(src_counts.get(src, 0)) + 1
        prev = float(src_newest_child_mtime.get(src, 0.0))
        if mt > prev:
            src_newest_child_mtime[src] = mt

    best = None
    best_key = None

    for pid, cnt in src_counts.items():
        if int(processed_ids.get(int(pid), 0)) > 0:
            continue
        parent = by_id.get(int(pid))
        if not parent:
            continue
        parent_path, parent_mtime = parent
        child_mtime = float(src_newest_child_mtime.get(int(pid), 0.0))
        key = (int(cnt), float(child_mtime), float(parent_mtime))
        if best is None or key > best_key:
            best = parent_path
            best_key = key

    if best:
        return best

    src_entries = []
    orig_entries = []
    for path, mt in entries:
        name = os.path.basename(path)
        sid = _parse_seed_id(name)
        if sid is None:
            continue
        if int(processed_ids.get(int(sid), 0)) > 0:
            continue
        if _parse_src_id(name) is not None:
            src_entries.append((path, mt))
        else:
            orig_entries.append((path, mt))

    def pick_latest(xs):
        if not xs:
            return None
        xs.sort(key=lambda t: float(t[1]))
        return xs[-1][0]

    return pick_latest(src_entries) or pick_latest(orig_entries)
