#!/usr/bin/env python3
import argparse
import glob
import json
import os
import shutil
import time
from typing import Any, Dict, List, Tuple


def _now() -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    except Exception:
        return "unknown"


def _write_json_atomic(path: str, obj: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def _safe_load_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def priority(v: Any) -> int:
    if v == 1:
        return 3
    if v == -1:
        return 2
    if v == -2:
        return 1
    return 0


def merge_coverage(base: Any, delta: Any) -> Dict[str, Any]:
    if not isinstance(base, dict):
        base = {}
    if not isinstance(delta, dict):
        return base
    for file_path, lines in delta.items():
        if not isinstance(lines, dict):
            continue
        if file_path not in base or not isinstance(base.get(file_path), dict):
            base[file_path] = lines
            continue
        for ln, val in lines.items():
            ln_str = str(ln)
            if ln_str not in base[file_path]:
                base[file_path][ln_str] = val
            else:
                if priority(val) > priority(base[file_path][ln_str]):
                    base[file_path][ln_str] = val
    return base


def _snapshot_candidates_in_dir(d: str) -> List[str]:
    patterns = [
        os.path.join(d, "coverage__*.cc.json"),
        os.path.join(d, "coverage_*.cc.json"),
        os.path.join(d, "*.cc.json"),
    ]
    out: List[str] = []
    for p in patterns:
        out.extend(glob.glob(p))
    seen = set()
    uniq: List[str] = []
    for f in out:
        if f not in seen:
            seen.add(f)
            uniq.append(f)
    return uniq


def _collect_snapshot_files(results_dir: str) -> List[str]:
    files: List[str] = []
    files.extend(_snapshot_candidates_in_dir(results_dir))
    try:
        children = os.listdir(results_dir)
    except Exception:
        children = []
    for name in children:
        p = os.path.join(results_dir, name)
        if not os.path.isdir(p):
            continue
        if not name.startswith("tr"):
            continue
        cov_snap = os.path.join(p, "coverage_snapshots")
        if os.path.isdir(cov_snap):
            files.extend(_snapshot_candidates_in_dir(cov_snap))
        else:
            files.extend(_snapshot_candidates_in_dir(p))
    files = [f for f in files if os.path.isfile(f)]
    return sorted(set(files))


def _file_sig(path: str) -> Tuple[int, int]:
    try:
        st = os.stat(path)
        return int(st.st_size), int(st.st_mtime)
    except Exception:
        return 0, 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dir", help="Witcher run results directory (contains tr*_... entry dirs)")
    parser.add_argument("--output", default="coverage_total.cc.json", help="Output total coverage file name or path")
    parser.add_argument("--state", default=".coverage_total.state.json", help="State file name or path")
    parser.add_argument("--verbose", action="store_true", help="Print progress")
    args = parser.parse_args()

    results_dir = os.path.abspath(args.results_dir)
    if not os.path.isdir(results_dir):
        return 2

    output_path = args.output
    if not os.path.isabs(output_path):
        output_path = os.path.join(results_dir, output_path)

    state_path = args.state
    if not os.path.isabs(state_path):
        state_path = os.path.join(results_dir, state_path)

    state_obj = _safe_load_json(state_path)
    processed: Dict[str, Any] = {}
    if isinstance(state_obj, dict) and isinstance(state_obj.get("processed"), dict):
        processed = dict(state_obj.get("processed") or {})

    global_cov: Any = _safe_load_json(output_path)
    if not isinstance(global_cov, dict):
        global_cov = {}

    all_snaps = _collect_snapshot_files(results_dir)
    output_mode = "none"

    if len(all_snaps) == 1:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
        shutil.copyfile(all_snaps[0], output_path)
        output_mode = "copy_single"
        if args.verbose:
            print(
                json.dumps(
                    {
                        "results_dir": results_dir,
                        "output": output_path,
                        "state": state_path,
                        "snapshots_found": 1,
                        "snapshots_to_merge": 0,
                        "snapshots_merged": 0,
                        "output_mode": output_mode,
                        "output_exists": bool(os.path.isfile(output_path)),
                    },
                    ensure_ascii=False,
                )
            )
        return 0
    if all_snaps and not os.path.isfile(output_path):
        processed = {}

    to_merge: List[str] = []
    for f in all_snaps:
        rel = os.path.relpath(f, results_dir)
        size, mtime = _file_sig(f)
        prev = processed.get(rel)
        if not isinstance(prev, dict) or int(prev.get("size") or -1) != size or int(prev.get("mtime") or -1) != mtime:
            to_merge.append(f)

    if not to_merge and all_snaps and not os.path.isfile(output_path):
        to_merge = all_snaps[:]

    merged = 0
    for f in to_merge:
        delta = _safe_load_json(f)
        if not isinstance(delta, dict):
            continue
        global_cov = merge_coverage(global_cov, delta)
        rel = os.path.relpath(f, results_dir)
        size, mtime = _file_sig(f)
        processed[rel] = {"size": int(size), "mtime": int(mtime)}
        merged += 1

    if merged == 0 and all_snaps and not os.path.isfile(output_path):
        newest = max(all_snaps, key=lambda p: _file_sig(p)[1])
        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
        shutil.copyfile(newest, output_path)
        output_mode = "copy_fallback"

    if merged > 0:
        _write_json_atomic(output_path, global_cov)
        _write_json_atomic(
            state_path,
            {
                "ts": _now(),
                "results_dir": results_dir,
                "output": os.path.basename(output_path),
                "merged_files": int(merged),
                "processed": processed,
            },
        )

    if args.verbose:
        print(
            json.dumps(
                {
                    "results_dir": results_dir,
                    "output": output_path,
                    "state": state_path,
                    "snapshots_found": int(len(all_snaps)),
                    "snapshots_to_merge": int(len(to_merge)),
                    "snapshots_merged": int(merged),
                "output_mode": output_mode,
                    "output_exists": bool(os.path.isfile(output_path)),
                },
                ensure_ascii=False,
            )
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
