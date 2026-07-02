#!/usr/bin/env python3
import argparse
import json
import os
from typing import Any, Dict, List, Tuple


def _safe_load_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def _coverage_ratio(obj: Any) -> Tuple[int, int, float]:
    if not isinstance(obj, dict):
        return 0, 0, 0.0
    total = 0
    covered = 0
    for file_path, lines in obj.items():
        if file_path.endswith("/enable_cc.php") or file_path.endswith("\\enable_cc.php") or file_path == "enable_cc.php":
            continue
        if not isinstance(lines, dict):
            continue
        for _, v in lines.items():
            total += 1
            if v == 1:
                covered += 1
    ratio = (float(covered) / float(total)) if total > 0 else 0.0
    return covered, total, ratio


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root_dir", help="Directory to scan recursively for coverage_total.cc.json")
    parser.add_argument("--output", default="coverage_total.stats.txt", help="Output file name or path")
    args = parser.parse_args()

    root_dir = os.path.abspath(args.root_dir)
    if not os.path.isdir(root_dir):
        return 2

    out_path = args.output
    if not os.path.isabs(out_path):
        out_path = os.path.join(root_dir, out_path)

    found: List[str] = []
    for r, _, files in os.walk(root_dir):
        for fn in files:
            if fn == "coverage_total.cc.json":
                found.append(os.path.join(r, fn))

    lines_out: List[str] = []
    for p in sorted(found):
        obj = _safe_load_json(p)
        covered, total, ratio = _coverage_ratio(obj)
        rel = os.path.relpath(p, root_dir)
        lines_out.append(f"{rel}\t{ratio:.6f}\t{covered}\t{total}")

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_out) + ("\n" if lines_out else ""))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
