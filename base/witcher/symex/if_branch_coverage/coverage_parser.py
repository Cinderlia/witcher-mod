"""
Parse line-coverage reports (cc.json) into fast lookup structures for branch coverage checks.
"""

import glob
import json
import os
from typing import Dict, Set

from utils.cpg_utils.graph_mapping import norm_nodes_path, safe_int


def find_cc_json(input_dir: str) -> str:
    if not input_dir:
        return ""
    pattern = os.path.join(input_dir, "*.cc.json")
    matches = sorted(glob.glob(pattern))
    return matches[0] if matches else ""


def load_coverage(cc_path: str) -> dict:
    if not cc_path or not os.path.exists(cc_path):
        return {}
    try:
        with open(cc_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def build_coverage_index(raw: dict) -> Dict[str, Dict[int, int]]:
    """Normalize raw coverage payload into {normalized_path: {line: status}}."""
    out: Dict[str, Dict[int, int]] = {}
    for path, line_map in (raw or {}).items():
        if not isinstance(line_map, dict):
            continue
        norm = norm_nodes_path(path)
        if not norm:
            continue
        lines: Dict[int, int] = {}
        for k, v in line_map.items():
            ln = safe_int(k)
            st = safe_int(v)
            if ln is None or st is None:
                continue
            lines[int(ln)] = int(st)
        if lines:
            out[norm] = lines
    return out


def has_covered_line(coverage_index: Dict[str, Dict[int, int]], norm_path: str, lines: Set[int]) -> bool:
    line_map = coverage_index.get(norm_path) or {}
    for ln in lines or []:
        li = safe_int(ln)
        if li is None:
            continue
        if line_map.get(int(li)) == 1:
            return True
    return False
