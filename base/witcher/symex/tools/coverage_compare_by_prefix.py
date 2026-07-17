#!/usr/bin/env python3
import argparse
import json
import os
from typing import Any, Dict, Iterable, List, Set, Tuple


def _safe_load_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def _priority(value: Any) -> int:
    if value == 1:
        return 3
    if value == -1:
        return 2
    if value == -2:
        return 1
    return 0


def _normalize_path(path: str) -> str:
    s = str(path or "").strip()
    if not s:
        return ""
    s = s.replace("\\", "/")
    while "//" in s:
        s = s.replace("//", "/")
    return s


def _iter_cc_json_files(root_dir: str) -> Iterable[str]:
    for current_root, _, files in os.walk(root_dir):
        for name in files:
            if name.endswith(".cc.json"):
                yield os.path.join(current_root, name)


def _merge_coverage(base: Dict[str, Dict[int, int]], delta: Any) -> Dict[str, Dict[int, int]]:
    if not isinstance(delta, dict):
        return base
    for raw_file_path, raw_lines in delta.items():
        if not isinstance(raw_lines, dict):
            continue
        file_path = _normalize_path(str(raw_file_path))
        if not file_path:
            continue
        file_bucket = base.setdefault(file_path, {})
        for raw_ln, raw_val in raw_lines.items():
            try:
                line_no = int(raw_ln)
                value = int(raw_val)
            except Exception:
                continue
            current = file_bucket.get(line_no)
            if current is None or _priority(value) > _priority(current):
                file_bucket[line_no] = value
    return base


def _collect_merged_coverage(root_dir: str) -> Tuple[Dict[str, Dict[int, int]], int]:
    merged: Dict[str, Dict[int, int]] = {}
    file_count = 0
    for path in _iter_cc_json_files(root_dir):
        obj = _safe_load_json(path)
        if not isinstance(obj, dict):
            continue
        _merge_coverage(merged, obj)
        file_count += 1
    return merged, file_count


def _classify_prefix(file_path: str) -> str:
    path = _normalize_path(file_path)
    if not path:
        return "/"

    drive, tail = os.path.splitdrive(path)
    tail = tail.lstrip("/")
    parts = [part for part in tail.split("/") if part]

    if len(parts) >= 2:
        prefix = "/" + parts[0] + "/" + parts[1] + "/"
    elif len(parts) == 1:
        prefix = "/" + parts[0] + "/"
    else:
        prefix = "/"

    if drive:
        return prefix
    return prefix


def _group_covered_lines(coverage: Dict[str, Dict[int, int]]) -> Dict[str, Set[Tuple[str, int]]]:
    grouped: Dict[str, Set[Tuple[str, int]]] = {}
    for file_path, lines in coverage.items():
        if not isinstance(lines, dict):
            continue
        prefix = _classify_prefix(file_path)
        bucket = grouped.setdefault(prefix, set())
        for line_no, value in lines.items():
            if value == 1:
                bucket.add((file_path, int(line_no)))
    return grouped


def _format_table(
    rows: List[Tuple[str, int, int, int, int, int]],
    label_a: str,
    label_b: str,
) -> str:
    header_group = "Category"
    header_a = f"{label_a} Only"
    header_common = "Shared"
    header_b = f"{label_b} Only"
    header_total_a = f"{label_a} Total"
    header_total_b = f"{label_b} Total"

    group_width = max(len(header_group), *(len(group) for group, _, _, _, _, _ in rows)) if rows else len(header_group)
    a_width = max(len(header_a), *(len(str(a_only)) for _, a_only, _, _, _, _ in rows)) if rows else len(header_a)
    common_width = max(len(header_common), *(len(str(common)) for _, _, common, _, _, _ in rows)) if rows else len(header_common)
    b_width = max(len(header_b), *(len(str(b_only)) for _, _, _, b_only, _, _ in rows)) if rows else len(header_b)
    total_a_width = max(len(header_total_a), *(len(str(total_a)) for _, _, _, _, total_a, _ in rows)) if rows else len(header_total_a)
    total_b_width = max(len(header_total_b), *(len(str(total_b)) for _, _, _, _, _, total_b in rows)) if rows else len(header_total_b)

    lines = [
        f"{header_group:<{group_width}}  {header_a:>{a_width}}  {header_common:>{common_width}}  {header_b:>{b_width}}  {header_total_a:>{total_a_width}}  {header_total_b:>{total_b_width}}"
    ]
    for group, a_only, common, b_only, total_a, total_b in rows:
        lines.append(
            f"{group:<{group_width}}  {a_only:>{a_width}}  {common:>{common_width}}  {b_only:>{b_width}}  {total_a:>{total_a_width}}  {total_b:>{total_b_width}}"
        )
    return "\n".join(lines) + "\n"


def _build_rows(
    grouped_a: Dict[str, Set[Tuple[str, int]]],
    grouped_b: Dict[str, Set[Tuple[str, int]]],
) -> List[Tuple[str, int, int, int, int, int]]:
    rows: List[Tuple[str, int, int, int, int, int]] = []
    all_groups = sorted(set(grouped_a.keys()) | set(grouped_b.keys()))
    for group in all_groups:
        lines_a = grouped_a.get(group, set())
        lines_b = grouped_b.get(group, set())
        common = len(lines_a & lines_b)
        a_only = len(lines_a - lines_b)
        b_only = len(lines_b - lines_a)
        total_a = len(lines_a)
        total_b = len(lines_b)
        rows.append((group, a_only, common, b_only, total_a, total_b))
    return rows


def _format_summary_table(
    rows: List[Tuple[str, int, int, int, int, int]],
    label_a: str,
    label_b: str,
    total_a: int,
    total_b: int,
) -> str:
    header_a = f"{label_a} Only"
    header_common = "Shared"
    header_b = f"{label_b} Only"
    header_total_a = f"{label_a} Total"
    header_total_b = f"{label_b} Total"

    sum_a_only = sum(a_only for _, a_only, _, _, _, _ in rows)
    sum_common = sum(common for _, _, common, _, _, _ in rows)
    sum_b_only = sum(b_only for _, _, _, b_only, _, _ in rows)

    widths = [
        max(len(header_a), len(str(sum_a_only))),
        max(len(header_common), len(str(sum_common))),
        max(len(header_b), len(str(sum_b_only))),
        max(len(header_total_a), len(str(total_a))),
        max(len(header_total_b), len(str(total_b))),
    ]

    header_line = "  ".join(
        [
            f"{header_a:>{widths[0]}}",
            f"{header_common:>{widths[1]}}",
            f"{header_b:>{widths[2]}}",
            f"{header_total_a:>{widths[3]}}",
            f"{header_total_b:>{widths[4]}}",
        ]
    )
    value_line = "  ".join(
        [
            f"{sum_a_only:>{widths[0]}}",
            f"{sum_common:>{widths[1]}}",
            f"{sum_b_only:>{widths[2]}}",
            f"{total_a:>{widths[3]}}",
            f"{total_b:>{widths[4]}}",
        ]
    )
    return header_line + "\n" + value_line + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare all .cc.json coverage files under two directories and summarize covered-line differences by the first two source-path segments."
    )
    parser.add_argument("dir_a", help="Directory A")
    parser.add_argument("dir_b", help="Directory B")
    parser.add_argument(
        "--output",
        default="coverage_compare_by_prefix.txt",
        help="Output table path. Defaults to the current working directory.",
    )
    parser.add_argument("--label-a", default="Directory A", help="Prefix for column A headers in the table")
    parser.add_argument("--label-b", default="Directory B", help="Prefix for column B headers in the table")
    args = parser.parse_args()

    dir_a = os.path.abspath(args.dir_a)
    dir_b = os.path.abspath(args.dir_b)
    if not os.path.isdir(dir_a):
        print(f"Directory does not exist: {dir_a}")
        return 2
    if not os.path.isdir(dir_b):
        print(f"Directory does not exist: {dir_b}")
        return 2

    output_path = args.output
    if not os.path.isabs(output_path):
        output_path = os.path.abspath(output_path)

    coverage_a, count_a = _collect_merged_coverage(dir_a)
    coverage_b, count_b = _collect_merged_coverage(dir_b)

    grouped_a = _group_covered_lines(coverage_a)
    grouped_b = _group_covered_lines(coverage_b)
    rows = _build_rows(grouped_a, grouped_b)
    total_a = sum(len(lines) for lines in grouped_a.values())
    total_b = sum(len(lines) for lines in grouped_b.values())
    table_text = _format_table(rows, args.label_a, args.label_b)
    summary_text = _format_summary_table(rows, args.label_a, args.label_b, total_a, total_b)
    output_text = table_text + "\n" + summary_text

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(output_text)

    print(f"Directory A: {dir_a}")
    print(f"Directory B: {dir_b}")
    print(f"Coverage files in A: {count_a}")
    print(f"Coverage files in B: {count_b}")
    print(f"Output file: {output_path}")
    print("")
    print(output_text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
