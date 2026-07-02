import argparse
import json
import os
import sys
try:
    from dataclasses import asdict, dataclass
except Exception:
    from compat_dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from if_branch_coverage.coverage_parser import build_coverage_index, load_coverage
from if_branch_coverage.if_scope import get_if_branch_lines, get_if_file_path, is_ast_if
from utils.cpg_utils.graph_mapping import load_ast_edges, load_nodes, norm_nodes_path, resolve_top_id, safe_int


@dataclass(frozen=True)
class FileIfCoverage:
    path: str
    if_total: int
    if_covered_all: int

    @property
    def rate(self) -> float:
        t = self.if_total
        return float(self.if_covered_all / t) if t else 0.0


@dataclass(frozen=True)
class IfCoverageReport:
    input_path: str
    generated_at_utc: str
    if_total: int
    if_covered_all: int
    files: list[FileIfCoverage]

    @property
    def rate(self) -> float:
        t = self.if_total
        return float(self.if_covered_all / t) if t else 0.0


def _default_nodes_path() -> str:
    return os.path.join(_BASE_DIR, "input", "nodes.csv")


def _default_rels_path() -> str:
    return os.path.join(_BASE_DIR, "input", "rels.csv")


def _build_if_ids_by_file(
    nodes: dict[int, dict],
    parent_of: dict[int, int],
    top_id_to_file: dict[int, str],
    target_files: set[str],
) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {p: [] for p in target_files}
    for nid, nx in nodes.items():
        if (nx.get("type") or "") != "AST_IF":
            continue
        top = resolve_top_id(int(nid), parent_of, nodes, top_id_to_file)
        if top is None:
            continue
        file_path = (top_id_to_file.get(int(top)) or "").strip()
        if not file_path:
            continue
        if file_path not in target_files:
            continue
        out[file_path].append(int(nid))
    return out


def _check_if_covered(
    if_id: int,
    nodes: dict[int, dict],
    parent_of: dict[int, int],
    children_of: dict[int, set[int]],
    top_id_to_file: dict[int, str],
    coverage_index: dict[str, dict[int, int]],
) -> bool:
    nid = safe_int(if_id)
    if nid is None:
        return False
    if not is_ast_if(nid, nodes):
        return False
    file_path = get_if_file_path(nid, parent_of, nodes, top_id_to_file)
    if not file_path:
        return False
    true_lines, false_lines = get_if_branch_lines(nid, nodes, children_of)
    true_covered = bool(
        any(coverage_index.get(file_path, {}).get(int(ln)) == 1 for ln in (true_lines or []))
    )
    if false_lines:
        false_covered = bool(
            any(coverage_index.get(file_path, {}).get(int(ln)) == 1 for ln in (false_lines or []))
        )
        return bool(true_covered and false_covered)
    return bool(true_covered)


def compute_if_coverage(
    cc_json_path: str,
    *,
    nodes_path: str | None = None,
    rels_path: str | None = None,
) -> IfCoverageReport:
    coverage_index = build_coverage_index(load_coverage(cc_json_path))
    target_files = set(coverage_index.keys())
    nodes_path = nodes_path or _default_nodes_path()
    rels_path = rels_path or _default_rels_path()
    nodes, top_id_to_file = load_nodes(nodes_path)
    parent_of, children_of = load_ast_edges(rels_path)

    if_ids_by_file = _build_if_ids_by_file(nodes, parent_of, top_id_to_file, target_files)

    files: list[FileIfCoverage] = []
    total_if = 0
    covered_all = 0

    for file_path in sorted(target_files):
        if_ids = if_ids_by_file.get(file_path) or []
        file_total = 0
        file_covered = 0
        for if_id in if_ids:
            file_total += 1
            if _check_if_covered(if_id, nodes, parent_of, children_of, top_id_to_file, coverage_index):
                file_covered += 1
        total_if += file_total
        covered_all += file_covered
        if file_total > 0:
            files.append(
                FileIfCoverage(
                    path=file_path,
                    if_total=int(file_total),
                    if_covered_all=int(file_covered),
                )
            )

    files.sort(key=lambda x: (x.rate, x.if_total, x.path))

    return IfCoverageReport(
        input_path=str(cc_json_path),
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        if_total=int(total_if),
        if_covered_all=int(covered_all),
        files=files,
    )


def to_report_dict(report: IfCoverageReport) -> dict[str, Any]:
    obj = asdict(report)
    obj["rate"] = report.rate
    for f in obj.get("files") or []:
        total = safe_int(f.get("if_total")) or 0
        covered = safe_int(f.get("if_covered_all")) or 0
        f["rate"] = float(covered / total) if total else 0.0
    return obj


def write_if_coverage_report(report: IfCoverageReport, out_dir: str) -> dict[str, str]:
    out_dir = (out_dir or "").strip() or "."
    os.makedirs(out_dir, exist_ok=True)

    report_obj = to_report_dict(report)
    json_path = os.path.join(out_dir, "if_coverage_report.json")
    txt_path = os.path.join(out_dir, "if_coverage_report.txt")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_obj, f, ensure_ascii=False, indent=2)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"input={report.input_path}\n")
        f.write(f"generated_at_utc={report.generated_at_utc}\n")
        f.write(f"if_total={report.if_total}\n")
        f.write(f"if_covered_all={report.if_covered_all}\n")
        f.write(f"rate={report.rate:.6f}\n")
        f.write("\n")
        f.write("all_files_by_rate:\n")
        for item in report.files:
            f.write(
                f"{item.rate:.6f}\tif_covered_all={item.if_covered_all}\tif_total={item.if_total}\t{item.path}\n"
            )

    return {"json": json_path, "txt": txt_path}


def run_if_coverage(cc_json_path: str, out_dir: str) -> dict[str, Any]:
    report = compute_if_coverage(cc_json_path)
    out_paths = write_if_coverage_report(report, out_dir)
    return {"report": to_report_dict(report), "outputs": out_paths}


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cc_if_coverage")
    p.add_argument("input", help="输入 .cc.json 覆盖率文件路径")
    p.add_argument("output_dir", help="输出目录")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    run_if_coverage(args.input, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
