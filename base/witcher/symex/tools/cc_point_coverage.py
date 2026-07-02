import argparse
import json
import os
try:
    from dataclasses import asdict, dataclass
except Exception:
    from compat_dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote


@dataclass(frozen=True)
class FilePointCoverage:
    path: str
    covered: int
    uncovered: int
    dead: int

    @property
    def total(self) -> int:
        return int(self.covered + self.uncovered)

    @property
    def rate(self) -> float:
        t = self.total
        return float(self.covered / t) if t else 0.0


@dataclass(frozen=True)
class PointCoverageReport:
    input_path: str
    generated_at_utc: str
    covered: int
    uncovered: int
    dead: int
    files: list[FilePointCoverage]

    @property
    def total(self) -> int:
        return int(self.covered + self.uncovered)

    @property
    def rate(self) -> float:
        t = self.total
        return float(self.covered / t) if t else 0.0


def _safe_int(v: Any) -> int | None:
    try:
        return int(v)
    except Exception:
        return None


def _normalize_cc_path(p: str) -> str:
    s = (p or "").strip()
    if not s:
        return ""
    s = unquote(s)
    s = s.replace("\\", "/")
    while "//" in s:
        s = s.replace("//", "/")
    return s


def load_cc_json(cc_json_path: str) -> dict[str, dict[int, int]]:
    if not cc_json_path or not os.path.exists(cc_json_path):
        return {}
    try:
        with open(cc_json_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}

    out: dict[str, dict[int, int]] = {}
    for file_path, line_map in obj.items():
        if not isinstance(line_map, dict):
            continue
        norm_path = _normalize_cc_path(str(file_path))
        if not norm_path:
            continue
        out_line_map: dict[int, int] = {}
        for k, v in line_map.items():
            ln = _safe_int(k)
            st = _safe_int(v)
            if ln is None or st is None:
                continue
            out_line_map[int(ln)] = int(st)
        if out_line_map:
            out[norm_path] = out_line_map
    return out


def compute_point_coverage(raw: dict[str, dict[int, int]]) -> PointCoverageReport:
    files: list[FilePointCoverage] = []
    total_covered = 0
    total_uncovered = 0
    total_dead = 0

    for file_path, line_map in (raw or {}).items():
        covered = 0
        uncovered = 0
        dead = 0
        for _, st in (line_map or {}).items():
            if st == 1:
                covered += 1
            elif st == -1:
                uncovered += 1
            elif st == -2:
                dead += 1
        if covered or uncovered or dead:
            files.append(
                FilePointCoverage(
                    path=str(file_path),
                    covered=int(covered),
                    uncovered=int(uncovered),
                    dead=int(dead),
                )
            )
        total_covered += covered
        total_uncovered += uncovered
        total_dead += dead

    files.sort(key=lambda x: (x.rate, x.total, x.path))

    return PointCoverageReport(
        input_path="",
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        covered=int(total_covered),
        uncovered=int(total_uncovered),
        dead=int(total_dead),
        files=files,
    )


def to_report_dict(report: PointCoverageReport) -> dict[str, Any]:
    obj = asdict(report)
    obj["total"] = report.total
    obj["rate"] = report.rate
    for f in obj.get("files") or []:
        covered = _safe_int(f.get("covered")) or 0
        uncovered = _safe_int(f.get("uncovered")) or 0
        total = int(covered + uncovered)
        f["total"] = total
        f["rate"] = float(covered / total) if total else 0.0
    return obj


def write_point_coverage_report(report: PointCoverageReport, out_dir: str) -> dict[str, str]:
    out_dir = (out_dir or "").strip() or "."
    os.makedirs(out_dir, exist_ok=True)

    report_obj = to_report_dict(report)
    json_path = os.path.join(out_dir, "point_coverage_report.json")
    txt_path = os.path.join(out_dir, "point_coverage_report.txt")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_obj, f, ensure_ascii=False, indent=2)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"input={report.input_path}\n")
        f.write(f"generated_at_utc={report.generated_at_utc}\n")
        f.write(f"covered={report.covered}\n")
        f.write(f"uncovered={report.uncovered}\n")
        f.write(f"dead={report.dead}\n")
        f.write(f"total={report.total}\n")
        f.write(f"rate={report.rate:.6f}\n")
        f.write("\n")
        f.write("all_files_by_rate:\n")
        all_files = sorted(report.files, key=lambda x: (x.rate, x.total, x.path))
        for item in all_files:
            f.write(
                f"{item.rate:.6f}\tcovered={item.covered}\tuncovered={item.uncovered}\tdead={item.dead}\t{item.path}\n"
            )

    return {"json": json_path, "txt": txt_path}


def run_point_coverage(cc_json_path: str, out_dir: str) -> dict[str, Any]:
    raw = load_cc_json(cc_json_path)
    report = compute_point_coverage(raw)
    report = PointCoverageReport(
        input_path=str(cc_json_path),
        generated_at_utc=report.generated_at_utc,
        covered=report.covered,
        uncovered=report.uncovered,
        dead=report.dead,
        files=report.files,
    )
    out_paths = write_point_coverage_report(report, out_dir)
    return {"report": to_report_dict(report), "outputs": out_paths}


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cc_point_coverage")
    p.add_argument("input", help="输入 .cc.json 覆盖率文件路径")
    p.add_argument("output_dir", help="输出目录")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    run_point_coverage(args.input, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
