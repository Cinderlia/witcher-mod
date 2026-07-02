import argparse
import json
import os
try:
    from dataclasses import asdict, dataclass
except Exception:
    from compat_dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class UrlGroup:
    base: str
    count: int
    keys: list[str]
    urls: list[str]


@dataclass(frozen=True)
class GoSpiderReport:
    input_path: str
    generated_at_utc: str
    url_with_params_count: int
    groups: list[UrlGroup]
    urls: list[str]


def _extract_last_segment(line: str) -> str:
    parts = [p.strip() for p in (line or "").split(" - ") if p.strip()]
    return parts[-1] if parts else ""


def _parse_param_keys(query: str) -> list[str]:
    keys: list[str] = []
    for seg in (query or "").split("&"):
        seg = seg.strip()
        if not seg:
            continue
        if "=" in seg:
            k = seg.split("=", 1)[0].strip()
        else:
            k = seg
        if k:
            keys.append(k)
    return keys


def _base_allowed(url: str) -> bool:
    s = urlsplit(url)
    base = s._replace(query="", fragment="").geturl()
    path = urlsplit(base).path or ""
    tail = path.rsplit("/", 1)[-1]
    if not tail:
        return True
    if "." not in tail:
        return True
    ext = tail.rsplit(".", 1)[-1].lower()
    return ext == "php"


def _group_urls(urls: list[str]) -> list[UrlGroup]:
    base_to_keys: dict[str, set[str]] = {}
    base_to_urls: dict[str, set[str]] = {}
    for u in urls:
        s = urlsplit(u)
        base = s._replace(query="", fragment="").geturl()
        base_to_urls.setdefault(base, set()).add(u)
        keys = _parse_param_keys(s.query)
        if keys:
            base_to_keys.setdefault(base, set()).update(keys)
        else:
            base_to_keys.setdefault(base, set())
    groups = []
    for base, urls_set in base_to_urls.items():
        keys = sorted(base_to_keys.get(base, set()))
        urls_list = sorted(urls_set)
        groups.append(UrlGroup(base=base, count=int(len(urls_list)), keys=keys, urls=urls_list))
    groups.sort(key=lambda x: (-x.count, x.base))
    return groups


def load_gospider_lines(input_path: str) -> list[str]:
    if not input_path or not os.path.exists(input_path):
        return []
    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        return [x.rstrip("\n") for x in f]


def compute_gospider_report(input_path: str) -> GoSpiderReport:
    lines = load_gospider_lines(input_path)
    urls_with_params_set: set[str] = set()

    for line in lines:
        if line.startswith("[form]"):
            u = _extract_last_segment(line)
            if "?" in u and _base_allowed(u):
                urls_with_params_set.add(u)
        elif line.startswith("[url]"):
            u = _extract_last_segment(line)
            if "?" in u and _base_allowed(u):
                urls_with_params_set.add(u)

    urls_with_params = sorted(urls_with_params_set)
    groups = _group_urls(urls_with_params)

    return GoSpiderReport(
        input_path=str(input_path),
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        url_with_params_count=int(len(urls_with_params)),
        groups=groups,
        urls=urls_with_params,
    )


def to_report_dict(report: GoSpiderReport) -> dict[str, Any]:
    return asdict(report)


def write_gospider_report(report: GoSpiderReport, out_dir: str) -> dict[str, str]:
    out_dir = (out_dir or "").strip() or "."
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "gospider_report.json")
    txt_path = os.path.join(out_dir, "gospider_report.txt")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(to_report_dict(report), f, ensure_ascii=False, indent=2)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"input={report.input_path}\n")
        f.write(f"generated_at_utc={report.generated_at_utc}\n")
        f.write(f"url_with_params_count={report.url_with_params_count}\n")
        f.write(f"group_count={len(report.groups)}\n")
        f.write("\n")
        f.write("url_groups:\n")
        for g in report.groups:
            keys = ",".join(g.keys) if g.keys else "-"
            f.write(f"{g.count}\t{g.base}\t{keys}\n")
            for u in g.urls:
                f.write(f"\t{u}\n")

    return {"json": json_path, "txt": txt_path}


def run_gospider_report(input_path: str, out_dir: str) -> dict[str, Any]:
    report = compute_gospider_report(input_path)
    out_paths = write_gospider_report(report, out_dir)
    return {"report": to_report_dict(report), "outputs": out_paths}


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gospider_report")
    p.add_argument("input", help="输入 gospider 结果文件路径")
    p.add_argument("output_dir", help="输出目录")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    run_gospider_report(args.input, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
