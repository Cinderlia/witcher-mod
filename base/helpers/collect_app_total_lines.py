#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from collections import Counter
from typing import Dict, Iterable, List, Optional, Set, Tuple


IGNORED_DIRS = {
    "vendor",
    "node_modules",
    "third_party",
    "dist",
    "build",
    "bower_components",
    ".git",
}

PHP_EXTENSIONS = {".php", ".inc", ".phtml", ".php5", ".php7", ".php8"}
APP_ROOT = "/app"
START_FLAG = "/tmp/start_test.dat"
COVERAGE_DIR = "/tmp/coverages"
SHM_COVERAGE_DIR = "/dev/shm/coverages"
SMALL_FILE_TIMEOUT_SEC = 3
LARGE_FILE_TIMEOUT_SEC = 5
LARGE_FILE_SIZE_BYTES = 200 * 1024
TARGET_PROJECT = "/app/xvwa"
DISABLE_DIR_EXCLUDES_FOR_TARGET = True


def safe_print(msg: str) -> None:
    s = str(msg)
    s = re.sub(r"runner_fallback_[^/\s]+\.cc\.json", "runner_fallback_*.cc.json", s)
    s = re.sub(r"\.wc_cov_runner_[^/\s]+\.php", ".wc_cov_runner_*.php", s)
    try:
        print(s)
        return
    except UnicodeEncodeError:
        pass
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    data = (s + "\n").encode(enc, errors="replace")
    out = getattr(sys.stdout, "buffer", None)
    if out is not None:
        out.write(data)
        out.flush()
    else:
        sys.stdout.write(data.decode(enc, errors="replace"))
        sys.stdout.flush()


def norm_path(path: str) -> str:
    return os.path.normpath(path).replace("\\", "/")


def is_ignored_path(path: str) -> bool:
    parts = [p for p in norm_path(path).split("/") if p]
    return any(part in IGNORED_DIRS for part in parts)


def map_alias_to_app(path: str) -> str:
    p = norm_path(path)
    if p.startswith("/var/www/html/"):
        return "/app/" + p[len("/var/www/html/") :]
    if p == "/var/www/html":
        return "/app"
    return p


def discover_projects(app_root: str) -> List[str]:
    projects: List[str] = []
    for entry in sorted(os.scandir(app_root), key=lambda e: e.name):
        if not entry.is_dir():
            continue
        if entry.name in IGNORED_DIRS:
            continue
        projects.append(entry.path)
    return projects


def scan_php_files(project_root: str, disable_ignored_dirs: bool = False) -> Tuple[List[str], Dict[str, int]]:
    php_files: List[str] = []
    skipped_dir_hits: Dict[str, int] = {}
    for root, dirs, files in os.walk(project_root):
        if not disable_ignored_dirs:
            removed = [d for d in dirs if d in IGNORED_DIRS]
            for d in removed:
                skipped_dir_hits[d] = skipped_dir_hits.get(d, 0) + 1
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for fn in files:
            if os.path.splitext(fn)[1].lower() not in PHP_EXTENSIONS:
                continue
            fpath = os.path.join(root, fn)
            if os.path.basename(fpath) == "coverage.php":
                continue
            php_files.append(norm_path(os.path.abspath(fpath)))
    php_files.sort()
    return php_files, skipped_dir_hits


def build_coverage_php_content() -> str:
    return """<?php
@set_time_limit(0);
@ini_set('display_errors', '0');
@error_reporting(E_ALL & ~E_WARNING & ~E_NOTICE);

$target = isset($argv[1]) ? $argv[1] : '';
if (!is_string($target) || $target === '' || !file_exists($target)) {
    exit(0);
}

try {
    ob_start();
    include $target;
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }
} catch (Throwable $e) {
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }
    fwrite(STDERR, "INCLUDE_ERROR: " . $e->getMessage() . PHP_EOL);
}
"""


def write_coverage_php(project_root: str) -> str:
    output_path = os.path.join(project_root, ".wc_cov_runner_" + str(uuid.uuid4()) + ".php")
    content = build_coverage_php_content()
    with open(output_path, "w", encoding="utf-8") as wf:
        wf.write(content)
    return output_path


def ensure_start_flag(flag_path: str) -> None:
    os.makedirs(os.path.dirname(flag_path), exist_ok=True)
    with open(flag_path, "a", encoding="utf-8"):
        pass


def wait_until_dir_empty(dir_path: str, sleep_sec: int = 5) -> None:
    while True:
        if not os.path.isdir(dir_path):
            return
        try:
            with os.scandir(dir_path) as it:
                has_any = any(True for _ in it)
        except Exception:
            return
        if not has_any:
            return
        safe_print(f"[INFO] wait for empty dir: {dir_path}, sleep {sleep_sec}s")
        time.sleep(sleep_sec)


def wait_until_no_project_entries(dir_path: str, project_prefix: str, sleep_sec: int = 5) -> None:
    while True:
        if not os.path.isdir(dir_path):
            return
        try:
            with os.scandir(dir_path) as it:
                has_project_entry = any(entry.name.startswith(project_prefix) for entry in it)
        except Exception:
            return
        if not has_project_entry:
            return
        safe_print(f"[INFO] wait for '{project_prefix}*' gone in {dir_path}, sleep {sleep_sec}s")
        time.sleep(sleep_sec)


def run_generated_coverage(
    php_bin: str,
    coverage_php_path: str,
    target_file: str,
    project_root: str,
    file_timeout_sec: int = SMALL_FILE_TIMEOUT_SEC,
) -> Tuple[int, str]:
    target_dir = os.path.dirname(target_file) or project_root
    cmd = [
        php_bin,
        "-d",
        "include_path=.:" + target_dir + ":" + project_root + ":/usr/share/php:/usr/share/pear",
        coverage_php_path,
        target_file,
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=target_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        out_b, err_b = proc.communicate(timeout=file_timeout_sec)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            out_b, err_b = proc.communicate(timeout=1)
        except Exception:
            out_b, err_b = b"", b""
        return 124, f"TIMEOUT({file_timeout_sec}s): {target_file}"

    out = out_b.decode("utf-8", errors="replace") if isinstance(out_b, bytes) else str(out_b or "")
    err = err_b.decode("utf-8", errors="replace") if isinstance(err_b, bytes) else str(err_b or "")
    merged = "\n".join([x for x in [out.strip(), err.strip()] if x]).strip()
    return proc.returncode, merged


def get_file_timeout_sec(file_path: str) -> int:
    try:
        size = os.path.getsize(file_path)
    except Exception:
        return SMALL_FILE_TIMEOUT_SEC
    if size >= LARGE_FILE_SIZE_BYTES:
        return LARGE_FILE_TIMEOUT_SEC
    return SMALL_FILE_TIMEOUT_SEC


def iter_coverage_files(coverage_dirs: List[str]) -> Iterable[str]:
    seen: Set[str] = set()
    for root in coverage_dirs:
        if not os.path.isdir(root):
            continue
        for cur_root, _, files in os.walk(root):
            for fn in files:
                if not fn.endswith(".cc.json"):
                    continue
                fpath = os.path.join(cur_root, fn)
                if fpath in seen:
                    continue
                seen.add(fpath)
                yield fpath


def load_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as rf:
            obj = json.load(rf)
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def count_lines_from_coverage(
    coverage_files: Iterable[str],
) -> Tuple[Dict[str, int], int, int, Set[str], Set[str]]:
    app_root_norm = norm_path(os.path.abspath(APP_ROOT)).rstrip("/")
    totals: Dict[str, int] = {}
    seen_lines_by_file: Dict[str, Set[int]] = {}
    raw_unique_files: Set[str] = set()
    filtered_unique_files: Set[str] = set()

    for cov_file in coverage_files:
        data = load_json(cov_file)
        if not isinstance(data, dict):
            continue
        for src_file, lines in data.items():
            if not isinstance(src_file, str) or not isinstance(lines, dict):
                continue
            raw_unique_files.add(norm_path(src_file))
            src_norm = norm_path(src_file)
            if not src_norm.startswith(app_root_norm + "/"):
                continue
            if is_ignored_path(src_norm):
                continue
            base = os.path.basename(src_norm)
            if base in {"enable_cc.php", "coverage.php"}:
                continue
            filtered_unique_files.add(src_norm)
            line_set = seen_lines_by_file.setdefault(src_norm, set())
            for ln in lines.keys():
                try:
                    line_set.add(int(ln))
                except Exception:
                    continue

    for src_file, line_set in seen_lines_by_file.items():
        rel = src_file[len(app_root_norm) + 1 :]
        top = rel.split("/", 1)[0] if rel else ""
        if not top:
            continue
        project_path = norm_path(os.path.join(app_root_norm, top))
        totals[project_path] = totals.get(project_path, 0) + len(line_set)
    return totals, len(raw_unique_files), len(filtered_unique_files), filtered_unique_files, raw_unique_files


def summarize_path_features(paths: Set[str], project_root: str, topn: int = 8) -> Tuple[List[Tuple[str, int]], List[Tuple[str, int]]]:
    ext_counter: Counter = Counter()
    dir_counter: Counter = Counter()
    p_root = norm_path(project_root).rstrip("/")
    for p in paths:
        pp = norm_path(p)
        ext = os.path.splitext(pp)[1].lower() or "<noext>"
        ext_counter[ext] += 1
        if pp.startswith(p_root + "/"):
            rel = pp[len(p_root) + 1 :]
        else:
            rel = pp
        first = rel.split("/", 1)[0] if rel else "."
        dir_counter[first] += 1
    return ext_counter.most_common(topn), dir_counter.most_common(topn)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate per-project coverage.php under /app, execute once, "
            "and print '<project_path>\\t<total_lines>' from coverage json files."
        )
    )
    parser.add_argument("--php-bin", default="php", help="PHP executable path")
    args = parser.parse_args()

    app_root = os.path.abspath(APP_ROOT)
    if not os.path.isdir(app_root):
        safe_print(f"ERROR: app root not found: {app_root}")
        return 2

    safe_print(f"[INFO] app_root={APP_ROOT}")
    safe_print(f"[INFO] coverage_dir={COVERAGE_DIR}")
    safe_print(f"[INFO] touch start flag: {START_FLAG}")
    ensure_start_flag(START_FLAG)

    target_project = norm_path(os.path.abspath(TARGET_PROJECT))
    if not os.path.isdir(target_project):
        safe_print(f"ERROR: target project not found: {target_project}")
        return 2
    projects = [target_project]
    safe_print(f"[INFO] target-only mode project={target_project}")
    project_prefix = "+app+xvwa"
    scanned_file_counts: Dict[str, int] = {}
    failed_files_by_project: Dict[str, Set[str]] = {}
    scanned_files_by_project: Dict[str, Set[str]] = {}
    for project in projects:
        wait_until_no_project_entries(SHM_COVERAGE_DIR, project_prefix=project_prefix, sleep_sec=5)
        safe_print(f"[INFO] scanning php files: {project}")
        disable_ignored = DISABLE_DIR_EXCLUDES_FOR_TARGET and norm_path(project) == norm_path(TARGET_PROJECT)
        php_files, skipped_dir_hits = scan_php_files(project, disable_ignored_dirs=disable_ignored)
        scanned_file_counts[project] = len(php_files)
        scanned_files_by_project[project] = set(php_files)
        failed_files_by_project[project] = set()
        safe_print(f"[DEBUG] dir_excludes_disabled={str(disable_ignored).lower()} skipped_dir_hits={skipped_dir_hits}")
        safe_print(f"[INFO] found {len(php_files)} files, generating temp runner")
        coverage_php = write_coverage_php(project)
        safe_print(f"[INFO] executing with runner: {coverage_php}")
        failed = 0
        last_progress = 0.0
        total = len(php_files)
        try:
            for idx, fpath in enumerate(php_files, start=1):
                now = time.time()
                if idx == 1 or idx == total or now - last_progress >= 5.0:
                    safe_print(f"[PROGRESS] project={project} {idx}/{total} file={fpath}")
                    last_progress = now
                rc, stderr = run_generated_coverage(
                    php_bin=args.php_bin,
                    coverage_php_path=coverage_php,
                    target_file=fpath,
                    project_root=project,
                    file_timeout_sec=get_file_timeout_sec(fpath),
                )
                if rc != 0:
                    failed += 1
                    failed_files_by_project[project].add(fpath)
                    if failed <= 3:
                        err = (stderr or "").strip().splitlines()
                        last = err[-1] if err else ""
                        safe_print(f"WARN: file failed project={project} rc={rc} file={fpath} {last}")
            safe_print(f"[INFO] done: {coverage_php} total_files={total} failed_files={failed}")
        finally:
            try:
                if os.path.exists(coverage_php):
                    os.remove(coverage_php)
                    safe_print(f"[INFO] removed temp runner: {coverage_php}")
            except Exception as ex:
                safe_print(f"WARN: failed to remove temp runner: {coverage_php} error={ex}")

    safe_print(f"[INFO] all projects executed, wait '{project_prefix}*' gone before final counting...")
    wait_until_no_project_entries(SHM_COVERAGE_DIR, project_prefix=project_prefix, sleep_sec=5)
    safe_print(f"[INFO] '{project_prefix}*' gone, sleep 10s before reading /tmp/coverages...")
    time.sleep(10)
    safe_print(f"[INFO] reading coverage files once from {COVERAGE_DIR}")
    coverage_json_files = list(iter_coverage_files([COVERAGE_DIR]))
    totals, raw_cov_file_count, filtered_cov_file_count, covered_filtered_files, covered_raw_files = count_lines_from_coverage(coverage_json_files)
    safe_print(f"[DEBUG] coverage_json_count={len(coverage_json_files)}")
    safe_print(f"[DEBUG] coverage_unique_files_raw={raw_cov_file_count}")
    safe_print(f"[DEBUG] coverage_unique_files_filtered={filtered_cov_file_count}")
    safe_print(f"[INFO] final project count: {len(projects)}")
    for project in projects:
        p = norm_path(os.path.abspath(project))
        scanned_count = scanned_file_counts.get(p, 0)
        safe_print(f"[DEBUG] scanned_php_files project={p} count={scanned_count}")
        scanned_set = scanned_files_by_project.get(p, set())
        covered_set = {f for f in covered_filtered_files if f.startswith(p + "/")}
        covered_raw_alias_to_app = {map_alias_to_app(f) for f in covered_raw_files}
        safe_print(f"[DEBUG] covered_files_in_project project={p} count={len(covered_set)}")
        missing_set = scanned_set - covered_set
        failed_set = failed_files_by_project.get(p, set())
        missing_failed = missing_set & failed_set
        missing_not_failed = missing_set - failed_set
        missing_in_ignored = {f for f in missing_not_failed if is_ignored_path(f)}
        missing_alias_match = {f for f in missing_not_failed if f in covered_raw_alias_to_app and f not in covered_set}
        missing_other = missing_not_failed - missing_in_ignored - missing_alias_match
        missing_equals_failed = missing_set == failed_set
        safe_print(
            f"[DEBUG] compare_missing_failed project={p} missing={len(missing_set)} failed={len(failed_set)} equal={str(missing_equals_failed).lower()}"
        )
        safe_print(
            f"[DEBUG] missing_buckets project={p} missing_failed={len(missing_failed)} missing_in_ignored={len(missing_in_ignored)} missing_alias_match={len(missing_alias_match)} missing_other={len(missing_other)}"
        )
        ext_top, dir_top = summarize_path_features(missing_set, p)
        safe_print(f"[DEBUG] missing_ext_top project={p} top={ext_top}")
        safe_print(f"[DEBUG] missing_dir_top project={p} top={dir_top}")
        safe_print(f"[DEBUG] missing_sample project={p} sample={sorted(list(missing_set))[:12]}")
        safe_print(f"[DEBUG] missing_other_sample project={p} sample={sorted(list(missing_other))[:12]}")
        safe_print(f"{p}\t{totals.get(p, 0)}")
    safe_print("[INFO] finished.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
