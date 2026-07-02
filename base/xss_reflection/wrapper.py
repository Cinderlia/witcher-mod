import json
import os
import shutil
import stat
import glob
import time
from typing import Dict, Optional

from .integration.seed_injector import generate_xss_seeds
from .integration.cgi_validator import validate_xss_seeds
from .integration.attack_runner import run_targeted_attacks
from .login_refresh import refresh_xss_login


def run_xss_flow(
    work_dir: str,
    output_dir_name: str = "xss_queue",
    max_seconds: float = None,
    result_storage_pathname: str = None,
    appdir: str = None,
    config_path: str = None,
) -> Dict[str, int]:
    debug_mode = False
    log_path = os.path.join(work_dir, "xss_reflection.log")
    deadline = None
    try:
        if max_seconds is not None and float(max_seconds) > 0:
            deadline = time.monotonic() + float(max_seconds)
    except Exception:
        deadline = None
    try:
        login_refresh = refresh_xss_login(work_dir, config_path=config_path, log_path=log_path)
        result = generate_xss_seeds(
            work_dir,
            output_dir_name=output_dir_name,
            deadline=deadline,
            session_cookie_name=login_refresh.get("session_cookie_name", ""),
            session_cookie_value=login_refresh.get("session_cookie_value", ""),
        )
        if deadline is not None and time.monotonic() >= deadline:
            return dict(result)
        validation = validate_xss_seeds(work_dir, output_dir_name=output_dir_name, deadline=deadline)
        if deadline is not None and time.monotonic() >= deadline:
            summary = dict(result)
            summary.update(validation)
            return summary
        attacks = run_targeted_attacks(work_dir, output_dir_name=output_dir_name, deadline=deadline)
        if not debug_mode:
            if deadline is not None and time.monotonic() >= deadline:
                summary = dict(result)
                summary.update(validation)
                summary.update(attacks)
                return summary
            collected = _collect_confirmed(
                work_dir,
                output_dir_name,
                deadline=deadline,
                result_storage_pathname=result_storage_pathname,
                appdir=appdir,
            )
            _log(log_path, f"Witcher-XSS collected_confirmed_unique={collected}")
        _log(
            log_path,
            f"Witcher-XSS summary scanned={result.get('seeds_scanned', 0)} "
            f"generated={result.get('seeds_generated', 0)} "
            f"executed={validation.get('executed', 0)} "
            f"reflected={validation.get('reflected', 0)} "
            f"attack_executed={attacks.get('attack_executed', 0)} "
            f"attack_confirmed={attacks.get('attack_confirmed', 0)} "
            f"attack_confirmed_unique={attacks.get('attack_confirmed_unique', 0)}",
        )
        summary = dict(result)
        summary.update(validation)
        summary.update(attacks)
        return summary
    except Exception as exp:
        _log(log_path, f"Witcher-XSS failed: {exp}")
        return {"seeds_scanned": 0, "seeds_generated": 0}


def _log(log_path: str, message: str) -> None:
    print(f"[Witcher-XSS] {message}")
    with open(log_path, "a", encoding="utf-8") as wf:
        wf.write(message + "\n")


def _collect_confirmed(
    work_dir: str,
    output_dir_name: str,
    deadline: float = None,
    result_storage_pathname: str = None,
    appdir: str = None,
) -> int:
    report_dir = _find_report_dir(work_dir)
    seed_crashes_dir = os.path.join(report_dir, "seed-crashes")
    target_dir = os.path.join(seed_crashes_dir, "xss-confirmed")
    os.makedirs(target_dir, exist_ok=True)
    _log(os.path.join(work_dir, "xss_reflection.log"), f"Witcher-XSS report_dir={report_dir}")

    saved = 0
    seen_hashes = set()
    fuzz_script_path = _find_fuzz_script(work_dir)
    encoded_url_path = _encode_result_storage_path(result_storage_pathname, appdir)
    for queue_root in _queue_roots(work_dir, output_dir_name):
        if deadline is not None and time.monotonic() >= deadline:
            break
        if not os.path.isdir(queue_root):
            continue
        for seed_dir in _seed_dirs(queue_root):
            if deadline is not None and time.monotonic() >= deadline:
                break
            confirmed_dir = os.path.join(seed_dir, "confirmed")
            if not os.path.isdir(confirmed_dir):
                continue
            source_seed = _load_source_seed(seed_dir)
            for name in os.listdir(confirmed_dir):
                if deadline is not None and time.monotonic() >= deadline:
                    break
                if name.endswith(".html") or name.endswith(".json") or name.endswith(".tmp"):
                    continue
                src = os.path.join(confirmed_dir, name)
                if os.path.isfile(src):
                    with open(src, "rb") as rf:
                        seed_hash = rf.read()
                    if seed_hash in seen_hashes:
                        continue
                    seen_hashes.add(seed_hash)
                    fid = len([n for n in os.listdir(target_dir) if n.startswith("id:") and not n.endswith(".sh")])
                    src_name = source_seed or name
                    if encoded_url_path:
                        crash_name = f"id:{fid:06},{encoded_url_path},src:{src_name},xss"
                    else:
                        crash_name = f"id:{fid:06},src:{src_name},xss"
                    dst = os.path.join(target_dir, crash_name)
                    shutil.copy2(src, dst)
                    if fuzz_script_path:
                        _write_repro_script(fuzz_script_path, dst)
                    saved += 1
    return saved


def _seed_dirs(queue_root: str):
    items = []
    for name in sorted(os.listdir(queue_root)):
        path = os.path.join(queue_root, name)
        if os.path.isdir(path):
            items.append(path)
    return items


def _find_fuzz_script(work_dir: str):
    fuzz0 = os.path.join(work_dir, "fuzz-0.sh")
    if os.path.isfile(fuzz0):
        return fuzz0
    candidates = []
    for name in os.listdir(work_dir):
        if name.startswith("fuzz-") and name.endswith(".sh"):
            path = os.path.join(work_dir, name)
            if os.path.isfile(path):
                candidates.append(path)
    if not candidates:
        return None
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


def _fuzzer_dirs(work_dir: str):
    items = []
    for name in sorted(os.listdir(work_dir)):
        if name == "fuzzer-master" or (name.startswith("fuzzer-") and name != "extsync"):
            path = os.path.join(work_dir, name)
            if os.path.isdir(path):
                items.append(path)
    return items


def _queue_roots(work_dir: str, output_dir_name: str):
    modern_root = os.path.join(work_dir, output_dir_name)
    if os.path.isdir(modern_root):
        return [modern_root]
    items = []
    for fuzzer_dir in _fuzzer_dirs(work_dir):
        queue_root = os.path.join(fuzzer_dir, output_dir_name)
        if os.path.isdir(queue_root):
            items.append(queue_root)
    return items


def _find_report_dir(work_dir: str):
    candidates = []
    for base in ["/results", os.path.dirname(work_dir)]:
        if os.path.isdir(base):
            for path in glob.glob(os.path.join(base, "*")):
                if os.path.isdir(path) and os.path.isfile(os.path.join(path, "fuzz_campaign_status.json")):
                    candidates.append(path)
    if candidates:
        candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return candidates[0]
    return work_dir


def _load_source_seed(seed_dir: str) -> Optional[str]:
    map_path = os.path.join(seed_dir, "xss_map.json")
    if not os.path.isfile(map_path):
        return None
    try:
        with open(map_path, "r", encoding="utf-8") as rf:
            data = json.load(rf)
    except Exception:
        return None
    if not isinstance(data, list):
        return None
    for item in data:
        if isinstance(item, dict):
            source_seed = item.get("source_seed")
            if source_seed:
                return str(source_seed)
    return None


def _encode_result_storage_path(result_storage_pathname: str, appdir: str) -> Optional[str]:
    if not result_storage_pathname:
        return None
    encoded = str(result_storage_pathname)
    if appdir:
        encoded = encoded.replace(appdir + "/", "")
        encoded = encoded.replace(appdir + "\\", "")
    encoded = encoded.replace("\\", "/").lstrip("/")
    encoded = encoded.replace("/", "+")
    return encoded or None


def _write_repro_script(fuzz_script_path: str, seed_path: str) -> None:
    with open(fuzz_script_path, "r") as rf:
        scr = rf.read()
    cat_str = f'cat "$SCRIPT_DIR/{os.path.basename(seed_path)}"'
    out_scr = ""
    for line in scr.split("\n"):
        if line.find("afl-fuzz") > -1:
            out_scr += """SCRIPT_DIR="$(cd "$(dirname $0)" > /dev/null && pwd)" \n"""
            args = line.split(" ")
            out_args = [f"{os.path.dirname(args[0])}/afl-showmap", "-o", f"/tmp/map-{os.path.basename(seed_path)}"]
            argindex = 1
            while argindex < len(args):
                arg = args[argindex]
                if arg == "-i" or arg == "-o" or arg == "-x" or arg == "-M":
                    argindex += 2
                else:
                    out_args.append(arg)
                    argindex += 1
            out_scr += cat_str + " | " + " ".join(out_args) + "\n"
        else:
            out_scr += line + "\n"
    exec_fpath = f"{seed_path}.sh"
    with open(exec_fpath, "w") as wf:
        wf.write(out_scr)
    os.chmod(exec_fpath, stat.S_IRWXU | stat.S_IRWXG | stat.S_IWOTH | stat.S_IROTH)
