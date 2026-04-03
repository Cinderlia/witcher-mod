import os
import shutil
import stat
import glob
from typing import Dict

from .integration.seed_injector import generate_xss_seeds
from .integration.cgi_validator import validate_xss_seeds
from .integration.attack_runner import run_targeted_attacks


def run_xss_flow(work_dir: str, output_dir_name: str = "xss_queue") -> Dict[str, int]:
    debug_mode = False
    log_path = os.path.join(work_dir, "xss_reflection.log")
    try:
        result = generate_xss_seeds(work_dir, output_dir_name=output_dir_name)
        validation = validate_xss_seeds(work_dir, output_dir_name=output_dir_name)
        attacks = run_targeted_attacks(work_dir, output_dir_name=output_dir_name)
        if not debug_mode:
            collected = _collect_confirmed(work_dir, output_dir_name)
            _log(log_path, f"Witcher-XSS collected_confirmed={collected}")
        _log(
            log_path,
            f"Witcher-XSS summary scanned={result.get('seeds_scanned', 0)} "
            f"generated={result.get('seeds_generated', 0)} "
            f"executed={validation.get('executed', 0)} "
            f"reflected={validation.get('reflected', 0)} "
            f"attack_executed={attacks.get('attack_executed', 0)} "
            f"attack_confirmed={attacks.get('attack_confirmed', 0)}",
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


def _collect_confirmed(work_dir: str, output_dir_name: str) -> int:
    report_dir = _find_report_dir(work_dir)
    seed_crashes_dir = os.path.join(report_dir, "seed-crashes")
    target_dir = os.path.join(seed_crashes_dir, "xss-confirmed")
    os.makedirs(target_dir, exist_ok=True)
    _log(os.path.join(work_dir, "xss_reflection.log"), f"Witcher-XSS report_dir={report_dir}")

    saved = 0
    fid = len([n for n in os.listdir(target_dir) if n.startswith("id:")])
    fuzz_script_path = _find_fuzz_script(work_dir)
    for fuzzer_dir in _fuzzer_dirs(work_dir):
        queue_root = os.path.join(fuzzer_dir, output_dir_name)
        if not os.path.isdir(queue_root):
            continue
        for seed_dir in _seed_dirs(queue_root):
            confirmed_dir = os.path.join(seed_dir, "confirmed")
            if not os.path.isdir(confirmed_dir):
                continue
            for name in os.listdir(confirmed_dir):
                if name.endswith(".html") or name.endswith(".json") or name.endswith(".tmp"):
                    continue
                src = os.path.join(confirmed_dir, name)
                if os.path.isfile(src):
                    fid += 1
                    crash_name = f"id:{fid:06},src:{name},xss"
                    dst = os.path.join(target_dir, crash_name)
                    shutil.copy2(src, dst)
                    if fuzz_script_path:
                        _write_repro_script(fuzz_script_path, dst)
                    saved += 1
        shutil.rmtree(queue_root)
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
        if name == "fuzzer-master" or name.startswith("fuzzer-"):
            path = os.path.join(work_dir, name)
            if os.path.isdir(path):
                items.append(path)
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
