#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def parse_exports_from_fuzz_script(script_path: Path) -> Dict[str, str]:
    env = {}
    export_re = re.compile(r'^export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
    with script_path.open("r", encoding="utf-8", errors="replace") as rf:
        for line in rf:
            line = line.strip()
            m = export_re.match(line)
            if not m:
                continue
            key = m.group(1)
            val = m.group(2).strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            env[key] = val
    return env


def infer_group_cc_json(script_filename: str) -> str:
    # Mirrors group_key_from_tarut_name() in symex/enable_cc.php
    script_dir = os.path.dirname(script_filename)
    tarut_dirname = script_dir.replace("/", "+")
    names = [x for x in tarut_dirname.split("+") if x]
    first = names[0] if len(names) > 0 else "root"
    second = names[1] if len(names) > 1 else "root"
    group_key = f"+{first}+{second}"
    
    # Path is now nested under its own directory to avoid cross-app pollution
    p1 = f"/dev/shm/coverages/{group_key}/{group_key}.cc.json"
    if os.path.exists(p1):
        return p1
    p2 = f"/tmp/coverages/{group_key}/{group_key}.cc.json"
    return p2 if os.path.exists(p2) else p1


def decode_seed(seed_data: bytes) -> Tuple[str, str, str, str]:
    parts = seed_data.split(b"\x00", 3)
    while len(parts) < 4:
        parts.append(b"")
    cookie = parts[0].decode("utf-8", errors="replace")
    get_data = parts[1].decode("utf-8", errors="replace")
    post_data = parts[2].decode("utf-8", errors="replace")
    headers = parts[3].decode("utf-8", errors="replace")
    return cookie, get_data, post_data, headers


def ensure_dirs(work_dir: Path) -> Dict[str, Path]:
    root = work_dir / "symex_runtime"
    dirs = {
        "root": root,
        "input": root / "input",
        "ast": root / "ast_inputs",
        "coverage": root / "coverage",
        "commands": root / "commands",
        "traces": root / "traces",
        "meta": root / "meta",
        "tmp": root / "tmp",
        "test": root / "test",
        "output": root / "output",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def collect_ast_csv(ast_dir: Path, out_ast_dir: Path) -> List[str]:
    copied = []
    for csv_path in sorted(ast_dir.glob("*.csv")):
        copied.append(str(csv_path))
    return copied


def sync_runtime_input(dirs: Dict[str, Path], *, copied_csv_paths: List[str], cc_json_path: str = "") -> None:
    return


def build_trace_session_capture_filename(input_dir: str) -> str:
    raw = str(input_dir or "").strip()
    if not raw:
        return "session_capture.json"
    try:
        key = hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()
    except Exception:
        key = "default"
    return f"session_capture_{key}.json"


def load_auth_snapshot(snapshot_path: Path) -> Dict[str, str]:
    if not snapshot_path or not snapshot_path.is_file():
        return {}
    try:
        with snapshot_path.open("r", encoding="utf-8", errors="replace") as rf:
            obj = json.load(rf)
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    out = {}
    for k, v in obj.items():
        if not isinstance(k, str):
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = str(v)
    return out


def read_json_dict(path: Path) -> Dict[str, object]:
    if not path or not path.is_file():
        return {}
    try:
        with path.open("r", encoding="utf-8", errors="replace") as rf:
            obj = json.load(rf)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def write_runtime_config_json(
    runtime_root: Path,
    *,
    source_config_path: Optional[Path] = None,
    ast_dir: str = "",
    coverage_json_path: str = "",
) -> None:
    cfg_path = runtime_root / "config.json"
    obj = read_json_dict(source_config_path) if isinstance(source_config_path, Path) else {}
    paths = obj.get("paths") if isinstance(obj.get("paths"), dict) else {}
    obj["paths"] = dict(paths)
    obj["paths"]["input_dir"] = "input"
    obj["paths"]["tmp_dir"] = "tmp"
    obj["paths"]["test_dir"] = "test"
    obj["paths"]["output_dir"] = "output"
    if ast_dir:
        obj["ast_dir"] = str(ast_dir)
    if coverage_json_path:
        obj["coverage_json_path"] = str(coverage_json_path)
    cfg_path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def write_command_files(
    commands_dir: Path,
    env: Dict[str, str],
    auth_snapshot: Dict[str, str] = None,
    php_cgi_binary: str = "",
    trace_input_dir: str = "",
    trace_session_capture_filename: str = "",
) -> None:
    wanted = ["method_map", "SCRIPT_FILENAME", "SCRIPT_NAME", "METHOD"]
    trace_wanted = [
        "method_map",
        "SCRIPT_FILENAME",
        "SCRIPT_NAME",
        "REQUEST_URI",
        "METHOD",
        "PATH_INFO",
        "REQUEST_METHOD",
        "DOCUMENT_ROOT",
        "LD_LIBRARY_PATH",
        "AFL_PRELOAD",
        "WC_INSTRUMENTATION",
        "NO_WC_EXTRA",
        "STRICT",
        "HTTP_HOST",
        "SERVER_NAME",
        "DO_JSON",
        "WITCHER_PRINT_OP",
        "LOGIN_COOKIE",
        "MANDATORY_COOKIE",
        "MANDATORY_GET",
        "MANDATORY_POST",
        "AUTHORIZATION",
        "HTTP_AUTHORIZATION",
    ]
    auth_snapshot = auth_snapshot if isinstance(auth_snapshot, dict) else {}
    php_cgi_binary = str(php_cgi_binary or "").strip() or "/phpsrc/sapi/cgi/php-cgi"
    cmd_txt = commands_dir / "test_command.txt"
    env_sh = commands_dir / "env_exports.sh"
    trace_env_sh = commands_dir / "trace_env_exports.sh"
    trace_sh = commands_dir / "run_trace_with_seed.sh"

    with cmd_txt.open("w", encoding="utf-8") as wf:
        wf.write("export OPCODE_TRACE=trace.log\n")
        for key in wanted:
            wf.write(f'export {key}="{env.get(key, "")}"\n')

    with env_sh.open("w", encoding="utf-8") as wf:
        wf.write("#!/bin/bash\n")
        wf.write("set -euo pipefail\n")
        wf.write("export OPCODE_TRACE=trace.log\n")
        for key in wanted:
            wf.write(f'export {key}="{env.get(key, "")}"\n')

    with trace_env_sh.open("w", encoding="utf-8") as wf:
        wf.write("#!/bin/bash\n")
        wf.write("set -euo pipefail\n")
        method_v = str(env.get("METHOD", "") or "")
        for key in trace_wanted:
            val = env.get(key, "")
            if (not val) and key in auth_snapshot:
                val = auth_snapshot.get(key, "")
            if (not val) and key == "REQUEST_METHOD":
                val = method_v
            if (not val) and key == "REQUEST_URI":
                val = str(env.get("SCRIPT_NAME", "") or env.get("SCRIPT_FILENAME", "") or "")
            wf.write(f'export {key}="{val}"\n')
        wf.write(f'export WC_TRACE_INPUT_DIR="{str(trace_input_dir or "")}"\n')
        wf.write(f'export WC_TRACE_SESSION_CAPTURE_FILENAME="{str(trace_session_capture_filename or "")}"\n')

    with trace_sh.open("w", encoding="utf-8") as wf:
        wf.write("#!/bin/bash\n")
        wf.write("set -euo pipefail\n")
        wf.write('SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n')
        wf.write('if [ "$#" -lt 1 ]; then echo "Usage: $0 <seed_bin>"; exit 1; fi\n')
        wf.write('SEED_FILE="$1"\n')
        wf.write('if [ -f "$SCRIPT_DIR/trace_env_exports.sh" ]; then source "$SCRIPT_DIR/trace_env_exports.sh"; fi\n')
        wf.write("export OPCODE_TRACE=trace.log\n")
        for key in wanted:
            wf.write(f'export {key}="{env.get(key, "")}"\n')
        wf.write('if [ -f "$PWD/trace_env_overrides.sh" ]; then source "$PWD/trace_env_overrides.sh"; fi\n')
        wf.write('{\n')
        wf.write('  echo "SEED_FILE=$SEED_FILE"\n')
        wf.write('  echo "OPCODE_TRACE=$OPCODE_TRACE"\n')
        wf.write('  echo "METHOD=$METHOD"\n')
        wf.write('  echo "SCRIPT_NAME=$SCRIPT_NAME"\n')
        wf.write('  echo "SCRIPT_FILENAME=$SCRIPT_FILENAME"\n')
        wf.write('  echo "REQUEST_URI=${REQUEST_URI:-}"\n')
        wf.write('  echo "CONTENT_TYPE=${CONTENT_TYPE:-}"\n')
        wf.write('  echo "CONTENT_LENGTH=${CONTENT_LENGTH:-}"\n')
        wf.write('  echo "QUERY_STRING=${QUERY_STRING:-}"\n')
        wf.write('  echo "LD_PRELOAD=${LD_PRELOAD:-}"\n')
        wf.write('  echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}"\n')
        wf.write('  echo "STRICT=${STRICT:-}"\n')
        wf.write('  echo "WC_INSTRUMENTATION=${WC_INSTRUMENTATION:-}"\n')
        wf.write('  echo "NO_WC_EXTRA=${NO_WC_EXTRA:-}"\n')
        wf.write('  echo "AFL_PRELOAD=${AFL_PRELOAD:-}"\n')
        wf.write('  echo "DO_JSON=${DO_JSON:-}"\n')
        wf.write('  echo "WITCHER_PRINT_OP=${WITCHER_PRINT_OP:-}"\n')
        wf.write('  echo "REDIRECT_STATUS=${REDIRECT_STATUS:-}"\n')
        wf.write('  echo "HTTP_REDIRECT_STATUS=${HTTP_REDIRECT_STATUS:-}"\n')
        wf.write('  echo "method_map=$method_map"\n')
        wf.write('  echo "LOGIN_COOKIE=${LOGIN_COOKIE:-}"\n')
        wf.write('  echo "MANDATORY_COOKIE=${MANDATORY_COOKIE:-}"\n')
        wf.write('  echo "HTTP_HOST=${HTTP_HOST:-}"\n')
        wf.write('  echo "SERVER_NAME=${SERVER_NAME:-}"\n')
        wf.write('  echo "REQUEST_METHOD=${REQUEST_METHOD:-}"\n')
        wf.write('  echo "PATH_INFO=${PATH_INFO:-}"\n')
        wf.write('  echo "WC_TRACE_INPUT_DIR=${WC_TRACE_INPUT_DIR:-}"\n')
        wf.write('  echo "WC_TRACE_SESSION_CAPTURE_FILENAME=${WC_TRACE_SESSION_CAPTURE_FILENAME:-}"\n')
        wf.write(f'  echo "php_cgi={php_cgi_binary}"\n')
        wf.write('  ls -l "$SEED_FILE" 2>/dev/null || true\n')
        wf.write(f'  ls -l "{php_cgi_binary}" 2>/dev/null || true\n')
        wf.write('  if [ -n "${SCRIPT_FILENAME:-}" ]; then ls -ld "$SCRIPT_FILENAME" 2>/dev/null || true; fi\n')
        wf.write('} > trace_cmd.env 2>&1\n')
        wf.write("set +e\n")
        wf.write(f'cat "$SEED_FILE" | "{php_cgi_binary}" >trace_cmd.stdout 2>trace_cmd.stderr\n')
        wf.write("rc=$?\n")
        wf.write("set -e\n")
        wf.write('echo "$rc" > trace_cmd.rc\n')
        wf.write("exit $rc\n")


def prepare_inputs(config: str, work_dir: str, request_data: str = "") -> dict:
    config_path = Path(config).expanduser().resolve()
    work_dir = Path(work_dir).resolve()
    req_path = Path(request_data).expanduser().resolve() if request_data else None

    if not config_path.is_file():
        raise FileNotFoundError(f"config not found: {config_path}")
    if not work_dir.is_dir():
        raise FileNotFoundError(f"work_dir not found: {work_dir}")

    base_dir = config_path.parent
    with config_path.open("r", encoding="utf-8", errors="replace") as rf:
        raw_config = json.load(rf)
    if not isinstance(raw_config, dict):
        raise ValueError(f"invalid config json: {config_path}")
    symex_config_path = base_dir / "symex_config.json"
    runtime_config_source = symex_config_path if symex_config_path.is_file() else config_path
    ast_dir = base_dir / "AST"
    if not ast_dir.is_dir():
        raise FileNotFoundError(f"AST directory not found: {ast_dir}")

    dirs = ensure_dirs(work_dir)
    write_runtime_config_json(dirs["root"], source_config_path=runtime_config_source, ast_dir=str(ast_dir))

    # 1) AST csv inputs
    copied_csv = collect_ast_csv(ast_dir, dirs["ast"])

    # 2) Parse AFL launch script exports
    fuzz_scripts = sorted(Path(work_dir).glob("fuzz-*.sh"))
    if not fuzz_scripts:
        raise FileNotFoundError(f"No AFL startup script found under {work_dir} (expected fuzz-*.sh)")
    env = parse_exports_from_fuzz_script(fuzz_scripts[0])
    auth_snapshot = load_auth_snapshot(dirs["meta"] / "auth_snapshot.json")
    trace_session_capture_filename = build_trace_session_capture_filename(str(dirs["input"]))
    write_command_files(
        dirs["commands"],
        env,
        auth_snapshot=auth_snapshot,
        php_cgi_binary=str(raw_config.get("afl_inst_interpreter_binary", "") or "").strip(),
        trace_input_dir=str(dirs["input"]),
        trace_session_capture_filename=trace_session_capture_filename,
    )

    # 3) Infer total coverage json
    script_filename = env.get("SCRIPT_FILENAME", "")
    cc_json_src = infer_group_cc_json(script_filename) if script_filename else ""
    cc_json_exists = bool(cc_json_src and os.path.isfile(cc_json_src))
    write_runtime_config_json(
        dirs["root"],
        source_config_path=runtime_config_source,
        ast_dir=str(ast_dir),
        coverage_json_path=cc_json_src,
    )
    sync_runtime_input(dirs, copied_csv_paths=copied_csv, cc_json_path=cc_json_src)

    meta = {
        "config": str(config_path),
        "runtime_config_source": str(runtime_config_source),
        "request_data": str(req_path) if req_path else "",
        "work_dir": str(work_dir),
        "ast_dir": str(ast_dir),
        "ast_csv_count": len(copied_csv),
        "ast_csv_files": copied_csv,
        "fuzz_script": str(fuzz_scripts[0]),
        "command_exports": {
            "method_map": env.get("method_map", ""),
            "SCRIPT_FILENAME": env.get("SCRIPT_FILENAME", ""),
            "SCRIPT_NAME": env.get("SCRIPT_NAME", ""),
            "METHOD": env.get("METHOD", ""),
            "OPCODE_TRACE": "trace.log",
        },
        "trace_auth_exports": {
            "LOGIN_COOKIE": (env.get("LOGIN_COOKIE", "") or auth_snapshot.get("LOGIN_COOKIE", "")),
            "MANDATORY_COOKIE": (env.get("MANDATORY_COOKIE", "") or auth_snapshot.get("MANDATORY_COOKIE", "")),
            "AUTHORIZATION": (env.get("AUTHORIZATION", "") or auth_snapshot.get("AUTHORIZATION", "")),
            "HTTP_AUTHORIZATION": (env.get("HTTP_AUTHORIZATION", "") or auth_snapshot.get("HTTP_AUTHORIZATION", "")),
            "HTTP_HOST": (env.get("HTTP_HOST", "") or auth_snapshot.get("HTTP_HOST", "")),
            "SERVER_NAME": (env.get("SERVER_NAME", "") or auth_snapshot.get("SERVER_NAME", "")),
        },
        "trace_session_capture_filename": trace_session_capture_filename,
        "trace_session_capture_tmp_path": str(Path("/tmp") / "wc_session_trace" / trace_session_capture_filename),
        "trace_session_capture_input_path": str(dirs["input"] / "session_capture.json"),
        "coverage_json_expected": cc_json_src,
        "coverage_json_found": cc_json_exists,
        "coverage_json_copied_to": "",
        "runtime_dirs": {k: str(v) for k, v in dirs.items()},
    }
    (dirs["meta"] / "prepare_report.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[symex] prepared under: {dirs['root']}")
    print(f"[symex] ast csv: {len(copied_csv)}, coverage found: {cc_json_exists}")
    return meta


def main():
    parser = argparse.ArgumentParser(description="Prepare symex hybrid-fuzzing inputs from Witcher/AFL runtime files.")
    parser.add_argument("--config", required=True, help="Path to witcher_config.json")
    parser.add_argument("--work-dir", required=True, help="Witcher work_dir used by AFL (contains fuzzer-* dirs)")
    parser.add_argument("--request-data", default="", help="Path to request_data.json (optional, for metadata)")
    args = parser.parse_args()
    prepare_inputs(args.config, args.work_dir, args.request_data)


if __name__ == "__main__":
    main()
