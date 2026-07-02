import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from typing import Dict, List, Optional

if __package__ in (None, ""):
    _HERE = os.path.dirname(os.path.abspath(__file__))
    _ROOT = os.path.dirname(_HERE)
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)
    from xss_reflection.integration.cgi_runner import CGIRunner
    from xss_reflection.core.seed_parser import SeedParser
else:
    from .integration.cgi_runner import CGIRunner
    from .core.seed_parser import SeedParser


DEFAULT_OUTPUT_DIR_NAME = "xss_queue"
DEFAULT_PROBE_URL = "http://127.0.0.1/joomla-3.7/administrator/index.php?option=com_users&groups=W10="
DEFAULT_REQUEST_TIMEOUT = 15
DEFAULT_PROBE_TIMEOUT = 15


def _write_json(path: str, obj: Dict[str, object]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)


def _read_seed(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _write_seed(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data or b"")


def _override_seed_cookie(raw_seed: bytes, cookie: str) -> bytes:
    parts = raw_seed.split(b"\x00")
    while len(parts) < 4:
        parts.append(b"")
    parts = parts[:4]
    parts[0] = str(cookie or "").encode("latin-1", errors="ignore")
    return b"\x00".join(parts)


def _extract_body(output: str) -> str:
    if "\r\n\r\n" in output:
        return output.split("\r\n\r\n", 1)[1]
    if "\n\n" in output:
        return output.split("\n\n", 1)[1]
    return output


def _execute_seed(cmd: List[str], env: Dict[str, str], seed_path: str, seed_bytes: bytes, timeout: int) -> Dict[str, object]:
    env_local = dict(env or {})
    env_local["AFL_FILE"] = seed_path
    started_at = time.time()
    close_fds = os.name != "nt"
    preexec_fn = None if os.name == "nt" else (lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN))
    try:
        proc = subprocess.run(
            cmd,
            input=seed_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env_local,
            timeout=max(1, int(timeout)),
            close_fds=close_fds,
            preexec_fn=preexec_fn,
        )
        stdout_text = proc.stdout.decode("latin-1", errors="ignore")
        stderr_text = proc.stderr.decode("latin-1", errors="ignore")
        return {
            "ok": True,
            "returncode": int(proc.returncode),
            "duration_ms": int((time.time() - started_at) * 1000.0),
            "stdout_body": _extract_body(stdout_text),
            "stdout_raw_tail": stdout_text[-4000:],
            "stderr_tail": stderr_text[-4000:],
        }
    except subprocess.TimeoutExpired as ex:
        stdout_text = (ex.stdout or b"").decode("latin-1", errors="ignore") if isinstance(ex.stdout, (bytes, bytearray)) else str(ex.stdout or "")
        stderr_text = (ex.stderr or b"").decode("latin-1", errors="ignore") if isinstance(ex.stderr, (bytes, bytearray)) else str(ex.stderr or "")
        return {
            "ok": False,
            "returncode": None,
            "duration_ms": int((time.time() - started_at) * 1000.0),
            "stdout_body": _extract_body(stdout_text),
            "stdout_raw_tail": stdout_text[-4000:],
            "stderr_tail": stderr_text[-4000:],
            "error": "timeout",
        }
    except Exception as ex:
        return {
            "ok": False,
            "returncode": None,
            "duration_ms": int((time.time() - started_at) * 1000.0),
            "stdout_body": "",
            "stdout_raw_tail": "",
            "stderr_tail": "",
            "error": str(ex),
        }


def _run_probe(cookie: str, probe_url: str, timeout: int) -> Dict[str, object]:
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", str(max(1, int(timeout))), "--cookie", str(cookie or ""), str(probe_url or "")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(1, int(timeout)) + 2,
            check=False,
        )
        body = proc.stdout.decode("utf-8", errors="replace")
        stderr_text = proc.stderr.decode("utf-8", errors="replace")
        return {
            "ok": True,
            "returncode": int(proc.returncode),
            "body_tail": body[-4000:],
            "body_text": body,
            "stderr_tail": stderr_text[-2000:],
        }
    except Exception as ex:
        return {
            "ok": False,
            "returncode": None,
            "body_tail": "",
            "body_text": "",
            "stderr_tail": "",
            "error": str(ex),
        }


def _extract_payload_markers(parsed_seed, seed_path: str) -> List[str]:
    text_parts = [
        str(getattr(parsed_seed, "query", "") or ""),
        str(getattr(parsed_seed, "post", "") or ""),
        str(os.path.basename(seed_path) or ""),
    ]
    joined = "\n".join(text_parts)
    found: List[str] = []
    seen = set()
    for pattern in (
        r"witcher_xss_\d{1,8}",
        r"witcher[a-z0-9_-]{0,64}",
        r"xss[a-z0-9_-]{0,64}",
    ):
        for m in re.findall(pattern, joined, flags=re.IGNORECASE):
            token = str(m or "").strip()
            if not token:
                continue
            token_l = token.lower()
            if token_l in seen:
                continue
            seen.add(token_l)
            found.append(token)
    for fallback in ("witcher", "xss"):
        if fallback in joined.lower() and fallback not in seen:
            seen.add(fallback)
            found.append(fallback)
    return found


def _probe_payload_hits(body: str, markers: List[str]) -> List[str]:
    text = str(body or "").lower()
    hits = []
    seen = set()
    for marker in markers or []:
        marker_s = str(marker or "").strip().lower()
        if not marker_s:
            continue
        if marker_s in text and marker_s not in seen:
            seen.add(marker_s)
            hits.append(marker_s)
    return hits


def _iter_seed_paths(work_dir: str, output_dir_name: str) -> List[str]:
    modern_root = os.path.join(work_dir, output_dir_name)
    queue_roots: List[str] = []
    if os.path.isdir(modern_root):
        queue_roots.append(modern_root)
    else:
        for name in sorted(os.listdir(work_dir)):
            if name == "fuzzer-master" or (name.startswith("fuzzer-") and name != "extsync"):
                queue_root = os.path.join(work_dir, name, output_dir_name)
                if os.path.isdir(queue_root):
                    queue_roots.append(queue_root)
    seed_paths: List[str] = []
    for queue_root in queue_roots:
        for seed_dir_name in sorted(os.listdir(queue_root)):
            seed_dir = os.path.join(queue_root, seed_dir_name)
            if not os.path.isdir(seed_dir):
                continue
            for name in sorted(os.listdir(seed_dir)):
                if name in {"xss_map.json", "hits", "responses", "confirmed", "attempts"}:
                    continue
                path = os.path.join(seed_dir, name)
                if os.path.isfile(path):
                    seed_paths.append(path)
    return seed_paths


def _build_result_root(work_dir: str) -> str:
    out_dir = os.path.join(work_dir, "xss_replay_probe")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def _log(log_path: str, message: str) -> None:
    line = "[xss-replay-probe] %s" % str(message)
    print(line)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_replay(
    *,
    work_dir: str,
    cookie: str,
    output_dir_name: str = DEFAULT_OUTPUT_DIR_NAME,
    probe_url: str = DEFAULT_PROBE_URL,
    request_timeout: int = DEFAULT_REQUEST_TIMEOUT,
    probe_timeout: int = DEFAULT_PROBE_TIMEOUT,
) -> int:
    work_dir = os.path.abspath(work_dir)
    result_root = _build_result_root(work_dir)
    log_path = os.path.join(result_root, "replay.log")
    runner = CGIRunner(work_dir)
    parser = SeedParser()
    script_path = runner.find_script()
    if not script_path:
        _log(log_path, "fuzz-*.sh script not found")
        return 1
    env, cmd = runner.parse_script(script_path)
    if not cmd:
        _log(log_path, "failed to parse command after '--' from fuzz script")
        return 1
    seed_paths = _iter_seed_paths(work_dir, output_dir_name)
    if not seed_paths:
        _log(log_path, "no seeds found for replay")
        return 1
    summary: Dict[str, object] = {
        "work_dir": work_dir,
        "script_path": script_path,
        "seed_count": int(len(seed_paths)),
        "started_at": int(time.time()),
        "effective_cookie": str(cookie or ""),
        "probe_url": str(probe_url or ""),
        "output_dir_name": str(output_dir_name or ""),
        "request_timeout": int(request_timeout),
        "probe_timeout": int(probe_timeout),
        "serial_mode": True,
        "stop_on_probe_hit": True,
        "status": "running",
    }
    _write_json(os.path.join(result_root, "summary.json"), summary)
    _log(log_path, "starting serial replay, seed_count=%d script=%s" % (len(seed_paths), script_path))
    for index, seed_path in enumerate(seed_paths, start=1):
        raw_seed = _read_seed(seed_path)
        replay_seed = _override_seed_cookie(raw_seed, cookie)
        parsed = parser.parse_seed(replay_seed)
        payload_markers = _extract_payload_markers(parsed, seed_path)
        _log(log_path, "replaying seed %d/%d: %s" % (index, len(seed_paths), seed_path))
        exec_result = _execute_seed(cmd, env, seed_path, replay_seed, request_timeout)
        probe_result = _run_probe(cookie, probe_url, probe_timeout)
        probe_hits = _probe_payload_hits(str(probe_result.get("body_text") or ""), payload_markers)
        probe_result["payload_markers"] = list(payload_markers)
        probe_result["payload_hits"] = list(probe_hits)
        probe_result["hit_count"] = int(len(probe_hits))
        probe_result["triggered"] = bool(len(probe_hits) >= 1)
        _log(
            log_path,
            "probe finished seed=%s exec_rc=%s probe_rc=%s markers=%s hits=%s"
            % (
                os.path.basename(seed_path),
                str(exec_result.get("returncode")),
                str(probe_result.get("returncode")),
                ",".join(payload_markers),
                ",".join(probe_hits),
            ),
        )
        if bool(probe_result.get("triggered")):
            trigger_dir = os.path.join(result_root, "triggered")
            os.makedirs(trigger_dir, exist_ok=True)
            copied_seed_path = os.path.join(trigger_dir, os.path.basename(seed_path))
            try:
                _write_seed(copied_seed_path, replay_seed)
            except Exception:
                copied_seed_path = ""
            trigger_payload: Dict[str, object] = {
                "triggered_at": int(time.time()),
                "seed_index": int(index),
                "seed_path": seed_path,
                "replayed_seed_path": copied_seed_path,
                "script_path": script_path,
                "cmd": list(cmd),
                "cookie": str(cookie or ""),
                "probe_url": str(probe_url or ""),
                "payload_markers": payload_markers,
                "probe_payload_hits": probe_hits,
                "probe_hit_count": int(probe_result.get("hit_count") or 0),
                "replay_request": {
                    "query": parsed.query,
                    "post": parsed.post,
                    "headers": parsed.headers,
                    "cookies": parsed.cookies,
                },
                "execute_result": exec_result,
                "probe_result": probe_result,
            }
            _write_json(os.path.join(trigger_dir, "trigger_request.json"), trigger_payload)
            summary["status"] = "triggered"
            summary["finished_at"] = int(time.time())
            summary["trigger_seed_path"] = seed_path
            summary["trigger_payload_hits"] = probe_hits
            summary["executed_count"] = int(index)
            _write_json(os.path.join(result_root, "summary.json"), summary)
            _log(log_path, "probe hit detected, stopping replay, seed=%s hits=%s" % (seed_path, ",".join(probe_hits)))
            return 2
    summary["status"] = "finished"
    summary["finished_at"] = int(time.time())
    summary["executed_count"] = int(len(seed_paths))
    _write_json(os.path.join(result_root, "summary.json"), summary)
    _log(log_path, "replay finished without probe hit")
    return 0


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Replay xss_reflection seeds serially and check whether the probe URL reflects the current payload markers.")
    p.add_argument("--work-dir", required=True, help="work_dir used by xss_reflection")
    p.add_argument("--cookie", required=True, help="cookie used to overwrite the cookie field in replayed seeds and probe requests")
    p.add_argument("--output-dir-name", default=DEFAULT_OUTPUT_DIR_NAME, help="seed root directory name, default: xss_queue")
    p.add_argument("--probe-url", default=DEFAULT_PROBE_URL, help="probe URL requested by curl after each replay")
    p.add_argument("--request-timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT, help="timeout in seconds for each replayed request")
    p.add_argument("--probe-timeout", type=int, default=DEFAULT_PROBE_TIMEOUT, help="timeout in seconds for each curl probe request")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    return run_replay(
        work_dir=str(args.work_dir or "").strip(),
        cookie=str(args.cookie or ""),
        output_dir_name=str(args.output_dir_name or DEFAULT_OUTPUT_DIR_NAME),
        probe_url=str(args.probe_url or DEFAULT_PROBE_URL),
        request_timeout=int(args.request_timeout),
        probe_timeout=int(args.probe_timeout),
    )


if __name__ == "__main__":
    raise SystemExit(main())
