import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import OrderedDict
from urllib.parse import urlparse


STATIC_RE = re.compile(r"http://.*/[a-zA-Z0-9_\-\.]+\.(css|js|toff|woff|jpg|gif|png)\?[0-9a-zA-Z ]*")
DROP_HEADERS = {
    "content-length",
    "host",
    "connection",
}


def load_request_data(json_path):
    with open(json_path, "r", encoding="latin-1") as rf:
        data = json.load(rf)
    if not isinstance(data, dict):
        raise ValueError("request_data.json 顶层必须是对象")
    requests_found = data.get("requestsFound", {})
    if not isinstance(requests_found, dict):
        requests_found = {}
    seed_requests = data.get("seedRequestsFound", {})
    if not isinstance(seed_requests, dict):
        seed_requests = {}

    merged = OrderedDict()
    for key, value in requests_found.items():
        merged[key] = value
    for key, value in seed_requests.items():
        if key not in merged:
            merged[key] = value
    return merged


def should_replay_request(req, witcher_filter):
    if not isinstance(req, dict):
        return False, "invalid"

    url = str(req.get("_url", "") or "")
    method = str(req.get("_method", "GET") or "GET").upper()
    post_data = str(req.get("_postData", "") or "")
    response_status = req.get("response_status", 200)

    if not url:
        return False, "empty url"
    if not witcher_filter:
        return True, ""
    if STATIC_RE.match(url):
        return False, "static extension"

    parsed = urlparse(url)
    if parsed.path.endswith("/") and "/?" in url:
        return False, "dir listing"

    try:
        response_status = int(response_status)
    except Exception:
        response_status = 200

    if response_status == 999:
        return False, "response_status=999"
    if 400 <= response_status < 500:
        return False, "4xx status"
    if method == "POST" and len(parsed.query) + len(post_data) < 1:
        return False, "post without params"
    if ("?" not in url) and ("&" not in url) and len(post_data) == 0:
        return False, "no query or post data"
    return True, ""


def build_headers(req, login_cookie):
    headers = OrderedDict()
    raw_headers = req.get("_headers", {})
    if isinstance(raw_headers, dict):
        for key, value in raw_headers.items():
            name = str(key or "").strip()
            if not name:
                continue
            lowered = name.lower()
            if lowered in DROP_HEADERS or lowered == "cookie":
                continue
            headers[name] = str(value if value is not None else "")
    headers["Cookie"] = login_cookie
    return headers


def build_curl_command(req, login_cookie, timeout):
    method = str(req.get("_method", "GET") or "GET").upper()
    url = str(req.get("_url", "") or "")
    post_data = str(req.get("_postData", "") or "")
    headers = build_headers(req, login_cookie)

    command = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--output",
        "NUL" if os.name == "nt" else "/dev/null",
        "--write-out",
        "%{http_code}",
        "--request",
        method,
        "--max-time",
        str(timeout),
        url,
    ]

    for key, value in headers.items():
        command.extend(["--header", "{}: {}".format(key, value)])

    if post_data:
        command.extend(["--data-binary", post_data])

    return command


def replay_requests(json_path, login_cookie, timeout, delay, witcher_filter):
    requests_found = load_request_data(json_path)
    total = 0
    failed = 0
    skipped = 0

    items = list(requests_found.items())
    for index, (reqkey, req) in enumerate(items, start=1):
        should_run, reason = should_replay_request(req, witcher_filter)
        if not should_run:
            skipped += 1
            print("[{}/{}] skip {} -> {}".format(index, len(items), reqkey, reason))
            continue

        total += 1
        command = build_curl_command(req, login_cookie, timeout)
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        http_code = (result.stdout or "").strip() or "000"
        url = str(req.get("_url", "") or "")
        method = str(req.get("_method", "GET") or "GET").upper()

        if result.returncode == 0 and http_code != "000":
            print("[{}/{}] {} {} -> {}".format(index, len(items), method, url, http_code))
        else:
            failed += 1
            print("[{}/{}] FAIL {} {} -> curl_exit={} http={}".format(
                index,
                len(items),
                method,
                url,
                result.returncode,
                http_code,
            ))
            stderr = (result.stderr or "").strip()
            if stderr:
                print(stderr)

        if delay > 0:
            time.sleep(delay)

    print("Replayed {} requests, {} skipped, {} failed".format(total, skipped, failed))
    return 0 if failed == 0 else 1


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Replay Witcher-consumable requests from request_data.json with a new cookie via curl."
    )
    parser.add_argument("json_file", help="Converted request_data.json file path")
    parser.add_argument("login_cookie", help="New login cookie header value")
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="curl max time in seconds for each request. Default: 30",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Optional delay in seconds between requests. Default: 0",
    )
    parser.add_argument(
        "--witcher-filter",
        action="store_true",
        help="Apply Witcher-like request filtering before replay. Default: replay all requests in request_data.json",
    )
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if not os.path.isfile(args.json_file):
        print("JSON file not found: {}".format(args.json_file))
        return 1
    return replay_requests(
        args.json_file,
        args.login_cookie,
        args.timeout,
        args.delay,
        args.witcher_filter,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
