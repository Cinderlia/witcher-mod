import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter, OrderedDict, defaultdict
from urllib.parse import urlparse


DROP_HEADERS = {
    "content-length",
    "host",
    "connection",
}

FIXED_HEADER_NAMES = [
    "user-agent",
    "accept",
    "accept-language",
    "accept-charset",
    "referer",
    "origin",
    "x-requested-with",
]


def load_request_data(json_path):
    with open(json_path, "r", encoding="latin-1") as rf:
        data = json.load(rf)
    if not isinstance(data, dict):
        raise ValueError("request_data.json 顶层必须是对象")

    requests_found = data.get("requestsFound", {})
    seed_requests = data.get("seedRequestsFound", {})
    if not isinstance(requests_found, dict):
        requests_found = {}
    if not isinstance(seed_requests, dict):
        seed_requests = {}

    merged = OrderedDict()
    for key, value in requests_found.items():
        merged[key] = value
    for key, value in seed_requests.items():
        if key not in merged:
            merged[key] = value
    return merged


def guess_target_path(req):
    url = str(req.get("_url", "") or "")
    parsed = urlparse(url)
    path = parsed.path or "/"

    lower = path.lower()
    php_idx = lower.find(".php")
    if php_idx != -1:
        return path[:php_idx + 4]
    return path


def extract_fixed_headers_for_group(items):
    buckets = {name: Counter() for name in FIXED_HEADER_NAMES}
    for _, req in items:
        headers = req.get("_headers", {}) or {}
        if not isinstance(headers, dict):
            continue
        for hk, hv in headers.items():
            key = str(hk or "").strip().lower()
            if key not in buckets:
                continue
            value = str(hv or "").strip()
            if not value:
                continue
            buckets[key][value] += 1

    fixed = {}
    for name in FIXED_HEADER_NAMES:
        counter = buckets.get(name)
        if not counter:
            continue
        most_common = counter.most_common(1)
        if most_common and most_common[0][0]:
            fixed[name] = most_common[0][0]
    return fixed


def build_groups(requests_found):
    groups = OrderedDict()
    temp = defaultdict(list)
    for reqkey, req in requests_found.items():
        target_path = guess_target_path(req)
        temp[target_path].append((reqkey, req))

    for target_path, items in temp.items():
        groups[target_path] = {
            "requests": items,
            "fixed_headers": extract_fixed_headers_for_group(items),
        }
    return groups


def build_headers(req, login_cookie, fixed_headers):
    headers = OrderedDict()
    raw_headers = req.get("_headers", {}) or {}
    if isinstance(raw_headers, dict):
        for key, value in raw_headers.items():
            name = str(key or "").strip()
            if not name:
                continue
            lowered = name.lower()
            if lowered in DROP_HEADERS or lowered == "cookie":
                continue
            headers[name] = str(value if value is not None else "")

    fixed_lookup = {k.lower(): v for k, v in (fixed_headers or {}).items()}
    for name, value in list(headers.items()):
        lowered = name.lower()
        if lowered in fixed_lookup:
            headers[name] = fixed_lookup[lowered]

    for lowered, value in fixed_lookup.items():
        if lowered not in [k.lower() for k in headers.keys()]:
            header_name = "-".join(part.capitalize() for part in lowered.split("-"))
            headers[header_name] = value

    headers["Cookie"] = login_cookie
    return headers


def build_curl_command(req, login_cookie, fixed_headers, timeout):
    method = str(req.get("_method", "GET") or "GET").upper()
    url = str(req.get("_url", "") or "")
    post_data = str(req.get("_postData", "") or "")
    headers = build_headers(req, login_cookie, fixed_headers)

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


def replay_requests(json_path, login_cookie, timeout, delay, show_groups):
    requests_found = load_request_data(json_path)
    groups = build_groups(requests_found)
    total = 0
    failed = 0

    if show_groups:
        print("Total groups: {}".format(len(groups)))
        for target_path, group in groups.items():
            print("[GROUP] {} reqs={} fixed_headers={}".format(
                target_path,
                len(group["requests"]),
                group["fixed_headers"],
            ))

    total_items = sum(len(group["requests"]) for group in groups.values())
    current_index = 0
    for target_path, group in groups.items():
        fixed_headers = group["fixed_headers"]
        for reqkey, req in group["requests"]:
            current_index += 1
            total += 1
            command = build_curl_command(req, login_cookie, fixed_headers, timeout)
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
                print("[{}/{}] {} {} -> {} | target={}".format(
                    current_index,
                    total_items,
                    method,
                    url,
                    http_code,
                    target_path,
                ))
            else:
                failed += 1
                print("[{}/{}] FAIL {} {} -> curl_exit={} http={} | target={}".format(
                    current_index,
                    total_items,
                    method,
                    url,
                    result.returncode,
                    http_code,
                    target_path,
                ))
                stderr = (result.stderr or "").strip()
                if stderr:
                    print(stderr)

            if delay > 0:
                time.sleep(delay)

    print("Replayed {} requests across {} groups, {} failed".format(total, len(groups), failed))
    return 0 if failed == 0 else 1


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Replay request_data.json with fixed per-target headers similar to Witcher consumption."
    )
    parser.add_argument("json_file", help="request_data.json file path")
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
        "--show-groups",
        action="store_true",
        help="Print grouped target paths and chosen fixed headers before replay.",
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
        args.show_groups,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
