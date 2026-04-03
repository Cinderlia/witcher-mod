import argparse
import json
import sys
from collections import OrderedDict
from urllib.parse import urlparse, urlunparse, parse_qsl, urljoin


class InputError(Exception):
    pass


def normalize_key(key):
    return key.strip().upper().replace("-", "_")


def parse_header_item(item):
    item = item.strip()
    if not item:
        return None, None
    if ":" in item:
        k, v = item.split(":", 1)
    elif "=" in item:
        k, v = item.split("=", 1)
    else:
        return None, None
    return k.strip(), v.strip()


def parse_headers_value(value):
    headers = {}
    for part in value.split(";"):
        k, v = parse_header_item(part)
        if k:
            headers[k] = v
    return headers


def parse_input_file(path):
    base_url = ""
    login_session_cookie = None
    input_set = []
    requests = []
    current = None

    def finalize_request(req):
        if req is None:
            return
        if not req.get("SCRIPT_FILENAME"):
            raise InputError("SCRIPT_FILENAME 不允许留空")
        requests.append(req)

    with open(path, "r", encoding="utf-8") as rf:
        for line_no, line in enumerate(rf, start=1):
            raw = line.rstrip("\n")
            stripped = raw.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                continue
            if ":" not in stripped:
                raise InputError(f"第 {line_no} 行缺少 ':' 分隔符")
            key, value = stripped.split(":", 1)
            key = normalize_key(key)
            value = value.strip()

            if key in {"BASE_URL", "BASEURL"}:
                base_url = value
                continue
            if key in {"LOGINSESSIONCOOKIE", "LOGIN_SESSION_COOKIE", "LOGINSESSIONCOOKIE"}:
                login_session_cookie = value
                continue
            if key == "INPUTSET":
                if value:
                    input_set.append(value)
                continue

            if key == "SCRIPT_FILENAME":
                finalize_request(current)
                current = {
                    "SCRIPT_FILENAME": value,
                    "GET": "",
                    "POST": "",
                    "COOKIE": "",
                    "METHOD": "",
                    "HEADERS": {},
                    "RESOURCE_TYPE": "document",
                    "RESPONSE_STATUS": None,
                    "ATTEMPTS": None,
                    "PROCESSED": None,
                    "FROM": "",
                }
                continue

            if current is None:
                raise InputError(f"第 {line_no} 行出现在 SCRIPT_FILENAME 之前")

            if key == "GET":
                current["GET"] = value
            elif key == "POST":
                current["POST"] = value
            elif key == "COOKIE":
                current["COOKIE"] = value
            elif key == "METHOD":
                current["METHOD"] = value
            elif key == "HEADERS":
                current["HEADERS"].update(parse_headers_value(value))
            elif key == "HEADER":
                hk, hv = parse_header_item(value)
                if hk:
                    current["HEADERS"][hk] = hv
            elif key == "RESOURCE_TYPE":
                current["RESOURCE_TYPE"] = value or "document"
            elif key == "RESPONSE_STATUS":
                current["RESPONSE_STATUS"] = value
            elif key == "ATTEMPTS":
                current["ATTEMPTS"] = value
            elif key == "PROCESSED":
                current["PROCESSED"] = value
            elif key == "FROM":
                current["FROM"] = value
            else:
                raise InputError(f"第 {line_no} 行未知字段 {key}")

    finalize_request(current)

    return base_url, login_session_cookie, input_set, requests


def ensure_absolute_url(script_filename, base_url):
    parsed = urlparse(script_filename)
    if parsed.scheme and parsed.netloc:
        return script_filename
    if not base_url:
        raise InputError(f"SCRIPT_FILENAME={script_filename} 需要 BASE_URL")
    return urljoin(base_url.rstrip("/") + "/", script_filename.lstrip("/"))


def build_url(script_filename, base_url, get_value):
    full = ensure_absolute_url(script_filename, base_url)
    parsed = urlparse(full)
    existing = parsed.query
    extra = get_value.lstrip("?")
    if extra:
        merged = f"{existing}&{extra}" if existing else extra
    else:
        merged = existing
    return urlunparse(parsed._replace(query=merged))


def coerce_int(value, default):
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError:
        raise InputError(f"数值字段无法解析: {value}")


def extract_inputset_from_requests(requests):
    seen = OrderedDict()
    for req in requests:
        for key, value in parse_qsl(urlparse(req["_url"]).query, keep_blank_values=True):
            seen[f"{key}={value}"] = None
        if req["_postData"]:
            for part in req["_postData"].split("&"):
                if part == "":
                    continue
                if "=" in part:
                    k, v = part.split("=", 1)
                else:
                    k, v = part, ""
                seen[f"{k}={v}"] = None
    return list(seen.keys())


def build_request_entries(base_url, requests):
    requests_found = OrderedDict()
    counter = 1
    for req in requests:
        url = build_url(req["SCRIPT_FILENAME"], base_url, req["GET"])
        method = (req["METHOD"] or ("POST" if req["POST"] else "GET")).upper()
        headers = dict(req["HEADERS"])
        cookie = req["COOKIE"]
        if cookie and not any(k.lower() == "cookie" for k in headers.keys()):
            headers["cookie"] = cookie
        entry = {
            "_id": counter,
            "_urlstr": url,
            "_url": url,
            "_resourceType": req["RESOURCE_TYPE"] or "document",
            "_method": method,
            "_postData": req["POST"] or "",
            "_headers": headers,
            "attempts": coerce_int(req["ATTEMPTS"], 0),
            "processed": coerce_int(req["PROCESSED"], 0),
            "from": req["FROM"] or "ManualRequest",
        }
        entry["_cookieData"] = cookie
        key = f"{method} {url} {entry['_postData']}"
        unique_key = key
        dup = 1
        while unique_key in requests_found:
            dup += 1
            unique_key = f"{key} #{dup}"
        entry["key"] = unique_key
        requests_found[unique_key] = entry
        counter += 1
    return requests_found


def build_output(base_url, login_session_cookie, input_set, requests):
    requests_found = build_request_entries(base_url, requests)
    if not input_set:
        input_set = extract_inputset_from_requests(requests_found.values())
    if not input_set:
        input_set = ["nv1=nv-val1"]
    output = {
        "requestsFound": requests_found,
        "inputSet": input_set,
    }
    if login_session_cookie is not None:
        output["loginSessionCookie"] = login_session_cookie
    return output


def parse_args(argv):
    p = argparse.ArgumentParser()
    p.add_argument("input_file")
    p.add_argument("--output", default="request_data.json")
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    base_url, login_session_cookie, input_set, requests = parse_input_file(args.input_file)
    output = build_output(base_url, login_session_cookie, input_set, requests)
    with open(args.output, "w", encoding="utf-8") as wf:
        json.dump(output, wf, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
