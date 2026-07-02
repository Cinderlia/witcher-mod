import argparse
import base64
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import OrderedDict
from urllib.parse import urljoin, urlsplit, urlunsplit

OLD_BASE = "http://172.28.8.69:8080/"
NEW_BASE = "http://127.0.0.1/"
XML_DECL_RE = re.compile(r"<\?xml\s+version=['\"]1\.1['\"]\s*\?>", re.IGNORECASE)
DOCTYPE_RE = re.compile(r"<!DOCTYPE[\s\S]*?\]>", re.IGNORECASE)

DROP_HEADERS = {
    "content-length",
    "host",
    "connection",
}


def rewrite_base(text):
    if not text:
        return text
    return text.replace(OLD_BASE, NEW_BASE)


def sanitize_xml_text(text):
    cleaned = text.replace("\x00", "")
    cleaned = XML_DECL_RE.sub('<?xml version="1.0"?>', cleaned, count=1)
    cleaned = DOCTYPE_RE.sub("", cleaned, count=1)
    return cleaned


def load_xml_root(xml_path):
    with open(xml_path, "rb") as rf:
        raw = rf.read()
    text = raw.decode("utf-8", errors="replace")
    text = sanitize_xml_text(text)
    return ET.fromstring(text)


def get_child_text(node, tag):
    child = node.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text


def decode_payload(node, tag):
    child = node.find(tag)
    if child is None or child.text is None:
        return ""
    payload = child.text
    if child.get("base64", "").lower() == "true":
        try:
            decoded = base64.b64decode(payload)
            return decoded.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return payload


def parse_http_request(raw_request):
    text = (raw_request or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text:
        return "", "", OrderedDict(), ""

    header_text, separator, body = text.partition("\n\n")
    header_lines = [line for line in header_text.split("\n") if line.strip()]
    if not header_lines:
        return "", "", OrderedDict(), ""

    request_line = header_lines[0].strip()
    method = ""
    target = ""
    parts = request_line.split()
    if len(parts) >= 2:
        method = parts[0].upper()
        target = parts[1]

    headers = OrderedDict()
    for line in header_lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = rewrite_base(value.strip())

    if not separator:
        body = ""
    elif body.strip() == "":
        body = ""
    else:
        body = rewrite_base(body.lstrip("\n"))

    return method, target, headers, body


def build_url(item_url, protocol, host_text, host_header, target):
    candidate = rewrite_base((item_url or "").strip())
    if candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme and parsed.netloc:
            if target.startswith("http://") or target.startswith("https://"):
                return rewrite_base(target)
            if target.startswith("/"):
                base = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
                return urljoin(base, target)
            return candidate

    if target.startswith("http://") or target.startswith("https://"):
        return rewrite_base(target)

    scheme = (protocol or "http").strip() or "http"
    netloc = (host_header or host_text or "").strip()
    if not netloc:
        return rewrite_base(candidate)
    if netloc == "172.28.8.69:8080":
        netloc = "127.0.0.1"
    return rewrite_base(urljoin("{}://{}".format(scheme, netloc), target or "/"))


def normalize_url(url):
    text = rewrite_base((url or "").strip())
    if not text:
        return ""
    parsed = urlsplit(text)
    if not parsed.scheme or not parsed.netloc:
        return text
    path = parsed.path or "/"
    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        path,
        parsed.query,
        parsed.fragment,
    ))


def build_replay_request(item, login_cookie):
    item_url = get_child_text(item, "url")
    protocol = get_child_text(item, "protocol")
    host_text = get_child_text(item, "host")
    raw_request = decode_payload(item, "request")

    method, target, headers, body = parse_http_request(raw_request)
    if not method:
        method = get_child_text(item, "method").strip().upper() or "GET"

    url = normalize_url(build_url(item_url, protocol, host_text, headers.get("host", ""), target))
    if not url:
        return None

    replay_headers = OrderedDict()
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in DROP_HEADERS or lowered == "cookie":
            continue
        replay_headers[key] = rewrite_base(value)

    replay_headers["cookie"] = login_cookie
    return {
        "method": method,
        "url": url,
        "headers": replay_headers,
        "body": body or "",
    }


def build_curl_command(request_info, timeout):
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--output",
        "NUL",
        "--write-out",
        "%{http_code}",
        "--request",
        request_info["method"],
        "--max-time",
        str(timeout),
        request_info["url"],
    ]

    for key, value in request_info["headers"].items():
        command.extend(["--header", "{}: {}".format(key, value)])

    if request_info["body"]:
        command.extend(["--data-binary", request_info["body"]])

    return command


def replay_requests(xml_path, login_cookie, timeout, delay):
    root = load_xml_root(xml_path)
    items = root.findall("./item")
    total = 0
    failed = 0

    for index, item in enumerate(items, start=1):
        request_info = build_replay_request(item, login_cookie)
        if request_info is None:
            print("[{}/{}] skip: empty url".format(index, len(items)))
            continue

        total += 1
        command = build_curl_command(request_info, timeout)
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        http_code = (result.stdout or "").strip() or "000"
        ok = result.returncode == 0 and http_code and http_code != "000"

        if ok:
            print("[{}/{}] {} {} -> {}".format(
                index,
                len(items),
                request_info["method"],
                request_info["url"],
                http_code,
            ))
        else:
            failed += 1
            print("[{}/{}] FAIL {} {} -> curl_exit={} http={}".format(
                index,
                len(items),
                request_info["method"],
                request_info["url"],
                result.returncode,
                http_code,
            ))
            stderr = (result.stderr or "").strip()
            if stderr:
                print(stderr)

        if delay > 0:
            time.sleep(delay)

    print("Replayed {} requests, {} failed".format(total, failed))
    return 0 if failed == 0 else 1


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Replay all requests from a Burp XML file with a new login cookie via curl."
    )
    parser.add_argument("xml_file", help="Burp exported XML file path")
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
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if not os.path.isfile(args.xml_file):
        print("XML file not found: {}".format(args.xml_file))
        return 1
    return replay_requests(args.xml_file, args.login_cookie, args.timeout, args.delay)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
