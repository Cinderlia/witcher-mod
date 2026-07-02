import argparse
import base64
import glob
import json
import os
import re
import xml.etree.ElementTree as ET
from collections import OrderedDict
from urllib.parse import urlsplit, urlunsplit, urljoin, urlencode


OLD_BASE = "http://172.28.8.69:8080/"
NEW_BASE = "http://127.0.0.1/"
VALUE_REPEAT_RE = re.compile(r"[Q2][Q2]+")
XML_DECL_RE = re.compile(r"<\?xml\s+version=['\"]1\.1['\"]\s*\?>", re.IGNORECASE)
DOCTYPE_RE = re.compile(r"<!DOCTYPE[\s\S]*?\]>", re.IGNORECASE)


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
        name = key.strip().lower()
        normalized_value = rewrite_base(value.strip())
        if name == "host" and normalized_value == "172.28.8.69:8080":
            normalized_value = "127.0.0.1"
        if name in headers:
            headers[name] = headers[name] + ", " + normalized_value
        else:
            headers[name] = normalized_value

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
    base = "{}://{}".format(scheme, netloc)
    path = target or "/"
    return rewrite_base(urljoin(base, path))


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


def split_raw_pairs(text, separator):
    pairs = []
    if not text:
        return pairs
    for item in text.split(separator):
        token = item.strip()
        if not token:
            continue
        if "=" in token:
            key, value = token.split("=", 1)
        else:
            key, value = token, ""
        key = key.strip()
        if not key:
            continue
        pairs.append((key, value.strip()))
    return pairs


def extract_path_pairs(url):
    parsed = urlsplit(url)
    pairs = []
    for segment in (parsed.path or "").split("/"):
        if not segment:
            continue
        if ";" in segment:
            parts = segment.split(";")
            for item in parts[1:]:
                if "=" not in item:
                    continue
                key, value = item.split("=", 1)
                key = key.strip()
                if key:
                    pairs.append((key, value.strip()))
    return pairs


def extract_hash_pairs(url):
    fragment = urlsplit(url).fragment
    if not fragment:
        return []
    if fragment.startswith("!"):
        fragment = fragment[1:]
    if "?" in fragment:
        fragment = fragment.split("?", 1)[1]
    return split_raw_pairs(fragment, "&")


def extract_post_pairs(body, headers):
    content_type = headers.get("content-type", "")
    content_type_lower = content_type.lower()
    if not body:
        return []
    if "application/json" in content_type_lower:
        try:
            payload = json.loads(body)
        except Exception:
            return []
        return extract_json_pairs(payload)
    if "multipart/form-data" in content_type_lower:
        return extract_multipart_pairs(body, content_type)
    if "=" not in body:
        return []
    return split_raw_pairs(body, "&")


def extract_json_pairs(value, prefix=""):
    pairs = []
    if isinstance(value, dict):
        for key, item in value.items():
            next_prefix = "{}.{}".format(prefix, key) if prefix else str(key)
            pairs.extend(extract_json_pairs(item, next_prefix))
        return pairs
    if isinstance(value, list):
        for index, item in enumerate(value):
            next_prefix = "{}[{}]".format(prefix, index) if prefix else str(index)
            pairs.extend(extract_json_pairs(item, next_prefix))
        return pairs
    if prefix:
        pairs.append((prefix, "" if value is None else str(value)))
    return pairs


def extract_multipart_pairs(body, content_type):
    marker = "boundary="
    idx = content_type.find(marker)
    if idx == -1:
        return []
    boundary = content_type[idx + len(marker):].strip().strip('"')
    if not boundary:
        return []
    boundary_token = "--" + boundary
    pairs = []
    for part in body.split(boundary_token):
        chunk = part.strip()
        if not chunk or chunk == "--":
            continue
        headers_text, separator, part_body = chunk.partition("\n\n")
        if not separator:
            continue
        name_match = re.search(r'name="([^"]+)"', headers_text, re.IGNORECASE)
        if not name_match:
            continue
        key = name_match.group(1).strip()
        value = part_body.strip()
        if key:
            pairs.append((key, value))
    return pairs


def canonicalize_post_data(body, headers):
    content_type = headers.get("content-type", "")
    content_type_lower = content_type.lower()
    if not body:
        return "", ""
    if "multipart/form-data" not in content_type_lower and "application/json" not in content_type_lower:
        return body, ""

    pairs = extract_post_pairs(body, headers)
    if not pairs:
        return body, ""

    try:
        normalized = urlencode(pairs, doseq=True)
    except Exception:
        return body, ""
    return normalized, body


def add_input_value(samples, key, value):
    key = (key or "").strip()
    if not key:
        return

    value = "" if value is None else str(value)
    if VALUE_REPEAT_RE.search(value):
        value = value[:1]

    existing = samples.setdefault(key, [])
    if value == "":
        if not existing:
            existing.append("")
        return

    if value in existing:
        return
    if "" in existing:
        existing.remove("")
    if len(existing) < 4:
        existing.append(value)


def collect_input_set(url, post_data, headers):
    samples = OrderedDict()

    query = urlsplit(url).query
    for key, value in split_raw_pairs(query, "&"):
        add_input_value(samples, key, value)

    for key, value in extract_path_pairs(url):
        add_input_value(samples, key, value)

    for key, value in extract_hash_pairs(url):
        add_input_value(samples, key, value)

    for key, value in extract_post_pairs(post_data, headers):
        add_input_value(samples, key, value)

    for key, value in split_raw_pairs(headers.get("cookie", ""), ";"):
        add_input_value(samples, key, value)

    input_set = []
    for key, values in samples.items():
        for value in values:
            input_set.append("{}={}".format(key, value))
    return input_set


def build_request_entry(request_id, url, method, headers, post_data):
    normalized_headers = OrderedDict(headers)
    parsed = urlsplit(url)
    if parsed.netloc:
        normalized_headers["host"] = parsed.netloc

    normalized_post_data, raw_post_data = canonicalize_post_data(post_data, normalized_headers)
    if raw_post_data:
        normalized_headers["content-type"] = "application/x-www-form-urlencoded"

    entry = OrderedDict()
    entry["_id"] = request_id
    entry["_urlstr"] = url
    entry["_url"] = url
    entry["_resourceType"] = "document"
    entry["_method"] = (method or ("POST" if post_data else "GET")).upper()
    entry["_postData"] = normalized_post_data or ""
    entry["_headers"] = normalized_headers
    entry["attempts"] = 0
    entry["processed"] = 0
    entry["from"] = "burpXmlImport"
    if raw_post_data:
        entry["_rawPostData"] = raw_post_data
        entry["_originalContentType"] = headers.get("content-type", "")
    if normalized_headers.get("cookie"):
        entry["_cookieData"] = normalized_headers["cookie"]
    if entry["_method"] == "POST":
        entry["response_status"] = 200
    key = "{} {} {}".format(entry["_method"], entry["_url"], entry["_postData"])
    entry["key"] = key
    return key, entry


def convert_xml_file(xml_path):
    root = load_xml_root(xml_path)
    requests_found = OrderedDict()
    input_seen = OrderedDict()
    next_id = 1

    for item in root.findall("./item"):
        item_url = get_child_text(item, "url")
        protocol = get_child_text(item, "protocol")
        host_text = get_child_text(item, "host")
        raw_request = decode_payload(item, "request")

        method, target, headers, post_data = parse_http_request(raw_request)
        if not method:
            method = get_child_text(item, "method").strip().upper()

        url = build_url(item_url, protocol, host_text, headers.get("host", ""), target)
        url = normalize_url(url)
        if not url:
            continue

        key, entry = build_request_entry(next_id, url, method, headers, post_data)
        if key in requests_found:
            continue
        requests_found[key] = entry
        next_id += 1

        for token in collect_input_set(entry["_url"], entry["_postData"], entry["_headers"]):
            input_seen[token] = None

    output = OrderedDict()
    output["requestsFound"] = requests_found
    output["seedRequestsFound"] = OrderedDict()
    output["inputSet"] = list(input_seen.keys())
    output["_witcher_meta"] = {"init": {"burp_xml_import": True}}
    return output


def find_xml_files(input_dir):
    pattern = os.path.join(input_dir, "*.xml")
    return sorted(glob.glob(pattern))


def output_path_for(xml_path):
    base, _ = os.path.splitext(xml_path)
    return base + "_request_data.json"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert Burp XML files in a directory to Witcher request_data.json files."
    )
    parser.add_argument(
        "--input-dir",
        default=".",
        help="Directory containing Burp XML files. Default: current directory.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    input_dir = os.path.abspath(args.input_dir)
    xml_files = find_xml_files(input_dir)

    if not xml_files:
        print("No XML files found in {}".format(input_dir))
        return 1

    failures = []
    for xml_path in xml_files:
        try:
            output = convert_xml_file(xml_path)
            out_path = output_path_for(xml_path)
            with open(out_path, "w", encoding="utf-8") as wf:
                json.dump(output, wf, ensure_ascii=False, indent=2)
            print(
                "Wrote {} (requests={}, inputSet={})".format(
                    out_path,
                    len(output["requestsFound"]),
                    len(output["inputSet"]),
                )
            )
        except Exception as exc:
            failures.append((xml_path, str(exc)))

    if failures:
        for xml_path, reason in failures:
            print("Failed {}: {}".format(xml_path, reason))
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
