import argparse
import json
import os
import posixpath
import re
from urllib.parse import urlsplit, urlunsplit


URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)
TOP_PATTERN = re.compile(r"#top", re.IGNORECASE)
SLASH_PATTERN = re.compile(r"/{2,}")


def extract_url_from_line(line):
    text = (line or "").strip()
    if not text:
        return None
    match = URL_PATTERN.search(text)
    if match:
        return match.group(0)
    if text.lower().startswith(("http://", "https://")):
        return text
    return None


def normalize_url(raw_url):
    url = (raw_url or "").strip().strip("'\"")
    if not url:
        return None

    url = TOP_PATTERN.sub("", url)

    try:
        parts = urlsplit(url)
    except Exception:
        return None

    if not parts.scheme or not parts.netloc:
        return None

    path = normalize_path(parts.path)
    query = normalize_query(parts.query)

    return urlunsplit((
        parts.scheme.lower(),
        parts.netloc.lower(),
        path,
        query,
        "",
    ))


def normalize_path(path):
    text = path or "/"
    text = SLASH_PATTERN.sub("/", text)
    if not text.startswith("/"):
        text = "/" + text

    had_trailing_slash = text.endswith("/") and text != "/"
    normalized = posixpath.normpath(text)
    if not normalized or normalized == ".":
        return "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if had_trailing_slash:
        normalized += "/"
    return normalized


def normalize_query(query):
    text = (query or "").strip()
    if not text:
        return ""
    slash_index = text.find("/")
    if slash_index != -1:
        text = text[:slash_index]
    return text.rstrip("&")


def extract_input_tokens(url, post_data):
    tokens = []
    seen = set()

    try:
        query = urlsplit(url).query
    except Exception:
        query = ""

    for raw in (query, post_data or ""):
        for item in str(raw).split("&"):
            token = item.strip()
            if not token or token in seen:
                continue
            seen.add(token)
            tokens.append(token)
    return tokens


def parse_post_line(line):
    text = (line or "").strip()
    if not text.upper().startswith("POST:"):
        return None
    return text[5:].strip()


def collect_entries_from_txt(txt_path):
    entries = []
    current_entry = None

    with open(txt_path, "r", encoding="utf-8", errors="ignore") as rf:
        for raw_line in rf:
            line = raw_line.strip()
            if not line:
                continue

            post_data = parse_post_line(line)
            if post_data is not None:
                if current_entry is not None:
                    current_entry["_method"] = "POST"
                    current_entry["_postData"] = post_data
                    current_entry["_headers"]["content-type"] = "application/x-www-form-urlencoded"
                continue

            raw_url = extract_url_from_line(line)
            if not raw_url:
                continue

            url = normalize_url(raw_url)
            if not url:
                continue

            current_entry = {
                "_url": url,
                "_method": "GET",
                "_postData": "",
                "_headers": {},
            }
            entries.append(current_entry)

    return entries


def collect_entries_from_single_url(raw_url):
    url = normalize_url(raw_url)
    if not url:
        raise ValueError("无法解析输入 URL")
    return [{
        "_url": url,
        "_method": "GET",
        "_postData": "",
        "_headers": {},
    }]


def build_request_data(entries):
    requests_found = {}
    input_set = []
    seen_inputs = set()

    for idx, entry in enumerate(entries, 1):
        method = str(entry.get("_method", "GET") or "GET").upper()
        url = str(entry.get("_url", "") or "")
        post_data = str(entry.get("_postData", "") or "")
        headers = dict(entry.get("_headers", {}) or {})
        key_suffix = post_data if method == "POST" else ""
        request_key = "{} {} {}".format(method, url, key_suffix)

        requests_found[request_key] = {
            "_id": idx,
            "_urlstr": url,
            "_url": url,
            "_resourceType": "document",
            "_method": method,
            "_postData": post_data,
            "_headers": headers,
            "attempts": 0,
            "processed": 0,
            "from": "urlOrTxtImport",
            "key": request_key,
        }

        for token in extract_input_tokens(url, post_data):
            if token in seen_inputs:
                continue
            seen_inputs.add(token)
            input_set.append(token)

    return {
        "requestsFound": requests_found,
        "seedRequestsFound": {},
        "inputSet": input_set,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate Witcher request_data.json from one URL or a txt file."
    )
    parser.add_argument(
        "source",
        help="A single URL, or a txt file path. In txt mode, a line starting with POST: belongs to the previous URL.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output request_data.json path. Default: next to txt file, or ./request_data.json for single URL input.",
    )
    return parser.parse_args()


def resolve_output_path(source, explicit_output):
    if explicit_output:
        return os.path.abspath(explicit_output)
    if os.path.isfile(source):
        return os.path.join(os.path.dirname(os.path.abspath(source)), "request_data.json")
    return os.path.abspath("request_data.json")


def main():
    args = parse_args()
    source = args.source

    if os.path.isfile(source):
        entries = collect_entries_from_txt(source)
        source_desc = os.path.abspath(source)
    else:
        entries = collect_entries_from_single_url(source)
        source_desc = source

    request_data = build_request_data(entries)
    output_path = resolve_output_path(source, args.output)

    with open(output_path, "w", encoding="utf-8") as wf:
        json.dump(request_data, wf, ensure_ascii=False, indent=2)

    print("Loaded {}".format(source_desc))
    print("Collected {} requests".format(len(request_data["requestsFound"])))
    print("Collected {} inputSet items".format(len(request_data["inputSet"])))
    print("Wrote {}".format(output_path))


if __name__ == "__main__":
    main()
