import argparse
import glob
import json
import os
import posixpath
import re
from urllib.parse import urlsplit, urlunsplit


URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)
TOP_PATTERN = re.compile(r"#top", re.IGNORECASE)
SLASH_PATTERN = re.compile(r"/{2,}")


def extract_urls_from_line(line):
    text = (line or "").strip()
    if not text:
        return []
    return URL_PATTERN.findall(text)


def normalize_url(raw_url):
    url = (raw_url or "").strip().strip("'\"")
    if not url:
        return None

    # Black Widow output may inject repeated "#top" fragments into the middle
    # of a URL. Remove them before parsing so the real path/query can be kept.
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

    # Black Widow output may append another path after the real query string,
    # such as "...&Itemid=101//joomla/index.php?...". Keep only the query part.
    slash_index = text.find("/")
    if slash_index != -1:
        text = text[:slash_index]

    text = text.rstrip("&")
    return text


def extract_input_tokens(url):
    try:
        query = urlsplit(url).query
    except Exception:
        return []

    if not query:
        return []

    out = []
    seen = set()
    for item in query.split("&"):
        token = item.strip()
        if not token:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def build_request_data(urls, input_set):
    requests_found = {}
    next_id = 1

    for url in urls:
        key = "GET {} ".format(url)
        requests_found[key] = {
            "_id": next_id,
            "_urlstr": url,
            "_url": url,
            "_resourceType": "document",
            "_method": "GET",
            "_postData": "",
            "_headers": {},
            "attempts": 0,
            "processed": 0,
            "from": "blackwidowTxtImport",
            "key": key,
        }
        next_id += 1

    return {
        "requestsFound": requests_found,
        "inputSet": input_set,
    }


def collect_urls(input_dir):
    txt_files = sorted(glob.glob(os.path.join(input_dir, "*.txt")))
    normalized_urls = []
    input_set = []
    seen = set()
    seen_inputs = set()

    for txt_file in txt_files:
        with open(txt_file, "r", encoding="utf-8", errors="ignore") as rf:
            for line in rf:
                for raw_url in extract_urls_from_line(line):
                    url = normalize_url(raw_url)
                    if not url or url in seen:
                        continue
                    seen.add(url)
                    normalized_urls.append(url)
                    for token in extract_input_tokens(url):
                        if token in seen_inputs:
                            continue
                        seen_inputs.add(token)
                        input_set.append(token)

    return txt_files, normalized_urls, input_set


def main():
    default_dir = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(
        description="Read all txt files in a directory and generate Witcher request_data.json."
    )
    parser.add_argument(
        "--input-dir",
        default=default_dir,
        help="Directory containing Black Widow txt files. Default: script directory.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path. Default: <input-dir>/request_data.json",
    )
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input_dir)
    output_path = os.path.abspath(args.output or os.path.join(input_dir, "request_data.json"))

    txt_files, urls, input_set = collect_urls(input_dir)
    request_data = build_request_data(urls, input_set)

    with open(output_path, "w", encoding="utf-8") as wf:
        json.dump(request_data, wf, ensure_ascii=False, indent=2)

    print("Loaded {} txt files".format(len(txt_files)))
    print("Collected {} unique URLs".format(len(urls)))
    print("Collected {} inputSet items".format(len(input_set)))
    print("Wrote {}".format(output_path))


if __name__ == "__main__":
    main()
