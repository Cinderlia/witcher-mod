import argparse
import json
import re
import sys
from collections import OrderedDict
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlparse


def _as_url_string(req: Any) -> str:
    if not isinstance(req, dict):
        return ""
    v = req.get("_url")
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        href = v.get("href") or v.get("url") or v.get("_url")
        return href if isinstance(href, str) else ""
    v = req.get("_urlstr")
    if isinstance(v, str):
        return v
    v = req.get("url")
    return v if isinstance(v, str) else ""


def _canon_path(p: str) -> str:
    s = (p or "").strip().replace("\\", "/")
    if s.startswith("/app/"):
        s = s[5:]
    if s.startswith("/"):
        s = s[1:]
    return s.lower()


def _canon_url(u: str) -> str:
    return (u or "").strip()


def _split_rule(raw: str) -> Tuple[str, str]:
    s = (raw or "").strip()
    if not s:
        return "path", ""
    if s.startswith("re:"):
        return "re", s[3:]
    if "://" in s:
        return "url", s
    return "path", s


def _compile_rules(entries: Iterable[str]):
    out = []
    for raw in entries or []:
        kind, val = _split_rule(raw)
        if not val:
            continue
        if kind == "re":
            out.append(("re", re.compile(val)))
        elif kind == "url":
            out.append(("url", _canon_url(val)))
        else:
            out.append(("path", _canon_path(val)))
    return out


def _match(url: str, rules) -> bool:
    u = _canon_url(url)
    if not u:
        return False
    parsed = urlparse(u)
    upath = _canon_path(parsed.path or "")
    for kind, rule in rules:
        if kind == "re":
            if rule.search(u):
                return True
        elif kind == "url":
            if u == rule or u.startswith(rule):
                return True
        else:
            if not rule:
                continue
            if upath == rule or upath.endswith("/" + rule) or upath.endswith(rule):
                return True
    return False


def _filter_request_map(req_map: Any, rules) -> "OrderedDict[str, Any]":
    out: "OrderedDict[str, Any]" = OrderedDict()
    if not isinstance(req_map, dict):
        return out
    for k, v in req_map.items():
        u = _as_url_string(v)
        if _match(u, rules):
            out[k] = v
    return out


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def _dump_json(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def parse_args(argv):
    p = argparse.ArgumentParser()
    p.add_argument("request_data_json")
    p.add_argument(
        "--entry",
        action="append",
        required=True,
        help="Match rule. Supports: URL, path, or re:<regex>. Examples: /administrator/index.php , re:option=com_templates , http://host/path",
    )
    p.add_argument("--output", default="")
    p.add_argument("--inplace", action="store_true")
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    rules = _compile_rules(args.entry)
    if not rules:
        raise SystemExit("no valid --entry rule")

    obj = _load_json(args.request_data_json)
    out_path = args.request_data_json if args.inplace else (args.output or (args.request_data_json + ".filtered.json"))

    if isinstance(obj, dict) and isinstance(obj.get("requestsFound"), dict):
        out_obj: Dict[str, Any] = dict(obj)
        out_obj["requestsFound"] = _filter_request_map(obj.get("requestsFound"), rules)
        if isinstance(obj.get("seedRequestsFound"), dict):
            out_obj["seedRequestsFound"] = _filter_request_map(obj.get("seedRequestsFound"), rules)
        _dump_json(out_path, out_obj)
        return 0

    filtered = _filter_request_map(obj, rules)
    _dump_json(out_path, {"requestsFound": filtered})
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

