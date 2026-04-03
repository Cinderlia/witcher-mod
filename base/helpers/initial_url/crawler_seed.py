import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def seed_request_data_json(base_appdir: str, urls: List[str], filename: str = "request_data.json") -> Tuple[int, int]:
    base_dir = Path(base_appdir)
    out_path = base_dir / filename

    data = _load_request_data(out_path)
    if "requestsFound" not in data or not isinstance(data["requestsFound"], dict):
        data["requestsFound"] = {}
    if "inputSet" not in data or not isinstance(data["inputSet"], list):
        data["inputSet"] = []

    requests_found = data["requestsFound"]
    next_id = _next_id(requests_found)

    added = 0
    reset = 0
    for u in urls:
        url = (u or "").strip()
        if not url:
            continue
        reqkey = _get_request_key("GET", url, "")
        if reqkey in requests_found:
            try:
                req = requests_found[reqkey]
                if isinstance(req, dict):
                    req["attempts"] = 0
                    req["processed"] = 0
                    req["from"] = "initialCodeScan"
                reset += 1
            except Exception:
                pass
            continue

        entry = {
            "_id": next_id,
            "_urlstr": url,
            "_url": url,
            "_resourceType": "document",
            "_method": "GET",
            "_postData": "",
            "_headers": {},
            "attempts": 0,
            "processed": 0,
            "from": "initialCodeScan",
            "key": reqkey,
        }
        requests_found[reqkey] = entry
        next_id += 1
        added += 1

    with open(out_path, "w", encoding="utf-8") as wf:
        json.dump(data, wf, ensure_ascii=False, indent=2)

    return added, reset


def _load_request_data(path: Path) -> Dict:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as rf:
            obj = json.load(rf)
            if isinstance(obj, dict):
                return obj
    except Exception:
        return {}
    return {}


def _next_id(requests_found: Dict) -> int:
    mx = 0
    try:
        for v in requests_found.values():
            if isinstance(v, dict) and "_id" in v:
                try:
                    mx = max(mx, int(v["_id"]))
                except Exception:
                    pass
    except Exception:
        return 1
    return mx + 1


def _get_request_key(method: str, url: str, post_data: str) -> str:
    return "{} {} {}".format(method.upper(), url, post_data)

