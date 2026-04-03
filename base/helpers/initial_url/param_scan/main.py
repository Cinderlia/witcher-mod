import json
from pathlib import Path
from typing import Dict, List, Set

from .extract import extract_params_from_tree


def run(tree, base_appdir: str, max_file_bytes: int, output_filenames: Dict[str, str]) -> Dict[str, Dict[str, Set[str]]]:
    base_dir = Path(base_appdir)
    params = extract_params_from_tree(tree, max_file_bytes=max_file_bytes)

    out_json = output_filenames.get("params_json", "initial_params.json")
    out_get = output_filenames.get("params_get_txt", "initial_params_get.txt")
    out_post = output_filenames.get("params_post_txt", "initial_params_post.txt")
    out_cookie = output_filenames.get("params_cookie_txt", "initial_params_cookie.txt")

    json_obj = {
        "GET": _to_sorted_dict(params.get("GET", {})),
        "POST": _to_sorted_dict(params.get("POST", {})),
        "COOKIE": _to_sorted_dict(params.get("COOKIE", {})),
    }
    with open(base_dir / out_json, "w", encoding="utf-8") as wf:
        json.dump(json_obj, wf, ensure_ascii=False, indent=2)

    _write_kv_lines(base_dir / out_get, json_obj["GET"])
    _write_kv_lines(base_dir / out_post, json_obj["POST"])
    _write_kv_lines(base_dir / out_cookie, json_obj["COOKIE"])

    return params


def _to_sorted_dict(d: Dict[str, Set[str]]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for k in sorted(d.keys()):
        out[k] = sorted(list(d[k]))
    return out


def _write_kv_lines(path: Path, d: Dict[str, List[str]]) -> None:
    with open(path, "w", encoding="utf-8") as wf:
        for k in sorted(d.keys()):
            vals = d[k]
            if not vals:
                wf.write("{}=1\n".format(k))
                continue
            for v in vals:
                wf.write("{}={}\n".format(k, v))

