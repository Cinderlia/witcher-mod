import argparse
import json
import os
import signal
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional

try:
    from .code_scan.main import collect_urls as collect_code_scan_urls
except Exception:
    from code_scan.main import collect_urls as collect_code_scan_urls

try:
    from .code_scan.url_build import build_url as build_initial_url
except Exception:
    try:
        from code_scan.url_build import build_url as build_initial_url
    except Exception:
        build_initial_url = None

try:
    from .tree_loader import build_php_tree, leaf_relpaths
except Exception:
    from tree_loader import build_php_tree, leaf_relpaths

try:
    from .param_scan.main import run as run_param_scan
except Exception:
    from param_scan.main import run as run_param_scan


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("base_url")
    p.add_argument("base_appdir")
    p.add_argument("source_dir")
    p.add_argument("--output", default="initial_urls.txt")
    p.add_argument("--max-file-bytes", type=int, default=5 * 1024 * 1024)
    p.add_argument("--config", default="initial_url_config.json")
    p.add_argument("--start-crawler", action="store_true")
    p.add_argument("--no-headless", action="store_true")
    p.add_argument("--xvfb", action="store_true")
    p.add_argument("--timeout", default="")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    base_url = args.base_url
    base_appdir = Path(args.base_appdir)
    source_dir = Path(args.source_dir)
    output_path = base_appdir / args.output
    config_path = base_appdir / args.config

    if not base_appdir.exists() or not base_appdir.is_dir():
        raise SystemExit("base_appdir not found or not a directory: {}".format(str(base_appdir)))
    if not source_dir.exists() or not source_dir.is_dir():
        raise SystemExit("source_dir not found or not a directory: {}".format(str(source_dir)))

    cfg = load_config(config_path)

    request_data_path = base_appdir / "request_data.json"
    init_meta = read_request_data_init_meta(str(base_appdir))

    cfg_code_scan = cfg.get("enable_code_scan", True)
    cfg_param_scan = cfg.get("enable_param_scan", True)

    run_code_scan = cfg_code_scan and (init_meta.get("code_scan") is not True)
    run_param_pipeline = cfg_param_scan and (init_meta.get("param_scan") is not True)

    if (not run_code_scan) and (not run_param_pipeline):
        crawler_cfg = cfg.get("crawler", {})
        start_crawler = args.start_crawler or (isinstance(crawler_cfg, dict) and crawler_cfg.get("start", False))
        if start_crawler:
            if args.xvfb:
                if not isinstance(crawler_cfg, dict):
                    crawler_cfg = {}
                crawler_cfg["xvfb"] = True
            if args.no_headless:
                if not isinstance(crawler_cfg, dict):
                    crawler_cfg = {}
                crawler_cfg["no_headless"] = True
            if args.timeout:
                if not isinstance(crawler_cfg, dict):
                    crawler_cfg = {}
                crawler_cfg["timeout"] = args.timeout
            _start_request_crawler(base_url, str(base_appdir), crawler_cfg)
        return 0

    tree = build_php_tree(str(source_dir))
    # Removed redundant archive output: php_files.txt was not consumed by downstream pipeline.

    urls = []
    valid_entry_files = None
    raw_code_urls = []

    if run_code_scan:
        cs_raw_out_fn = "initial_urls_code_scan_raw.txt"
        raw_code_urls = collect_code_scan_urls(
            base_url=base_url,
            source_dir=source_dir,
            max_file_bytes=args.max_file_bytes,
            tree=None,
        )
        write_lines(base_appdir / cs_raw_out_fn, raw_code_urls)

    if run_param_pipeline:
        ps_cfg = cfg.get("param_scan", {})
        run_param_scan(
            tree=tree,
            base_appdir=str(base_appdir),
            max_file_bytes=args.max_file_bytes,
            output_filenames={
                "params_json": ps_cfg.get("params_json", "initial_params.json"),
                "params_get_txt": ps_cfg.get("params_get_txt", "initial_params_get.txt"),
                "params_post_txt": ps_cfg.get("params_post_txt", "initial_params_post.txt"),
                "params_cookie_txt": ps_cfg.get("params_cookie_txt", "initial_params_cookie.txt"),
            },
        )

        unselected_urls = build_unselected_urls(tree, base_url)
        unselected_out = cfg.get("code_scan", {}).get("unselected_output_filename", "initial_urls_unselected.txt")
        write_lines(base_appdir / unselected_out, unselected_urls)

        crawler_cfg = cfg.get("crawler", {})
        start_crawler = args.start_crawler or (isinstance(crawler_cfg, dict) and crawler_cfg.get("start", False))
        
        if start_crawler:
            if args.xvfb:
                if not isinstance(crawler_cfg, dict):
                    crawler_cfg = {}
                crawler_cfg["xvfb"] = True
            if args.no_headless:
                if not isinstance(crawler_cfg, dict):
                    crawler_cfg = {}
                crawler_cfg["no_headless"] = True
            if args.timeout:
                if not isinstance(crawler_cfg, dict):
                    crawler_cfg = {}
                crawler_cfg["timeout"] = args.timeout
    
            rc = _run_param_minimizer(base_url, str(base_appdir), cfg, crawler_cfg)
            if rc == 0:
                update_request_data_meta(str(base_appdir), {"param_scan": True})
                
                valid_entry_files = set()
                try:
                    with open(base_appdir / "afl_request_data.json", "r", encoding="utf-8") as rf:
                        data = json.load(rf)
                        reqs = data.get("requestsFound", {})
                        for req in reqs.values():
                            if req.get("from") == "initialParamMin":
                                u = req.get("_urlstr", "")
                                if u:
                                    base_u = u.split("?")[0].split("#")[0]
                                    valid_entry_files.add(base_u)
                except Exception:
                    pass

    if run_code_scan:
        cs_out_fn = cfg.get("code_scan", {}).get("output_filename", args.output)
        code_urls = list(raw_code_urls)

        if valid_entry_files is not None:
            filtered_code_urls = []
            for cu in code_urls:
                cu_base = cu.split("?")[0].split("#")[0]
                if cu_base in valid_entry_files:
                    filtered_code_urls.append(cu)
            code_urls = filtered_code_urls

        write_lines(base_appdir / cs_out_fn, code_urls)
        urls.extend(code_urls)
        seed_afl_request_data_json(str(base_appdir), code_urls)
        update_request_data_meta(str(base_appdir), {"code_scan": True})
        # Removed redundant archive output: selected_php_files.txt was not consumed downstream.

    integrated_out_fn = cfg.get("integrated_urls_filename", args.output)
    integrated_path = output_path if integrated_out_fn == args.output else (base_appdir / integrated_out_fn)
    write_lines(integrated_path, urls)

    crawler_cfg = cfg.get("crawler", {})
    start_crawler = args.start_crawler or (isinstance(crawler_cfg, dict) and crawler_cfg.get("start", False))
    if start_crawler:
        if args.xvfb:
            if not isinstance(crawler_cfg, dict):
                crawler_cfg = {}
            crawler_cfg["xvfb"] = True
        if args.no_headless:
            if not isinstance(crawler_cfg, dict):
                crawler_cfg = {}
            crawler_cfg["no_headless"] = True
        if args.timeout:
            if not isinstance(crawler_cfg, dict):
                crawler_cfg = {}
            crawler_cfg["timeout"] = args.timeout

        _start_request_crawler(base_url, str(base_appdir), crawler_cfg)

    return 0


def integrate_urls(url_lists: Iterable[List[str]]) -> List[str]:
    out: List[str] = []
    for lst in url_lists:
        out.extend(lst)
    return out


def load_config(path: Path) -> dict:
    if not path.exists():
        return default_config()
    try:
        with open(path, "r", encoding="utf-8") as rf:
            obj = json.load(rf)
            if isinstance(obj, dict):
                merged = default_config()
                merged.update(obj)
                return merged
    except Exception:
        return default_config()
    return default_config()


def default_config() -> dict:
    return {
        "enable_code_scan": True,
        "enable_param_scan": True,
        "php_list_filename": "php_files.txt",
        "integrated_urls_filename": "initial_urls.txt",
        "code_scan": {
            "output_filename": "initial_urls_code_scan.txt",
            "unselected_output_filename": "initial_urls_unselected.txt"
        },
        "param_scan": {
            "params_json": "initial_params.json",
            "params_get_txt": "initial_params_get.txt",
            "params_post_txt": "initial_params_post.txt",
            "params_cookie_txt": "initial_params_cookie.txt",
        },
        "param_minimizer": {
            "urls_filename": "initial_urls_unselected.txt",
            "params_json": "initial_params.json",
            "mode_arg": "request_crawler",
            "accept_full_params_without_minimization": False,
            "full_params_output_filename": "initial_urls_full_params.txt"
        },
        "crawler": {
            "start": False,
            "node_bin": "node",
            "no_headless": False,
            "xvfb": True,
            "timeout": "4h",
            "mode_arg": "request_crawler"
        },
    }


def dedupe_list(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for it in items:
        if it in seen:
            continue
        seen.add(it)
        out.append(it)
    return out


def write_lines(path: Path, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as wf:
        for ln in lines:
            wf.write(ln)
            wf.write("\n")


def _start_request_crawler(base_url: str, base_appdir: str, crawler_cfg: dict) -> None:
    try:
        node_bin = "node"
        if isinstance(crawler_cfg, dict) and crawler_cfg.get("node_bin"):
            node_bin = crawler_cfg.get("node_bin")

        no_headless = False
        if isinstance(crawler_cfg, dict) and crawler_cfg.get("no_headless", False):
            no_headless = True

        use_xvfb = False
        if isinstance(crawler_cfg, dict) and crawler_cfg.get("xvfb", False):
            use_xvfb = True

        timeout_value = ""
        if isinstance(crawler_cfg, dict) and crawler_cfg.get("timeout"):
            timeout_value = str(crawler_cfg.get("timeout") or "").strip()

        mode_arg = ""
        if isinstance(crawler_cfg, dict) and crawler_cfg.get("mode_arg"):
            mode_arg = str(crawler_cfg.get("mode_arg") or "").strip()

        crawler_js = (Path(__file__).resolve().parent.parent / "request_crawler" / "main.js").resolve()
        cmd = []
        if timeout_value:
            kill_after = "30s"
            if isinstance(crawler_cfg, dict) and crawler_cfg.get("timeout_kill_after"):
                kill_after = str(crawler_cfg.get("timeout_kill_after") or "").strip() or "30s"
            cmd.extend(["timeout", "-k", kill_after, timeout_value])
        if use_xvfb:
            cmd.extend(["xvfb-run", "-a"])

        cmd.extend([node_bin, str(crawler_js.parent / "main.js")])
        if mode_arg:
            cmd.append(mode_arg)
        cmd.extend([base_url, base_appdir])
        if no_headless:
            cmd.append("--no-headless")

        _run_foreground(cmd)
    except Exception:
        pass


def build_unselected_urls(tree, base_url: str) -> List[str]:
    out = []
    for leaf in tree.leaves:
        try:
            if getattr(leaf, "selected", False):
                continue
            rel = tree.rel_posix_path(leaf)
            if build_initial_url is not None:
                built = build_initial_url(base_url, rel, "")
                out.append(built.href)
            else:
                base = base_url if base_url.endswith("/") else (base_url + "/")
                out.append((base + rel.lstrip("/")))
        except Exception:
            continue
    out.sort()
    return dedupe_list(out)


def read_request_data_init_meta(base_appdir: str) -> dict:
    fn = Path(base_appdir) / "request_data.json"
    if not fn.exists():
        return {}
    try:
        with open(fn, "r", encoding="utf-8") as rf:
            obj = json.load(rf)
            if not isinstance(obj, dict):
                return {}
            meta = obj.get("_witcher_meta")
            if not isinstance(meta, dict):
                return {}
            init = meta.get("init")
            if not isinstance(init, dict):
                return {}
            return init
    except Exception:
        return {}


def get_selected_relpaths(tree) -> List[str]:
    out = []
    for leaf in tree.leaves:
        try:
            if getattr(leaf, "selected", False):
                out.append(tree.rel_posix_path(leaf))
        except Exception:
            pass
    out.sort()
    return dedupe_list(out)


def apply_selected_from_file(tree, selected_file: Path) -> None:
    try:
        if not selected_file.exists():
            return
        lines = selected_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        for ln in lines:
            frag = (ln or "").strip()
            if not frag:
                continue
            leaves = tree.match_fragment(frag)
            for leaf in leaves:
                try:
                    leaf.selected = True
                except Exception:
                    pass
    except Exception:
        return


def seed_afl_request_data_json(base_appdir: str, urls: List[str]) -> None:
    fn = Path(base_appdir) / "afl_request_data.json"
    data = {"requestsFound": {}, "inputSet": []}
    if fn.exists():
        try:
            with open(fn, "r", encoding="utf-8") as rf:
                obj = json.load(rf)
                if isinstance(obj, dict) and isinstance(obj.get("requestsFound"), dict):
                    data = obj
        except Exception:
            data = {"requestsFound": {}, "inputSet": []}

    store = data.get("requestsFound")
    if not isinstance(store, dict):
        store = {}
        data["requestsFound"] = store

    next_id = 1
    for v in store.values():
        if isinstance(v, dict) and "_id" in v:
            try:
                next_id = max(next_id, int(v["_id"]) + 1)
            except Exception:
                pass

    added = 0
    for u in urls:
        url = (u or "").strip()
        if not url:
            continue
        key = "GET {} ".format(url)
        if key in store:
            continue
        store[key] = {
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
            "key": key,
        }
        next_id += 1
        added += 1

    with open(fn, "w", encoding="utf-8") as wf:
        json.dump(data, wf, ensure_ascii=False, indent=2)


def update_request_data_meta(base_appdir: str, init_updates: dict) -> None:
    fn = Path(base_appdir) / "request_data.json"
    data = {}
    if fn.exists():
        try:
            with open(fn, "r", encoding="utf-8") as rf:
                obj = json.load(rf)
                if isinstance(obj, dict):
                    data = obj
        except Exception:
            data = {}

    meta = data.get("_witcher_meta")
    if not isinstance(meta, dict):
        meta = {}
    init = meta.get("init")
    if not isinstance(init, dict):
        init = {}
    for k, v in init_updates.items():
        init[k] = v
    meta["init"] = init
    data["_witcher_meta"] = meta
    if "requestsFound" not in data:
        data["requestsFound"] = {}
    if "inputSet" not in data:
        data["inputSet"] = []
    try:
        with open(fn, "w", encoding="utf-8") as wf:
            json.dump(data, wf, ensure_ascii=False, indent=2)
    except Exception:
        pass

def _run_param_minimizer(base_url: str, base_appdir: str, cfg: dict, crawler_cfg: dict) -> int:
    pm_cfg = cfg.get("param_minimizer", {})
    if pm_cfg is False:
        return
    if isinstance(pm_cfg, dict) and not pm_cfg.get("enabled", True):
        return

    urls_fn = "initial_urls_unselected.txt"
    params_fn = "initial_params.json"
    mode_arg = "request_crawler"
    accept_full_params_without_minimization = False
    full_params_output_filename = "initial_urls_full_params.txt"
    if isinstance(pm_cfg, dict):
        if pm_cfg.get("urls_filename"):
            urls_fn = pm_cfg.get("urls_filename")
        if pm_cfg.get("params_json"):
            params_fn = pm_cfg.get("params_json")
        if pm_cfg.get("mode_arg"):
            mode_arg = pm_cfg.get("mode_arg")
        accept_full_params_without_minimization = bool(pm_cfg.get("accept_full_params_without_minimization", False))
        if pm_cfg.get("full_params_output_filename"):
            full_params_output_filename = str(pm_cfg.get("full_params_output_filename") or "").strip() or "initial_urls_full_params.txt"

    urls_path = str(Path(base_appdir) / urls_fn)
    params_path = str(Path(base_appdir) / params_fn)
    full_params_output_path = str(Path(base_appdir) / full_params_output_filename)
    if not Path(urls_path).exists() or not Path(params_path).exists():
        return 2

    node_bin = "node"
    if isinstance(crawler_cfg, dict) and crawler_cfg.get("node_bin"):
        node_bin = crawler_cfg.get("node_bin")

    no_headless = False
    if isinstance(crawler_cfg, dict) and crawler_cfg.get("no_headless", False):
        no_headless = True

    use_xvfb = False
    if isinstance(crawler_cfg, dict) and crawler_cfg.get("xvfb", False):
        use_xvfb = True

    timeout_value = ""
    if isinstance(crawler_cfg, dict) and crawler_cfg.get("timeout"):
        timeout_value = str(crawler_cfg.get("timeout") or "").strip()

    script_js = (Path(__file__).resolve().parent.parent / "request_crawler" / "param_minimizer.js").resolve()
    script_entry = str(script_js.parent / "param_minimizer.js")
    cmd = []
    if timeout_value:
        kill_after = "30s"
        if isinstance(crawler_cfg, dict) and crawler_cfg.get("timeout_kill_after"):
            kill_after = str(crawler_cfg.get("timeout_kill_after") or "").strip() or "30s"
        cmd.extend(["timeout", "-k", kill_after, timeout_value])
    if use_xvfb:
        cmd.extend(["xvfb-run", "-a"])
    cmd.extend([node_bin, script_entry])
    if mode_arg:
        cmd.append(mode_arg)
    cmd.extend([base_url, base_appdir, urls_path, params_path])
    if accept_full_params_without_minimization:
        cmd.append("--accept-full-params-without-minimization")
    if full_params_output_path:
        cmd.extend(["--full-params-output", full_params_output_path])
    if no_headless:
        cmd.append("--no-headless")
    return _run_foreground(cmd)


def _run_foreground(cmd: List[str]) -> int:
    p = None
    try:
        if os.name == "posix":
            p = subprocess.Popen(cmd, preexec_fn=os.setsid)
        else:
            p = subprocess.Popen(cmd)
        return p.wait()
    except KeyboardInterrupt:
        try:
            if p is None:
                raise SystemExit(130)
            if os.name == "posix":
                os.killpg(p.pid, signal.SIGINT)
            else:
                p.send_signal(signal.SIGINT)
            p.wait()
            raise SystemExit(130)
        except Exception:
            try:
                if p is not None:
                    p.terminate()
            except Exception:
                pass
            raise SystemExit(130)


if __name__ == "__main__":
    raise SystemExit(main())
