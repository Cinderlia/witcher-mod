import os
from pathlib import Path
from typing import Iterable, List, Optional

import argparse
try:
    from ..datastructures.php_tree import PhpFileTree
except Exception:
    try:
        from helpers.initial_url.datastructures.php_tree import PhpFileTree
    except Exception:
        try:
            from initial_url.datastructures.php_tree import PhpFileTree
        except Exception:
            from datastructures.php_tree import PhpFileTree
from .dedupe import dedupe_preserve_order
from .url_build import build_url
from .url_extract import build_query_string, extract_raw_php_urls, normalize_query


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("base_url")
    p.add_argument("base_appdir")
    p.add_argument("source_dir")
    p.add_argument("--output", default="initial_urls_code_scan.txt")
    p.add_argument("--max-file-bytes", type=int, default=5 * 1024 * 1024)
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    base_url = args.base_url
    base_appdir = Path(args.base_appdir)
    source_dir = Path(args.source_dir)
    output_path = base_appdir / args.output

    if not base_appdir.exists() or not base_appdir.is_dir():
        raise SystemExit("base_appdir not found or not a directory: {}".format(str(base_appdir)))
    if not source_dir.exists() or not source_dir.is_dir():
        raise SystemExit("source_dir not found or not a directory: {}".format(str(source_dir)))

    urls = collect_urls(
        base_url=base_url,
        source_dir=source_dir,
        max_file_bytes=args.max_file_bytes,
        tree=None,
    )

    with open(output_path, "w", encoding="utf-8") as wf:
        for u in urls:
            wf.write(u)
            wf.write("\n")

    return 0


def collect_urls(
    base_url: str,
    source_dir: Path,
    max_file_bytes: int,
    tree: Optional["PhpFileTree"] = None,
) -> List[str]:
    if tree is None:
        tree = PhpFileTree(source_dir)
        tree.build()

    urls: List[str] = []

    for abs_file in iter_source_files(source_dir):
        text = try_read_text(abs_file, max_file_bytes=max_file_bytes)
        if text is None:
            continue
        for cand in extract_raw_php_urls(text):
            pairs = normalize_query(cand.query)
            qs = build_query_string(pairs)
            leaves = tree.match_fragment(cand.path)
            if not leaves:
                continue
            for leaf in leaves:
                try:
                    leaf.selected = True
                except Exception:
                    pass
                rel = tree.rel_posix_path(leaf)
                built = build_url(base_url, rel, qs)
                urls.append(built.href)

    urls.sort()
    return dedupe_preserve_order(urls)


def iter_source_files(source_dir: Path) -> Iterable[Path]:
    skip_dirnames = {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        "__pycache__",
        "node_modules",
        "vendor",
        "bower_components",
        "third_party",
        "third-party",
        "thirdparty",
        "external",
        "externals",
        "deps",
        "dep",
        "dist",
        "build",
        "out",
        "target",
        "coverage",
        "docs",
        "doc",
        "tmp",
        "temp",
        "cache",
        "logs",
        "log",
        "runtime",
        "storage",
    }
    for dirpath, dirnames, filenames in os.walk(source_dir):
        dirnames[:] = [d for d in dirnames if d.lower() not in skip_dirnames]
        for fn in filenames:
            yield Path(dirpath) / fn


def try_read_text(path: Path, max_file_bytes: int) -> Optional[str]:
    try:
        st = path.stat()
        if st.st_size <= 0:
            return None
        if st.st_size > max_file_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None

    if b"\x00" in data:
        return None

    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        try:
            return data.decode(errors="ignore")
        except Exception:
            return None


if __name__ == "__main__":
    raise SystemExit(main())
