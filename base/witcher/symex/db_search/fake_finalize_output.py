"""Minimal helper to simulate finalize output without calling db_search/LLM."""

import os
import re
import sys
from typing import Optional

from runtime_bridge import resolve_db_runtime_paths, ensure_db_runtime_layout, allocate_external_seed_id


_ID_RE = re.compile(r"^id:(\d+)")


def _parse_parent_seed_id_from_cwd(cwd: str) -> str:
    name = os.path.basename(os.path.abspath(cwd.rstrip("/\\")))
    m = re.search(r"(?:^|,)id:(\d+)(?:,|$)", name)
    if not m:
        return "000000"
    return "%06d" % int(m.group(1))


def _write_text(path: str, text: str) -> str:
    out_path = os.path.abspath(path)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(str(text or ""))
    os.replace(tmp_path, out_path)
    return out_path


def _format_seed_name(*, seed_id: int, srcid: str, seq: int) -> str:
    return "id:%06d,src:fuzzer-master,srcid:%s,seq:%d,idx:1,mods:SQL" % (int(seed_id), str(srcid), int(seq))


def _format_sql_log_name(*, srcid: str, newid: int, seq: int) -> str:
    return "fuzzer-master_srcid-%s_newid-%06d_seq-%d.sql" % (str(srcid), int(newid), int(seq))


def main(argv: list) -> int:
    seq = 1
    if len(argv) >= 2:
        seq = int(argv[1])
    cwd = os.path.abspath(os.getcwd())
    parent_dir = os.path.dirname(cwd)
    paths = resolve_db_runtime_paths(work_dir=parent_dir)
    if paths is None:
        print("db_runtime_paths_unavailable", file=sys.stderr)
        return 1
    ensure_db_runtime_layout(paths)

    seed_dir = os.path.join(paths.extsync_dir, "seed")
    os.makedirs(seed_dir, exist_ok=True)
    os.makedirs(paths.runtime_dir, exist_ok=True)

    seed_id: Optional[int] = allocate_external_seed_id(paths)
    if seed_id is None:
        print("allocate_external_seed_id_failed", file=sys.stderr)
        return 2

    srcid = _parse_parent_seed_id_from_cwd(cwd)
    seed_name = _format_seed_name(seed_id=int(seed_id), srcid=srcid, seq=int(seq))
    seed_path = os.path.join(seed_dir, seed_name)
    _write_text(seed_path, "coo")

    sql_name = _format_sql_log_name(srcid=srcid, newid=int(seed_id), seq=int(seq))
    sql_path = os.path.join(paths.runtime_dir, sql_name)
    sql_text = "\n".join([
        "-- fuzzer: fuzzer-master",
        "-- seed_id: " + str(srcid),
        "-- new_seed_id: %06d" % int(seed_id),
        "-- target_seq: %d" % int(seq),
        "-- phase: finalize",
        "",
        "SELECT 1;",
        "",
    ])
    _write_text(sql_path, sql_text)

    print(seed_path)
    print(sql_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
