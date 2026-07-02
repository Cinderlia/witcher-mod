"""
Load and normalize configuration for the branch-selection pipeline.
"""

import json
import os
try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class BranchSelectorConfig:
    seq_start: int = 0
    seq_limit: int = 10000
    buffer_token_limit: int = 3000
    buffer_count: int = 1
    sql_buffer_token_limit: int = 3000
    sql_buffer_count: int = 1
    xss_buffer_token_limit: int = 3000
    xss_buffer_count: int = 1
    cmd_buffer_token_limit: int = 3000
    cmd_buffer_count: int = 1
    enable_if: bool = True
    enable_switch: bool = True
    enable_sql: bool = True
    enable_xss: bool = True
    enable_cmd: bool = True
    max_analyze_concurrency: int = 5
    log_level: str = "INFO"
    if_branch_cache_skip: bool = False
    test_mode: bool = True
    analyze_llm_test_mode: bool = True
    llm_max_attempts: int = 0
    llm_temperature: float = 0.8
    nearest_seq_count: int = 3
    farthest_seq_count: int = 3
    base_prompt: str = ""
    prompt_out_dir: str = os.path.join("test", "branch_selector", "prompts")
    response_out_dir: str = os.path.join("test", "branch_selector", "responses")
    trace_index_path: str = os.path.join("tmp", "trace_index.json")
    scope_root: str = "/app"
    windows_root: str = r"D:\files\witcher\app"


def _default_config() -> BranchSelectorConfig:
    return BranchSelectorConfig()


def _resolve_config_path(base: str, root: str, repo_root: str, config_path: Optional[str]) -> str:
    candidates = []
    req = (config_path or "").strip() if isinstance(config_path, str) else ""
    if req:
        primary = os.path.abspath(req)
        candidates.append(primary)
        name = os.path.basename(primary).lower()
        if name == "config.json":
            candidates.append(os.path.join(os.path.dirname(primary), "symex_config.json"))
        elif name == "symex_config.json":
            candidates.append(os.path.join(os.path.dirname(primary), "config.json"))
    else:
        for folder in (repo_root, root, base):
            candidates.append(os.path.join(folder, "symex_config.json"))
            candidates.append(os.path.join(folder, "config.json"))
    seen = set()
    for cand in candidates:
        key = os.path.normcase(os.path.abspath(cand))
        if key in seen:
            continue
        seen.add(key)
        if os.path.exists(cand):
            return cand
    return ""


# Summary: Resolve config.json location and coerce fields into a BranchSelectorConfig instance.
def load_config(config_path: Optional[str] = None) -> BranchSelectorConfig:
    base = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(base)
    repo_root = os.path.dirname(root)
    cfg_path = _resolve_config_path(base, root, repo_root, config_path)
    if not cfg_path:
        return _default_config()
    try:
        with open(cfg_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return _default_config()
    if not isinstance(obj, dict):
        return _default_config()
    if isinstance(obj.get("branch_selector"), dict):
        obj = obj.get("branch_selector") or {}
    def _get_int(k: str, d: int) -> int:
        v = obj.get(k)
        try:
            return int(v) if v is not None else d
        except Exception:
            return d
    def _get_bool(k: str, d: bool) -> bool:
        v = obj.get(k)
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "on"):
                return True
            if s in ("0", "false", "no", "off"):
                return False
        return d
    def _get_str(k: str, d: str) -> str:
        v = obj.get(k)
        return str(v).strip() if isinstance(v, str) else d
    def _get_float(k: str, d: float) -> float:
        v = obj.get(k)
        try:
            return float(v) if v is not None else d
        except Exception:
            return d
    return BranchSelectorConfig(
        seq_start=_get_int("seq_start", 0),
        seq_limit=_get_int("seq_limit", 10000),
        buffer_token_limit=_get_int("buffer_token_limit", 3000),
        buffer_count=_get_int("buffer_count", 1),
        sql_buffer_token_limit=_get_int("sql_buffer_token_limit", 3000),
        sql_buffer_count=_get_int("sql_buffer_count", 1),
        xss_buffer_token_limit=_get_int("xss_buffer_token_limit", 3000),
        xss_buffer_count=_get_int("xss_buffer_count", 1),
        cmd_buffer_token_limit=_get_int("cmd_buffer_token_limit", 3000),
        cmd_buffer_count=_get_int("cmd_buffer_count", 1),
        enable_if=_get_bool("enable_if", True),
        enable_switch=_get_bool("enable_switch", True),
        enable_sql=_get_bool("enable_sql", True),
        enable_xss=_get_bool("enable_xss", True),
        enable_cmd=_get_bool("enable_cmd", True),
        max_analyze_concurrency=_get_int("max_analyze_concurrency", 5),
        log_level=_get_str("log_level", "INFO"),
        if_branch_cache_skip=_get_bool("if_branch_cache_skip", False),
        test_mode=_get_bool("test_mode", True),
        analyze_llm_test_mode=_get_bool("analyze_llm_test_mode", True),
        llm_max_attempts=_get_int("llm_max_attempts", 0),
        llm_temperature=_get_float("llm_temperature", 0.8),
        nearest_seq_count=_get_int("nearest_seq_count", 3),
        farthest_seq_count=_get_int("farthest_seq_count", 3),
        base_prompt=_get_str("base_prompt", ""),
        prompt_out_dir=_get_str("prompt_out_dir", os.path.join("test", "branch_selector", "prompts")),
        response_out_dir=_get_str("response_out_dir", os.path.join("test", "branch_selector", "responses")),
        trace_index_path=_get_str("trace_index_path", os.path.join("tmp", "trace_index.json")),
        scope_root=_get_str("scope_root", "/app"),
        windows_root=_get_str("windows_root", r"D:\files\witcher\app"),
    )
