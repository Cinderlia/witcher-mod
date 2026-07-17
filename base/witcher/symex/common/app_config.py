"""
Application configuration loader for the trace/taint analysis pipeline.

Resolves config.json from CLI/env, normalizes input/tmp/test paths, and exposes helpers to locate inputs.
"""

import json
import os
try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set
from pathlib import Path


@dataclass(frozen=True)
class AppConfig:
    base_dir: str
    config_path: str
    input_dir: str
    tmp_dir: str
    test_dir: str
    output_dir: str
    app_name: str
    raw: Dict[str, Any]

    def input_path(self, *parts: str) -> str:
        return os.path.join(self.input_dir, *parts)

    def tmp_path(self, *parts: str) -> str:
        return os.path.join(self.tmp_dir, *parts)

    def test_path(self, *parts: str) -> str:
        return os.path.join(self.test_dir, *parts)

    def output_path(self, *parts: str) -> str:
        return os.path.join(self.output_dir, *parts)

    def find_input_file(self, name: str) -> str:
        c1 = self.input_path(name)
        if os.path.exists(c1):
            return c1
        raw = self.raw if isinstance(self.raw, dict) else {}
        ast_dir = raw.get("ast_dir") if isinstance(raw.get("ast_dir"), str) else ""
        if ast_dir:
            c_ast = os.path.join(str(ast_dir).strip(), name)
            if os.path.exists(c_ast):
                return c_ast
        c2 = os.path.join(self.base_dir, name)
        return c2


def _is_abs(p: str) -> bool:
    try:
        return Path(p).is_absolute()
    except Exception:
        return os.path.isabs(p)


def _abspath(base_dir: str, p: str) -> str:
    v = (p or "").strip()
    if not v:
        return os.path.abspath(base_dir)
    if _is_abs(v):
        return os.path.abspath(v)
    return os.path.abspath(os.path.join(base_dir, v))


def _read_json(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _normalize_app_name(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def get_symex_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _alternate_config_path(path: str) -> Optional[str]:
    p = (path or "").strip()
    if not p:
        return None
    base = os.path.basename(p).lower()
    if base == "config.json":
        return os.path.join(os.path.dirname(p), "symex_config.json")
    if base == "symex_config.json":
        return os.path.join(os.path.dirname(p), "config.json")
    return None


def _resolve_symex_config_hint(base_dir: str, requested_path: Optional[str], argv: Optional[List[str]] = None) -> str:
    """Resolve the shared symex_config.json used by the active Witcher run."""
    args = list(argv or [])
    req = (
        _parse_kv_arg(args, "--config")
        or requested_path
        or os.environ.get("SYMEX_SHARED_CONFIG_PATH")
        or os.environ.get("JOERNTRACE_CONFIG")
    )
    candidates: List[str] = []
    if req:
        primary = _abspath(base_dir, req)
        folder = os.path.dirname(primary)
        base = os.path.basename(primary).lower()
        if folder:
            if base in ("witcher_config.json", "request_data.json", "config.json", "symex_config.json"):
                candidates.append(os.path.abspath(os.path.join(folder, "symex_config.json")))
            candidates.append(os.path.abspath(primary))
            alt = _alternate_config_path(primary)
            if alt:
                candidates.append(os.path.abspath(alt))
    else:
        candidates.append(os.path.abspath(os.path.join(base_dir, "symex_config.json")))
    seen = set()
    ordered: List[str] = []
    for cand in candidates:
        if not cand:
            continue
        key = os.path.normcase(os.path.abspath(cand))
        if key in seen:
            continue
        seen.add(key)
        ordered.append(os.path.abspath(cand))
    for cand in ordered:
        if os.path.exists(cand):
            return cand
    return ordered[0] if ordered else os.path.abspath(os.path.join(base_dir, "symex_config.json"))


def _resolve_config_path(base_dir: str, requested_path: Optional[str]) -> str:
    candidates: List[str] = []
    req = (requested_path or "").strip()
    if req:
        primary = _abspath(base_dir, req)
        candidates.append(primary)
        alt = _alternate_config_path(primary)
        if alt:
            candidates.append(os.path.abspath(alt))
    else:
        candidates.append(os.path.abspath(os.path.join(base_dir, "symex_config.json")))
        candidates.append(os.path.abspath(os.path.join(base_dir, "config.json")))
    seen = set()
    ordered: List[str] = []
    for cand in candidates:
        if not cand:
            continue
        key = os.path.normcase(os.path.abspath(cand))
        if key in seen:
            continue
        seen.add(key)
        ordered.append(os.path.abspath(cand))
    for cand in ordered:
        if os.path.exists(cand):
            return cand
    return ordered[0] if ordered else os.path.abspath(os.path.join(base_dir, "symex_config.json"))


def get_app_name(raw_or_cfg: Any) -> str:
    if isinstance(raw_or_cfg, AppConfig):
        if raw_or_cfg.app_name:
            return raw_or_cfg.app_name
        raw_or_cfg = raw_or_cfg.raw
    if isinstance(raw_or_cfg, dict):
        return _normalize_app_name(raw_or_cfg.get("app_name"))
    return ""


def build_app_name_prompt_line(raw_or_cfg: Any) -> str:
    app_name = get_app_name(raw_or_cfg)
    if not app_name:
        return ""
    return "The following code comes from " + app_name


def append_app_name_to_prompt(prompt_text: str, raw_or_cfg: Any) -> str:
    base = (prompt_text or "").strip()
    app_line = build_app_name_prompt_line(raw_or_cfg)
    if not app_line:
        return base
    if not base:
        return app_line
    if app_line in base:
        return base
    return base + "\n\n" + app_line


def _parse_kv_arg(argv: List[str], key: str) -> Optional[str]:
    if not argv:
        return None
    for i, x in enumerate(argv):
        if not isinstance(x, str):
            continue
        if x.startswith(key + "="):
            return (x.split("=", 1)[1] or "").strip()
        if x == key and (i + 1) < len(argv):
            v = argv[i + 1]
            return (v or "").strip() if isinstance(v, str) else None
    return None


def load_app_config(*, config_path: Optional[str] = None, argv: Optional[List[str]] = None, base_dir: Optional[str] = None) -> AppConfig:
    """Load config.json and resolve key directories, with optional CLI overrides."""
    base = os.path.abspath(base_dir or os.getcwd())
    args = list(argv or [])

    cfg_arg = (
        _parse_kv_arg(args, "--config")
        or config_path
        or os.environ.get("JOERNTRACE_CONFIG")
    )
    cfg_path = _resolve_config_path(base, cfg_arg)
    raw = _read_json(cfg_path)

    paths = raw.get("paths") if isinstance(raw.get("paths"), dict) else {}
    input_dir = _parse_kv_arg(args, "--input-dir") or (paths.get("input_dir") if isinstance(paths, dict) else None) or raw.get("input_dir") or "input"
    tmp_dir = _parse_kv_arg(args, "--tmp-dir") or (paths.get("tmp_dir") if isinstance(paths, dict) else None) or raw.get("tmp_dir") or "tmp"
    test_dir = _parse_kv_arg(args, "--test-dir") or (paths.get("test_dir") if isinstance(paths, dict) else None) or raw.get("test_dir") or "test"
    output_dir = _parse_kv_arg(args, "--output-dir") or (paths.get("output_dir") if isinstance(paths, dict) else None) or raw.get("output_dir") or "output"

    input_abs = _abspath(base, str(input_dir))
    tmp_abs = _abspath(base, str(tmp_dir))
    test_abs = _abspath(base, str(test_dir))
    output_abs = _abspath(base, str(output_dir))

    return AppConfig(
        base_dir=base,
        config_path=str(cfg_path),
        input_dir=input_abs,
        tmp_dir=tmp_abs,
        test_dir=test_abs,
        output_dir=output_abs,
        app_name=_normalize_app_name(raw.get("app_name")),
        raw=raw,
    )


def load_symex_app_config(*, config_path: Optional[str] = None, argv: Optional[List[str]] = None) -> AppConfig:
    symex_root = get_symex_root()
    resolved_cfg = _resolve_symex_config_hint(symex_root, config_path, argv=argv)
    resolved_base = os.path.dirname(os.path.abspath(resolved_cfg)) if resolved_cfg else symex_root
    args = list(argv or [])
    filtered_args: List[str] = []
    skip_next = False
    for idx, item in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if not isinstance(item, str):
            filtered_args.append(item)
            continue
        if item == "--config":
            if idx + 1 < len(args):
                skip_next = True
            continue
        if item.startswith("--config="):
            continue
        filtered_args.append(item)
    return load_app_config(config_path=resolved_cfg, argv=filtered_args, base_dir=resolved_base)


_SYMBOLIC_SEED_KIND_KEYS = ("POST", "GET", "COOKIE", "SESSION", "ENV", "SQL", "FILE")
_SYMBOLIC_SEED_KIND_DEFAULTS: Dict[str, bool] = {key: True for key in _SYMBOLIC_SEED_KIND_KEYS}


def load_symbolic_seed_kind_flags(*, config_path: Optional[str] = None, argv: Optional[List[str]] = None) -> Dict[str, bool]:
    cfg = load_symex_app_config(config_path=config_path, argv=argv)
    raw = cfg.raw if isinstance(getattr(cfg, "raw", None), dict) else {}
    sec = raw.get("symbolic_seed_kinds") if isinstance(raw.get("symbolic_seed_kinds"), dict) else {}
    out: Dict[str, bool] = dict(_SYMBOLIC_SEED_KIND_DEFAULTS)
    for key in _SYMBOLIC_SEED_KIND_KEYS:
        if key not in sec:
            continue
        value = sec.get(key)
        if isinstance(value, bool):
            out[key] = value
            continue
        if isinstance(value, str):
            norm = value.strip().lower()
            if norm in {"1", "true", "yes", "on"}:
                out[key] = True
            elif norm in {"0", "false", "no", "off"}:
                out[key] = False
    return out


def get_disabled_symbolic_seed_kinds(*, config_path: Optional[str] = None, argv: Optional[List[str]] = None) -> Set[str]:
    flags = load_symbolic_seed_kind_flags(config_path=config_path, argv=argv)
    return {key for key, enabled in flags.items() if not bool(enabled)}
