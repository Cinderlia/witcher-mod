"""CLI entry point for the standalone database exploration pipeline."""

import argparse
import json
import os
import re
from typing import Any, Dict, Optional

from .debug_log import ensure_log_dir
from .models import BranchSliceContext, DBSearchRequest
from .orchestrator import run_db_search_pipeline
from .phases.bootstrap import build_external_input_snapshot


def _read_text(path: str) -> str:
    if not isinstance(path, str) or not path or not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _read_json(path: str) -> Dict[str, Any]:
    if not isinstance(path, str) or not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--code-slice", dest="code_slice_path", default="", help="Path to the code-slice text input")
    parser.add_argument("--input-json", dest="input_json_path", default="", help="Path to the external input snapshot JSON")
    parser.add_argument("--debug-spec", dest="debug_spec_path", default="", help="Path to a labeled debug input file")
    parser.add_argument("--target-seq", dest="target_seq", type=int, default=0, help="Target seq for the branch")
    parser.add_argument("--target-loc", dest="target_loc", default="", help="Target source location")
    parser.add_argument("--config", dest="config_path", default="", help="Optional symex_config.json path")
    parser.add_argument("--run-dir", dest="run_dir", default="", help="Optional artifact directory for this run")
    return parser


_SPEC_LABEL_MAP = {
    "target_code": "code_slice",
    "code_slice": "code_slice",
    "code": "code_slice",
    "code_slice": "code_slice",
    "get": "get",
    "post": "post",
    "cookie": "cookie",
    "session": "session",
    "env": "env",
    "target_seq": "target_seq",
    "seq": "target_seq",
    "target_loc": "target_loc",
    "loc": "target_loc",
    "trigger_reason": "trigger_reason",
    "trigger": "trigger_reason",
}


def _normalize_spec_label(text: str) -> str:
    raw = str(text or "").strip().lower()
    raw = raw.replace("：", ":")
    raw = raw.strip(":").strip()
    return _SPEC_LABEL_MAP.get(raw, "")


def _parse_debug_spec_text(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    current_key = ""
    current_lines = []
    for raw_line in (str(text or "").splitlines() or []):
        line = str(raw_line or "")
        m = re.match(r"^\s*([^:：]+)\s*[：:]\s*(.*)$", line)
        key = _normalize_spec_label(m.group(1)) if m else ""
        if key:
            if current_key:
                out[current_key] = "\n".join(current_lines).strip()
            current_key = key
            current_lines = []
            remainder = str(m.group(2) or "").rstrip()
            if remainder:
                current_lines.append(remainder)
            continue
        if current_key:
            current_lines.append(line)
    if current_key:
        out[current_key] = "\n".join(current_lines).strip()
    return out


def _parse_session_spec(session_text: str):
    raw = str(session_text or "").strip()
    if not raw:
        return {}, ""
    try:
        obj = json.loads(raw)
    except Exception:
        return {}, raw
    return (obj if isinstance(obj, dict) else {}), raw


def build_request_from_debug_spec(args: argparse.Namespace) -> DBSearchRequest:
    spec_text = _read_text(str(getattr(args, "debug_spec_path", "") or ""))
    spec = _parse_debug_spec_text(spec_text)
    session_data, session_block = _parse_session_spec(spec.get("session", ""))
    context = BranchSliceContext(
        target_seq=(
            int(spec.get("target_seq"))
            if str(spec.get("target_seq", "")).strip().isdigit()
            else (int(args.target_seq) if getattr(args, "target_seq", 0) else None)
        ),
        target_loc=str(spec.get("target_loc") or getattr(args, "target_loc", "") or ""),
        code_slice=str(spec.get("code_slice") or ""),
        input_snapshot=build_external_input_snapshot(
            env_block=str(spec.get("env") or ""),
            get_block=str(spec.get("get") or ""),
            post_block=str(spec.get("post") or ""),
            cookie_block=str(spec.get("cookie") or ""),
            session_data=session_data,
            session_block=session_block,
        ),
    )
    return DBSearchRequest(
        context=context,
        config_path=(str(getattr(args, "config_path", "") or "") or None),
        run_dir=str(getattr(args, "run_dir", "") or ""),
        source_component="debug_spec_file",
        trigger_reason=str(spec.get("trigger_reason") or "manual_debug_spec"),
    )


def build_request_from_args(args: argparse.Namespace) -> DBSearchRequest:
    """Build the standalone DB search request from CLI arguments."""
    if str(getattr(args, "debug_spec_path", "") or "").strip():
        return build_request_from_debug_spec(args)
    input_snapshot = _read_json(str(getattr(args, "input_json_path", "") or ""))
    env_raw = input_snapshot.get("ENV")
    get_raw = input_snapshot.get("GET")
    post_raw = input_snapshot.get("POST")
    cookie_raw = input_snapshot.get("COOKIE")
    session_raw = input_snapshot.get("SESSION")
    session_block = ""
    if isinstance(session_raw, dict):
        try:
            session_block = json.dumps(session_raw, ensure_ascii=False, indent=2)
        except Exception:
            session_block = ""
    env_block = env_raw if isinstance(env_raw, str) else ""
    if isinstance(env_raw, dict):
        env_block = "\n".join([str(k) + "=" + str(v) for k, v in env_raw.items()])
    get_block = get_raw if isinstance(get_raw, str) else ""
    if isinstance(get_raw, dict):
        get_block = "&".join([str(k) + "=" + str(v) for k, v in get_raw.items()])
    post_block = post_raw if isinstance(post_raw, str) else ""
    if isinstance(post_raw, dict):
        post_block = "&".join([str(k) + "=" + str(v) for k, v in post_raw.items()])
    cookie_block = cookie_raw if isinstance(cookie_raw, str) else ""
    if isinstance(cookie_raw, dict):
        cookie_block = "&".join([str(k) + "=" + str(v) for k, v in cookie_raw.items()])
    context = BranchSliceContext(
        target_seq=(int(args.target_seq) if getattr(args, "target_seq", 0) else None),
        target_loc=str(getattr(args, "target_loc", "") or ""),
        code_slice=_read_text(str(getattr(args, "code_slice_path", "") or "")),
        input_snapshot=build_external_input_snapshot(
            env_block=env_block,
            get_block=get_block,
            post_block=post_block,
            cookie_block=cookie_block,
            session_data=(session_raw if isinstance(session_raw, dict) else {}),
            session_block=session_block,
        ),
    )
    return DBSearchRequest(
        context=context,
        config_path=(str(getattr(args, "config_path", "") or "") or None),
        run_dir=str(getattr(args, "run_dir", "") or ""),
    )


def summarize_state_for_stdout(state) -> Dict[str, Any]:
    """Serialize the most important state fields for the initial standalone CLI."""
    return {
        "current_phase": state.current_phase,
        "goal": {
            "summary": state.goal.summary,
            "branch_effect": state.goal.branch_effect,
            "db_reason": state.goal.db_reason,
            "context_strategy": state.goal.context_strategy,
            "relevant_symbols": list(state.goal.relevant_symbols or []),
            "relevant_inputs": list(state.goal.relevant_inputs or []),
            "retained_code_lines": list(state.goal.retained_code_lines or []),
            "retained_inputs": dict(state.goal.retained_inputs or {}),
            "schema_goal": state.goal.schema_goal,
            "candidate_goal": state.goal.candidate_goal,
            "finalize_goal": state.goal.finalize_goal,
            "db_information_needs": list(state.goal.db_information_needs or []),
            "db_mutation_targets": list(state.goal.db_mutation_targets or []),
            "code_seen_tables": list(state.goal.code_seen_tables or []),
            "code_seen_columns": list(state.goal.code_seen_columns or []),
            "inferred_tables": list(state.goal.inferred_tables or []),
            "inferred_columns": list(state.goal.inferred_columns or []),
            "schema_stop_conditions": list(state.goal.schema_stop_conditions or []),
            "candidate_stop_conditions": list(state.goal.candidate_stop_conditions or []),
            "finalize_stop_conditions": list(state.goal.finalize_stop_conditions or []),
            "evidence": list(state.goal.evidence or []),
            "abstraction_warnings": list(state.goal.abstraction_warnings or []),
        },
        "schema_rounds": int(state.schema_rounds),
        "candidate_rounds": int(state.candidate_rounds),
        "finalize_rounds": int(state.finalize_rounds),
        "schema_identified": bool(state.schema_identified),
        "schema_findings": list(state.schema_findings or []),
        "candidate_found": bool(state.candidate_found),
        "candidate_impossible": bool(state.candidate_impossible),
        "output_ready": bool(state.output_ready),
        "fallback_to_schema_used": bool(state.fallback_to_schema_used),
        "filtered_memory_count": len(state.filtered_memory or []),
        "finalize_context_payload_count": len(state.finalize_context_payloads or []),
        "round_trace_count": len(state.round_traces or []),
        "final_output": dict(state.final_output or {}),
        "sql_log_paths": list(state.sql_log_paths or []),
        "log_dir": ensure_log_dir(run_dir=state.run_dir),
        "todo_notes": list(state.todo_notes or []),
    }


def main(argv: Optional[list] = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    request = build_request_from_args(args)
    state = run_db_search_pipeline(request, config_path=(args.config_path or ""))
    print(json.dumps(summarize_state_for_stdout(state), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
