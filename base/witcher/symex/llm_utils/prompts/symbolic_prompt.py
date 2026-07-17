"""
Generate plain-text prompts for LLM-assisted symbolic execution.
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from common.app_config import build_app_name_prompt_line, load_symex_app_config, load_symbolic_seed_kind_flags
from llm_utils.solution_markers import DELETE_KEY_SENTINEL


DEFAULT_TEST_COMMAND_PATH = os.path.join("input", "test_command.txt")
DEFAULT_URL_PATH = os.path.join("input", "url.txt")


def _append_prompt_stage_debug(base_inputs: Optional[Dict[str, Any]], event: str, **fields) -> None:
    if not isinstance(base_inputs, dict):
        return
    run_dir = str(base_inputs.get("__WITCHER_RUN_DIR__") or "").strip()
    if not run_dir:
        return
    payload = {
        "event": str(event or ""),
        "pid": int(os.getpid()),
        "ppid": int(os.getppid()),
    }
    for k, v in (fields or {}).items():
        payload[str(k)] = v
    try:
        logs_dir = os.path.join(os.path.abspath(run_dir), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        with open(os.path.join(logs_dir, "stage_debug.ndjson"), "a", encoding="utf-8", errors="replace") as f:
            f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception:
        pass


def _import_prompt_utils():
    try:
        from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
        return map_result_set_to_source_lines
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
        return map_result_set_to_source_lines


def _import_prompt_input_utils():
    try:
        from llm_utils.prompts.prompt_utils import (
            INPUT_VALUE_MASK_NOTICE,
            append_standard_input_sections,
            collect_prompt_input_blocks,
        )
        return INPUT_VALUE_MASK_NOTICE, collect_prompt_input_blocks, append_standard_input_sections
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from llm_utils.prompts.prompt_utils import (
            INPUT_VALUE_MASK_NOTICE,
            append_standard_input_sections,
            collect_prompt_input_blocks,
        )
        return INPUT_VALUE_MASK_NOTICE, collect_prompt_input_blocks, append_standard_input_sections


def _import_if_branch_utils():
    try:
        from llm_utils.branch.if_branch import infer_if_directions_for_seqs, load_trace_index_records
        return infer_if_directions_for_seqs, load_trace_index_records
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from llm_utils.branch.if_branch import infer_if_directions_for_seqs, load_trace_index_records
        return infer_if_directions_for_seqs, load_trace_index_records


def _import_switch_branch_utils():
    try:
        from llm_utils.branch.switch_branch import (
            build_seq_to_case_label,
            build_switch_case_result_set_for_seq,
            infer_switch_choices_for_seqs,
            insert_mapped_items_after_seq,
        )
        return infer_switch_choices_for_seqs, build_seq_to_case_label, build_switch_case_result_set_for_seq, insert_mapped_items_after_seq
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from llm_utils.branch.switch_branch import (
            build_seq_to_case_label,
            build_switch_case_result_set_for_seq,
            infer_switch_choices_for_seqs,
            insert_mapped_items_after_seq,
        )
        return infer_switch_choices_for_seqs, build_seq_to_case_label, build_switch_case_result_set_for_seq, insert_mapped_items_after_seq


def _import_switch_case_utils():
    try:
        from llm_utils.branch.switch_branch import get_switch_case_ids, get_switch_case_line
        return get_switch_case_ids, get_switch_case_line
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from llm_utils.branch.switch_branch import get_switch_case_ids, get_switch_case_line
        return get_switch_case_ids, get_switch_case_line


def _import_switch_coverage_utils():
    try:
        from if_branch_coverage.switch_coverage import check_switch_branch_coverage
        return check_switch_branch_coverage
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from if_branch_coverage.switch_coverage import check_switch_branch_coverage
        return check_switch_branch_coverage


def _import_graph_mapping():
    try:
        from utils.cpg_utils.graph_mapping import load_ast_edges, load_nodes
        return load_nodes, load_ast_edges
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from utils.cpg_utils.graph_mapping import load_ast_edges, load_nodes
        return load_nodes, load_ast_edges


def _import_call_scope_utils():
    try:
        from taint_handlers.handlers.call.ast_method_call import partition_function_scope_for_call
        return partition_function_scope_for_call
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from taint_handlers.handlers.call.ast_method_call import partition_function_scope_for_call
        return partition_function_scope_for_call


def _import_scope_filter_utils():
    try:
        from taint_handlers.handlers.helpers.ast_var_include import (
            _filter_define_locs_from_include,
            _filter_func_def_locs_from_include,
        )
        return _filter_define_locs_from_include, _filter_func_def_locs_from_include
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from taint_handlers.handlers.helpers.ast_var_include import (
            _filter_define_locs_from_include,
            _filter_func_def_locs_from_include,
        )
        return _filter_define_locs_from_include, _filter_func_def_locs_from_include


def _build_switch_case_coverage(
    switch_ids: List[int],
    *,
    nodes: Dict[int, dict],
    children_of: Dict[int, List[int]],
) -> Tuple[Dict[int, List[dict]], Dict[int, Dict[int, bool]]]:
    get_switch_case_ids, get_switch_case_line = _import_switch_case_utils()
    check_switch_branch_coverage = _import_switch_coverage_utils()
    line_to_cases: Dict[int, List[dict]] = {}
    switch_to_coverage: Dict[int, Dict[int, bool]] = {}
    for sid in switch_ids or []:
        try:
            sid_i = int(sid)
        except Exception:
            continue
        cov_raw = check_switch_branch_coverage(int(sid_i))
        cov_map: Dict[int, bool] = {}
        if isinstance(cov_raw, dict):
            for k, v in cov_raw.items():
                try:
                    ki = int(k)
                except Exception:
                    continue
                cov_map[int(ki)] = bool(v)
        switch_to_coverage[int(sid_i)] = cov_map
        for case_id in get_switch_case_ids(int(sid_i), nodes=nodes, children_of=children_of):
            try:
                cid_i = int(case_id)
            except Exception:
                continue
            ln = get_switch_case_line(int(cid_i), nodes)
            if ln is None:
                continue
            covered = bool(cov_map.get(int(cid_i))) if cov_map else False
            line_to_cases.setdefault(int(ln), []).append(
                {"case_id": int(cid_i), "covered": bool(covered), "switch_id": int(sid_i)}
            )
    return line_to_cases, switch_to_coverage


def _load_result_set(result_set_or_path):
    if isinstance(result_set_or_path, str) and os.path.exists(result_set_or_path):
        with open(result_set_or_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        if isinstance(obj, dict):
            return obj.get("result_set") or []
        return []
    return result_set_or_path or []

def _load_analysis_obj(result_set_or_path) -> Optional[dict]:
    if isinstance(result_set_or_path, str) and os.path.exists(result_set_or_path):
        with open(result_set_or_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    return result_set_or_path if isinstance(result_set_or_path, dict) else None


def _merge_initial_seq_into_result_set(
    result_set,
    *,
    input_seq: Optional[int],
    input_path: Optional[str],
    input_line: Optional[int],
) -> list:
    if not result_set:
        result_set = []
    if input_seq is None:
        return list(result_set)
    try:
        seq_i = int(input_seq)
    except Exception:
        return list(result_set)

    for it in result_set or []:
        if not isinstance(it, dict):
            continue
        s = it.get("seq")
        try:
            if int(s) == seq_i:
                return list(result_set)
        except Exception:
            continue

    added = {"seq": seq_i}
    p = (str(input_path).strip() if isinstance(input_path, str) else "").strip()
    if p and input_line is not None:
        try:
            ln_i = int(input_line)
        except Exception:
            ln_i = None
        if ln_i is not None:
            added["path"] = p
            added["line"] = ln_i
            added["loc"] = f"{p}:{ln_i}"

    out = list(result_set) + [added]
    keyed = []
    for idx, it in enumerate(out):
        if isinstance(it, dict):
            s = it.get("seq")
            try:
                si = int(s) if s is not None else None
            except Exception:
                si = None
            if si is not None:
                keyed.append((0, si, idx, it))
                continue
        keyed.append((1, 0, idx, it))
    keyed.sort(key=lambda x: (x[0], x[1], x[2]))
    return [it for _, _, _, it in keyed]


def _resolve_existing_path(path: str, *, fallback: Optional[str] = None) -> str:
    if path and os.path.exists(path):
        return path
    if fallback and os.path.exists(fallback):
        return fallback
    return path


def _extract_int_seqs(mapped_items: List[dict]) -> List[int]:
    out: Set[int] = set()
    for it in mapped_items or []:
        if not isinstance(it, dict):
            continue
        s = it.get("seq")
        try:
            si = int(s)
        except Exception:
            continue
        out.add(int(si))
    return sorted(out)


def _build_seq_to_branch(if_dirs: list) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for d in if_dirs or []:
        try:
            s = int(getattr(d, "if_seq"))
        except Exception:
            continue
        direction = getattr(d, "direction", None)
        direction_s = (str(direction) if direction is not None else "").strip()
        if not direction_s:
            continue
        if s not in out:
            out[s] = direction_s
    return out


def _build_trace_seq_to_index(trace_index_records: List[dict]) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for r in trace_index_records or []:
        if not isinstance(r, dict):
            continue
        idx = r.get("index")
        try:
            idx_i = int(idx) if idx is not None else None
        except Exception:
            idx_i = None
        if idx_i is None:
            continue
        for s in r.get("seqs") or []:
            try:
                si = int(s)
            except Exception:
                continue
            if si not in out:
                out[si] = int(idx_i)
    return out


def _build_trace_seq_to_group(trace_index_records: List[dict]) -> Dict[int, Tuple[int, ...]]:
    out: Dict[int, Tuple[int, ...]] = {}
    for r in trace_index_records or []:
        if not isinstance(r, dict):
            continue
        seqs: List[int] = []
        for s in r.get("seqs") or []:
            try:
                seqs.append(int(s))
            except Exception:
                continue
        if not seqs:
            continue
        seq_group = tuple(sorted(set(seqs)))
        if not seq_group:
            continue
        for si in seq_group:
            if int(si) not in out:
                out[int(si)] = seq_group
    return out


def _norm_loc_for_dedupe(loc: str) -> str:
    s = (loc or "").strip()
    if not s:
        return ""
    if ":" not in s:
        return s.replace("\\", "/").lower()
    p, ln_s = s.rsplit(":", 1)
    try:
        ln_i = int(ln_s)
    except Exception:
        return s.replace("\\", "/").lower()
    return p.replace("\\", "/").lower() + ":" + str(int(ln_i))


def _is_if_like_code(code: str) -> bool:
    s = (code or "").lstrip()
    if not s:
        return False
    if re.match(r"^(?:\}+\s*)?(?:else\s+)?if\s*\(", s, flags=re.IGNORECASE):
        return True
    if re.match(r"^(?:\}+\s*)?elseif\s*\(", s, flags=re.IGNORECASE):
        return True
    return False


def _apply_branch_tag(code: str, branch_tag: str) -> str:
    code_s = code if isinstance(code, str) else ""
    tag = (branch_tag or "").strip()
    if not tag:
        return code_s
    if _is_if_like_code(code_s):
        return f"[{tag}] {code_s}"
    return f"{code_s}    # Current branch direction: {tag}"


def extract_db_search_source_from_prompt_text(prompt_text: str, *, target_seq: Optional[int] = None) -> Dict[str, str]:
    """Extract code/input source blocks from the rendered symbolic prompt."""
    try:
        input_value_mask_notice, _, _ = _import_prompt_input_utils()
    except Exception:
        input_value_mask_notice = ""
    lines = list((str(prompt_text or "")).splitlines())
    env_block = ""
    cookie_block = ""
    get_block = ""
    post_block = ""
    session_block = ""
    code_slice = ""
    target_loc = ""

    def _find_line(text: str) -> int:
        needle = str(text or "").strip()
        for idx, line in enumerate(lines):
            if str(line or "").strip() == needle:
                return idx
        return -1

    env_idx = _find_line("Environment variables for this execution:")
    input_idx = _find_line("Input for this execution:")
    context_idx = _find_line("Code context (each line: seq | path:line | code):")
    constraint_idx = _find_line("Symbolic execution must be based solely on the provided code and if statements. Do not introduce any conditions, comparisons, or implicit assumptions that are not present in the code.")

    if env_idx >= 0:
        env_end = input_idx if input_idx > env_idx else len(lines)
        env_lines = []
        for line in lines[env_idx + 1:env_end]:
            if str(line or "").strip():
                env_lines.append(str(line))
        env_block = "\n".join(env_lines).strip()

    if input_idx >= 0:
        input_end = context_idx if context_idx > input_idx else len(lines)
        in_session = False
        session_lines: List[str] = []
        for raw in lines[input_idx + 1:input_end]:
            line = str(raw or "")
            stripped = line.strip()
            if not stripped:
                if in_session:
                    session_lines.append("")
                continue
            if input_value_mask_notice and stripped == input_value_mask_notice:
                continue
            if stripped.startswith("COOKIE:"):
                cookie_block = stripped.split("COOKIE:", 1)[1].strip()
                in_session = False
                continue
            if stripped.startswith("GET:"):
                get_block = stripped.split("GET:", 1)[1].strip()
                in_session = False
                continue
            if stripped.startswith("POST:"):
                post_block = stripped.split("POST:", 1)[1].strip()
                in_session = False
                continue
            if stripped == "SESSION:":
                in_session = True
                continue
            if in_session:
                session_lines.append(line)
        session_block = "\n".join(session_lines).strip()

    if context_idx >= 0:
        code_end = constraint_idx if constraint_idx > context_idx else len(lines)
        code_lines: List[str] = []
        for raw in lines[context_idx + 1:code_end]:
            line = str(raw or "")
            if not line.strip():
                continue
            code_lines.append(line)
            if target_seq is not None and not target_loc:
                parts = [p.strip() for p in line.split("|", 2)]
                if len(parts) >= 2:
                    try:
                        if int(parts[0]) == int(target_seq):
                            target_loc = parts[1]
                    except Exception:
                        pass
        code_slice = "\n".join(code_lines).strip()

    return {
        "env_block": env_block,
        "cookie_block": cookie_block,
        "get_block": get_block,
        "post_block": post_block,
        "session_block": session_block,
        "code_slice": code_slice,
        "target_loc": target_loc,
    }


def extract_symbolic_objective_from_prompt_text(prompt_text: str, *, target_seq: Optional[int] = None) -> str:
    """Extract the top-level branch-flipping objective from the rendered symbolic prompt."""
    lines = [str(x or "").strip() for x in str(prompt_text or "").splitlines()]
    seq_text = str(int(target_seq)) if target_seq is not None else ""
    objective_lines: List[str] = []
    objective_prefixes = [
        f"If line {seq_text}" if seq_text else "",
        "Only flip",
        "Only reverse",
        "Only modify",
        "Switch statement:",
        "switch statement:",
    ]
    continuation_keywords = ("branch", "case", "target")
    for line in lines:
        if not line:
            if objective_lines:
                break
            continue
        if line.startswith("The following code comes from "):
            break
        if line.startswith("Environment variables for this execution:"):
            break
        if line.startswith("Code context (each line: seq | path:line | code):"):
            break
        if seq_text and (seq_text + " line") in line:
            objective_lines.append(line)
            continue
        if any(prefix and line.startswith(prefix) for prefix in objective_prefixes):
            objective_lines.append(line)
            continue
        if objective_lines and any(keyword in line for keyword in continuation_keywords):
            objective_lines.append(line)
            continue
    return "\n".join([x for x in objective_lines if x]).strip()


# Summary: Tag mapped source locations with the callsite whose implementation scope they fall into.
def _build_loc_to_func_impl_tags(
    mapped: List[dict],
    *,
    trace_index_records: List[dict],
    trace_seq_to_index: Dict[int, int],
    nodes: Dict[int, dict],
    parent_of: Dict[int, int],
    children_of: Dict[int, List[int]],
    top_id_to_file: Dict[int, str],
) -> Dict[str, List[str]]:
    partition_function_scope_for_call = _import_call_scope_utils()

    mapped_locs: Set[str] = set()
    for it in mapped or []:
        if not isinstance(it, dict):
            continue
        loc = (it.get("loc") or "").strip()
        if not loc:
            p = (it.get("path") or "").strip()
            ln = it.get("line")
            if p and ln is not None:
                try:
                    loc = f"{p}:{int(ln)}"
                except Exception:
                    loc = ""
        if loc:
            mapped_locs.add(loc)

    callsites: List[dict] = []
    seen_calls: Set[Tuple[int, int]] = set()
    for it in mapped or []:
        if not isinstance(it, dict):
            continue
        seq = it.get("seq")
        it_code = it.get("code")
        it_code_s = (it_code if isinstance(it_code, str) else "").strip()
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        if seq_i is None:
            continue
        rec_idx = trace_seq_to_index.get(int(seq_i))
        if rec_idx is None or rec_idx < 0 or rec_idx >= len(trace_index_records):
            continue
        rec = trace_index_records[int(rec_idx)] or {}
        for nid in rec.get("node_ids") or []:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            nt = ((nodes.get(nid_i) or {}).get("type") or "").strip()
            if nt not in ("AST_METHOD_CALL", "AST_CALL"):
                continue
            key = (int(nid_i), int(seq_i))
            if key in seen_calls:
                continue
            seen_calls.add(key)
            call_name = ((nodes.get(nid_i) or {}).get("name") or (nodes.get(nid_i) or {}).get("code") or "").strip()
            if it_code_s:
                call_name = it_code_s
            callsites.append({"call_id": int(nid_i), "call_seq": int(seq_i), "call_name": call_name})

    if not callsites:
        return {}

    scope_ctx = {
        "nodes": nodes,
        "parent_of": parent_of,
        "children_of": children_of,
        "top_id_to_file": top_id_to_file,
        "trace_index_records": trace_index_records,
        "trace_seq_to_index": trace_seq_to_index,
    }

    loc_to_tags: Dict[str, List[str]] = {}
    for cs in callsites:
        call_id = cs.get("call_id")
        call_seq = cs.get("call_seq")
        call_name = (cs.get("call_name") or "").strip()
        if call_id is None or call_seq is None:
            continue
        try:
            call_id_i = int(call_id)
            call_seq_i = int(call_seq)
        except Exception:
            continue
        if not call_name:
            for it in mapped or []:
                if not isinstance(it, dict):
                    continue
                s2 = it.get("seq")
                try:
                    s2i = int(s2) if s2 is not None else None
                except Exception:
                    s2i = None
                if s2i is None or int(s2i) != int(call_seq_i):
                    continue
                code2 = it.get("code")
                code2s = (code2 if isinstance(code2, str) else "").strip()
                if code2s:
                    call_name = code2s
                break
        scope_info = partition_function_scope_for_call(int(call_id_i), int(call_seq_i), scope_ctx)
        if not isinstance(scope_info, dict):
            continue
        scope_rows = scope_info.get("scope") or []
        scope_loc_set: Set[str] = set()
        for row in scope_rows:
            if not isinstance(row, dict):
                continue
            rp = (row.get("path") or "").strip()
            rl = row.get("line")
            if not rp or rl is None:
                continue
            try:
                rl_i = int(rl)
            except Exception:
                continue
            scope_loc_set.add(f"{rp}:{rl_i}")
        if not scope_loc_set:
            continue
        try:
            scope_start = int(scope_info.get("scope_start_seq"))
            scope_end = int(scope_info.get("scope_end_seq"))
        except Exception:
            continue

        tag = call_name or f"call_id={call_id_i}"
        for it in mapped or []:
            if not isinstance(it, dict):
                continue
            seq = it.get("seq")
            p = (it.get("path") or "").strip()
            ln = it.get("line")
            if not p or ln is None or seq is None:
                continue
            try:
                seq_i = int(seq)
                ln_i = int(ln)
            except Exception:
                continue
            if int(seq_i) <= int(call_seq_i):
                continue
            if int(seq_i) < int(scope_start) or int(seq_i) > int(scope_end):
                continue
            loc = f"{p}:{ln_i}"
            if loc not in scope_loc_set:
                continue
            if loc not in mapped_locs:
                continue
            lst = loc_to_tags.get(loc)
            if lst is None:
                loc_to_tags[loc] = [tag]
            else:
                if tag not in lst:
                    lst.append(tag)
    return loc_to_tags


# Summary: Build a single prompt that asks the LLM to symbolically flip IF/SWITCH branches for given seqs.
def generate_symbolic_execution_prompt(
    result_set_or_path,
    *,
    input_seq: Optional[int] = None,
    input_path: Optional[str] = None,
    input_line: Optional[int] = None,
    scope_root: str = "/app",
    trace_index_path: str = os.path.join("tmp", "trace_index.json"),
    windows_root: str = r"D:\files\witcher\app",
    base_prompt: Optional[str] = None,
    base_inputs: Optional[Dict[str, Any]] = None,
    nodes_path: str = os.path.join("input", "nodes.csv"),
    rels_path: str = os.path.join("input", "rels.csv"),
    trace_index_records: Optional[List[dict]] = None,
    trace_seq_to_index: Optional[Dict[int, int]] = None,
    nodes: Optional[Dict[int, dict]] = None,
    parent_of: Optional[Dict[int, int]] = None,
    children_of: Optional[Dict[int, List[int]]] = None,
    top_id_to_file: Optional[Dict[int, str]] = None,
) -> str:
    _append_prompt_stage_debug(base_inputs, "gsep_enter", input_seq=input_seq, result_set_type=type(result_set_or_path).__name__)
    map_result_set_to_source_lines = _import_prompt_utils()
    trace_index_path2 = _resolve_existing_path(
        trace_index_path,
        fallback=os.path.join(os.getcwd(), "tmp", os.path.basename(trace_index_path or "trace_index.json")),
    )
    rs = _load_result_set(result_set_or_path)
    analysis_obj = _load_analysis_obj(result_set_or_path)
    if analysis_obj is not None:
        if input_seq is None:
            try:
                input_seq = int(analysis_obj.get("input_seq"))
            except Exception:
                input_seq = None
        if not input_path:
            input_path = analysis_obj.get("path")
        if input_line is None:
            try:
                input_line = int(analysis_obj.get("line"))
            except Exception:
                input_line = None
    provided_trace_index_records = list(trace_index_records or [])
    if (not input_path or input_line is None) and input_seq is not None:
        _infer_if_directions_for_seqs, load_trace_index_records = _import_if_branch_utils()
        if provided_trace_index_records:
            trace_index_records0 = provided_trace_index_records
        elif trace_index_path2 and os.path.exists(trace_index_path2):
            try:
                trace_index_records0 = load_trace_index_records(trace_index_path2)
            except Exception:
                trace_index_records0 = []
        else:
            trace_index_records0 = []
        try:
            input_seq_i = int(input_seq)
        except Exception:
            input_seq_i = None
        if input_seq_i is not None:
            for r in trace_index_records0 or []:
                if not isinstance(r, dict):
                    continue
                hit = False
                for s in r.get("seqs") or []:
                    try:
                        if int(s) == input_seq_i:
                            hit = True
                            break
                    except Exception:
                        continue
                if not hit:
                    continue
                if not input_path:
                    input_path = r.get("path")
                if input_line is None:
                    try:
                        input_line = int(r.get("line"))
                    except Exception:
                        input_line = None
                break
    rs = _merge_initial_seq_into_result_set(rs, input_seq=input_seq, input_path=input_path, input_line=input_line)
    _append_prompt_stage_debug(base_inputs, "gsep_inputs_ready", input_seq=input_seq, input_path=str(input_path or ""), input_line=input_line, result_set_count=len(rs or []), trace_index_path=str(trace_index_path2 or ""), provided_trace_index_records=len(provided_trace_index_records))
    if callable(map_result_set_to_source_lines):
        _append_prompt_stage_debug(base_inputs, "gsep_before_map_result_set", result_set_count=len(rs or []))
        mapped = map_result_set_to_source_lines(
            scope_root,
            rs,
            trace_index_path=trace_index_path2,
            windows_root=windows_root,
        )
        _append_prompt_stage_debug(base_inputs, "gsep_after_map_result_set", mapped_count=len(mapped or []))
    else:
        mapped = list(rs or [])
        _append_prompt_stage_debug(base_inputs, "gsep_map_result_set_skipped", mapped_count=len(mapped or []))

    infer_if_directions_for_seqs, load_trace_index_records = _import_if_branch_utils()
    infer_switch_choices_for_seqs, build_seq_to_case_label, build_switch_case_result_set_for_seq, insert_mapped_items_after_seq = _import_switch_branch_utils()
    load_nodes, load_ast_edges = _import_graph_mapping()
    nodes_path2 = _resolve_existing_path(nodes_path)
    rels_path2 = _resolve_existing_path(rels_path)
    if_seqs = _extract_int_seqs(mapped or [])
    trace_index_records2: List[dict] = list(trace_index_records or [])
    nodes2: Dict[int, dict] = dict(nodes or {})
    top_id_to_file2: Dict[int, str] = dict(top_id_to_file or {})
    parent_of2: Dict[int, int] = dict(parent_of or {})
    children_of2: Dict[int, List[int]] = dict(children_of or {})
    have_graph = bool(
        if_seqs
        and (
            bool(trace_index_records2)
            or (trace_index_path2 and os.path.exists(trace_index_path2))
        )
        and bool(nodes2 or (nodes_path2 and os.path.exists(nodes_path2)))
        and bool(children_of2 or (rels_path2 and os.path.exists(rels_path2)))
    )
    if have_graph:
        try:
            _append_prompt_stage_debug(base_inputs, "gsep_graph_enter", if_seq_count=len(if_seqs or []), have_trace_records=bool(trace_index_records2), have_nodes=bool(nodes2), have_children=bool(children_of2))
            if not trace_index_records2 and trace_index_path2 and os.path.exists(trace_index_path2):
                trace_index_records2 = load_trace_index_records(trace_index_path2)
                _append_prompt_stage_debug(base_inputs, "gsep_graph_trace_loaded", trace_record_count=len(trace_index_records2 or []))
            if not nodes2 and nodes_path2 and os.path.exists(nodes_path2):
                nodes2, top_id_to_file2 = load_nodes(nodes_path2)
                _append_prompt_stage_debug(base_inputs, "gsep_graph_nodes_loaded", node_count=len(nodes2 or {}), top_file_count=len(top_id_to_file2 or {}))
            if not children_of2 and rels_path2 and os.path.exists(rels_path2):
                parent_of2, children_of2 = load_ast_edges(rels_path2)
                _append_prompt_stage_debug(base_inputs, "gsep_graph_edges_loaded", parent_count=len(parent_of2 or {}), child_count=len(children_of2 or {}))
            _append_prompt_stage_debug(base_inputs, "gsep_before_if_dirs", if_seq_count=len(if_seqs or []))
            if_dirs = infer_if_directions_for_seqs(
                if_seqs,
                trace_index_records=trace_index_records2,
                nodes=nodes2,
                children_of=children_of2,
            )
            _append_prompt_stage_debug(base_inputs, "gsep_after_if_dirs", if_dir_count=len(if_dirs or []))
            _append_prompt_stage_debug(base_inputs, "gsep_before_switch_choices", if_seq_count=len(if_seqs or []))
            switch_choices = infer_switch_choices_for_seqs(
                if_seqs,
                trace_index_records=trace_index_records2,
                nodes=nodes2,
                children_of=children_of2,
            )
            _append_prompt_stage_debug(base_inputs, "gsep_after_switch_choices", switch_choice_count=len(switch_choices or []))
        except Exception as exc:
            _append_prompt_stage_debug(base_inputs, "gsep_graph_failed", error=str(exc))
            trace_index_records2 = []
            nodes2 = {}
            top_id_to_file2 = {}
            parent_of2 = {}
            children_of2 = {}
            if_dirs = []
            switch_choices = []
    else:
        if_dirs = []
        switch_choices = []
    seq_to_branch = _build_seq_to_branch(if_dirs)
    seq_to_switch_case = build_seq_to_case_label(switch_choices)
    loc_to_impl_tags: Dict[str, List[str]] = {}
    trace_seq_to_index2: Dict[int, int] = dict(trace_seq_to_index or {})
    trace_seq_to_group: Dict[int, Tuple[int, ...]] = {}
    if have_graph and trace_index_records2 and nodes2:
        try:
            if not trace_seq_to_index2:
                trace_seq_to_index2 = _build_trace_seq_to_index(trace_index_records2)
            trace_seq_to_group = _build_trace_seq_to_group(trace_index_records2)
            loc_to_impl_tags = _build_loc_to_func_impl_tags(
                mapped or [],
                trace_index_records=trace_index_records2,
                trace_seq_to_index=trace_seq_to_index2,
                nodes=nodes2,
                parent_of=parent_of2 if isinstance(parent_of2, dict) else {},
                children_of=children_of2 if isinstance(children_of2, dict) else {},
                top_id_to_file=top_id_to_file2 if isinstance(top_id_to_file2, dict) else {},
            )
        except Exception:
            loc_to_impl_tags = {}

    input_seq_i = None
    try:
        input_seq_i = int(input_seq) if input_seq is not None else None
    except Exception:
        input_seq_i = None
    if have_graph and input_seq_i is not None:
        _append_prompt_stage_debug(base_inputs, "gsep_before_case_rs", input_seq=input_seq_i)
        case_rs = build_switch_case_result_set_for_seq(
            int(input_seq_i),
            trace_index_records=trace_index_records2,
            nodes=nodes2,
            children_of=children_of2,
        )
        _append_prompt_stage_debug(base_inputs, "gsep_after_case_rs", case_rs_count=len(case_rs or []))
        if case_rs:
            mapped_cases = map_result_set_to_source_lines(
                scope_root,
                case_rs,
                trace_index_path=trace_index_path2,
                windows_root=windows_root,
            )
            _append_prompt_stage_debug(base_inputs, "gsep_after_map_case_rs", mapped_case_count=len(mapped_cases or []))
            mapped = insert_mapped_items_after_seq(mapped or [], after_seq=int(input_seq_i), insert_items=mapped_cases or [])
            _append_prompt_stage_debug(base_inputs, "gsep_after_insert_case_rs", mapped_count=len(mapped or []))

    switch_case_line_map: Dict[int, List[dict]] = {}
    switch_coverage_summary: Dict[int, Dict[int, bool]] = {}
    if have_graph and input_seq_i is not None and nodes2 and children_of2:
        switch_ids: List[int] = []
        for sc in switch_choices or []:
            try:
                sseq = int(getattr(sc, "switch_seq"))
                sid = int(getattr(sc, "switch_id"))
            except Exception:
                continue
            if int(sseq) == int(input_seq_i):
                switch_ids.append(int(sid))
        if switch_ids:
            switch_case_line_map, switch_coverage_summary = _build_switch_case_coverage(
                switch_ids,
                nodes=nodes,
                children_of=children_of2,
            )

    if have_graph and mapped:
        try:
            _append_prompt_stage_debug(base_inputs, "gsep_scope_filter_enter", mapped_count=len(mapped or []))
            _filter_define_locs_from_include, _filter_func_def_locs_from_include = _import_scope_filter_utils()
            scope_ctx = {
                "initial_taints": (analysis_obj or {}).get("initial_taints") if isinstance(analysis_obj, dict) else None,
                "taint_sources": (analysis_obj or {}).get("taint_sources") if isinstance(analysis_obj, dict) else None,
                "nodes": nodes,
                "children_of": children_of2,
                "parent_of": parent_of2 if isinstance(parent_of2, dict) else {},
                "trace_index_records": trace_index_records2,
            }
            locs = []
            keep_locs = set()
            for it in mapped or []:
                if not isinstance(it, dict):
                    continue
                p = (it.get("path") or "").strip()
                ln = it.get("line")
                if not p or ln is None:
                    continue
                try:
                    loc = f"{p}:{int(ln)}"
                    locs.append(loc)
                    code = (it.get("code") or "").lower()
                    if "function" in code:
                        keep_locs.add(loc)
                except Exception:
                    continue
            _append_prompt_stage_debug(base_inputs, "gsep_before_filter_func_defs", loc_count=len(locs), keep_loc_count=len(keep_locs))
            locs2 = _filter_func_def_locs_from_include(list(locs), trace_index_records2, nodes2, scope_ctx)
            _append_prompt_stage_debug(base_inputs, "gsep_after_filter_func_defs", loc_count=len(locs2 or []))
            locs2 = _filter_define_locs_from_include(locs2, trace_index_records2, nodes2, children_of2, scope_ctx.get("parent_of") or {}, scope_ctx)
            _append_prompt_stage_debug(base_inputs, "gsep_after_filter_defines", loc_count=len(locs2 or []))
            loc_set = set(locs2) | set(keep_locs)
            if loc_set:
                filtered = []
                for it in mapped or []:
                    if not isinstance(it, dict):
                        continue
                    p = (it.get("path") or "").strip()
                    ln = it.get("line")
                    if not p or ln is None:
                        continue
                    try:
                        loc = f"{p}:{int(ln)}"
                    except Exception:
                        continue
                    if loc in loc_set:
                        filtered.append(it)
                mapped = filtered
                _append_prompt_stage_debug(base_inputs, "gsep_scope_filter_applied", filtered_count=len(mapped or []))
        except Exception as exc:
            _append_prompt_stage_debug(base_inputs, "gsep_scope_filter_failed", error=str(exc))
            pass

    INPUT_VALUE_MASK_NOTICE, collect_prompt_input_blocks, append_standard_input_sections = _import_prompt_input_utils()
    _append_prompt_stage_debug(base_inputs, "gsep_before_collect_inputs")
    input_blocks = collect_prompt_input_blocks(
        test_command_path=DEFAULT_TEST_COMMAND_PATH,
        url_path=DEFAULT_URL_PATH,
        hidden_env_keys={"OPCODE_TRACE", "SCRIPT_FILENAME", "LOGIN_COOKIE", "SCRIPT_NAME"},
        base_inputs=base_inputs if isinstance(base_inputs, dict) else None,
    )
    _append_prompt_stage_debug(base_inputs, "gsep_after_collect_inputs", input_block_keys=sorted(list(input_blocks.keys())) if isinstance(input_blocks, dict) else [])
    env_block = str(input_blocks.get("env_block") or "")
    cookie_block = str(input_blocks.get("cookie_block") or "")
    get_block = str(input_blocks.get("get_block") or "")
    post_block = str(input_blocks.get("post_block") or "")
    session_block = str(input_blocks.get("session_block") or "")
    seed_block = str(input_blocks.get("seed_block") or "")

    seq_display = ""
    if input_seq_i is not None:
        seq_display = str(int(input_seq_i))
    else:
        seq_display = "?"
    current_target_branch = ""
    desired_target_branch = ""
    if input_seq_i is not None:
        current_target_branch = (seq_to_branch.get(int(input_seq_i)) or "").strip().lower()
        if current_target_branch == "true":
            desired_target_branch = "false"
        elif current_target_branch == "false":
            desired_target_branch = "true"

    lines: List[str] = []
    target_stmt = "if statement"
    if switch_case_line_map:
        target_stmt = "switch statement"
    switch_mode = bool(switch_case_line_map)
    if switch_mode:
        lines.append(
            "Please follow the general workflow of symbolic execution based on the code context. Symbolically execute the switch statement at line "
            + seq_display
            + " and all preceding relevant if statement conditional expressions, representing them using external input expressions to form constraints. Then solve these constraint expressions. Please modify environment variables and inputs to produce external inputs that can reach all uncovered case branches. The if statements are prefixed with the current branch direction."
        )
        lines.append("Switch statement: Based on case coverage, generate inputs to reach uncovered cases. A case prefixed with false indicates it is uncovered.")
        lines.append(
            "Only modify the switch statement at line "
            + seq_display
            + "."
        )
    else:
        lines.append(
            "Please follow the general workflow of symbolic execution based on the code context. Symbolically execute the if statement at line "
            + seq_display
            + " and all preceding relevant if statement conditional expressions, representing them using external input expressions to form constraints. Then solve these constraint expressions. Please modify environment variables and inputs to provide an external input that makes the code take the opposite direction of the if statement. The [true]/[false] prefix on the if statement line indicates the branch direction actually taken in the current execution, not the target direction."
        )
        lines.append("Unless necessary, do not arbitrarily modify unrelated environment variables or input values, to ensure the code can reach the target branch.")
        if current_target_branch and desired_target_branch:
            lines.append(
                "The current actual execution direction of line "
                + seq_display
                + " is "
                + current_target_branch
                + ". Your goal this time is to make it take the "
                + desired_target_branch
                + " branch."
            )
        else:
            lines.append(
                "If line "
                + seq_display
                + " is prefixed with [true], it means the true branch was actually taken, and your goal is to make it take the false branch. If prefixed with [false], your goal is to make it take the true branch."
            )
        lines.append(
            "Only reverse the if statement at line "
            + seq_display
            + "."
        )
    try:
        app_line = build_app_name_prompt_line(load_symex_app_config())
    except Exception:
        app_line = ""
    if app_line:
        lines.append("")
        lines.append(app_line)

    lines.append("")
    append_standard_input_sections(
        lines,
        env_block=env_block,
        cookie_block=cookie_block,
        get_block=get_block,
        post_block=post_block,
        session_block=session_block,
        seed_block=seed_block,
        input_value_mask_notice=INPUT_VALUE_MASK_NOTICE,
    )
    lines.append("Code context (each line: seq | path:line | code):")
    try:
        from llm_utils.prompts.structured_context import structure_mapped_context
    except Exception:
        structure_mapped_context = None
    _append_prompt_stage_debug(base_inputs, "gsep_before_structure_context", mapped_count=len(mapped or []), has_structure_helper=bool(structure_mapped_context is not None))
    structured_input = []
    for it in mapped or []:
        if isinstance(it, dict):
            structured_input.append({**it, "__WITCHER_RUN_DIR__": str((base_inputs or {}).get("__WITCHER_RUN_DIR__") or "")})
        else:
            structured_input.append(it)
    structured = (
        structure_mapped_context(structured_input, nodes2, parent_of2, top_id_to_file2) if structure_mapped_context is not None else mapped
    )
    _append_prompt_stage_debug(base_inputs, "gsep_after_structure_context", structured_count=len(structured or []))
    context_items = []
    for it in structured or []:
        if not isinstance(it, dict):
            continue
        seq = it.get("seq")
        seq_i = None
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        loc = (it.get("loc") or "").strip()
        if not loc:
            path = (it.get("path") or "").strip()
            ln = it.get("line")
            try:
                ln_i = int(ln)
            except Exception:
                ln_i = ln
            if path and ln_i is not None:
                loc = f"{path}:{ln_i}"
        if not loc:
            continue
        code = it.get("code")
        code_s = (code if isinstance(code, str) else "").rstrip("\n")
        if not code_s.strip():
            code_s = "<SOURCE_NOT_FOUND>"
        seq_s = str(seq) if seq is not None else "?"
        branch_tag = ""
        if seq_i is not None:
            branch_tag = (seq_to_branch.get(int(seq_i)) or "").strip()
        switch_tag = ""
        if ln_i is not None:
            case_entries = switch_case_line_map.get(int(ln_i)) or []
            if case_entries:
                covered = bool((case_entries[0] or {}).get("covered"))
                switch_tag = f"[{str(covered).lower()}] "
        if branch_tag:
            code_s = _apply_branch_tag(code_s, branch_tag)
        if switch_tag:
            code_s = f"{switch_tag}{code_s}"
        context_items.append({
            "seq_s": seq_s,
            "seq_i": seq_i,
            "loc": loc,
            "loc_norm": _norm_loc_for_dedupe(loc),
            "code_s": code_s
        })

    seen_keys = set()
    unique_items = []
    for item in sorted(context_items, key=lambda x: x["seq_i"] if x["seq_i"] is not None else float('inf')):
        loc_norm = item.get("loc_norm") or item["loc"]
        seq_i = item["seq_i"]
        seq_group = trace_seq_to_group.get(int(seq_i)) if seq_i is not None else None
        record_idx = trace_seq_to_index.get(int(seq_i)) if seq_i is not None else None
        if seq_group is not None:
            dedup_key = (loc_norm, ("group", seq_group))
        elif record_idx is not None:
            dedup_key = (loc_norm, ("record", int(record_idx)))
        else:
            dedup_key = (loc_norm, ("seq", seq_i))
        if dedup_key not in seen_keys:
            seen_keys.add(dedup_key)
            unique_items.append(item)

    # Fallback dedupe: for contiguous seqs on the same source line, keep the smallest seq.
    contiguous_dedup_items = []
    for item in unique_items:
        if not contiguous_dedup_items:
            contiguous_dedup_items.append(item)
            continue
        prev = contiguous_dedup_items[-1]
        prev_seq = prev.get("seq_i")
        cur_seq = item.get("seq_i")
        if (
            prev_seq is not None
            and cur_seq is not None
            and int(cur_seq) == int(prev_seq) + 1
            and (item.get("loc_norm") or "") == (prev.get("loc_norm") or "")
        ):
            continue
        contiguous_dedup_items.append(item)

    _append_prompt_stage_debug(base_inputs, "gsep_context_items_ready", raw_context_count=len(context_items), dedup_context_count=len(contiguous_dedup_items))
    for item in contiguous_dedup_items:
        lines.append(f"{item['seq_s']} | {item['loc']} | {item['code_s']}")
    lines.append("")
    lines.append("Symbolic execution must be based solely on the provided code and if statements. Do not introduce any conditions, comparisons, or implicit assumptions that are not present in the code.")
    lines.append("General engineering priors (e.g., database NOT NULL, INSERT failure conditions, protocol specifications) may be used to infer which modifications are 'highly likely' to affect branch outcomes in real-world systems. However, do not assume specific schemas, field lengths, or hidden code.")
    lines.append("If the exact format of a parameter name cannot be determined, generate all possible parameter formats based on prior knowledge.")
    lines.append("If multiple approaches can achieve the inversion, output only one of them. If you are unsure whether a given approach is valid, you may output multiple approaches.")
    flags = load_symbolic_seed_kind_flags()
    disabled_types = [key for key in ("POST", "GET", "COOKIE", "SESSION", "ENV", "SQL", "FILE") if not bool(flags.get(key, True))]
    enabled_http_fields = [name for name in ("ENV", "POST", "COOKIE", "GET", "SESSION") if bool(flags.get(name, True))]
    lines.append("Please modify the PHP request environment variables, POST, COOKIE, GET, and SESSION parameters as needed. Only output the keys and values that need to be modified. Do not copy back the unchanged parts of the JSON.")
    if enabled_http_fields:
        lines.append("Only the following request fields are allowed to be modified: " + "/".join(enabled_http_fields))
    else:
        lines.append("All ENV/POST/COOKIE/GET/SESSION fields are currently disabled. Do not output these fields in solutions.")
    lines.append("Prefer outputting multiple solutions, each corresponding to one possible input value combination, rather than placing all possible input value modifications into a single solution.")
    if bool(flags.get("SQL", True)):
        lines.append("If the current external inputs alone cannot reliably satisfy the branch, and you need additional database information or need to modify the database state to invert the target statement, include a DB_REQUEST field in one of the objects in the solutions array.")
        lines.append('The DB_REQUEST must be a JSON object containing at least the following fields: mode, goal, reason. The mode must be one of: "lookup", "mutation", or "either".')
        lines.append("The reason must explain why modifying the current ENV/POST/COOKIE/GET/SESSION alone is insufficient, and why database information or database modification is necessary to reliably invert the target statement.")
    else:
        lines.append("SQL type is disabled: do not output DB_REQUEST, DB_QUERY, or SQL, and do not suggest solving via database queries or database state modifications.")
    if bool(flags.get("SESSION", True)):
        lines.append("If SESSION parameters need to be modified, output the session key-value pairs in the SESSION field of the JSON, using the same format as POST/GET.")
    if bool(flags.get("FILE", True)):
        lines.append("Two types of file-related external inputs are supported. File content must always be Base64-encoded. Do not write raw binary data directly into POST/GET/COOKIE/SESSION.")
        lines.append("Type 1: Direct file upload. If a POST/GET/COOKIE/ENV/SESSION key itself represents an uploaded file, set its value to the fixed placeholder __WITCHER_FILE_PAYLOAD__, and include a top-level field __WITCHER_FILE_PAYLOADS__ in the same solution.")
        lines.append("__WITCHER_FILE_PAYLOADS__ must be a JSON object. The keys are the field names from the external input; the values are file description objects containing at least filename and content_base64, with content_type optional.")
        lines.append("Type 2: File path passed in external input. If a POST/GET/COOKIE/ENV/SESSION key expects a file path, set its value to the fixed path placeholder __WITCHER_FILE_PATH__:<file_key>, where <file_key> is defined by you and must match the corresponding key in the top-level field __WITCHER_FILE_PATH_PAYLOADS__.")
        lines.append("__WITCHER_FILE_PATH_PAYLOADS__ must be a JSON object. The keys are <file_key> values, and the values are file description objects containing at least filename and content_base64, with content_type optional.")
    else:
        lines.append("FILE type is disabled: do not output __WITCHER_FILE_PAYLOAD__, __WITCHER_FILE_PAYLOADS__, __WITCHER_FILE_PATH__:*, or __WITCHER_FILE_PATH_PAYLOADS__.")
    lines.append("If some information is missing, infer possible input formats based on variable names in the code and your engineering priors, and generate some plausible input values. Do not output an empty JSON.")
    lines.append("Output only JSON. Do not output any explanatory text or Markdown.")
    lines.append(f"If you wish to delete an existing key rather than setting it to null or an empty string, set the value of that key to a string strictly equal to {DELETE_KEY_SENTINEL}. This convention applies equally to ENV/POST/COOKIE/GET/SESSION.")
    if disabled_types:
        lines.append("Additional constraint: the following types have been disabled in symex_config.json and must not appear in any solution: " + ", ".join(disabled_types) + ".")
    lines.append("Please output a JSON file. Example:")
    lines.append("{")
    lines.append('  "solutions": [')
    lines.append("    {")
    lines.append('      "POST": {')
    lines.append('        "username": "new_admin",')
    lines.append('        "status": "active"')
    lines.append("      },")
    lines.append('      "COOKIE": {')
    lines.append('        "session_id": "updated_session_12345",')
    lines.append('        "user_token": "new_token_abc"')
    lines.append("      }")
    lines.append("    },")
    lines.append("    {")
    lines.append('      "ENV": {')
    lines.append('        "METHOD": "GET"')
    lines.append("      }")
    lines.append("    },")
    lines.append("    {")
    lines.append('      "SESSION": {')
    lines.append('        "is_admin": true,')
    lines.append('        "user_id": 1')
    lines.append("      }")
    lines.append("    },")
    if bool(flags.get("FILE", True)):
        lines.append("    {")
        lines.append('      "POST": {')
        lines.append('        "avatar": "__WITCHER_FILE_PAYLOAD__"')
        lines.append("      },")
        lines.append('      "__WITCHER_FILE_PAYLOADS__": {')
        lines.append('        "avatar": {')
        lines.append('          "filename": "avatar.php",')
        lines.append('          "content_type": "application/octet-stream",')
        lines.append('          "content_base64": "PD9waHAgZWNobyAxOz8+"')
        lines.append("        }")
        lines.append("      }")
        lines.append("    },")
        lines.append("    {")
        lines.append('      "GET": {')
        lines.append('        "template_path": "__WITCHER_FILE_PATH__:tpl1"')
        lines.append("      },")
        lines.append('      "__WITCHER_FILE_PATH_PAYLOADS__": {')
        lines.append('        "tpl1": {')
        lines.append('          "filename": "shell.tpl",')
        lines.append('          "content_base64": "e3sgNyoqLyBzeXN0ZW0oJF9HRVRbY21kXSk7ICovIH19"')
        lines.append("        }")
        lines.append("      }")
        lines.append("    },")
    if bool(flags.get("SQL", True)):
            lines.append("    {")
            lines.append('      "DB_REQUEST": {')
            lines.append('        "mode": "lookup",')
            lines.append('        "goal": "To make the target if statement take the opposite branch, need to confirm whether the user record corresponding to $_POST[username] exists, and whether the role/status in that record affects the branch decision.",')
            lines.append('        "reason": "The current code bases the branch outcome on the user state in the database. Guessing input values alone cannot reliably solve this."')
            lines.append("      }")
            lines.append("    }")
    else:
        lines.append("    {")
        lines.append('      "GET": {')
        lines.append('        "debug": "1"')
        lines.append("      }")
        lines.append("    }")
    lines.append("  ]")
    lines.append("}")
    prompt_text = "\n".join(lines).rstrip() + "\n"
    _append_prompt_stage_debug(base_inputs, "gsep_return", line_count=len(lines), prompt_len=len(prompt_text or ""))
    return prompt_text


def write_symbolic_execution_prompt_from_analysis(
    analysis_output_path: str,
    *,
    out_path: Optional[str] = None,
    scope_root: str = "/app",
    trace_index_path: str = "trace_index.json",
    windows_root: str = r"D:\files\witcher\app",
    base_prompt: Optional[str] = None,
    nodes_path: str = "nodes.csv",
    rels_path: str = "rels.csv",
) -> str:
    prompt = generate_symbolic_execution_prompt(
        analysis_output_path,
        scope_root=scope_root,
        trace_index_path=trace_index_path,
        windows_root=windows_root,
        base_prompt=base_prompt,
        nodes_path=nodes_path,
        rels_path=rels_path,
    )
    if not out_path:
        out_dir = os.path.dirname(os.path.abspath(analysis_output_path))
        try:
            with open(analysis_output_path, "r", encoding="utf-8", errors="replace") as f:
                obj: Any = json.load(f)
        except Exception:
            obj = {}
        seq = obj.get("input_seq") if isinstance(obj, dict) else None
        name = f"symbolic_prompt_{seq}.txt" if seq is not None else "symbolic_prompt.txt"
        out_path = os.path.join(out_dir, name)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(prompt)
    return out_path


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    p.add_argument("analysis_output", help="Path to the JSON file output by analyze_if_line.py, or a direct seq (e.g., 52564)")
    p.add_argument("--out", dest="out_path", default="", help="Output path for the prompt text file")
    p.add_argument("--scope-root", dest="scope_root", default="/app")
    p.add_argument("--trace-index", dest="trace_index_path", default=os.path.join("tmp", "trace_index.json"))
    p.add_argument("--windows-root", dest="windows_root", default=r"D:\files\witcher\app")
    p.add_argument("--base-prompt", dest="base_prompt", default="")
    p.add_argument("--nodes", dest="nodes_path", default=os.path.join("input", "nodes.csv"))
    p.add_argument("--rels", dest="rels_path", default=os.path.join("input", "rels.csv"))
    return p


def main(argv=None) -> int:
    args = _build_arg_parser().parse_args(argv)
    analysis_output_path = args.analysis_output
    if isinstance(analysis_output_path, str) and analysis_output_path.isdigit() and not os.path.exists(analysis_output_path):
        analysis_output_path = os.path.join(
            os.getcwd(),
            "test",
            f"seq_{analysis_output_path}",
            f"analysis_output_{analysis_output_path}.json",
        )
    out = write_symbolic_execution_prompt_from_analysis(
        analysis_output_path,
        out_path=(args.out_path or None),
        scope_root=args.scope_root,
        trace_index_path=args.trace_index_path,
        windows_root=args.windows_root,
        base_prompt=(args.base_prompt or None),
        nodes_path=args.nodes_path,
        rels_path=args.rels_path,
    )
    sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
