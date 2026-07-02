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
    return f"{code_s}    # 当前分支方向: {tag}"


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

    env_idx = _find_line("本次执行的环境变量是：")
    input_idx = _find_line("本次执行的输入是：")
    context_idx = _find_line("代码上下文（每行：seq | path:line | code）：")
    constraint_idx = _find_line("仅基于给出的代码和if语句进行符号化， 不允许引入任何未在代码中出现的条件、比较、隐含判断。")

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
    for line in lines:
        if not line:
            if objective_lines:
                break
            continue
        if line.startswith("下面的代码来自"):
            break
        if line.startswith("本次执行的环境变量是："):
            break
        if line.startswith("代码上下文（每行：seq | path:line | code）："):
            break
        if seq_text and seq_text + "行" in line:
            objective_lines.append(line)
            continue
        if line.startswith("如果" + seq_text + "行") or line.startswith("仅反转") or line.startswith("仅修改") or line.startswith("switch语句："):
            objective_lines.append(line)
            continue
        if objective_lines and ("分支" in line or "case" in line or "目标" in line):
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
    if callable(map_result_set_to_source_lines):
        mapped = map_result_set_to_source_lines(
            scope_root,
            rs,
            trace_index_path=trace_index_path2,
            windows_root=windows_root,
        )
    else:
        mapped = list(rs or [])

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
            if not trace_index_records2 and trace_index_path2 and os.path.exists(trace_index_path2):
                trace_index_records2 = load_trace_index_records(trace_index_path2)
            if not nodes2 and nodes_path2 and os.path.exists(nodes_path2):
                nodes2, top_id_to_file2 = load_nodes(nodes_path2)
            if not children_of2 and rels_path2 and os.path.exists(rels_path2):
                parent_of2, children_of2 = load_ast_edges(rels_path2)
            if_dirs = infer_if_directions_for_seqs(
                if_seqs,
                trace_index_records=trace_index_records2,
                nodes=nodes2,
                children_of=children_of2,
            )
            switch_choices = infer_switch_choices_for_seqs(
                if_seqs,
                trace_index_records=trace_index_records2,
                nodes=nodes2,
                children_of=children_of2,
            )
        except Exception:
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
        case_rs = build_switch_case_result_set_for_seq(
            int(input_seq_i),
            trace_index_records=trace_index_records2,
            nodes=nodes2,
            children_of=children_of2,
        )
        if case_rs:
            mapped_cases = map_result_set_to_source_lines(
                scope_root,
                case_rs,
                trace_index_path=trace_index_path2,
                windows_root=windows_root,
            )
            mapped = insert_mapped_items_after_seq(mapped or [], after_seq=int(input_seq_i), insert_items=mapped_cases or [])

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
            locs2 = _filter_func_def_locs_from_include(list(locs), trace_index_records2, nodes2, scope_ctx)
            locs2 = _filter_define_locs_from_include(locs2, trace_index_records2, nodes2, children_of2, scope_ctx.get("parent_of") or {}, scope_ctx)
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
        except Exception:
            pass

    INPUT_VALUE_MASK_NOTICE, collect_prompt_input_blocks, append_standard_input_sections = _import_prompt_input_utils()
    input_blocks = collect_prompt_input_blocks(
        test_command_path=DEFAULT_TEST_COMMAND_PATH,
        url_path=DEFAULT_URL_PATH,
        hidden_env_keys={"OPCODE_TRACE", "SCRIPT_FILENAME", "LOGIN_COOKIE", "SCRIPT_NAME"},
        base_inputs=base_inputs if isinstance(base_inputs, dict) else None,
    )
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
    target_stmt = "if语句"
    if switch_case_line_map:
        target_stmt = "switch语句"
    switch_mode = bool(switch_case_line_map)
    if switch_mode:
        lines.append(
            "请你根据代码上下文，严格按照符号执行的一般流程，将"
            + seq_display
            + "行的switch语句和它之前所有相关的if语句的条件表达式符号化，使用外部输入的表达式来表示，形成符号执行中的约束。然后求解这些约束表达式，请修改环境变量和输入，给我能够进入所有未被覆盖到的case分支的外部输入。if语句的前面标注了当前的分支走向。"
        )
        lines.append("switch语句：根据case覆盖情况，生成进入未覆盖case的输入，case前标注false代表未覆盖。")
        lines.append(
            "仅修改"
            + seq_display
            + "行的switch语句。"
        )
    else:
        lines.append(
            "请你根据代码上下文，严格按照符号执行的一般流程，将"
            + seq_display
            + "行的if语句和它之前所有相关的if语句的条件表达式符号化，使用外部输入的表达式来表示，形成符号执行中的约束。然后求解这些约束表达式，请修改环境变量和输入，给我一个能够让代码走向if语句另一个方向的外部输入。if语句代码行前面的[true]/[false]标注表示当前这次执行实际走到的分支方向，不是目标方向。"
        )
        lines.append("非必要的话，不要随意修改无关的环境变量和输入值，以确保代码能够执行到目标分支。")
        if current_target_branch and desired_target_branch:
            lines.append(
                seq_display
                + "行当前实际执行方向是"
                + current_target_branch
                + "，你这次的目标是让这一行改走"
                + desired_target_branch
                + "分支。"
            )
        else:
            lines.append(
                "如果"
                + seq_display
                + "行前面标注为[true]，表示当前实际执行到了true分支，你的目标是让它改走false分支；如果标注为[false]，则目标是让它改走true分支。"
            )
        lines.append(
            "仅反转"
            + seq_display
            + "行的if语句。"
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
    lines.append("代码上下文（每行：seq | path:line | code）：")
    try:
        from llm_utils.prompts.structured_context import structure_mapped_context
    except Exception:
        structure_mapped_context = None
    structured = (
        structure_mapped_context(mapped, nodes2, parent_of2, top_id_to_file2) if structure_mapped_context is not None else mapped
    )
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

    for item in contiguous_dedup_items:
        lines.append(f"{item['seq_s']} | {item['loc']} | {item['code_s']}")
    lines.append("")
    lines.append("仅基于给出的代码和if语句进行符号化， 不允许引入任何未在代码中出现的条件、比较、隐含判断。")
    lines.append("允许使用通用工程先验（如数据库 NOT NULL、INSERT 失败条件、协议规范）来推断哪些修改“在现实系统中高度可能”影响分支结果，但不允许假设具体 schema、字段长度或隐藏代码")
    lines.append("如果无法确定参数名称的具体格式，根据先验知识尝试生成所有可能的参数格式。")
    lines.append("如果有多个方案，都可以实现反转，仅输出其中一个。如果你不能确定该方案是否有效，可以输出多个方案。")
    flags = load_symbolic_seed_kind_flags()
    disabled_types = [key for key in ("POST", "GET", "COOKIE", "SESSION", "ENV", "SQL", "FILE") if not bool(flags.get(key, True))]
    enabled_http_fields = [name for name in ("ENV", "POST", "COOKIE", "GET", "SESSION") if bool(flags.get(name, True))]
    lines.append("请根据需求修改PHP请求的环境变量、POST、COOKIE、GET、SESSION参数（对应 JSON 字段：ENV/POST/COOKIE/GET/SESSION）。只输出需要修改的键和值，不要把未修改的部分原样抄回 JSON。下游会基于当前输入做增量合并。")
    if enabled_http_fields:
        lines.append("当前允许输出的请求/环境字段只有：" + "/".join(enabled_http_fields) + "。")
    else:
        lines.append("当前 ENV/POST/COOKIE/GET/SESSION 全部被禁用，solutions 中不要输出这些字段。")
    lines.append("倾向于输出复数个解决方案，每个解决方案对应一个可能的输入值组合，而不是把所有可能的输入值修改都写在一个解决方案里。")
    if bool(flags.get("SQL", True)):
        lines.append("如果仅靠当前外部输入无法稳定求解，而你需要额外的数据库信息，或者需要通过修改数据库状态来反转当前目标语句，请在 solutions 数组中的某个对象里输出 DB_REQUEST 字段。")
        lines.append('DB_REQUEST 必须是一个 JSON 对象，至少包含以下字段：mode、goal、reason。mode 只能是 "lookup"、"mutation"、"either" 之一。')
        lines.append("reason 需要说明为什么只改当前 ENV/POST/COOKIE/GET/SESSION 还不够，为什么必须借助数据库信息或数据库修改，才能稳定反转目标语句。")
    else:
        lines.append("SQL 类型已被禁用：不要输出 DB_REQUEST、DB_QUERY、SQL，也不要建议通过数据库查询或数据库状态修改来求解。")
    lines.append("如果缺少部分信息，尽量根据代码中的变量名和你的工程先验执行推断外部输入的格式，生成一些可能的输入值。不要输出空json。")
    lines.append("只输出JSON，不要输出任何解释性文字或Markdown。")
    if bool(flags.get("SESSION", True)):
        lines.append("如果需要修改SESSION参数，请在JSON的 SESSION 字段中输出你想修改的 session 键值对，格式与 POST/GET 类似。")
    if bool(flags.get("FILE", True)):
        lines.append("支持两类文件相关外部输入，并且文件内容一律使用 Base64。不要把二进制原文直接写进 POST/GET/COOKIE/SESSION。")
        lines.append("第一类：直接上传文件。如果某个 POST/GET/COOKIE/ENV/SESSION 键本身代表上传文件，请把该键的值设置为固定文件占位标记 __WITCHER_FILE_PAYLOAD__ ，并在同一个 solution 里输出顶层字段 __WITCHER_FILE_PAYLOADS__。")
        lines.append("__WITCHER_FILE_PAYLOADS__ 必须是 JSON 对象，键名就是外部输入里的那个字段名；值是文件描述对象，至少包含 filename、content_base64，可选 content_type。")
        lines.append("第二类：外部输入里传递的是文件路径。如果某个 POST/GET/COOKIE/ENV/SESSION 键需要的是文件路径，请把该键的值设置为固定路径占位标记 __WITCHER_FILE_PATH__:<file_key> ，其中 <file_key> 由你自定义但要和顶层字段 __WITCHER_FILE_PATH_PAYLOADS__ 里的键一致。")
        lines.append("__WITCHER_FILE_PATH_PAYLOADS__ 必须是 JSON 对象，键为 <file_key>，值是文件描述对象，至少包含 filename、content_base64，可选 content_type。")
    else:
        lines.append("FILE 类型已被禁用：不要输出 __WITCHER_FILE_PAYLOAD__、__WITCHER_FILE_PAYLOADS__、__WITCHER_FILE_PATH__:*、__WITCHER_FILE_PATH_PAYLOADS__。")
    lines.append(f"如果你想删除某个已有键，而不是把它设为 null 或空串，请把该键的值设置为严格等于 {DELETE_KEY_SENTINEL} 的字符串。这个约定同样适用于 ENV/POST/COOKIE/GET/SESSION。")
    if disabled_types:
        lines.append("额外约束：以下类型已在 symex_config.json 中被禁用，solutions 中严禁出现：" + ", ".join(disabled_types) + "。")
    lines.append("请输出一个JSON文件，示例：")
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
        lines.append('        "goal": "为了让目标 if 改走另一侧分支，需要确认 $_POST[username] 对应的用户记录是否存在，以及该记录中的 role/status 是否会影响该分支判断。",')
        lines.append('        "reason": "当前代码把分支结果建立在数据库中的用户状态上，仅靠猜测输入值无法稳定求解。"')
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
    return "\n".join(lines).rstrip() + "\n"


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
    p.add_argument("analysis_output", help="analyze_if_line.py 输出的 JSON 文件路径，或直接输入 seq（例如 52564）")
    p.add_argument("--out", dest="out_path", default="", help="输出 prompt 文本文件路径")
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
