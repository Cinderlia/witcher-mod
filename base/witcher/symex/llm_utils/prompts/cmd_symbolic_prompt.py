"""
Generate plain-text prompts for LLM-assisted symbolic execution.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from common.app_config import append_app_name_to_prompt, build_app_name_prompt_line, load_symex_app_config
from llm_utils.solution_markers import DELETE_KEY_SENTINEL

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


DEFAULT_TEST_COMMAND_PATH = os.path.join("input", "test_command.txt")


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

def _normalize_key_case(obj: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (obj or {}).items():
        if not isinstance(k, str):
            continue
        ks = k.strip().upper()
        if not ks:
            continue
        out[ks] = v
    return out


def _load_result_set(result_set_or_path):
    if isinstance(result_set_or_path, (list, tuple)):
        return list(result_set_or_path)
    if not isinstance(result_set_or_path, str) or not result_set_or_path:
        return []
    if not os.path.exists(result_set_or_path):
        return []
    try:
        with open(result_set_or_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        if isinstance(obj, dict):
            return obj.get("result_set") or obj.get("result") or []
        if isinstance(obj, list):
            return obj
        return []
    except Exception:
        return []


def _load_analysis_obj(result_set_or_path):
    if not isinstance(result_set_or_path, str) or not result_set_or_path:
        return None
    if not os.path.exists(result_set_or_path):
        return None
    try:
        with open(result_set_or_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _resolve_existing_path(path: str, fallback: str) -> str:
    if path and os.path.exists(path):
        return path
    if fallback and os.path.exists(fallback):
        return fallback
    return path or fallback


def _import_prompt_utils():
    try:
        from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
    except Exception:
        map_result_set_to_source_lines = None
    return map_result_set_to_source_lines


def _import_if_branch_utils():
    try:
        from if_branch_coverage import infer_if_directions_for_seqs
    except Exception:
        infer_if_directions_for_seqs = None
    try:
        from utils.trace_utils.trace_edges import load_trace_index_records
    except Exception:
        load_trace_index_records = None
    return infer_if_directions_for_seqs, load_trace_index_records


def _import_call_scope_utils():
    try:
        from taint_handlers.handlers.call.ast_method_call import partition_function_scope_for_call
    except Exception:
        partition_function_scope_for_call = None
    return partition_function_scope_for_call


def _loc_key(path: str, line: int) -> Optional[Tuple[str, int]]:
    if not path or line is None:
        return None
    try:
        ln = int(line)
    except Exception:
        return None
    return str(path), ln


def _strip_app_prefix(p: str) -> str:
    p = (p or "").strip()
    if p.startswith("/app/"):
        p = p[5:]
    if p.startswith("/"):
        p = p[1:]
    return p


def _parse_loc(loc: str):
    if not loc or ":" not in loc:
        return None
    p, ln_s = loc.rsplit(":", 1)
    try:
        ln = int(ln_s)
    except Exception:
        return None
    p = _strip_app_prefix(p).replace("\\", "/")
    return p, ln


def _match_loc(loc: str, path: str, line: int) -> bool:
    if not loc or not path or line is None:
        return False
    pr = _parse_loc(loc)
    if not pr:
        return False
    p, ln = pr
    try:
        ln_i = int(ln)
    except Exception:
        return False
    return p == _strip_app_prefix(path).replace("\\", "/") and ln_i == int(line)


def _merge_initial_seq_into_result_set(result_set, *, input_seq: Optional[int], input_path: Optional[str], input_line: Optional[int]):
    if input_seq is None or not input_path or input_line is None:
        return result_set
    out = list(result_set or [])
    for it in out:
        if not isinstance(it, dict):
            continue
        if it.get("seq") == input_seq:
            return out
    out.append({"seq": int(input_seq), "path": input_path, "line": int(input_line), "loc": f"{input_path}:{int(input_line)}"})
    return out


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


def _build_trace_seq_to_group(trace_index_records: List[dict]) -> Dict[int, Tuple[int, ...]]:
    out: Dict[int, Tuple[int, ...]] = {}
    for rec in trace_index_records or []:
        if not isinstance(rec, dict):
            continue
        seqs: List[int] = []
        for s in rec.get("seqs") or []:
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


def _normalize_dir_name(s: str) -> str:
    if not isinstance(s, str):
        return ""
    v = s.strip().lower()
    if v in ("t", "true", "1", "yes"):
        return "true"
    if v in ("f", "false", "0", "no"):
        return "false"
    return v


def _format_if_direction(dir_s: str) -> str:
    v = _normalize_dir_name(dir_s)
    if not v:
        return ""
    if v in ("true", "t", "yes", "1"):
        return "true"
    if v in ("false", "f", "no", "0"):
        return "false"
    return v


def _merge_dir_into_code(code: str, dir_s: str) -> str:
    d = _format_if_direction(dir_s)
    if not d:
        return code
    return f"{code}    # Current branch direction: {d}"


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
        rec = trace_index_records[rec_idx] or {}
        node_ids = rec.get("node_ids") or []
        call_id = None
        for nid in node_ids:
            try:
                ni = int(nid)
            except Exception:
                continue
            nt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
            if nt in ("AST_METHOD_CALL", "AST_CALL", "AST_STATIC_CALL"):
                call_id = int(ni)
                break
        if call_id is None:
            continue
        callsites.append({"call_id": call_id, "call_seq": seq_i, "code": it_code_s})

    callsites.sort(key=lambda x: int(x.get("call_seq") or 0))
    loc_to_tags: Dict[str, List[str]] = {}
    seen_call_tags: Set[str] = set()
    for call in callsites:
        call_id_i = call.get("call_id")
        call_seq_i = call.get("call_seq")
        if call_id_i is None or call_seq_i is None:
            continue
        key = (int(call_id_i), int(call_seq_i))
        if key in seen_calls:
            continue
        seen_calls.add(key)
        try:
            scope = partition_function_scope_for_call(int(call_id_i), int(call_seq_i), {
                "nodes": nodes,
                "children_of": children_of,
                "parent_of": parent_of,
                "top_id_to_file": top_id_to_file,
                "trace_index_records": trace_index_records,
                "trace_seq_to_index": trace_seq_to_index,
                "calls_edges_union": None,
            })
        except Exception:
            scope = None
        if not scope:
            continue
        scope_start = scope.get("scope_start_seq")
        scope_end = scope.get("scope_end_seq")
        if scope_start is None or scope_end is None:
            continue
        scope_locs = scope.get("scope") or []
        scope_loc_set = set()
        for it in scope_locs:
            if not isinstance(it, dict):
                continue
            loc = it.get("loc")
            if not loc:
                p = it.get("path")
                ln = it.get("line")
                if p and ln is not None:
                    loc = f"{p}:{ln}"
            if loc:
                scope_loc_set.add(loc)

        call_name = call.get("code")
        tag = call_name or f"call_id={call_id_i}"
        if tag in seen_call_tags:
            continue
        seen_call_tags.add(tag)
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
    trace_index_records2 = list(trace_index_records or [])
    if not trace_index_records2 and load_trace_index_records and trace_index_path2:
        trace_index_records2 = load_trace_index_records(trace_index_path2)
    trace_seq_to_index2 = dict(trace_seq_to_index or {})
    trace_seq_to_group = _build_trace_seq_to_group(trace_index_records2)
    for rec in trace_index_records2 or []:
        idx = rec.get("index")
        for s in rec.get("seqs") or []:
            try:
                si = int(s)
            except Exception:
                continue
            if si not in trace_seq_to_index2:
                trace_seq_to_index2[si] = int(idx) if idx is not None else 0

    nodes2 = dict(nodes or {})
    parent_of2 = dict(parent_of or {})
    children_of2 = dict(children_of or {})
    top_id_to_file2 = dict(top_id_to_file or {})
    if not nodes2 or not children_of2:
        nodes_path2 = _resolve_existing_path(
            nodes_path,
            fallback=os.path.join(os.getcwd(), "input", os.path.basename(nodes_path or "nodes.csv")),
        )
        rels_path2 = _resolve_existing_path(
            rels_path,
            fallback=os.path.join(os.getcwd(), "input", os.path.basename(rels_path or "rels.csv")),
        )
        try:
            from utils.cpg_utils.graph_mapping import load_nodes, load_ast_edges
            if not nodes2 and nodes_path2 and os.path.exists(nodes_path2):
                nodes2, top_id_to_file2 = load_nodes(nodes_path2)
            if not children_of2 and rels_path2 and os.path.exists(rels_path2):
                parent_of2, children_of2 = load_ast_edges(rels_path2)
        except Exception:
            nodes2 = {}
            parent_of2 = {}
            children_of2 = {}
            top_id_to_file2 = {}

    loc_to_tags = _build_loc_to_func_impl_tags(
        mapped,
        trace_index_records=trace_index_records2,
        trace_seq_to_index=trace_seq_to_index2,
        nodes=nodes2,
        parent_of=parent_of2,
        children_of=children_of2,
        top_id_to_file=top_id_to_file2,
    )

    env_block = ""
    cookie_block = ""
    get_block = ""
    post_block = ""
    seed_block = ""
    INPUT_VALUE_MASK_NOTICE, collect_prompt_input_blocks, append_standard_input_sections = _import_prompt_input_utils()
    env_block = ""
    cookie_block = ""
    get_block = ""
    post_block = ""
    session_block = ""
    seed_block = ""
    if base_prompt is None:
        input_blocks = collect_prompt_input_blocks(
            test_command_path=DEFAULT_TEST_COMMAND_PATH,
            base_inputs=base_inputs if isinstance(base_inputs, dict) else None,
        )
        env_block = str(input_blocks.get("env_block") or "")
        cookie_block = str(input_blocks.get("cookie_block") or "")
        get_block = str(input_blocks.get("get_block") or "")
        post_block = str(input_blocks.get("post_block") or "")
        session_block = str(input_blocks.get("session_block") or "")
        seed_block = str(input_blocks.get("seed_block") or "")
    else:
        base_prompt = (base_prompt or "").strip()
        if base_prompt:
            try:
                return append_app_name_to_prompt(base_prompt, load_symex_app_config()) + "\n"
            except Exception:
                return append_app_name_to_prompt(base_prompt, {}) + "\n"

    if_dirs = infer_if_directions_for_seqs(
        list({int(x.get("seq")) for x in (mapped or []) if isinstance(x, dict) and x.get("seq") is not None}),
        trace_index_records=trace_index_records2,
        nodes=nodes2,
        children_of=children_of2,
    ) if infer_if_directions_for_seqs and trace_index_records2 and nodes2 and children_of2 else []
    seq_to_dir = _build_seq_to_branch(if_dirs or [])

    lines = []
    if input_seq is not None:
        seq_display = f"{int(input_seq)}"
    else:
        seq_display = "?"
    lines.append("You are a professional code analysis assistant. Your task is to help the Web Fuzzer discover command injection vulnerabilities.")
    lines.append("")
    lines.append(
        "Symbolically execute the command execution statement at line "
        + seq_display
        + ", representing it using external input expressions to form constraints for symbolic execution. Then solve these constraint expressions. Please modify environment variables and inputs to provide an external input (environment variables, COOKIE, POST, GET, SESSION) that can break the syntactic structure of the command execution statement."
    )
    lines.append("Note: The goal is not to exploit the vulnerability, but to construct inputs that cause bash to produce errors, thereby triggering the fuzz tool's error detection mechanism.")
    lines.append("Target the syntactic structure of the command execution statement. Use unclosed quotes, backticks, and other special constructs to induce syntax errors. Prefer short payloads.")
    try:
        app_line = build_app_name_prompt_line(load_symex_app_config())
    except Exception:
        app_line = ""
    if app_line:
        lines.append("")
        lines.append(app_line)

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
        if seq_i is not None:
            if seq_to_dir.get(seq_i):
                code_s = _merge_dir_into_code(code_s, seq_to_dir.get(seq_i) or "")
        tags = loc_to_tags.get(loc) or []
        if tags:
            code_s = f"{code_s}    # {', '.join(tags)}"
        seq_s = str(seq) if seq is not None else "?"
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
    lines.append("General engineering priors (e.g., database NOT NULL, INSERT failure conditions, protocol specifications) may be used to infer which modifications are 'highly likely' to affect command execution outcomes in real-world systems. However, do not assume specific schemas, field lengths, or hidden code.")
    lines.append("If the exact format of a parameter name cannot be determined, generate all possible parameter formats based on prior knowledge.")
    lines.append("If multiple approaches can achieve the inversion, output only one of them. If you are unsure whether a given approach is valid, you may output multiple approaches.")
    lines.append("If you can confirm that the variable determining this command execution statement does not come from any of the above five input types (environment variables, COOKIE, POST, GET, SESSION), then treat it as unmodifiable.")
    lines.append("If some information is missing, infer possible input formats based on variable names in the code and your engineering priors, and generate some plausible input values. Only output an empty JSON when you are certain that no further information can be inferred.")
    lines.append("Output only the keys and values that need to be modified. Do not copy unmodified ENV/COOKIE/POST/GET/SESSION fields back into the JSON; downstream will perform incremental merging based on the current inputs.")
    lines.append("Output only JSON. Do not output any explanatory text or Markdown.")
    lines.append("If SESSION parameters need to be modified, output the session key-value pairs in the SESSION field of the JSON, using a JSON object. Do not output the full session file content; downstream will automatically generate a valid session file based on the current SESSION and your modifications.")
    lines.append(f"If you wish to delete an existing key rather than setting it to null or an empty string, set the value of that key to a string strictly equal to {DELETE_KEY_SENTINEL}. This convention applies equally to ENV/POST/COOKIE/GET/SESSION.")
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
    lines.append("    }")
    lines.append("  ]")
    lines.append("}")
    return "\n".join(lines).rstrip() + "\n"


def _load_prompt_text(path: str) -> str:
    if not isinstance(path, str) or not path:
        return ""
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("result_set", nargs="?", default="")
    ap.add_argument("--prompt", default="")
    ap.add_argument("--input-seq", type=int, default=None)
    ap.add_argument("--input-path", type=str, default=None)
    ap.add_argument("--input-line", type=int, default=None)
    ap.add_argument("--scope-root", type=str, default="/app")
    ap.add_argument("--trace-index", type=str, default=os.path.join("tmp", "trace_index.json"))
    ap.add_argument("--windows-root", type=str, default=r"D:\files\witcher\app")
    ap.add_argument("--nodes", type=str, default=os.path.join("input", "nodes.csv"))
    ap.add_argument("--rels", type=str, default=os.path.join("input", "rels.csv"))
    args = ap.parse_args()

    base_prompt = _load_prompt_text(args.prompt) if args.prompt else None
    txt = generate_symbolic_execution_prompt(
        args.result_set,
        input_seq=args.input_seq,
        input_path=args.input_path,
        input_line=args.input_line,
        scope_root=args.scope_root,
        trace_index_path=args.trace_index,
        windows_root=args.windows_root,
        base_prompt=base_prompt,
        nodes_path=args.nodes,
        rels_path=args.rels,
    )
    sys.stdout.write(txt or "")


if __name__ == "__main__":
    main()
