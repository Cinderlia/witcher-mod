import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from common.app_config import append_app_name_to_prompt, build_app_name_prompt_line, load_symex_app_config
from llm_utils.solution_markers import DELETE_KEY_SENTINEL

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

DEFAULT_TEST_COMMAND_PATH = os.path.join("input", "test_command.txt")
DEFAULT_URL_PATH = os.path.join("input", "url.txt")

from llm_utils.prompts.prompt_utils import (
    INPUT_VALUE_MASK_NOTICE,
    append_http_input_sections,
    collect_prompt_input_blocks,
    read_json_obj,
    resolve_prompt_input_path,
)


def _resolve_existing_path(path: str, fallback: str) -> str:
    p = (path or "").strip()
    if p and os.path.exists(p):
        return p
    if fallback and os.path.exists(fallback):
        return fallback
    return p or fallback


def _load_result_set(result_set_or_path) -> List[dict]:
    if isinstance(result_set_or_path, str):
        try:
            with open(result_set_or_path, "r", encoding="utf-8", errors="replace") as f:
                obj = json.load(f)
        except Exception:
            return []
        if isinstance(obj, dict):
            return obj.get("result_set") or []
        return obj if isinstance(obj, list) else []
    if isinstance(result_set_or_path, dict):
        return result_set_or_path.get("result_set") or []
    return result_set_or_path if isinstance(result_set_or_path, list) else []


def _load_analysis_obj(result_set_or_path):
    if isinstance(result_set_or_path, str):
        try:
            with open(result_set_or_path, "r", encoding="utf-8", errors="replace") as f:
                obj = json.load(f)
        except Exception:
            return None
        return obj if isinstance(obj, dict) else None
    if isinstance(result_set_or_path, dict):
        return result_set_or_path
    return None


def _merge_initial_seq_into_result_set(rs: List[dict], *, input_seq: Optional[int], input_path: Optional[str], input_line: Optional[int]) -> List[dict]:
    if input_seq is None or not input_path or input_line is None:
        return rs
    for it in rs or []:
        try:
            if int(it.get("seq")) == int(input_seq):
                return rs
        except Exception:
            continue
    rs2 = list(rs or [])
    rs2.append({"seq": int(input_seq), "path": input_path, "line": int(input_line)})
    return rs2


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

    if base_prompt:
        base_prompt = (base_prompt or "").strip()
        if base_prompt:
            try:
                return append_app_name_to_prompt(base_prompt, load_symex_app_config()) + "\n"
            except Exception:
                return append_app_name_to_prompt(base_prompt, {}) + "\n"

    env_block = ""
    header_block = ""
    cookie_block = ""
    get_block = ""
    post_block = ""
    seed_block = ""
    override_inputs = dict(base_inputs or {}) if isinstance(base_inputs, dict) else {}
    base_inputs = {}
    env_path = resolve_prompt_input_path(os.path.join("input", "env.json"))
    try:
        base_inputs = read_json_obj(env_path)
    except Exception:
        base_inputs = {}
    if not isinstance(base_inputs, dict):
        base_inputs = {}
    if isinstance(base_inputs, dict) and isinstance(override_inputs, dict) and override_inputs:
        merged_inputs = dict(base_inputs)
        merged_env = dict(merged_inputs.get("ENV") or {})
        merged_env.update(dict(override_inputs.get("ENV") or {}))
        merged_inputs.update(override_inputs)
        if merged_env:
            merged_inputs["ENV"] = merged_env
        base_inputs = merged_inputs

    input_blocks = collect_prompt_input_blocks(
        test_command_path=DEFAULT_TEST_COMMAND_PATH,
        url_path=DEFAULT_URL_PATH,
        base_inputs=base_inputs if isinstance(base_inputs, dict) else None,
    )
    env_block = str(input_blocks.get("env_block") or "")
    header_block = str(input_blocks.get("header_block") or "")
    cookie_block = str(input_blocks.get("cookie_block") or "")
    get_block = str(input_blocks.get("get_block") or "")
    post_block = str(input_blocks.get("post_block") or "")
    seed_block = str(input_blocks.get("seed_block") or "")
    session_block = str(input_blocks.get("session_block") or "")

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
    lines.append("You are a professional code analysis assistant. Your task is to help the Web Fuzzer discover reflected XSS injection vulnerabilities.")
    lines.append("")
    lines.append(
        "Symbolically execute the expression at the XSS injection point on line "
        + seq_display
        + ", representing it using external input expressions to form constraints for symbolic execution. Then solve these constraint expressions. Please modify environment variables and inputs to provide an external input (environment variables, COOKIE, POST, GET, SESSION) that can trigger XSS injection."
    )
    lines.append("Note: The goal is not merely to have the input reflected into the HTML page, but to construct input that injects executable structures into the HTML page.")
    lines.append("Construct payloads based on the actual context. For example, when encountering single quotes, close the quotes to escape them; the same applies to parentheses and comments.")
    lines.append("Also pay attention to the direction of if statements to ensure the code can reach the injection point.")
    try:
        app_line = build_app_name_prompt_line(load_symex_app_config())
    except Exception:
        app_line = ""
    if app_line:
        lines.append("")
        lines.append(app_line)

    append_http_input_sections(
        lines,
        env_block=env_block,
        header_block=header_block,
        cookie_block=cookie_block,
        get_block=get_block,
        post_block=post_block,
        session_block=session_block,
        seed_block=seed_block,
        input_value_mask_notice=INPUT_VALUE_MASK_NOTICE,
    )

    lines.append("Below is the path that the XSS injection point depends on. Please analyze the path information to infer how the XSS injection point is controlled by the input.")
    lines.append("")
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
        try:
            seq_i = int(seq)
        except Exception:
            seq_i = None
        loc = it.get("loc")
        if not loc:
            p = it.get("path")
            ln = it.get("line")
            if p and ln is not None:
                loc = f"{p}:{int(ln)}"
        if not loc:
            continue
        code_s = it.get("code") or ""
        if not code_s.strip():
            code_s = "<SOURCE_NOT_FOUND>"
        seq_s = str(seq) if seq is not None else "?"
        branch_tag = ""
        if seq_i is not None:
            branch_tag = (seq_to_dir.get(int(seq_i)) or "").strip()
        if branch_tag and code_s.lstrip().startswith("if"):
            code_s = f"[{branch_tag}] {code_s}"
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

    lines.append("Symbolic execution must be based solely on the provided code and if statements. Do not introduce any conditions, comparisons, or implicit assumptions that are not present in the code.")
    lines.append("General engineering priors (e.g., database NOT NULL, INSERT failure conditions, protocol specifications) may be used to infer which modifications are 'highly likely' to affect xss injection point outcomes in real-world systems. However, do not assume specific schemas, field lengths, or hidden code.")
    lines.append("If the exact format of a parameter name cannot be determined, generate all possible parameter formats based on prior knowledge.")
    lines.append("If multiple approaches can achieve the inversion, output only one of them. If you are unsure whether a given approach is valid, you may output multiple approaches.")
    lines.append("If you can confirm that the variable determining this SQL statement does not come from any of the above five input types (environment variables, COOKIE, POST, GET, SESSION), then treat it as unmodifiable.")
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
