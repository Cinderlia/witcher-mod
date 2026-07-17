"""Build LLM prompts and parse per-candidate source labels."""

import json
import re
from typing import Dict, Iterable, List, Optional


CATEGORIES = (
    "POST",
    "GET",
    "COOKIE",
    "SESSION",
    "Headers",
    "SERVER",
    "ENV",
    "FILE",
    "SQL",
    "CACHE",
)


def build_count_prompt(
    *,
    app_name: str,
    reference_lines: Iterable[str],
    context_lines: Iterable[str],
    candidate_variables: Iterable[str],
) -> str:
    app_label = (app_name or "").strip()
    if app_label:
        source_line = "The following code is from " + app_label
    else:
        source_line = "The following code is from an application to be analyzed"

    merged_reference = [(line or "").rstrip() for line in (reference_lines or [])]
    merged_reference = [line for line in merged_reference if line is not None]
    merged_context = [(line or "").rstrip() for line in (context_lines or []) if (line or "").strip()]
    merged_candidates = [(name or "").strip() for name in (candidate_variables or []) if (name or "").strip()]

    lines = [
        "You are a code audit assistant. Please identify the source of all candidate variables that appear in the conditions of if, else if, and switch statements in the following code, and classify them.",
        "There are 10 categories in total: POST, GET, COOKIE, SESSION, Headers, SERVER, ENV, FILE, SQL, CACHE.",
        source_line,
        "You do not need to distinguish which code block a variable comes from. Variables with the same name across different code blocks can be treated as the same variable.",
        "Below, the deduplicated merged 'environment variables for this execution' and 'inputs for this execution' are provided as reference only, to help determine variable sources. Do not treat these reference fields themselves as results to be counted.",
        "The reference input section only contains parameter keys or environment variable names, not parameter values. You may only use these key names as auxiliary clues; do not make judgments based on non-existent parameter values.",
        "A list of candidate variables extracted locally is also provided below. You must classify only these candidate variables. Do not add new candidate variables, and do not omit any.",
        "Only focus on variables that appear inside the parentheses of if, else if, and switch conditions. Do not count values outside parentheses, nor variables in case, else, ordinary assignments, or other non-condition positions.",
        "All candidate variables must be classified according to their system-external sources. No candidate variable may be omitted.",
        "The inputs for this execution are provided only as a reference for determining sources. The inputs contain only parameter keys, not parameter values.",
        "CACHE refers only to variables whose values come directly from an external caching system or external caching medium, such as Redis, Memcached, external KV, shared cache, or persistent cache files.",
        "Do not classify a variable as CACHE merely because its variable name, object name, function name, or field name contains words like cache, cached, or caching. Internal program cache variables, cache objects, cache results, and cache fields are not external sources.",
        "If a variable is merely an internal program cache of raw external input, database results, or server variables, you must trace it back to its true external source. For example, a cached SQL query result should be classified as SQL, not CACHE.",
        "Prioritize determining variable sources based on the given code. Only when the code is insufficient for direct determination may you use engineering prior knowledge and your understanding of the target application to make reasonable guesses. However, the guess must still target the true system-external source, not internal program intermediate naming.",
        "",
    ]
    if merged_reference:
        lines.append("Merged execution reference:")
        lines.extend(merged_reference)
        lines.append("")
    if merged_candidates:
        lines.append("Candidate variable list (only variables from this list may be selected and classified):")
        lines.append(json.dumps(merged_candidates, ensure_ascii=False))
        lines.append("")
    if merged_context:
        lines.append("Code context (each line: seq | path:line | code):")
        lines.extend(merged_context)
    lines.extend(
        [
            "",
            "Output only the classification results for each candidate variable, one by one.",
            "Each candidate variable must appear exactly once. The candidate field must be taken directly from the provided candidate variable list, and all variables in the list must appear. The category must be one of the 10 categories.",
            "The return format must strictly conform to the following JSON structure.",
            "Output only JSON. Do not output any explanatory text or Markdown.",
            "Please output a JSON file. Example:",
            "{",
            '  "schema": "external_input_source_labels.v1",',
            '  "labels": [',
            '    {"candidate": "$requestId", "category": "GET"},',
            '    {"candidate": "$submitFlag", "category": "POST"},',
            '    {"candidate": "$requestHost", "category": "Headers"},',
            '    {"candidate": "$dbRow", "category": "SQL"}',
            "  ]",
            "}",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _try_load_json(text: str):
    if not isinstance(text, str):
        return None
    raw = text.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def extract_json_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    raw = text.strip()
    if not raw:
        return ""

    if _try_load_json(raw) is not None:
        return raw

    fenced = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", raw, flags=re.IGNORECASE)
    if fenced:
        inner = (fenced.group(1) or "").strip()
        if _try_load_json(inner) is not None:
            return inner

    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        candidate = raw[start : end + 1]
        if _try_load_json(candidate) is not None:
            return candidate

    return ""


def parse_source_label_response(text: str) -> Optional[List[Dict[str, str]]]:
    obj = _try_load_json(text)
    if obj is None:
        obj = _try_load_json(extract_json_text(text))
    if not isinstance(obj, dict):
        return None

    labels = obj.get("labels")
    if not isinstance(labels, list):
        return None

    normalized = []
    seen = set()
    for item in labels:
        if not isinstance(item, dict):
            return None
        candidate = (item.get("candidate") or "").strip()
        category = (item.get("category") or "").strip()
        if not candidate or category not in CATEGORIES:
            return None
        key = candidate.lower()
        if key in seen:
            return None
        seen.add(key)
        normalized.append({"candidate": candidate, "category": category})

    if not normalized:
        return None
    return normalized


def source_label_response_has_valid_json(text: str) -> bool:
    return parse_source_label_response(text) is not None


def merge_counts(total: Dict[str, int], partial: Dict[str, int]) -> Dict[str, int]:
    out = {}
    total = total or {}
    partial = partial or {}
    for category in CATEGORIES:
        out[category] = int(total.get(category, 0)) + int(partial.get(category, 0))
    return out
