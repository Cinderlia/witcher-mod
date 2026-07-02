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
        source_line = "以下代码来自" + app_label
    else:
        source_line = "以下代码来自一个待分析的应用"

    merged_reference = [(line or "").rstrip() for line in (reference_lines or [])]
    merged_reference = [line for line in merged_reference if line is not None]
    merged_context = [(line or "").rstrip() for line in (context_lines or []) if (line or "").strip()]
    merged_candidates = [(name or "").strip() for name in (candidate_variables or []) if (name or "").strip()]

    lines = [
        "你是一个代码审计助手，请你识别以下代码中，所有if、else if、switch语句条件里的候选变量来源，并将它们进行分类。",
        "类别一共10种：POST、GET、COOKIE、SESSION、Headers、SERVER、ENV、FILE、SQL、CACHE。",
        source_line,
        "你不需要区分变量来自哪个代码块，可以把跨代码块的同名变量视作同一个变量。",
        "下面会先给出合并去重后的“本次执行的环境变量”和“本次执行的输入”，它们仅作为参考信息，用于帮助判断变量来源，不能把这些参考字段本身直接当作需要统计的结果。",
        "参考输入区里只保留参数键或环境变量名，不包含参数值；你只能把这些键名当作辅助线索，不能根据不存在的参数值做判断。",
        "下面还会给出本地抽取出的候选变量列表；你必须只对这些候选变量做分类，不要新增候选变量，也不要遗漏候选变量。",
        "只关注if、else if、switch的条件括号内出现的变量，不统计括号外的值，也不统计case、else、普通赋值或其他非条件位置的变量。",
        "所有候选变量都必须根据系统外部来源进行分类，候选变量一个都不能遗漏。",
        "本次执行的输入仅作为参考，供你判断来源使用；输入里只有参数键，没有参数值。",
        "CACHE 只表示变量的值直接来自外部缓存系统或外部缓存介质，例如 Redis、Memcached、外部 KV、共享缓存或持久化缓存文件。",
        "不要因为变量名、对象名、函数名或字段名里包含 cache、cached、caching 等字样，就把它判成 CACHE；程序内部的缓存变量、缓存对象、缓存结果、缓存字段都不是外部来源。",
        "如果一个变量只是程序内部缓存了原始外部输入、数据库结果或服务器变量，你必须继续追溯其真正的外部来源；例如缓存的 SQL 查询结果优先判为 SQL，而不是 CACHE。",
        "优先根据所给出的代码判断变量来源；当代码不足以直接判断时，才允许使用工程先验知识和你对目标应用的了解进行合理猜测，但猜测的目标仍然必须是真正的系统外部来源，而不是程序内部中间层命名。",
        "",
    ]
    if merged_reference:
        lines.append("合并后的执行参考：")
        lines.extend(merged_reference)
        lines.append("")
    if merged_candidates:
        lines.append("候选变量列表（只允许从这个列表里选择并分类）：")
        lines.append(json.dumps(merged_candidates, ensure_ascii=False))
        lines.append("")
    if merged_context:
        lines.append("代码上下文（每行：seq | path:line | code）：")
        lines.extend(merged_context)
    lines.extend(
        [
            "",
            "只需要逐个输出候选变量的分类结果。",
            "每个候选变量必须且只能出现一次，candidate 必须直接取自给定的候选变量列表，且列表中的所有变量必须全部出现，category 必须是 10 个类别之一。",
            "返回格式必须严格满足以下JSON结构。",
            "只输出JSON，不要输出任何解释性文字或Markdown。",
            "请输出一个JSON文件，示例：",
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
