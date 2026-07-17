import os
import sys
from typing import Dict, Iterable, List, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.app_config import append_app_name_to_prompt, load_symex_app_config
from common.logger import Logger

BASE_PROMPT = """You are a penetration testing expert specializing in attack surface analysis, tasked with identifying all possible cross-site scripting injection points.
Your goal is to discover as many potential XSS injection points as possible.


Guiding principle: It is better to make a false positive than to miss a potentially XSS injection point.

Explicit rules:
1. [MUST SELECT] If the variable in the XSS statement may originate directly or indirectly from user input (GET, POST, COOKIE, HTTP headers, etc.)
2. [MUST SELECT] If the variable in the XSS statement may originate from environment variables (e.g., getenv).
3. [MUST SELECT] If the variable in the XSS statement may originate from SESSION file storage.
4. [MUST SELECT] If the variable in the XSS statement may originate from database query results.
5. [MUST SELECT] If the variable in the XSS statement may originate from user-uploaded files or read file paths controlled by the user.
6. [DO NOT SELECT] If the variable most likely originates from local files or hardcoded configuration.
7. [DO NOT SELECT] If the variable most likely originates from database connection (excluding query results).
8. [DO NOT SELECT] If the variable is a system environment check (PHP version, SQL version, system version, etc.) or a server environment check (e.g., Apache, Nginx, etc.).
9. [DO NOT SELECT] If the variable is a local file existence check.
10. [DO NOT SELECT] If the variable is a database connection test or component functionality verification.
11. [DO NOT SELECT] If the variable is a constant definition.
12. [DO NOT SELECT] If the variable is an environment variable definition.
13. [DO NOT SELECT] If the variable is a class, function, or method definition.
14. [SHOULD SELECT] For variables that are uncertain about their source, prioritize whether they might originate from GET, POST, COOKIE, SESSION, environment variables, database query results, or user-controllable files.
15. [SHOULD SELECT] If the variable name or usage pattern suggests it may be user input (e.g., $input, $param, $data), select the XSS statement.
16. [SHOULD SELECT] For business data variables, it is generally assumed that they may originate from user input.

If the explicit rules do not cover all possible scenarios, please select any XSS statement that is likely to be influenced by external inputs.


Output Format:
Only output a JSON array containing the numbers of the selected XSS statements. If no XSS statement is selected, return an empty array.
Example: [123, 456, 789]
Do not output any other content. """


def build_prompt(*, sections: Iterable[dict], separator: str, base_prompt: Optional[str] = None, logger: Optional[Logger] = None) -> str:
    chunks = []
    count = 0
    prompt_text = (base_prompt or "").strip()
    if not prompt_text:
        prompt_text = BASE_PROMPT.strip()
    try:
        prompt_text = append_app_name_to_prompt(prompt_text, load_symex_app_config())
    except Exception:
        prompt_text = append_app_name_to_prompt(prompt_text, {})
    chunks.append(prompt_text)
    for sec in sections or []:
        seq = sec.get("seq")
        code = sec.get("code") or ""
        if seq is None:
            continue
        body = f"{code}".rstrip()
        chunks.append(body)
        count += 1
    out = f"\n{separator}\n".join(chunks)
    if logger is not None:
        logger.debug("prompt_built", sections=count, chars=len(out))
    return out


def format_section(seq: int, lines: List[Dict], mark_seqs: Optional[Iterable[int]] = None, logger: Optional[Logger] = None) -> Dict:
    code_lines = []
    mark_set = set()
    for ms in mark_seqs or []:
        try:
            mark_set.add(int(ms))
        except Exception:
            continue
    if not mark_set:
        try:
            mark_set.add(int(seq))
        except Exception:
            pass
    grouped_keys = []
    best_by_key = {}
    for it in lines or []:
        if not isinstance(it, dict):
            continue
        p = it.get("path")
        ln = it.get("line")
        if p and ln is not None:
            key = (str(p), int(ln))
        else:
            key = ("__code__", (it.get("code") or "").strip())
        if key not in best_by_key:
            best_by_key[key] = it
            grouped_keys.append(key)
            continue
        try:
            si = int(it.get("seq")) if it.get("seq") is not None else None
        except Exception:
            si = None
        if si is not None and (int(si) == int(seq) or int(si) in mark_set):
            best_by_key[key] = it
    for key in grouped_keys:
        it = best_by_key.get(key)
        if not isinstance(it, dict):
            continue
        s = it.get("seq")
        code = (it.get("code") or "").strip()
        if s is None:
            continue
        try:
            si = int(s)
        except Exception:
            continue
        if int(si) in mark_set:
            code_lines.append(f"{int(si)} {code}".rstrip())
        else:
            code_lines.append(f"{code}".rstrip())
    marked = []
    marked_seen = set()
    for line in code_lines:
        if not line:
            continue
        head = line.split(" ", 1)[0].strip()
        try:
            si = int(head)
        except Exception:
            continue
        if si in mark_set and si not in marked_seen:
            marked_seen.add(si)
            marked.append(int(si))
    out = {"seq": int(seq), "code": "\n".join(code_lines), "mark_seqs": marked}
    if logger is not None:
        logger.debug("section_formatted", seq=int(seq), lines=len(code_lines))
    return out
