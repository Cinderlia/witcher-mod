import os
import sys
from typing import Dict, Iterable, List, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.app_config import append_app_name_to_prompt, load_symex_app_config
from common.logger import Logger

BASE_PROMPT = """你是一个专注于攻击面分析的渗透测试专家，正在寻找所有可能由用户控制的SQL语句。
你的目标是最大化符号执行的覆盖范围，尽可能多地发现潜在的SQL注入点。

核心指导思想：宁可选错，也不要放过任何一个有可能的SQL注入点。

明确规则：
1. 【必须选】如果SQL语句中的变量可能直接或间接来源于用户输入（GET、POST、COOKIE、HTTP头部等）
2. 【必须选】如果SQL语句中的变量可能来源于环境变量（如getenv）
3. 【必须选】如果SQL语句中的变量可能来源于SESSION文件存储
4. 【不要选】如果变量大概率来源于本地文件、硬编码配置
5. 【不要选】如果该语句只是长得像SQL语句，但是变量名或使用模式暗示可能不是用户输入
6. 【应该选】如果变量名或使用模式暗示可能是用户输入（如$input、$param、$data等），选择该SQL语句
7. 【应该选】对于处理业务数据的变量，倾向于认为可能来自用户输入

如果明确规则没有覆盖到的话，请选择可能被外部输入影响的SQL语句。

输出格式：
仅输出一个JSON数组，包含被选择SQL语句前面的编号。如果没有选择任何SQL语句，也需要返回一个合法的空数组。
示例：[123, 456, 789]
不要输出任何其他内容。"""


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
