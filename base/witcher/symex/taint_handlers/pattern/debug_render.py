from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
from typing import List


def render_scope_sources(locs: list, ctx: dict) -> List[dict]:
    if not isinstance(ctx, dict):
        return []
    scope_root = ctx.get("scope_root") or "/app"
    trace_index_path = ctx.get("trace_index_path") or "tmp/trace_index.json"
    windows_root = ctx.get("windows_root") or r"D:\files\witcher\app"
    out = []
    seen = set()
    for item in map_result_set_to_source_lines(
        scope_root,
        locs or [],
        trace_index_path=trace_index_path,
        windows_root=windows_root,
    ):
        if not isinstance(item, dict):
            continue
        key = (
            int(item.get("seq")) if item.get("seq") is not None else None,
            (item.get("code") or "").rstrip(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "seq": item.get("seq"),
                "code": (item.get("code") or "").rstrip(),
            }
        )
    return out


def render_scope_block(lines: List[dict]) -> str:
    out = []
    for item in lines or []:
        if not isinstance(item, dict):
            continue
        seq = item.get("seq")
        code = (item.get("code") or "").rstrip()
        if seq is None:
            out.append(code)
            continue
        try:
            out.append(f"{int(seq)} {code}".rstrip())
        except Exception:
            out.append(code)
    return "\n".join(out)
