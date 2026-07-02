from taint_handlers.handlers.call import ast_method_call
from taint_handlers.llm.utils.llm_prop_scope import pick_innermost_scope
from typing import List


def expand_param_bridge_taints(item: dict, call_param_arg_info, prop_call_scopes_info) -> List[dict]:
    if not isinstance(item, dict):
        return []
    out = [dict(item)]
    seen = {_key(item)}
    for repl in _iter_param_arg_rewrites(item, call_param_arg_info, prop_call_scopes_info):
        if not isinstance(repl, dict):
            continue
        key = _key(repl)
        if key in seen:
            continue
        seen.add(key)
        bridged = dict(repl)
        bridged["_pattern_param_bridge"] = True
        out.append(bridged)
    return out


def bridge_current_param_to_args(current: dict, call_param_arg_info, prop_call_scopes_info) -> List[dict]:
    if not isinstance(current, dict):
        return []
    out = []
    for repl in _iter_param_arg_rewrites(current, call_param_arg_info, prop_call_scopes_info):
        if not isinstance(repl, dict):
            continue
        bridged = dict(repl)
        bridged["_pattern_param_bridge"] = True
        out.append(bridged)
    return out


def _iter_param_arg_rewrites(item: dict, call_param_arg_info, prop_call_scopes_info):
    if isinstance(call_param_arg_info, dict):
        repl, _ = ast_method_call.convert_param_based_taint_to_call_arg_taint(item, call_param_arg_info)
        if repl is not None:
            yield repl
    if isinstance(call_param_arg_info, list):
        for info in call_param_arg_info:
            if not isinstance(info, dict):
                continue
            repl, _ = ast_method_call.convert_param_based_taint_to_call_arg_taint(item, info)
            if repl is not None:
                yield repl
    if isinstance(prop_call_scopes_info, list):
        try:
            seq = int(item.get("seq"))
        except Exception:
            seq = None
        scope = pick_innermost_scope(prop_call_scopes_info, seq) if seq is not None else None
        scoped = scope.get("call_param_arg_info") if isinstance(scope, dict) else None
        if isinstance(scoped, dict):
            repl, _ = ast_method_call.convert_param_based_taint_to_call_arg_taint(item, scoped)
            if repl is not None:
                yield repl


def _key(item: dict) -> tuple:
    try:
        return (
            int(item.get("id")) if item.get("id") is not None else None,
            int(item.get("seq")) if item.get("seq") is not None else None,
            (item.get("type") or "").strip(),
            (item.get("name") or "").strip(),
        )
    except Exception:
        return (
            item.get("id"),
            item.get("seq"),
            item.get("type"),
            item.get("name"),
        )
