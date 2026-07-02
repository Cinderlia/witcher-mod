"""
Taint handler for `AST_CALL` nodes.

This delegates to the shared call-like processing used by method calls, while
keeping debug bookkeeping isolated from `AST_METHOD_CALL`.
"""

import os

from . import ast_method_call
from ..expr.ast_var import record_taint_source


def process(taint, ctx):
    """Expand a call taint by analyzing its call edges and relevant arguments."""
    call_id = taint.get('id')
    if call_id is None:
        return []
    record_taint_source(taint, ctx)

    calls_edges = ctx.get('calls_edges_union')
    if calls_edges is None:
        calls_edges = ast_method_call.read_calls_edges(os.getcwd())
        ctx['calls_edges_union'] = calls_edges
    if not (calls_edges.get(call_id) or []):
        return []

    dbg_ctx = ctx.get('debug')
    backup = None
    swapped = False
    if isinstance(dbg_ctx, dict):
        backup = dbg_ctx.get('ast_method_call')
        dbg_ctx['ast_method_call'] = dbg_ctx.setdefault('ast_call', [])
        swapped = True
    try:
        return ast_method_call.process_call_like(taint, ctx, debug_key='ast_call')
    finally:
        if swapped and isinstance(dbg_ctx, dict):
            if backup is None:
                dbg_ctx.pop('ast_method_call', None)
            else:
                dbg_ctx['ast_method_call'] = backup
