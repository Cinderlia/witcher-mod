"""Thin wrapper taint handler for `AST_DIM` nodes (array/index access)."""

from . import ast_var


def process(taint, ctx):
    """Delegate `AST_DIM` handling to variable-style backward scope only."""
    return ast_var.process(taint, ctx)
