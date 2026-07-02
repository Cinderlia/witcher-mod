"""
Rule-based taint handler registry.

Each handler takes a taint dict and a shared context dict and extends the
`result_set`/queue according to its node type semantics.
"""

from .handlers.expr import ast_var
from .handlers.expr import ast_prop
from .handlers.expr import ast_dim
from .handlers.call import ast_method_call
from .handlers.call import ast_call
from .handlers.call import ast_static_call

REGISTRY = {
    'AST_VAR': ast_var.process,
    'AST_PROP': ast_prop.process,
    'AST_DIM': ast_dim.process,
    'AST_METHOD_CALL': ast_method_call.process,
    'AST_CALL': ast_call.process,
    'AST_STATIC_CALL': ast_static_call.process
}
