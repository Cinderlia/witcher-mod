import os
from pathlib import Path
from typing import Optional, Tuple


try:
    from .datastructures.php_tree import PhpFileTree
except Exception:
    try:
        from helpers.initial_url.datastructures.php_tree import PhpFileTree
    except Exception:
        try:
            from initial_url.datastructures.php_tree import PhpFileTree
        except Exception:
            from datastructures.php_tree import PhpFileTree


def build_php_tree(source_dir: str) -> "PhpFileTree":
    source_root = Path(source_dir)
    tree = PhpFileTree(source_root)
    tree.build()
    return tree


def leaf_relpaths(tree: "PhpFileTree") -> list:
    out = []
    for leaf in tree.leaves:
        try:
            out.append(tree.rel_posix_path(leaf))
        except Exception:
            if getattr(leaf, "abs_path", None) is not None:
                out.append(str(leaf.abs_path))
    return out

