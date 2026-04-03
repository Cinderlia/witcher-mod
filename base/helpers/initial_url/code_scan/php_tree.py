try:
    from ..datastructures.php_tree import PhpFileTree, PhpTreeNode
except Exception:
    try:
        from helpers.initial_url.datastructures.php_tree import PhpFileTree, PhpTreeNode
    except Exception:
        try:
            from initial_url.datastructures.php_tree import PhpFileTree, PhpTreeNode
        except Exception:
            from datastructures.php_tree import PhpFileTree, PhpTreeNode

__all__ = ["PhpFileTree", "PhpTreeNode"]
