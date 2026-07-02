import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence


class PhpTreeNode(object):
    __slots__ = ("name", "parent", "children", "abs_path", "selected")

    def __init__(
        self,
        name: str,
        parent: Optional["PhpTreeNode"] = None,
        children: Optional[Dict[str, "PhpTreeNode"]] = None,
        abs_path: Optional[Path] = None,
    ) -> None:
        self.name = name
        self.parent = parent
        self.children = children if children is not None else {}
        self.abs_path = abs_path
        self.selected = False

    def is_leaf(self) -> bool:
        return self.abs_path is not None

    def ancestors(self):  # type: () -> Iterable["PhpTreeNode"]
        cur = self.parent
        while cur is not None:
            yield cur
            cur = cur.parent

    def rel_parts(self):  # type: () -> List[str]
        parts = []  # type: List[str]
        cur = self  # type: Optional["PhpTreeNode"]
        while cur is not None and cur.parent is not None:
            parts.append(cur.name)
            cur = cur.parent
        parts.reverse()
        return parts


class PhpFileTree:
    def __init__(self, source_root: Path) -> None:
        self.source_root = source_root
        self.root = PhpTreeNode(name="")
        self._leaves = []  # type: List[PhpTreeNode]

    @property
    def leaves(self) -> Sequence[PhpTreeNode]:
        return self._leaves

    def build(self) -> None:
        self.root = PhpTreeNode(name="")
        self._leaves = []

        for abs_file in self._iter_php_files(self.source_root):
            rel = abs_file.relative_to(self.source_root)
            rel_parts = [p for p in rel.parts if p and p not in (".",)]
            self._add_rel_path(rel_parts, abs_file)

    def _add_rel_path(self, rel_parts: List[str], abs_file: Path) -> None:
        cur = self.root
        for part in rel_parts:
            nxt = cur.children.get(part)
            if nxt is None:
                nxt = PhpTreeNode(name=part, parent=cur)
                cur.children[part] = nxt
            cur = nxt
        cur.abs_path = abs_file
        cur.selected = False
        self._leaves.append(cur)

    def rel_posix_path(self, leaf: PhpTreeNode) -> str:
        return "/".join(leaf.rel_parts())

    def match_fragment(self, fragment_path: str) -> List[PhpTreeNode]:
        path_str = fragment_path.replace("\\", "/").strip()
        while path_str.startswith("./"):
            path_str = path_str[2:]
        path_str = path_str.lstrip("/")
        if not path_str:
            return []

        parts = [p for p in path_str.split("/") if p and p not in (".",)]
        if not parts:
            return []
        filename = parts[-1]
        dir_parts = parts[:-1]

        matches = []  # type: List[PhpTreeNode]
        fn_lower = filename.lower()
        for leaf in self._leaves:
            if leaf.name.lower() != fn_lower:
                continue
            if self._match_dir_suffix(leaf, dir_parts):
                matches.append(leaf)
        return matches

    def _match_dir_suffix(self, leaf: PhpTreeNode, dir_parts: List[str]) -> bool:
        if not dir_parts:
            return True
        parts_rev = list(reversed([p for p in dir_parts if p and p not in (".",)]))
        anc = leaf.parent
        for expected in parts_rev:
            if anc is None:
                return False
            if anc.name.lower() != expected.lower():
                return False
            anc = anc.parent
        return True

    def _iter_php_files(self, root: Path) -> Iterable[Path]:
        if not root.exists():
            return
        skip_dirnames = {
            ".git",
            ".hg",
            ".svn",
            ".idea",
            ".vscode",
            "__pycache__",
            "node_modules",
            "vendor",
            "bower_components",
            "third_party",
            "third-party",
            "thirdparty",
            "external",
            "externals",
            "deps",
            "dep",
            "dist",
            "build",
            "out",
            "target",
            "coverage",
            "docs",
            "doc",
            "tmp",
            "temp",
            "cache",
            "logs",
            "log",
            "runtime",
            "storage",
        }
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in skip_dirnames]
            for fn in filenames:
                if not fn.lower().endswith(".php"):
                    continue
                yield Path(dirpath) / fn
