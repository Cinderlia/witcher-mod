from typing import Iterable, List, Set, TypeVar

T = TypeVar("T")


def dedupe_preserve_order(items: Iterable[T]) -> List[T]:
    seen: Set[T] = set()
    out: List[T] = []
    for it in items:
        if it in seen:
            continue
        seen.add(it)
        out.append(it)
    return out
