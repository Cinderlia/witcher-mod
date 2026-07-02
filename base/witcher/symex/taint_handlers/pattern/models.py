try:
    from dataclasses import dataclass, field
except Exception:
    from compat_dataclasses import dataclass, field
from typing import List


@dataclass
class PatternRelation:
    seq: int
    kind: str
    taints: List[dict] = field(default_factory=list)
    detail: dict = field(default_factory=dict)
