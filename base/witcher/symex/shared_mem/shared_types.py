try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class SharedMemorySettings:
    enabled: bool
    mode: str
    require_linux: bool
    fallback_legacy: bool
    fail_fast_on_content_error: bool


@dataclass(frozen=True)
class TraceContextData:
    trace_path: str
    trace_locator: str
    trace_index_path: str
    trace_index_records: List[dict]
    seq_to_index: Dict[int, int]


@dataclass(frozen=True)
class AstContextData:
    nodes_path: str
    rels_path: str
    nodes: Dict[int, dict]
    top_id_to_file: Dict[int, str]
    parent_of: Dict[int, int]
    children_of: Dict[int, List[int]]


@dataclass(frozen=True)
class AnalyzeInputBundle:
    seq: int
    provider_name: str
    provider_mode: str
    settings: SharedMemorySettings
    ast: AstContextData
    trace: TraceContextData
