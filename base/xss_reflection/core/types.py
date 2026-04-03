from typing import List, Optional, NamedTuple


class SeedInput(NamedTuple):
    raw: bytes
    cookies: str
    query: str
    post: str
    headers: str


class Param(NamedTuple):
    location: str
    key: str
    value: str
    index: int


class Payload(NamedTuple):
    token: str
    value: str
    kind: str


class ExecutionResult(NamedTuple):
    seed: bytes
    response_text: str
    status_code: Optional[int]
    error: Optional[str]
    duration_ms: Optional[float]


class ReflectionFinding(NamedTuple):
    token: str
    positions: List[int]
    context_snippets: List[str]


class ContextSnippet(NamedTuple):
    text: str
    start: int
    end: int
    context_type: str


class RiskDecision(NamedTuple):
    is_vulnerable: bool
    reason: str


class XSSFinding(NamedTuple):
    param: Param
    payload: Payload
    context: ContextSnippet
    decision: RiskDecision
    evidence: str
