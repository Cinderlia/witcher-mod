"""Core data models for the standalone database exploration pipeline."""

try:
    from dataclasses import dataclass, field
except Exception:
    from compat_dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class PhaseName(object):
    """String constants for the four-round database exploration pipeline."""

    GOAL_ABSTRACTION = "goal_abstraction"
    SCHEMA_DISCOVERY = "schema_discovery"
    CANDIDATE_LOOKUP = "candidate_lookup"
    FINALIZE = "finalize"


@dataclass
class ExternalInputSnapshot:
    """Structured external inputs copied from symbolic_prompt or related callers."""

    env: Dict[str, str] = field(default_factory=dict)
    get: Dict[str, str] = field(default_factory=dict)
    post: Dict[str, str] = field(default_factory=dict)
    cookie: Dict[str, str] = field(default_factory=dict)
    session: Dict[str, Any] = field(default_factory=dict)
    raw_env_block: str = ""
    raw_get_block: str = ""
    raw_post_block: str = ""
    raw_cookie_block: str = ""
    raw_session_block: str = ""


@dataclass
class BranchSliceContext:
    """Bundle the branch slice, target location, and current external inputs."""

    target_seq: Optional[int] = None
    target_loc: str = ""
    code_slice: str = ""
    input_snapshot: ExternalInputSnapshot = field(default_factory=ExternalInputSnapshot)
    notes: List[str] = field(default_factory=list)


@dataclass
class SearchGoal:
    """Normalized goal abstraction emitted by the first LLM round."""

    summary: str = ""
    branch_effect: str = ""
    db_reason: str = ""
    relevant_symbols: List[str] = field(default_factory=list)
    relevant_inputs: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    context_strategy: str = "keep_selected_context"
    retained_code_lines: List[str] = field(default_factory=list)
    retained_inputs: Dict[str, Any] = field(default_factory=dict)
    schema_goal: str = ""
    candidate_goal: str = ""
    finalize_goal: str = ""
    db_information_needs: List[str] = field(default_factory=list)
    db_mutation_targets: List[str] = field(default_factory=list)
    code_seen_tables: List[str] = field(default_factory=list)
    code_seen_columns: List[str] = field(default_factory=list)
    inferred_tables: List[str] = field(default_factory=list)
    inferred_columns: List[str] = field(default_factory=list)
    schema_stop_conditions: List[str] = field(default_factory=list)
    candidate_stop_conditions: List[str] = field(default_factory=list)
    finalize_stop_conditions: List[str] = field(default_factory=list)
    abstraction_warnings: List[str] = field(default_factory=list)


@dataclass
class DBQueryPlan:
    """Single SQL action proposed by the LLM for one phase round."""

    sql: str = ""
    purpose: str = ""
    phase: str = ""
    allow_write: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DBQueryExecution:
    """Audit and execution result for one SQL action."""

    plan: DBQueryPlan = field(default_factory=DBQueryPlan)
    raw_result: Dict[str, Any] = field(default_factory=dict)
    allowed: bool = False
    audit_message: str = ""


@dataclass
class FilteredQueryPayload:
    """Compressed database result forwarded into later prompts."""

    phase: str = ""
    overall_goal: str = ""
    goal: str = ""
    query_result_pairs: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PhaseOutcome:
    """Structured phase decision parsed from one LLM response."""

    phase: str = ""
    completed: bool = False
    request_schema_fallback: bool = False
    rationale: str = ""
    findings: List[str] = field(default_factory=list)
    query_plans: List[DBQueryPlan] = field(default_factory=list)
    output_solutions: List[Dict[str, Any]] = field(default_factory=list)
    output_patch: Dict[str, Any] = field(default_factory=dict)
    db_actions: List[DBQueryPlan] = field(default_factory=list)


@dataclass
class RoundTrace:
    """Trace data captured for one LLM round inside one phase."""

    phase: str = ""
    round_index: int = 0
    prompt_text: str = ""
    llm_response_text: str = ""
    executions: List[DBQueryExecution] = field(default_factory=list)
    filtered_payloads: List[FilteredQueryPayload] = field(default_factory=list)


@dataclass
class DBSearchRequest:
    """Top-level request for the standalone database exploration pipeline."""

    context: BranchSliceContext = field(default_factory=BranchSliceContext)
    config_path: Optional[str] = None
    run_dir: str = ""
    source_component: str = "symbolic_prompt"
    trigger_reason: str = ""
    symbolic_objective: str = ""
    db_request_mode: str = ""
    db_request_goal: str = ""
    db_request_reason: str = ""
    db_request_focus: List[str] = field(default_factory=list)


@dataclass
class DBSearchState:
    """Mutable pipeline state shared across all four rounds."""

    current_phase: str = PhaseName.GOAL_ABSTRACTION
    context: BranchSliceContext = field(default_factory=BranchSliceContext)
    run_dir: str = ""
    goal: SearchGoal = field(default_factory=SearchGoal)
    schema_round_limit: int = 0
    candidate_schema_fallback_limit: int = 0
    schema_rounds: int = 0
    candidate_rounds: int = 0
    finalize_rounds: int = 0
    schema_identified: bool = False
    candidate_found: bool = False
    candidate_impossible: bool = False
    output_ready: bool = False
    fallback_to_schema_used: bool = False
    schema_findings: List[str] = field(default_factory=list)
    round_traces: List[RoundTrace] = field(default_factory=list)
    filtered_memory: List[FilteredQueryPayload] = field(default_factory=list)
    schema_raw_pairs: List[Dict[str, Any]] = field(default_factory=list)
    candidate_raw_pairs: List[Dict[str, Any]] = field(default_factory=list)
    finalize_context_payloads: List[FilteredQueryPayload] = field(default_factory=list)
    final_output: Dict[str, Any] = field(default_factory=dict)
    sql_log_paths: List[str] = field(default_factory=list)
    todo_notes: List[str] = field(default_factory=list)
    fatal_error: str = ""
    fatal_error_detail: Dict[str, Any] = field(default_factory=dict)
