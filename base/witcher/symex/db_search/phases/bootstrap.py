"""First-round goal abstraction phase for the standalone database exploration flow."""

from urllib.parse import parse_qsl

from ..llm_gateway import build_goal_abstraction_prompt, parse_goal_response, run_text_llm_call
from ..models import BranchSliceContext, DBSearchRequest, DBSearchState, ExternalInputSnapshot, PhaseName, RoundTrace


def _parse_env_block(env_block: str):
    out = {}
    for raw in (str(env_block or "").splitlines() or []):
        line = (raw or "").strip()
        if not line:
            continue
        if line.lower().startswith("export "):
            line = (line[len("export "):] or "").strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key_s = (key or "").strip()
        if not key_s:
            continue
        out[key_s] = (value or "").strip()
    return out


def _parse_query_text(text: str):
    out = {}
    s = str(text or "").strip()
    if not s:
        return out
    if ";" in s and "&" not in s:
        s = s.replace(";", "&")
    try:
        for key, value in parse_qsl(s, keep_blank_values=True):
            key_s = str(key).strip()
            if not key_s:
                continue
            out[key_s] = str(value)
    except Exception:
        return out
    return out


def build_external_input_snapshot(
    *,
    env_block: str = "",
    get_block: str = "",
    post_block: str = "",
    cookie_block: str = "",
    session_data=None,
    session_block: str = "",
) -> ExternalInputSnapshot:
    """Build a structured input snapshot from symbolic_prompt-style raw blocks."""
    session_obj = session_data if isinstance(session_data, dict) else {}
    return ExternalInputSnapshot(
        env=_parse_env_block(env_block),
        get=_parse_query_text(get_block),
        post=_parse_query_text(post_block),
        cookie=_parse_query_text(cookie_block),
        session=session_obj,
        raw_env_block=str(env_block or "").strip(),
        raw_get_block=str(get_block or "").strip(),
        raw_post_block=str(post_block or "").strip(),
        raw_cookie_block=str(cookie_block or "").strip(),
        raw_session_block=str(session_block or "").strip(),
    )


def build_db_search_request_from_symbolic_prompt(
    *,
    target_seq=None,
    target_loc: str = "",
    code_slice: str = "",
    env_block: str = "",
    get_block: str = "",
    post_block: str = "",
    cookie_block: str = "",
    session_data=None,
    session_block: str = "",
    trigger_reason: str = "",
    symbolic_objective: str = "",
    db_request_mode: str = "",
    db_request_goal: str = "",
    db_request_reason: str = "",
    db_request_focus=None,
    notes=None,
    config_path=None,
    run_dir: str = "",
) -> DBSearchRequest:
    """Build the standalone DB-search request from symbolic_prompt source data."""
    snapshot = build_external_input_snapshot(
        env_block=env_block,
        get_block=get_block,
        post_block=post_block,
        cookie_block=cookie_block,
        session_data=session_data,
        session_block=session_block,
    )
    context = BranchSliceContext(
        target_seq=target_seq,
        target_loc=str(target_loc or ""),
        code_slice=str(code_slice or ""),
        input_snapshot=snapshot,
        notes=[str(x) for x in (notes or []) if str(x).strip()],
    )
    return DBSearchRequest(
        context=context,
        config_path=config_path,
        run_dir=str(run_dir or ""),
        source_component="symbolic_prompt",
        trigger_reason=str(trigger_reason or ""),
        symbolic_objective=str(symbolic_objective or ""),
        db_request_mode=str(db_request_mode or ""),
        db_request_goal=str(db_request_goal or ""),
        db_request_reason=str(db_request_reason or ""),
        db_request_focus=[str(x).strip() for x in (db_request_focus or []) if str(x).strip()],
    )


def run_goal_abstraction_phase(request: DBSearchRequest, state: DBSearchState) -> DBSearchState:
    """Run the single non-retriable LLM round that abstracts code and inputs into a DB goal."""
    prompt_text = build_goal_abstraction_prompt(request, state)
    response_text = run_text_llm_call(
        prompt_text,
        run_dir=state.run_dir,
        phase=PhaseName.GOAL_ABSTRACTION,
        round_index=1,
        role="goal_abstraction",
    )
    state.goal = parse_goal_response(response_text)
    state.round_traces.append(
        RoundTrace(
            phase=PhaseName.GOAL_ABSTRACTION,
            round_index=1,
            prompt_text=prompt_text,
            llm_response_text=response_text,
        )
    )
    state.current_phase = PhaseName.SCHEMA_DISCOVERY
    return state
