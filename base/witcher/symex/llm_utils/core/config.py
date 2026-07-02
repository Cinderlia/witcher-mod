"""Load LLM runtime configuration from file and environment variables."""

import json
import os
try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class LLMConfig:
    """Immutable configuration for an LLM HTTP client."""
    base_url: str
    api_key: str
    model: str
    temperature: float = 0.0
    timeout_s: float = 60.0
    max_tokens: Optional[int] = None
    max_retries: int = 3


def _norm_base_url(base_url: str) -> str:
    """Normalize a base URL to a stable form (no trailing '/')."""
    u = (base_url or '').strip()
    if not u:
        return u
    return u.rstrip('/')


def load_llm_config(config_path: Optional[str] = None) -> LLMConfig:
    """
    Load LLM config from JSON file and environment variables.

    Precedence:
    - explicit `config_path`
    - `JOERNTRACE_LLM_CONFIG`
    - `llm_config.json` next to this module
    - environment overrides: `OPENAI_*` or `JOERNTRACE_LLM_*`
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cfg_path = (
        config_path
        or os.environ.get('JOERNTRACE_LLM_CONFIG')
        or os.path.join(base_dir, 'llm_config.json')
    )
    if not os.path.exists(cfg_path):
        alt_path = os.path.join(os.path.dirname(base_dir), 'llm_config.json')
        if os.path.exists(alt_path):
            cfg_path = alt_path

    obj: Dict[str, Any] = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, 'r', encoding='utf-8', errors='replace') as f:
            loaded = json.load(f)
            if isinstance(loaded, dict):
                obj = loaded

    env_base_url = os.environ.get('OPENAI_BASE_URL') or os.environ.get('JOERNTRACE_LLM_BASE_URL')
    env_api_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('JOERNTRACE_LLM_API_KEY')
    env_model = os.environ.get('OPENAI_MODEL') or os.environ.get('JOERNTRACE_LLM_MODEL')

    base_url = _norm_base_url(str(env_base_url or obj.get('base_url') or '').strip())
    api_key = str(env_api_key or obj.get('api_key') or '').strip()
    model = str(env_model or obj.get('model') or '').strip()

    temperature = obj.get('temperature')
    timeout_s = obj.get('timeout_s')
    max_tokens = obj.get('max_tokens')
    max_retries = obj.get('max_retries')

    temperature_f = float(temperature) if temperature is not None else 0.0
    timeout_f = float(timeout_s) if timeout_s is not None else 60.0
    max_tokens_i = int(max_tokens) if max_tokens is not None else None
    max_retries_i = int(max_retries) if max_retries is not None else 3

    if not base_url:
        raise ValueError(f'missing base_url (config: {cfg_path})')
    if not api_key:
        raise ValueError(f'missing api_key (config: {cfg_path})')
    if not model:
        raise ValueError(f'missing model (config: {cfg_path})')

    return LLMConfig(
        base_url=base_url,
        api_key=api_key,
        model=model,
        temperature=temperature_f,
        timeout_s=timeout_f,
        max_tokens=max_tokens_i,
        max_retries=max_retries_i,
    )
