"""
Local test helpers for simulating LLM responses and persisting prompt/response artifacts.
"""

import json
import os
import sys
from typing import Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger

from ..prompt.llm_response import build_test_response_from_prompts


def write_prompt_text(out_dir: str, name: str, text: str, logger: Optional[Logger] = None) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    if logger is not None:
        logger.info("prompt_written", path=path, chars=len(text or ""))
    return path


def write_response_json(out_dir: str, name: str, payload, logger: Optional[Logger] = None) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    if logger is not None:
        logger.info("response_written", path=path)
    return path


def simulate_response(prompt_items, *, pick_count: int = 5, logger: Optional[Logger] = None):
    return build_test_response_from_prompts(prompt_items, pick_count=pick_count, logger=logger)
