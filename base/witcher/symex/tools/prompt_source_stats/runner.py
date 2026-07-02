"""Run the prompt-source counting workflow with multi-buffer LLM concurrency."""

import asyncio
import json
import os
try:
    from dataclasses import dataclass, field
except Exception:
    from compat_dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from llm_utils import get_default_client
from llm_utils.taint.taint_llm_calls import (
    LLMCallFailure,
    chat_text_with_retries,
    write_llm_failure_artifact,
)

from prompt_source_stats.candidates import BatchPromptData, normalize_candidate_name, prepare_batch_prompt
from prompt_source_stats.prompting import (
    CATEGORIES,
    build_count_prompt,
    merge_counts,
    parse_source_label_response,
)
from prompt_source_stats.scanner import PromptCodeBlock, extract_prompt_code_block, iter_prompt_paths


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, int(len(text) / 4))


def _write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text or "")


def _write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)


def _result_path(output_dir: str) -> str:
    return os.path.join(output_dir, "result.txt")


def _write_result_txt(output_dir: str, counts: Dict[str, int]) -> str:
    lines = []
    for category in CATEGORIES:
        lines.append("{0}\t{1}".format(category, int(counts.get(category, 0))))
    out_path = _result_path(output_dir)
    _write_text(out_path, "\n".join(lines) + "\n")
    return out_path


def _failure_response_text(failure: LLMCallFailure) -> str:
    details = getattr(failure, "details", None) or {}
    for key in ("response_text", "raw_response_text", "response_body"):
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            return value
    payload = details.get("response_payload")
    if payload is not None:
        try:
            return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        except Exception:
            return str(payload)
    return str(failure)


def _resolve_parsed_labels(
    labels: List[Dict[str, str]],
    candidate_lookup: Dict[str, str],
) -> Optional[Dict[str, str]]:
    resolved = {}
    for item in labels or []:
        raw_candidate = (item.get("candidate") or "").strip()
        raw_category = (item.get("category") or "").strip()
        lookup_key = normalize_candidate_name(raw_candidate)
        canonical = candidate_lookup.get(lookup_key) or candidate_lookup.get(raw_candidate) or ""
        canonical_key = normalize_candidate_name(canonical)
        if not canonical_key or raw_category not in CATEGORIES:
            return None
        if canonical_key in resolved and resolved[canonical_key] != raw_category:
            return None
        resolved[canonical_key] = raw_category
    return resolved


def _count_batch_matches(block_candidate_keys: List[set], candidate_categories: Dict[str, str]) -> Dict[str, int]:
    total = {category: 0 for category in CATEGORIES}
    for candidate_keys in block_candidate_keys or []:
        block_counts = {category: 0 for category in CATEGORIES}
        for candidate_key in candidate_keys:
            category = candidate_categories.get(candidate_key)
            if category in block_counts:
                block_counts[category] += 1
        total = merge_counts(total, block_counts)
    return total


def _labels_to_category_lists(candidate_categories: Dict[str, str], candidate_lookup: Dict[str, str]) -> Dict[str, List[str]]:
    out = {category: [] for category in CATEGORIES}
    seen = {category: set() for category in CATEGORIES}
    for alias_key, category in (candidate_categories or {}).items():
        canonical = candidate_lookup.get(alias_key) or ""
        canonical_key = normalize_candidate_name(canonical)
        if not canonical or category not in out or canonical_key in seen[category]:
            continue
        seen[category].add(canonical_key)
        out[category].append(canonical)
    return out


def _build_label_validator(expected_candidates: List[str], candidate_lookup: Dict[str, str]):
    expected_keys = set(normalize_candidate_name(name) for name in (expected_candidates or []) if normalize_candidate_name(name))

    def _validator(text: str) -> bool:
        labels = parse_source_label_response(text)
        if labels is None:
            return False
        resolved = _resolve_parsed_labels(labels, candidate_lookup)
        if resolved is None:
            return False
        return set(resolved.keys()) == expected_keys

    return _validator


@dataclass
class BufferSlot:
    token_limit: int
    blocks: List[PromptCodeBlock] = field(default_factory=list)

    def is_empty(self) -> bool:
        return len(self.blocks) == 0

    def add(self, block: PromptCodeBlock, block_text: str) -> None:
        self.blocks.append(block)

    def clear(self) -> None:
        self.blocks = []


class BufferPool:
    def __init__(self, *, buffer_count: int, token_limit: int):
        self.buffers = [BufferSlot(token_limit=int(token_limit)) for _ in range(max(1, int(buffer_count)))]
        self.queue = asyncio.Queue()
        for idx in range(len(self.buffers)):
            self.queue.put_nowait(idx)

    async def acquire(self) -> Tuple[int, BufferSlot]:
        idx = await self.queue.get()
        return idx, self.buffers[idx]

    def release(self, idx: int) -> None:
        self.queue.put_nowait(int(idx))


@dataclass
class RunSummary:
    input_dir: str
    output_dir: str
    discovered_prompt_count: int = 0
    scanned_prompt_count: int = 0
    submitted_batch_count: int = 0
    succeeded_batch_count: int = 0
    failed_batch_count: int = 0
    counts: Dict[str, int] = field(default_factory=lambda: {category: 0 for category in CATEGORIES})


try:
    _asyncio_to_thread = asyncio.to_thread
except Exception:
    _asyncio_to_thread = None


def _create_task(coro):
    create_fn = getattr(asyncio, "create_task", None)
    if create_fn is not None:
        return create_fn(coro)
    return asyncio.ensure_future(coro)


async def _to_thread(func, *args, **kwargs):
    if _asyncio_to_thread is not None:
        return await _asyncio_to_thread(func, *args, **kwargs)
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


async def _produce_prompt_paths(
    *,
    input_dir: str,
    path_queue: asyncio.Queue,
    extractor_worker_count: int,
    summary: RunSummary,
    summary_lock: asyncio.Lock,
) -> None:
    try:
        for prompt_path in iter_prompt_paths(input_dir):
            async with summary_lock:
                summary.discovered_prompt_count += 1
            await path_queue.put(prompt_path)
    finally:
        for _ in range(int(extractor_worker_count)):
            await path_queue.put(None)


async def _extract_prompt_blocks(
    *,
    input_dir: str,
    path_queue: asyncio.Queue,
    block_queue: asyncio.Queue,
    summary: RunSummary,
    summary_lock: asyncio.Lock,
) -> None:
    while True:
        prompt_path = await path_queue.get()
        try:
            if prompt_path is None:
                await block_queue.put(None)
                return
            block = await _to_thread(extract_prompt_code_block, prompt_path, input_dir)
            if block is None:
                continue
            async with summary_lock:
                summary.scanned_prompt_count += 1
            await block_queue.put(block)
        finally:
            path_queue.task_done()


async def _process_buffer(
    *,
    batch_id: int,
    buffer_index: int,
    buffer_slot: BufferSlot,
    pool: BufferPool,
    client,
    app_name: str,
    output_dir: str,
    aggregate_lock: asyncio.Lock,
    summary: RunSummary,
) -> None:
    batch_dir = os.path.join(output_dir, "batches", "buffer_{0:02d}".format(buffer_index))
    failure_dir = os.path.join(output_dir, "failures", "buffer_{0:02d}".format(buffer_index))
    prompt_path = os.path.join(batch_dir, "batch_{0:04d}_prompt.txt".format(batch_id))
    response_path = os.path.join(batch_dir, "batch_{0:04d}_response.txt".format(batch_id))
    parsed_path = os.path.join(batch_dir, "batch_{0:04d}_response.json".format(batch_id))

    snapshot_blocks = list(buffer_slot.blocks)
    batch_data: BatchPromptData = prepare_batch_prompt(snapshot_blocks)
    prompt_text = build_count_prompt(
        app_name=app_name,
        reference_lines=batch_data.reference_lines,
        context_lines=batch_data.context_lines,
        candidate_variables=batch_data.candidate_variables,
    )
    _write_text(prompt_path, prompt_text)

    try:
        response_text = await chat_text_with_retries(
            client=client,
            prompt=prompt_text,
            system=None,
            temperature=0.0,
            max_attempts=3,
            call_timeout_s=getattr(client, "timeout_s", None) if client else None,
            call_index=batch_id,
            taint_type="prompt_source_count",
            taint_name="batch_{0:04d}".format(batch_id),
            response_validator=_build_label_validator(batch_data.candidate_variables, batch_data.candidate_lookup),
            response_validator_name="source_label_full_coverage_validator",
        )
        parsed_labels = parse_source_label_response(response_text)
        if parsed_labels is None:
            raise LLMCallFailure(
                message="invalid_source_label_response",
                retryable=False,
                details={"response_text": response_text},
            )
        candidate_categories = _resolve_parsed_labels(parsed_labels, batch_data.candidate_lookup)
        if candidate_categories is None:
            raise LLMCallFailure(
                message="invalid_source_label_resolution",
                retryable=False,
                details={"response_text": response_text},
            )
        expected_keys = set(normalize_candidate_name(name) for name in batch_data.candidate_variables if normalize_candidate_name(name))
        if set(candidate_categories.keys()) != expected_keys:
            raise LLMCallFailure(
                message="incomplete_source_label_coverage",
                retryable=False,
                details={
                    "response_text": response_text,
                    "expected_candidates": batch_data.candidate_variables,
                    "resolved_candidates": sorted(candidate_categories.keys()),
                },
            )
        parsed_vars = _labels_to_category_lists(candidate_categories, batch_data.candidate_lookup)
        parsed_counts = _count_batch_matches(batch_data.block_candidate_keys, candidate_categories)

        _write_text(response_path, response_text)
        _write_json(
            parsed_path,
            {
                "schema": "external_input_source_labels.v1",
                "buffer_index": int(buffer_index),
                "batch_id": int(batch_id),
                "prompt_count": len(snapshot_blocks),
                "candidate_variables": batch_data.candidate_variables,
                "labels": parsed_labels,
                "variables": parsed_vars,
                "counts": parsed_counts,
                "prompt_files": [block.relative_path for block in snapshot_blocks],
            },
        )

        async with aggregate_lock:
            summary.succeeded_batch_count += 1
            summary.counts = merge_counts(summary.counts, parsed_counts)
    except LLMCallFailure as failure:
        _write_text(response_path, _failure_response_text(failure))
        write_llm_failure_artifact(
            failure_dir=failure_dir,
            failure_name="batch_{0:04d}".format(batch_id),
            prompt_path=prompt_path,
            failure=failure,
            extra={
                "batch_id": int(batch_id),
                "buffer_index": int(buffer_index),
                "prompt_count": len(snapshot_blocks),
                "prompt_files": [block.relative_path for block in snapshot_blocks],
            },
        )
        async with aggregate_lock:
            summary.failed_batch_count += 1
    finally:
        buffer_slot.clear()
        pool.release(buffer_index)


def _estimate_merged_prompt_tokens(app_name: str, blocks: List[PromptCodeBlock]) -> int:
    batch_data: BatchPromptData = prepare_batch_prompt(blocks)
    prompt_text = build_count_prompt(
        app_name=app_name,
        reference_lines=batch_data.reference_lines,
        context_lines=batch_data.context_lines,
        candidate_variables=batch_data.candidate_variables,
    )
    return estimate_tokens(prompt_text)


async def run_source_count_tool(
    *,
    app_name: str = "",
    input_dir: str,
    output_dir: str,
    buffer_token_limit: int = 3000,
    buffer_count: int = 5,
    extractor_worker_count: int = 2,
    llm_config_path: Optional[str] = None,
) -> RunSummary:
    input_dir = os.path.abspath(input_dir)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    summary = RunSummary(
        input_dir=input_dir,
        output_dir=output_dir,
    )
    _write_result_txt(output_dir, summary.counts)

    client = None
    pool = BufferPool(buffer_count=max(1, int(buffer_count)), token_limit=max(1, int(buffer_token_limit)))
    extractor_worker_count = max(1, int(extractor_worker_count))
    path_queue = asyncio.Queue(maxsize=max(8, int(buffer_count) * 4))
    block_queue = asyncio.Queue(maxsize=max(8, int(buffer_count) * 2))
    aggregate_lock = asyncio.Lock()
    summary_lock = asyncio.Lock()
    llm_tasks = []
    producer_task = None
    extractor_tasks = []

    try:
        producer_task = _create_task(
            _produce_prompt_paths(
                input_dir=input_dir,
                path_queue=path_queue,
                extractor_worker_count=extractor_worker_count,
                summary=summary,
                summary_lock=summary_lock,
            )
        )
        extractor_tasks = [
            _create_task(
                _extract_prompt_blocks(
                    input_dir=input_dir,
                    path_queue=path_queue,
                    block_queue=block_queue,
                    summary=summary,
                    summary_lock=summary_lock,
                )
            )
            for _ in range(extractor_worker_count)
        ]

        current_index, current_buffer = await pool.acquire()
        next_batch_id = 1
        finished_extractors = 0

        while finished_extractors < extractor_worker_count:
            block = await block_queue.get()
            if block is None:
                finished_extractors += 1
                block_queue.task_done()
                continue
            block_text = block.to_prompt_text()
            if current_buffer.is_empty():
                current_buffer.add(block, block_text)
                block_queue.task_done()
                continue
            prospective_blocks = list(current_buffer.blocks)
            prospective_blocks.append(block)
            if _estimate_merged_prompt_tokens(app_name, prospective_blocks) <= int(current_buffer.token_limit):
                current_buffer.add(block, block_text)
                block_queue.task_done()
                continue

            summary.submitted_batch_count += 1
            if client is None:
                client = get_default_client(llm_config_path)
            llm_tasks.append(
                _create_task(
                    _process_buffer(
                        batch_id=next_batch_id,
                        buffer_index=current_index,
                        buffer_slot=current_buffer,
                        pool=pool,
                        client=client,
                        app_name=app_name,
                        output_dir=output_dir,
                        aggregate_lock=aggregate_lock,
                        summary=summary,
                    )
                )
            )
            next_batch_id += 1

            current_index, current_buffer = await pool.acquire()
            current_buffer.add(block, block_text)
            block_queue.task_done()

        if not current_buffer.is_empty():
            summary.submitted_batch_count += 1
            if client is None:
                client = get_default_client(llm_config_path)
            llm_tasks.append(
                _create_task(
                    _process_buffer(
                        batch_id=next_batch_id,
                        buffer_index=current_index,
                        buffer_slot=current_buffer,
                        pool=pool,
                        client=client,
                        app_name=app_name,
                        output_dir=output_dir,
                        aggregate_lock=aggregate_lock,
                        summary=summary,
                    )
                )
            )
        else:
            pool.release(current_index)

        await producer_task
        await asyncio.gather(*extractor_tasks)
        if llm_tasks:
            await asyncio.gather(*llm_tasks)

        _write_result_txt(output_dir, summary.counts)
        _write_json(
            os.path.join(output_dir, "summary.json"),
            {
                "input_dir": summary.input_dir,
                "output_dir": summary.output_dir,
                "discovered_prompt_count": int(summary.discovered_prompt_count),
                "scanned_prompt_count": int(summary.scanned_prompt_count),
                "submitted_batch_count": int(summary.submitted_batch_count),
                "succeeded_batch_count": int(summary.succeeded_batch_count),
                "failed_batch_count": int(summary.failed_batch_count),
                "counts": summary.counts,
            },
        )
        return summary
    except Exception:
        pending = []
        if producer_task is not None:
            pending.append(producer_task)
        pending.extend(extractor_tasks)
        pending.extend(llm_tasks)
        for task in pending:
            if task is not None and not task.done():
                task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        raise
