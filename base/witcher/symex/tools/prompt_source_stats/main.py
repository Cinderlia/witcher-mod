#!/usr/bin/env python3
"""CLI entry point for counting external-input source categories from prompt archives."""

import argparse
import asyncio
import os
import sys


_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.dirname(_THIS_DIR)
_SYMEX_DIR = os.path.dirname(_TOOLS_DIR)
for _path in (_TOOLS_DIR, _SYMEX_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from prompt_source_stats.runner import run_source_count_tool


def _run_async(coro):
    run_fn = getattr(asyncio, "run", None)
    if run_fn is not None:
        return run_fn(coro)

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        asyncio.set_event_loop(None)
        loop.close()


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan archived symbolic prompts, call the configured LLM, and count external-input source categories."
    )
    cwd = os.getcwd()
    parser.add_argument("--app-name", default="", help="应用名，默认留空")
    parser.add_argument("--input-dir", default=cwd, help="输入目录，默认当前工作目录")
    parser.add_argument("--output-dir", default=cwd, help="输出目录，默认当前工作目录")
    parser.add_argument("--buffer-token-limit", type=int, default=3000, help="单个缓冲区的估算 token 上限，默认 3000")
    parser.add_argument("--buffer-count", type=int, default=5, help="缓冲区数量，也是最大并发批次数，默认 5")
    parser.add_argument("--extractor-workers", type=int, default=2, help="prompt 提取 worker 数量，默认 2")
    parser.add_argument("--llm-config", default="", help="可选的 LLM 配置文件路径")
    return parser


def main(argv=None) -> int:
    args = _build_arg_parser().parse_args(argv)
    summary = _run_async(
        run_source_count_tool(
            app_name=args.app_name,
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            buffer_token_limit=args.buffer_token_limit,
            buffer_count=args.buffer_count,
            extractor_worker_count=args.extractor_workers,
            llm_config_path=(args.llm_config or None),
        )
    )

    print("input_dir:", summary.input_dir)
    print("output_dir:", summary.output_dir)
    print("discovered_prompt_count:", summary.discovered_prompt_count)
    print("scanned_prompt_count:", summary.scanned_prompt_count)
    print("submitted_batch_count:", summary.submitted_batch_count)
    print("succeeded_batch_count:", summary.succeeded_batch_count)
    print("failed_batch_count:", summary.failed_batch_count)
    print("result_path:", os.path.join(summary.output_dir, "result.txt"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
