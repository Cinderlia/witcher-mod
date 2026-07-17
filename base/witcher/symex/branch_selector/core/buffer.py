"""
Lightweight token-based buffering utilities for grouping prompt sections.
"""

import asyncio
from typing import Dict, List, Tuple


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, int(len(text) / 4))


class PromptBuffer:
    def __init__(self, *, token_limit: int):
        self.token_limit = int(token_limit)
        self.items: List[Dict] = []
        self.tokens = 0

    def clear(self):
        self.items = []
        self.tokens = 0

    def is_empty(self) -> bool:
        return len(self.items) == 0


class BufferPool:
    def __init__(self, *, buffer_count: int, token_limit: int):
        self.buffers = [PromptBuffer(token_limit=token_limit) for _ in range(int(buffer_count))]
        self.queue = asyncio.Queue()
        for i in range(len(self.buffers)):
            self.queue.put_nowait(i)

    async def acquire(self) -> Tuple[int, PromptBuffer]:
        idx = await self.queue.get()
        return idx, self.buffers[idx]

    def release(self, idx: int):
        self.queue.put_nowait(int(idx))
