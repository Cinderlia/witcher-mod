from typing import List

from ..core.types import ReflectionFinding


class ReflectionDetector:
    def __init__(self, context_window: int = 80):
        self.context_window = context_window

    def find_reflections(self, response_text: str, token: str) -> List[ReflectionFinding]:
        if not response_text or not token:
            return []
        positions = []
        start = 0
        while True:
            idx = response_text.find(token, start)
            if idx == -1:
                break
            positions.append(idx)
            start = idx + len(token)
        if not positions:
            return []
        snippets = [self._snippet(response_text, p) for p in positions]
        return [ReflectionFinding(token=token, positions=positions, context_snippets=snippets)]

    def _snippet(self, text: str, pos: int) -> str:
        left = max(0, pos - self.context_window)
        right = min(len(text), pos + self.context_window)
        return text[left:right]
