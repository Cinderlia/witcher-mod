from ..core.types import ContextSnippet


class ContextAnalyzer:
    def classify(self, snippet: str, token: str, offset: int) -> ContextSnippet:
        context_type = self._classify_type(snippet, token)
        start = max(0, offset)
        end = start + len(snippet)
        return ContextSnippet(text=snippet, start=start, end=end, context_type=context_type)

    def _classify_type(self, snippet: str, token: str) -> str:
        lower = snippet.lower()
        if "<script" in lower and "</script>" in lower:
            return "script"
        if "onerror" in lower or "onload" in lower or "onclick" in lower:
            return "attr"
        if "javascript:" in lower:
            return "url"
        if "<" in lower and ">" in lower and token in snippet:
            return "html"
        return "text"
