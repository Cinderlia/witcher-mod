from ..core.types import ContextSnippet, RiskDecision


class RiskEvaluator:
    def evaluate(self, context: ContextSnippet) -> RiskDecision:
        if context.context_type in {"script", "attr", "url", "html"}:
            return RiskDecision(is_vulnerable=True, reason=f"context={context.context_type}")
        return RiskDecision(is_vulnerable=False, reason=f"context={context.context_type}")
