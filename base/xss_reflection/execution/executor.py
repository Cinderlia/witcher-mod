from ..core.types import ExecutionResult


class SeedExecutor:
    def execute(self, seed: bytes) -> ExecutionResult:
        raise NotImplementedError()
