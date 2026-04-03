import glob
import os
from typing import Iterable, Optional, List

from ..core.config import XSSConfig
from ..core.types import XSSFinding, ContextSnippet
from ..core.seed_parser import SeedParser
from ..core.seed_mutator import SeedMutator
from ..core.payloads import PayloadFactory
from ..analysis.reflection_detector import ReflectionDetector
from ..analysis.context_analyzer import ContextAnalyzer
from ..analysis.risk_evaluator import RiskEvaluator
from ..execution.executor import SeedExecutor
from ..storage.storage import FindingStorage
from ..core.token_registry import TokenRegistry


class ReflectionXSSPipeline:
    def __init__(
        self,
        config: XSSConfig,
        executor: SeedExecutor,
        storage: FindingStorage,
        parser: Optional[SeedParser] = None,
        mutator: Optional[SeedMutator] = None,
        payloads: Optional[PayloadFactory] = None,
        detector: Optional[ReflectionDetector] = None,
        analyzer: Optional[ContextAnalyzer] = None,
        evaluator: Optional[RiskEvaluator] = None,
    ):
        self.config = config
        self.executor = executor
        self.storage = storage
        self.parser = parser or SeedParser()
        self.mutator = mutator or SeedMutator()
        self.payloads = payloads or PayloadFactory(config)
        self.detector = detector or ReflectionDetector(config.context_window)
        self.analyzer = analyzer or ContextAnalyzer()
        self.evaluator = evaluator or RiskEvaluator()
        self.registry = TokenRegistry()

    def run(self) -> List[XSSFinding]:
        seeds = self._load_seeds(self.config.seed_dir)
        return self.run_on_seeds(seeds)

    def run_on_seeds(self, seeds: Iterable[bytes]) -> List[XSSFinding]:
        findings = []
        for seed in seeds:
            findings.extend(self.run_on_seed(seed))
        return findings

    def run_on_seed(self, seed: bytes) -> List[XSSFinding]:
        seed_input = self.parser.parse_seed(seed)
        params = self.parser.extract_params(seed_input)
        findings = []
        for param in params:
            payload = self.payloads.random_payload(param)
            mutated = self.mutator.replace_param(seed_input, param, payload.value)
            self.registry.add(payload.token, param, seed, mutated)
            result = self.executor.execute(mutated)
            reflections = self.detector.find_reflections(result.response_text, payload.token)
            if not reflections:
                self.registry.remove(payload.token)
                continue
            for reflection in reflections:
                for snippet in reflection.context_snippets:
                    context = self.analyzer.classify(snippet, payload.token, 0)
                    findings.extend(self._confirm_attack(seed_input, param, payload.token, context))
            self.registry.remove(payload.token)
        return findings

    def _confirm_attack(
        self,
        seed_input,
        param,
        token,
        context: ContextSnippet,
    ) -> List[XSSFinding]:
        findings = []
        for payload in self.payloads.attack_payloads(token):
            mutated = self.mutator.replace_param(seed_input, param, payload.value)
            result = self.executor.execute(mutated)
            reflections = self.detector.find_reflections(result.response_text, payload.token)
            if not reflections:
                continue
            decision = self.evaluator.evaluate(context)
            if decision.is_vulnerable:
                evidence = reflections[0].context_snippets[0]
                finding = XSSFinding(
                    param=param,
                    payload=payload,
                    context=context,
                    decision=decision,
                    evidence=evidence,
                )
                findings.append(finding)
        return findings

    def _load_seeds(self, seed_dir: str) -> List[bytes]:
        patterns = [os.path.join(seed_dir, "*")]
        seeds = []
        for pattern in patterns:
            for path in sorted(glob.glob(pattern)):
                if os.path.isdir(path):
                    continue
                with open(path, "rb") as rf:
                    seeds.append(rf.read())
        if self.config.max_seeds and len(seeds) > self.config.max_seeds:
            seeds = seeds[: self.config.max_seeds]
        return seeds
