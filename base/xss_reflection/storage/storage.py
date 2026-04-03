import json
import os
from typing import Any, Dict

from ..core.types import ExecutionResult, XSSFinding


class FindingStorage:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def save_seed(self, seed: bytes, name: str) -> str:
        path = os.path.join(self.output_dir, name)
        with open(path, "wb") as wf:
            wf.write(seed)
        return path

    def save_response(self, result: ExecutionResult, name: str) -> str:
        path = os.path.join(self.output_dir, name)
        with open(path, "w", encoding="utf-8") as wf:
            wf.write(result.response_text)
        return path

    def save_finding(self, finding: XSSFinding, name: str) -> str:
        path = os.path.join(self.output_dir, name)
        if hasattr(finding, "_asdict"):
            payload = finding._asdict()
        else:
            payload = {
                "param": finding.param,
                "payload": finding.payload,
                "context": finding.context,
                "decision": finding.decision,
                "evidence": finding.evidence,
            }
        with open(path, "w", encoding="utf-8") as wf:
            json.dump(payload, wf, ensure_ascii=False, indent=2)
        return path

    def save_metadata(self, data: Dict[str, Any], name: str) -> str:
        path = os.path.join(self.output_dir, name)
        with open(path, "w", encoding="utf-8") as wf:
            json.dump(data, wf, ensure_ascii=False, indent=2)
        return path
