from typing import Dict, Optional, NamedTuple

from .types import Param


class TokenRecord(NamedTuple):
    token: str
    param: Param
    seed: bytes
    mutated_seed: bytes


class TokenRegistry:
    def __init__(self):
        self._records: Dict[str, TokenRecord] = {}

    def add(self, token: str, param: Param, seed: bytes, mutated_seed: bytes) -> None:
        self._records[token] = TokenRecord(token=token, param=param, seed=seed, mutated_seed=mutated_seed)

    def get(self, token: str) -> Optional[TokenRecord]:
        return self._records.get(token)

    def remove(self, token: str) -> None:
        if token in self._records:
            del self._records[token]

    def to_dict(self) -> Dict[str, dict]:
        return {
            token: {
                "param": {
                    "location": record.param.location,
                    "key": record.param.key,
                    "value": record.param.value,
                    "index": record.param.index,
                },
                "seed_len": len(record.seed),
                "mutated_len": len(record.mutated_seed),
            }
            for token, record in self._records.items()
        }
