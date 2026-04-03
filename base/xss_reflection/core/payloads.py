import secrets
from typing import List

from .types import Payload, Param
from .config import XSSConfig


class PayloadFactory:
    def __init__(self, config: XSSConfig):
        self.config = config

    def random_payload(self, param: Param) -> Payload:
        token = self._token()
        return Payload(token=token, value=token, kind="random")

    def attack_payloads(self, token: str) -> List[Payload]:
        payloads = []
        for template in self.config.attack_templates:
            payloads.append(Payload(token=token, value=template.format(token=token), kind="attack"))
        return payloads

    def _token(self) -> str:
        number = secrets.randbelow(10000)
        return f"witcher_xss_{number:04d}"
