from typing import List, Dict, Optional


class XSSConfig:
    def __init__(
        self,
        seed_dir: str,
        output_dir: str,
        payload_count: int = 3,
        context_window: int = 80,
        max_seeds: int = 0,
        cgi_binary: Optional[str] = None,
        cgi_args: Optional[List[str]] = None,
        script_filename: Optional[str] = None,
        document_root: Optional[str] = None,
        method: str = "AUTO",
        path_info: str = "",
        content_type: str = "application/x-www-form-urlencoded",
        timeout_seconds: float = 5.0,
        extra_env: Optional[Dict[str, str]] = None,
        random_templates: Optional[List[str]] = None,
        attack_templates: Optional[List[str]] = None,
    ):
        self.seed_dir = seed_dir
        self.output_dir = output_dir
        self.payload_count = payload_count
        self.context_window = context_window
        self.max_seeds = max_seeds
        self.cgi_binary = cgi_binary
        self.cgi_args = cgi_args or []
        self.script_filename = script_filename
        self.document_root = document_root
        self.method = method
        self.path_info = path_info
        self.content_type = content_type
        self.timeout_seconds = timeout_seconds
        self.extra_env = extra_env or {}
        self.random_templates = random_templates or [
            "<xss>{token}</xss>",
            "\"{token}\"",
            "'{token}'",
            "{token}",
        ]
        self.attack_templates = attack_templates or [
            "<script>{token}</script>",
            "\"><img src=x onerror={token}>",
            "'><svg/onload={token}>",
            "javascript:{token}",
        ]
