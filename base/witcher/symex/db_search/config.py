"""Runtime configuration helpers for the database exploration pipeline."""

import os
try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Optional

from common.app_config import AppConfig, load_symex_app_config
from db_query.query_executor import DBQueryConfig, load_db_query_config_from_raw


@dataclass(frozen=True)
class DBSearchRuntimeConfig:
    """Resolved runtime configuration for the standalone database search flow."""

    app_config: AppConfig
    db_config: DBQueryConfig
    goal_round_limit: int = 1
    schema_round_limit: int = 5
    candidate_round_limit: int = 10
    finalize_round_limit: int = 5
    candidate_schema_fallback_limit: int = 1


def load_db_search_runtime_config(config_path: Optional[str] = None) -> DBSearchRuntimeConfig:
    """Load app/db settings from the existing symex configuration files."""
    app_cfg = load_symex_app_config(config_path=config_path)
    db_cfg = load_db_query_config_from_raw(app_cfg.raw if hasattr(app_cfg, "raw") else {})
    return DBSearchRuntimeConfig(app_config=app_cfg, db_config=db_cfg)


def build_db_search_run_dir(runtime_cfg: DBSearchRuntimeConfig, run_dir: str = "") -> str:
    """Return the artifact directory for the standalone database search run."""
    if run_dir:
        return os.path.abspath(run_dir)
    return os.path.join(runtime_cfg.app_config.test_dir, "db_search")
