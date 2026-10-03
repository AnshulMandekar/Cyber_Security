"""Runtime configuration, read from environment variables.

No secrets are hardcoded anywhere in OktaTrace. Optional values (for example an
LLM API key for the report summarizer) are only ever read from the environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from oktatrace.scenario import DEFAULT_SEED

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _env_positive_int(name: str, default: int) -> int:
    """Read a positive integer from the environment, failing loudly on bad input."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive, got {value}")
    return value


def _env_choice(name: str, choices: tuple[str, ...], default: str) -> str:
    """Read one of a fixed set of values from the environment."""
    value = (os.getenv(name) or default).strip().lower()
    if value not in choices:
        raise ValueError(f"{name} must be one of {', '.join(choices)}, got {value!r}")
    return value


@dataclass(frozen=True)
class Settings:
    """Application settings.

    Attributes:
        data_dir: Directory holding sample and generated artefacts.
        long_lived_threshold_seconds: Token lifetime above which a credential is
            flagged as long-lived.
        max_har_bytes: Largest HAR upload the API will accept.
        cors_origins: Browser origins allowed to call the API (the Vite dev server).
        db_path: SQLite database holding the generated dataset.
        seed: Seed used when the dataset is generated automatically.
        summary_mode: ``auto`` (LLM if credentials are present, else template), ``llm`` or ``template``.
        llm_model: Claude model used by the report summarizer.
        llm_timeout_seconds: Per-request timeout for the summarizer's API call.
    """

    data_dir: Path
    long_lived_threshold_seconds: int
    max_har_bytes: int
    cors_origins: tuple[str, ...]
    db_path: Path
    seed: int
    summary_mode: str
    llm_model: str
    llm_timeout_seconds: int


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Build settings once per process from ``OKTATRACE_*`` environment variables."""
    origins = os.getenv("OKTATRACE_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    data_dir = Path(os.getenv("OKTATRACE_DATA_DIR", str(PROJECT_ROOT / "data")))
    return Settings(
        data_dir=data_dir,
        long_lived_threshold_seconds=_env_positive_int("OKTATRACE_LONG_LIVED_HOURS", 8) * 3600,
        max_har_bytes=_env_positive_int("OKTATRACE_MAX_HAR_MB", 25) * 1024 * 1024,
        cors_origins=tuple(o.strip() for o in origins.split(",") if o.strip()),
        db_path=Path(os.getenv("OKTATRACE_DB_PATH", str(data_dir / "generated" / "oktatrace.db"))),
        seed=_env_positive_int("OKTATRACE_SEED", DEFAULT_SEED),
        summary_mode=_env_choice("OKTATRACE_SUMMARY_MODE", ("auto", "llm", "template"), "auto"),
        llm_model=os.getenv("OKTATRACE_LLM_MODEL", "claude-opus-5-5"),
        llm_timeout_seconds=_env_positive_int("OKTATRACE_LLM_TIMEOUT_SECONDS", 120),
    )
