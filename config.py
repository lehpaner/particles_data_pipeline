"""
Application-level configuration, loaded once from a YAML file at startup.

File location resolution order:
  1. TSI_CONFIG_PATH environment variable (absolute or relative path)
  2. config.yaml next to this file (project root)

If no file is found, built-in defaults below are used and a warning is logged.

Secrets are NOT read from this file — TSI_CLIENT_SECRET and
TSI_SESSION_SECRET must be supplied as environment variables (see auth.py).
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import yaml

log = logging.getLogger("config")

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config.yaml"


@dataclass
class AppSettings:
    host: str = "0.0.0.0"
    port: int = 8080
    reload: bool = True
    log_level: str = "INFO"


@dataclass
class PostgresSettings:
    host: str = "localhost"
    port: int = 5432
    dbname: str = "tsi_data"
    user: str = "postgres"
    password: str = ""     # prefer the TSI_PG_PASSWORD env var over storing this in YAML
    sslmode: str = "prefer"
    schema: str = "bpfc"


@dataclass
class DatabaseSettings:
    driver: str = "sqlite"   # "sqlite" | "postgresql"
    path: str = "database/tsi_data.db"          # used when driver = sqlite
    postgres: PostgresSettings = field(default_factory=PostgresSettings)


@dataclass
class CorsSettings:
    allow_origins: List[str] = field(default_factory=lambda: ["http://localhost:8080"])


@dataclass
class AuthSettings:
    client_id: str = ""
    tenant_id: str = ""
    redirect_uri: str = "http://localhost:8080/msgraph/oauth/callback"
    scopes: str = "openid profile email offline_access"
    session_ttl_hours: float = 8.0


@dataclass
class SchedulerSettings:
    poll_interval_seconds: int = 10


@dataclass
class InstrumentSettings:
    default_port: int = 502
    default_timeout: float = 3.0


@dataclass
class Config:
    app: AppSettings = field(default_factory=AppSettings)
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    cors: CorsSettings = field(default_factory=CorsSettings)
    auth: AuthSettings = field(default_factory=AuthSettings)
    scheduler: SchedulerSettings = field(default_factory=SchedulerSettings)
    instrument: InstrumentSettings = field(default_factory=InstrumentSettings)

    @property
    def db_path(self) -> Path:
        return Path(self.database.path)

    @property
    def postgres_dsn(self) -> str:
        pg = self.database.postgres
        return (
            f"host={pg.host} port={pg.port} dbname={pg.dbname} "
            f"user={pg.user} password={pg.password} sslmode={pg.sslmode}"
        )


def _apply(section, values: dict, section_name: str):
    if not values:
        return section
    for key, value in values.items():
        if hasattr(section, key):
            setattr(section, key, value)
        else:
            log.warning(f"Unknown config key '{section_name}.{key}' ignored")
    return section


def load_config(path: Path = None) -> Config:
    resolved = Path(path or os.environ.get("TSI_CONFIG_PATH", DEFAULT_CONFIG_PATH))
    cfg = Config()

    if not resolved.exists():
        log.warning(f"Config file '{resolved}' not found — using built-in defaults")
        return cfg

    with open(resolved, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    db_raw = dict(raw.get("database") or {})
    postgres_raw = db_raw.pop("postgres", None)

    _apply(cfg.app, raw.get("app"), "app")
    _apply(cfg.database, db_raw, "database")
    _apply(cfg.database.postgres, postgres_raw, "database.postgres")
    _apply(cfg.cors, raw.get("cors"), "cors")
    _apply(cfg.auth, raw.get("auth"), "auth")
    _apply(cfg.scheduler, raw.get("scheduler"), "scheduler")
    _apply(cfg.instrument, raw.get("instrument"), "instrument")

    # Secrets are never read from YAML, only from the environment.
    pg_password = os.environ.get("TSI_PG_PASSWORD")
    if pg_password is not None:
        cfg.database.postgres.password = pg_password

    log.info(f"Configuration loaded from {resolved} (database.driver={cfg.database.driver})")
    return cfg


# Loaded once, at import time (i.e. application startup).
CONFIG = load_config()
