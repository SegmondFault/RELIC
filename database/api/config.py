from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from psycopg.conninfo import conninfo_to_dict
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_HOST = re.compile(r"^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$")
_LOOPBACK = {"", "localhost", "127.0.0.1", "::1"}
_TLS_MODES = {"require", "verify-ca", "verify-full"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RELIC_",
        env_file=".env",
        extra="ignore",
    )

    # Public host name (or IP) of this deployment, without scheme. Signed
    # challenges and tokens are bound to https://<host> so they cannot be
    # replayed against another RELIC deployment.
    host: str
    database_url: SecretStr
    jwt_secret: SecretStr
    jwt_ttl_seconds: int = Field(28800, ge=60, le=28800)
    challenge_ttl_seconds: int = Field(120, ge=1, le=600)

    pool_min_size: int = Field(2, ge=0)
    pool_max_size: int = Field(10, ge=1)
    statement_timeout_ms: int = Field(5000, ge=100)

    max_body_bytes: int = Field(64 * 1024, ge=1024)
    # FIDBF manifests and BSim/provenance submissions (JSON).
    max_submission_bytes: int = Field(4 * 1024 * 1024, ge=1024)
    # One uploaded FIDBF object.
    max_object_bytes: int = Field(64 * 1024 * 1024, ge=1024)
    # All staged uploads together; uploads beyond it are refused (507). Also
    # put the staging directory on its own, smaller filesystem
    # (docs/deployment.md): this cap is enforced by the API, a filesystem
    # limit holds even if the API is compromised.
    max_staging_bytes: int = Field(4 * 1024 * 1024 * 1024, ge=1024)
    # Uploads in progress at once, per Analyst and in total (slow clients
    # cannot tie up the API), and bytes one Analyst may upload per 24 hours.
    max_uploads_per_analyst: int = Field(2, ge=1)
    max_uploads_total: int = Field(8, ge=1)
    upload_bytes_per_analyst_per_day: int = Field(1024 * 1024 * 1024, ge=1024)
    # FIDBF downloads per account per hour.
    download_rate_limit_per_hour: int = Field(120, ge=1)
    # Uploaded FIDBF objects wait here for relic-admit (read-write mount).
    staging_dir: Path = Path("/var/lib/relic/staging")
    # The content-addressed FIDBF object store (read-only mount).
    fidbf_root: Path = Path("/srv/relic-objects")
    global_rate_limit_per_minute: int = Field(300, ge=1)
    auth_rate_limit_per_minute: int = Field(10, ge=1)
    registration_rate_limit_per_hour: int = Field(5, ge=1)

    # Development only: enables /docs and plaintext remote database links.
    insecure_dev_mode: bool = False

    @field_validator("host")
    @classmethod
    def _bare_host(cls, value: str) -> str:
        if not _HOST.fullmatch(value):
            raise ValueError("RELIC_HOST must be a bare host name or IP, without scheme or path")
        return value.lower()

    @field_validator("jwt_secret")
    @classmethod
    def _long_secret(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("RELIC_JWT_SECRET must be at least 32 characters")
        return value

    @model_validator(mode="after")
    def _database_link_is_protected(self) -> Settings:
        params = conninfo_to_dict(self.database_url.get_secret_value())
        host = str(params.get("host") or "")
        local = host in _LOOPBACK or host.startswith("/")
        if not local and params.get("sslmode") not in _TLS_MODES and not self.insecure_dev_mode:
            raise ValueError(
                "RELIC_DATABASE_URL points at a remote host without TLS; "
                "add sslmode=verify-full (preferred) or sslmode=require"
            )
        if self.pool_min_size > self.pool_max_size:
            raise ValueError("RELIC_POOL_MIN_SIZE must not exceed RELIC_POOL_MAX_SIZE")
        return self

    @property
    def audience(self) -> str:
        return f"https://{self.host}"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
