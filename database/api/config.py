from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RELIC_",
        env_file=".env",
        extra="ignore"
    )

    database_url: str
    jwt_secret: str
    jwt_ttl_seconds: int = 900
    pool_min_size: int = 2
    pool_max_size: int = 10

    insecure_dev_mode: bool = False

    @field_validator("jwt_secret")
    @classmethod
    def _long_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("RELIC_JWT_SECRET must be at least 32 characters")
        return v

@lru_cache
def get_settings() -> Settings:
    return Settings()
