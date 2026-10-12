"""
AegisX application configuration — loaded from environment / .env file.
"""
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── General ──────────────────────────────────────────────────────────────
    ENV: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    SECRET_KEY: str = "change-me-in-production"
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]

    # ── Database ──────────────────────────────────────────────────────────────
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "aegisx"
    POSTGRES_USER: str = "aegisx_user"
    POSTGRES_PASSWORD: str = "changeme"

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB:   int = 0

    @property
    def REDIS_URL(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # ── LLM ───────────────────────────────────────────────────────────────────
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2"
    HUGGINGFACE_TOKEN: str = ""

    # ── Threat Intelligence ───────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = ""
    OTX_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""

    # ── Agent Limits ──────────────────────────────────────────────────────────
    AGENT_MAX_ITERATIONS: int = 15
    AGENT_TIMEOUT_SECONDS: int = 120

    # ── Endpoint Agent Integration ────────────────────────────────────────────
    # Admin API key protecting enrollment-token creation and agent administration.
    # MUST be overridden in .env for any non-local deployment.
    AEGISX_ADMIN_API_KEY: str = "change-me-admin-key"
    # A registered endpoint whose last heartbeat is older than the offline
    # timeout is considered Offline; older than the warning timeout is a Warning.
    ENDPOINT_OFFLINE_TIMEOUT_SECONDS: int = 180
    ENDPOINT_WARNING_TIMEOUT_SECONDS: int = 90
    # Default validity window for a freshly minted enrollment token.
    ENROLLMENT_TOKEN_TTL_SECONDS: int = 86_400
    # Maximum events accepted in a single agent /events batch.
    ENDPOINT_EVENT_BATCH_MAX: int = 500


settings = Settings()
