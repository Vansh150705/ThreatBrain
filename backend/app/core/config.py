from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        # Loads from `backend/.env` if present
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        # Permit extra keys in .env (e.g., VITE_* values shared with the frontend)
        extra="ignore",
    )

    # Application
    APP_NAME: str = "ThreatBrain"
    APP_ENV: Literal["development", "staging", "production"] = "development"
    APP_DEBUG: bool = True
    APP_VERSION: str = "0.1.0"

    # Backend Server
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    BACKEND_URL: AnyHttpUrl = Field(default="http://localhost:8000")

    # CORS — comma-separated list of allowed origins
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # Supabase
    SUPABASE_URL: AnyHttpUrl
    SUPABASE_ANON_KEY: str
    SUPABASE_SERVICE_ROLE_KEY: str
    SUPABASE_JWT_SECRET: str

    # Security / JWT
    JWT_SECRET_KEY: str = Field(
        default="dev-insecure-change-me",
        description="Secret used by the backend for internal JWTs (not Supabase).",
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Groq AI
    GROQ_API_KEY: str = Field(default="", description="Groq API key for LLM inference.")
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    GROQ_TEMPERATURE: float = 0.2
    GROQ_MAX_TOKENS: int = 4096

    # Threat Intelligence APIs (all optional)
    ABUSEIPDB_API_KEY: str = ""
    ABUSEIPDB_BASE_URL: AnyHttpUrl = Field(default="https://api.abuseipdb.com/api/v2")

    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_BASE_URL: AnyHttpUrl = Field(default="https://www.virustotal.com/api/v3")

    SHODAN_API_KEY: str = ""
    SHODAN_BASE_URL: AnyHttpUrl = Field(default="https://api.shodan.io")

    OTX_API_KEY: str = ""
    OTX_BASE_URL: AnyHttpUrl = Field(default="https://otx.alienvault.com/api/v1")

    # Notifications (all optional)
    DISCORD_WEBHOOK_URL: str = ""
    RESEND_API_KEY: str = ""
    RESEND_FROM_EMAIL: str = ""

    # N8N Automation (all optional)
    N8N_WEBHOOK_BASE_URL: str = ""
    N8N_API_KEY: str = ""

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000

    # Logging
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_FORMAT: Literal["json", "console"] = "console"


    @property
    def cors_origins_list(self) -> list[str]:
        """CORS_ORIGINS as a parsed list."""
        return [
            origin.strip()
            for origin in self.CORS_ORIGINS.split(",")
            if origin.strip()
        ]

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def warn_on_insecure_jwt_secret(cls, v: str, info) -> str:
        """In production, refuse to start with the dev default."""
        if v == "dev-insecure-change-me" and info.data.get("APP_ENV") == "production":
            raise ValueError(
                "JWT_SECRET_KEY must be changed from the default in production."
            )
        return v



@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a singleton Settings instance.

    Cached so .env parsing only happens once per process. Use this
    function anywhere you need settings — never instantiate
    ``Settings()`` directly in business logic.
    """
    return Settings()  # type: ignore[call-arg]