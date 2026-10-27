from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, model_validator
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
    APP_DEBUG: bool = False
    APP_VERSION: str = "0.1.0"

    # Backend Server
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    BACKEND_URL: AnyHttpUrl = Field(default="http://localhost:8000")

    # cors, comma separated list of allowed origins
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # Behind a reverse proxy (HF Spaces, Vercel rewrites) the socket peer is the
    # proxy, so rate limits would be shared by every client. Only enable this
    # when the proxy overwrites X-Forwarded-For.
    TRUST_PROXY_HEADERS: bool = False

    # Self-service signup creates a workspace + owner account. Disable on
    # deployments where accounts are provisioned by an administrator.
    ALLOW_PUBLIC_SIGNUP: bool = True
    # Populate brand-new workspaces with clearly tagged sample threats/incidents
    # so the console is not empty on first login. Turn off for real deployments.
    SEED_DEMO_DATA: bool = True

    # Supabase
    SUPABASE_URL: AnyHttpUrl
    SUPABASE_ANON_KEY: str
    SUPABASE_SERVICE_ROLE_KEY: str
    SUPABASE_JWT_SECRET: str

    # Groq AI
    GROQ_API_KEY: str = Field(default="", description="Groq API key for LLM inference.")
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    GROQ_TEMPERATURE: float = 0.2
    GROQ_MAX_TOKENS: int = 4096
    LLM_TIMEOUT_SECONDS: float = 45.0
    LLM_MAX_RETRIES: int = 2
    LLM_RETRY_BASE_SECONDS: float = 1.0
    LLM_MAX_CONCURRENCY: int = 4

    # Agent pipeline
    PIPELINE_STAGE_TIMEOUT_SECONDS: int = 120
    PIPELINE_WORKERS: int = 4
    DEDUP_WINDOW_MINUTES: int = 30
    CORRELATION_WINDOW_HOURS: int = 72
    # Maximum number of events accepted by one webhook/batch ingest call.
    INGEST_MAX_BATCH: int = 50
    # Proactive hunting interval; 0 disables the background scheduler.
    HUNT_INTERVAL_MINUTES: int = 0

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

    # Rate Limiting (per client IP for anonymous routes, per principal otherwise)
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 120
    RATE_LIMIT_PER_HOUR: int = 3000
    # Stricter limits for unauthenticated + LLM-backed endpoints
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10
    LLM_RATE_LIMIT_PER_MINUTE: int = 20

    # Logging
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_FORMAT: Literal["json", "console"] = "console"


    @property
    def discord_webhook_ok(self) -> bool:
        """Only genuine Discord webhook URLs are accepted (SSRF guard)."""
        url = self.DISCORD_WEBHOOK_URL
        return url.startswith("https://discord.com/api/webhooks/") or url.startswith(
            "https://discordapp.com/api/webhooks/"
        )

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

    @model_validator(mode="after")
    def _production_guards(self) -> "Settings":
        """Refuse to boot a production deployment with unsafe settings."""
        if self.is_production:
            problems: list[str] = []
            if self.APP_DEBUG:
                problems.append("APP_DEBUG must be false in production")
            if "*" in self.cors_origins_list:
                problems.append("CORS_ORIGINS must not contain '*' in production")
            if len(self.SUPABASE_JWT_SECRET) < 16:
                problems.append("SUPABASE_JWT_SECRET looks too short")
            if problems:
                raise ValueError("; ".join(problems))
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a singleton Settings instance.

    Cached so .env parsing only happens once per process. Use this
    function anywhere you need settings — never instantiate
    ``Settings()`` directly in business logic.
    """
    return Settings()  # type: ignore[call-arg]
