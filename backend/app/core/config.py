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
    # Containers must listen on all interfaces; the compose files publish the port on 127.0.0.1 only.
    BACKEND_HOST: str = "0.0.0.0"  # nosec B104
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
    ALLOW_DEMO_LOAD: bool = True          # POST /onboarding/demo (admin): load a synthetic campaign; set false in production
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

    # LLM provider: groq (default) | openai_compatible (OpenAI, Azure OpenAI gateways, vLLM,
    # Ollama ... anything exposing /chat/completions) | none (rules-only operation)
    LLM_PROVIDER: Literal["groq", "openai_compatible", "none"] = "groq"
    LLM_BASE_URL: str = ""
    LLM_API_KEY: str = ""
    LLM_MODEL_OVERRIDE: str = ""          # force one model name for every agent (needed for non-Groq providers)
    LLM_ALLOW_INSECURE_HTTP: bool = False  # permit http:// endpoints (isolated networks only)

    # Durable job queue + workers
    EMBEDDED_WORKER: bool = True          # run a worker thread inside the API process (single-container mode)
    WORKER_CONCURRENCY: int = 4
    WORKER_POLL_SECONDS: float = 1.0
    JOB_LEASE_SECONDS: int = 300
    JOB_MAX_ATTEMPTS: int = 5
    JOB_RETRY_BASE_SECONDS: float = 5.0
    QUEUE_MAX_DEPTH: int = 5000           # global queued-job ceiling; ingest answers 503 above it
    QUEUE_MAX_DEPTH_PER_ORG: int = 2000   # per-tenant ceiling so one noisy tenant cannot starve the rest

    # Ingestion behaviour. matched: run the agents only for events a rule/correlation flagged
    # (or that carry a medium+ severity hint); all: triage everything; none: detect + store only.
    INGEST_TRIAGE_MODE: Literal["matched", "all", "none"] = "matched"

    # Retention (days). audit_logs is append-only and is never purged by the application.
    RETENTION_EVENTS_DAYS: int = 30
    RETENTION_EVIDENCE_DAYS: int = 365
    RETENTION_JOBS_DAYS: int = 14
    RETENTION_RUNS_DAYS: int = 90
    RETENTION_ANOMALIES_DAYS: int = 90      # behavioural anomaly records (evidence)
    RETENTION_BASELINE_DAYS: int = 180      # baselines of entities not seen for this long are dropped

    # Secrets / identity
    APP_SECRET: str = ""                  # derives per-key webhook signing secrets (>= 32 chars)
    METRICS_TOKEN: str = ""               # bearer token for GET /metrics (empty = endpoint disabled)
    MAX_TOKEN_AGE_MINUTES: int = 0        # reject JWTs older than this (0 = rely on exp only)
    SUPABASE_JWKS_URL: str = ""           # asymmetric Supabase signing keys (default derived from SUPABASE_URL)
    OIDC_ISSUER: str = ""                 # optional external IdP: accept its tokens for provisioned users
    OIDC_AUDIENCE: str = ""
    OIDC_JWKS_URL: str = ""
    OIDC_ALLOWED_ALGS: str = "RS256,ES256"

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
            if self.APP_SECRET and len(self.APP_SECRET) < 32:
                problems.append("APP_SECRET must be at least 32 characters")
            if self.OIDC_ISSUER and not (self.OIDC_AUDIENCE and self.OIDC_ISSUER.startswith("https://")):
                problems.append("OIDC_ISSUER requires an https:// issuer and OIDC_AUDIENCE")
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
