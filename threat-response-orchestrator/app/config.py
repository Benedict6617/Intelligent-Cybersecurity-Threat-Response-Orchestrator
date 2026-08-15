"""
Central application configuration.

Settings are loaded from environment variables (see .env.example). Sensible
defaults are provided so the platform runs out-of-the-box in a local /
evaluation environment, but every value here should be overridden with
real secrets and endpoints before production use.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Core ---
    APP_NAME: str = "Intelligent Cybersecurity Threat Response Orchestrator"
    APP_ENV: str = "development"
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = "change-me-in-production-please"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # --- Database ---
    DATABASE_URL: str = "sqlite:///./data/orchestrator.db"

    # --- Correlation / detection tuning ---
    CORRELATION_WINDOW_MINUTES: int = 15
    ANOMALY_CONTAMINATION: float = 0.03  # expected proportion of outliers for IsolationForest
    FALSE_POSITIVE_CONFIDENCE_THRESHOLD: float = 0.65
    AUTO_CONTAINMENT_MIN_SEVERITY: str = "high"  # high|critical trigger automated playbooks

    # --- ITSM integration (e.g. ServiceNow / Jira Service Management) ---
    ITSM_PROVIDER: str = "generic"
    ITSM_BASE_URL: str = "https://itsm.example-corp.local/api"
    ITSM_API_TOKEN: str = "replace-with-real-token"
    ITSM_DEFAULT_QUEUE: str = "SOC-L1"

    # --- Threat intelligence feeds ---
    THREAT_INTEL_FEED_URLS: str = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    THREAT_INTEL_REFRESH_MINUTES: int = 30

    # --- Notifications ---
    SLACK_WEBHOOK_URL: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    ALERT_EMAIL_FROM: str = "soc-alerts@example-corp.local"

    # --- Compliance ---
    COMPLIANCE_FRAMEWORKS: str = "SOC2,ISO27001"
    ORGANIZATION_NAME: str = "Example Corp"


@lru_cache
def get_settings() -> Settings:
    return Settings()
