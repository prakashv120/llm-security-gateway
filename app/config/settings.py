"""Configuration management for LLM Security Gateway."""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Application
    APP_NAME: str = "LLM Security Gateway - AI Guardrails & Threat Detection System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # PostgreSQL Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/llm_security_gateway"
    DATABASE_ECHO: bool = False
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # Ollama LLM
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2"
    OLLAMA_TIMEOUT_SECONDS: float = 30.0

    # Security Thresholds
    # Below this is considered safe / low-risk
    THRESHOLD_ALLOW: float = 0.30
    # At or above this threshold, the request is flagged for review
    # At or above THRESHOLD_REVIEW (or >= 0.7), the request is strictly blocked
    THRESHOLD_REVIEW: float = 0.70

    # Guardrails Controls
    MASK_PII_BEFORE_FORWARDING: bool = True
    ENABLE_OUTPUT_GUARDRAILS: bool = True
    MAX_PROMPT_LENGTH: int = 10000


settings = Settings()
