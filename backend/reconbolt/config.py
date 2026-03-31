"""Centralized configuration using Pydantic Settings.

Loads settings from environment variables and .env files with full validation.
"""

from pathlib import Path
from typing import Literal, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="RECONBOLT_",
        extra="ignore",
    )

    # --- AI Providers ---
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")

    # --- Threat Intelligence APIs ---
    virustotal_api_key: Optional[str] = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    shodan_api_key: Optional[str] = Field(default=None, alias="SHODAN_API_KEY")
    alienvault_otx_key: Optional[str] = Field(default=None, alias="ALIENVAULT_OTX_KEY")

    # --- Scan Defaults ---
    default_intensity: Literal["low", "normal", "aggressive"] = "normal"
    cmd_timeout: int = Field(default=360, ge=30, le=3600)
    max_concurrent_scans: int = Field(default=5, ge=1, le=50)

    # --- Storage ---
    db_url: str = "sqlite:///reconbolt.db"
    output_dir: Path = Path("scan_results")

    # --- API Server ---
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    @property
    def has_ai(self) -> bool:
        """Check if at least one AI provider is configured."""
        return bool(self.gemini_api_key or self.openai_api_key)

    @property
    def has_virustotal(self) -> bool:
        return bool(self.virustotal_api_key)

    @property
    def has_shodan(self) -> bool:
        return bool(self.shodan_api_key)

    @property
    def has_otx(self) -> bool:
        return bool(self.alienvault_otx_key)


# Singleton instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get the global settings instance (lazy-loaded singleton)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
