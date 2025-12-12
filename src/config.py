"""Application configuration from environment variables."""

from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Target configuration
    target_host: str = "example.com"
    scan_interval_hours: int = 2

    # Data storage
    data_dir: Path = Path("/app/data")

    @property
    def database_url(self) -> str:
        """SQLite database URL."""
        return f"sqlite+aiosqlite:///{self.data_dir}/scanner.db"

    @property
    def jobs_database_url(self) -> str:
        """SQLite database URL for APScheduler jobs."""
        return f"sqlite:///{self.data_dir}/jobs.db"

    # SMTP settings
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    smtp_to: Optional[str] = None

    # Webhook settings
    webhook_url: Optional[str] = None

    # Web server
    web_host: str = "0.0.0.0"
    web_port: int = 8080

    # Logging
    log_level: str = "INFO"

    @property
    def smtp_configured(self) -> bool:
        """Check if SMTP is properly configured."""
        return all([
            self.smtp_host,
            self.smtp_user,
            self.smtp_password,
            self.smtp_from,
            self.smtp_to,
        ])

    @property
    def webhook_configured(self) -> bool:
        """Check if webhook is configured."""
        return bool(self.webhook_url)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()
