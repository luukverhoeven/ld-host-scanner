"""Application configuration from environment variables."""

from pathlib import Path
from typing import Dict, List, Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Target configuration
    target_host: str = "example.com"
    scan_interval_hours: int = 2

    # Scan performance tuning (nmap - used for UDP)
    scan_workers: int = 4           # Parallel nmap processes for TCP
    scan_timing: str = "4"          # Nmap timing template (3-5)
    scan_min_rate: int = 1000       # Min packets/second (0 to disable)
    scan_host_timeout: str = "30m"  # Max time per host
    scan_max_retries: int = 1       # Connection retries

    # Rustscan performance tuning (used for TCP - much faster)
    rustscan_batch_size: int = 1000    # Concurrent connections per batch (lower = more reliable)
    rustscan_timeout: int = 3000       # Timeout per port in milliseconds
    rustscan_ulimit: int = 5000        # File descriptor limit

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
    log_format: str = "text"  # "text" or "json"

    # Expected ports (comma-separated, format: "port/protocol" e.g. "80/tcp,443/tcp,22/tcp")
    expected_ports: Optional[str] = None

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

    @property
    def expected_ports_list(self) -> List[Dict[str, any]]:
        """Parse expected ports into structured list.

        Returns:
            List of dicts with 'port' (int) and 'protocol' (str) keys.
        """
        if not self.expected_ports:
            return []
        ports = []
        for entry in self.expected_ports.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if "/" in entry:
                port_str, protocol = entry.split("/", 1)
                ports.append({"port": int(port_str), "protocol": protocol.lower()})
            else:
                ports.append({"port": int(entry), "protocol": "tcp"})
        return ports

    @property
    def expected_ports_configured(self) -> bool:
        """Check if expected ports are configured."""
        return bool(self.expected_ports)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()
