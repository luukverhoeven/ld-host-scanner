"""Application configuration from environment variables."""

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from zoneinfo import ZoneInfo

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Target configuration
    target_host: str = "example.com"  # Must be configured via TARGET_HOST env var

    @field_validator('target_host')
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        """Validate hostname/IP to prevent command injection.

        Validates against RFC 1123 hostname format and rejects shell metacharacters.
        """
        # RFC 1123 hostname pattern (allows digits at start)
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

        if not v:
            raise ValueError('target_host cannot be empty')
        if len(v) > 253:
            raise ValueError('hostname too long (max 253 chars)')

        # Check for shell metacharacters
        dangerous_chars = set(';&|`$(){}[]<>\\\'\"!#*?~')
        if any(c in v for c in dangerous_chars):
            raise ValueError('hostname contains invalid characters')

        if not (re.match(hostname_pattern, v) or re.match(ipv4_pattern, v)):
            raise ValueError('invalid hostname format')

        return v

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

    # Service detection enrichment (nmap - used after Rustscan TCP discovery)
    tcp_service_enrichment: bool = True
    tcp_service_enrichment_intensity: str = "light"  # "light", "normal", "thorough"
    tcp_service_enrichment_ports_limit: int = 200

    # UDP tuning
    udp_top_ports: int = 1000
    udp_version_detection: bool = True
    udp_version_detection_intensity: str = "light"  # "light", "normal", "thorough"
    udp_version_detection_ports_limit: int = 50

    # WireGuard verification (optional)
    wireguard_public_key: Optional[str] = None  # Server's public key (base64)
    wireguard_probe_ports: Optional[str] = None  # Ports to probe, e.g., "448,51820"

    @property
    def wireguard_probe_ports_list(self) -> List[int]:
        """Parse WireGuard probe ports into list of integers.

        If not configured, defaults to common WireGuard ports (448, 51820).
        """
        if self.wireguard_probe_ports:
            return [int(p.strip()) for p in self.wireguard_probe_ports.split(",") if p.strip()]
        return [448, 51820]

    @property
    def wireguard_configured(self) -> bool:
        """Check if WireGuard verification is configured."""
        return bool(self.wireguard_public_key)

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

    # Host status monitoring
    host_offline_threshold: int = 2  # Consecutive failures before offline alert

    # Timezone for display (reads from TZ env var, defaults to UTC)
    display_timezone: str = os.getenv("TZ", "UTC")

    @property
    def tz(self) -> ZoneInfo:
        """Get timezone object for configured display timezone."""
        try:
            return ZoneInfo(self.display_timezone)
        except Exception:
            return ZoneInfo("UTC")

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
    def expected_ports_list(self) -> List[Dict[str, Any]]:
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
        extra = "ignore"  # Ignore unknown environment variables


# Global settings instance
settings = Settings()


def to_local_iso(dt: Optional[datetime]) -> Optional[str]:
    """Convert UTC datetime to configured timezone ISO string.

    Args:
        dt: Datetime object (assumed UTC if naive).

    Returns:
        ISO format string with timezone offset, or None if input is None.
    """
    if dt is None:
        return None

    # Assume naive datetime is UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))

    # Convert to configured timezone
    local_dt = dt.astimezone(settings.tz)
    return local_dt.isoformat()
