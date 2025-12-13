"""Prometheus metrics for the Security Scanner application."""

from prometheus_client import Counter, Gauge, Histogram, Info

# Application info
app_info = Info("security_scanner", "Application information")
app_info.info({
    "version": "1.0.0",
    "service": "ld-host-scanner",
})

# Scan metrics
scans_total = Counter(
    "security_scanner_scans_total",
    "Total number of scans executed",
    ["status", "target"],
)

scan_duration_seconds = Histogram(
    "security_scanner_scan_duration_seconds",
    "Duration of scans in seconds",
    ["scan_type"],
    buckets=[60, 300, 600, 900, 1200, 1800, 3600],
)

# Port metrics
open_ports_count = Gauge(
    "security_scanner_open_ports",
    "Number of open ports discovered",
    ["target", "protocol"],
)

port_changes_total = Counter(
    "security_scanner_port_changes_total",
    "Total number of port state changes detected",
    ["change_type"],
)

# Expected ports metrics
expected_ports_missing = Gauge(
    "security_scanner_expected_ports_missing",
    "Number of expected ports that are missing/closed",
    ["target"],
)

expected_port_status = Gauge(
    "security_scanner_expected_port_status",
    "Status of expected ports (1=open, 0=missing)",
    ["target", "port", "protocol"],
)

# Host status
host_online_status = Gauge(
    "security_scanner_host_online",
    "Host online status (1=online, 0=offline)",
    ["target"],
)

# Notification metrics
notifications_sent_total = Counter(
    "security_scanner_notifications_sent_total",
    "Total number of notifications sent",
    ["channel", "type"],
)

notifications_failed_total = Counter(
    "security_scanner_notifications_failed_total",
    "Total number of failed notification attempts",
    ["channel", "type"],
)
