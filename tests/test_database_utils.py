"""Tests for pure helper functions in storage layer."""

from src.storage.database import detect_newly_missing_expected_ports


def test_detect_newly_missing_expected_ports_returns_only_new():
    prev = [{"port": 80, "protocol": "tcp"}]
    current = [{"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}]

    newly = detect_newly_missing_expected_ports(current, prev)
    assert newly == [{"port": 443, "protocol": "tcp"}]

