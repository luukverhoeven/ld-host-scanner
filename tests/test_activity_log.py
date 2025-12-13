"""Tests for scan activity log storage."""

import pytest
from unittest.mock import AsyncMock, patch

from src.scanner.activity_log import (
    MAX_LOG_ENTRIES,
    MAX_DISCOVERED_PORTS,
    add_log_entry,
    add_discovered_port,
    clear_scan_data,
    get_activity_log,
    get_discovered_ports,
    get_scan_state,
    init_scan_state,
    update_scan_state,
    delayed_cleanup,
)


@pytest.mark.asyncio
async def test_activity_log_trimmed_to_max_entries():
    """Keeps only the most recent MAX_LOG_ENTRIES entries."""
    scan_id = "test-scan"
    await init_scan_state(scan_id)

    total_entries = MAX_LOG_ENTRIES + 10
    for i in range(total_entries):
        await add_log_entry(scan_id, f"msg-{i}", "info")

    logs = get_activity_log(scan_id)
    assert len(logs) == MAX_LOG_ENTRIES
    assert logs[0]["msg"] == "msg-10"
    assert logs[-1]["msg"] == f"msg-{total_entries - 1}"

    await clear_scan_data(scan_id)


@pytest.mark.asyncio
async def test_update_scan_state_converts_datetime():
    scan_id = "test-state"
    await init_scan_state(scan_id)

    await update_scan_state(scan_id, tcp_status="in_progress")
    state = get_scan_state(scan_id)
    assert state["tcp_status"] == "in_progress"

    await clear_scan_data(scan_id)


@pytest.mark.asyncio
async def test_delayed_cleanup_clears_data_without_waiting():
    scan_id = "test-cleanup"
    await init_scan_state(scan_id)
    await add_log_entry(scan_id, "hello", "info")

    with patch("asyncio.sleep", new=AsyncMock()):
        await delayed_cleanup(scan_id, delay=999)

    assert get_activity_log(scan_id) == []


@pytest.mark.asyncio
async def test_discovered_ports_deduplicated_and_trimmed():
    scan_id = "test-discovered"
    await init_scan_state(scan_id)

    # Duplicate should be ignored
    add_discovered_port(scan_id, 51820, "udp", "unknown", "wireguard")
    add_discovered_port(scan_id, 51820, "udp", "unknown", "wireguard")
    assert len(get_discovered_ports(scan_id)) == 1

    # Fill beyond limit to force trimming
    for i in range(MAX_DISCOVERED_PORTS + 5):
        add_discovered_port(scan_id, 10000 + i, "tcp", None, None)

    ports = get_discovered_ports(scan_id)
    assert len(ports) == MAX_DISCOVERED_PORTS

    await clear_scan_data(scan_id)
