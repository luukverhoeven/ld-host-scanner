"""Tests for scan activity log storage."""

import pytest

from src.scanner.activity_log import (
    MAX_LOG_ENTRIES,
    add_log_entry,
    clear_scan_data,
    get_activity_log,
    init_scan_state,
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

