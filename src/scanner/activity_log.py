"""In-memory activity log storage for scan progress tracking.

This module provides thread-safe storage for activity logs during scans.
Logs are stored in-memory to avoid database write overhead and are
automatically cleaned up after scan completion.
"""

import asyncio
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Any

# In-memory storage for activity logs (keyed by scan_id)
_activity_logs: Dict[str, List[Dict]] = defaultdict(list)

# In-memory storage for scan state (TCP/UDP status)
_scan_states: Dict[str, Dict[str, Any]] = {}

# Locks for thread-safe access
_locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

# Maximum log entries to keep per scan (prevents memory bloat)
MAX_LOG_ENTRIES = 100


def _get_lock(scan_id: str) -> asyncio.Lock:
    """Get or create a lock for the given scan_id."""
    if scan_id not in _locks:
        _locks[scan_id] = asyncio.Lock()
    return _locks[scan_id]


async def add_log_entry(
    scan_id: str,
    message: str,
    entry_type: str = "info"
) -> None:
    """Add a log entry for the given scan.

    Args:
        scan_id: The scan identifier.
        message: Log message text.
        entry_type: Log type - 'info', 'success', 'warning', or 'error'.
    """
    async with _get_lock(scan_id):
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "msg": message,
            "type": entry_type,
        }
        _activity_logs[scan_id].append(entry)

        # Trim old entries if over limit
        if len(_activity_logs[scan_id]) > MAX_LOG_ENTRIES:
            _activity_logs[scan_id] = _activity_logs[scan_id][-MAX_LOG_ENTRIES:]


def add_log_entry_sync(
    scan_id: str,
    message: str,
    entry_type: str = "info"
) -> None:
    """Synchronous version of add_log_entry for use in sync contexts.

    Args:
        scan_id: The scan identifier.
        message: Log message text.
        entry_type: Log type - 'info', 'success', 'warning', or 'error'.
    """
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "msg": message,
        "type": entry_type,
    }
    _activity_logs[scan_id].append(entry)

    # Trim old entries if over limit
    if len(_activity_logs[scan_id]) > MAX_LOG_ENTRIES:
        _activity_logs[scan_id] = _activity_logs[scan_id][-MAX_LOG_ENTRIES:]


def get_activity_log(scan_id: str) -> List[Dict]:
    """Get all activity log entries for the given scan.

    Args:
        scan_id: The scan identifier.

    Returns:
        List of log entries with ts, msg, and type fields.
    """
    return list(_activity_logs.get(scan_id, []))


async def init_scan_state(scan_id: str) -> None:
    """Initialize scan state for a new scan.

    Args:
        scan_id: The scan identifier.
    """
    async with _get_lock(scan_id):
        _scan_states[scan_id] = {
            "tcp_status": "not_started",
            "udp_status": "not_started",
            "tcp_started_at": None,
            "tcp_completed_at": None,
            "udp_started_at": None,
            "udp_completed_at": None,
        }
        _activity_logs[scan_id] = []


async def update_scan_state(scan_id: str, **kwargs) -> None:
    """Update scan state fields.

    Args:
        scan_id: The scan identifier.
        **kwargs: State fields to update (tcp_status, udp_status, etc.)
    """
    async with _get_lock(scan_id):
        if scan_id not in _scan_states:
            _scan_states[scan_id] = {
                "tcp_status": "not_started",
                "udp_status": "not_started",
                "tcp_started_at": None,
                "tcp_completed_at": None,
                "udp_started_at": None,
                "udp_completed_at": None,
            }

        for key, value in kwargs.items():
            if key in _scan_states[scan_id]:
                # Convert datetime to ISO string for JSON serialization
                if isinstance(value, datetime):
                    value = value.isoformat() + "Z"
                _scan_states[scan_id][key] = value


def get_scan_state(scan_id: str) -> Dict[str, Any]:
    """Get current scan state.

    Args:
        scan_id: The scan identifier.

    Returns:
        Dictionary with tcp_status, udp_status, and timestamps.
    """
    return _scan_states.get(scan_id, {
        "tcp_status": "not_started",
        "udp_status": "not_started",
        "tcp_started_at": None,
        "tcp_completed_at": None,
        "udp_started_at": None,
        "udp_completed_at": None,
    })


async def clear_scan_data(scan_id: str) -> None:
    """Clear all data for a completed scan.

    Args:
        scan_id: The scan identifier.
    """
    async with _get_lock(scan_id):
        if scan_id in _activity_logs:
            del _activity_logs[scan_id]
        if scan_id in _scan_states:
            del _scan_states[scan_id]
        if scan_id in _locks:
            del _locks[scan_id]


async def delayed_cleanup(scan_id: str, delay: int = 60) -> None:
    """Schedule cleanup of scan data after a delay.

    This allows the frontend to fetch final state before cleanup.

    Args:
        scan_id: The scan identifier.
        delay: Seconds to wait before cleanup (default: 60).
    """
    await asyncio.sleep(delay)
    await clear_scan_data(scan_id)
