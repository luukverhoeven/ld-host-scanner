"""In-memory activity log storage for scan progress tracking.

This module provides thread-safe storage for activity logs during scans.
Logs are stored in-memory to avoid database write overhead and are
automatically cleaned up after scan completion.
"""

import asyncio
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional

# Maximum log entries to keep per scan (prevents memory bloat)
MAX_LOG_ENTRIES = 100

# Maximum discovered ports to keep per scan
MAX_DISCOVERED_PORTS = 500

# In-memory storage for activity logs (keyed by scan_id)
_activity_logs: Dict[str, Deque[Dict[str, str]]] = defaultdict(
    lambda: deque(maxlen=MAX_LOG_ENTRIES)
)

# In-memory storage for scan state (TCP/UDP status)
_scan_states: Dict[str, Dict[str, Any]] = {}

# In-memory storage for discovered ports (keyed by scan_id)
_discovered_ports: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

# Locks for thread-safe access
_locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)


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


def get_activity_log(scan_id: str) -> List[Dict]:
    """Get all activity log entries for the given scan.

    Args:
        scan_id: The scan identifier.

    Returns:
        List of log entries with ts, msg, and type fields.
    """
    return list(_activity_logs.get(scan_id, ()))


async def init_scan_state(
    scan_id: str,
    trigger_source: Optional[str] = None
) -> None:
    """Initialize scan state for a new scan.

    Args:
        scan_id: The scan identifier.
        trigger_source: How the scan was triggered - 'manual' or 'scheduled'.
    """
    async with _get_lock(scan_id):
        _scan_states[scan_id] = {
            "tcp_status": "not_started",
            "udp_status": "not_started",
            "tcp_started_at": None,
            "tcp_completed_at": None,
            "udp_started_at": None,
            "udp_completed_at": None,
            "trigger_source": trigger_source,
            "current_sub_phase": None,
            "enrichment_progress": {"done": 0, "total": 0},
        }
        _activity_logs[scan_id] = deque(maxlen=MAX_LOG_ENTRIES)
        _discovered_ports[scan_id] = []


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
                "trigger_source": None,
                "current_sub_phase": None,
                "enrichment_progress": {"done": 0, "total": 0},
            }

        for key, value in kwargs.items():
            # Convert datetime to ISO string for JSON serialization
            if isinstance(value, datetime):
                value = value.isoformat() + "Z"
            _scan_states[scan_id][key] = value


def get_scan_state(scan_id: str) -> Dict[str, Any]:
    """Get current scan state.

    Args:
        scan_id: The scan identifier.

    Returns:
        Dictionary with tcp_status, udp_status, timestamps, and enhanced fields.
    """
    return _scan_states.get(scan_id, {
        "tcp_status": "not_started",
        "udp_status": "not_started",
        "tcp_started_at": None,
        "tcp_completed_at": None,
        "udp_started_at": None,
        "udp_completed_at": None,
        "trigger_source": None,
        "current_sub_phase": None,
        "enrichment_progress": {"done": 0, "total": 0},
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
        if scan_id in _discovered_ports:
            del _discovered_ports[scan_id]
        if scan_id in _locks:
            del _locks[scan_id]


def add_discovered_port(
    scan_id: str,
    port: int,
    protocol: str,
    service: Optional[str] = None,
    common_service: Optional[str] = None
) -> None:
    """Add a discovered port to the live feed.

    Args:
        scan_id: The scan identifier.
        port: Port number.
        protocol: Protocol type ('tcp' or 'udp').
        service: Detected service name.
        common_service: Common service name from lookup.
    """
    if scan_id not in _discovered_ports:
        _discovered_ports[scan_id] = []

    # Prevent duplicates
    for existing in _discovered_ports[scan_id]:
        if existing["port"] == port and existing["protocol"] == protocol:
            return

    port_info = {
        "port": port,
        "protocol": protocol,
        "service": service,
        "common_service": common_service,
        "discovered_at": datetime.utcnow().isoformat() + "Z",
    }
    _discovered_ports[scan_id].append(port_info)

    # Trim if over limit
    if len(_discovered_ports[scan_id]) > MAX_DISCOVERED_PORTS:
        _discovered_ports[scan_id] = _discovered_ports[scan_id][-MAX_DISCOVERED_PORTS:]


def get_discovered_ports(
    scan_id: str,
    after_index: int = 0
) -> List[Dict[str, Any]]:
    """Get discovered ports, optionally after a specific index for incremental updates.

    Args:
        scan_id: The scan identifier.
        after_index: Return only ports discovered after this index (0-based).

    Returns:
        List of port info dictionaries.
    """
    ports = _discovered_ports.get(scan_id, [])
    return ports[after_index:]


def get_discovered_ports_count(scan_id: str) -> int:
    """Get the total count of discovered ports.

    Args:
        scan_id: The scan identifier.

    Returns:
        Number of discovered ports.
    """
    return len(_discovered_ports.get(scan_id, []))


async def delayed_cleanup(scan_id: str, delay: int = 60) -> None:
    """Schedule cleanup of scan data after a delay.

    This allows the frontend to fetch final state before cleanup.

    Args:
        scan_id: The scan identifier.
        delay: Seconds to wait before cleanup (default: 60).
    """
    await asyncio.sleep(delay)
    await clear_scan_data(scan_id)
