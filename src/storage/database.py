"""Database operations and session management."""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import desc, func, insert, select
from sqlalchemy.sql.functions import coalesce
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from src.config import settings, to_local_iso
from src.storage.models import Base, Scan, Port, PortChange, Notification, HostStatus, HostStatusHistory, ScanLog

logger = logging.getLogger(__name__)

# Async engine and session factory
engine = None
async_session_factory = None

# Lock to prevent race condition in database initialization
_init_lock = asyncio.Lock()
_initialized = False


async def init_database() -> None:
    """Initialize the database and create tables."""
    global engine, async_session_factory

    # Ensure data directory exists
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    # Create async engine
    engine = create_async_engine(
        settings.database_url,
        echo=False,
    )

    # Create session factory
    async_session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Run migrations for schema updates
    await run_migrations()

    logger.info("Database initialized at %s", settings.data_dir / "scanner.db")


async def run_migrations() -> None:
    """Run database migrations to add missing columns."""
    from sqlalchemy import text

    # Whitelist of valid table names for SQL injection prevention
    VALID_TABLES = {'ports', 'host_status', 'scans'}

    migrations = [
        # Add common_service column to ports table
        ("ports", "common_service", "ALTER TABLE ports ADD COLUMN common_service VARCHAR(50)"),
        # Add failure_count column to host_status table
        ("host_status", "failure_count", "ALTER TABLE host_status ADD COLUMN failure_count INTEGER DEFAULT 0"),
        # Add progress tracking columns to scans table
        ("scans", "current_phase", "ALTER TABLE scans ADD COLUMN current_phase VARCHAR(20)"),
        ("scans", "tcp_ports_found", "ALTER TABLE scans ADD COLUMN tcp_ports_found INTEGER DEFAULT 0"),
        ("scans", "udp_ports_found", "ALTER TABLE scans ADD COLUMN udp_ports_found INTEGER DEFAULT 0"),
        # Add is_stealth column for UDP stealth services (WireGuard, etc.)
        ("ports", "is_stealth", "ALTER TABLE ports ADD COLUMN is_stealth BOOLEAN DEFAULT 0"),
    ]

    async with engine.begin() as conn:
        for table, column, sql in migrations:
            # Validate table name against whitelist to prevent SQL injection
            if table not in VALID_TABLES:
                logger.warning("Skipping migration for unknown table: %s", table)
                continue

            # Check if column exists
            # Note: PRAGMA doesn't support parameters, but table is whitelist-validated
            result = await conn.execute(text(f"PRAGMA table_info({table})"))
            columns = [row[1] for row in result.fetchall()]

            if column not in columns:
                try:
                    await conn.execute(text(sql))
                    logger.info("Migration: Added column %s.%s", table, column)
                except Exception as e:
                    logger.warning("Migration failed for %s.%s: %s", table, column, e)


async def cleanup_stale_running_scans() -> int:
    """Mark any running scans as failed (called on startup).

    When the application restarts, any scans that were in 'running' status
    are stale and should be marked as failed since they were interrupted.

    Returns:
        Number of stale scans that were cleaned up.
    """
    async with await get_session() as session:
        result = await session.execute(
            select(Scan).where(Scan.status == "running")
        )
        stale_scans = result.scalars().all()
        count = 0
        for scan in stale_scans:
            scan.status = "failed"
            scan.error_message = "Scan interrupted by application restart"
            scan.completed_at = datetime.utcnow()
            count += 1
        await session.commit()
        return count


async def has_running_scan() -> bool:
    """Check if there's already a scan running.

    Returns:
        True if a scan is currently running, False otherwise.
    """
    async with await get_session() as session:
        result = await session.execute(
            select(Scan).where(Scan.status == "running")
        )
        return result.scalar_one_or_none() is not None


async def get_session() -> AsyncSession:
    """Get a database session."""
    global _initialized

    if not _initialized:
        async with _init_lock:
            # Double-check after acquiring lock to prevent race condition
            if not _initialized:
                await init_database()
                _initialized = True

    return async_session_factory()


async def save_scan(
    scan_id: str,
    target: str,
    scan_type: str,
    started_at: datetime,
    status: str,
    host_status: Optional[str] = None,
    completed_at: Optional[datetime] = None,
    error_message: Optional[str] = None,
) -> Scan:
    """Save or update a scan record."""
    async with await get_session() as session:
        # Check if scan exists
        result = await session.execute(
            select(Scan).where(Scan.scan_id == scan_id)
        )
        scan = result.scalar_one_or_none()

        if scan:
            # Update existing scan
            scan.status = status
            scan.host_status = host_status
            scan.completed_at = completed_at
            scan.error_message = error_message
        else:
            # Create new scan
            scan = Scan(
                scan_id=scan_id,
                target=target,
                scan_type=scan_type,
                started_at=started_at,
                status=status,
                host_status=host_status,
                completed_at=completed_at,
                error_message=error_message,
            )
            session.add(scan)

        await session.commit()
        return scan


async def update_scan_progress(
    scan_id: str,
    current_phase: str,
    tcp_ports_found: int = 0,
    udp_ports_found: int = 0,
) -> None:
    """Update scan progress for real-time tracking."""
    async with await get_session() as session:
        result = await session.execute(
            select(Scan).where(Scan.scan_id == scan_id)
        )
        scan = result.scalar_one_or_none()

        if scan:
            scan.current_phase = current_phase
            scan.tcp_ports_found = tcp_ports_found
            scan.udp_ports_found = udp_ports_found
            await session.commit()


async def get_scan_progress(scan_id: str, after_port_index: int = 0) -> Optional[Dict]:
    """Get current scan progress for SSE streaming.

    Returns scan progress including activity log, TCP/UDP status,
    and discovered ports from the in-memory activity log store.

    Args:
        scan_id: The scan identifier.
        after_port_index: Return only discovered ports after this index (for incremental updates).
    """
    # Import here to avoid circular imports
    from src.scanner.activity_log import (
        get_activity_log,
        get_scan_state,
        get_discovered_ports,
        get_discovered_ports_count,
    )

    async with await get_session() as session:
        result = await session.execute(
            select(Scan).where(Scan.scan_id == scan_id)
        )
        scan = result.scalar_one_or_none()

        if not scan:
            return None

        # Get in-memory state (TCP/UDP status, activity log, discovered ports)
        scan_state = get_scan_state(scan_id)
        activity_log = get_activity_log(scan_id)
        discovered_ports = get_discovered_ports(scan_id, after_port_index)
        discovered_ports_count = get_discovered_ports_count(scan_id)

        return {
            "scan_id": scan.scan_id,
            "status": scan.status,
            "current_phase": scan.current_phase or "starting",
            "tcp_ports_found": scan.tcp_ports_found or 0,
            "udp_ports_found": scan.udp_ports_found or 0,
            "host_status": scan.host_status,
            # Scan context
            "target": scan.target,
            "scan_type": scan.scan_type,
            "trigger_source": scan_state.get("trigger_source"),
            # Enhanced progress tracking
            "started_at": scan.started_at.isoformat() + "Z" if scan.started_at else None,
            "tcp_status": scan_state.get("tcp_status", "not_started"),
            "udp_status": scan_state.get("udp_status", "not_started"),
            "tcp_started_at": scan_state.get("tcp_started_at"),
            "tcp_completed_at": scan_state.get("tcp_completed_at"),
            "udp_started_at": scan_state.get("udp_started_at"),
            "udp_completed_at": scan_state.get("udp_completed_at"),
            "current_sub_phase": scan_state.get("current_sub_phase"),
            "enrichment_progress": scan_state.get("enrichment_progress", {"done": 0, "total": 0}),
            # Live port discovery (incremental)
            "discovered_ports": discovered_ports,
            "discovered_ports_count": discovered_ports_count,
            # Activity log
            "activity_log": activity_log,
        }


async def save_ports(scan_id: str, ports: List[Dict]) -> None:
    """Save discovered ports for a scan."""
    if not ports:
        return

    async with await get_session() as session:
        now = datetime.utcnow()
        rows = [
            {
                "scan_id": scan_id,
                "port": port_data["port"],
                "protocol": port_data["protocol"],
                "state": port_data["state"],
                "service": port_data.get("service"),
                "version": port_data.get("version"),
                "common_service": port_data.get("common_service"),
                "is_stealth": port_data.get("is_stealth", False),
                "created_at": now,
            }
            for port_data in ports
        ]
        await session.execute(insert(Port), rows)
        await session.commit()


async def detect_changes(scan_id: str, target: str) -> List[Dict]:
    """Detect port changes compared to previous scan."""
    async with await get_session() as session:
        # Get current scan ports
        current_result = await session.execute(
            select(Port).where(Port.scan_id == scan_id)
        )
        current_ports = {
            (p.port, p.protocol): p for p in current_result.scalars().all()
        }

        # Get previous scan
        prev_scan_result = await session.execute(
            select(Scan)
            .where(Scan.target == target)
            .where(Scan.status == "completed")
            .where(Scan.scan_id != scan_id)
            .order_by(desc(Scan.completed_at))
            .limit(1)
        )
        prev_scan = prev_scan_result.scalar_one_or_none()

        if not prev_scan:
            # First scan, no changes to detect
            return []

        # Get previous scan ports
        prev_ports_result = await session.execute(
            select(Port).where(Port.scan_id == prev_scan.scan_id)
        )
        prev_ports = {
            (p.port, p.protocol): p for p in prev_ports_result.scalars().all()
        }

        changes = []

        # Find newly opened ports
        for key, port in current_ports.items():
            if port.state == "open" and key not in prev_ports:
                change = PortChange(
                    scan_id=scan_id,
                    port=port.port,
                    protocol=port.protocol,
                    change_type="opened",
                    previous_state=None,
                    new_state="open",
                    service=port.service,
                )
                session.add(change)
                changes.append({
                    "port": port.port,
                    "protocol": port.protocol,
                    "change_type": "opened",
                    "service": port.service,
                })

        # Find closed ports
        for key, prev_port in prev_ports.items():
            if prev_port.state == "open" and key not in current_ports:
                change = PortChange(
                    scan_id=scan_id,
                    port=prev_port.port,
                    protocol=prev_port.protocol,
                    change_type="closed",
                    previous_state="open",
                    new_state="closed",
                    service=prev_port.service,
                )
                session.add(change)
                changes.append({
                    "port": prev_port.port,
                    "protocol": prev_port.protocol,
                    "change_type": "closed",
                    "service": prev_port.service,
                })

        await session.commit()
        return changes


async def get_recent_scans(limit: int = 20, offset: int = 0) -> List[Dict]:
    """Get recent scan results with ports."""
    async with await get_session() as session:
        # Sort by most recent activity: completed_at for finished scans, started_at for running
        result = await session.execute(
            select(Scan)
            .order_by(desc(coalesce(Scan.completed_at, Scan.started_at)))
            .offset(offset)
            .limit(limit)
        )
        scans = result.scalars().all()

        if not scans:
            return []

        scan_ids = [scan.scan_id for scan in scans]

        ports_by_scan: Dict[str, List[Port]] = defaultdict(list)
        ports_result = await session.execute(
            select(Port)
            .where(Port.scan_id.in_(scan_ids))
            .where(Port.state == "open")
            .order_by(Port.port.asc(), Port.protocol.asc())
        )
        for port in ports_result.scalars().all():
            ports_by_scan[port.scan_id].append(port)

        scan_list = []
        for scan in scans:
            ports = ports_by_scan.get(scan.scan_id, [])

            scan_list.append({
                "scan_id": scan.scan_id,
                "target": scan.target,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "host_status": scan.host_status,
                "started_at": to_local_iso(scan.started_at),
                "completed_at": to_local_iso(scan.completed_at),
                "error_message": scan.error_message,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "version": p.version,
                        "common_service": p.common_service,
                        "is_stealth": p.is_stealth or False,
                    }
                    for p in ports
                ],
            })

        return scan_list


async def get_scan_by_id(scan_id: str) -> Optional[Dict]:
    """Get a specific scan by ID."""
    async with await get_session() as session:
        result = await session.execute(
            select(Scan).where(Scan.scan_id == scan_id)
        )
        scan = result.scalar_one_or_none()

        if not scan:
            return None

        # Get ports
        ports_result = await session.execute(
            select(Port).where(Port.scan_id == scan_id)
        )
        ports = ports_result.scalars().all()

        # Get changes
        changes_result = await session.execute(
            select(PortChange).where(PortChange.scan_id == scan_id)
        )
        changes = changes_result.scalars().all()

        return {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "host_status": scan.host_status,
            "started_at": to_local_iso(scan.started_at),
            "completed_at": to_local_iso(scan.completed_at),
            "error_message": scan.error_message,
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
                    "common_service": p.common_service,
                    "is_stealth": p.is_stealth or False,
                }
                for p in ports
            ],
            "changes": [
                {
                    "port": c.port,
                    "protocol": c.protocol,
                    "change_type": c.change_type,
                    "service": c.service,
                }
                for c in changes
            ],
        }


async def get_port_history(limit: int = 50) -> List[Dict]:
    """Get port change history."""
    async with await get_session() as session:
        result = await session.execute(
            select(PortChange)
            .order_by(desc(PortChange.detected_at))
            .limit(limit)
        )
        changes = result.scalars().all()

        return [
            {
                "scan_id": c.scan_id,
                "port": c.port,
                "protocol": c.protocol,
                "change_type": c.change_type,
                "service": c.service,
                "detected_at": to_local_iso(c.detected_at),
            }
            for c in changes
        ]


async def get_changes_for_scan(scan_id: str) -> List[Dict]:
    """Get port changes detected in a specific scan."""
    async with await get_session() as session:
        result = await session.execute(
            select(PortChange)
            .where(PortChange.scan_id == scan_id)
            .order_by(desc(PortChange.detected_at))
        )
        changes = result.scalars().all()

        return [
            {
                "port": c.port,
                "protocol": c.protocol,
                "change_type": c.change_type,
                "service": c.service,
                "detected_at": to_local_iso(c.detected_at),
            }
            for c in changes
        ]


async def get_current_status(target: str) -> Optional[Dict]:
    """Get current status of target using real-time host check status."""
    async with await get_session() as session:
        # Get real-time host status from quick checks
        host_status_result = await session.execute(
            select(HostStatus).where(HostStatus.target == target)
        )
        host_status_record = host_status_result.scalar_one_or_none()

        # Get latest completed scan for port data
        scan_result = await session.execute(
            select(Scan)
            .where(Scan.target == target)
            .where(Scan.status == "completed")
            .order_by(desc(Scan.completed_at))
            .limit(1)
        )
        scan = scan_result.scalar_one_or_none()

        # Determine host status: prefer real-time check, fallback to scan
        if host_status_record:
            # Map quick check status to dashboard status
            status = "up" if host_status_record.status == "online" else "down"
            status_time = host_status_record.last_check
        elif scan:
            status = scan.host_status
            status_time = scan.completed_at
        else:
            return None

        # Get open ports from latest scan
        ports = []
        last_scan = None
        if scan:
            last_scan = scan.completed_at
            ports_result = await session.execute(
                select(Port)
                .where(Port.scan_id == scan.scan_id)
                .where(Port.state == "open")
            )
            ports = ports_result.scalars().all()

        return {
            "target": target,
            "host_status": status,
            "last_scan": to_local_iso(last_scan),
            "last_host_check": to_local_iso(status_time),
            "open_port_count": len(ports),
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "common_service": p.common_service,
                    "is_stealth": p.is_stealth or False,
                }
                for p in ports
            ],
        }


async def update_port_service(
    target: str,
    port_num: int,
    protocol: str,
    service: Optional[str],
    version: Optional[str],
    common_service: Optional[str],
) -> bool:
    """Update service/version info for a port in the latest scan.

    Args:
        target: Target hostname.
        port_num: Port number.
        protocol: Protocol ('tcp' or 'udp').
        service: Detected service name.
        version: Detected version string.
        common_service: Common service name from lookup.

    Returns:
        True if updated successfully, False otherwise.
    """
    async with await get_session() as session:
        # Find the latest completed scan for this target
        scan_result = await session.execute(
            select(Scan)
            .where(Scan.target == target)
            .where(Scan.status == "completed")
            .order_by(desc(Scan.completed_at))
            .limit(1)
        )
        scan = scan_result.scalar_one_or_none()

        if not scan:
            return False

        # Find the port record
        port_result = await session.execute(
            select(Port)
            .where(Port.scan_id == scan.scan_id)
            .where(Port.port == port_num)
            .where(Port.protocol == protocol)
        )
        port_record = port_result.scalar_one_or_none()

        if not port_record:
            return False

        # Update the port record
        port_record.service = service
        port_record.version = version
        port_record.common_service = common_service

        await session.commit()
        return True


async def save_notification(
    notification_type: str,
    status: str,
    scan_id: Optional[str] = None,
    subject: Optional[str] = None,
    message: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    """Save notification record."""
    async with await get_session() as session:
        notification = Notification(
            scan_id=scan_id,
            notification_type=notification_type,
            subject=subject,
            message=message,
            status=status,
            error_message=error_message,
        )
        session.add(notification)
        await session.commit()


async def get_previous_missing_expected_ports(
    target: str,
    current_scan_id: str,
    expected_ports: List[Dict],
) -> List[Dict]:
    """Get which expected ports were missing in the previous scan.

    Args:
        target: Target hostname.
        current_scan_id: Current scan ID to exclude.
        expected_ports: List of expected ports to check.

    Returns:
        List of expected ports that were missing in the previous scan.
    """
    async with await get_session() as session:
        # Get the previous completed scan
        prev_scan_result = await session.execute(
            select(Scan)
            .where(Scan.target == target)
            .where(Scan.status == "completed")
            .where(Scan.scan_id != current_scan_id)
            .order_by(desc(Scan.completed_at))
            .limit(1)
        )
        prev_scan = prev_scan_result.scalar_one_or_none()

        if not prev_scan:
            # First scan, all expected ports were "missing" before (new state)
            # Return empty to indicate nothing was previously missing
            return []

        # Get open ports from previous scan
        prev_ports_result = await session.execute(
            select(Port)
            .where(Port.scan_id == prev_scan.scan_id)
            .where(Port.state == "open")
        )
        prev_open_ports = {
            (p.port, p.protocol) for p in prev_ports_result.scalars().all()
        }

        # Find which expected ports were missing in the previous scan
        missing_in_prev = []
        for exp in expected_ports:
            if (exp["port"], exp["protocol"]) not in prev_open_ports:
                missing_in_prev.append(exp)

        return missing_in_prev


def detect_newly_missing_expected_ports(
    current_missing: List[Dict],
    previous_missing: List[Dict],
) -> List[Dict]:
    """Detect expected ports that are newly missing (went from open to closed).

    Args:
        current_missing: Expected ports currently missing.
        previous_missing: Expected ports that were missing in previous scan.

    Returns:
        List of expected ports that are newly missing (state changed).
    """
    # Convert previous missing to a set for quick lookup
    prev_missing_set = {
        (p["port"], p["protocol"]) for p in previous_missing
    }

    # Find ports that are missing now but were NOT missing before
    newly_missing = []
    for port in current_missing:
        if (port["port"], port["protocol"]) not in prev_missing_set:
            newly_missing.append(port)

    return newly_missing


async def get_expected_ports_status(
    target: str,
    expected_ports: List[Dict],
) -> Dict:
    """Get the current status of expected ports.

    Args:
        target: Target hostname.
        expected_ports: List of expected ports to check.

    Returns:
        Dict with status information including open and missing ports.
    """
    async with await get_session() as session:
        # Get the latest completed scan
        scan_result = await session.execute(
            select(Scan)
            .where(Scan.target == target)
            .where(Scan.status == "completed")
            .order_by(desc(Scan.completed_at))
            .limit(1)
        )
        scan = scan_result.scalar_one_or_none()

        if not scan:
            return {
                "configured": True,
                "last_check": None,
                "all_open": None,
                "open_ports": [],
                "missing_ports": expected_ports,
            }

        # Get open ports from the scan
        ports_result = await session.execute(
            select(Port)
            .where(Port.scan_id == scan.scan_id)
            .where(Port.state == "open")
        )
        open_ports = {
            (p.port, p.protocol): p for p in ports_result.scalars().all()
        }

        # Check which expected ports are open/missing
        open_expected = []
        missing_expected = []

        for exp in expected_ports:
            key = (exp["port"], exp["protocol"])
            if key in open_ports:
                port = open_ports[key]
                open_expected.append({
                    "port": exp["port"],
                    "protocol": exp["protocol"],
                    "service": port.service,
                })
            else:
                missing_expected.append({
                    "port": exp["port"],
                    "protocol": exp["protocol"],
                })

        return {
            "configured": True,
            "last_check": to_local_iso(scan.completed_at),
            "all_open": len(missing_expected) == 0,
            "open_ports": open_expected,
            "missing_ports": missing_expected,
        }


async def save_host_status(target: str, status: str) -> int:
    """Save or update host status from quick check.

    Tracks consecutive failures: resets to 0 when online, increments otherwise.

    Args:
        target: Target hostname.
        status: Host status ('online', 'offline', 'dns_only').

    Returns:
        Current failure count (0 if online, incremented if not online).
    """
    async with await get_session() as session:
        result = await session.execute(
            select(HostStatus).where(HostStatus.target == target)
        )
        host_status = result.scalar_one_or_none()

        now = datetime.utcnow()

        if host_status:
            host_status.status = status
            host_status.last_check = now
            if status == "online":
                host_status.failure_count = 0
            else:
                host_status.failure_count = (host_status.failure_count or 0) + 1
            failure_count = host_status.failure_count
        else:
            failure_count = 0 if status == "online" else 1
            host_status = HostStatus(
                target=target,
                status=status,
                failure_count=failure_count,
                last_check=now,
            )
            session.add(host_status)

        await session.commit()
        return failure_count


async def get_last_host_status(target: str) -> Optional[str]:
    """Get the last known host status.

    Args:
        target: Target hostname.

    Returns:
        Last known status ('online', 'offline', 'dns_only') or None if never checked.
    """
    async with await get_session() as session:
        result = await session.execute(
            select(HostStatus).where(HostStatus.target == target)
        )
        host_status = result.scalar_one_or_none()

        if host_status:
            return host_status.status
        return None


async def get_host_status_record(target: str) -> Optional[Dict]:
    """Get full host status record.

    Args:
        target: Target hostname.

    Returns:
        Dict with status info or None if never checked.
    """
    async with await get_session() as session:
        result = await session.execute(
            select(HostStatus).where(HostStatus.target == target)
        )
        host_status = result.scalar_one_or_none()

        if host_status:
            return {
                "target": host_status.target,
                "status": host_status.status,
                "failure_count": host_status.failure_count or 0,
                "last_check": to_local_iso(host_status.last_check),
            }
        return None


async def get_port_count_history(target: str, limit: int = 30) -> List[Dict]:
    """Get open port count per scan for charting.

    Args:
        target: Target hostname.
        limit: Maximum number of data points to return.

    Returns:
        List of dicts with completed_at timestamp and open_port_count.
    """
    async with await get_session() as session:
        # Get completed scans ordered by time
        scans_result = await session.execute(
            select(Scan)
            .where(Scan.target == target)
            .where(Scan.status == "completed")
            .order_by(desc(Scan.completed_at))
            .limit(limit)
        )
        scans = scans_result.scalars().all()

        if not scans:
            return []

        scan_ids = [scan.scan_id for scan in scans]
        counts_result = await session.execute(
            select(Port.scan_id, func.count(Port.id))
            .where(Port.scan_id.in_(scan_ids))
            .where(Port.state == "open")
            .group_by(Port.scan_id)
        )
        open_counts = {scan_id: count for scan_id, count in counts_result.all()}

        history = []
        for scan in scans:
            history.append({
                "completed_at": to_local_iso(scan.completed_at),
                "open_port_count": int(open_counts.get(scan.scan_id, 0)),
                "host_status": scan.host_status,
            })

        # Reverse to get chronological order (oldest first)
        history.reverse()
        return history


async def get_open_ports_from_last_scan(target: str) -> List[int]:
    """Get list of open TCP ports from the last completed scan.

    Used by quick_host_check to probe known-open ports instead of hardcoded ones.

    Args:
        target: Target hostname.

    Returns:
        List of port numbers that were open in the last scan.
    """
    async with await get_session() as session:
        # Get the latest completed scan
        scan_result = await session.execute(
            select(Scan)
            .where(Scan.target == target)
            .where(Scan.status == "completed")
            .order_by(desc(Scan.completed_at))
            .limit(1)
        )
        scan = scan_result.scalar_one_or_none()

        if not scan:
            return []

        # Get open TCP ports from this scan
        ports_result = await session.execute(
            select(Port)
            .where(Port.scan_id == scan.scan_id)
            .where(Port.state == "open")
            .where(Port.protocol == "tcp")
        )
        ports = ports_result.scalars().all()

        return [p.port for p in ports]


async def save_host_status_history(
    target: str,
    status: str,
    dns_resolved: Optional[bool] = None,
    tcp_reachable: Optional[bool] = None,
    icmp_reachable: Optional[bool] = None,
    check_method: Optional[str] = None,
) -> None:
    """Save a historical record of a host status check.

    Args:
        target: Target hostname.
        status: Host status ('online', 'offline', 'dns_only').
        dns_resolved: Whether DNS resolution succeeded.
        tcp_reachable: Whether TCP probe succeeded.
        icmp_reachable: Whether ICMP ping succeeded.
        check_method: Method that confirmed status ('icmp', 'tcp', 'dns').
    """
    async with await get_session() as session:
        history_record = HostStatusHistory(
            target=target,
            status=status,
            dns_resolved=dns_resolved,
            tcp_reachable=tcp_reachable,
            icmp_reachable=icmp_reachable,
            check_method=check_method,
            checked_at=datetime.utcnow(),
        )
        session.add(history_record)
        await session.commit()


async def get_host_status_history(target: str, limit: int = 30) -> List[Dict]:
    """Get host status history for charting.

    Args:
        target: Target hostname.
        limit: Maximum number of data points to return.

    Returns:
        List of dicts with checked_at timestamp and status (chronological order, oldest first).
    """
    async with await get_session() as session:
        result = await session.execute(
            select(HostStatusHistory)
            .where(HostStatusHistory.target == target)
            .order_by(desc(HostStatusHistory.checked_at))
            .limit(limit)
        )
        records = result.scalars().all()

        history = [
            {
                "checked_at": to_local_iso(record.checked_at),
                "status": record.status,
                "dns_resolved": record.dns_resolved,
                "tcp_reachable": record.tcp_reachable,
                "check_method": record.check_method,
            }
            for record in records
        ]

        # Reverse to get chronological order (oldest first for chart)
        history.reverse()
        return history


async def save_scan_log(
    scan_id: str,
    message: str,
    log_type: str = "info",
) -> None:
    """Save a scan activity log entry to the database.

    Args:
        scan_id: The scan identifier.
        message: Log message.
        log_type: Type of log entry ('info', 'success', 'warning', 'error').
    """
    async with await get_session() as session:
        log_entry = ScanLog(
            scan_id=scan_id,
            message=message,
            log_type=log_type,
            timestamp=datetime.utcnow(),
        )
        session.add(log_entry)
        await session.commit()


async def get_scan_logs(scan_id: str, limit: int = 100) -> List[Dict]:
    """Get activity logs for a specific scan.

    Args:
        scan_id: The scan identifier.
        limit: Maximum number of log entries to return.

    Returns:
        List of log entries (oldest first).
    """
    async with await get_session() as session:
        result = await session.execute(
            select(ScanLog)
            .where(ScanLog.scan_id == scan_id)
            .order_by(ScanLog.timestamp.asc())
            .limit(limit)
        )
        logs = result.scalars().all()

        return [
            {
                "id": log.id,
                "scan_id": log.scan_id,
                "timestamp": to_local_iso(log.timestamp),
                "message": log.message,
                "log_type": log.log_type,
            }
            for log in logs
        ]


async def get_all_scan_logs(
    limit: int = 100,
    offset: int = 0,
    log_type: Optional[str] = None,
) -> List[Dict]:
    """Get scan activity logs across all scans.

    Args:
        limit: Maximum number of log entries to return.
        offset: Number of entries to skip.
        log_type: Optional filter by log type.

    Returns:
        List of log entries (newest first).
    """
    async with await get_session() as session:
        query = select(ScanLog).order_by(desc(ScanLog.timestamp))

        if log_type:
            query = query.where(ScanLog.log_type == log_type)

        query = query.offset(offset).limit(limit)
        result = await session.execute(query)
        logs = result.scalars().all()

        return [
            {
                "id": log.id,
                "scan_id": log.scan_id,
                "timestamp": to_local_iso(log.timestamp),
                "message": log.message,
                "log_type": log.log_type,
            }
            for log in logs
        ]


async def get_event_logs(
    limit: int = 50,
    offset: int = 0,
    event_type: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
) -> List[Dict]:
    """Get combined event logs from multiple sources.

    Args:
        limit: Maximum number of entries to return.
        offset: Number of entries to skip.
        event_type: Filter by event type ('scan', 'notification', 'port_change', 'host_check').
        date_from: Start date filter.
        date_to: End date filter.

    Returns:
        List of events (newest first), combining scans, notifications, port changes, and host checks.
    """
    events = []

    async with await get_session() as session:
        # Get scans
        if not event_type or event_type == "scan":
            scan_query = select(Scan).order_by(desc(Scan.started_at))
            if date_from:
                scan_query = scan_query.where(Scan.started_at >= date_from)
            if date_to:
                scan_query = scan_query.where(Scan.started_at <= date_to)
            scan_query = scan_query.limit(limit)
            result = await session.execute(scan_query)
            for scan in result.scalars().all():
                events.append({
                    "event_type": "scan",
                    "timestamp": to_local_iso(scan.started_at),
                    "message": f"Scan {scan.status}: {scan.target} ({scan.scan_type})",
                    "details": {
                        "scan_id": scan.scan_id,
                        "status": scan.status,
                        "target": scan.target,
                        "host_status": scan.host_status,
                        "error_message": scan.error_message,
                    },
                })

        # Get notifications
        if not event_type or event_type == "notification":
            notif_query = select(Notification).order_by(desc(Notification.sent_at))
            if date_from:
                notif_query = notif_query.where(Notification.sent_at >= date_from)
            if date_to:
                notif_query = notif_query.where(Notification.sent_at <= date_to)
            notif_query = notif_query.limit(limit)
            result = await session.execute(notif_query)
            for notif in result.scalars().all():
                events.append({
                    "event_type": "notification",
                    "timestamp": to_local_iso(notif.sent_at),
                    "message": f"Notification {notif.status}: {notif.notification_type} - {notif.subject or 'No subject'}",
                    "details": {
                        "notification_type": notif.notification_type,
                        "status": notif.status,
                        "subject": notif.subject,
                        "error_message": notif.error_message,
                    },
                })

        # Get port changes
        if not event_type or event_type == "port_change":
            change_query = select(PortChange).order_by(desc(PortChange.detected_at))
            if date_from:
                change_query = change_query.where(PortChange.detected_at >= date_from)
            if date_to:
                change_query = change_query.where(PortChange.detected_at <= date_to)
            change_query = change_query.limit(limit)
            result = await session.execute(change_query)
            for change in result.scalars().all():
                events.append({
                    "event_type": "port_change",
                    "timestamp": to_local_iso(change.detected_at),
                    "message": f"Port {change.change_type}: {change.port}/{change.protocol} ({change.service or 'unknown'})",
                    "details": {
                        "port": change.port,
                        "protocol": change.protocol,
                        "change_type": change.change_type,
                        "service": change.service,
                        "scan_id": change.scan_id,
                    },
                })

        # Get host status checks
        if not event_type or event_type == "host_check":
            host_query = select(HostStatusHistory).order_by(desc(HostStatusHistory.checked_at))
            if date_from:
                host_query = host_query.where(HostStatusHistory.checked_at >= date_from)
            if date_to:
                host_query = host_query.where(HostStatusHistory.checked_at <= date_to)
            host_query = host_query.limit(limit)
            result = await session.execute(host_query)
            for check in result.scalars().all():
                events.append({
                    "event_type": "host_check",
                    "timestamp": to_local_iso(check.checked_at),
                    "message": f"Host check: {check.target} is {check.status} (method: {check.check_method or 'unknown'})",
                    "details": {
                        "target": check.target,
                        "status": check.status,
                        "dns_resolved": check.dns_resolved,
                        "tcp_reachable": check.tcp_reachable,
                        "check_method": check.check_method,
                    },
                })

    # Sort all events by timestamp (newest first) and apply pagination
    events.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return events[offset:offset + limit]
