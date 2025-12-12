"""Database operations and session management."""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from src.config import settings
from src.storage.models import Base, Scan, Port, PortChange, Notification, HostStatus

logger = logging.getLogger(__name__)

# Async engine and session factory
engine = None
async_session_factory = None


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

    logger.info("Database initialized at %s", settings.data_dir / "scanner.db")


async def get_session() -> AsyncSession:
    """Get a database session."""
    if async_session_factory is None:
        await init_database()
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


async def save_ports(scan_id: str, ports: List[Dict]) -> None:
    """Save discovered ports for a scan."""
    async with await get_session() as session:
        for port_data in ports:
            port = Port(
                scan_id=scan_id,
                port=port_data["port"],
                protocol=port_data["protocol"],
                state=port_data["state"],
                service=port_data.get("service"),
                version=port_data.get("version"),
            )
            session.add(port)
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


async def get_recent_scans(limit: int = 20) -> List[Dict]:
    """Get recent scan results with ports."""
    async with await get_session() as session:
        result = await session.execute(
            select(Scan)
            .order_by(desc(Scan.started_at))
            .limit(limit)
        )
        scans = result.scalars().all()

        scan_list = []
        for scan in scans:
            # Get ports for this scan
            ports_result = await session.execute(
                select(Port)
                .where(Port.scan_id == scan.scan_id)
                .where(Port.state == "open")
            )
            ports = ports_result.scalars().all()

            scan_list.append({
                "scan_id": scan.scan_id,
                "target": scan.target,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "host_status": scan.host_status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "error_message": scan.error_message,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "version": p.version,
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
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "error_message": scan.error_message,
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
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
                "detected_at": c.detected_at,
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
            "last_scan": last_scan,
            "last_host_check": status_time,
            "open_port_count": len(ports),
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                }
                for p in ports
            ],
        }


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
            "last_check": scan.completed_at,
            "all_open": len(missing_expected) == 0,
            "open_ports": open_expected,
            "missing_ports": missing_expected,
        }


async def save_host_status(target: str, status: str) -> None:
    """Save or update host status from quick check.

    Args:
        target: Target hostname.
        status: Host status ('online', 'offline', 'dns_only').
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
        else:
            host_status = HostStatus(
                target=target,
                status=status,
                last_check=now,
            )
            session.add(host_status)

        await session.commit()


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
                "last_check": host_status.last_check,
            }
        return None
