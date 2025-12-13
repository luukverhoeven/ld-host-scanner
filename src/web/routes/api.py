"""REST API routes."""

import asyncio
import json
from typing import List, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks, Path, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from src.config import settings
from src.storage.database import (
    get_recent_scans,
    get_scan_by_id,
    get_current_status,
    get_port_history,
    get_port_count_history,
    get_host_status_history,
    update_port_service,
    get_scan_progress,
    get_scan_logs,
    get_all_scan_logs,
    get_event_logs,
)
from src.scheduler.job_scheduler import trigger_manual_scan, get_jobs_info
from src.scanner.port_scanner import PortScanner

router = APIRouter()


# Response models
class PortResponse(BaseModel):
    port: int
    protocol: str
    state: Optional[str] = None
    service: Optional[str] = None
    version: Optional[str] = None
    common_service: Optional[str] = None


class ChangeResponse(BaseModel):
    port: int
    protocol: str
    change_type: str
    service: Optional[str] = None
    detected_at: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: str
    host_status: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    ports: List[PortResponse] = []
    changes: Optional[List[ChangeResponse]] = None


class StatusResponse(BaseModel):
    target: str
    host_status: Optional[str] = None
    last_scan: Optional[str] = None
    open_port_count: int = 0
    ports: List[PortResponse] = []


class JobResponse(BaseModel):
    id: str
    name: str
    next_run: Optional[str] = None
    trigger: str


class TriggerResponse(BaseModel):
    message: str
    status: str = "queued"


class PortRescanResponse(BaseModel):
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    common_service: Optional[str] = None
    scan_duration_seconds: float
    updated: bool


@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0, le=1_000),
):
    """Get list of recent scans."""
    scans = await get_recent_scans(limit=limit, offset=offset)
    return scans


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    """Get specific scan details."""
    scan = await get_scan_by_id(scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@router.get("/status", response_model=StatusResponse)
async def get_status():
    """Get current target status."""
    status = await get_current_status(settings.target_host)

    if not status:
        return StatusResponse(
            target=settings.target_host,
            host_status="unknown",
            open_port_count=0,
            ports=[],
        )

    return status


@router.get("/changes", response_model=List[ChangeResponse])
async def list_changes(limit: int = Query(50, ge=1, le=500)):
    """Get port change history."""
    changes = await get_port_history(limit=limit)
    return changes


@router.post("/scans/trigger", response_model=TriggerResponse)
async def trigger_scan(background_tasks: BackgroundTasks):
    """Manually trigger a scan."""
    message = await trigger_manual_scan()

    return TriggerResponse(
        message=message,
        status="queued",
    )


@router.get("/scans/running")
async def get_running_scan():
    """Get the currently running scan if any.

    Returns the scan_id and progress of any currently running scan.
    Useful for connecting to the progress stream after triggering a scan.
    """
    # Get most recent scans and find one that's running
    scans = await get_recent_scans(limit=5, offset=0)
    for scan in scans:
        if scan.get("status") == "running":
            progress = await get_scan_progress(scan["scan_id"])
            return progress
    return None


@router.get("/scans/{scan_id}/progress")
async def scan_progress_stream(scan_id: str):
    """Stream scan progress via Server-Sent Events (SSE).

    Returns real-time updates of scan progress including:
    - current_phase: starting, scanning, enriching, saving, completed
    - tcp_ports_found: number of TCP ports discovered
    - udp_ports_found: number of UDP ports discovered
    - status: running, completed, failed
    """
    async def event_generator():
        while True:
            progress = await get_scan_progress(scan_id)

            if not progress:
                yield {
                    "event": "error",
                    "data": json.dumps({"error": "Scan not found"}),
                }
                break

            if progress["status"] == "completed":
                yield {
                    "event": "complete",
                    "data": json.dumps(progress),
                }
                break
            elif progress["status"] == "failed":
                yield {
                    "event": "error",
                    "data": json.dumps(progress),
                }
                break

            yield {
                "event": "progress",
                "data": json.dumps(progress),
            }

            await asyncio.sleep(1)

    return EventSourceResponse(event_generator())


@router.get("/jobs", response_model=List[JobResponse])
async def list_jobs():
    """Get scheduled jobs information."""
    return get_jobs_info()


@router.get("/config")
async def get_config():
    """Get current configuration (non-sensitive)."""
    return {
        "target_host": settings.target_host,
        "scan_interval_hours": settings.scan_interval_hours,
        "smtp_configured": settings.smtp_configured,
        "webhook_configured": settings.webhook_configured,
    }


@router.get("/port-history")
async def port_history(limit: int = Query(30, ge=1, le=365)):
    """Get open port count history for charting."""
    history = await get_port_count_history(settings.target_host, limit)
    return history


@router.get("/host-status-history")
async def host_status_history(limit: int = Query(48, ge=1, le=365)):
    """Get host status history for charting uptime.

    Returns chronological list of status checks for timeline visualization.
    Default limit of 48 covers ~12 hours at 15-minute intervals.
    """
    history = await get_host_status_history(settings.target_host, limit)
    return history


@router.post("/ports/{port}/rescan", response_model=PortRescanResponse)
async def rescan_port(
    port: int = Path(..., ge=1, le=65535, description="Port number to rescan"),
    protocol: str = Query("tcp", pattern="^(tcp|udp)$", description="Protocol"),
    intensity: str = Query(
        "normal",
        pattern="^(light|normal|thorough)$",
        description="Service detection intensity",
    ),
):
    """Rescan a single port with detailed service detection using nmap.

    This endpoint performs a focused nmap scan on a single port to get
    detailed service and version information. Results are saved to the database.

    Intensity levels:
    - light: Fast scan, checks most likely services (~2-3 sec)
    - normal: Balanced scan (~3-5 sec)
    - thorough: Comprehensive scan, tries all probes (~5-10 sec)
    """
    target = settings.target_host

    try:
        # Create scanner and run the scan in a thread pool
        scanner = PortScanner()
        result = await asyncio.to_thread(
            scanner.scan_single_port,
            target,
            port,
            protocol,
            intensity,
        )

        # Update the database with new service info
        updated = await update_port_service(
            target=target,
            port_num=port,
            protocol=protocol,
            service=result.get("service"),
            version=result.get("version"),
            common_service=result.get("common_service"),
        )

        return PortRescanResponse(
            port=result["port"],
            protocol=result["protocol"],
            state=result["state"],
            service=result.get("service"),
            version=result.get("version"),
            common_service=result.get("common_service"),
            scan_duration_seconds=result.get("scan_duration", 0),
            updated=updated,
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Port rescan failed: {str(e)}",
        )


# ============================================================================
# Logs API Endpoints
# ============================================================================


class LogEntryResponse(BaseModel):
    """Log entry response model."""
    timestamp: Optional[str] = None
    message: str
    log_type: Optional[str] = None
    level: Optional[str] = None
    logger: Optional[str] = None


class ScanLogResponse(BaseModel):
    """Scan log entry response model."""
    id: int
    scan_id: str
    timestamp: str
    message: str
    log_type: str


class EventLogResponse(BaseModel):
    """Event log response model."""
    event_type: str
    timestamp: Optional[str] = None
    message: str
    details: Optional[dict] = None


@router.get("/logs/app", response_model=List[LogEntryResponse])
async def get_app_logs(
    lines: int = Query(100, ge=1, le=1000, description="Number of lines to return"),
    level: Optional[str] = Query(None, pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$", description="Filter by log level"),
):
    """Get recent application logs from the log file.

    Reads the last N lines from the rotating log file. Supports filtering by log level.
    """
    log_file = settings.data_dir / "logs" / "app.log"

    if not log_file.exists():
        return []

    try:
        # Read file and get last N lines
        with open(log_file, "r", encoding="utf-8") as f:
            all_lines = f.readlines()

        # Parse log lines (support both text and JSON formats)
        log_entries = []
        for line in all_lines[-lines:]:
            line = line.strip()
            if not line:
                continue

            entry = {"message": line}

            # Try to parse as JSON first
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    entry = {
                        "timestamp": data.get("timestamp"),
                        "message": data.get("message", line),
                        "level": data.get("level"),
                        "logger": data.get("logger"),
                        "log_type": data.get("level", "").lower() if data.get("level") else None,
                    }
                except json.JSONDecodeError:
                    pass
            else:
                # Parse text format: "2025-12-13 22:30:45,123 - logger - LEVEL - message"
                parts = line.split(" - ", 3)
                if len(parts) >= 4:
                    entry = {
                        "timestamp": parts[0],
                        "logger": parts[1],
                        "level": parts[2],
                        "message": parts[3],
                        "log_type": parts[2].lower() if parts[2] else None,
                    }
                elif len(parts) >= 3:
                    entry = {
                        "timestamp": parts[0],
                        "level": parts[1],
                        "message": parts[2],
                        "log_type": parts[1].lower() if parts[1] else None,
                    }

            # Apply level filter
            if level and entry.get("level") != level:
                continue

            log_entries.append(entry)

        # Return in reverse order (newest first)
        log_entries.reverse()
        return log_entries

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read log file: {str(e)}",
        )


@router.get("/logs/scan/{scan_id}", response_model=List[ScanLogResponse])
async def get_scan_activity_logs(
    scan_id: str,
    limit: int = Query(100, ge=1, le=500, description="Maximum entries to return"),
):
    """Get activity logs for a specific scan.

    Returns the activity log entries saved during scan execution.
    """
    logs = await get_scan_logs(scan_id, limit=limit)
    return logs


@router.get("/logs/scans", response_model=List[ScanLogResponse])
async def get_all_scans_logs(
    limit: int = Query(100, ge=1, le=500, description="Maximum entries to return"),
    offset: int = Query(0, ge=0, description="Number of entries to skip"),
    log_type: Optional[str] = Query(None, pattern="^(info|success|warning|error)$", description="Filter by log type"),
):
    """Get activity logs across all scans.

    Returns scan activity log entries from all scans, newest first.
    """
    logs = await get_all_scan_logs(limit=limit, offset=offset, log_type=log_type)
    return logs


@router.get("/logs/events", response_model=List[EventLogResponse])
async def get_events(
    limit: int = Query(50, ge=1, le=200, description="Maximum entries to return"),
    offset: int = Query(0, ge=0, description="Number of entries to skip"),
    event_type: Optional[str] = Query(
        None,
        pattern="^(scan|notification|port_change|host_check)$",
        description="Filter by event type",
    ),
):
    """Get combined event logs from all sources.

    Combines events from scans, notifications, port changes, and host status checks
    into a unified timeline view, sorted by timestamp (newest first).
    """
    events = await get_event_logs(
        limit=limit,
        offset=offset,
        event_type=event_type,
    )
    return events
