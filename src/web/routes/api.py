"""REST API routes."""

from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from src.config import settings
from src.storage.database import (
    get_recent_scans,
    get_scan_by_id,
    get_current_status,
    get_port_history,
)
from src.scheduler.job_scheduler import trigger_manual_scan, get_jobs_info

router = APIRouter()


# Response models
class PortResponse(BaseModel):
    port: int
    protocol: str
    state: Optional[str] = None
    service: Optional[str] = None
    version: Optional[str] = None


class ChangeResponse(BaseModel):
    port: int
    protocol: str
    change_type: str
    service: Optional[str] = None
    detected_at: Optional[datetime] = None


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: str
    host_status: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    ports: List[PortResponse] = []
    changes: Optional[List[ChangeResponse]] = None


class StatusResponse(BaseModel):
    target: str
    host_status: Optional[str] = None
    last_scan: Optional[datetime] = None
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


@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(limit: int = 20, offset: int = 0):
    """Get list of recent scans."""
    scans = await get_recent_scans(limit=limit)

    # Apply offset
    if offset > 0:
        scans = scans[offset:]

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
async def list_changes(limit: int = 50):
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
