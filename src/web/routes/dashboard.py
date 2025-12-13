"""Dashboard web routes."""

from datetime import datetime

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse

from src.config import settings
from src.storage.database import (
    get_recent_scans,
    get_port_history,
    get_current_status,
    get_expected_ports_status,
    get_scan_by_id,
    get_changes_for_scan,
)
from src.web.app import templates

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page."""
    scans = await get_recent_scans(limit=10)
    status = await get_current_status(settings.target_host)

    # Get expected ports status if configured
    expected_ports_status = None
    if settings.expected_ports_configured:
        expected_ports_status = await get_expected_ports_status(
            settings.target_host,
            settings.expected_ports_list,
        )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "target": settings.target_host,
            "status": status,
            "recent_scans": scans,
            "scan_interval": settings.scan_interval_hours,
            "expected_ports_status": expected_ports_status,
            "timezone": settings.display_timezone,
        },
    )


@router.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    """Port change history page."""
    changes = await get_port_history(limit=100)
    scans = await get_recent_scans(limit=50)

    return templates.TemplateResponse(
        "history.html",
        {
            "request": request,
            "target": settings.target_host,
            "changes": changes,
            "scans": scans,
            "timezone": settings.display_timezone,
        },
    )


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: str):
    """Scan detail page showing ports and changes."""
    scan = await get_scan_by_id(scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Determine if scan is still running (for SSE integration)
    is_running = scan.get("status") == "running"

    # Get port changes for this scan
    changes = await get_changes_for_scan(scan_id)

    # Calculate duration if completed
    duration = None
    if scan.get("completed_at") and scan.get("started_at"):
        try:
            # Parse ISO format timestamps
            started = datetime.fromisoformat(scan["started_at"].replace("Z", "+00:00"))
            completed = datetime.fromisoformat(scan["completed_at"].replace("Z", "+00:00"))
            delta = completed - started
            minutes, seconds = divmod(int(delta.total_seconds()), 60)
            if minutes > 0:
                duration = f"{minutes}m {seconds}s"
            else:
                duration = f"{seconds}s"
        except (ValueError, TypeError):
            duration = None

    return templates.TemplateResponse(
        "scan_detail.html",
        {
            "request": request,
            "scan": scan,
            "scan_id": scan_id,
            "is_running": is_running,
            "ports": scan.get("ports", []),
            "changes": changes,
            "duration": duration,
            "timezone": settings.display_timezone,
        },
    )
