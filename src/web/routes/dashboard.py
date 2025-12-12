"""Dashboard web routes."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from src.config import settings
from src.storage.database import (
    get_recent_scans,
    get_port_history,
    get_current_status,
    get_expected_ports_status,
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
        },
    )
