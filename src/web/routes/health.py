"""Health check routes."""

from typing import Optional

from fastapi import APIRouter
from fastapi.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel

from src.scheduler.job_scheduler import get_scheduler
from src.version import __version__, get_version_info

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    scheduler_running: bool
    version: str
    message: str = "OK"


class VersionResponse(BaseModel):
    version: str
    build_date: Optional[str] = None
    git_commit: Optional[str] = None


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for Docker/monitoring."""
    scheduler = get_scheduler()
    scheduler_running = scheduler is not None and scheduler.running

    return HealthResponse(
        status="healthy" if scheduler_running else "degraded",
        scheduler_running=scheduler_running,
        version=__version__,
        message="OK" if scheduler_running else "Scheduler not running",
    )


@router.get("/version", response_model=VersionResponse)
async def version():
    """Get application version information."""
    info = get_version_info()
    return VersionResponse(**info)


@router.get("/ready")
async def readiness_check():
    """Readiness check for Kubernetes/orchestration."""
    scheduler = get_scheduler()

    if scheduler and scheduler.running:
        return {"ready": True}

    return {"ready": False, "reason": "Scheduler not running"}


@router.get("/live")
async def liveness_check():
    """Liveness check - always returns OK if app is running."""
    return {"alive": True}


@router.get("/metrics")
async def prometheus_metrics():
    """Prometheus metrics endpoint.

    Returns metrics in Prometheus exposition format for scraping.
    """
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
