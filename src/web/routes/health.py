"""Health check routes."""

from fastapi import APIRouter
from pydantic import BaseModel

from src.scheduler.job_scheduler import get_scheduler

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    scheduler_running: bool
    message: str = "OK"


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for Docker/monitoring."""
    scheduler = get_scheduler()
    scheduler_running = scheduler is not None and scheduler.running

    return HealthResponse(
        status="healthy" if scheduler_running else "degraded",
        scheduler_running=scheduler_running,
        message="OK" if scheduler_running else "Scheduler not running",
    )


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
