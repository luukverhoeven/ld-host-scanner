"""FastAPI web application."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.config import settings
from src.storage.database import init_database
from src.scheduler.job_scheduler import start_scheduler, shutdown_scheduler

logger = logging.getLogger(__name__)

# Base directory for web assets
WEB_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    # Startup
    logger.info("Starting Security Scanner...")

    # Initialize database
    await init_database()
    logger.info("Database initialized")

    # Start scheduler
    start_scheduler()
    logger.info("Scheduler started")

    yield

    # Shutdown
    logger.info("Shutting down Security Scanner...")
    shutdown_scheduler()
    logger.info("Shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="Security Scanner",
    description="Home network port scanner and security monitor",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount static files
static_dir = WEB_DIR / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Setup templates
templates_dir = WEB_DIR / "templates"
templates_dir.mkdir(parents=True, exist_ok=True)
templates = Jinja2Templates(directory=str(templates_dir))

# Import and include routers
from src.web.routes import dashboard, api, health

app.include_router(dashboard.router, tags=["Dashboard"])
app.include_router(api.router, prefix="/api", tags=["API"])
app.include_router(health.router, tags=["Health"])
