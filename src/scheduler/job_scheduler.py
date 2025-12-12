"""Job scheduler using APScheduler."""

import logging
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED, JobExecutionEvent

from src.config import settings

logger = logging.getLogger(__name__)

# Global scheduler instance
scheduler: Optional[AsyncIOScheduler] = None


def _job_listener(event: JobExecutionEvent) -> None:
    """Listen for job execution events."""
    if event.exception:
        logger.error(
            "Job %s failed with exception: %s",
            event.job_id,
            event.exception,
        )
    else:
        logger.info("Job %s executed successfully", event.job_id)


def create_scheduler() -> AsyncIOScheduler:
    """Create and configure the scheduler.

    Returns:
        Configured AsyncIOScheduler instance.
    """
    # Ensure data directory exists
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    # Configure job stores
    jobstores = {
        "default": SQLAlchemyJobStore(url=settings.jobs_database_url),
    }

    # Configure job defaults
    job_defaults = {
        "coalesce": True,  # Combine missed jobs into one
        "max_instances": 1,  # Only one instance of each job at a time
        "misfire_grace_time": 3600,  # Allow 1 hour grace for misfired jobs
    }

    return AsyncIOScheduler(
        jobstores=jobstores,
        job_defaults=job_defaults,
        timezone="UTC",
    )


def start_scheduler() -> None:
    """Start the scheduler with configured jobs."""
    global scheduler

    # Import here to avoid circular imports
    from src.scanner.port_scanner import run_full_scan, run_host_check

    scheduler = create_scheduler()

    # Add job execution listener
    scheduler.add_listener(_job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)

    # Main full scan job - every N hours
    scheduler.add_job(
        run_full_scan,
        trigger=IntervalTrigger(hours=settings.scan_interval_hours),
        id="full_scan",
        name="Full Port Scan",
        replace_existing=True,
    )
    logger.info(
        "Scheduled full scan every %d hours",
        settings.scan_interval_hours,
    )

    # Quick host check - every 15 minutes
    scheduler.add_job(
        run_host_check,
        trigger=IntervalTrigger(minutes=15),
        id="host_check",
        name="Host Online Check",
        replace_existing=True,
    )
    logger.info("Scheduled host check every 15 minutes")

    # Run initial scan shortly after startup (30 seconds delay)
    scheduler.add_job(
        run_full_scan,
        trigger="date",
        id="initial_scan",
        name="Initial Scan on Startup",
        replace_existing=True,
    )
    logger.info("Scheduled initial scan on startup")

    # Start the scheduler
    scheduler.start()
    logger.info(
        "Scheduler started with %d jobs",
        len(scheduler.get_jobs()),
    )


def shutdown_scheduler() -> None:
    """Gracefully shutdown the scheduler."""
    global scheduler

    if scheduler and scheduler.running:
        scheduler.shutdown(wait=True)
        logger.info("Scheduler shutdown complete")


def get_scheduler() -> Optional[AsyncIOScheduler]:
    """Get the current scheduler instance.

    Returns:
        The scheduler instance or None if not started.
    """
    return scheduler


def get_jobs_info() -> list:
    """Get information about scheduled jobs.

    Returns:
        List of job information dictionaries.
    """
    if not scheduler:
        return []

    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            "id": job.id,
            "name": job.name,
            "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            "trigger": str(job.trigger),
        })

    return jobs


async def trigger_manual_scan() -> str:
    """Trigger an immediate manual scan.

    Returns:
        Message indicating scan was triggered.
    """
    from src.scanner.port_scanner import run_full_scan

    if scheduler:
        # Add a one-time job to run immediately
        scheduler.add_job(
            run_full_scan,
            trigger="date",
            id="manual_scan",
            name="Manual Scan",
            replace_existing=True,
        )
        return "Manual scan triggered"
    else:
        # Run directly if scheduler not available
        await run_full_scan()
        return "Manual scan completed"
