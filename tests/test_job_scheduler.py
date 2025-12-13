"""Tests for APScheduler wrapper utilities."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def test_job_listener_logs_exception():
    from src.scheduler import job_scheduler

    event = SimpleNamespace(exception=RuntimeError("boom"), job_id="job1")
    job_scheduler._job_listener(event)


def test_get_jobs_info_formats_jobs():
    from src.scheduler import job_scheduler

    job = SimpleNamespace(
        id="a",
        name="n",
        next_run_time=datetime(2025, 1, 1, tzinfo=timezone.utc),
        trigger="interval[0:15:00]",
    )
    job_scheduler.scheduler = SimpleNamespace(get_jobs=lambda: [job])
    info = job_scheduler.get_jobs_info()
    assert info[0]["id"] == "a"
    assert info[0]["name"] == "n"
    assert "2025" in info[0]["next_run"]


def test_shutdown_scheduler_only_when_running():
    from src.scheduler import job_scheduler

    sched = MagicMock()
    sched.running = True
    job_scheduler.scheduler = sched

    job_scheduler.shutdown_scheduler()
    sched.shutdown.assert_called_once()


def test_start_scheduler_adds_jobs():
    from src.scheduler import job_scheduler

    sched = MagicMock()
    sched.get_jobs.return_value = []

    with patch.object(job_scheduler, "create_scheduler", return_value=sched), \
         patch("src.scanner.port_scanner.run_full_scan", new=AsyncMock()), \
         patch("src.scanner.port_scanner.run_host_check", new=AsyncMock()):
        job_scheduler.settings = SimpleNamespace(scan_interval_hours=2, host_check_interval_minutes=15, data_dir=SimpleNamespace(mkdir=lambda **_: None), jobs_database_url="sqlite://")
        job_scheduler.start_scheduler()

    ids = [call.kwargs.get("id") for call in sched.add_job.call_args_list]
    assert "full_scan" in ids
    assert "host_check" in ids
    assert "initial_scan" in ids


@pytest.mark.asyncio
async def test_trigger_manual_scan_queues_when_scheduler_present():
    from src.scheduler import job_scheduler

    sched = MagicMock()
    job_scheduler.scheduler = sched

    with patch("src.scanner.port_scanner.run_full_scan", new=AsyncMock()):
        msg = await job_scheduler.trigger_manual_scan()

    assert msg == "Manual scan triggered"
    assert sched.add_job.called


@pytest.mark.asyncio
async def test_trigger_manual_scan_runs_direct_when_no_scheduler():
    from src.scheduler import job_scheduler

    job_scheduler.scheduler = None
    run_full_scan = AsyncMock()

    with patch("src.scanner.port_scanner.run_full_scan", new=run_full_scan):
        msg = await job_scheduler.trigger_manual_scan()

    assert msg == "Manual scan completed"
    run_full_scan.assert_awaited()

