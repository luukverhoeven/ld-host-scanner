"""Main notification orchestrator."""

import logging
from typing import Dict, List

from src.notifications.email_notifier import (
    send_email_alert,
    send_host_offline_email,
    send_missing_ports_email,
)
from src.notifications.webhook_notifier import (
    send_webhook_alert,
    send_host_offline_webhook,
    send_missing_ports_webhook,
)
from src.metrics import notifications_sent_total, notifications_failed_total

logger = logging.getLogger(__name__)


async def send_notifications(
    scan_id: str,
    target: str,
    ports: List[Dict],
    changes: List[Dict],
    host_status: str = "up",
) -> None:
    """Send notifications through all configured channels.

    Args:
        scan_id: Unique scan identifier.
        target: Scanned target hostname/IP.
        ports: List of open ports found.
        changes: List of port changes detected.
        host_status: Host status ('up' or 'down').
    """
    results = []

    # Send email notification
    email_result = await send_email_alert(
        scan_id=scan_id,
        target=target,
        ports=ports,
        changes=changes,
        host_status=host_status,
    )
    results.append(("email", email_result))

    # Send webhook notification
    webhook_result = await send_webhook_alert(
        scan_id=scan_id,
        target=target,
        ports=ports,
        changes=changes,
        host_status=host_status,
    )
    results.append(("webhook", webhook_result))

    # Log results and update metrics
    sent = [name for name, success in results if success]
    failed = [name for name, success in results if not success]

    for name, success in results:
        if success:
            notifications_sent_total.labels(channel=name, type="scan").inc()
        else:
            notifications_failed_total.labels(channel=name, type="scan").inc()

    if sent:
        logger.info("Notifications sent via: %s", ", ".join(sent))
    if failed:
        logger.warning("Notifications failed/skipped: %s", ", ".join(failed))


async def send_host_status_notification(target: str, status: str) -> None:
    """Send host status change notification.

    Args:
        target: Target hostname/IP.
        status: Current status ('online' or 'offline').
    """
    if status == "offline":
        # Send offline alerts
        email_result = await send_host_offline_email(target)
        webhook_result = await send_host_offline_webhook(target)

        # Update metrics
        if email_result:
            notifications_sent_total.labels(channel="email", type="host_offline").inc()
        else:
            notifications_failed_total.labels(channel="email", type="host_offline").inc()

        if webhook_result:
            notifications_sent_total.labels(channel="webhook", type="host_offline").inc()
        else:
            notifications_failed_total.labels(channel="webhook", type="host_offline").inc()

        logger.warning("Host offline notifications sent for %s", target)
    else:
        # Could add "back online" notifications here in the future
        logger.info("Host %s is %s", target, status)


async def send_missing_ports_notification(target: str, missing_ports: List[Dict]) -> None:
    """Send notification when expected ports are missing/closed.

    Args:
        target: Target hostname/IP.
        missing_ports: List of expected ports that are missing/closed.
    """
    # Send email notification
    email_result = await send_missing_ports_email(target, missing_ports)

    # Send webhook notification
    webhook_result = await send_missing_ports_webhook(target, missing_ports)

    # Update metrics
    if email_result:
        notifications_sent_total.labels(channel="email", type="missing_ports").inc()
    else:
        notifications_failed_total.labels(channel="email", type="missing_ports").inc()

    if webhook_result:
        notifications_sent_total.labels(channel="webhook", type="missing_ports").inc()
    else:
        notifications_failed_total.labels(channel="webhook", type="missing_ports").inc()

    port_list = ", ".join(f"{p['port']}/{p['protocol']}" for p in missing_ports)
    logger.warning("Missing ports notifications sent for %s: %s", target, port_list)
