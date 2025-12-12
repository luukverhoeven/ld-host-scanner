"""Main notification orchestrator."""

import logging
from typing import Dict, List

from src.notifications.email_notifier import send_email_alert, send_host_offline_email
from src.notifications.webhook_notifier import send_webhook_alert, send_host_offline_webhook

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

    # Log results
    sent = [name for name, success in results if success]
    failed = [name for name, success in results if not success]

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
        await send_host_offline_email(target)
        await send_host_offline_webhook(target)
        logger.warning("Host offline notifications sent for %s", target)
    else:
        # Could add "back online" notifications here in the future
        logger.info("Host %s is %s", target, status)
