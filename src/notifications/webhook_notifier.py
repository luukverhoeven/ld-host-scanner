"""Webhook notifications for Discord and Slack."""

import logging
from datetime import datetime
from typing import Dict, List

import httpx

from src.config import settings
from src.storage.database import save_notification

logger = logging.getLogger(__name__)


def _build_discord_embed(
    scan_id: str,
    target: str,
    ports: List[Dict],
    changes: List[Dict],
    host_status: str,
) -> Dict:
    """Build Discord embed format."""
    # Color: red if changes, orange if ports found, green if clean
    if changes:
        color = 16711680  # Red
    elif ports:
        color = 16744192  # Orange
    else:
        color = 65280  # Green

    fields = [
        {
            "name": "Host Status",
            "value": host_status.upper(),
            "inline": True,
        },
        {
            "name": "Open Ports",
            "value": str(len(ports)),
            "inline": True,
        },
        {
            "name": "Changes",
            "value": str(len(changes)),
            "inline": True,
        },
    ]

    # Add port list if not too many
    if ports and len(ports) <= 15:
        port_list = "\n".join(
            f"`{p['port']}/{p['protocol']}` - {p.get('service', 'unknown')}"
            for p in ports[:15]
        )
        fields.append({
            "name": "Detected Ports",
            "value": port_list,
            "inline": False,
        })

    # Add changes if any
    if changes:
        change_list = "\n".join(
            f"{'🔴' if c['change_type'] == 'opened' else '🟢'} "
            f"**{c['change_type'].upper()}**: {c['port']}/{c['protocol']}"
            for c in changes[:10]
        )
        fields.append({
            "name": "Port Changes",
            "value": change_list,
            "inline": False,
        })

    return {
        "embeds": [{
            "title": "Security Scan Alert",
            "description": f"**Target:** `{target}`",
            "color": color,
            "timestamp": datetime.utcnow().isoformat(),
            "fields": fields,
            "footer": {
                "text": f"Scan ID: {scan_id}",
            },
        }],
    }


def _build_slack_payload(
    scan_id: str,
    target: str,
    ports: List[Dict],
    changes: List[Dict],
    host_status: str,
) -> Dict:
    """Build Slack message format."""
    # Color: red if changes, orange if ports found, green if clean
    if changes:
        color = "#FF0000"  # Red
    elif ports:
        color = "#FFA500"  # Orange
    else:
        color = "#00FF00"  # Green

    fields = [
        {
            "title": "Host Status",
            "value": host_status.upper(),
            "short": True,
        },
        {
            "title": "Open Ports",
            "value": str(len(ports)),
            "short": True,
        },
    ]

    if changes:
        change_text = "\n".join(
            f"• {c['change_type'].upper()}: {c['port']}/{c['protocol']}"
            for c in changes[:10]
        )
        fields.append({
            "title": "Port Changes",
            "value": change_text,
            "short": False,
        })

    if ports and len(ports) <= 10:
        port_text = "\n".join(
            f"• {p['port']}/{p['protocol']} ({p.get('service', 'unknown')})"
            for p in ports[:10]
        )
        fields.append({
            "title": "Detected Ports",
            "value": port_text,
            "short": False,
        })

    return {
        "attachments": [{
            "color": color,
            "title": f"Security Scan: {target}",
            "fields": fields,
            "footer": f"Scan ID: {scan_id}",
            "ts": int(datetime.utcnow().timestamp()),
        }],
    }


def _is_slack_webhook(url: str) -> bool:
    """Detect if webhook URL is for Slack."""
    return "slack.com" in url or "hooks.slack" in url


async def send_webhook_alert(
    scan_id: str,
    target: str,
    ports: List[Dict],
    changes: List[Dict],
    host_status: str = "up",
) -> bool:
    """Send webhook alert (Discord/Slack compatible).

    Args:
        scan_id: Unique scan identifier.
        target: Scanned target hostname/IP.
        ports: List of open ports found.
        changes: List of port changes detected.
        host_status: Host status ('up' or 'down').

    Returns:
        True if webhook sent successfully, False otherwise.
    """
    if not settings.webhook_configured:
        logger.debug("Webhook not configured, skipping notification")
        return False

    webhook_url = settings.webhook_url

    # Build payload based on webhook type
    if _is_slack_webhook(webhook_url):
        payload = _build_slack_payload(scan_id, target, ports, changes, host_status)
    else:
        # Default to Discord format
        payload = _build_discord_embed(scan_id, target, ports, changes, host_status)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook_url,
                json=payload,
                timeout=10.0,
            )
            response.raise_for_status()

        logger.info("Webhook notification sent")

        await save_notification(
            notification_type="webhook",
            status="sent",
            scan_id=scan_id,
            message=f"Sent to {'Slack' if _is_slack_webhook(webhook_url) else 'Discord'}",
        )

        return True

    except httpx.HTTPStatusError as e:
        logger.error("Webhook HTTP error: %s - %s", e.response.status_code, e.response.text)

        await save_notification(
            notification_type="webhook",
            status="failed",
            scan_id=scan_id,
            error_message=f"HTTP {e.response.status_code}: {e.response.text[:200]}",
        )

        return False

    except Exception as e:
        logger.error("Failed to send webhook: %s", e)

        await save_notification(
            notification_type="webhook",
            status="failed",
            scan_id=scan_id,
            error_message=str(e),
        )

        return False


async def send_host_offline_webhook(target: str) -> bool:
    """Send webhook alert when host goes offline.

    Args:
        target: Target hostname/IP that went offline.

    Returns:
        True if webhook sent successfully, False otherwise.
    """
    if not settings.webhook_configured:
        logger.debug("Webhook not configured, skipping notification")
        return False

    webhook_url = settings.webhook_url

    if _is_slack_webhook(webhook_url):
        payload = {
            "attachments": [{
                "color": "#FF0000",
                "title": f"ALERT: {target} is OFFLINE",
                "text": "The monitored host is not responding to network checks.",
                "fields": [
                    {"title": "Target", "value": target, "short": True},
                    {"title": "Status", "value": "OFFLINE", "short": True},
                ],
                "ts": int(datetime.utcnow().timestamp()),
            }],
        }
    else:
        payload = {
            "embeds": [{
                "title": "Host Offline Alert",
                "description": f"**{target}** is not responding to network checks.",
                "color": 16711680,  # Red
                "timestamp": datetime.utcnow().isoformat(),
                "fields": [
                    {"name": "Target", "value": f"`{target}`", "inline": True},
                    {"name": "Status", "value": "OFFLINE", "inline": True},
                ],
            }],
        }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook_url,
                json=payload,
                timeout=10.0,
            )
            response.raise_for_status()

        logger.info("Host offline webhook sent")

        await save_notification(
            notification_type="webhook",
            status="sent",
            message=f"Host offline alert for {target}",
        )

        return True

    except Exception as e:
        logger.error("Failed to send host offline webhook: %s", e)

        await save_notification(
            notification_type="webhook",
            status="failed",
            error_message=str(e),
        )

        return False
