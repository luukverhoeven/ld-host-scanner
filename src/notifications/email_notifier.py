"""Email notifications via SMTP."""

import html
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List

import aiosmtplib

from src.config import settings
from src.storage.database import save_notification

logger = logging.getLogger(__name__)


def _build_port_table(ports: List[Dict]) -> str:
    """Build HTML table of ports."""
    if not ports:
        return "<p>No open ports detected.</p>"

    rows = "".join(
        f"<tr>"
        f"<td style='padding: 8px; border: 1px solid #ddd;'>{html.escape(str(p['port']))}</td>"
        f"<td style='padding: 8px; border: 1px solid #ddd;'>{html.escape(str(p['protocol']).upper())}</td>"
        f"<td style='padding: 8px; border: 1px solid #ddd;'>{html.escape(str(p.get('service', 'unknown')))}</td>"
        f"<td style='padding: 8px; border: 1px solid #ddd;'>{html.escape(str(p.get('version', '-')))}</td>"
        f"</tr>"
        for p in ports
    )

    return f"""
    <table style='border-collapse: collapse; width: 100%; margin: 10px 0;'>
        <thead>
            <tr style='background-color: #f4f4f4;'>
                <th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Port</th>
                <th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Protocol</th>
                <th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Service</th>
                <th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Version</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    """


def _build_changes_list(changes: List[Dict]) -> str:
    """Build HTML list of port changes."""
    if not changes:
        return ""

    items = "".join(
        f"<li style='padding: 5px 0;'>"
        f"<strong style='color: {'#d63031' if c['change_type'] == 'opened' else '#27ae60'};'>"
        f"{c['change_type'].upper()}</strong>: "
        f"Port {html.escape(str(c['port']))}/{html.escape(str(c['protocol']))} "
        f"({html.escape(str(c.get('service', 'unknown')))})"
        f"</li>"
        for c in changes
    )

    return f"""
    <h3 style='color: #e74c3c;'>Port Changes Detected</h3>
    <ul style='list-style-type: none; padding: 0;'>
        {items}
    </ul>
    """


async def send_email_alert(
    scan_id: str,
    target: str,
    ports: List[Dict],
    changes: List[Dict],
    host_status: str = "up",
) -> bool:
    """Send email alert about scan results.

    Args:
        scan_id: Unique scan identifier.
        target: Scanned target hostname/IP.
        ports: List of open ports found.
        changes: List of port changes detected.
        host_status: Host status ('up' or 'down').

    Returns:
        True if email sent successfully, False otherwise.
    """
    if not settings.smtp_configured:
        logger.debug("SMTP not configured, skipping email notification")
        return False

    # Build subject
    subject_parts = [f"Security Scan: {target}"]
    if changes:
        subject_parts.append(f"- {len(changes)} changes detected")
    elif ports:
        subject_parts.append(f"- {len(ports)} open ports")
    subject = " ".join(subject_parts)

    # Build HTML content
    status_color = "#27ae60" if host_status == "up" else "#e74c3c"
    safe_target = html.escape(str(target))
    safe_host_status = html.escape(str(host_status).upper())
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
    </head>
    <body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;'>
        <div style='background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px 5px 0 0;'>
            <h1 style='margin: 0;'>Security Scan Report</h1>
        </div>

        <div style='background-color: #f9f9f9; padding: 20px; border: 1px solid #ddd;'>
            <h2 style='margin-top: 0;'>Target: {safe_target}</h2>

            <p>
                <strong>Status:</strong>
                <span style='color: {status_color}; font-weight: bold;'>
                    {safe_host_status}
                </span>
            </p>

            <p><strong>Open Ports:</strong> {len(ports)}</p>

            {_build_changes_list(changes)}

            <h3>Open Ports</h3>
            {_build_port_table(ports)}

            <p style='color: #7f8c8d; font-size: 12px; margin-top: 20px;'>
                Scan ID: {scan_id}
            </p>
        </div>

        <div style='background-color: #ecf0f1; padding: 10px; text-align: center; border-radius: 0 0 5px 5px;'>
            <p style='margin: 0; color: #7f8c8d; font-size: 12px;'>
                Security Scanner - Automated Network Monitoring
            </p>
        </div>
    </body>
    </html>
    """

    # Create message
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = settings.smtp_to
    message.attach(MIMEText(html_content, "html"))

    try:
        await aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            start_tls=True,
        )

        logger.info("Email sent to %s", settings.smtp_to)

        await save_notification(
            notification_type="email",
            status="sent",
            scan_id=scan_id,
            subject=subject,
        )

        return True

    except Exception as e:
        logger.error("Failed to send email: %s", e)

        await save_notification(
            notification_type="email",
            status="failed",
            scan_id=scan_id,
            subject=subject,
            error_message=str(e),
        )

        return False


async def send_host_offline_email(target: str) -> bool:
    """Send email alert when host goes offline.

    Args:
        target: Target hostname/IP that went offline.

    Returns:
        True if email sent successfully, False otherwise.
    """
    if not settings.smtp_configured:
        logger.debug("SMTP not configured, skipping email notification")
        return False

    subject = f"ALERT: {target} is OFFLINE"
    safe_target = html.escape(str(target))

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
    </head>
    <body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;'>
        <div style='background-color: #e74c3c; color: white; padding: 20px; border-radius: 5px 5px 0 0;'>
            <h1 style='margin: 0;'>Host Offline Alert</h1>
        </div>

        <div style='background-color: #f9f9f9; padding: 20px; border: 1px solid #ddd;'>
            <h2 style='margin-top: 0; color: #e74c3c;'>Target: {safe_target}</h2>

            <p style='font-size: 18px;'>
                The monitored host is not responding to network checks.
            </p>

            <p>This could indicate:</p>
            <ul>
                <li>Network connectivity issues</li>
                <li>Host is powered off or rebooting</li>
                <li>Firewall blocking all traffic</li>
                <li>ISP or routing problems</li>
            </ul>
        </div>

        <div style='background-color: #ecf0f1; padding: 10px; text-align: center; border-radius: 0 0 5px 5px;'>
            <p style='margin: 0; color: #7f8c8d; font-size: 12px;'>
                Security Scanner - Automated Network Monitoring
            </p>
        </div>
    </body>
    </html>
    """

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = settings.smtp_to
    message.attach(MIMEText(html_content, "html"))

    try:
        await aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            start_tls=True,
        )

        logger.info("Host offline email sent to %s", settings.smtp_to)

        await save_notification(
            notification_type="email",
            status="sent",
            subject=subject,
        )

        return True

    except Exception as e:
        logger.error("Failed to send host offline email: %s", e)

        await save_notification(
            notification_type="email",
            status="failed",
            subject=subject,
            error_message=str(e),
        )

        return False


async def send_missing_ports_email(target: str, missing_ports: List[Dict]) -> bool:
    """Send email alert when expected ports are not open.

    Args:
        target: Target hostname/IP.
        missing_ports: List of expected ports that are missing/closed.

    Returns:
        True if email sent successfully, False otherwise.
    """
    if not settings.smtp_configured:
        logger.debug("SMTP not configured, skipping email notification")
        return False

    port_list = ", ".join(
        f"{p['port']}/{p['protocol']}" for p in missing_ports
    )
    subject = f"ALERT: Expected ports CLOSED on {target}"

    # Build port table for missing ports
    port_rows = "".join(
        f"<tr>"
        f"<td style='padding: 8px; border: 1px solid #ddd;'>{p['port']}</td>"
        f"<td style='padding: 8px; border: 1px solid #ddd;'>{p['protocol'].upper()}</td>"
        f"</tr>"
        for p in missing_ports
    )

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
    </head>
    <body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;'>
        <div style='background-color: #e74c3c; color: white; padding: 20px; border-radius: 5px 5px 0 0;'>
            <h1 style='margin: 0;'>Expected Ports Alert</h1>
        </div>

        <div style='background-color: #f9f9f9; padding: 20px; border: 1px solid #ddd;'>
            <h2 style='margin-top: 0; color: #e74c3c;'>Target: {target}</h2>

            <p style='font-size: 18px;'>
                The following expected ports are no longer open:
            </p>

            <table style='border-collapse: collapse; width: 100%; margin: 10px 0;'>
                <thead>
                    <tr style='background-color: #f4f4f4;'>
                        <th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Port</th>
                        <th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Protocol</th>
                    </tr>
                </thead>
                <tbody>
                    {port_rows}
                </tbody>
            </table>

            <p>This could indicate:</p>
            <ul>
                <li>Service has stopped or crashed</li>
                <li>Firewall configuration changed</li>
                <li>Service is overloaded or unresponsive</li>
                <li>Network issues blocking specific ports</li>
            </ul>

            <p style='color: #7f8c8d; font-size: 12px; margin-top: 20px;'>
                Expected ports: {port_list}
            </p>
        </div>

        <div style='background-color: #ecf0f1; padding: 10px; text-align: center; border-radius: 0 0 5px 5px;'>
            <p style='margin: 0; color: #7f8c8d; font-size: 12px;'>
                Security Scanner - Automated Network Monitoring
            </p>
        </div>
    </body>
    </html>
    """

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = settings.smtp_to
    message.attach(MIMEText(html_content, "html"))

    try:
        await aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            start_tls=True,
        )

        logger.info("Missing ports email sent to %s", settings.smtp_to)

        await save_notification(
            notification_type="email",
            status="sent",
            subject=subject,
        )

        return True

    except Exception as e:
        logger.error("Failed to send missing ports email: %s", e)

        await save_notification(
            notification_type="email",
            status="failed",
            subject=subject,
            error_message=str(e),
        )

        return False
