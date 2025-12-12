"""Lightweight host status checker."""

import asyncio
import logging
import socket
from typing import Optional

from src.config import settings

logger = logging.getLogger(__name__)


async def check_host_dns(target: str) -> Optional[str]:
    """Resolve hostname to IP address.

    Args:
        target: Hostname to resolve.

    Returns:
        IP address if resolved, None otherwise.
    """
    try:
        loop = asyncio.get_event_loop()
        result = await loop.getaddrinfo(
            target,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
        if result:
            ip = result[0][4][0]
            logger.debug("Resolved %s to %s", target, ip)
            return ip
    except socket.gaierror as e:
        logger.warning("DNS resolution failed for %s: %s", target, e)
    except Exception as e:
        logger.error("Unexpected error resolving %s: %s", target, e)
    return None


async def check_host_tcp_connect(
    target: str,
    port: int = 443,
    timeout: float = 5.0,
) -> bool:
    """Check if host is reachable via TCP connect.

    This is a lightweight alternative to nmap ping when
    ICMP is blocked but common ports are open.

    Args:
        target: Hostname or IP address.
        port: Port to try connecting to.
        timeout: Connection timeout in seconds.

    Returns:
        True if connection successful, False otherwise.
    """
    try:
        loop = asyncio.get_event_loop()
        future = asyncio.open_connection(target, port)
        reader, writer = await asyncio.wait_for(future, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        logger.debug("TCP connect to %s:%d successful", target, port)
        return True
    except asyncio.TimeoutError:
        logger.debug("TCP connect to %s:%d timed out", target, port)
        return False
    except ConnectionRefusedError:
        # Connection refused means host is up, port is closed
        logger.debug("TCP connect to %s:%d refused (host is up)", target, port)
        return True
    except Exception as e:
        logger.debug("TCP connect to %s:%d failed: %s", target, port, e)
        return False


async def quick_host_check(target: Optional[str] = None) -> dict:
    """Perform quick host status check.

    Tries multiple methods to determine if host is reachable:
    1. DNS resolution
    2. TCP connect to common ports (443, 80, 22)

    Args:
        target: Hostname or IP to check. Defaults to configured target.

    Returns:
        Dictionary with check results.
    """
    if target is None:
        target = settings.target_host

    result = {
        "target": target,
        "dns_resolved": False,
        "ip_address": None,
        "tcp_reachable": False,
        "status": "unknown",
    }

    # Try DNS resolution
    ip = await check_host_dns(target)
    if ip:
        result["dns_resolved"] = True
        result["ip_address"] = ip

    # Try TCP connect to common ports
    common_ports = [443, 80, 22, 8080]
    for port in common_ports:
        if await check_host_tcp_connect(target, port):
            result["tcp_reachable"] = True
            break

    # Determine overall status
    if result["tcp_reachable"]:
        result["status"] = "online"
    elif result["dns_resolved"]:
        result["status"] = "dns_only"  # DNS works but no TCP response
    else:
        result["status"] = "offline"

    logger.info(
        "Quick check for %s: %s (DNS: %s, TCP: %s)",
        target,
        result["status"],
        result["dns_resolved"],
        result["tcp_reachable"],
    )

    return result
