"""Lightweight host status checker."""

import asyncio
import logging
import socket
from typing import List, Optional

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
        loop = asyncio.get_running_loop()
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
    writer = None
    try:
        future = asyncio.open_connection(target, port)
        reader, writer = await asyncio.wait_for(future, timeout=timeout)
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
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass  # Ignore cleanup errors


async def check_host_ping(target: str, timeout: float = 2.0, count: int = 1) -> bool:
    """Check if host is reachable via ICMP ping using system ping command.

    Uses the system ping command which is more reliable than icmplib in Docker
    containers with NET_RAW capability.

    Args:
        target: Hostname or IP address.
        timeout: Ping timeout in seconds.
        count: Number of ping packets to send.

    Returns:
        True if host responds to ping, False otherwise.
    """
    import platform
    import shutil

    ping_cmd = shutil.which("ping")
    if not ping_cmd:
        logger.warning("ping command not found in PATH")
        return False

    try:
        # Platform-specific timeout args:
        # Linux uses -W (seconds), macOS uses -W (milliseconds)
        if platform.system() == "Darwin":
            timeout_ms = int(timeout * 1000)
            cmd = [ping_cmd, "-c", str(count), "-W", str(timeout_ms), target]
        else:
            # Linux
            cmd = [ping_cmd, "-c", str(count), "-W", str(int(timeout)), target]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        returncode = await proc.wait()

        if returncode == 0:
            logger.debug("Ping to %s successful", target)
            return True
        else:
            logger.debug("Ping to %s failed (exit code %d)", target, returncode)
            return False
    except Exception as e:
        logger.debug("Ping to %s failed: %s", target, e)
        return False


async def quick_host_check(target: Optional[str] = None) -> dict:
    """Perform quick host status check.

    Tries multiple methods to determine if host is reachable:
    1. DNS resolution
    2. ICMP ping (fast, tried first)
    3. TCP connect fallback (for hosts that block ICMP)

    Args:
        target: Hostname or IP to check. Defaults to configured target.

    Returns:
        Dictionary with check results.
    """
    # Import here to avoid circular imports
    from src.storage.database import get_open_ports_from_last_scan

    if target is None:
        target = settings.target_host

    result = {
        "target": target,
        "dns_resolved": False,
        "ip_address": None,
        "ping_reachable": False,
        "tcp_reachable": False,
        "status": "unknown",
        "method": None,  # How status was determined: icmp, tcp, dns, or None
    }

    # Try DNS resolution
    ip = await check_host_dns(target)
    if ip:
        result["dns_resolved"] = True
        result["ip_address"] = ip

    # Try ICMP ping first (fastest method)
    if await check_host_ping(target):
        result["ping_reachable"] = True
    else:
        # Ping failed, fall back to TCP connect check
        # Get ports from last successful scan, fallback to common ports
        discovered_ports = await get_open_ports_from_last_scan(target)
        common_ports = [443, 80, 22, 8080]

        # Prioritize discovered ports, then add common ports as fallback
        # Use set to avoid duplicates, limit to 8 ports for speed
        ports_to_check: List[int] = []
        for port in discovered_ports[:5]:
            if port not in ports_to_check:
                ports_to_check.append(port)
        for port in common_ports:
            if port not in ports_to_check and len(ports_to_check) < 8:
                ports_to_check.append(port)

        logger.debug("Ping failed, trying TCP on ports: %s", ports_to_check)

        # Try TCP connect to ports
        for port in ports_to_check:
            if await check_host_tcp_connect(target, port):
                result["tcp_reachable"] = True
                break

    # Determine overall status and method
    if result["ping_reachable"]:
        result["status"] = "online"
        result["method"] = "icmp"
    elif result["tcp_reachable"]:
        result["status"] = "online"
        result["method"] = "tcp"
    elif result["dns_resolved"]:
        result["status"] = "dns_only"  # DNS works but no ping/TCP response
        result["method"] = "dns"
    else:
        result["status"] = "offline"
        # method stays None for offline

    logger.info(
        "Quick check for %s: %s (DNS: %s, Ping: %s, TCP: %s)",
        target,
        result["status"],
        result["dns_resolved"],
        result["ping_reachable"],
        result["tcp_reachable"],
    )

    return result
