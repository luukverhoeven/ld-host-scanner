"""Port scanner using nmap."""

import asyncio
import logging
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional

import nmap

from src.config import settings
from src.storage.database import (
    save_scan,
    save_ports,
    detect_changes,
    get_previous_missing_expected_ports,
    detect_newly_missing_expected_ports,
)
from src.metrics import (
    scans_total,
    scan_duration_seconds,
    open_ports_count,
    port_changes_total,
    expected_ports_missing,
    expected_port_status,
    host_online_status,
)

logger = logging.getLogger(__name__)


class PortScanner:
    """Nmap-based port scanner."""

    def __init__(self):
        """Initialize the port scanner."""
        self.nm = nmap.PortScanner()

    def check_host_online(self, target: str) -> bool:
        """Quick ping check to see if host is online.

        Args:
            target: Hostname or IP address to check.

        Returns:
            True if host responds to ping, False otherwise.
        """
        try:
            # -sn: Ping scan (no port scan)
            # -PE: ICMP echo request
            self.nm.scan(hosts=target, arguments="-sn -PE")
            return target in self.nm.all_hosts()
        except nmap.PortScannerError as e:
            logger.error("Host check failed: %s", e)
            return False
        except Exception as e:
            logger.error("Unexpected error during host check: %s", e)
            return False

    def scan_tcp(
        self,
        target: str,
        ports: str = "1-65535",
    ) -> Dict:
        """Full TCP SYN scan.

        Args:
            target: Hostname or IP address to scan.
            ports: Port range to scan (default: all ports).

        Returns:
            Dictionary with host_status and list of discovered ports.
        """
        try:
            logger.info("Starting TCP scan of %s (ports %s)", target, ports)

            # Build arguments dynamically from config
            # -sS: SYN scan (fast, stealthy)
            # -sV: Version detection
            # -T{n}: Timing template (3-5)
            # --open: Only show open ports
            # --max-retries: Limit retries for faster scan
            # --min-rate: Minimum packets per second
            # --host-timeout: Max time per host
            args = (
                f"-sS -sV -T{settings.scan_timing} --open "
                f"--max-retries {settings.scan_max_retries}"
            )
            if settings.scan_min_rate > 0:
                args += f" --min-rate {settings.scan_min_rate}"
            args += f" --host-timeout {settings.scan_host_timeout}"

            self.nm.scan(
                hosts=target,
                ports=ports,
                arguments=args,
            )

            return self._parse_results(target, "tcp")

        except nmap.PortScannerError as e:
            logger.error("TCP scan failed: %s", e)
            raise
        except Exception as e:
            logger.error("Unexpected error during TCP scan: %s", e)
            raise

    def scan_udp(
        self,
        target: str,
        ports: str = "1-1000",
    ) -> Dict:
        """UDP scan (slower, scans top 1000 ports by default).

        Args:
            target: Hostname or IP address to scan.
            ports: Port range to scan (default: top 1000).

        Returns:
            Dictionary with host_status and list of discovered ports.
        """
        try:
            logger.info("Starting UDP scan of %s (ports %s)", target, ports)

            # Build arguments dynamically from config
            # -sU: UDP scan
            # -sV: Version detection
            # -T{n}: Timing template (3-5)
            # --open: Only show open ports
            # --max-retries: Limit retries (UDP is slow, keep at 1)
            # --min-rate: Use half of TCP rate for UDP
            # --host-timeout: Max time per host
            args = (
                f"-sU -sV -T{settings.scan_timing} --open "
                f"--max-retries 1"
            )
            if settings.scan_min_rate > 0:
                # Use lower rate for UDP (it's inherently slower)
                udp_rate = max(100, settings.scan_min_rate // 2)
                args += f" --min-rate {udp_rate}"
            args += f" --host-timeout {settings.scan_host_timeout}"

            self.nm.scan(
                hosts=target,
                ports=ports,
                arguments=args,
            )

            return self._parse_results(target, "udp")

        except nmap.PortScannerError as e:
            logger.error("UDP scan failed: %s", e)
            raise
        except Exception as e:
            logger.error("Unexpected error during UDP scan: %s", e)
            raise

    def _parse_results(self, target: str, protocol: str) -> Dict:
        """Parse nmap scan results into structured data.

        Args:
            target: The scanned target.
            protocol: Protocol scanned ('tcp' or 'udp').

        Returns:
            Dictionary with host_status and list of port dictionaries.
        """
        results = {
            "host_status": "down",
            "ports": [],
        }

        # Check if target was found
        if target not in self.nm.all_hosts():
            # Try to find by resolved IP
            for host in self.nm.all_hosts():
                if self.nm[host].hostname() == target:
                    target = host
                    break
            else:
                logger.warning("Target %s not found in scan results", target)
                return results

        host = self.nm[target]
        results["host_status"] = host.state()

        # Extract port information
        if protocol in host.all_protocols():
            for port_num in host[protocol].keys():
                port_info = host[protocol][port_num]
                results["ports"].append({
                    "port": port_num,
                    "protocol": protocol,
                    "state": port_info.get("state", "unknown"),
                    "service": port_info.get("name", "unknown"),
                    "version": port_info.get("version", ""),
                })

        logger.info(
            "Found %d %s ports on %s (host: %s)",
            len(results["ports"]),
            protocol.upper(),
            target,
            results["host_status"],
        )

        return results


async def scan_tcp_parallel(target: str, workers: int = 4) -> Dict:
    """Scan TCP ports in parallel batches for faster scanning.

    Args:
        target: Hostname or IP address to scan.
        workers: Number of parallel nmap processes.

    Returns:
        Dictionary with host_status and list of discovered ports.
    """
    total_ports = 65535
    batch_size = total_ports // workers

    async def scan_batch(start: int, end: int) -> tuple:
        """Scan a single batch of ports."""
        scanner = PortScanner()  # Each batch needs own scanner instance
        result = await asyncio.to_thread(
            scanner.scan_tcp, target, f"{start}-{end}"
        )
        return result["ports"], result["host_status"]

    # Create batch tasks
    tasks = []
    for i in range(workers):
        start = i * batch_size + 1
        end = (i + 1) * batch_size if i < workers - 1 else total_ports
        tasks.append(scan_batch(start, end))

    logger.info(
        "Starting parallel TCP scan of %s with %d workers",
        target, workers
    )

    # Run all batches concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Merge results
    all_ports = []
    host_status = "down"
    for result in results:
        if isinstance(result, Exception):
            logger.error("Batch scan failed: %s", result)
            continue
        ports, status = result
        all_ports.extend(ports)
        if status == "up":
            host_status = "up"

    logger.info(
        "Parallel TCP scan completed. Found %d ports across %d batches",
        len(all_ports), workers
    )

    return {"host_status": host_status, "ports": all_ports}


def check_expected_ports(
    all_ports: List[Dict],
    expected: List[Dict],
) -> List[Dict]:
    """Check which expected ports are missing from scan results.

    Args:
        all_ports: List of discovered open ports.
        expected: List of expected ports to check.

    Returns:
        List of expected ports that are missing/closed.
    """
    open_ports = {(p["port"], p["protocol"]) for p in all_ports}
    missing = []
    for exp in expected:
        if (exp["port"], exp["protocol"]) not in open_ports:
            missing.append(exp)
    return missing


def update_expected_ports_metrics(
    target: str,
    expected_ports: List[Dict],
    missing_ports: List[Dict],
) -> None:
    """Update Prometheus metrics for expected ports.

    Args:
        target: Target hostname.
        expected_ports: List of configured expected ports.
        missing_ports: List of expected ports that are currently missing.
    """
    missing_set = {(p["port"], p["protocol"]) for p in missing_ports}

    # Update per-port status metrics
    for exp in expected_ports:
        is_open = (exp["port"], exp["protocol"]) not in missing_set
        expected_port_status.labels(
            target=target,
            port=str(exp["port"]),
            protocol=exp["protocol"],
        ).set(1 if is_open else 0)

    # Update total missing count
    expected_ports_missing.labels(target=target).set(len(missing_ports))


async def run_full_scan() -> Optional[str]:
    """Execute full TCP and UDP scan.

    Returns:
        Scan ID if successful, None if failed.
    """
    # Import here to avoid circular imports
    from src.notifications.notifier import (
        send_notifications,
        send_missing_ports_notification,
    )

    scan_id = str(uuid.uuid4())
    target = settings.target_host
    started_at = datetime.utcnow()
    start_time = time.time()

    logger.info("Starting full scan %s for %s", scan_id, target)

    scanner = PortScanner()

    try:
        # Save scan as running
        await save_scan(scan_id, target, "full", started_at, "running")

        # Run TCP and UDP scans concurrently for faster execution
        # TCP uses parallel batches if workers > 1
        if settings.scan_workers > 1:
            tcp_task = scan_tcp_parallel(target, settings.scan_workers)
        else:
            tcp_task = asyncio.to_thread(
                scanner.scan_tcp, target, "1-65535"
            )

        # UDP scan (top 1000 ports - UDP is inherently slow)
        udp_task = asyncio.to_thread(
            scanner.scan_udp, target, "1-1000"
        )

        # Execute both scans concurrently
        tcp_results, udp_results = await asyncio.gather(tcp_task, udp_task)

        # Combine results
        all_ports = tcp_results["ports"] + udp_results["ports"]
        host_status = tcp_results["host_status"]

        # Save ports to database
        await save_ports(scan_id, all_ports)

        # Detect changes from previous scan
        changes = await detect_changes(scan_id, target)

        # Update scan status
        await save_scan(
            scan_id,
            target,
            "full",
            started_at,
            "completed",
            host_status=host_status,
            completed_at=datetime.utcnow(),
        )

        # Record scan duration metric
        duration = time.time() - start_time
        scan_duration_seconds.labels(scan_type="full").observe(duration)

        # Update port count metrics
        tcp_ports = [p for p in all_ports if p["protocol"] == "tcp"]
        udp_ports = [p for p in all_ports if p["protocol"] == "udp"]
        open_ports_count.labels(target=target, protocol="tcp").set(len(tcp_ports))
        open_ports_count.labels(target=target, protocol="udp").set(len(udp_ports))

        # Update host status metric
        host_online_status.labels(target=target).set(1 if host_status == "up" else 0)

        # Update port changes metrics
        for change in changes:
            port_changes_total.labels(change_type=change["change_type"]).inc()

        # Record successful scan metric
        scans_total.labels(status="completed", target=target).inc()

        # Send notifications if any open ports or changes detected
        if all_ports or changes:
            await send_notifications(scan_id, target, all_ports, changes, host_status)

        # Check expected ports (only if configured)
        if settings.expected_ports_configured:
            expected_ports = settings.expected_ports_list
            missing_ports = check_expected_ports(all_ports, expected_ports)

            # Update expected ports metrics
            update_expected_ports_metrics(target, expected_ports, missing_ports)

            # Get previously missing ports to detect changes
            previous_missing = await get_previous_missing_expected_ports(
                target, scan_id, expected_ports
            )

            # Find newly missing ports (state changed from open to closed)
            newly_missing = detect_newly_missing_expected_ports(
                missing_ports, previous_missing
            )

            # Only notify for newly missing ports (not every scan)
            if newly_missing:
                logger.warning(
                    "Expected ports newly missing: %s",
                    ", ".join(f"{p['port']}/{p['protocol']}" for p in newly_missing),
                )
                await send_missing_ports_notification(target, newly_missing)
            elif missing_ports:
                logger.info(
                    "Expected ports still missing (no change): %s",
                    ", ".join(f"{p['port']}/{p['protocol']}" for p in missing_ports),
                )

        logger.info(
            "Scan %s completed in %.1fs. Found %d open ports, %d changes",
            scan_id,
            duration,
            len(all_ports),
            len(changes),
        )

        return scan_id

    except Exception as e:
        logger.error("Scan %s failed: %s", scan_id, e)
        scans_total.labels(status="failed", target=target).inc()
        await save_scan(
            scan_id,
            target,
            "full",
            started_at,
            "failed",
            error_message=str(e),
            completed_at=datetime.utcnow(),
        )
        return None


async def run_host_check() -> bool:
    """Quick host online/offline check.

    Returns:
        True if host is online, False otherwise.
    """
    # Import here to avoid circular imports
    from src.notifications.notifier import send_host_status_notification

    target = settings.target_host
    scanner = PortScanner()

    is_online = await asyncio.to_thread(scanner.check_host_online, target)

    # Update host status metric
    host_online_status.labels(target=target).set(1 if is_online else 0)

    logger.info("Host check for %s: %s", target, "online" if is_online else "offline")

    # Send notification if host is offline
    if not is_online:
        await send_host_status_notification(target, "offline")

    return is_online
