"""Port scanner using Rustscan (TCP) and nmap (UDP)."""

import asyncio
import logging
import subprocess
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional

import nmap

from src.config import settings
from src.scanner.services import get_common_service_name
from src.storage.database import (
    save_scan,
    save_ports,
    detect_changes,
    get_previous_missing_expected_ports,
    detect_newly_missing_expected_ports,
    update_scan_progress,
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
    """Port scanner using Rustscan (TCP) and nmap (UDP)."""

    def __init__(self):
        """Initialize the port scanner."""
        self.nm = nmap.PortScanner()

    @staticmethod
    def _version_detection_args(intensity: str) -> str:
        """Build nmap version detection args for a given intensity."""
        if intensity == "light":
            return "-sV --version-light"
        if intensity == "thorough":
            return "-sV --version-all"
        return "-sV"

    def _find_nmap_target_key(self, target: str) -> Optional[str]:
        """Resolve the target key used in python-nmap results."""
        if target in self.nm.all_hosts():
            return target

        for host in self.nm.all_hosts():
            if self.nm[host].hostname() == target:
                return host

        return None

    def scan_tcp_rustscan(self, target: str, ports: str = "1-65535") -> Dict:
        """TCP scan using Rustscan for speed.

        Rustscan is significantly faster than nmap for port discovery,
        scanning all 65535 ports in seconds rather than minutes.

        Args:
            target: Hostname or IP address to scan.
            ports: Port range to scan (default: all ports).

        Returns:
            Dictionary with host_status and list of discovered ports.
        """
        try:
            logger.info("Starting Rustscan TCP scan of %s (ports %s)", target, ports)

            # Build Rustscan command
            # -a: target address
            # -r: port range
            # -g: greppable output (hostname -> [port1, port2, ...])
            # -t: timeout per port in ms
            # -b: batch size (concurrent connections)
            # --ulimit: file descriptor limit
            cmd = [
                "rustscan",
                "-a", target,
                "-r", ports,
                "-g",
                "-t", str(settings.rustscan_timeout),
                "-b", str(settings.rustscan_batch_size),
                "--ulimit", str(settings.rustscan_ulimit),
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute max timeout
            )

            if result.returncode != 0 and result.stderr:
                logger.warning("Rustscan stderr: %s", result.stderr.strip())

            return self._parse_rustscan_output(target, result.stdout)

        except subprocess.TimeoutExpired:
            logger.error("Rustscan timed out for %s", target)
            raise
        except FileNotFoundError:
            logger.error("Rustscan not found. Is it installed?")
            raise
        except Exception as e:
            logger.error("Rustscan failed: %s", e)
            raise

    def _parse_rustscan_output(self, target: str, output: str) -> Dict:
        """Parse Rustscan greppable output.

        Greppable format: hostname -> [port1, port2, port3]

        Args:
            target: The scanned target.
            output: Rustscan stdout output.

        Returns:
            Dictionary with host_status and list of port dictionaries.
        """
        results = {"host_status": "down", "ports": []}

        if not output or not output.strip():
            logger.warning("No output from Rustscan for %s", target)
            return results

        for line in output.strip().split("\n"):
            if "->" in line:
                results["host_status"] = "up"
                # Parse: "hostname -> [80, 443, 8080]"
                parts = line.split("->")
                if len(parts) == 2:
                    ports_str = parts[1].strip().strip("[]")
                    if ports_str:
                        for port_str in ports_str.split(","):
                            port_str = port_str.strip()
                            if port_str and port_str.isdigit():
                                port_num = int(port_str)
                                results["ports"].append({
                                    "port": port_num,
                                    "protocol": "tcp",
                                    "state": "open",
                                    "service": "unknown",
                                    "version": "",
                                    "common_service": get_common_service_name(port_num, "tcp"),
                                })

        logger.info(
            "Rustscan found %d open TCP ports on %s",
            len(results["ports"]),
            target,
        )

        return results

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

            # Direct match (works for IPs)
            if target in self.nm.all_hosts():
                return True

            # Fallback: check if target matches any host's hostname
            # (nmap stores resolved IP as key, hostname as attribute)
            for host in self.nm.all_hosts():
                if self.nm[host].hostname() == target:
                    return True

            return False
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
            # -Pn: Skip host discovery (handles ICMP-blocked hosts)
            # -sV: Version detection
            # -T{n}: Timing template (3-5)
            # --open: Only show open ports
            # --max-retries: Limit retries for faster scan
            # --min-rate: Minimum packets per second
            # --host-timeout: Max time per host
            args = (
                f"-sS -Pn -sV -T{settings.scan_timing} --open "
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

    def scan_udp(self, target: str, ports: Optional[str] = None) -> Dict:
        """UDP scan (slower, scans top 1000 ports by default).

        Args:
            target: Hostname or IP address to scan.
            ports: Optional port range/list to scan. If omitted, scans the top 1000 UDP ports.

        Returns:
            Dictionary with host_status and list of discovered ports.
        """
        try:
            udp_scope = ports if ports else "top 1000"
            logger.info("Starting UDP scan of %s (%s)", target, udp_scope)

            # Phase 1: Discovery scan (no version detection for speed).
            discovery_args = f"-sU -Pn -T{settings.scan_timing} --max-retries 1"
            if not ports:
                discovery_args += f" --top-ports {settings.udp_top_ports}"
            if settings.scan_min_rate > 0:
                udp_rate = max(100, settings.scan_min_rate // 2)
                discovery_args += f" --min-rate {udp_rate}"
            discovery_args += f" --host-timeout {settings.scan_host_timeout}"

            self.nm.scan(hosts=target, ports=ports, arguments=discovery_args)

            target_key = self._find_nmap_target_key(target)
            if not target_key:
                logger.warning("Target %s not found in scan results", target)
                return {"host_status": "down", "ports": []}

            host = self.nm[target_key]
            host_status = host.state()

            allowed_states = ("open", "open|filtered")
            discovered_ports: List[Dict] = []
            discovered_raw_states: Dict[int, str] = {}

            if "udp" in host.all_protocols():
                for port_num in host["udp"].keys():
                    port_info = host["udp"][port_num]
                    raw_state = port_info.get("state", "unknown")
                    if raw_state not in allowed_states:
                        continue

                    discovered_raw_states[port_num] = raw_state
                    discovered_ports.append({
                        "port": port_num,
                        "protocol": "udp",
                        "state": "open",  # Normalize for storage/UX consistency
                        "service": port_info.get("name", "unknown"),
                        "version": "",
                        "common_service": get_common_service_name(port_num, "udp"),
                    })

            # Phase 2: Optional version detection on a small subset of ports.
            if settings.udp_version_detection and discovered_ports:
                expected_set = {
                    (p["port"], p["protocol"]) for p in settings.expected_ports_list
                }

                candidates: List[tuple[int, int]] = []
                for port_entry in discovered_ports:
                    port_num = port_entry["port"]
                    priority = 0
                    if (port_num, "udp") in expected_set:
                        priority += 1_000
                    if discovered_raw_states.get(port_num) == "open":
                        priority += 100
                    if port_entry.get("common_service"):
                        priority += 10
                    if priority > 0:
                        candidates.append((priority, port_num))

                # Stable, deterministic selection: highest priority first, then port number.
                candidates.sort(key=lambda item: (-item[0], item[1]))
                ports_to_version_scan: List[int] = []
                seen: set[int] = set()
                for _, port_num in candidates:
                    if port_num in seen:
                        continue
                    seen.add(port_num)
                    ports_to_version_scan.append(port_num)
                    if len(ports_to_version_scan) >= settings.udp_version_detection_ports_limit:
                        break

                if ports_to_version_scan:
                    version_args = (
                        f"-sU -Pn {self._version_detection_args(settings.udp_version_detection_intensity)} "
                        f"-T{settings.scan_timing} --max-retries 1"
                    )
                    if settings.scan_min_rate > 0:
                        udp_rate = max(100, settings.scan_min_rate // 2)
                        version_args += f" --min-rate {udp_rate}"
                    version_args += f" --host-timeout {settings.scan_host_timeout}"

                    self.nm.scan(
                        hosts=target,
                        ports=",".join(str(p) for p in ports_to_version_scan),
                        arguments=version_args,
                    )

                    version_results = self._parse_results(target, "udp")
                    version_map = {
                        p["port"]: p for p in version_results.get("ports", [])
                    }

                    for port_entry in discovered_ports:
                        version_entry = version_map.get(port_entry["port"])
                        if not version_entry:
                            continue
                        port_entry["service"] = version_entry.get("service", port_entry["service"])
                        port_entry["version"] = version_entry.get("version", port_entry["version"])

            logger.info(
                "UDP scan completed. Found %d UDP ports on %s (host: %s)",
                len(discovered_ports),
                target,
                host_status,
            )

            return {"host_status": host_status, "ports": discovered_ports}

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

        target_key = self._find_nmap_target_key(target)
        if not target_key:
            logger.warning("Target %s not found in scan results", target)
            return results

        host = self.nm[target_key]
        results["host_status"] = host.state()

        # Extract port information
        # For UDP, we accept "open" and "open|filtered" states to catch
        # services like WireGuard that don't respond to probes
        allowed_states = ("open", "open|filtered")

        if protocol in host.all_protocols():
            for port_num in host[protocol].keys():
                port_info = host[protocol][port_num]
                state = port_info.get("state", "unknown")

                # Only include ports that are likely open
                if state not in allowed_states:
                    continue

                results["ports"].append({
                    "port": port_num,
                    "protocol": protocol,
                    "state": "open",  # Normalize to "open" for consistency
                    "service": port_info.get("name", "unknown"),
                    "version": port_info.get("version", ""),
                    "common_service": get_common_service_name(port_num, protocol),
                })

        logger.info(
            "Found %d %s ports on %s (host: %s)",
            len(results["ports"]),
            protocol.upper(),
            target,
            results["host_status"],
        )

        return results

    def scan_single_port(
        self,
        target: str,
        port: int,
        protocol: str = "tcp",
        intensity: str = "normal",
    ) -> Dict:
        """Scan a single port with detailed service detection using nmap.

        Args:
            target: Hostname or IP address to scan.
            port: Port number to scan (1-65535).
            protocol: Protocol ('tcp' or 'udp').
            intensity: Service detection intensity ('light', 'normal', 'thorough').

        Returns:
            Dictionary with port info including service and version details.
        """
        import time

        start_time = time.time()

        try:
            logger.info(
                "Starting single port scan of %s:%d/%s (intensity: %s)",
                target, port, protocol, intensity
            )

            # Build nmap arguments based on intensity
            # -sS for TCP SYN scan, -sU for UDP
            scan_type = "-sS" if protocol == "tcp" else "-sU"

            version_args = self._version_detection_args(intensity)
            args = f"{scan_type} -Pn {version_args} -T4 --host-timeout 30s"

            self.nm.scan(
                hosts=target,
                ports=str(port),
                arguments=args,
            )

            duration = time.time() - start_time

            # Parse results
            result = {
                "port": port,
                "protocol": protocol,
                "state": "closed",
                "service": None,
                "version": None,
                "common_service": get_common_service_name(port, protocol),
                "scan_duration": round(duration, 2),
            }

            target_key = self._find_nmap_target_key(target)
            if not target_key:
                logger.warning("Target %s not found in scan results", target)
                result["state"] = "unknown"
                return result

            host = self.nm[target_key]

            # Check if port was found in results
            if protocol in host.all_protocols():
                if port in host[protocol]:
                    port_info = host[protocol][port]
                    result["state"] = port_info.get("state", "unknown")
                    result["service"] = port_info.get("name", "unknown")
                    result["version"] = port_info.get("version", "")

            logger.info(
                "Single port scan completed: %s:%d/%s -> %s (%s) in %.2fs",
                target, port, protocol,
                result["state"],
                result["service"] or "unknown",
                duration,
            )

            return result

        except nmap.PortScannerError as e:
            logger.error("Single port scan failed: %s", e)
            raise
        except Exception as e:
            logger.error("Unexpected error during single port scan: %s", e)
            raise

    def enrich_tcp_services(self, target: str, ports: List[int], intensity: str) -> Dict[int, Dict]:
        """Enrich TCP port entries with service/version detection via nmap.

        Args:
            target: Hostname or IP address to scan.
            ports: List of TCP port numbers to enrich.
            intensity: Version detection intensity ("light", "normal", "thorough").

        Returns:
            Mapping of port -> port details (service/version).
        """
        if not ports:
            return {}

        ports_limited = sorted(set(ports))[:settings.tcp_service_enrichment_ports_limit]
        ports_arg = ",".join(str(p) for p in ports_limited)

        args = (
            f"-sS -Pn {self._version_detection_args(intensity)} "
            f"-T{settings.scan_timing} --open --max-retries {settings.scan_max_retries}"
        )
        if settings.scan_min_rate > 0:
            args += f" --min-rate {settings.scan_min_rate}"
        args += f" --host-timeout {settings.scan_host_timeout}"

        self.nm.scan(hosts=target, ports=ports_arg, arguments=args)

        results = self._parse_results(target, "tcp")
        return {p["port"]: p for p in results.get("ports", [])}


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
        # Save scan as running with initial phase
        await save_scan(scan_id, target, "full", started_at, "running")
        await update_scan_progress(scan_id, "starting", 0, 0)

        # Run TCP (Rustscan) and UDP (nmap) scans concurrently
        # Rustscan is much faster than nmap for TCP port discovery
        await update_scan_progress(scan_id, "scanning", 0, 0)

        tcp_task = asyncio.to_thread(
            scanner.scan_tcp_rustscan, target, "1-65535"
        )

        # UDP scan uses nmap (top 1000 ports - UDP is inherently slow)
        udp_task = asyncio.to_thread(
            scanner.scan_udp, target
        )

        # Execute both scans concurrently
        tcp_results, udp_results = await asyncio.gather(tcp_task, udp_task)

        # Update progress with port counts
        tcp_port_count = len(tcp_results.get("ports", []))
        udp_port_count = len(udp_results.get("ports", []))
        await update_scan_progress(scan_id, "enriching", tcp_port_count, udp_port_count)

        # Optional: Enrich TCP service/version info after fast Rustscan discovery.
        if settings.tcp_service_enrichment and tcp_results.get("ports"):
            discovered_tcp_ports = [p["port"] for p in tcp_results["ports"]]
            try:
                enrichment_map = await asyncio.to_thread(
                    scanner.enrich_tcp_services,
                    target,
                    discovered_tcp_ports,
                    settings.tcp_service_enrichment_intensity,
                )
                for port_entry in tcp_results["ports"]:
                    enriched = enrichment_map.get(port_entry["port"])
                    if not enriched:
                        continue
                    port_entry["service"] = enriched.get("service", port_entry.get("service"))
                    port_entry["version"] = enriched.get("version", port_entry.get("version"))
            except Exception as e:
                logger.warning("TCP service enrichment failed: %s", e)

        # Combine results
        all_ports = tcp_results["ports"] + udp_results["ports"]

        # Determine host status from both protocols
        # Host is "up" if either scan reports it up, or if either found open ports
        tcp_up = tcp_results["host_status"] == "up" or len(tcp_results["ports"]) > 0
        udp_up = udp_results["host_status"] == "up" or len(udp_results["ports"]) > 0
        host_status = "up" if (tcp_up or udp_up) else "down"

        # Update progress before saving
        tcp_port_count = len(tcp_results.get("ports", []))
        udp_port_count = len(udp_results.get("ports", []))
        await update_scan_progress(scan_id, "saving", tcp_port_count, udp_port_count)

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

        # Send notifications only when port changes are detected
        if changes:
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

    Uses comprehensive check with TCP fallback when ICMP is blocked.
    Persists status to database and only notifies on status changes.

    Returns:
        True if host is online, False otherwise.
    """
    # Import here to avoid circular imports
    from src.notifications.notifier import send_host_status_notification
    from src.scanner.host_checker import quick_host_check
    from src.storage.database import save_host_status, get_last_host_status

    target = settings.target_host

    # Get previous status before checking
    previous_status = await get_last_host_status(target)

    # Use comprehensive check with TCP fallback (ICMP often blocked by firewalls)
    result = await quick_host_check(target)
    current_status = result["status"]
    is_online = current_status == "online"

    # Save status to database for dashboard (returns failure count)
    failure_count = await save_host_status(target, current_status)

    # Update host status metric
    host_online_status.labels(target=target).set(1 if is_online else 0)

    logger.info(
        "Host check for %s: %s (DNS: %s, TCP: %s, previous: %s, failures: %d)",
        target,
        current_status,
        result["dns_resolved"],
        result["tcp_reachable"],
        previous_status or "unknown",
        failure_count,
    )

    # Only send notification on status CHANGE with threshold for offline
    if previous_status == "online" and current_status != "online":
        # Host appears offline - check failure threshold
        threshold = settings.host_offline_threshold
        if failure_count >= threshold:
            logger.warning(
                "Host %s went OFFLINE (was online, %d consecutive failures)",
                target,
                failure_count,
            )
            await send_host_status_notification(target, "offline")
        else:
            logger.info(
                "Host %s check failed (%d/%d), waiting for confirmation",
                target,
                failure_count,
                threshold,
            )
    elif previous_status and previous_status != "online" and current_status == "online":
        # Host came back online
        logger.info("Host %s came back ONLINE", target)
        await send_host_status_notification(target, "online")

    return is_online
