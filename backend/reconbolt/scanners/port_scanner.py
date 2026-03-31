"""Port scanning module using python-nmap.

Wraps nmap to discover open ports and services on target hosts,
running scans concurrently via asyncio.to_thread().
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from reconbolt.engine.events import ScanPhase
from reconbolt.models.findings import PortFinding
from reconbolt.scanners.base import BaseScanner


class PortScanner(BaseScanner):
    """Scans for open ports and service versions using nmap."""

    phase = ScanPhase.PORT_SCAN

    # Top 100 ports commonly scanned
    TOP_PORTS = (
        "21,22,23,25,26,53,80,81,110,111,113,135,139,143,179,199,443,445,465,514,"
        "515,548,554,587,646,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,"
        "1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,"
        "5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,"
        "8008,8009,8080,8081,8443,8888,9100,9200,9999,10000,11211,27017,27018,32768,"
        "49152,49153,49154,49155,49156,49157,50000"
    )

    def check_dependencies(self) -> list[str]:
        missing = []
        try:
            import nmap  # noqa: F401
        except ImportError:
            missing.append("python-nmap")
        return missing

    async def scan(self, targets: list[str] | None = None, **kwargs: Any) -> list[PortFinding]:
        """Scan ports on all specified targets concurrently."""
        missing = self.check_dependencies()
        if missing:
            self.emitter.warning(self.phase, f"Missing dependencies: {', '.join(missing)}. Skipping port scan.")
            return []

        if not targets:
            targets = [self.config.target]

        self.emitter.info(self.phase, f"Starting port scan on {len(targets)} target(s)")

        # Build scan arguments
        intensity_map = {"low": "-T2", "normal": "-T3", "aggressive": "-T4"}
        scan_speed = intensity_map.get(self.config.intensity, "-T3")
        scan_args = f"{scan_speed} -sV --open"

        # Scan targets — run scans in thread pool for concurrency
        all_findings: list[PortFinding] = []
        semaphore = asyncio.Semaphore(self.settings.max_concurrent_scans)

        async def scan_host(idx: int, target: str) -> list[PortFinding]:
            async with semaphore:
                findings = await asyncio.to_thread(self._scan_single_host, target, scan_args)
                progress = (idx + 1) / len(targets) * 100
                self.emitter.info(
                    self.phase,
                    f"Scanned {target}: {len(findings)} open ports",
                    progress=progress,
                )
                return findings

        tasks = [scan_host(i, t) for i, t in enumerate(targets)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                self.emitter.warning(self.phase, f"Scan error: {result}")

        self.emitter.success(
            self.phase,
            f"Port scan complete. Found {len(all_findings)} open ports across {len(targets)} hosts.",
            progress=100.0,
        )
        return all_findings

    def _scan_single_host(self, target: str, scan_args: str) -> list[PortFinding]:
        """Run nmap scan on a single host (blocking, runs in thread)."""
        import nmap

        # Validate target resolves
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            self.emitter.warning(self.phase, f"Cannot resolve {target}, skipping")
            return []

        findings: list[PortFinding] = []
        try:
            scanner = nmap.PortScanner()
            scanner.scan(target, self.TOP_PORTS, arguments=scan_args)

            if target not in scanner.all_hosts():
                return findings

            for proto in scanner[target].all_protocols():
                for port in sorted(scanner[target][proto].keys()):
                    port_data = scanner[target][proto][port]
                    if port_data["state"] == "open":
                        findings.append(
                            PortFinding(
                                host=target,
                                source="nmap",
                                port=port,
                                protocol=proto,
                                state="open",
                                service_name=port_data.get("name", ""),
                                product=port_data.get("product", ""),
                                version=port_data.get("version", ""),
                                extra_info=port_data.get("extrainfo", ""),
                            )
                        )
        except Exception as e:
            self.emitter.error(self.phase, f"Nmap error on {target}: {e}")

        return findings
