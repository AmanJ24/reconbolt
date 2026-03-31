"""OSINT and Threat Intelligence module.

Gathers external intelligence from:
- Shodan (host information, CVEs, services)
- VirusTotal (domain reputation, analysis stats)
"""

from __future__ import annotations

import socket
from typing import Any

import httpx

from reconbolt.engine.events import ScanPhase
from reconbolt.models.findings import OSINTFinding
from reconbolt.scanners.base import BaseScanner


class OSINTScanner(BaseScanner):
    """Gathers threat intelligence from external APIs."""

    phase = ScanPhase.OSINT

    async def scan(self, **kwargs: Any) -> list[OSINTFinding]:
        """Query all configured OSINT sources."""
        self.emitter.info(self.phase, "Starting OSINT intelligence gathering")
        findings: list[OSINTFinding] = []

        async with httpx.AsyncClient(timeout=30.0, headers={"User-Agent": "ReconBolt/1.0"}) as client:
            # VirusTotal domain reputation
            if self.settings.has_virustotal:
                self.emitter.info(self.phase, "Querying VirusTotal for domain reputation", progress=10)
                vt_findings = await self._virustotal_domain(client)
                findings.extend(vt_findings)
            else:
                self.emitter.warning(self.phase, "VirusTotal API key not configured, skipping")

            # Shodan host intel
            if self.settings.has_shodan:
                self.emitter.info(self.phase, "Querying Shodan for host intelligence", progress=50)
                shodan_findings = await self._shodan_host(client)
                findings.extend(shodan_findings)
            else:
                self.emitter.warning(self.phase, "Shodan API key not configured, skipping")

        self.emitter.success(
            self.phase,
            f"OSINT gathering complete. Collected {len(findings)} intelligence findings.",
            progress=100.0,
        )
        return findings

    async def _virustotal_domain(self, client: httpx.AsyncClient) -> list[OSINTFinding]:
        """Query VirusTotal for domain reputation."""
        findings: list[OSINTFinding] = []
        url = f"https://www.virustotal.com/api/v3/domains/{self.config.target}"
        headers = {"x-apikey": self.settings.virustotal_api_key}

        try:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})

                # Reputation
                rep_data = {}
                if "reputation" in attrs:
                    rep_data["reputation"] = attrs["reputation"]
                if "last_analysis_stats" in attrs:
                    rep_data["analysis_stats"] = attrs["last_analysis_stats"]
                if "creation_date" in attrs:
                    rep_data["creation_date"] = attrs["creation_date"]

                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                summary = f"VirusTotal: {malicious} malicious, {suspicious} suspicious, {harmless} harmless detections"

                findings.append(
                    OSINTFinding(
                        host=self.config.target,
                        source="virustotal",
                        intel_source="virustotal",
                        category="reputation",
                        data=rep_data,
                        summary=summary,
                    )
                )

                if malicious > 0:
                    self.emitter.warning(self.phase, f"VirusTotal: {malicious} malicious detections!")
                else:
                    self.emitter.success(self.phase, "VirusTotal: Domain appears clean")
            elif response.status_code == 401:
                self.emitter.error(self.phase, "Invalid VirusTotal API key")
            else:
                self.emitter.warning(self.phase, f"VirusTotal returned status {response.status_code}")
        except Exception as e:
            self.emitter.error(self.phase, f"VirusTotal query failed: {e}")

        return findings

    async def _shodan_host(self, client: httpx.AsyncClient) -> list[OSINTFinding]:
        """Query Shodan for host information."""
        findings: list[OSINTFinding] = []

        # Resolve domain to IP first
        try:
            ip = socket.gethostbyname(self.config.target)
            self.emitter.info(self.phase, f"Resolved {self.config.target} → {ip} for Shodan lookup")
        except socket.gaierror:
            self.emitter.warning(self.phase, f"Cannot resolve {self.config.target} for Shodan")
            return findings

        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.settings.shodan_api_key}"
        try:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                shodan_data = {}

                if "ports" in data:
                    shodan_data["open_ports"] = data["ports"]
                if "hostnames" in data:
                    shodan_data["hostnames"] = data["hostnames"]
                if "country_name" in data:
                    shodan_data["country"] = data["country_name"]
                if "os" in data:
                    shodan_data["os"] = data["os"]
                if "vulns" in data:
                    shodan_data["vulnerabilities"] = data["vulns"]
                    self.emitter.warning(
                        self.phase, f"Shodan reports {len(data['vulns'])} known CVEs!"
                    )

                # Extract service banners
                services = []
                for i, svc in enumerate(data.get("data", [])[:10]):
                    services.append({
                        "port": svc.get("port"),
                        "transport": svc.get("transport"),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                    })
                if services:
                    shodan_data["services"] = services

                port_count = len(data.get("ports", []))
                vuln_count = len(data.get("vulns", []))
                summary = f"Shodan: {port_count} ports, {vuln_count} CVEs reported"

                findings.append(
                    OSINTFinding(
                        host=self.config.target,
                        source="shodan",
                        intel_source="shodan",
                        category="host_intelligence",
                        data=shodan_data,
                        summary=summary,
                    )
                )
                self.emitter.success(self.phase, f"Shodan: {port_count} ports exposed, {vuln_count} CVEs")
            elif response.status_code == 401:
                self.emitter.error(self.phase, "Invalid Shodan API key")
            elif response.status_code == 404:
                self.emitter.info(self.phase, f"Shodan has no data for {ip}")
            else:
                self.emitter.warning(self.phase, f"Shodan returned status {response.status_code}")
        except Exception as e:
            self.emitter.error(self.phase, f"Shodan query failed: {e}")

        return findings
