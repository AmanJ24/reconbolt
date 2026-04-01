"""Scan orchestrator — the brain of ReconBolt.

Manages the end-to-end scan pipeline:
1. Validate target (non-blocking, non-fatal)
2. Subdomain enumeration
3. Port scanning (concurrent across hosts)
4. Vulnerability scanning
5. OSINT gathering
6. Subdomain takeover check
7. AI analysis
8. Compute risk score
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from datetime import datetime, timezone

from reconbolt.config import get_settings
from reconbolt.engine.events import EventEmitter, ScanPhase
from reconbolt.models.scan import ScanConfig, ScanResult, ScanStatus


class ScanOrchestrator:
    """Orchestrates the full reconnaissance pipeline."""

    def __init__(self, config: ScanConfig, emitter: EventEmitter | None = None) -> None:
        self.config = config
        self.emitter = emitter or EventEmitter()
        self.settings = get_settings()
        # Clean the target: strip scheme, paths, wildcards
        clean_target = self._clean_target(config.target)
        self.config = config.model_copy(update={"target": clean_target})
        self.result = ScanResult(target=clean_target, config=self.config)

    @staticmethod
    def _clean_target(raw: str) -> str:
        """Strip scheme, paths, wildcards, and whitespace from target."""
        target = raw.strip()
        # Remove scheme
        target = re.sub(r'^https?://', '', target)
        # Remove path/query
        target = target.split('/')[0].split('?')[0].split('#')[0]
        # Remove wildcard prefix: *.example.com → example.com
        if target.startswith('*.'):
            target = target[2:]
        # Remove trailing dots
        target = target.rstrip('.')
        return target.lower()

    async def run(self) -> ScanResult:
        """Execute the full scan pipeline."""
        start_time = time.time()
        self.result.status = ScanStatus.RUNNING
        self.emitter.info(ScanPhase.INITIALIZING, f"Starting scan of {self.config.target}")

        try:
            # Step 0: Validate target (non-fatal — many domains lack apex A records)
            await self._validate_target()

            # Step 1: Subdomain enumeration
            if self.config.enable_subdomain_enum:
                await self._run_subdomain_enum()

            # Step 2: Port scanning
            if self.config.enable_port_scan:
                await self._run_port_scan()

            # Step 3: Vulnerability scanning
            if self.config.enable_vuln_scan:
                await self._run_vuln_scan()

            # Step 4: OSINT
            if self.config.enable_osint:
                await self._run_osint()

            # Step 5: Takeover check
            if self.config.enable_takeover_check:
                await self._run_takeover_check()

            # Step 6: AI analysis
            if self.config.enable_ai_analysis and self.settings.has_ai:
                await self._run_ai_analysis()

            # Finalize
            self.result.status = ScanStatus.COMPLETED
            self.result.completed_at = datetime.now(timezone.utc)
            self.result.duration_seconds = round(time.time() - start_time, 2)
            self.result.compute_summary()

            self.emitter.success(
                ScanPhase.COMPLETED,
                f"Scan complete in {self.result.duration_seconds}s — "
                f"Risk: {self.result.summary.risk_level.upper()} ({self.result.summary.risk_score}/10)",
                progress=100.0,
            )

        except Exception as e:
            self.result.status = ScanStatus.FAILED
            self.result.errors.append(str(e))
            self.emitter.error(ScanPhase.COMPLETED, f"Scan failed: {e}")

        return self.result

    async def _validate_target(self) -> None:
        """Validate the target — non-fatal, just logs a warning if DNS fails.

        Many legitimate targets (e.g., numerique.canada.ca) don't have an
        A record at the apex. The scan should proceed regardless since
        subdomain enumeration will discover resolvable hosts.
        """
        self.emitter.info(ScanPhase.INITIALIZING, f"Resolving {self.config.target}...")
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, self.config.target)
            self.emitter.success(ScanPhase.INITIALIZING, f"Resolved {self.config.target} → {ip}", progress=5.0)
        except socket.gaierror:
            self.emitter.warning(
                ScanPhase.INITIALIZING,
                f"Cannot resolve apex {self.config.target} (this is normal for some domains). "
                f"Proceeding with subdomain enumeration and other modules.",
            )

    async def _run_subdomain_enum(self) -> None:
        """Run subdomain enumeration phase."""
        from reconbolt.scanners.subdomain import SubdomainScanner

        scanner = SubdomainScanner(self.config, self.emitter)
        try:
            findings = await scanner.scan()
            self.result.subdomains = findings
            self.emitter.success(
                ScanPhase.SUBDOMAIN_ENUM,
                f"Subdomain enumeration complete: {len(findings)} found",
                progress=25.0,
            )
        except Exception as e:
            self.result.errors.append(f"Subdomain enumeration error: {e}")
            self.emitter.error(ScanPhase.SUBDOMAIN_ENUM, f"Subdomain scan failed: {e}")

    async def _run_port_scan(self) -> None:
        """Run port scanning on target and discovered subdomains."""
        from reconbolt.scanners.port_scanner import PortScanner

        scanner = PortScanner(self.config, self.emitter)

        # Build target list: main target + discovered subdomains that resolved
        targets = []
        # Only add main target if we can resolve it
        try:
            await asyncio.to_thread(socket.gethostbyname, self.config.target)
            targets.append(self.config.target)
        except socket.gaierror:
            pass

        # Add resolved subdomains
        for sub in self.result.subdomains[:20]:  # Limit to avoid excessive scanning
            if sub.ip_address and sub.subdomain != self.config.target:
                targets.append(sub.subdomain)

        if not targets:
            self.emitter.warning(ScanPhase.PORT_SCAN, "No resolvable targets for port scanning, skipping.")
            return

        try:
            findings = await scanner.scan(targets=targets)
            self.result.ports = findings
        except Exception as e:
            self.result.errors.append(f"Port scan error: {e}")
            self.emitter.error(ScanPhase.PORT_SCAN, f"Port scan failed: {e}")

    async def _run_vuln_scan(self) -> None:
        """Run vulnerability scanning on web-facing targets."""
        from reconbolt.scanners.vuln_scanner import VulnScanner

        scanner = VulnScanner(self.config, self.emitter)

        # Identify web targets (hosts with port 80 or 443 open, or the main target)
        web_ports = {80, 443, 8080, 8443}
        web_targets = set()

        # Add main target if it resolved, or any subdomain
        try:
            await asyncio.to_thread(socket.gethostbyname, self.config.target)
            web_targets.add(self.config.target)
        except socket.gaierror:
            pass

        for port_finding in self.result.ports:
            if port_finding.port in web_ports:
                web_targets.add(port_finding.host)

        # If no web targets from ports, try the first few resolved subdomains
        if not web_targets:
            for sub in self.result.subdomains[:5]:
                if sub.ip_address:
                    web_targets.add(sub.subdomain)
                    break

        if not web_targets:
            self.emitter.warning(ScanPhase.VULN_SCAN, "No web targets identified, skipping vulnerability scan.")
            return

        try:
            findings = await scanner.scan(web_targets=list(web_targets)[:10])
            # Separate finding types
            for f in findings:
                if hasattr(f, "header_name"):
                    self.result.headers.append(f)
                elif hasattr(f, "tested_origin"):
                    self.result.cors_findings.append(f)
                elif hasattr(f, "vuln_type"):
                    self.result.vulnerabilities.append(f)
        except Exception as e:
            self.result.errors.append(f"Vulnerability scan error: {e}")
            self.emitter.error(ScanPhase.VULN_SCAN, f"Vulnerability scan failed: {e}")

    async def _run_osint(self) -> None:
        """Run OSINT intelligence gathering."""
        from reconbolt.scanners.osint import OSINTScanner

        scanner = OSINTScanner(self.config, self.emitter)
        try:
            findings = await scanner.scan()
            self.result.osint = findings
        except Exception as e:
            self.result.errors.append(f"OSINT error: {e}")
            self.emitter.error(ScanPhase.OSINT, f"OSINT scan failed: {e}")

    async def _run_takeover_check(self) -> None:
        """Run subdomain takeover check."""
        from reconbolt.scanners.takeover import TakeoverScanner

        scanner = TakeoverScanner(self.config, self.emitter)
        subdomain_list = [s.subdomain for s in self.result.subdomains]

        if not subdomain_list:
            self.emitter.warning(ScanPhase.TAKEOVER_CHECK, "No subdomains to check for takeover.")
            return

        try:
            findings = await scanner.scan(subdomains=subdomain_list)
            self.result.takeovers = findings
        except Exception as e:
            self.result.errors.append(f"Takeover check error: {e}")
            self.emitter.error(ScanPhase.TAKEOVER_CHECK, f"Takeover check failed: {e}")

    async def _run_ai_analysis(self) -> None:
        """Run AI-powered analysis of scan results."""
        self.emitter.info(ScanPhase.AI_ANALYSIS, "Starting AI analysis of findings...")
        self.result.status = ScanStatus.ANALYZING

        try:
            from reconbolt.ai.analyzer import AIAnalyzer

            analyzer = AIAnalyzer()
            summary = await analyzer.analyze(self.result)
            self.result.ai_summary = summary
            self.emitter.success(ScanPhase.AI_ANALYSIS, "AI analysis complete", progress=95.0)
        except Exception as e:
            self.result.errors.append(f"AI analysis error: {e}")
            self.emitter.warning(ScanPhase.AI_ANALYSIS, f"AI analysis failed: {e}")
