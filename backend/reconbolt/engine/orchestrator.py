"""Scan orchestrator — the brain of ReconBolt.

Manages the end-to-end scan pipeline:
1. Resolve target
2. Subdomain enumeration
3. Port scanning (concurrent across hosts)
4. Vulnerability scanning
5. OSINT gathering
6. Subdomain takeover check
7. AI analysis
8. Compute risk score
"""

from __future__ import annotations

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
        self.result = ScanResult(target=config.target, config=config)

    async def run(self) -> ScanResult:
        """Execute the full scan pipeline."""
        start_time = time.time()
        self.result.status = ScanStatus.RUNNING
        self.emitter.info(ScanPhase.INITIALIZING, f"Starting scan of {self.config.target}")

        try:
            # Step 0: Validate target
            if not self._validate_target():
                self.result.status = ScanStatus.FAILED
                return self.result

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

    def _validate_target(self) -> bool:
        """Validate the target can be resolved."""
        self.emitter.info(ScanPhase.INITIALIZING, f"Resolving {self.config.target}...")
        try:
            ip = socket.gethostbyname(self.config.target)
            self.emitter.success(ScanPhase.INITIALIZING, f"Resolved {self.config.target} → {ip}")
            return True
        except socket.gaierror:
            self.emitter.error(ScanPhase.INITIALIZING, f"Cannot resolve {self.config.target}. Aborting scan.")
            self.result.errors.append(f"DNS resolution failed for {self.config.target}")
            return False

    async def _run_subdomain_enum(self) -> None:
        """Run subdomain enumeration phase."""
        from reconbolt.scanners.subdomain import SubdomainScanner

        scanner = SubdomainScanner(self.config, self.emitter)
        try:
            findings = await scanner.scan()
            self.result.subdomains = findings
        except Exception as e:
            self.result.errors.append(f"Subdomain enumeration error: {e}")
            self.emitter.error(ScanPhase.SUBDOMAIN_ENUM, f"Subdomain scan failed: {e}")

    async def _run_port_scan(self) -> None:
        """Run port scanning on target and discovered subdomains."""
        from reconbolt.scanners.port_scanner import PortScanner

        scanner = PortScanner(self.config, self.emitter)

        # Build target list: main target + discovered subdomains
        targets = [self.config.target]
        for sub in self.result.subdomains[:20]:  # Limit to avoid excessive scanning
            if sub.subdomain != self.config.target:
                targets.append(sub.subdomain)

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

        # Identify web targets (hosts with port 80 or 443 open)
        web_ports = {80, 443, 8080, 8443}
        web_targets = set()
        web_targets.add(self.config.target)
        for port_finding in self.result.ports:
            if port_finding.port in web_ports:
                web_targets.add(port_finding.host)

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
            self.emitter.success(ScanPhase.AI_ANALYSIS, "AI analysis complete", progress=100.0)
        except Exception as e:
            self.result.errors.append(f"AI analysis error: {e}")
            self.emitter.warning(ScanPhase.AI_ANALYSIS, f"AI analysis failed: {e}")
