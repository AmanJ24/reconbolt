"""Subdomain takeover detection module.

Uses the subzy CLI tool to detect subdomains vulnerable to takeover.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from reconbolt.engine.events import ScanPhase
from reconbolt.models.findings import TakeoverFinding
from reconbolt.scanners.base import BaseScanner


class TakeoverScanner(BaseScanner):
    """Checks discovered subdomains for takeover vulnerabilities using subzy."""

    phase = ScanPhase.TAKEOVER_CHECK

    def check_dependencies(self) -> list[str]:
        if not self.find_executable("subzy"):
            return ["subzy"]
        return []

    async def scan(self, subdomains: list[str] | None = None, **kwargs: Any) -> list[TakeoverFinding]:
        """Run subzy against discovered subdomains."""
        missing = self.check_dependencies()
        if missing:
            self.emitter.warning(self.phase, "subzy not installed. Skipping subdomain takeover check.")
            return []

        if not subdomains:
            self.emitter.info(self.phase, "No subdomains provided for takeover check")
            return []

        self.emitter.info(self.phase, f"Checking {len(subdomains)} subdomains for takeover vulnerabilities")

        # Write subdomains to a temp file for subzy
        findings: list[TakeoverFinding] = []
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            for sub in subdomains:
                tmp.write(f"{sub}\n")
            tmp_path = Path(tmp.name)

        try:
            subzy_path = self.find_executable("subzy")
            cmd = [subzy_path, "run", "--targets", str(tmp_path), "--concurrency", "10"]
            output = await self.run_command(cmd, "subzy")

            if output:
                for line in output.splitlines():
                    lower_line = line.lower()
                    if "[vulnerable]" in lower_line:
                        # Parse subzy output to extract subdomain and service
                        parts = line.split()
                        subdomain = ""
                        service = ""
                        for part in parts:
                            if "." in part and not part.startswith("["):
                                subdomain = part.strip()
                            elif part.startswith("[") and part != "[VULNERABLE]":
                                service = part.strip("[]")

                        if subdomain:
                            findings.append(
                                TakeoverFinding(
                                    host=self.config.target,
                                    subdomain=subdomain,
                                    service=service or "unknown",
                                    confidence="high",
                                )
                            )
                            self.emitter.warning(
                                self.phase,
                                f"Potential takeover: {subdomain} via {service}",
                            )
        finally:
            # Cleanup temp file
            if tmp_path.exists():
                tmp_path.unlink()

        self.emitter.success(
            self.phase,
            f"Takeover check complete. Found {len(findings)} vulnerable subdomains.",
            progress=100.0,
        )
        return findings
