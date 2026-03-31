"""Vulnerability scanning module.

Checks for:
- Missing security headers
- CORS misconfigurations
- SQL injection (via sqlmap CLI)
- Web vulnerabilities (via Nikto CLI)
"""

from __future__ import annotations

from typing import Any

import httpx

from reconbolt.engine.events import ScanPhase
from reconbolt.models.findings import BaseFinding, CORSFinding, HeaderFinding, VulnerabilityFinding
from reconbolt.scanners.base import BaseScanner

# Important security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HSTS enforces secure HTTPS connections",
        "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "description": "CSP prevents XSS and data injection attacks",
        "recommendation": "Implement a Content-Security-Policy suited to your application",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "recommendation": "X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking via framing",
        "recommendation": "X-Frame-Options: DENY or SAMEORIGIN",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs",
        "recommendation": "Restrict unnecessary browser features",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filtering (still useful for older browsers)",
        "recommendation": "X-XSS-Protection: 1; mode=block",
    },
}


class VulnScanner(BaseScanner):
    """Scans for web vulnerabilities including headers, CORS, SQLi, and Nikto."""

    phase = ScanPhase.VULN_SCAN

    async def scan(self, web_targets: list[str] | None = None, **kwargs: Any) -> list[BaseFinding]:
        """Run all vulnerability checks on the provided web targets."""
        if not web_targets:
            web_targets = [self.config.target]

        self.emitter.info(self.phase, f"Starting vulnerability scanning on {len(web_targets)} target(s)")

        all_findings: list[BaseFinding] = []
        total = len(web_targets)

        for idx, target in enumerate(web_targets):
            url = self._normalize_url(target)
            progress = (idx / total) * 100

            # Security headers check
            self.emitter.info(self.phase, f"Checking security headers on {target}", progress=progress)
            header_findings = await self._check_headers(target, url)
            all_findings.extend(header_findings)

            # CORS check
            self.emitter.info(self.phase, f"Checking CORS configuration on {target}", progress=progress + 5)
            cors_findings = await self._check_cors(target, url)
            all_findings.extend(cors_findings)

            # SQLmap (if available)
            if self.find_executable("sqlmap"):
                self.emitter.info(self.phase, f"Running sqlmap on {target}", progress=progress + 10)
                sqli_findings = await self._run_sqlmap(target, url)
                all_findings.extend(sqli_findings)

            # Nikto (if available)
            if self.find_executable("nikto"):
                self.emitter.info(self.phase, f"Running Nikto on {target}", progress=progress + 15)
                nikto_findings = await self._run_nikto(target, url)
                all_findings.extend(nikto_findings)

        self.emitter.success(
            self.phase,
            f"Vulnerability scan complete. Found {len(all_findings)} findings.",
            progress=100.0,
        )
        return all_findings

    # --- Header Check ---

    async def _check_headers(self, host: str, url: str) -> list[HeaderFinding]:
        """Check for missing security headers."""
        findings: list[HeaderFinding] = []
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                response = await client.get(url)

            for header_name, info in SECURITY_HEADERS.items():
                present = header_name in response.headers
                # Check aliases (e.g., Feature-Policy → Permissions-Policy)
                if not present and header_name == "Permissions-Policy":
                    present = "Feature-Policy" in response.headers

                findings.append(
                    HeaderFinding(
                        host=host,
                        header_name=header_name,
                        present=present,
                        value=response.headers.get(header_name),
                        description=info["description"],
                        recommendation=info["recommendation"] if not present else "",
                    )
                )

                if not present:
                    self.emitter.warning(self.phase, f"Missing header on {host}: {header_name}")

        except Exception as e:
            self.emitter.warning(self.phase, f"Header check failed for {host}: {e}")
        return findings

    # --- CORS Check ---

    async def _check_cors(self, host: str, url: str) -> list[CORSFinding]:
        """Test for CORS misconfigurations with various origin values."""
        test_origins = [
            "https://evil.com",
            "https://attacker.evil.com",
            "null",
            f"https://{host}.evil.com",
        ]

        findings: list[CORSFinding] = []
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                for origin in test_origins:
                    try:
                        response = await client.get(url, headers={"Origin": origin})
                        acao = response.headers.get("Access-Control-Allow-Origin")
                        if acao and (acao == origin or acao == "*"):
                            creds = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
                            severity = "critical" if creds and acao != "*" else "high" if creds else "medium"

                            findings.append(
                                CORSFinding(
                                    host=host,
                                    tested_origin=origin,
                                    reflected_origin=acao,
                                    credentials_allowed=creds,
                                    severity=severity,
                                )
                            )
                            self.emitter.warning(
                                self.phase,
                                f"CORS misconfiguration on {host}: origin '{origin}' reflected (creds={creds})",
                            )
                    except Exception:
                        continue

        except Exception as e:
            self.emitter.warning(self.phase, f"CORS check failed for {host}: {e}")
        return findings

    # --- SQLmap ---

    async def _run_sqlmap(self, host: str, url: str) -> list[VulnerabilityFinding]:
        """Run sqlmap for SQL injection detection."""
        cmd = ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1", "--forms"]
        output = await self.run_command(cmd, "sqlmap")

        findings: list[VulnerabilityFinding] = []
        if output and "is vulnerable" in output:
            # Extract vulnerable parameters
            for line in output.splitlines():
                if "Parameter:" in line and "is vulnerable" in line:
                    findings.append(
                        VulnerabilityFinding(
                            host=host,
                            source="sqlmap",
                            vuln_type="sql_injection",
                            severity="critical",
                            title="SQL Injection Vulnerability",
                            description=line.strip(),
                            url=url,
                            remediation="Use parameterized queries / prepared statements",
                        )
                    )
            self.emitter.warning(self.phase, f"SQL injection found on {host}!")
        return findings

    # --- Nikto ---

    async def _run_nikto(self, host: str, url: str) -> list[VulnerabilityFinding]:
        """Run Nikto for web server vulnerability scanning."""
        cmd = ["nikto", "-h", url, "-Format", "csv", "-nointeractive"]
        output = await self.run_command(cmd, "nikto")

        findings: list[VulnerabilityFinding] = []
        if output:
            for line in output.splitlines():
                # Nikto CSV format: "host","IP","port","OSVDB-ID","method","URL","message"
                if line.startswith('"') and "OSVDB-" in line:
                    parts = [p.strip('"') for p in line.split('","')]
                    if len(parts) >= 7:
                        findings.append(
                            VulnerabilityFinding(
                                host=host,
                                source="nikto",
                                vuln_type="web_vuln",
                                severity="medium",
                                title=f"Nikto: {parts[3]}",
                                description=parts[6] if len(parts) > 6 else "",
                                url=parts[5] if len(parts) > 5 else url,
                            )
                        )
            if findings:
                self.emitter.warning(self.phase, f"Nikto found {len(findings)} issues on {host}")
        return findings

    @staticmethod
    def _normalize_url(target: str) -> str:
        """Ensure target has a scheme."""
        if not target.startswith(("http://", "https://")):
            return f"https://{target}"
        return target
