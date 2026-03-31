"""Scan configuration and result models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from reconbolt.models.findings import (
    CORSFinding,
    HeaderFinding,
    OSINTFinding,
    PortFinding,
    SubdomainFinding,
    TakeoverFinding,
    VulnerabilityFinding,
)


class ScanStatus(str, Enum):
    """Status of a scan throughout its lifecycle."""

    PENDING = "pending"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanConfig(BaseModel):
    """Configuration for a reconnaissance scan."""

    target: str = Field(..., description="Domain or IP address to scan")
    intensity: Literal["low", "normal", "aggressive"] = "normal"

    # Module toggles
    enable_subdomain_enum: bool = True
    enable_port_scan: bool = True
    enable_vuln_scan: bool = True
    enable_osint: bool = True
    enable_takeover_check: bool = True
    enable_ai_analysis: bool = True

    # Subdomain options
    enable_bruteforce: bool = False
    wordlist_path: Optional[str] = None

    # Port scan options
    top_ports: int = Field(default=100, ge=1, le=65535)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "target": "example.com",
                "intensity": "normal",
                "enable_subdomain_enum": True,
                "enable_port_scan": True,
                "enable_bruteforce": False,
            }
        }
    )


class ScanSummary(BaseModel):
    """High-level summary statistics for a completed scan."""

    total_subdomains: int = 0
    total_open_ports: int = 0
    total_vulnerabilities: int = 0
    total_takeovers: int = 0
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    risk_level: Literal["info", "low", "medium", "high", "critical"] = "info"


class ScanResult(BaseModel):
    """Complete results of a reconnaissance scan."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    target: str
    config: ScanConfig
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Findings by category
    subdomains: list[SubdomainFinding] = Field(default_factory=list)
    ports: list[PortFinding] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)
    headers: list[HeaderFinding] = Field(default_factory=list)
    cors_findings: list[CORSFinding] = Field(default_factory=list)
    osint: list[OSINTFinding] = Field(default_factory=list)
    takeovers: list[TakeoverFinding] = Field(default_factory=list)

    # AI Analysis
    ai_summary: Optional[str] = None

    # Computed summary
    summary: ScanSummary = Field(default_factory=ScanSummary)

    # Errors encountered during scan
    errors: list[str] = Field(default_factory=list)

    def compute_summary(self) -> None:
        """Recompute the summary statistics from findings."""
        self.summary.total_subdomains = len(self.subdomains)
        self.summary.total_open_ports = len(self.ports)
        self.summary.total_vulnerabilities = len(self.vulnerabilities) + len(self.cors_findings)
        self.summary.total_takeovers = len(self.takeovers)
        self._compute_risk_score()

    def _compute_risk_score(self) -> None:
        """Calculate a risk score (0-10) based on findings."""
        score = 0.0

        # Critical services exposed
        critical_ports = {21, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017}
        exposed_critical = sum(1 for p in self.ports if p.port in critical_ports)
        score += min(exposed_critical * 1.5, 3.0)

        # Vulnerability count
        vuln_count = len(self.vulnerabilities)
        score += min(vuln_count * 0.5, 2.5)

        # CORS misconfigurations
        critical_cors = sum(1 for c in self.cors_findings if c.credentials_allowed)
        score += min(critical_cors * 1.0, 2.0)

        # Missing security headers
        missing_critical_headers = sum(
            1 for h in self.headers if not h.present and h.header_name in {"Strict-Transport-Security", "Content-Security-Policy"}
        )
        score += min(missing_critical_headers * 0.5, 1.0)

        # Subdomain takeovers
        score += min(len(self.takeovers) * 2.0, 3.0)

        self.summary.risk_score = min(round(score, 1), 10.0)

        if self.summary.risk_score >= 8.0:
            self.summary.risk_level = "critical"
        elif self.summary.risk_score >= 6.0:
            self.summary.risk_level = "high"
        elif self.summary.risk_score >= 4.0:
            self.summary.risk_level = "medium"
        elif self.summary.risk_score >= 2.0:
            self.summary.risk_level = "low"
        else:
            self.summary.risk_level = "info"
