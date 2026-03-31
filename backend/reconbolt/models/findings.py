"""Finding models for all scanner output types."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class BaseFinding(BaseModel):
    """Base class for all scanner findings."""

    source: str = Field(..., description="Scanner module that produced this finding")
    host: str = Field(..., description="Host this finding relates to")


# --- Subdomain Enumeration ---


class SubdomainFinding(BaseFinding):
    """A discovered subdomain."""

    subdomain: str
    ip_address: Optional[str] = None
    source: str = "subdomain_enum"


# --- Port Scanning ---


class PortFinding(BaseFinding):
    """An open port discovered on a host."""

    port: int = Field(..., ge=1, le=65535)
    protocol: str = "tcp"
    state: str = "open"
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""

    @property
    def service_string(self) -> str:
        """Human-readable service description."""
        parts = [self.service_name]
        if self.product:
            detail = self.product
            if self.version:
                detail += f" {self.version}"
            parts.append(f"({detail})")
        return " ".join(parts)


# --- Vulnerability Scanning ---


class VulnerabilityFinding(BaseFinding):
    """A vulnerability discovered by sqlmap, nikto, or custom checks."""

    vuln_type: str = Field(..., description="Category: sql_injection, web_vuln, etc.")
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    title: str = ""
    description: str = ""
    url: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None


class HeaderFinding(BaseFinding):
    """Status of a security header on a host."""

    header_name: str
    present: bool
    value: Optional[str] = None
    description: str = ""
    recommendation: str = ""
    source: str = "header_check"


class CORSFinding(BaseFinding):
    """CORS misconfiguration finding."""

    tested_origin: str
    reflected_origin: Optional[str] = None
    credentials_allowed: bool = False
    severity: Literal["medium", "high", "critical"] = "medium"
    source: str = "cors_check"


# --- OSINT / Threat Intelligence ---


class OSINTFinding(BaseFinding):
    """Threat intelligence from external APIs (Shodan, VirusTotal)."""

    intel_source: str = Field(..., description="shodan, virustotal, etc.")
    category: str = ""  # reputation, cve, service, etc.
    data: dict = Field(default_factory=dict)
    summary: str = ""


# --- Subdomain Takeover ---


class TakeoverFinding(BaseFinding):
    """A subdomain potentially vulnerable to takeover."""

    subdomain: str
    service: str = Field(..., description="Service that could be taken over (e.g., GitHub Pages)")
    confidence: Literal["low", "medium", "high"] = "medium"
    source: str = "takeover_check"
