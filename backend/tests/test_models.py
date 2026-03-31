"""Tests for data models and risk scoring."""

import pytest
from reconbolt.models.scan import ScanConfig, ScanResult, ScanStatus, ScanSummary
from reconbolt.models.findings import (
    SubdomainFinding,
    PortFinding,
    VulnerabilityFinding,
    HeaderFinding,
    CORSFinding,
    TakeoverFinding,
    OSINTFinding,
)


class TestScanConfig:
    """Tests for ScanConfig validation."""

    def test_defaults(self):
        config = ScanConfig(target="example.com")
        assert config.target == "example.com"
        assert config.intensity == "normal"
        assert config.enable_subdomain_enum is True
        assert config.enable_port_scan is True
        assert config.enable_bruteforce is False

    def test_custom_config(self):
        config = ScanConfig(
            target="test.com",
            intensity="aggressive",
            enable_bruteforce=True,
            top_ports=50,
        )
        assert config.intensity == "aggressive"
        assert config.enable_bruteforce is True
        assert config.top_ports == 50

    def test_invalid_intensity(self):
        with pytest.raises(Exception):
            ScanConfig(target="x.com", intensity="invalid")

    def test_port_range_validation(self):
        with pytest.raises(Exception):
            ScanConfig(target="x.com", top_ports=0)
        with pytest.raises(Exception):
            ScanConfig(target="x.com", top_ports=70000)


class TestFindings:
    """Tests for finding model creation."""

    def test_subdomain_finding(self):
        f = SubdomainFinding(host="example.com", subdomain="api.example.com", ip_address="1.2.3.4")
        assert f.subdomain == "api.example.com"
        assert f.source == "subdomain_enum"

    def test_port_finding(self):
        f = PortFinding(host="example.com", source="nmap", port=443, service_name="https", product="nginx", version="1.21")
        assert f.port == 443
        assert f.service_string == "https (nginx 1.21)"

    def test_port_finding_minimal(self):
        f = PortFinding(host="example.com", source="nmap", port=22, service_name="ssh")
        assert f.service_string == "ssh"

    def test_vulnerability_finding(self):
        f = VulnerabilityFinding(
            host="example.com",
            source="sqlmap",
            vuln_type="sql_injection",
            severity="critical",
            title="SQL Injection on login form",
        )
        assert f.severity == "critical"
        assert f.vuln_type == "sql_injection"

    def test_cors_finding(self):
        f = CORSFinding(
            host="example.com",
            tested_origin="https://evil.com",
            reflected_origin="https://evil.com",
            credentials_allowed=True,
            severity="critical",
        )
        assert f.credentials_allowed is True

    def test_header_finding(self):
        f = HeaderFinding(
            host="example.com",
            header_name="Strict-Transport-Security",
            present=False,
            description="HSTS enforces HTTPS",
            recommendation="Add HSTS header",
        )
        assert f.present is False

    def test_takeover_finding(self):
        f = TakeoverFinding(host="example.com", subdomain="dev.example.com", service="GitHub Pages")
        assert f.confidence == "medium"


class TestRiskScoring:
    """Tests for the risk scoring algorithm."""

    def test_clean_target(self):
        result = ScanResult(target="clean.com", config=ScanConfig(target="clean.com"))
        result.compute_summary()
        assert result.summary.risk_score == 0.0
        assert result.summary.risk_level == "info"

    def test_critical_ports(self):
        result = ScanResult(target="t.com", config=ScanConfig(target="t.com"))
        # Add critical ports
        result.ports = [
            PortFinding(host="t.com", source="nmap", port=3306, service_name="mysql"),
            PortFinding(host="t.com", source="nmap", port=6379, service_name="redis"),
        ]
        result.compute_summary()
        assert result.summary.risk_score >= 3.0

    def test_vulnerability_scoring(self):
        result = ScanResult(target="t.com", config=ScanConfig(target="t.com"))
        result.vulnerabilities = [
            VulnerabilityFinding(host="t.com", source="sqlmap", vuln_type="sql_injection", severity="critical"),
            VulnerabilityFinding(host="t.com", source="nikto", vuln_type="web_vuln", severity="medium"),
        ]
        result.compute_summary()
        assert result.summary.risk_score >= 1.0
        assert result.summary.total_vulnerabilities == 2

    def test_takeover_high_risk(self):
        result = ScanResult(target="t.com", config=ScanConfig(target="t.com"))
        result.takeovers = [
            TakeoverFinding(host="t.com", subdomain="dev.t.com", service="GitHub Pages"),
        ]
        result.compute_summary()
        assert result.summary.risk_score >= 2.0
        assert result.summary.total_takeovers == 1

    def test_max_risk_capped(self):
        result = ScanResult(target="t.com", config=ScanConfig(target="t.com"))
        # Add lots of findings to test cap at 10
        result.ports = [
            PortFinding(host="t.com", source="nmap", port=p, service_name="svc")
            for p in [21, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017]
        ]
        result.vulnerabilities = [
            VulnerabilityFinding(host="t.com", source="test", vuln_type="test", severity="critical")
            for _ in range(10)
        ]
        result.takeovers = [
            TakeoverFinding(host="t.com", subdomain=f"sub{i}.t.com", service="svc")
            for i in range(5)
        ]
        result.compute_summary()
        assert result.summary.risk_score <= 10.0
        assert result.summary.risk_level == "critical"
