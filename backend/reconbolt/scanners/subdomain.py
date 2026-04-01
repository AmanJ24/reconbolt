"""Subdomain enumeration scanner.

Discovers subdomains using multiple sources:
- Certificate Transparency (crt.sh)
- VirusTotal API (with pagination)
- AlienVault OTX passive DNS
- URLScan.io
- DNS brute-force with customizable wordlists
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import httpx

from reconbolt.engine.events import ScanPhase
from reconbolt.models.findings import SubdomainFinding
from reconbolt.scanners.base import BaseScanner

# Default wordlist for DNS brute-force
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "login", "admin", "test", "dev", "api", "blog",
    "shop", "app", "mobile", "m", "secure", "vpn", "remote", "portal", "cdn", "images",
    "docs", "staging", "beta", "alpha", "demo", "sandbox", "auth", "account", "billing",
    "store", "download", "media", "static", "assets", "content", "support", "help", "wiki",
    "status", "dashboard", "analytics", "monitor", "internal", "web", "server", "ns1", "ns2",
    "smtp", "mx", "email", "cloud", "git", "gitlab", "jenkins", "ci", "jira", "confluence",
    "signup", "sso", "corp", "intranet", "extranet", "uat", "prod", "backup", "relay",
    "proxy", "gateway", "edge", "lb", "redis", "db", "mysql", "postgres", "mongo", "elastic",
    "kafka", "queue", "mq", "s3", "storage", "vault", "key", "log", "logs", "grafana",
    "prometheus", "kibana", "sentry", "oauth", "iam", "directory",
]


class SubdomainScanner(BaseScanner):
    """Discovers subdomains using multiple passive and active techniques."""

    phase = ScanPhase.SUBDOMAIN_ENUM

    async def scan(self, **kwargs: Any) -> list[SubdomainFinding]:
        """Run all subdomain enumeration sources and deduplicate results."""
        self.emitter.info(self.phase, f"Starting subdomain enumeration for {self.config.target}")

        all_subdomains: set[str] = set()

        # Passive sources
        sources = {
            "crt.sh": self._from_crtsh,
            "VirusTotal": self._from_virustotal,
            "AlienVault OTX": self._from_otx,
            "URLScan.io": self._from_urlscan,
        }

        total_sources = len(sources) + (1 if self.config.enable_bruteforce else 0)
        completed = 0

        async with httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": "ReconBolt/1.0"},
            follow_redirects=True,
        ) as client:
            for name, func in sources.items():
                try:
                    self.emitter.info(self.phase, f"Querying {name}...")
                    found = await func(client)
                    all_subdomains.update(found)
                    self.emitter.success(
                        self.phase,
                        f"Found {len(found)} subdomains from {name}",
                        progress=(completed + 1) / total_sources * 20,  # 0-20% for enumeration
                    )
                except Exception as e:
                    self.emitter.warning(self.phase, f"Error querying {name}: {e}")
                completed += 1

        # Active: DNS brute-force
        if self.config.enable_bruteforce:
            try:
                brute_found = await self._bruteforce()
                all_subdomains.update(brute_found)
                self.emitter.success(
                    self.phase,
                    f"DNS brute-force found {len(brute_found)} subdomains",
                    progress=25.0,
                )
            except Exception as e:
                self.emitter.warning(self.phase, f"DNS brute-force error: {e}")

        # Build findings — resolve IPs concurrently
        findings = []
        subdomains_sorted = sorted(all_subdomains)

        if subdomains_sorted:
            self.emitter.info(self.phase, f"Resolving IPs for {len(subdomains_sorted)} subdomains...")

            # Resolve IPs in batches using asyncio
            async def resolve(subdomain: str) -> tuple[str, str | None]:
                ip = await asyncio.to_thread(self._resolve_ip, subdomain)
                return subdomain, ip

            # Run all resolutions concurrently with a semaphore to avoid flooding
            sem = asyncio.Semaphore(20)

            async def resolve_with_sem(subdomain: str) -> tuple[str, str | None]:
                async with sem:
                    return await resolve(subdomain)

            results = await asyncio.gather(
                *(resolve_with_sem(s) for s in subdomains_sorted),
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, tuple):
                    subdomain, ip = result
                    findings.append(
                        SubdomainFinding(
                            host=self.config.target,
                            subdomain=subdomain,
                            ip_address=ip,
                        )
                    )

        self.emitter.success(
            self.phase,
            f"Total unique subdomains discovered: {len(findings)}",
            progress=25.0,
        )
        return findings

    # --- Source Implementations ---

    async def _from_crtsh(self, client: httpx.AsyncClient) -> set[str]:
        """Query Certificate Transparency logs via crt.sh."""
        url = f"https://crt.sh/?q=%.{self.config.target}&output=json"
        subdomains: set[str] = set()
        try:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for item in data:
                        name = item.get("name_value", "").lower().strip()
                        # Handle multi-line cert entries
                        for line in name.split("\n"):
                            line = line.strip()
                            if line.endswith(f".{self.config.target}") and "*" not in line:
                                subdomains.add(line)
        except (httpx.HTTPError, ValueError) as e:
            self.emitter.warning(self.phase, f"crt.sh error: {e}")
        return subdomains

    async def _from_virustotal(self, client: httpx.AsyncClient) -> set[str]:
        """Query VirusTotal subdomains API with pagination."""
        if not self.settings.has_virustotal:
            self.emitter.warning(self.phase, "VirusTotal API key not configured, skipping")
            return set()

        subdomains: set[str] = set()
        url: str | None = f"https://www.virustotal.com/api/v3/domains/{self.config.target}/subdomains?limit=40"
        headers = {"x-apikey": self.settings.virustotal_api_key}

        try:
            while url:
                response = await client.get(url, headers=headers)
                if response.status_code != 200:
                    self.emitter.warning(self.phase, f"VirusTotal returned status {response.status_code}")
                    break
                data = response.json()
                for item in data.get("data", []):
                    subdomains.add(item["id"])
                url = data.get("links", {}).get("next")
        except Exception as e:
            self.emitter.warning(self.phase, f"VirusTotal error: {e}")

        return subdomains

    async def _from_otx(self, client: httpx.AsyncClient) -> set[str]:
        """Query AlienVault OTX passive DNS."""
        if not self.settings.has_otx:
            self.emitter.warning(self.phase, "AlienVault OTX key not configured, skipping")
            return set()

        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.config.target}/passive_dns"
        headers = {"X-OTX-API-KEY": self.settings.alienvault_otx_key}
        subdomains: set[str] = set()

        try:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                for record in response.json().get("passive_dns", []):
                    hostname = record.get("hostname", "")
                    if hostname.endswith(f".{self.config.target}"):
                        subdomains.add(hostname)
        except Exception as e:
            self.emitter.warning(self.phase, f"OTX error: {e}")

        return subdomains

    async def _from_urlscan(self, client: httpx.AsyncClient) -> set[str]:
        """Query URLScan.io for subdomains."""
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.config.target}"
        subdomains: set[str] = set()

        try:
            response = await client.get(url)
            if response.status_code == 200:
                for result in response.json().get("results", []):
                    domain = result.get("task", {}).get("domain", "")
                    if domain.endswith(f".{self.config.target}"):
                        subdomains.add(domain)
        except Exception as e:
            self.emitter.warning(self.phase, f"URLScan error: {e}")

        return subdomains

    async def _bruteforce(self) -> set[str]:
        """DNS brute-force using a wordlist."""
        wordlist = DEFAULT_WORDLIST

        if self.config.wordlist_path:
            try:
                from pathlib import Path
                wl_path = Path(self.config.wordlist_path)
                if wl_path.is_file():
                    wordlist = [line.strip() for line in wl_path.read_text().splitlines() if line.strip()]
                    self.emitter.info(self.phase, f"Loaded custom wordlist: {len(wordlist)} entries")
            except Exception as e:
                self.emitter.warning(self.phase, f"Error loading wordlist, using default: {e}")

        self.emitter.info(self.phase, f"Starting DNS brute-force with {len(wordlist)} words...")
        found: set[str] = set()

        sem = asyncio.Semaphore(30)

        async def try_subdomain(word: str) -> str | None:
            async with sem:
                subdomain = f"{word}.{self.config.target}"
                ip = await asyncio.to_thread(self._resolve_ip, subdomain)
                if ip:
                    return subdomain
                return None

        tasks = [try_subdomain(word) for word in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, str):
                found.add(result)
                self.emitter.info(self.phase, f"Discovered: {result}")
            # Report progress periodically
            if (i + 1) % 20 == 0:
                pct = (i + 1) / len(wordlist) * 100
                self.emitter.info(self.phase, f"Brute-force progress: {i + 1}/{len(wordlist)}", progress=pct)

        return found

    @staticmethod
    def _resolve_ip(hostname: str) -> str | None:
        """Try to resolve a hostname to an IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.error:
            return None
