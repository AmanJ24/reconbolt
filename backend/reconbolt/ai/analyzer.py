"""Multi-provider AI analysis engine.

Supports Google Gemini (primary) and OpenAI (fallback).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from reconbolt.ai.prompts import EXECUTIVE_SUMMARY_PROMPT
from reconbolt.config import get_settings

if TYPE_CHECKING:
    from reconbolt.models.scan import ScanResult


class AIAnalyzer:
    """Generates AI-powered security analysis from scan results."""

    def __init__(self) -> None:
        self.settings = get_settings()

    async def analyze(self, result: ScanResult, prompt_type: str = "executive") -> str:
        """Analyze scan results using the best available AI provider."""
        # Prepare scan data summary (avoid sending massive payloads)
        scan_data = self._prepare_scan_data(result)
        prompt = EXECUTIVE_SUMMARY_PROMPT.format(scan_data=json.dumps(scan_data, indent=2, default=str))

        # Try Gemini first, then OpenAI
        if self.settings.gemini_api_key:
            try:
                return await self._analyze_with_gemini(prompt)
            except Exception as e:
                if self.settings.openai_api_key:
                    pass  # Fall through to OpenAI
                else:
                    return f"AI analysis failed (Gemini error: {e})"

        if self.settings.openai_api_key:
            try:
                return await self._analyze_with_openai(prompt)
            except Exception as e:
                return f"AI analysis failed (OpenAI error: {e})"

        return "AI analysis unavailable — no API keys configured."

    async def _analyze_with_gemini(self, prompt: str) -> str:
        """Run analysis using Google Gemini."""
        import asyncio
        from google import genai

        client = genai.Client(api_key=self.settings.gemini_api_key)

        response = await asyncio.to_thread(
            client.models.generate_content,
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return response.text

    async def _analyze_with_openai(self, prompt: str) -> str:
        """Run analysis using OpenAI."""
        import asyncio
        from openai import OpenAI

        client = OpenAI(api_key=self.settings.openai_api_key)

        response = await asyncio.to_thread(
            client.chat.completions.create,
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity analyst."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=2000,
            temperature=0.3,
        )
        return response.choices[0].message.content

    def _prepare_scan_data(self, result: ScanResult) -> dict:
        """Prepare a concise summary of scan results for the AI prompt."""
        return {
            "target": result.target,
            "scan_duration": result.duration_seconds,
            "summary": {
                "total_subdomains": result.summary.total_subdomains,
                "total_open_ports": result.summary.total_open_ports,
                "total_vulnerabilities": result.summary.total_vulnerabilities,
                "total_takeovers": result.summary.total_takeovers,
                "risk_score": result.summary.risk_score,
                "risk_level": result.summary.risk_level,
            },
            "subdomains": [s.subdomain for s in result.subdomains[:30]],
            "open_ports": [
                {"host": p.host, "port": p.port, "service": p.service_string}
                for p in result.ports[:50]
            ],
            "vulnerabilities": [
                {"host": v.host, "type": v.vuln_type, "severity": v.severity, "title": v.title}
                for v in result.vulnerabilities
            ],
            "cors_issues": [
                {"host": c.host, "origin": c.tested_origin, "credentials": c.credentials_allowed}
                for c in result.cors_findings
            ],
            "missing_headers": [h.header_name for h in result.headers if not h.present],
            "osint_summaries": [o.summary for o in result.osint],
            "takeovers": [
                {"subdomain": t.subdomain, "service": t.service}
                for t in result.takeovers
            ],
        }
