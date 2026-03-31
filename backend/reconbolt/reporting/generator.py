"""Multi-format report generator.

Produces JSON, Markdown, and standalone HTML reports from scan results.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reconbolt.models.scan import ScanResult


class ReportGenerator:
    """Generates scan reports in multiple formats."""

    def __init__(self, result: ScanResult, output_dir: Path | None = None) -> None:
        self.result = result
        self.output_dir = output_dir or Path(f"scan_results_{result.target.replace('.', '_')}_{result.scan_id}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self) -> dict[str, Path]:
        """Generate reports in all formats. Returns dict of format -> file path."""
        paths = {}
        paths["json"] = self.generate_json()
        paths["markdown"] = self.generate_markdown()
        paths["html"] = self.generate_html()
        return paths

    def generate_json(self) -> Path:
        """Generate a JSON report."""
        path = self.output_dir / "report.json"
        with open(path, "w") as f:
            json.dump(self.result.model_dump(), f, indent=2, default=str)
        return path

    def generate_markdown(self) -> Path:
        """Generate a Markdown report."""
        r = self.result
        s = r.summary
        lines = [
            f"# ReconBolt Security Report — {r.target}",
            "",
            f"**Scan ID:** `{r.scan_id}`  ",
            f"**Date:** {r.started_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Duration:** {r.duration_seconds}s  ",
            f"**Risk Level:** **{s.risk_level.upper()}** ({s.risk_score}/10)",
            "",
            "---",
            "",
            "## Summary",
            "",
            f"| Metric | Count |",
            f"|---|---|",
            f"| Subdomains Discovered | {s.total_subdomains} |",
            f"| Open Ports | {s.total_open_ports} |",
            f"| Vulnerabilities | {s.total_vulnerabilities} |",
            f"| Subdomain Takeovers | {s.total_takeovers} |",
            "",
        ]

        # Subdomains
        if r.subdomains:
            lines.extend([
                "## Discovered Subdomains",
                "",
                "| Subdomain | IP Address |",
                "|---|---|",
            ])
            for sub in r.subdomains[:50]:
                lines.append(f"| {sub.subdomain} | {sub.ip_address or 'N/A'} |")
            lines.append("")

        # Open ports
        if r.ports:
            lines.extend([
                "## Open Ports",
                "",
                "| Host | Port | Service | Version |",
                "|---|---|---|---|",
            ])
            for p in r.ports:
                svc = p.service_name
                ver = f"{p.product} {p.version}".strip() or "—"
                lines.append(f"| {p.host} | {p.port}/{p.protocol} | {svc} | {ver} |")
            lines.append("")

        # Vulnerabilities
        if r.vulnerabilities:
            lines.extend([
                "## Vulnerabilities",
                "",
                "| Host | Type | Severity | Title |",
                "|---|---|---|---|",
            ])
            for v in r.vulnerabilities:
                lines.append(f"| {v.host} | {v.vuln_type} | **{v.severity.upper()}** | {v.title} |")
            lines.append("")

        # CORS
        if r.cors_findings:
            lines.extend([
                "## CORS Misconfigurations",
                "",
                "| Host | Origin Tested | Credentials | Severity |",
                "|---|---|---|---|",
            ])
            for c in r.cors_findings:
                cred = "✅ Yes" if c.credentials_allowed else "No"
                lines.append(f"| {c.host} | {c.tested_origin} | {cred} | **{c.severity.upper()}** |")
            lines.append("")

        # Missing headers
        missing_headers = [h for h in r.headers if not h.present]
        if missing_headers:
            lines.extend([
                "## Missing Security Headers",
                "",
                "| Host | Header | Recommendation |",
                "|---|---|---|",
            ])
            for h in missing_headers:
                lines.append(f"| {h.host} | {h.header_name} | {h.recommendation} |")
            lines.append("")

        # Takeovers
        if r.takeovers:
            lines.extend([
                "## ⚠️ Subdomain Takeover Risks",
                "",
                "| Subdomain | Vulnerable Service | Confidence |",
                "|---|---|---|",
            ])
            for t in r.takeovers:
                lines.append(f"| {t.subdomain} | {t.service} | {t.confidence} |")
            lines.append("")

        # OSINT
        if r.osint:
            lines.extend(["## Threat Intelligence", ""])
            for o in r.osint:
                lines.append(f"- **{o.intel_source.title()}:** {o.summary}")
            lines.append("")

        # AI Analysis
        if r.ai_summary:
            lines.extend([
                "## AI Security Analysis",
                "",
                r.ai_summary,
                "",
            ])

        # Errors
        if r.errors:
            lines.extend(["## Errors Encountered", ""])
            for err in r.errors:
                lines.append(f"- {err}")
            lines.append("")

        lines.extend([
            "---",
            f"*Report generated by ReconBolt v1.0.0 on {datetime.now().strftime('%Y-%m-%d %H:%M')}*",
        ])

        path = self.output_dir / "report.md"
        path.write_text("\n".join(lines))
        return path

    def generate_html(self) -> Path:
        """Generate a standalone HTML report with embedded CSS."""
        r = self.result
        s = r.summary
        risk_color = {
            "info": "#3b82f6", "low": "#22c55e", "medium": "#f59e0b",
            "high": "#ef4444", "critical": "#dc2626",
        }.get(s.risk_level, "#6b7280")

        # Build HTML sections
        port_rows = "\n".join(
            f"<tr><td>{p.host}</td><td>{p.port}/{p.protocol}</td>"
            f"<td>{p.service_name}</td><td>{p.product} {p.version}</td></tr>"
            for p in r.ports
        )
        vuln_rows = "\n".join(
            f"<tr><td>{v.host}</td><td>{v.vuln_type}</td>"
            f"<td class='severity-{v.severity}'>{v.severity.upper()}</td><td>{v.title}</td></tr>"
            for v in r.vulnerabilities
        )
        subdomain_list = "\n".join(
            f"<li>{sub.subdomain} <span class='ip'>({sub.ip_address or 'N/A'})</span></li>"
            for sub in r.subdomains[:60]
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconBolt Report — {r.target}</title>
<style>
:root {{ --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #e2e8f0; --accent: #06b6d4; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }}
.container {{ max-width: 1200px; margin: auto; }}
h1 {{ color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }}
h2 {{ color: var(--accent); margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--border); }}
.meta {{ color: #94a3b8; margin-bottom: 2rem; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; text-align: center; }}
.card .number {{ font-size: 2.5rem; font-weight: 800; color: var(--accent); }}
.card .label {{ color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }}
.risk-badge {{ display: inline-block; padding: 0.5rem 1.5rem; border-radius: 8px; font-weight: 700; font-size: 1.1rem;
  background: {risk_color}22; color: {risk_color}; border: 2px solid {risk_color}; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card); border-radius: 8px; overflow: hidden; }}
th {{ background: #0f172a; text-align: left; padding: 0.75rem 1rem; font-size: 0.8rem; text-transform: uppercase;
  letter-spacing: 0.5px; color: #94a3b8; }}
td {{ padding: 0.6rem 1rem; border-top: 1px solid var(--border); font-size: 0.9rem; }}
tr:hover {{ background: #ffffff08; }}
.severity-critical {{ color: #dc2626; font-weight: 700; }}
.severity-high {{ color: #ef4444; font-weight: 700; }}
.severity-medium {{ color: #f59e0b; font-weight: 600; }}
.severity-low {{ color: #22c55e; }}
ul {{ list-style: none; columns: 3; gap: 0.5rem; }}
li {{ padding: 0.3rem 0; font-size: 0.9rem; }}
.ip {{ color: #64748b; font-size: 0.8rem; }}
.ai-summary {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 2rem;
  line-height: 1.7; white-space: pre-wrap; }}
footer {{ text-align: center; margin-top: 3rem; color: #475569; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>⚡ ReconBolt Security Report</h1>
  <p class="meta">Target: <strong>{r.target}</strong> &middot; Scan ID: {r.scan_id} &middot;
    {r.started_at.strftime('%Y-%m-%d %H:%M UTC')} &middot; Duration: {r.duration_seconds}s</p>

  <div style="margin: 1.5rem 0">
    <span class="risk-badge">{s.risk_level.upper()} RISK — {s.risk_score}/10</span>
  </div>

  <div class="cards">
    <div class="card"><div class="number">{s.total_subdomains}</div><div class="label">Subdomains</div></div>
    <div class="card"><div class="number">{s.total_open_ports}</div><div class="label">Open Ports</div></div>
    <div class="card"><div class="number">{s.total_vulnerabilities}</div><div class="label">Vulnerabilities</div></div>
    <div class="card"><div class="number">{s.total_takeovers}</div><div class="label">Takeover Risks</div></div>
  </div>

  {"<h2>Open Ports</h2><table><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr></thead><tbody>" + port_rows + "</tbody></table>" if r.ports else ""}

  {"<h2>Vulnerabilities</h2><table><thead><tr><th>Host</th><th>Type</th><th>Severity</th><th>Title</th></tr></thead><tbody>" + vuln_rows + "</tbody></table>" if r.vulnerabilities else ""}

  {"<h2>Discovered Subdomains (" + str(len(r.subdomains)) + ")</h2><ul>" + subdomain_list + "</ul>" if r.subdomains else ""}

  {"<h2>AI Security Analysis</h2><div class='ai-summary'>" + (r.ai_summary or '') + "</div>" if r.ai_summary else ""}

  <footer>&copy; ReconBolt v1.0.0 &middot; Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}</footer>
</div>
</body>
</html>"""

        path = self.output_dir / "report.html"
        path.write_text(html)
        return path
