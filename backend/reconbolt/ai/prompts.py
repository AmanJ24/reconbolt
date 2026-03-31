"""Prompt templates for AI security analysis."""

EXECUTIVE_SUMMARY_PROMPT = """You are a senior cybersecurity analyst writing an executive briefing.

Analyze the following reconnaissance scan results and produce a professional security assessment report.

## Instructions:
1. **Executive Summary** — 2-3 sentence overview of the target's security posture
2. **Critical Findings** — List the most urgent issues, ordered by severity
3. **Attack Surface Analysis** — Comment on the breadth of exposed infrastructure
4. **Network Exposure** — Analyze open ports, services, and potential risks
5. **Web Security** — Comment on header security, CORS, and vulnerability scan results
6. **Threat Intelligence** — Summarize any reputation or CVE data
7. **Risk Rating** — Assign an overall risk level (Info / Low / Medium / High / Critical) with justification
8. **Recommendations** — Prioritized, actionable remediation steps

Use markdown formatting. Be professional, concise, and actionable.

## Scan Data:
```json
{scan_data}
```
"""

TECHNICAL_DEEPDIVE_PROMPT = """You are a penetration tester providing a technical analysis.

Analyze the following scan data and provide:
1. Detailed technical analysis of each finding
2. Potential attack chains and exploitation paths
3. CVSS scoring rationale for critical findings
4. Specific remediation commands/configurations
5. Further testing recommendations

Be technically precise. Reference specific CVEs, tools, and configurations.

## Scan Data:
```json
{scan_data}
```
"""
