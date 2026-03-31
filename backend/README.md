# ⚡ ReconBolt

**AI-Powered Cybersecurity Reconnaissance Platform**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109%2B-green)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A production-grade, modular reconnaissance tool that automates attack surface discovery, network enumeration, vulnerability assessment, and AI-powered analysis — with a beautiful CLI and a REST API.

---

## Architecture

```
reconbolt/
├── backend/
│   ├── reconbolt/              # Python package
│   │   ├── config.py           # Pydantic Settings (.env loading)
│   │   ├── models/             # Pydantic data models
│   │   ├── scanners/           # Modular scanner plugins
│   │   │   ├── base.py         # Abstract BaseScanner
│   │   │   ├── subdomain.py    # crt.sh, VirusTotal, OTX, DNS brute
│   │   │   ├── port_scanner.py # Async nmap wrapper
│   │   │   ├── vuln_scanner.py # Headers, CORS, SQLi, Nikto
│   │   │   ├── osint.py        # Shodan, VirusTotal intel
│   │   │   └── takeover.py     # Subdomain takeover (subzy)
│   │   ├── engine/             # Orchestration & events
│   │   ├── ai/                 # Multi-provider AI analysis
│   │   ├── reporting/          # JSON, Markdown, HTML reports
│   │   ├── api/                # FastAPI REST + WebSocket
│   │   └── cli/                # Rich terminal interface
│   ├── tests/                  # pytest test suite
│   └── pyproject.toml          # Modern packaging
└── frontend/                   # React dashboard (coming soon)
```

## Features

- 🔎 **Subdomain Discovery** — crt.sh, VirusTotal, OTX, URLScan, DNS brute-force
- 🔓 **Port Scanning** — Concurrent nmap with service version detection
- 🛡️ **Vulnerability Scanning** — Security headers, CORS, SQLi (sqlmap), web vulns (Nikto)
- 🌐 **Threat Intelligence** — Shodan host intel, VirusTotal reputation
- ⚠️ **Subdomain Takeover** — Detection via subzy
- 🤖 **AI Analysis** — Gemini / OpenAI executive summaries & risk assessment
- 📊 **Risk Scoring** — Algorithmic 0-10 risk score with severity classification
- 📄 **Multi-Format Reports** — JSON, Markdown tables, standalone HTML
- 🖥️ **Beautiful CLI** — Rich progress bars, colored output, formatted tables
- 🌐 **REST API** — FastAPI with WebSocket for real-time scan progress
- ⚡ **Fully Async** — Concurrent scanning with asyncio

## Quick Start

### 1. Install

```bash
cd reconbolt/backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install with all dependencies
pip install -e ".[all]"
```

### 2. Configure API Keys

```bash
cp .env.example .env
# Edit .env with your API keys (all optional but recommended)
```

### 3. Run a Scan (CLI)

```bash
# Basic scan
reconbolt scan example.com

# Aggressive scan with brute-force
reconbolt scan example.com --intensity aggressive --bruteforce

# Skip specific phases
reconbolt scan example.com --skip-ports --skip-osint

# JSON output only
reconbolt scan example.com --json
```

### 4. Run the API Server

```bash
uvicorn reconbolt.api.app:app --reload

# API docs at http://localhost:8000/docs
```

### 5. Run Tests

```bash
pytest tests/ -v
```

## CLI Commands

| Command | Description |
|---|---|
| `reconbolt scan <target>` | Run a full recon scan |
| `reconbolt version` | Show version |

### Scan Options

| Flag | Description | Default |
|---|---|---|
| `--intensity` | Scan speed: low, normal, aggressive | normal |
| `--bruteforce` | Enable DNS brute-force | off |
| `--wordlist` | Custom brute-force wordlist path | built-in |
| `--skip-subdomains` | Skip subdomain enumeration | — |
| `--skip-ports` | Skip port scanning | — |
| `--skip-vuln` | Skip vulnerability scanning | — |
| `--skip-osint` | Skip OSINT gathering | — |
| `--skip-ai` | Skip AI analysis | — |
| `--json` | JSON-only output (no Rich) | — |
| `-o` / `--output` | Custom output directory | auto |

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/api/scans/` | Start a new scan |
| GET | `/api/scans/` | List all scans |
| GET | `/api/scans/{id}` | Get scan results |
| DELETE | `/api/scans/{id}` | Delete/cancel scan |
| WS | `/api/scans/{id}/ws` | Real-time scan progress |

## External Tools (Optional)

For full functionality, install these system tools:

```bash
sudo apt install nmap sqlmap nikto
go install -v github.com/LukaSikic/subzy@latest
```

## License

MIT License — see [LICENSE](LICENSE) for details.

---

⚠️ **Disclaimer**: This tool is for authorized security assessments only. Always obtain proper permission before scanning any systems.
