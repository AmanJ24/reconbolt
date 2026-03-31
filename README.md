<div align="center">

# ⚡ ReconBolt

### AI-Powered Cybersecurity Reconnaissance Platform

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Automated attack surface discovery · Network enumeration · Vulnerability assessment · AI-driven security analysis**

</div>

---

## 🚀 Overview

ReconBolt is a production-grade, modular reconnaissance platform that transforms traditional security scanning into an intelligent, automated workflow. It features **6 modular scanner plugins**, a **Rich CLI**, a **FastAPI REST + WebSocket API**, and a **React dashboard** — all powered by AI analysis from Gemini and OpenAI.

### Key Capabilities

| Module | What It Does |
|---|---|
| 🌐 **Subdomain Discovery** | crt.sh, VirusTotal, AlienVault OTX, URLScan.io, DNS brute-force |
| 🔓 **Port Scanning** | Concurrent nmap with service & version detection |
| 🛡️ **Vulnerability Scanner** | Security headers, CORS misconfigs, SQL injection (sqlmap), web vulns (Nikto) |
| 🕵️ **Threat Intelligence** | Shodan host intel, VirusTotal domain reputation, CVE correlation |
| ⚠️ **Takeover Detection** | Subdomain takeover vulnerability detection via subzy |
| 🤖 **AI Analysis** | Gemini / OpenAI executive security briefings with risk assessment |

### Additional Features

- 📊 **Algorithmic Risk Scoring** — 0-10 score based on exposed services, CVEs, misconfigurations
- 📄 **Multi-Format Reports** — JSON (machine), Markdown (human), standalone HTML (dark theme)
- ⚡ **Fully Async** — Concurrent scanning with `asyncio` and `httpx`
- 🌐 **REST API + WebSocket** — Real-time scan progress streaming
- 🖥️ **Beautiful CLI** — Rich progress bars, colored output, formatted tables
- 🎨 **React Dashboard** — Dark cyberpunk theme with glassmorphism and neon accents

---

## 📐 Architecture

```
reconbolt/
├── backend/                          # Python package
│   ├── reconbolt/
│   │   ├── config.py                # Pydantic Settings (.env loading)
│   │   ├── models/                  # Pydantic data models & risk scoring
│   │   │   ├── scan.py             # ScanConfig, ScanResult, ScanStatus
│   │   │   └── findings.py         # 7 typed finding models
│   │   ├── scanners/                # Modular scanner plugins
│   │   │   ├── base.py             # Abstract BaseScanner interface
│   │   │   ├── subdomain.py        # Multi-source subdomain enumeration
│   │   │   ├── port_scanner.py     # Async nmap wrapper
│   │   │   ├── vuln_scanner.py     # Headers, CORS, SQLi, Nikto
│   │   │   ├── osint.py            # Shodan & VirusTotal intel
│   │   │   └── takeover.py         # Subdomain takeover (subzy)
│   │   ├── engine/                  # Orchestration layer
│   │   │   ├── orchestrator.py     # Scan pipeline & error isolation
│   │   │   └── events.py           # Real-time event system
│   │   ├── ai/                      # AI analysis engine
│   │   │   ├── analyzer.py         # Gemini + OpenAI dual-provider
│   │   │   └── prompts.py          # Security analysis prompts
│   │   ├── reporting/               # Report generation
│   │   │   └── generator.py        # JSON, Markdown, HTML output
│   │   ├── api/                     # FastAPI REST + WebSocket
│   │   │   ├── app.py              # Application factory
│   │   │   └── routes/             # Scan CRUD & health endpoints
│   │   └── cli/                     # Rich terminal interface
│   │       └── main.py             # Typer CLI with Rich
│   ├── tests/                       # pytest suite (26 tests)
│   ├── pyproject.toml               # Modern Python packaging
│   └── .env.example                 # API key template
└── frontend/                         # React + TypeScript + Vite
    └── src/
        ├── components/              # Dashboard, ScanForm, Progress, Results, History
        ├── services/                # REST & WebSocket API client
        ├── types.ts                 # Full TypeScript type system
        └── index.css                # Dark cyberpunk design system
```

---

## ⚡ Quick Start

### Prerequisites

- **Python 3.10+**
- **Node.js 18+** (for the dashboard)
- **nmap** (for port scanning)

### 1. Clone & Install

```bash
git clone https://github.com/AmanJ24/reconbolt.git
cd reconbolt/backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate    # Linux/Mac
# .\venv\Scripts\activate   # Windows

# Install with all dependencies
pip install -e ".[all]"
```

### 2. Configure API Keys

```bash
cp .env.example .env
```

Edit `.env` and add your API keys (all optional but recommended):

```env
GEMINI_API_KEY="your-gemini-key"
OPENAI_API_KEY="your-openai-key"
VIRUSTOTAL_API_KEY="your-vt-key"
SHODAN_API_KEY="your-shodan-key"
```

### 3. Run a Scan (CLI)

```bash
# Basic scan
reconbolt scan example.com

# Aggressive scan with DNS brute-force
reconbolt scan example.com --intensity aggressive --bruteforce

# Skip specific phases
reconbolt scan example.com --skip-ports --skip-osint

# JSON output only (for piping)
reconbolt scan example.com --json > results.json
```

### 4. Run the API Server

```bash
uvicorn reconbolt.api.app:app --reload
# Interactive docs at http://localhost:8000/docs
```

### 5. Run the Dashboard

```bash
cd ../frontend
npm install
npm run dev
# Opens at http://localhost:5173
```

### 6. Run Tests

```bash
cd backend
pytest tests/ -v
```

---

## 🖥️ CLI Reference

```
Usage: reconbolt scan [OPTIONS] TARGET

  ⚡ Run a full reconnaissance scan against a target.

Options:
  -i, --intensity TEXT     Scan speed: low, normal, aggressive  [default: normal]
  -o, --output TEXT        Custom output directory for reports
  -b, --bruteforce         Enable DNS brute-force subdomain enumeration
  -w, --wordlist TEXT      Custom wordlist path for brute-force
  --skip-subdomains        Skip subdomain enumeration
  --skip-ports             Skip port scanning
  --skip-vuln              Skip vulnerability scanning
  --skip-osint             Skip OSINT gathering
  --skip-ai                Skip AI analysis
  --json                   Output JSON only (no Rich formatting)
  --help                   Show this message and exit.
```

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/api/scans/` | Start a new scan |
| `GET` | `/api/scans/` | List all scans |
| `GET` | `/api/scans/{id}` | Get full scan results |
| `DELETE` | `/api/scans/{id}` | Delete or cancel a scan |
| `WS` | `/api/scans/{id}/ws` | Real-time scan progress via WebSocket |

Full interactive documentation available at `/docs` (Swagger) or `/redoc` when the API server is running.

---

## 🔧 External Tools

For full functionality, install these optional system tools:

```bash
# Debian/Ubuntu
sudo apt install nmap sqlmap nikto

# Subdomain takeover detection
go install -v github.com/LukaSikic/subzy@latest
```

ReconBolt gracefully degrades — scanners automatically skip if their tools aren't installed.

---

## 🧪 Testing

```bash
cd backend
pytest tests/ -v --tb=short

# With coverage
pytest tests/ -v --cov=reconbolt --cov-report=html
```

Current test suite: **26 tests** covering:
- Data model validation & serialization
- Risk scoring algorithm (edge cases, cap at 10)
- Event system (emission, listeners, error isolation)
- API endpoints (health, CRUD, scan lifecycle)

---

## 🛠️ Development

```bash
# Install dev dependencies
cd backend
pip install -e ".[all]"

# Lint
ruff check reconbolt/ tests/

# Format
ruff format reconbolt/ tests/

# Run API with hot reload
uvicorn reconbolt.api.app:app --reload

# Run frontend with hot reload
cd ../frontend && npm run dev
```

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**This tool is intended for authorized security assessments only.** Always obtain proper written permission before scanning any systems or networks you do not own. Unauthorized scanning may violate applicable laws and regulations. The authors are not responsible for misuse of this tool.

---

<div align="center">
  <sub>Built with ⚡ by <a href="https://github.com/AmanJ24">Aman</a></sub>
</div>
