# Contributing to ReconBolt

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/AmanJ24/reconbolt.git
cd reconbolt

# Backend setup
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -e ".[all]"

# Frontend setup
cd ../frontend
npm install
```

## Running Tests

```bash
cd backend
pytest tests/ -v
```

## Code Style

- **Python**: We use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting (120 char line length)
- **TypeScript**: Standard TypeScript with strict mode

```bash
# Lint & format Python
cd backend
ruff check reconbolt/ tests/
ruff format reconbolt/ tests/
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest tests/ -v`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Adding a New Scanner Module

1. Create a new file in `backend/reconbolt/scanners/`
2. Extend `BaseScanner` from `scanners/base.py`
3. Implement the `async scan()` method
4. Add finding models to `models/findings.py` if needed
5. Register the scanner in `engine/orchestrator.py`
6. Add tests in `tests/`

## Reporting Issues

Please include:
- Python version (`python --version`)
- OS and version
- Full error traceback
- Steps to reproduce
