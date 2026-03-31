.PHONY: install dev test lint api cli clean

install:
	pip install -e ".[all]"

dev:
	pip install -e ".[all]"

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --cov=reconbolt --cov-report=html

lint:
	ruff check reconbolt/ tests/
	ruff format --check reconbolt/ tests/

format:
	ruff format reconbolt/ tests/

api:
	uvicorn reconbolt.api.app:app --reload --host 0.0.0.0 --port 8000

cli:
	python -m reconbolt.cli.main scan example.com --skip-ports --skip-vuln --skip-osint --skip-ai

clean:
	rm -rf __pycache__ .pytest_cache .coverage htmlcov *.egg-info dist build
	find . -type d -name __pycache__ -exec rm -rf {} +
