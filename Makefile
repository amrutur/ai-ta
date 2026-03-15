.PHONY: run test lint format install clean

# ---------------------------------------------------------------------------
# Development
# ---------------------------------------------------------------------------

## Install all dependencies (app + dev/test)
install:
	pip install -r requirements-dev.txt

## Run the app locally (requires .env with valid GCP credentials)
run:
	cd src && python api_server.py

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------

## Run the full test suite
test:
	pytest tests/ -v

## Lint source and test files
lint:
	ruff check src/ tests/

## Auto-format source and test files
format:
	ruff format src/ tests/

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------

## Remove Python cache files
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache
