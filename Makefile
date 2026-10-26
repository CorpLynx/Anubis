# Anubis Makefile
# Convenient targets for common operations
#
# Usage: make <target> [VAR=value ...]

SHELL := /bin/bash
.PHONY: help require-model quick full watch build test lint benchmark clean audit update-advisories install ci sarif json format

# Default configuration
FORMAT ?= rich
MODEL ?=
WATCH_DIR ?= .
IMAGE ?= anubis-scanner:latest
PYTHON ?= python3

help:
	@echo "Anubis - Security Scanner for Local AI Models"
	@echo ""
	@echo "Usage: make <target> [VAR=value ...]"
	@echo ""
	@echo "Targets:"
	@echo "  quick MODEL=<path>         Fast scan with tight limits"
	@echo "  full MODEL=<path>          Full scan with online provenance checks"
	@echo "  watch WATCH_DIR=<dir>      Continuous scanning of new or changed models"
	@echo "  sarif MODEL=<path>         Full scan, SARIF written to results.sarif"
	@echo "  json MODEL=<path>          Full scan, JSON written to scan-results.json"
	@echo "  audit                      Audit the local environment"
	@echo "  build                      Build Docker image ($(IMAGE))"
	@echo "  install                    Install Anubis in editable mode with dev extras"
	@echo "  test                       Run pytest test suite"
	@echo "  lint                       Lint with ruff and check formatting with black"
	@echo "  benchmark                  Run the labeled threat corpus benchmark"
	@echo "  ci                         lint + test + benchmark"
	@echo "  format                     Format code with black"
	@echo "  clean                      Remove build artifacts and cache"
	@echo "  update-advisories          Refresh Ollama security advisories"
	@echo ""
	@echo "Variables:"
	@echo "  FORMAT     Output format: rich|json|sarif (default: rich)"
	@echo "  MODEL      Target model path for quick/full/sarif/json"
	@echo "  WATCH_DIR  Directory to watch (default: .)"

require-model:
	@if [ -z "$(MODEL)" ]; then echo "Error: set MODEL=<path>" >&2; exit 2; fi

# Quick scan with tight limits
quick: require-model
	@./scripts/quick-scan.sh "$(MODEL)" --format "$(FORMAT)"

# Full scan with all inspections including online provenance
full: require-model
	@./scripts/full-scan.sh "$(MODEL)" --format "$(FORMAT)" --online

# Continuous watch mode for a directory
watch:
	@./scripts/watch.sh "$(WATCH_DIR)" --format "$(FORMAT)"

# Generate a SARIF report for a model
sarif: require-model
	@./scripts/full-scan.sh "$(MODEL)" --format sarif > results.sarif; \
	status=$$?; echo "SARIF report written to results.sarif (exit code $$status)"; exit $$status

# Export scan results to JSON
json: require-model
	@./scripts/full-scan.sh "$(MODEL)" --format json > scan-results.json; \
	status=$$?; echo "Scan results exported to scan-results.json (exit code $$status)"; exit $$status

# Audit the local environment (network, runners, workspace secrets)
audit:
	anubis audit --workspace . --format "$(FORMAT)"

# Build Docker image
build:
	docker build -t "$(IMAGE)" .
	@echo "Docker image built: $(IMAGE)"
	@docker run --rm "$(IMAGE)" --help

# Install Anubis in development mode
install:
	$(PYTHON) -m pip install -e '.[dev]'

# Run pytest test suite
test:
	$(PYTHON) -m pytest -v

# Lint with ruff and check formatting with black (both configured in pyproject.toml)
lint:
	ruff check src tests scripts
	black --check src tests scripts

# Format code with black
format:
	black src tests scripts

# Run the labeled threat corpus benchmark
benchmark:
	$(PYTHON) scripts/benchmark_security_corpus.py

# CI-style check
ci: lint test benchmark
	@echo "All checks passed!"

# Remove build artifacts and cache
clean:
	find . -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build/ dist/ src/*.egg-info/ .pytest_cache/ .ruff_cache/ .hypothesis/ .coverage htmlcov/
	@echo "Cleaned build artifacts and cache"

# Refresh Ollama security advisories from OSV.dev
update-advisories:
	$(PYTHON) scripts/update_ollama_advisories.py
