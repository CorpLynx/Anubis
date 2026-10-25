# Anubis Integration Usage Guide

This document provides a quick reference for using Anubis with Docker, GitHub Actions CI/CD, and script wrappers.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Docker Usage](#docker-usage)
3. [GitHub Actions CI/CD](#github-actions-cicd)
4. [Script Wrappers](#script-wrappers)
5. [Makefile Targets](#makefile-targets)
6. [Best Practices](#best-practices)

---

## Quick Start

### Installation

```bash
cd anubis
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

### Basic Scanning

```bash
# Quick scan (tight limits, fast)
./scripts/quick-scan.sh ~/.cache/huggingface/hub/models--org--repo

# Full scan (all inspections)
./scripts/full-scan.sh model.gguf --online --format json

# Continuous monitoring
./scripts/watch.sh /models --format json --output reports.log
```

---

## Docker Usage

### Build Image

```bash
docker build -t anubis-scanner:latest .

# With the Anthropic SDK for `anubis redteam --provider anthropic`
docker build --build-arg EXTRAS=judge -t anubis-scanner:judge .
```

### Run Scanner in Container

The image's entrypoint is `anubis`, its working directory is `/scan`, and it runs as an unprivileged user. Mount models read-only.

```bash
# Scan a model file
docker run --rm -v "$PWD":/scan:ro \
  anubis-scanner:latest scan /scan/model.gguf

# Scan the host's Ollama model store
docker run --rm -v ~/.ollama/models:/scan:ro \
  anubis-scanner:latest scan /scan

# Generate SARIF output
docker run --rm -v "$PWD":/scan:ro \
  anubis-scanner:latest scan /scan/model.gguf --format sarif > results.sarif
```

`anubis audit` inside a container inspects the container's network and processes, not the host's. Run `audit` on the host.

### Docker Compose (Optional)

Create `docker-compose.yml`:

```yaml
services:
  anubis:
    build: .
    volumes:
      - ./models:/scan:ro
    command: ["scan", "/scan/model.gguf", "--format", "json"]
```

Run with:

```bash
docker compose run --rm anubis
```

---

## GitHub Actions CI/CD

### Workflow Overview

`.github/workflows/ci.yml` runs these jobs:

| Job | Purpose | Triggers |
|-----|---------|----------|
| `lint` | Ruff with the rule set pinned in `pyproject.toml` | Push to `main`, pull requests |
| `test` | pytest, threat-corpus benchmark, CLI smoke test on Python 3.10–3.15, macOS, Windows | Push to `main`, pull requests |
| `scan-sarif` | Scans clean and malicious example models, uploads the SARIF report as an artifact | Push to `main`, pull requests |
| `docker` | Builds the image and runs the CLI in it | Push to `main`, pull requests |
| `fuzz-smoke` | Short coverage-guided fuzzing of the GGUF, Safetensors, and Jinja parsers | Push to `main`, pull requests |
| `advisories` | Fails when the bundled Ollama OSV advisory snapshot is stale | Weekly (Sunday 00:00 UTC), manual |

### Workflow Features

- **Automatic on push/PR**: lint, test, scan, Docker, and fuzz jobs run in parallel
- **Weekly schedule**: checks the Ollama advisory snapshot against OSV.dev; refresh it with `make update-advisories`
- **SARIF output**: the example scan's SARIF report is uploaded as the `anubis-example-scan-sarif` artifact

### Scanning Your Own Models in CI

```yaml
jobs:
  scan-models:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "anubis-ai @ git+https://github.com/CorpLynx/Anubis.git"
      - name: Scan
        run: anubis scan models/ --format sarif > results.sarif || true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Script Wrappers

The wrappers use `$ANUBIS_BIN` if set, then the project's `.venv`, then `anubis` on `PATH`. Progress messages go to stderr, so JSON and SARIF on stdout can be redirected.

### Quick Scan (`quick-scan.sh`)

A scan with tight resource limits. Good for CI/CD pipelines where speed is important.

```bash
# Basic usage
./scripts/quick-scan.sh model.gguf

# With options
./scripts/quick-scan.sh model.gguf \
  --format json \
  --max-files 100 \
  --max-depth 8 \
  --max-seconds 30 \
  --max-bytes 512MiB

# Pass any other `anubis scan` option after --
./scripts/quick-scan.sh model.gguf -- --fail-on high
```

**Use cases:**
- CI/CD pipeline validation
- Quick verification before full scan
- Monitoring scripts

### Full Scan (`full-scan.sh`)

Comprehensive security audit with the default limits, plus optional online provenance and hash verification.

```bash
# Basic usage
./scripts/full-scan.sh model.gguf

# With recommended options
./scripts/full-scan.sh model.safetensors \
  --online \
  --format json \
  --fail-on-critical

# Extract prompt text for the LLM judge
./scripts/full-scan.sh model.gguf --format json --include-prompt-text > report.json
anubis redteam report.json --judge --model llama3.1
```

**Use cases:**
- Pre-deployment security checks
- Detailed security reports
- Compliance audits

### Watch Mode (`watch.sh`)

Scans a directory once, then rescans models as they are added or changed. A `.gguf` file is rescanned on its own; a changed `.safetensors`, `tokenizer_config.json`, or chat-template file triggers a rescan of its directory. Scan findings are logged with their exit code and don't stop the watch.

```bash
# Basic usage
./scripts/watch.sh /models

# Append results to a file, checking every 30 seconds
./scripts/watch.sh /models \
  --format json \
  --interval 30 \
  --output /var/log/anubis-watch.log
```

**Use cases:**
- Model download directories
- Automated model repository scanning
- Continuous security awareness

---

## Makefile Targets

The Makefile provides convenient shortcuts. Options are passed as variables (`FORMAT=json`), not flags.

```bash
# Quick scan
make quick MODEL=model.gguf

# Full scan with online provenance checks
make full MODEL=model.safetensors FORMAT=json > report.json

# Watch mode
make watch WATCH_DIR=/models

# Run tests
make test

# Lint code
make lint

# Clean build artifacts
make clean

# CI-style check (lint + test + corpus benchmark)
make ci

# SARIF report written to results.sarif
make sarif MODEL=model.gguf

# JSON report written to scan-results.json
make json MODEL=model.gguf

# Build the Docker image
make build
```

---

## Best Practices

### For CI/CD Pipelines

1. **Use quick scan for fast feedback**: Include in pre-commit hooks or initial CI checks
2. **Use full scan for final validation**: Run comprehensive checks before release
3. **Output SARIF for integration**: Generate machine-readable reports for security dashboards
4. **Fail on critical findings**: Use `--fail-on-critical` (scripts) or `--fail-on critical` (CLI) to block deployments

### For Security Audits

1. **Run full scans with --online**: Verify provenance against Hugging Face Hub
2. **Deep verification for large models**: Use `--deep --max-bytes 32GiB`
3. **Generate SARIF reports**: Integrate with security tools that accept SARIF 2.1.0

### For Containerized Deployments

1. **Mount models read-only**: `-v /models:/scan:ro`
2. **Pin Docker image tags**: Use specific versions for reproducibility
3. **Mount volumes carefully**: Only share necessary directories

### For Script Wrappers

1. **Use quick-scan.sh for CI**: Fast validation in pipelines
2. **Use full-scan.sh for reports**: Comprehensive analysis for documentation
3. **Use watch.sh for monitoring**: Continuous security awareness

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success: no finding reached the failure policy |
| 1 | Failure: a finding reached `--fail-on`/`--strict`, or the scan was incomplete with `--require-complete` |
| 2 | CLI error (usage/validation error) |

---

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `ANUBIS_BIN` | Anubis executable used by the `scripts/` wrappers | `/opt/anubis/bin/anubis` |
| `ANUBIS_INTERVAL` | Seconds between checks in `scripts/watch.sh` | 30 |
| `ANUBIS_SOURCE_URL` | Source archive URL or local path for the standalone installers | a release archive URL |

Scan limits are command-line options (`--max-files`, `--max-depth`, `--max-seconds`, `--max-bytes`).

---

## Integration Examples

### GitHub Actions + Docker

```yaml
# .github/workflows/docker-ci.yml
name: Docker CI

on: [push, pull_request]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Anubis image
        run: docker build -t anubis:${{ github.sha }} .

      - name: Scan models in the repository
        run: |
          docker run --rm -v "$PWD/models":/scan:ro \
            anubis:${{ github.sha }} scan /scan --format json --fail-on high
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    stages {
        stage('Build Docker') {
            steps {
                sh 'docker build -t anubis:latest .'
            }
        }

        stage('Quick Scan') {
            steps {
                sh './scripts/quick-scan.sh /models'
            }
        }

        stage('Full Scan') {
            steps {
                sh './scripts/full-scan.sh /models --format json > scan-report.json'
            }
        }
    }
}
```

---

## Troubleshooting

### Docker build fails

```bash
# Check that the build context has pyproject.toml, README.md and src/
ls pyproject.toml README.md src/anubis

# Rebuild without cache
docker build --no-cache -t anubis-scanner:latest .
```

### Scripts can't find anubis

```bash
# Install into the project's virtualenv
python3 -m venv .venv && .venv/bin/pip install -e .

# Or point the scripts at an existing install
ANUBIS_BIN=/path/to/anubis ./scripts/quick-scan.sh model.gguf
```

### Scan times out

Increase timeout:

```bash
./scripts/full-scan.sh model.gguf --max-seconds 300
```

### Scan stops early on large models

Raise the bytes limit (the scan is marked incomplete when a limit is hit):

```bash
./scripts/full-scan.sh model.safetensors --max-bytes 32GiB
```

---

## License

MIT License - See [LICENSE](LICENSE) for details.
