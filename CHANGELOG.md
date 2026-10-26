# Changelog - Integration Improvements

All notable changes to the Anubis integration package.

## [Unreleased]

### Added

#### Docker Support
- **Dockerfile**: Python 3.12 slim image that installs Anubis from `pyproject.toml`, runs as an unprivileged `anubis` user, and uses `anubis` as its entrypoint; `--build-arg EXTRAS=judge` adds the Anthropic SDK
- **.dockerignore**: keeps the build context to `pyproject.toml`, `README.md`, and `src/`, and never copies model weights into the image
- **requirements.txt**: runtime dependency listing that mirrors `pyproject.toml`

Key features:
- Containerized scanner for portable, reproducible security checks
- Minimal attack surface: slim base image, no compilers, non-root user
- Ready for CI/CD pipeline integration via `docker build` and `docker run`

#### GitHub Actions Workflow (`.github/workflows/ci.yml`)
Extends the existing test matrix and fuzz smoke job with:

1. **lint**: Ruff and a Black format check (line length 120), both configured in `pyproject.toml`
2. **CLI smoke test** (`scripts/ci_scan_smoke.py`): scans a clean and a malicious example model through `anubis scan` and checks exit codes and findings, on every matrix entry
3. **scan-sarif**: uploads the example scan's SARIF report as a workflow artifact
4. **docker**: builds the image and runs the CLI inside it

#### Script Wrappers in `scripts/` directory:

1. **`quick-scan.sh`** - Fast scan with tight resource limits
   - Use case: CI/CD pipelines, quick verification
   - Parameters: format, max-files, max-depth, max-seconds, max-bytes; other `anubis scan` options after `--`

2. **`full-scan.sh`** - Full security audit with all inspections
   - Use case: Pre-deployment checks, compliance audits
   - Parameters: online checks, deep hash verification, failure thresholds, `--include-prompt-text`

3. **`watch.sh`** - Continuous monitoring mode
   - Use case: model download directories, repository monitoring
   - Rescans new or changed models; parameters: format, interval, output file

All three use `$ANUBIS_BIN`, the project's `.venv`, or `anubis` on `PATH`, and write progress to stderr so JSON/SARIF output can be redirected.

#### Makefile
Convenient targets for common operations:
- `make quick MODEL=<model>` - Fast scan with tight limits
- `make full MODEL=<model>` - Full scan with online provenance checks
- `make watch WATCH_DIR=<directory>` - Continuous scanning
- `make sarif MODEL=<model>` / `make json MODEL=<model>` - Write a report file
- `make test` - Run pytest test suite
- `make lint` - Lint with Ruff and check formatting with Black
- `make format` - Format code with Black
- `make ci` - CI-style check (lint + test + corpus benchmark)
- `make build` - Build the Docker image
- `make clean` - Remove build artifacts and cache

#### Documentation Updates
- **USAGE.md**: Comprehensive quick reference for all new features
- **README.md**: Updated with Docker, CI/CD, and script wrapper documentation

#### Chat Template & Prompt-Text Scanning
- **Harmful instruction detection** (`inspectors/prompt_text.py`): literal prompt text is checked for instruction overrides, credential harvesting, exfiltration, harmful-action steering, guardrail removal, deception, and self-concealment; concealed HIGH findings escalate to CRITICAL. Text is NFKC/homoglyph-normalized, and invisible Unicode tag, bidi, and zero-width characters are reported (tag payloads are decoded and scanned).
- **Jinja2 scanner hardening:** raw template text and folded concatenations are now scanned (split URLs no longer evade detection); content triggers are tracked through `and`/`or`/`not`, `{% set %}`, loops, namespaces, macros, string methods, and `selectattr`; `|attr()`, `map(attribute=...)`, and string-built keys are checked for sandbox escapes; transformers' `{% generation %}` and loop-control tags parse.
- **Ollama model stores** (`inspectors/ollama_models.py`): `anubis scan ~/.ollama/models` resolves manifests to blobs and audits GGUF weights, Go `TEMPLATE`s, `SYSTEM` prompts, and seeded `MESSAGES`.
- **Prompt-text judge** (`anubis redteam --judge`): `scan --format json --include-prompt-text` exports extracted template and system-prompt text, and a local (Ollama, OpenAI-compatible) or frontier (Anthropic, via the optional `judge` extra) model judges it for paraphrased harmful instructions. Includes nonce-delimited untrusted input, schema-constrained output, quote verification, refusal handling, deduplication, chunking, `--max-requests`, and `--fail-on-verdict`. `anubis redteam` hypothesis mode also gains `--provider`.
- **Corpus:** new labeled malicious and benign look-alike cases for these classes, plus `go_template` and `prompt_text` case kinds.

### Integration Examples Added

1. **Docker Compose** configuration example
2. **GitHub Actions + Docker** integration example
3. **Jenkins Pipeline** Groovy script for containerized scanning

---

## Previous Versions

See git history for prior changes to core Anubis functionality.

---

## Migration Notes

### For Existing Users

No breaking changes. All new features are opt-in:

- Existing `anubis` CLI commands work unchanged
- New scripts are in separate directory (`scripts/`)
- Makefile targets are convenience wrappers

### For CI/CD Integration Teams

Recommended adoption path:

1. **Phase 1**: Use `make quick` or `quick-scan.sh` in pre-commit hooks
2. **Phase 2**: Add `anubis scan --format sarif` to GitHub Actions workflows (see USAGE.md)
3. **Phase 3**: Adopt Docker containers for reproducible builds

### For Security Teams

- SARIF 2.1.0 output integrates with GitHub Code Scanning and other SARIF-aware tooling
- Containerized deployment ensures consistent scanning environment
- Watch mode enables continuous security monitoring of model repositories

---

## See Also

- [USAGE.md](USAGE.md) - Complete integration usage guide
- [README.md](README.md#containerization-with-docker) - Docker integration overview
- [README.md](README.md#cicd-with-github-actions) - CI/CD workflow documentation
