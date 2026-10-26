# Anubis (`anubis`)

Offline-first security scanner for local AI model files and runtimes. It statically inspects **GGUF**, **Safetensors**, MLX/Hugging Face model directories, Ollama model stores, chat templates, local AI server bindings, and agent workspaces without loading model tensors.

## What it checks

- **Binary integrity:** GGUF tensor bounds, quantization block alignment, and overlapping spans; Safetensors header limits, tensor shape/byte consistency, offsets, overlap, and unclaimed data regions.
- **Model directory hygiene:** legacy pickle weights, `auto_map`/`trust_remote_code` indicators, suspicious Python imports/calls, and embedded tokenizer/chat templates.
- **Chat templates:** Jinja2 AST sandbox-escape patterns (including `|attr()` and string-built names), message-content triggers tracked through variables, namespaces, and macros, URLs/IP addresses, and Base64-encoded URLs or high-entropy blobs.
- **Prompt text:** every literal string a template injects, plus Ollama `SYSTEM` prompts and seeded messages, is checked for instruction overrides, credential harvesting, data exfiltration, harmful-action steering, guardrail removal, deception, self-concealment, and invisible Unicode smuggling. These are phrase heuristics; hardcoded prose is also surfaced as an INFO finding for manual review.
- **Ollama models:** manifests resolved to blobs; GGUF weights, Go `TEMPLATE`s, `SYSTEM` prompts, and `MESSAGES` layers are audited.
- **Local services:** known AI ports plus process-signature discovery for common runners on custom ports, including process/PID context, non-loopback bindings, and bounded unauthenticated API/CORS probes. It uses psutil with `lsof` (macOS) and `netstat` (Windows) fallbacks; probes issue local GET requests and do not follow redirects.
- **Runner advisories:** Ollama versions matched against a dated, curated OSV snapshot; unmatched versions are explicitly not considered vulnerability-free.
- **Threat corpus:** a small labeled benign/malicious regression corpus reports per-class true/false positives and negatives.
- **Workspace and provenance:** likely secrets in agent workspaces, non-authoritative uploader/name heuristics, plus optional Hugging Face repository and file-integrity checks.

These are static checks and heuristics, not a guarantee that a model or machine is safe. In particular, a familiar uploader name is not cryptographic verification, and suspicious content should be reviewed in context.

## Install

The platform installers create an isolated per-user Python environment and install Anubis plus its dependencies:

```bash
# macOS / Linux (from a cloned repository; add ~/.local/bin to PATH if prompted)
./install.sh

# Windows (from cmd.exe, in a cloned repository)
install.cmd
```

When run from a clone, the installer uses that checkout. Run standalone, it downloads the current `main` source archive from GitHub. Set `ANUBIS_SOURCE_URL` to install a pinned release/archive or a local source path instead. Both scripts require Python 3.10+ and do not require administrator privileges.

Manual setup is also supported:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Usage

```bash
# Offline scan of one model file or a Hugging Face/MLX directory
anubis scan ~/.cache/huggingface/hub/models--mlx-community--some-model

# Scan every locally pulled Ollama model (or one manifest under models/manifests/)
anubis scan ~/.ollama/models

# Fail with exit code 1 if HIGH or CRITICAL findings appear
anubis scan model.gguf --strict

# Emit machine-readable JSON or SARIF 2.1.0
anubis scan model.gguf --format json
anubis scan model.gguf --format sarif --fail-on high

# Return exit code 1 if any scan coverage was incomplete
anubis scan ~/.cache/huggingface/hub/models--org--repo --require-complete

# Opt in to Hugging Face network checks (repo lookup + file sizes)
anubis scan model.safetensors --online

# Also stream local model files and compare SHA256 with upstream LFS OIDs
anubis scan ~/.cache/huggingface/hub/models--org--repo --deep --max-bytes 32GiB

# Audit the host, local AI ports, and current workspace
anubis audit --workspace .

# Skip active API/CORS probes while still inspecting listening sockets
anubis audit --workspace . --no-probe

# Audit host and optionally verify a model online
anubis audit --workspace . --model model.gguf --online

# Tune traversal and content-read budgets
anubis audit --workspace . --max-files 5000 --max-depth 32 --max-bytes 1073741824 --max-seconds 60

# Ask a separate local Ollama model for unverified regression-test ideas
anubis scan model.gguf --format json > scan-report.json
anubis redteam scan-report.json --model qwen2.5:14b

# Have a model judge extracted prompt text for paraphrased harmful instructions
anubis scan ~/.ollama/models --format json --include-prompt-text > prompts.json
anubis redteam prompts.json --judge --model qwen3:8b                                  # local Ollama
anubis redteam prompts.json --judge --provider openai --model qwen3-8b                # LM Studio / llama.cpp / vLLM
anubis redteam prompts.json --judge --provider anthropic --allow-remote --fail-on-verdict suspicious
```

`--deep` implies the online check. Online checks are opt-in; offline scans do not contact Hugging Face. Hash checking only succeeds when the Hub exposes an LFS SHA256 OID for the corresponding file.

The built-in Ollama advisory snapshot carries its own date and links each finding to OSV.dev. An informational warning appears when the snapshot is older than 90 days; a clean match means only that no included advisory range matched the reported version.

The old `localguard` command remains as a compatibility alias; new usage should invoke `anubis`.

### Reports and scan limits

`--format rich` is the default. `--format json` emits Anubis JSON schema version 1.0, and `--format sarif` emits SARIF 2.1.0. Findings include stable rule IDs, evidence, remediation, and a rule-class confidence estimate; confidence is **not** a calibrated probability. Exit code `0` means the selected failure policy passed, `1` means `--strict`, `--fail-on`, or `--require-complete` was triggered, and `2` is used for CLI usage/validation errors. Incomplete scans are visibly marked even when `--require-complete` is not set.

Defaults are 20,000 files, depth 64, 2 GiB of total bytes read (16 GiB with `--deep`), and 120 seconds per command. Use `--max-bytes 32GiB` for larger models. Budget exhaustion is reported as an informational finding, marks the report incomplete, and can be made an exit failure with `--require-complete`. During directory walks, Anubis follows file symlinks that resolve inside the scan root (needed for Hugging Face cache snapshots), skips external links, and skips directory symlinks unless `--follow-symlinks` is specified. An explicitly selected file symlink is treated as a user-selected target.

### Advisory refresh and fuzzing

The bundled Ollama OSV snapshot is refreshed weekly by `.github/workflows/update-ollama-advisories.yml`, which opens a reviewable PR. New or changed records are informational until a maintainer reviews their ranges/severity. To refresh locally, install the project and run `python scripts/update_ollama_advisories.py`.

Property-based no-crash tests run in the normal suite. Optional Atheris coverage-guided fuzzing is Linux-only: install with `pip install -e '.[fuzz]'`, then run `python scripts/fuzz_anubis.py gguf -runs=1000`. CI installs Clang/libFuzzer; Apple Clang on macOS does not include the libFuzzer runtime by default.

Run the labeled sample corpus with `python scripts/benchmark_security_corpus.py`. Its cases are synthetic regression fixtures, not a representative measure of real-world detection rates.

### Optional local red-team advisor

`anubis redteam` sends a minimized JSON scan summary to an already-installed Ollama model at loopback by default. It does **not** load the scanned model, execute returned ideas, change findings/severity, or claim the target is safe. The output is unverified test hypotheses; review and validate them in a disposable environment. Remote endpoints require the explicit `--allow-remote` flag and receive the minimized report.

### Optional prompt-text judge

Phrase rules miss paraphrased instructions, so `anubis redteam --judge` asks a model to read the text itself. `anubis scan --format json --include-prompt-text` adds each chat template, Ollama template, `SYSTEM` prompt, and seeded-message set (up to 64K characters each, plus the literal passages the static analyzer decoded) to the report; this is opt-in because system prompts can be private. The judge receives only that text and its type, never file paths or the rest of the report, and returns a separate JSON file of `UNVERIFIED_AI_JUDGMENT` verdicts (`benign`, `suspicious`, `malicious`) with categories and quoted evidence. Each quote is checked against the source text (`quote_verified`).

- **Providers:** `ollama` (default, `http://127.0.0.1:11434`), `openai` for any OpenAI-compatible server (default `http://127.0.0.1:1234`; sends `OPENAI_API_KEY` as a bearer token when set), and `anthropic` (defaults to `claude-opus-5-5`; install with `pip install 'anubis-ai[judge]'`, credentials from `ANTHROPIC_API_KEY` or `ant auth login`). Non-loopback endpoints and the Anthropic API require `--allow-remote`.
- **Injection handling:** judged text is wrapped in random-id delimiters and treated strictly as data; text that tries to influence the judge is classified as `judge_manipulation`. Output is schema-constrained and validated. A model that declines to judge (for example, a safety refusal) is recorded as `JUDGE_DECLINED`, never as benign.
- **Cost and CI:** identical texts are judged once, long texts are chunked (the worst verdict wins), and `--max-requests` (default 50) bounds spend. `--fail-on-verdict suspicious|malicious` exits 1 for CI. Verdicts never change scan findings, severities, or the scan's exit status, and a `benign` verdict is not proof of safety.

## Containerization with Docker

Build a portable Anubis scanner container:

```bash
# Build the Docker image
docker build -t anubis-scanner:latest .

# Optional: include the Anthropic SDK for `anubis redteam --provider anthropic`
docker build --build-arg EXTRAS=judge -t anubis-scanner:judge .

# Scan a model; mount it read-only under /scan
docker run --rm -v "$PWD":/scan:ro anubis-scanner:latest scan /scan/model.gguf

# Scan the host's Ollama model store
docker run --rm -v ~/.ollama/models:/scan:ro anubis-scanner:latest scan /scan
```

The image is built on `python:3.12-slim-bookworm`, installs Anubis from `pyproject.toml` with no compilers or extra system packages, and runs as an unprivileged `anubis` user with `anubis` as the entrypoint. Model weights are never copied into the image (see [.dockerignore](.dockerignore)).

`anubis audit` inside a container inspects the container's own network and processes, not the host's, so run `audit` on the host.

## CI/CD with GitHub Actions

The [`.github/workflows/ci.yml`](.github/workflows/ci.yml) workflow runs on every push to `main` and every pull request:

- **lint**: Ruff and a Black format check, both configured in `pyproject.toml`
- **test**: the pytest suite, the labeled threat-corpus benchmark, and a CLI smoke test, on Python 3.10–3.15 (Linux) plus macOS and Windows
- **scan-sarif**: scans a clean and a malicious example model through the CLI, checks the exit codes, and uploads the SARIF report as a workflow artifact
- **docker**: builds the image and runs the CLI inside it
- **fuzz-smoke**: short coverage-guided fuzzing runs of the GGUF, Safetensors, and Jinja parsers

The Ollama OSV advisory snapshot is refreshed separately by `.github/workflows/update-ollama-advisories.yml` (see [Advisory refresh and fuzzing](#advisory-refresh-and-fuzzing)).

To scan your own models in another repository's pipeline, run `anubis scan <path> --format sarif > results.sarif` and upload `results.sarif` with `github/codeql-action/upload-sarif` (the job needs `security-events: write`).

## Script Wrappers

The `scripts/` directory has wrappers for common use cases. They use `$ANUBIS_BIN` if set, then the project's `.venv`, then `anubis` on `PATH`. Progress messages go to stderr, so JSON and SARIF on stdout can be redirected to a file.

### Quick Scan (fast, tight limits)
```bash
# Quick scan of a model: 100 files, depth 8, 30 s, 512 MiB by default
./scripts/quick-scan.sh ~/.cache/huggingface/hub/models--org--repo

# With JSON output
./scripts/quick-scan.sh model.gguf --format json > quick-scan.json

# Pass any other `anubis scan` option after --
./scripts/quick-scan.sh model.gguf -- --fail-on high
```

### Full Scan (comprehensive inspection)
```bash
# Full security audit with all checks
./scripts/full-scan.sh ~/.cache/huggingface/hub/models--org--repo

# With online provenance verification
./scripts/full-scan.sh model.safetensors --online

# Deep verification with hash comparison (implies --online)
./scripts/full-scan.sh model.safetensors --deep --max-bytes 32GiB

# Fail the build on CRITICAL findings only
./scripts/full-scan.sh model.gguf --fail-on-critical
```

### Watch Mode (continuous monitoring)
```bash
# Scan a directory, then rescan models as they are added or changed
./scripts/watch.sh ~/.cache/huggingface/hub

# Append results to a file instead of stdout, checking every 30 s
./scripts/watch.sh /models --format json --output scan-watches.log --interval 30
```

Watch mode rescans a `.gguf` file on its own, and rescans the containing directory when a `.safetensors`, `tokenizer_config.json`, or chat-template file changes. The interval defaults to 5 seconds, or `$ANUBIS_INTERVAL`.

### Using Makefile Targets

The [Makefile](Makefile) provides convenient targets:

```bash
# Quick scan (tight limits)
make quick MODEL=model.gguf

# Full scan with online provenance checks
make full MODEL=model.safetensors FORMAT=json > results.json

# Continuous watch mode
make watch WATCH_DIR=/models

# SARIF report written to results.sarif
make sarif MODEL=model.gguf

# Run tests, lint, or both plus the corpus benchmark
make test
make lint
make ci

# Build the Docker image
make build

# Clean build artifacts
make clean
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANUBIS_SOURCE_URL` | Source archive URL or local path for the standalone installers | GitHub `main` archive |
| `ANUBIS_BIN` | Anubis executable used by the `scripts/` wrappers | `.venv/bin/anubis`, then `anubis` on `PATH` |
| `ANUBIS_INTERVAL` | Seconds between checks in `scripts/watch.sh` | 5 |

Scan limits are set with command-line options (`--max-files`, `--max-depth`, `--max-seconds`, `--max-bytes`), not environment variables.

## Development

```bash
pip install -e '.[dev]'
pytest
```

### Running Tests

```bash
# Run all tests
pytest -v

# Labeled threat corpus benchmark
python scripts/benchmark_security_corpus.py

# End-to-end CLI smoke test
python scripts/ci_scan_smoke.py
```

### Linting

```bash
pip install ruff "black==26.10.1"
ruff check src tests scripts
black --check src tests scripts   # `black src tests scripts` or `make format` to fix
```

### Fuzzing (Linux only)

Install with fuzz support and run coverage-guided fuzzing:

```bash
pip install -e '.[dev,fuzz]'
python scripts/fuzz_anubis.py gguf -runs=1000
```

## Contributing

See the [Development](#development) section for setup and testing instructions. Report issues via GitHub Issues; pull requests are welcome once `make ci` passes.
