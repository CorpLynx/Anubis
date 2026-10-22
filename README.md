# Anubis (`anubis`)

Offline-first security scanner for local AI model files and runtimes. It statically inspects **GGUF**, **Safetensors**, MLX/Hugging Face model directories, chat templates, local AI server bindings, and agent workspaces without loading model tensors.

## What it checks

- **Binary integrity:** GGUF tensor bounds, quantization block alignment, and overlapping spans; Safetensors header limits, tensor shape/byte consistency, offsets, overlap, and unclaimed data regions.
- **Model directory hygiene:** legacy pickle weights, `auto_map`/`trust_remote_code` indicators, suspicious Python imports/calls, and embedded tokenizer/chat templates.
- **Chat templates:** Jinja2 AST sandbox-escape patterns, content-conditional triggers, URLs/IP addresses, and Base64-encoded URLs or high-entropy blobs.
- **Local services:** known AI ports (`11434`, `1234`, `8000`, `8080`), any non-loopback binding, and bounded unauthenticated API/CORS probes. The probes only issue local GET requests and do not follow redirects.
- **Runner advisories:** Ollama versions matched against a dated, curated OSV snapshot; unmatched versions are explicitly not considered vulnerability-free.
- **Workspace and provenance:** likely secrets in agent workspaces, non-authoritative uploader/name heuristics, plus optional Hugging Face repository and file-integrity checks.

These are static checks and heuristics, not a guarantee that a model or machine is safe. In particular, a familiar uploader name is not cryptographic verification, and suspicious content should be reviewed in context.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Usage

```bash
# Offline scan of one model file or a Hugging Face/MLX directory
anubis scan ~/.cache/huggingface/hub/models--mlx-community--some-model

# Fail with exit code 1 if HIGH or CRITICAL findings appear
anubis scan model.gguf --strict

# Emit machine-readable JSON or SARIF 2.1.0
anubis scan model.gguf --format json
anubis scan model.gguf --format sarif --fail-on high

# Opt in to Hugging Face network checks (repo lookup + file sizes)
anubis scan model.safetensors --online

# Also stream local model files and compare SHA256 with upstream LFS OIDs
anubis scan ~/.cache/huggingface/hub/models--org--repo --deep

# Audit the host, local AI ports, and current workspace
anubis audit --workspace .

# Skip active API/CORS probes while still inspecting listening sockets
anubis audit --workspace . --no-probe

# Audit host and optionally verify a model online
anubis audit --workspace . --model model.gguf --online

# Tune traversal and content-read budgets
anubis audit --workspace . --max-files 5000 --max-depth 32 --max-bytes 1073741824 --max-seconds 60
```

`--deep` implies the online check. Online checks are opt-in; offline scans do not contact Hugging Face. Hash checking only succeeds when the Hub exposes an LFS SHA256 OID for the corresponding file.

The built-in Ollama advisory snapshot carries its own date and links each finding to OSV.dev. An informational warning appears when the snapshot is older than 90 days; a clean match means only that no included advisory range matched the reported version.

The old `localguard` command remains as a compatibility alias; new usage should invoke `anubis`.

### Reports and scan limits

`--format rich` is the default. `--format json` emits Anubis JSON schema version 1.0, and `--format sarif` emits SARIF 2.1.0. Findings include stable rule IDs, evidence, remediation, and a rule-class confidence estimate; confidence is **not** a calibrated probability. Exit code `0` means the selected failure policy passed, `1` means `--strict`/`--fail-on` was triggered, and `2` is used for CLI usage/validation errors.

Defaults are 20,000 files, depth 64, 2 GiB of total bytes read, and 120 seconds per command. Budget exhaustion is reported as an informational finding, and incomplete scans do not claim a clean workspace. During directory walks, Anubis follows file symlinks that resolve inside the scan root (needed for Hugging Face cache snapshots), skips external links, and skips directory symlinks unless `--follow-symlinks` is specified. An explicitly selected file symlink is treated as a user-selected target.

### Advisory refresh and fuzzing

The bundled Ollama OSV snapshot is refreshed weekly by `.github/workflows/update-ollama-advisories.yml`, which opens a reviewable PR. New or changed records are informational until a maintainer reviews their ranges/severity. To refresh locally, install the project and run `python scripts/update_ollama_advisories.py`.

Property-based no-crash tests run in the normal suite. Optional Atheris coverage-guided fuzzing is Linux-only: install with `pip install -e '.[fuzz]'`, then run `python scripts/fuzz_anubis.py gguf -runs=1000`. CI installs Clang/libFuzzer; Apple Clang on macOS does not include the libFuzzer runtime by default.

## Development

```bash
pip install -e '.[dev]'
pytest
```
