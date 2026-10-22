# LocalGuard-AI (`localguard`)

Offline-first security scanner for local AI model files and runtimes. It statically inspects **GGUF**, **Safetensors**, MLX/Hugging Face model directories, chat templates, local AI server bindings, and agent workspaces without loading model tensors.

## What it checks

- **Binary integrity:** GGUF tensor bounds, quantization block alignment, and overlapping spans; Safetensors header limits, tensor shape/byte consistency, offsets, overlap, and unclaimed data regions.
- **Model directory hygiene:** legacy pickle weights, `auto_map`/`trust_remote_code` indicators, suspicious Python imports/calls, and embedded tokenizer/chat templates.
- **Chat templates:** Jinja2 AST sandbox-escape patterns, content-conditional triggers, URLs/IP addresses, and Base64-encoded URLs or high-entropy blobs.
- **Local services:** known AI ports (`11434`, `1234`, `8000`, `8080`), any non-loopback binding, and bounded unauthenticated API/CORS probes. The probes only issue local GET requests and do not follow redirects.
- **Workspace and provenance:** likely secrets in agent workspaces, local uploader/name heuristics, plus optional Hugging Face repository and file-integrity checks.

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
localguard scan ~/.cache/huggingface/hub/models--mlx-community--some-model

# Fail with exit code 1 if HIGH or CRITICAL findings appear
localguard scan model.gguf --strict

# Opt in to Hugging Face network checks (repo lookup + file sizes)
localguard scan model.safetensors --online

# Also stream local model files and compare SHA256 with upstream LFS OIDs
localguard scan ~/.cache/huggingface/hub/models--org--repo --deep

# Audit the host, local AI ports, and current workspace
localguard audit --workspace .

# Skip active API/CORS probes while still inspecting listening sockets
localguard audit --workspace . --no-probe

# Audit host and optionally verify a model online
localguard audit --workspace . --model model.gguf --online
```

`--deep` implies the online check. Online checks are opt-in; offline scans do not contact Hugging Face. Hash checking only succeeds when the Hub exposes an LFS SHA256 OID for the corresponding file.

## Development

```bash
pip install -e '.[dev]'
pytest
```
