#!/bin/bash
# anubis quick - Fast scan with tight resource limits
# Usage: quick-scan.sh <model_path> [OPTIONS] [-- EXTRA ANUBIS SCAN OPTIONS]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
# shellcheck source=scripts/_anubis_cmd.sh
source "$SCRIPT_DIR/_anubis_cmd.sh"

# Default values
FORMAT="rich"
MAX_FILES=100
MAX_DEPTH=8
MAX_SECONDS=30
MAX_BYTES="512MiB"
MODEL_PATH=""
EXTRA_ARGS=()

usage() {
    echo "Quick scan: Fast scan with tight resource limits"
    echo ""
    echo "Usage: $(basename "$0") <model_path> [OPTIONS] [-- EXTRA ANUBIS SCAN OPTIONS]"
    echo ""
    echo "Arguments:"
    echo "  <model_path>    Path to GGUF, Safetensors model, MLX/HF directory, or Ollama store"
    echo ""
    echo "Options:"
    echo "  --format FORMAT      Output format: rich|json|sarif (default: rich)"
    echo "  --max-files N        Maximum files to visit (default: 100)"
    echo "  --max-depth N        Maximum directory nesting depth (default: 8)"
    echo "  --max-seconds S      Maximum wall-clock time in seconds (default: 30)"
    echo "  --max-bytes SIZE     Maximum bytes to read, e.g., 1GiB (default: 512MiB)"
    echo "  -- ARGS              Pass remaining arguments to 'anubis scan' (e.g. -- --fail-on high)"
    echo ""
    echo "Examples:"
    echo "  $(basename "$0") ~/.cache/huggingface/hub/models--org--repo"
    echo "  $(basename "$0") model.gguf --format json"
    echo "  $(basename "$0") model.gguf -- --fail-on high"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --format)      FORMAT="$2"; shift 2 ;;
        --max-files)   MAX_FILES="$2"; shift 2 ;;
        --max-depth)   MAX_DEPTH="$2"; shift 2 ;;
        --max-seconds) MAX_SECONDS="$2"; shift 2 ;;
        --max-bytes)   MAX_BYTES="$2"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        --)            shift; EXTRA_ARGS=("$@"); break ;;
        -*)
            echo "Error: Unknown option: $1 (pass anubis options after --)" >&2
            exit 2
            ;;
        *)
            if [ -z "$MODEL_PATH" ]; then
                MODEL_PATH="$1"
            else
                echo "Error: Too many positional arguments" >&2
                exit 2
            fi
            shift
            ;;
    esac
done

if [ -z "$MODEL_PATH" ]; then
    usage >&2
    exit 2
fi

# Validate model path
if [ ! -f "$MODEL_PATH" ] && [ ! -d "$MODEL_PATH" ]; then
    echo "Error: Model path does not exist or is not a file/directory: $MODEL_PATH" >&2
    exit 2
fi

resolve_anubis_cmd "$PROJECT_ROOT"

# Progress goes to stderr so json/sarif output on stdout stays machine-readable
{
    echo "🚀 Quick scan starting..."
    echo "Target: $MODEL_PATH"
    echo "Mode: Tight limits ($MAX_FILES files, depth $MAX_DEPTH, ${MAX_SECONDS}s, $MAX_BYTES)"
    echo ""
} >&2

exec "${ANUBIS_CMD[@]}" scan \
    --format "$FORMAT" \
    --max-files "$MAX_FILES" \
    --max-depth "$MAX_DEPTH" \
    --max-seconds "$MAX_SECONDS" \
    --max-bytes "$MAX_BYTES" \
    ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} \
    "$MODEL_PATH"
