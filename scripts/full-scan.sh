#!/bin/bash
# anubis full - Full scan with all inspections including provenance and deep checks
# Usage: full-scan.sh <model_path> [OPTIONS]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
# shellcheck source=scripts/_anubis_cmd.sh
source "$SCRIPT_DIR/_anubis_cmd.sh"

# Default values
FORMAT="rich"
ONLINE=false
DEEP=false
FAIL_ON_HIGH=false
FAIL_ON_CRITICAL=false
REQUIRE_COMPLETE=false
INCLUDE_PROMPT_TEXT=false
MAX_FILES=20000
MAX_DEPTH=64
MAX_SECONDS=120
MAX_BYTES=""
MODEL_PATH=""

usage() {
    echo "Full scan: Comprehensive security audit with all inspections"
    echo ""
    echo "Usage: $(basename "$0") <model_path> [OPTIONS]"
    echo ""
    echo "Arguments:"
    echo "  <model_path>          Path to GGUF, Safetensors model, MLX/HF directory, or Ollama store"
    echo ""
    echo "Options:"
    echo "  --format FORMAT       Output format: rich|json|sarif (default: rich)"
    echo "  --online              Verify provenance against Hugging Face Hub API"
    echo "  --deep                Stream SHA256 hashes and compare with upstream LFS OIDs"
    echo "                        (--online is implied with --deep)"
    echo "  --strict, --fail-on-high   Exit 1 for HIGH or CRITICAL findings"
    echo "  --fail-on-critical    Exit 1 only for CRITICAL findings"
    echo "  --require-complete    Exit 1 if any requested scan work was skipped"
    echo "  --include-prompt-text With --format json: embed prompt text for 'anubis redteam --judge'"
    echo "  --max-files N         Maximum files to visit (default: 20000)"
    echo "  --max-depth N         Maximum directory nesting depth (default: 64)"
    echo "  --max-seconds S       Maximum wall-clock time in seconds (default: 120)"
    echo "  --max-bytes SIZE      Maximum bytes to read, e.g., 32GiB (default: 2GiB, 16GiB with --deep)"
    echo ""
    echo "Examples:"
    echo "  $(basename "$0") ~/.cache/huggingface/hub/models--org--repo"
    echo "  $(basename "$0") model.gguf --format json --online"
    echo "  $(basename "$0") model.safetensors --deep --max-bytes 32GiB"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --format)               FORMAT="$2"; shift 2 ;;
        --online)               ONLINE=true; shift ;;
        --deep)                 DEEP=true; ONLINE=true; shift ;;
        --strict|--fail-on-high) FAIL_ON_HIGH=true; shift ;;
        --fail-on-critical)     FAIL_ON_CRITICAL=true; shift ;;
        --require-complete)     REQUIRE_COMPLETE=true; shift ;;
        --include-prompt-text)  INCLUDE_PROMPT_TEXT=true; shift ;;
        --max-files)            MAX_FILES="$2"; shift 2 ;;
        --max-depth)            MAX_DEPTH="$2"; shift 2 ;;
        --max-seconds)          MAX_SECONDS="$2"; shift 2 ;;
        --max-bytes)            MAX_BYTES="$2"; shift 2 ;;
        -h|--help)              usage; exit 0 ;;
        -*)
            echo "Error: Unknown option: $1" >&2
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

case "$FORMAT" in
    rich|json|sarif) ;;
    *)
        echo "Error: Invalid format '$FORMAT'. Use rich, json, or sarif." >&2
        exit 2
        ;;
esac

ARGS=(
    scan
    --format "$FORMAT"
    --max-files "$MAX_FILES"
    --max-depth "$MAX_DEPTH"
    --max-seconds "$MAX_SECONDS"
)
[ -n "$MAX_BYTES" ] && ARGS+=(--max-bytes "$MAX_BYTES")
[ "$ONLINE" = true ] && ARGS+=(--online)
[ "$DEEP" = true ] && ARGS+=(--deep)
if [ "$FAIL_ON_HIGH" = true ]; then
    ARGS+=(--strict)
elif [ "$FAIL_ON_CRITICAL" = true ]; then
    ARGS+=(--fail-on critical)
fi
[ "$REQUIRE_COMPLETE" = true ] && ARGS+=(--require-complete)
[ "$INCLUDE_PROMPT_TEXT" = true ] && ARGS+=(--include-prompt-text)
ARGS+=("$MODEL_PATH")

resolve_anubis_cmd "$PROJECT_ROOT"

# Progress goes to stderr so json/sarif output on stdout stays machine-readable
{
    echo "🔍 Full security audit starting..."
    echo "Target: $MODEL_PATH"
    echo "Format: $FORMAT"
    [ "$ONLINE" = true ] && echo "Online checks: Enabled"
    [ "$DEEP" = true ] && echo "Deep verification: Enabled"
    if [ "$FAIL_ON_HIGH" = true ] || [ "$FAIL_ON_CRITICAL" = true ]; then
        echo "Strict mode: Enabled"
    fi
    echo ""
} >&2

exec "${ANUBIS_CMD[@]}" "${ARGS[@]}"
