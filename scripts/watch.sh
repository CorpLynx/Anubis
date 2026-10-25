#!/bin/bash
# anubis watch - Continuous monitoring of new or changed models in a directory
# Usage: watch.sh <directory> [OPTIONS]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
# shellcheck source=scripts/_anubis_cmd.sh
source "$SCRIPT_DIR/_anubis_cmd.sh"

# Default values
FORMAT="rich"
MAX_FILES=20000
MAX_DEPTH=64
MAX_SECONDS=120
MAX_BYTES=""
INTERVAL="${ANUBIS_INTERVAL:-5}"  # seconds between checks
OUTPUT_FILE=""
WATCH_DIR=""

usage() {
    echo "Watch mode: Scan a directory, then rescan models as they are added or changed"
    echo ""
    echo "Usage: $(basename "$0") <directory> [OPTIONS]"
    echo ""
    echo "Arguments:"
    echo "  <directory>          Directory to monitor for GGUF/Safetensors models and chat templates"
    echo ""
    echo "Options:"
    echo "  --format FORMAT      Output format: rich|json|sarif (default: rich)"
    echo "  --max-files N        Maximum files to visit per scan (default: 20000)"
    echo "  --max-depth N        Maximum directory nesting depth (default: 64)"
    echo "  --max-seconds S      Maximum wall-clock time per scan (default: 120)"
    echo "  --max-bytes SIZE     Maximum bytes to read per scan, e.g., 16GiB"
    echo "  --interval S         Seconds between checks (default: 5, or \$ANUBIS_INTERVAL)"
    echo "  --output FILE        Append results to FILE instead of stdout"
    echo ""
    echo "Examples:"
    echo "  $(basename "$0") ~/.cache/huggingface/hub"
    echo "  $(basename "$0") /models --format json --output /tmp/anubis-watch.log"
    echo "  $(basename "$0") /models --format sarif --max-bytes 32GiB"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --format)              FORMAT="$2"; shift 2 ;;
        --max-files)           MAX_FILES="$2"; shift 2 ;;
        --max-depth)           MAX_DEPTH="$2"; shift 2 ;;
        --max-seconds)         MAX_SECONDS="$2"; shift 2 ;;
        --max-bytes)           MAX_BYTES="$2"; shift 2 ;;
        --interval)            INTERVAL="$2"; shift 2 ;;
        --output|--output-file) OUTPUT_FILE="$2"; shift 2 ;;
        -h|--help)             usage; exit 0 ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            exit 2
            ;;
        *)
            if [ -z "$WATCH_DIR" ]; then
                WATCH_DIR="$1"
            else
                echo "Error: Too many positional arguments" >&2
                exit 2
            fi
            shift
            ;;
    esac
done

if [ -z "$WATCH_DIR" ]; then
    usage >&2
    exit 2
fi

# Validate directory
if [ ! -d "$WATCH_DIR" ]; then
    echo "Error: Directory does not exist: $WATCH_DIR" >&2
    exit 2
fi

resolve_anubis_cmd "$PROJECT_ROOT"

SCAN_ARGS=(
    --format "$FORMAT"
    --max-files "$MAX_FILES"
    --max-depth "$MAX_DEPTH"
    --max-seconds "$MAX_SECONDS"
)
[ -n "$MAX_BYTES" ] && SCAN_ARGS+=(--max-bytes "$MAX_BYTES")

log() {
    echo "$@" >&2
}

# Run one scan without exiting the watch loop; findings (exit 1) are reported, not fatal
scan_target() {
    local target="$1"
    local status=0
    log "[SCAN] Checking: $target"
    if [ -n "$OUTPUT_FILE" ]; then
        "${ANUBIS_CMD[@]}" scan "${SCAN_ARGS[@]}" "$target" >> "$OUTPUT_FILE" 2>&1 || status=$?
    else
        "${ANUBIS_CMD[@]}" scan "${SCAN_ARGS[@]}" "$target" || status=$?
    fi
    log "[SCAN] Completed: $target (exit code $status)"
}

# Print "<scan target>\t<size>:<mtime>" for every model-related file. GGUF files embed their
# chat template and are scanned alone; other files are scanned with their whole directory so
# tokenizer configs and chat templates are inspected together with the weights.
fingerprint_models() {
    local file size_mtime target
    # `|| true`: find exits non-zero on unreadable entries or when head closes the pipe early
    { find "$WATCH_DIR" -maxdepth "$MAX_DEPTH" -type f \( \
        -name "*.gguf" -o -name "*.safetensors" -o -name "tokenizer_config.json" \
        -o -name "chat_template.json" -o -name "chat_template.jinja" \) 2>/dev/null || true; } |
    head -n "$MAX_FILES" |
    while IFS= read -r file; do
        size_mtime="$(stat -c '%s:%Y' "$file" 2>/dev/null || stat -f '%z:%m' "$file" 2>/dev/null || echo missing)"
        case "$file" in
            *.gguf) target="$file" ;;
            *) target="$(dirname "$file")" ;;
        esac
        printf '%s\t%s\t%s\n' "$target" "$file" "$size_mtime"
    done | LC_ALL=C sort
}

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/anubis-watch.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
trap 'log ""; log "Watch mode stopped"; exit 0' INT TERM
SEEN="$STATE_DIR/seen"
CURRENT="$STATE_DIR/current"

log "👁️ Watch mode enabled"
log "Monitoring: $WATCH_DIR"
log "Interval: ${INTERVAL}s"
[ -n "$OUTPUT_FILE" ] && log "Output: $OUTPUT_FILE (appended)"
log ""
log "Press Ctrl+C to stop watching"
log "----------------------------------------"
log ""
log "=== Initial scan ==="
scan_target "$WATCH_DIR"
fingerprint_models > "$SEEN"
log ""
log "=== Watching for changes (Ctrl+C to stop) ==="

while true; do
    sleep "$INTERVAL"
    fingerprint_models > "$CURRENT"
    # Targets whose files are new or changed since the last check, each scanned once
    changed_targets="$(LC_ALL=C comm -13 "$SEEN" "$CURRENT" | cut -f1 | LC_ALL=C sort -u)"
    if [ -n "$changed_targets" ]; then
        while IFS= read -r target; do
            [ -e "$target" ] && scan_target "$target"
        done <<< "$changed_targets"
    fi
    mv "$CURRENT" "$SEEN"
done
