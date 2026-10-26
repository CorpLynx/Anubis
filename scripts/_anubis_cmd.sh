# shellcheck shell=bash disable=SC2034
# Shared helper for the wrapper scripts; source it, don't run it.
# Sets ANUBIS_CMD to an array that runs the Anubis CLI:
#   1. $ANUBIS_BIN if set
#   2. the project's .venv
#   3. `anubis` on PATH
#   4. python3 -m anubis.cli with src/ on PYTHONPATH (needs the dependencies installed)

resolve_anubis_cmd() {
    local project_root="$1"
    if [ -n "${ANUBIS_BIN:-}" ]; then
        ANUBIS_CMD=("$ANUBIS_BIN")
    elif [ -x "$project_root/.venv/bin/anubis" ]; then
        ANUBIS_CMD=("$project_root/.venv/bin/anubis")
    elif command -v anubis >/dev/null 2>&1; then
        ANUBIS_CMD=("anubis")
    else
        export PYTHONPATH="$project_root/src${PYTHONPATH:+:$PYTHONPATH}"
        ANUBIS_CMD=("python3" "-m" "anubis.cli")
    fi
}
