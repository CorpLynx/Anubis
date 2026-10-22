#!/bin/sh
set -eu

APP_NAME="Anubis"
DEFAULT_SOURCE="https://github.com/CorpLynx/Anubis/archive/refs/heads/main.zip"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ANUBIS_HOME=${ANUBIS_HOME:-"$HOME/.local/share/anubis"}
ANUBIS_BIN=${ANUBIS_BIN:-"$HOME/.local/bin"}
VENV="$ANUBIS_HOME/venv"

if [ -n "${ANUBIS_SOURCE_URL:-}" ]; then
    PACKAGE_SOURCE=$ANUBIS_SOURCE_URL
elif [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
    PACKAGE_SOURCE=$SCRIPT_DIR
else
    PACKAGE_SOURCE=$DEFAULT_SOURCE
fi

PYTHON_BIN=${PYTHON:-}
if [ -z "$PYTHON_BIN" ]; then
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && \
            "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
            PYTHON_BIN=$candidate
            break
        fi
    done
fi

if [ -z "$PYTHON_BIN" ]; then
    echo "${APP_NAME} requires Python 3.10 or newer. Set PYTHON to a supported interpreter." >&2
    exit 1
fi

"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
    echo "${APP_NAME} requires Python 3.10 or newer; found: $($PYTHON_BIN --version 2>&1)" >&2
    exit 1
}

mkdir -p "$ANUBIS_HOME" "$ANUBIS_BIN"
"$PYTHON_BIN" -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install --upgrade --force-reinstall "$PACKAGE_SOURCE"

cat > "$ANUBIS_BIN/anubis" <<EOF
#!/bin/sh
exec "$VENV/bin/anubis" "\$@"
EOF
cat > "$ANUBIS_BIN/localguard" <<EOF
#!/bin/sh
exec "$VENV/bin/localguard" "\$@"
EOF
chmod 755 "$ANUBIS_BIN/anubis" "$ANUBIS_BIN/localguard"

echo "${APP_NAME} installed at $VENV"
case ":$PATH:" in
    *":$ANUBIS_BIN:"*) echo "Run: anubis --help" ;;
    *)
        echo "Add this directory to your PATH to use the command in new terminals:"
        echo "  $ANUBIS_BIN"
        echo "Then run: anubis --help"
        ;;
esac
