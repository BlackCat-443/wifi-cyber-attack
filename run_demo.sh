#!/bin/bash
# Run WiFi Monitor - Demo Mode (tanpa root)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$DIR/env/bin/python3"
[ ! -f "$VENV_PYTHON" ] && VENV_PYTHON="$DIR/venv/bin/python3"
[ ! -f "$VENV_PYTHON" ] && VENV_PYTHON="python3"

echo "[INFO] Starting WiFi Monitor (DEMO MODE)..."
echo "[INFO] Dashboard: http://localhost:9002"
DEMO_MODE=1 "$VENV_PYTHON" "$DIR/app.py" --demo
