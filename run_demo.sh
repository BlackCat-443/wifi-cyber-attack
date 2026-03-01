#!/bin/bash
# WiFi Monitor - Demo Mode (tanpa root)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$DIR/env/bin/python3"

if [ ! -f "$VENV_PYTHON" ]; then
  VENV_PYTHON="python3"
fi

echo "[INFO] Starting WiFi Monitor (DEMO MODE)..."
echo "[INFO] Dashboard: http://localhost:9000"
DEMO_MODE=1 "$VENV_PYTHON" "$DIR/app.py" --demo
