#!/bin/bash
# Run WiFi Monitor - Full Mode (requires root for packet capture)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$DIR/env/bin/python3"
[ ! -f "$VENV_PYTHON" ] && VENV_PYTHON="$DIR/venv/bin/python3"
[ ! -f "$VENV_PYTHON" ] && VENV_PYTHON="python3"

echo "[INFO] Starting WiFi Monitor (Full Mode)..."
echo "[INFO] Dashboard: http://localhost:9002"

echo "[INFO] ESP USB flashing is available in Dashboard → ESP → USB Firmware Center"

if [ "$EUID" -ne 0 ]; then
  echo "[INFO] Menjalankan dengan sudo (diperlukan untuk packet capture)..."
  exec sudo "$VENV_PYTHON" "$DIR/app.py" "$@"
else
  exec "$VENV_PYTHON" "$DIR/app.py" "$@"
fi
