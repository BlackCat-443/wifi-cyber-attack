#!/bin/bash
# WiFi Monitor - Full Mode (requires root for packet capture)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$DIR/venv/bin/python3"

# Fallback ke python3 biasa kalau venv tidak ada
if [ ! -f "$VENV_PYTHON" ]; then
  VENV_PYTHON="python3"
fi

if [ "$EUID" -ne 0 ]; then
  echo "[INFO] Menjalankan dengan sudo (diperlukan untuk packet capture)..."
  exec sudo "$VENV_PYTHON" "$DIR/app.py" "$@"
else
  exec "$VENV_PYTHON" "$DIR/app.py" "$@"
fi
