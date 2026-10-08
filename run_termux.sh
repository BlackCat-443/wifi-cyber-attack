#!/bin/bash
# Run WiFi Monitor on Termux (Android)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[INFO] Starting WiFi Monitor on Termux..."
echo "[INFO] Dashboard: http://127.0.0.1:9002"
DEMO_MODE=1 python3 "$DIR/app.py" --demo
