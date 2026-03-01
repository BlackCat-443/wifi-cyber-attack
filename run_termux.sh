#!/bin/bash
# Run WiFi Monitor on Termux (Android)
cd "$(dirname "${BASH_SOURCE[0]}")"
echo "[INFO] Starting WiFi Monitor on Termux..."
echo "[INFO] Dashboard: http://localhost:5000"
echo "[INFO] Access from phone browser: http://127.0.0.1:5000"
DEMO_MODE=1 python app.py --demo
