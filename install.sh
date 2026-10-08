#!/bin/bash
# ╔══════════════════════════════════════════════════════╗
# ║     WiFi Cyber Attack Monitor - Installer            ║
# ║     Supports: Linux (Debian/Ubuntu/Arch) + Termux    ║
# ╚══════════════════════════════════════════════════════╝

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║         WiFi Cyber Attack Monitor v1.0               ║"
  echo "║         Real-time Network Security Dashboard         ║"
  echo "╚══════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Detect Environment ──────────────────────────────────────────────────────
detect_env() {
  if [ -d "/data/data/com.termux" ] || [ -n "$TERMUX_VERSION" ]; then
    ENV="termux"
    info "Detected: Termux (Android)"
  elif [ -f "/etc/debian_version" ] || command -v apt &>/dev/null; then
    ENV="debian"
    info "Detected: Debian/Ubuntu Linux"
  elif [ -f "/etc/arch-release" ] || command -v pacman &>/dev/null; then
    ENV="arch"
    info "Detected: Arch Linux"
  elif [ -f "/etc/redhat-release" ] || command -v yum &>/dev/null; then
    ENV="redhat"
    info "Detected: RedHat/CentOS Linux"
  else
    ENV="generic"
    warn "Unknown environment, using generic install"
  fi
}

# ── Install System Dependencies ─────────────────────────────────────────────
install_deps() {
  info "Installing system dependencies..."

  case $ENV in
    termux)
      pkg update -y
      pkg install -y python python-pip nmap net-tools iproute2 libpcap
      ;;
    debian)
      sudo apt update -y
      sudo apt install -y python3 python3-pip python3-venv nmap net-tools \
        iproute2 libpcap-dev tcpdump wireless-tools aircrack-ng usbutils 2>/dev/null || true
      ;;
    arch)
      sudo pacman -Sy --noconfirm python python-pip nmap net-tools iproute2 libpcap usbutils
      ;;
    redhat)
      sudo yum install -y python3 python3-pip nmap net-tools iproute libpcap-devel usbutils
      ;;
    *)
      warn "Please install manually: python3, pip, nmap, libpcap, and a USB-serial driver/toolchain if flashing ESP from USB"
      ;;
  esac

  success "System dependencies installed"
}

# ── Setup Python Virtual Environment ────────────────────────────────────────
setup_venv() {
  info "Setting up Python virtual environment..."

  if [ "$ENV" = "termux" ]; then
    # Termux doesn't need venv
    PYTHON="python"
    PIP="pip"
  else
    python3 -m venv venv 2>/dev/null || python -m venv venv
    source venv/bin/activate 2>/dev/null || . venv/bin/activate
    PYTHON="python"
    PIP="pip"
  fi

  success "Python environment ready"
}

# ── Install Python Packages ──────────────────────────────────────────────────
install_python_deps() {
  info "Installing Python packages from requirements.txt..."

  # Upgrade pip first
  $PIP install --upgrade pip -q 2>/dev/null

  if [ "$ENV" = "termux" ]; then
    $PIP install -r requirements.txt -q 2>/dev/null || {
      warn "Some packages failed on Termux; installing the portable subset..."
      $PIP install flask flask-socketio eventlet psutil requests dnspython pyserial esptool -q
      $PIP install scapy -q 2>/dev/null || warn "Scapy install failed (limited in Termux)"
      $PIP install netifaces -q 2>/dev/null || warn "netifaces install failed"
    }
  else
    # Install from requirements.txt
    if [ -f "requirements.txt" ]; then
      $PIP install -r requirements.txt -q
    else
      $PIP install flask flask-socketio eventlet scapy python-nmap netifaces psutil requests dnspython pyserial esptool -q
    fi
  fi

  success "All Python packages installed"
}

# ── Create Run Scripts ───────────────────────────────────────────────────────
create_run_scripts() {
  info "Creating run scripts..."

  # Detect venv python path
  VENV_PY="./env/bin/python3"
  if [ ! -f "$VENV_PY" ]; then
    VENV_PY="./venv/bin/python3"
  fi
  if [ ! -f "$VENV_PY" ]; then
    VENV_PY="python3"
  fi

  # Full mode (requires root)
  cat > run.sh << RUNEOF
#!/bin/bash
# Run WiFi Monitor - Full Mode (requires root for packet capture)
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="\$DIR/env/bin/python3"
[ ! -f "\$VENV_PYTHON" ] && VENV_PYTHON="\$DIR/venv/bin/python3"
[ ! -f "\$VENV_PYTHON" ] && VENV_PYTHON="python3"

echo "[INFO] Starting WiFi Monitor (Full Mode)..."
echo "[INFO] Dashboard: http://localhost:9002"

echo "[INFO] ESP USB flashing is available in Dashboard → ESP → USB Firmware Center"

if [ "\$EUID" -ne 0 ]; then
  echo "[INFO] Menjalankan dengan sudo (diperlukan untuk packet capture)..."
  exec sudo "\$VENV_PYTHON" "\$DIR/app.py" "\$@"
else
  exec "\$VENV_PYTHON" "\$DIR/app.py" "\$@"
fi
RUNEOF

  # Demo mode (no root needed)
  cat > run_demo.sh << DEMOEOF
#!/bin/bash
# Run WiFi Monitor - Demo Mode (tanpa root)
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="\$DIR/env/bin/python3"
[ ! -f "\$VENV_PYTHON" ] && VENV_PYTHON="\$DIR/venv/bin/python3"
[ ! -f "\$VENV_PYTHON" ] && VENV_PYTHON="python3"

echo "[INFO] Starting WiFi Monitor (DEMO MODE)..."
echo "[INFO] Dashboard: http://localhost:9002"
DEMO_MODE=1 "\$VENV_PYTHON" "\$DIR/app.py" --demo
DEMOEOF

  # Termux specific
  cat > run_termux.sh << TERMUXEOF
#!/bin/bash
# Run WiFi Monitor on Termux (Android)
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
echo "[INFO] Starting WiFi Monitor on Termux..."
echo "[INFO] Dashboard: http://127.0.0.1:9002"
DEMO_MODE=1 python3 "\$DIR/app.py" --demo
TERMUXEOF

  chmod +x run.sh run_demo.sh run_termux.sh
  success "Run scripts created"
}

# ── Verify Installation ──────────────────────────────────────────────────────
verify_install() {
  info "Verifying installation..."

  if $PYTHON -c "import flask, flask_socketio, eventlet" 2>/dev/null; then
    success "Core packages: OK"
  else
    error "Core packages missing! Try: pip install flask flask-socketio eventlet"
    return 1
  fi

  if $PYTHON -c "import serial, esptool" 2>/dev/null; then
    success "ESP USB flashing tools: OK"
  else
    warn "pyserial/esptool not available - USB firmware flashing disabled"
  fi

  if $PYTHON -c "import scapy" 2>/dev/null; then
    success "Scapy (packet capture): OK"
  else
    warn "Scapy not available - running in limited mode"
  fi

  success "Installation verified!"
}

# ── Print Usage ──────────────────────────────────────────────────────────────
print_usage() {
  echo ""
  echo -e "${BOLD}Installation Complete!${NC}"
  echo ""
  echo -e "${GREEN}How to run:${NC}"
  echo ""
  echo -e "  ${CYAN}Demo mode (no root):${NC}"
  echo "    bash run_demo.sh"
  echo ""
  echo -e "  ${CYAN}Full mode (Linux, auto-sudo):${NC}"
  echo "    bash run.sh"
  echo ""
  echo -e "  ${CYAN}Full mode (manual sudo dengan venv):${NC}"
  echo "    sudo ./env/bin/python3 app.py"
  echo ""
  echo -e "  ${CYAN}Termux (Android):${NC}"
  echo "    bash run_termux.sh"
  echo ""
  echo -e "${YELLOW}Access dashboard:${NC}"
  echo "  Browser: http://localhost:9002"
  echo "  Mobile:  http://<your-ip>:9002"
  echo ""
  echo -e "${RED}PENTING:${NC} Jangan pakai 'sudo python3 app.py' langsung!"
  echo "         Gunakan: sudo ./env/bin/python3 app.py"
  echo "         Atau:    bash run.sh  (otomatis pakai venv)"
  echo ""
  echo -e "${CYAN}ESP USB firmware:${NC}"
  echo "  Colok ESP8266 ke laptop → buka tab ESP → pilih port → pilih .bin → Flash Firmware"
  echo "  Browser cukup mengontrol laptop yang menjalankan Flask; USB dideteksi di laptop tersebut."
  echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  banner
  detect_env
  install_deps
  setup_venv
  install_python_deps
  create_run_scripts
  verify_install
  print_usage
}

main "$@"
