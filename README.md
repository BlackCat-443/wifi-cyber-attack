# 🛡️ WiFi Cyber Attack Monitor

> **Bahasa / Language:** [🇮🇩 Indonesia](#indonesia) | [🇬🇧 English](#english)

Monitor keamanan jaringan WiFi secara real-time. Deteksi serangan siber dan tampilkan alert langsung di dashboard browser.

Real-time WiFi network security monitor. Detects cyber attacks and shows instant alerts on a browser dashboard.

---

<a name="indonesia"></a>
## 🇮🇩 Dokumentasi Bahasa Indonesia

### Fitur

| Fitur | Keterangan |
|-------|------------|
| 📡 Device Scanner | Daftar semua perangkat di jaringan (IP, MAC, Hostname, Vendor) |
| ⚠️ ARP Spoofing | Deteksi perubahan MAC address (serangan Man-in-the-Middle) |
| 🚫 Deauth Attack | Deteksi banjir frame deauthentication WiFi |
| 🔴 DNS Spoofing | Bandingkan respons DNS dengan server terpercaya |
| 💥 DHCP Starvation | Deteksi flood DHCP dan rogue DHCP server |
| 🔍 Port Scanning | Deteksi TCP SYN scan, UDP scan, ICMP sweep |
| 💥 SYN Flood | Deteksi serangan DoS SYN flood |
| 📊 Dashboard Real-time | Update live via WebSocket, grafik, timeline alert |
| 📱 Mobile Friendly | UI responsif, bisa dibuka dari HP |
| 🔌 ESP8266 Sensor | Integrasi sensor lapangan via ESP8266 |
| 💾 ESP USB Flasher | Deteksi port ESP di laptop + flash firmware `.bin` dari dashboard |

---

### Cara Menjalankan

#### Linux — Full Mode (butuh root untuk packet capture)

```bash
# Langkah 1: Install semua dependensi ke virtual environment
bash install.sh

# Langkah 2: Jalankan dengan sudo otomatis
bash run.sh
```

Buka browser: **http://localhost:9002**

> ⚠️ Jangan pakai `sudo python3 app.py` langsung — system python3 tidak punya packages!
> Script `run.sh` sudah otomatis pakai python dari venv yang benar.

#### Linux — Demo Mode (tanpa root, data simulasi)

```bash
bash run_demo.sh
```

Cocok untuk testing UI tanpa perlu akses root atau jaringan nyata.

#### Termux (Android)

```bash
bash install.sh
bash run_termux.sh
```

#### Manual (tanpa install.sh)

```bash
# Buat virtual environment
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# Demo mode
DEMO_MODE=1 ./venv/bin/python3 app.py --demo

# Full mode (butuh root)
sudo ./venv/bin/python3 app.py
```

---

### Akses Dashboard

| Cara Akses | URL |
|------------|-----|
| Dari laptop sendiri | http://localhost:9002 |
| Dari HP / perangkat lain | http://\<IP-laptop\>:9002 |
| Termux | http://127.0.0.1:9002 |

Cari IP laptop kamu:
```bash
hostname -I
# atau
ip addr show | grep "inet " | grep -v 127.0.0.1
```

---

### Struktur File

```
wifi-monitor/
│
├── app.py                  # Server utama Flask + SocketIO
├── requirements.txt        # Daftar dependensi Python
├── install.sh              # Script instalasi otomatis
├── run.sh                  # Jalankan full mode (Linux)
├── run_demo.sh             # Jalankan demo mode (tanpa root)
├── run_termux.sh           # Jalankan di Termux/Android
│
├── core/                   # Modul inti deteksi serangan
│   ├── __init__.py
│   ├── alert.py            # Manajemen alert (dedup, severity, cooldown)
│   ├── scanner.py          # Scanner perangkat jaringan (ARP + hostname)
│   ├── arp_monitor.py      # Deteksi ARP spoofing / MITM
│   ├── deauth_monitor.py   # Deteksi deauth attack WiFi
│   ├── dns_monitor.py      # Deteksi DNS spoofing
│   ├── dhcp_monitor.py     # Deteksi DHCP starvation + rogue DHCP
│   ├── port_scanner.py     # Deteksi port scan + SYN flood
│   └── mitigator.py        # Eksekusi countermeasure (iptables, dll)
│
├── templates/
│   └── index.html          # Halaman dashboard web
│
├── static/
│   ├── css/style.css       # Styling dashboard
│   └── js/dashboard.js     # Logic frontend (SocketIO, chart, modal)
│
└── esp8266/                # Integrasi sensor ESP8266
    ├── wifi_probe.ino      # Kode Arduino untuk ESP8266
    └── README.md           # Dokumentasi ESP8266 (ID + EN)
```

---

### Cara Kerja Deteksi

#### ARP Spoofing / MITM
Monitor semua ARP reply di jaringan. Kalau IP yang sama tiba-tiba punya MAC berbeda, langsung trigger alert CRITICAL.

#### Deauth Attack
Tangkap frame 802.11 deauthentication. Butuh WiFi adapter yang support monitor mode. Kalau tidak ada, pakai ESP8266 sebagai sensor.

#### DNS Spoofing
Capture respons DNS, bandingkan dengan Google DNS (8.8.8.8) dan Cloudflare (1.1.1.1). Kalau hasilnya beda, alert HIGH.

#### DHCP Starvation
Hitung DHCP DISCOVER/REQUEST dari satu MAC. Kalau lebih dari 10 request dalam 30 detik, alert HIGH.

#### Port Scanning
Hitung port unik yang di-scan dari satu IP. Lebih dari 15 port dalam 10 detik = alert MEDIUM.

---

### Integrasi ESP8266

ESP8266 bisa dipasang sebagai sensor lapangan yang mengirim data ke dashboard ini.

```
ESP8266 ──HTTP POST──> /api/esp/report ──> Dashboard

USB flash dari laptop:
ESP8266 ──USB──> Flask laptop ──esptool──> firmware `.bin`
```

Di tab **🔌 ESP**, USB serial dideteksi otomatis. Cukup pilih firmware `.bin` lalu tekan **Auto Detect & Flash**; pilihan port manual tetap tersedia bila diperlukan. Saat mode Auto aktif, esptool akan mencari port serial yang tersambung dan mencoba menemukan chip ESP8266. Bila dashboard dibuka dari HP, USB yang ditampilkan tetap milik laptop yang menjalankan Flask.

Lihat dokumentasi lengkap di: [`esp8266/README.md`](esp8266/README.md)

Cek status ESP yang terhubung:
```bash
curl http://localhost:9002/api/esp/status
```

---

### Troubleshoot

#### ❌ `ModuleNotFoundError: No module named 'flask'`
```bash
# Jangan pakai sudo python3 langsung!
# Pakai script yang sudah benar:
bash run.sh

# Atau manual dengan python dari venv:
sudo ./venv/bin/python3 app.py
```

#### ❌ `OSError: [Errno 98] Address already in use`
Port sudah dipakai proses lain. Kill dulu:
```bash
# Cari proses yang pakai port 9002
sudo lsof -i :9002

# Kill semua proses python yang jalan
sudo pkill -f "python3.*app.py"

# Atau kill by port langsung
sudo fuser -k 9002/tcp
```

#### ❌ Hostname tampil IP bukan nama device
Ini normal kalau device tidak punya reverse DNS. Coba install tools tambahan:
```bash
# Untuk deteksi device Android/iOS/Mac (mDNS)
sudo apt install -y avahi-utils

# Untuk deteksi device Windows (NetBIOS)
sudo apt install -y samba-common-bin

# Untuk deteksi via nmap
sudo apt install -y nmap
```
Setelah install, restart server dan scan ulang.

#### ❌ Vendor device tampil "Unknown"
MAC address tidak ada di database lokal. Pastikan koneksi internet aktif — sistem akan otomatis query ke `macvendors.com` sebagai fallback.

#### ❌ ARP/Deauth monitor tidak jalan
```bash
# Cek apakah scapy bisa capture packet
sudo ./venv/bin/python3 -c "from scapy.all import sniff; print('OK')"

# Kalau error permission:
sudo setcap cap_net_raw+ep ./venv/bin/python3
```

#### ❌ Dashboard tidak update real-time (WebSocket error 500)
Pastikan pakai `eventlet` sebagai async backend:
```bash
# Cek versi
./venv/bin/pip show eventlet flask-socketio

# Reinstall kalau perlu
./venv/bin/pip install --upgrade eventlet flask-socketio
```

#### ❌ Tidak bisa akses dari HP
```bash
# Pastikan firewall mengizinkan port 9002
sudo ufw allow 9002/tcp
sudo ufw status

# Cek IP laptop
hostname -I
# Buka dari HP: http://<IP-laptop>:9002
```

---

### Kebutuhan Sistem

| Kebutuhan | Minimum |
|-----------|---------|
| Python | 3.8+ |
| RAM | 256 MB |
| OS | Linux (Ubuntu/Debian/Kali) |
| Hak akses | root/sudo untuk packet capture |
| WiFi adapter | Support monitor mode (untuk deauth detection) |

---

### Legal Notice / Peringatan Hukum

> 🇮🇩 Tools ini dibuat untuk **keperluan edukasi dan pertahanan** saja. Hanya gunakan di jaringan yang kamu miliki atau punya izin untuk memonitornya. Penggunaan untuk menyerang jaringan orang lain adalah ilegal.

> 🇬🇧 This tool is for **educational and defensive purposes only**. Only use on networks you own or have explicit permission to monitor. Using this to attack others' networks is illegal.

---

<a name="english"></a>
## 🇬🇧 English Documentation

### Features

| Feature | Description |
|---------|-------------|
| 📡 Device Scanner | Lists all network devices (IP, MAC, Hostname, Vendor) |
| ⚠️ ARP Spoofing | Detects MAC address changes (Man-in-the-Middle attacks) |
| 🚫 Deauth Attack | Detects WiFi deauthentication frame floods |
| 🔴 DNS Spoofing | Compares DNS responses against trusted servers |
| 💥 DHCP Starvation | Detects DHCP flood attacks & rogue DHCP servers |
| 🔍 Port Scanning | Detects TCP SYN scans, UDP scans, ICMP sweeps |
| 💥 SYN Flood | Detects DoS SYN flood attacks |
| 📊 Real-time Dashboard | Live WebSocket updates, charts, alert timeline |
| 📱 Mobile Friendly | Responsive UI, works on phone browser |
| 🔌 ESP8266 Sensor | Field sensor integration via ESP8266 |

---

### How to Run

#### Linux — Full Mode (requires root for packet capture)

```bash
# Step 1: Install all dependencies into virtual environment
bash install.sh

# Step 2: Run with automatic sudo
bash run.sh
```

Open browser: **http://localhost:9002**

> ⚠️ Don't use `sudo python3 app.py` directly — system python3 doesn't have the packages!
> The `run.sh` script automatically uses the correct python from venv.

#### Linux — Demo Mode (no root, simulated data)

```bash
bash run_demo.sh
```

Good for testing the UI without root access or a real network.

#### Termux (Android)

```bash
bash install.sh
bash run_termux.sh
```

#### Manual (without install.sh)

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# Demo mode
DEMO_MODE=1 ./venv/bin/python3 app.py --demo

# Full mode (requires root)
sudo ./venv/bin/python3 app.py
```

---

### Dashboard Access

| Access Method | URL |
|---------------|-----|
| From laptop | http://localhost:9002 |
| From phone / other device | http://\<laptop-IP\>:9002 |
| Termux | http://127.0.0.1:9002 |

Find your laptop's IP:
```bash
hostname -I
```

---

### Project Structure

```
wifi-monitor/
│
├── app.py                  # Main Flask + SocketIO server
├── requirements.txt        # Python dependencies
├── install.sh              # Auto installer script
├── run.sh                  # Run full mode (Linux)
├── run_demo.sh             # Run demo mode (no root)
├── run_termux.sh           # Run on Termux/Android
│
├── core/                   # Attack detection modules
│   ├── __init__.py
│   ├── alert.py            # Alert manager (dedup, severity, cooldown)
│   ├── scanner.py          # Network device scanner (ARP + hostname)
│   ├── arp_monitor.py      # ARP spoofing / MITM detector
│   ├── deauth_monitor.py   # WiFi deauth attack detector
│   ├── dns_monitor.py      # DNS spoofing detector
│   ├── dhcp_monitor.py     # DHCP starvation + rogue DHCP detector
│   ├── port_scanner.py     # Port scan + SYN flood detector
│   └── mitigator.py        # Countermeasure executor (iptables, etc.)
│
├── templates/
│   └── index.html          # Web dashboard page
│
├── static/
│   ├── css/style.css       # Dashboard styling
│   └── js/dashboard.js     # Frontend logic (SocketIO, charts, modals)
│
└── esp8266/                # ESP8266 sensor integration
    ├── wifi_probe.ino      # Arduino code for ESP8266
    └── README.md           # ESP8266 documentation (ID + EN)
```

---

### ESP8266 Integration

The ESP8266 can be deployed as a field sensor that sends data to this dashboard.

```
ESP8266 ──HTTP POST──> /api/esp/report ──> Dashboard
```

Full documentation: [`esp8266/README.md`](esp8266/README.md)

Check connected ESP devices:
```bash
curl http://localhost:9002/api/esp/status
```

---

### Troubleshooting

#### ❌ `ModuleNotFoundError: No module named 'flask'`
```bash
# Don't use sudo python3 directly!
bash run.sh
# or manually:
sudo ./venv/bin/python3 app.py
```

#### ❌ `OSError: [Errno 98] Address already in use`
```bash
sudo pkill -f "python3.*app.py"
sudo fuser -k 9002/tcp
```

#### ❌ Hostname shows IP instead of device name
Install additional tools for better hostname resolution:
```bash
sudo apt install -y avahi-utils        # Android/iOS/Mac (mDNS)
sudo apt install -y samba-common-bin   # Windows (NetBIOS)
sudo apt install -y nmap               # Fallback
```
Restart server and rescan after installing.

#### ❌ Vendor shows "Unknown"
MAC not in local database. Make sure internet is active — the system will automatically query `macvendors.com` as fallback.

#### ❌ ARP/Deauth monitor not working
```bash
sudo ./venv/bin/python3 -c "from scapy.all import sniff; print('OK')"
# If permission error:
sudo setcap cap_net_raw+ep ./venv/bin/python3
```

#### ❌ Dashboard not updating (WebSocket 500 error)
```bash
./venv/bin/pip install --upgrade eventlet flask-socketio
```

#### ❌ Can't access from phone
```bash
sudo ufw allow 9002/tcp
hostname -I   # use this IP from phone: http://<IP>:9002
```

---

### System Requirements

| Requirement | Minimum |
|-------------|---------|
| Python | 3.8+ |
| RAM | 256 MB |
| OS | Linux (Ubuntu/Debian/Kali) |
| Privileges | root/sudo for packet capture |
| WiFi adapter | Monitor mode support (for deauth detection) |
