# 🔌 ESP8266 Sensor Node — WiFi Monitor

> **Bahasa / Language:** [🇮🇩 Indonesia](#indonesia) | [🇬🇧 English](#english)

---

<a name="indonesia"></a>
## 🇮🇩 Dokumentasi Bahasa Indonesia

---

### Apa yang dilakukan ESP8266 ini?

ESP8266 bertindak sebagai **sensor lapangan** yang dipasang di jaringan WiFi kamu.

| Fitur | Keterangan |
|-------|------------|
| 📡 Scan WiFi | Deteksi semua jaringan WiFi di sekitar (SSID, channel, enkripsi, sinyal) |
| 🚫 Deteksi Deauth | Tangkap frame deauthentication 802.11 dari penyerang |
| 📤 Kirim Laporan | Kirim data ke server Flask via HTTP POST setiap 10 detik |
| 🌐 Web Server Mini | ESP punya server sendiri untuk terima perintah dari dashboard |

---

### Alur Kerja Lengkap

```
┌─────────────────────────────────────────────────────────────────┐
│                     ALUR KERJA ESP8266                          │
└─────────────────────────────────────────────────────────────────┘

1. ESP NYALA & KONEK WIFI
   ┌──────────┐    konek WiFi     ┌──────────┐
   │  ESP8266 │ ───────────────>  │  Router  │
   └──────────┘                   └──────────┘

2. ESP KIRIM LAPORAN KE DASHBOARD (setiap 10 detik)
   ┌──────────┐  HTTP POST        ┌──────────────┐  WebSocket   ┌─────────┐
   │  ESP8266 │ ───────────────>  │ Flask Server │ ──────────>  │ Browser │
   └──────────┘ /api/esp/report   └──────────────┘              └─────────┘
   Isi laporan:
   - deauth_events (serangan yang terdeteksi)
   - wifi_scan (daftar WiFi di sekitar)
   - status (IP, RSSI, uptime)

3. USER KLIK "SCAN WIFI" DI DASHBOARD
   ┌─────────┐  GET /api/esp/     ┌──────────────┐  GET /scan   ┌──────────┐
   │ Browser │ ───────────────>   │ Flask Server │ ──────────>  │  ESP8266 │
   └─────────┘ esp-01/scan        └──────────────┘              └──────────┘
                                         │                            │
                                         │    hasil scan JSON         │
                                         │ <──────────────────────────┘
                                         │
                                         │  emit 'esp_wifi_scan'
                                         └──────────────────────────> Browser
                                                                  (tab ESP update)

4. USER PILIH SSID & KLIK CONNECT
   ┌─────────┐  POST /api/esp/    ┌──────────────┐  POST /connect ┌──────────┐
   │ Browser │ ───────────────>   │ Flask Server │ ────────────>  │  ESP8266 │
   └─────────┘ esp-01/connect     └──────────────┘                └──────────┘
               {ssid, password}                                         │
                                                                        │ konek WiFi baru
                                                                        ▼
                                                                   ┌──────────┐
                                                                   │  Router  │
                                                                   │  Baru    │
                                                                   └──────────┘
                                                                        │
                                                                        │ kirim laporan
                                                                        ▼
                                                                ┌──────────────┐
                                                                │ Flask Server │
                                                                │ (status update)│
                                                                └──────────────┘

5. DASHBOARD UPDATE OTOMATIS
   Flask emit 'esp_status_update' → Browser update tab ESP
```

---

### Kebutuhan Hardware

| Komponen | Keterangan |
|----------|------------|
| ESP8266 | NodeMCU v1/v2/v3 ✅ atau Wemos D1 Mini ✅ |
| Kabel USB | Wajib support **data** (bukan charge only) |
| Power | 5V via USB |

> ⚠️ **Jangan pakai ESP-01** — RAM terlalu kecil (80KB), sering crash.
> Pakai **NodeMCU v3** atau **Wemos D1 Mini** untuk hasil terbaik.

---

### Konfigurasi Kode

Buka `wifi_probe.ino`, ubah bagian ini **sebelum** di-flash:

```cpp
// ─── WAJIB DIUBAH ────────────────────────────────────────────────
const char* WIFI_SSID     = "NamaWiFiKamu";       // WiFi awal ESP
const char* WIFI_PASSWORD = "PasswordWiFiKamu";   // Password WiFi
const char* SERVER_IP     = "192.168.100.66";     // IP laptop/server Flask
const int   SERVER_PORT   = 9002;                 // Port Flask
const char* ESP_ID        = "esp-sensor-01";      // Nama unik ESP ini
```

Cara cari IP laptop:
- **Windows**: buka CMD → ketik `ipconfig` → lihat IPv4 Address
- **Ubuntu/Debian**: buka terminal → ketik `hostname -I`

---

## 💻 Cara Flash ke ESP — Windows

### 🚀 Flash Firmware Langsung dari Dashboard (USB)

Sekarang kamu tidak wajib upload firmware lewat tombol Upload di Arduino IDE setiap kali. Selama Flask dijalankan di **laptop yang sama dengan ESP yang terhubung USB**, dashboard bisa mendeteksi port serial dan mengirim file firmware `.bin` ke ESP.

Alurnya:

```text
ESP8266 ──USB──> Laptop
                   │
                   ├─ Flask + pyserial + esptool
                   │
                   └─ Dashboard → ESP → USB Firmware Center
                                      │
                                      ├─ pilih port otomatis
                                      ├─ pilih file .bin
                                      └─ Flash Firmware
```

**Cara pakai:**

1. Jalankan aplikasi dengan `bash run.sh`.
2. Colok ESP8266 menggunakan kabel USB data.
3. Buka tab **🔌 ESP**.
4. Tunggu bagian **USB Firmware Center** mendeteksi `/dev/ttyUSB*`, `/dev/ttyACM*`, atau `COM*`.
5. Pilih file `.bin`, lalu klik **Auto Detect & Flash**. Port tidak perlu dipilih; esptool akan mencoba port serial yang terhubung secara otomatis. Jika ada beberapa serial device, port tertentu tetap bisa dipilih manual.
   - Dari Arduino IDE, gunakan **Sketch → Export Compiled Binary** untuk menghasilkan file `.bin`.
6. Progress/log flashing akan muncul langsung di dashboard.

> Catatan: deteksi USB terjadi di mesin yang menjalankan Flask. Jadi kalau dashboard dibuka dari HP, HP tetap hanya menjadi remote control; port USB laptop yang muncul di dashboard adalah milik laptop server.

> Untuk Linux, user harus punya akses ke serial device (umumnya group `dialout`) atau jalankan aplikasi dengan hak akses yang sesuai.

---

### Step 1 — Install Arduino IDE

1. Download dari **https://www.arduino.cc/en/software**
2. Pilih **Windows Win 10 and newer, 64 bits**
3. Install seperti biasa (Next → Next → Install)

### Step 2 — Install Driver CH340/CP2102

ESP8266 NodeMCU biasanya pakai chip USB-Serial CH340 atau CP2102.

**CH340 (paling umum di NodeMCU China):**
- Download: https://www.wch-ic.com/downloads/CH341SER_EXE.html
- Jalankan installer → Install

**CP2102 (Wemos D1 Mini):**
- Download: https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers
- Extract → jalankan `CP210xVCPInstaller_x64.exe`

Setelah install driver, colok ESP ke USB. Cek di **Device Manager** → **Ports (COM & LPT)** → harus muncul `COM3` atau `COM4` atau angka lain.

### Step 3 — Tambah Board ESP8266

1. Buka Arduino IDE
2. **File → Preferences**
3. Di kolom **Additional boards manager URLs**, tambahkan:
   ```
   https://arduino.esp8266.com/stable/package_esp8266com_index.json
   ```
4. Klik OK
5. **Tools → Board → Boards Manager**
6. Cari `esp8266` → klik **Install** (tunggu ~5 menit)

### Step 4 — Install Library ArduinoJson

1. **Tools → Manage Libraries**
2. Cari `ArduinoJson`
3. Pilih by **Benoit Blanchon** → versi **6.x** → **Install**

### Step 5 — Buka & Edit Kode

1. **File → Open** → navigasi ke folder `esp8266/` → buka `wifi_probe.ino`
2. Edit bagian konfigurasi (lihat section Konfigurasi Kode di atas)
3. Simpan: **Ctrl+S**

### Step 6 — Pilih Board & Port

**Tools → Board → ESP8266 Boards** → pilih:

| Hardware kamu | Pilih di Arduino IDE |
|---------------|----------------------|
| NodeMCU v2/v3 | `NodeMCU 1.0 (ESP-12E Module)` |
| Wemos D1 Mini | `LOLIN(WEMOS) D1 R2 & mini` |
| ESP-01 | `Generic ESP8266 Module` |

**Tools → Port** → pilih `COM3` (atau COM yang muncul di Device Manager)

**Tools → Upload Speed** → set ke `115200`

### Step 7 — Upload

1. Klik tombol **→ (Upload)** atau tekan **Ctrl+U**
2. Kalau muncul error `espcomm_upload_mem failed`:
   - Tahan tombol **FLASH/BOOT** di ESP
   - Klik Upload lagi
   - Lepas tombol setelah progress bar mulai jalan
3. Tunggu sampai muncul: `Done uploading.`

### Step 8 — Cek Serial Monitor

1. **Tools → Serial Monitor**
2. Set baud rate ke **115200** (pojok kanan bawah)
3. Output yang benar:

```
=== WiFi Monitor ESP8266 Sensor v2 ===
ESP ID   : esp-sensor-01
Server   : 192.168.100.66:9002
[WiFi] Connecting to: NamaWiFiKamu
....
[WiFi] Connected! IP: 192.168.100.50 | RSSI: -45 dBm
[WebServer] Jalan di http://192.168.100.50:80
[ESP] Sensor siap!
[HTTP] Laporan OK | deauth=0 scan=3
```

---

## 🐧 Cara Flash ke ESP — Ubuntu / Debian

### 🚀 Flash Firmware Directly from the Dashboard (USB)

You no longer need to upload firmware from Arduino IDE every time. When Flask runs on the **same laptop where the ESP is connected by USB**, the dashboard can detect the serial port and flash an exported `.bin` firmware file.

**How to use:**

1. Run `bash run.sh`.
2. Plug the ESP8266 into the laptop with a data USB cable.
3. Open the **🔌 ESP** tab.
4. Wait for **USB Firmware Center** to detect `/dev/ttyUSB*`, `/dev/ttyACM*`, or `COM*`.
5. Select a `.bin` file and click **Auto Detect & Flash**. You do not need to choose a port; esptool will enumerate serial ports and try to find the ESP8266 automatically. A specific port can still be selected manually when needed.
   - In Arduino IDE, use **Sketch → Export Compiled Binary** to produce the `.bin` file.
6. Flashing logs appear in the dashboard.

> USB detection happens on the machine running Flask. A phone browser can control the laptop server, but it cannot directly expose the phone's USB ports to the Flask server.

---

### Step 1 — Install Arduino IDE

```bash
# Cara 1: Download AppImage (direkomendasikan)
# Download dari https://www.arduino.cc/en/software → Linux 64 bits AppImage
chmod +x arduino-ide_*.AppImage
./arduino-ide_*.AppImage

# Cara 2: via snap
sudo snap install arduino

# Cara 3: via apt (versi lama 1.x)
sudo apt install -y arduino
```

### Step 2 — Izin Port USB

```bash
# Tambah user ke grup dialout agar bisa akses port USB tanpa sudo
sudo usermod -aG dialout $USER

# WAJIB logout dan login ulang setelah ini!
# Atau jalankan perintah ini untuk langsung aktif di session sekarang:
newgrp dialout
```

Cek port ESP terdeteksi:
```bash
# Colok ESP ke USB, lalu:
ls /dev/ttyUSB* /dev/ttyACM*
# Harusnya muncul: /dev/ttyUSB0 atau /dev/ttyACM0
```

Kalau tidak muncul, install driver:
```bash
sudo apt install -y linux-modules-extra-$(uname -r)
sudo modprobe ch341   # untuk chip CH340
# Cabut dan colok ulang ESP
```

### Step 3 — Tambah Board ESP8266

1. Buka Arduino IDE
2. **File → Preferences**
3. Di **Additional boards manager URLs**, tambahkan:
   ```
   https://arduino.esp8266.com/stable/package_esp8266com_index.json
   ```
4. **Tools → Board → Boards Manager** → cari `esp8266` → **Install**

### Step 4 — Install Library ArduinoJson

**Tools → Manage Libraries** → cari `ArduinoJson` by Benoit Blanchon → versi **6.x** → **Install**

### Step 5 — Buka & Edit Kode

```bash
# Buka file langsung dari terminal
arduino /home/banh-code/wifi-monitor/esp8266/wifi_probe.ino
# atau buka Arduino IDE dulu, lalu File → Open
```

Edit bagian konfigurasi, simpan dengan **Ctrl+S**.

### Step 6 — Pilih Board & Port

**Tools → Board → ESP8266 Boards:**

| Hardware | Pilih |
|----------|-------|
| NodeMCU v2/v3 | `NodeMCU 1.0 (ESP-12E Module)` |
| Wemos D1 Mini | `LOLIN(WEMOS) D1 R2 & mini` |
| ESP-01 | `Generic ESP8266 Module` |

**Tools → Port** → pilih `/dev/ttyUSB0` atau `/dev/ttyACM0`

**Tools → Upload Speed** → `115200`

### Step 7 — Upload

Klik **→ (Upload)** atau **Ctrl+U**.

Kalau error `Permission denied` pada port:
```bash
sudo chmod 666 /dev/ttyUSB0
# lalu coba upload lagi
```

Kalau error `espcomm_upload_mem failed`:
- Tahan tombol **FLASH/BOOT** di ESP → klik Upload → lepas setelah progress mulai

### Step 8 — Cek Serial Monitor

**Tools → Serial Monitor** → baud rate **115200**

Atau pakai terminal:
```bash
# Install screen kalau belum ada
sudo apt install -y screen

# Monitor serial
screen /dev/ttyUSB0 115200
# Keluar: Ctrl+A lalu ketik :quit
```

---

### Verifikasi di Dashboard

Setelah ESP nyala dan Flask server jalan (`bash run.sh`):

**1. Cek ESP terdaftar:**
```bash
curl http://localhost:9002/api/esp/status
```

Output:
```json
{
  "count": 1,
  "devices": [{
    "esp_id": "esp-sensor-01",
    "esp_ip": "192.168.100.50",
    "connected_ssid": "NamaWiFiKamu",
    "rssi": -45,
    "uptime": 120,
    "last_seen": "2026-03-01 18:00:00"
  }]
}
```

**2. Buka tab ESP di dashboard:**
```
http://192.168.100.66:9002
```
Klik tab **🔌 ESP** → ESP kamu muncul di sana.

**3. Scan WiFi dari dashboard:**
- Klik **📡 Scan WiFi Sekitar** di kartu ESP
- Tunggu ~10 detik
- Daftar WiFi di sekitar ESP muncul

**4. Konek ESP ke WiFi lain:**
- Klik salah satu SSID dari hasil scan
- Masukkan password
- Klik **📶 Connect**
- Tunggu ~15 detik → ESP konek ke WiFi baru
- Status di dashboard update otomatis

---

### Troubleshoot

#### ❌ Windows: Port COM tidak muncul di Device Manager
- Ganti kabel USB (pakai yang support data)
- Install ulang driver CH340: https://www.wch-ic.com/downloads/CH341SER_EXE.html
- Coba port USB yang berbeda

#### ❌ Ubuntu: `/dev/ttyUSB0` tidak ada
```bash
# Cek apakah kernel mendeteksi device
dmesg | tail -20
# Cari baris seperti: "ch341-uart converter now attached to ttyUSB0"

# Install driver manual
sudo apt install -y linux-modules-extra-$(uname -r)
sudo modprobe ch341
```

#### ❌ Upload gagal / timeout (Windows & Ubuntu)
- Tahan tombol **FLASH/BOOT** di ESP saat klik Upload
- Turunkan Upload Speed ke `9600`
- Ganti kabel USB

#### ❌ ESP konek WiFi tapi tidak muncul di dashboard
- Pastikan `SERVER_IP` di kode = IP laptop yang jalanin Flask
- Pastikan Flask jalan: `bash run.sh`
- Pastikan ESP dan laptop di jaringan WiFi yang **sama**
- Cek firewall:
  ```bash
  # Ubuntu
  sudo ufw allow 9002/tcp

  # Windows: buka Windows Defender Firewall
  # → Allow an app → tambahkan Python
  ```

#### ❌ Scan WiFi di dashboard tidak jalan
- Pastikan ESP sudah kirim laporan dulu (cek `/api/esp/status`)
- ESP harus sudah terdaftar sebelum bisa di-scan
- Cek log Flask di terminal untuk error

#### ❌ ESP crash / restart terus
- Pakai NodeMCU/Wemos D1 Mini, bukan ESP-01
- Naikkan `SCAN_INTERVAL` ke `60000` (1 menit)
- Kurangi `wifiNetworks[20]` jadi `[10]`

---

<a name="english"></a>
## 🇬🇧 English Documentation

---

### What does this ESP8266 do?

The ESP8266 acts as a **field sensor** on your WiFi network.

| Feature | Description |
|---------|-------------|
| 📡 WiFi Scan | Detects all nearby WiFi networks (SSID, channel, encryption, signal) |
| 🚫 Deauth Detection | Captures 802.11 deauthentication frames from attackers |
| 📤 Report Sending | Sends data to Flask server via HTTP POST every 10 seconds |
| 🌐 Mini Web Server | ESP has its own server to receive commands from the dashboard |

---

### Full Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                     ESP8266 WORKFLOW                            │
└─────────────────────────────────────────────────────────────────┘

1. ESP BOOTS & CONNECTS TO WIFI
   ┌──────────┐   connect WiFi    ┌──────────┐
   │  ESP8266 │ ───────────────>  │  Router  │
   └──────────┘                   └──────────┘

2. ESP SENDS REPORTS TO DASHBOARD (every 10 seconds)
   ┌──────────┐  HTTP POST        ┌──────────────┐  WebSocket   ┌─────────┐
   │  ESP8266 │ ───────────────>  │ Flask Server │ ──────────>  │ Browser │
   └──────────┘ /api/esp/report   └──────────────┘              └─────────┘
   Report contains:
   - deauth_events (detected attacks)
   - wifi_scan (nearby networks)
   - status (IP, RSSI, uptime)

3. USER CLICKS "SCAN WIFI" IN DASHBOARD
   ┌─────────┐  GET /api/esp/     ┌──────────────┐  GET /scan   ┌──────────┐
   │ Browser │ ───────────────>   │ Flask Server │ ──────────>  │  ESP8266 │
   └─────────┘ esp-01/scan        └──────────────┘              └──────────┘
                                         │                            │
                                         │    scan results JSON       │
                                         │ <──────────────────────────┘
                                         │
                                         │  emit 'esp_wifi_scan'
                                         └──────────────────────────> Browser
                                                                  (ESP tab updates)

4. USER SELECTS SSID & CLICKS CONNECT
   ┌─────────┐  POST /api/esp/    ┌──────────────┐  POST /connect ┌──────────┐
   │ Browser │ ───────────────>   │ Flask Server │ ────────────>  │  ESP8266 │
   └─────────┘ esp-01/connect     └──────────────┘                └──────────┘
               {ssid, password}                                         │
                                                                        │ connect new WiFi
                                                                        ▼
                                                                   ┌──────────┐
                                                                   │  New     │
                                                                   │  Router  │
                                                                   └──────────┘
                                                                        │
                                                                        │ send report
                                                                        ▼
                                                                ┌──────────────┐
                                                                │ Flask Server │
                                                                │ (status update)│
                                                                └──────────────┘

5. DASHBOARD AUTO-UPDATES
   Flask emits 'esp_status_update' → Browser updates ESP tab
```

---

### Hardware Requirements

| Component | Notes |
|-----------|-------|
| ESP8266 | NodeMCU v1/v2/v3 ✅ or Wemos D1 Mini ✅ |
| USB Cable | Must support **data** (not charge-only) |
| Power | 5V via USB |

> ⚠️ **Don't use ESP-01** — too little RAM (80KB), crashes frequently.
> Use **NodeMCU v3** or **Wemos D1 Mini** for best results.

---

### Code Configuration

Open `wifi_probe.ino` and change these values **before** flashing:

```cpp
// ─── MUST CHANGE ─────────────────────────────────────────────────
const char* WIFI_SSID     = "YourWiFiName";
const char* WIFI_PASSWORD = "YourWiFiPassword";
const char* SERVER_IP     = "192.168.100.66";   // Flask server IP
const int   SERVER_PORT   = 9002;
const char* ESP_ID        = "esp-sensor-01";
```

Find your laptop's IP:
- **Windows**: open CMD → type `ipconfig` → look for IPv4 Address
- **Ubuntu/Debian**: open terminal → type `hostname -I`

---

## 💻 Flashing on Windows

### Step 1 — Install Arduino IDE
Download from **https://www.arduino.cc/en/software** → Windows Win 10 64 bits → install normally.

### Step 2 — Install USB Driver

**CH340 (most common on cheap NodeMCU):**
- Download: https://www.wch-ic.com/downloads/CH341SER_EXE.html → run installer

**CP2102 (Wemos D1 Mini):**
- Download: https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers → run `CP210xVCPInstaller_x64.exe`

After installing, plug in ESP. Check **Device Manager → Ports (COM & LPT)** — should show `COM3` or similar.

### Step 3 — Add ESP8266 Board
1. **File → Preferences** → Additional boards manager URLs:
   ```
   https://arduino.esp8266.com/stable/package_esp8266com_index.json
   ```
2. **Tools → Board → Boards Manager** → search `esp8266` → **Install**

### Step 4 — Install ArduinoJson
**Tools → Manage Libraries** → search `ArduinoJson` by Benoit Blanchon → version **6.x** → **Install**

### Step 5 — Open & Edit Code
**File → Open** → navigate to `esp8266/wifi_probe.ino` → edit config → **Ctrl+S**

### Step 6 — Select Board & Port

| Your hardware | Select in Arduino IDE |
|---------------|-----------------------|
| NodeMCU v2/v3 | `NodeMCU 1.0 (ESP-12E Module)` |
| Wemos D1 Mini | `LOLIN(WEMOS) D1 R2 & mini` |

**Tools → Port** → select `COM3` (or whichever shows in Device Manager)
**Tools → Upload Speed** → `115200`

### Step 7 — Upload
Click **→ (Upload)** or **Ctrl+U**. If it fails, hold **FLASH/BOOT** button on ESP while clicking Upload.

### Step 8 — Serial Monitor
**Tools → Serial Monitor** → baud rate **115200**

Expected output:
```
=== WiFi Monitor ESP8266 Sensor v2 ===
[WiFi] Connected! IP: 192.168.100.50 | RSSI: -45 dBm
[WebServer] Running at http://192.168.100.50:80
[ESP] Sensor ready!
[HTTP] Report OK | deauth=0 scan=3
```

---

## 🐧 Flashing on Ubuntu / Debian

### Step 1 — Install Arduino IDE
```bash
# Download AppImage from https://www.arduino.cc/en/software → Linux 64 bits
chmod +x arduino-ide_*.AppImage
./arduino-ide_*.AppImage
```

### Step 2 — USB Port Permission
```bash
sudo usermod -aG dialout $USER
newgrp dialout   # apply without logout

# Verify ESP is detected
ls /dev/ttyUSB* /dev/ttyACM*
# Should show: /dev/ttyUSB0
```

If port not found:
```bash
sudo apt install -y linux-modules-extra-$(uname -r)
sudo modprobe ch341
```

### Step 3 — Add ESP8266 Board
Same as Windows — add URL in Preferences, install from Boards Manager.

### Step 4 — Install ArduinoJson
Same as Windows — via Manage Libraries.

### Step 5 — Open & Edit Code
```bash
arduino /home/banh-code/wifi-monitor/esp8266/wifi_probe.ino
```
Edit config, save with **Ctrl+S**.

### Step 6 — Select Board & Port
Same board selection as Windows.
**Tools → Port** → `/dev/ttyUSB0`

### Step 7 — Upload
Click **→ (Upload)**. If `Permission denied`:
```bash
sudo chmod 666 /dev/ttyUSB0
```

### Step 8 — Serial Monitor
**Tools → Serial Monitor** → baud rate **115200**

Or via terminal:
```bash
sudo apt install -y screen
screen /dev/ttyUSB0 115200
# Exit: Ctrl+A then type :quit
```

---

### Verify in Dashboard

```bash
# Check ESP registered
curl http://localhost:9002/api/esp/status

# Open dashboard
# http://192.168.100.66:9002 → click tab 🔌 ESP
```

Steps in dashboard:
1. Click **📡 Scan WiFi Sekitar** on the ESP card
2. Wait ~10 seconds for results
3. Click any SSID → enter password → click **📶 Connect**
4. Wait ~15 seconds → ESP connects to new WiFi
5. Dashboard status updates automatically

---

### Troubleshooting

| Problem | Solution |
|---------|----------|
| Windows: COM port missing | Install CH340 driver, try different USB port |
| Ubuntu: `/dev/ttyUSB0` missing | `sudo modprobe ch341`, replug ESP |
| Upload fails | Hold FLASH/BOOT button during upload |
| Ubuntu: Permission denied | `sudo chmod 666 /dev/ttyUSB0` |
| ESP connects but not in dashboard | Check `SERVER_IP` matches Flask server IP |
| Scan WiFi not working | ESP must send first report before scan works |
| ESP keeps crashing | Use NodeMCU/Wemos D1 Mini, not ESP-01 |
| Can't reach server | `sudo ufw allow 9002/tcp` (Ubuntu) |
  