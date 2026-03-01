"""
WiFi Cyber Attack Monitor
Main Flask + SocketIO Application
"""

import os
import sys
import time
import threading
import subprocess
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# Core modules
from core.alert import AlertManager
from core.scanner import NetworkScanner
from core.arp_monitor import ARPMonitor
from core.deauth_monitor import DeauthMonitor
from core.dns_monitor import DNSMonitor
from core.dhcp_monitor import DHCPMonitor
from core.port_scanner import PortScanMonitor
from core.mitigator import run_mitigation, get_mitigation_preview

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = 'wifi-monitor-secret-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# ─── Global Instances ─────────────────────────────────────────────────────────
alert_manager = AlertManager()
scanner = NetworkScanner()
arp_monitor = ARPMonitor(alert_manager)
deauth_monitor = DeauthMonitor(alert_manager)
dns_monitor = DNSMonitor(alert_manager)
dhcp_monitor = DHCPMonitor(alert_manager)
port_monitor = PortScanMonitor(alert_manager)

# ─── Stats ────────────────────────────────────────────────────────────────────
start_time = datetime.now()
demo_mode = "--demo" in sys.argv or os.environ.get("DEMO_MODE", "0") == "1"


# ─── Callbacks ────────────────────────────────────────────────────────────────
def on_new_alert(alert):
    """Push new alert to all connected clients via WebSocket"""
    socketio.emit('new_alert', alert)
    # Update stats
    socketio.emit('stats_update', get_stats_data())


def on_devices_update(devices):
    """Push device list update to all clients"""
    socketio.emit('devices_update', {'devices': devices})


alert_manager.on_alert = on_new_alert
scanner.on_update = on_devices_update


# ─── Background Tasks ─────────────────────────────────────────────────────────
def start_monitors():
    """Start all monitoring modules"""
    network, iface = scanner.network, scanner.iface

    # Start scanner first
    scanner.start()
    time.sleep(3)  # Wait for initial scan

    # Seed ARP table with known devices
    devices = scanner.get_devices()
    arp_monitor.seed_table(devices)

    # Start monitors
    arp_monitor.start(iface)
    deauth_monitor.start(iface)
    dns_monitor.start(iface)
    dhcp_monitor.start(iface)
    port_monitor.start(iface)

    print(f"[App] All monitors started | Interface: {iface}")


def auto_scan_loop():
    """Background thread: push device updates every 5 seconds"""
    while True:
        time.sleep(5)
        try:
            devices = scanner.get_devices()
            socketio.emit('devices_update', {'devices': devices})
            socketio.emit('stats_update', get_stats_data())
        except Exception:
            pass


def get_stats_data():
    alert_stats = alert_manager.get_stats()
    devices = scanner.get_devices()
    online = sum(1 for d in devices if d.get("status") == "online")
    uptime = str(datetime.now() - start_time).split('.')[0]

    return {
        "total_alerts": alert_stats["total"],
        "severity_counts": alert_stats["severity_counts"],
        "unread_alerts": alert_stats["unread"],
        "total_devices": len(devices),
        "online_devices": online,
        "uptime": uptime,
        "attack_counts": {
            "arp": arp_monitor.attack_count,
            "deauth": deauth_monitor.attack_count,
            "dns": dns_monitor.attack_count,
            "dhcp": dhcp_monitor.attack_count,
            "port": port_monitor.attack_count,
        }
    }


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/devices')
def api_devices():
    """
    GET /api/devices
    Kembalikan daftar semua perangkat yang terdeteksi di jaringan.

    Returns JSON:
        devices : list perangkat (ip, mac, hostname, vendor, status, threat_level)
        count   : jumlah perangkat

    ---
    GET /api/devices
    Return list of all devices detected on the network.

    Returns JSON:
        devices : device list (ip, mac, hostname, vendor, status, threat_level)
        count   : number of devices
    """
    devices = scanner.get_devices()
    return jsonify({"devices": devices, "count": len(devices)})


@app.route('/api/alerts')
def api_alerts():
    """
    GET /api/alerts
    Kembalikan daftar alert dengan filter opsional.

    Query params:
        limit    : jumlah maksimum alert (default 50)
        severity : filter severity — LOW | MEDIUM | HIGH | CRITICAL

    Returns JSON:
        alerts : list alert
        stats  : statistik ringkasan (total, unread, per-severity)

    ---
    GET /api/alerts
    Return list of alerts with optional filtering.

    Query params:
        limit    : max number of alerts (default 50)
        severity : severity filter — LOW | MEDIUM | HIGH | CRITICAL

    Returns JSON:
        alerts : alert list
        stats  : summary statistics (total, unread, per-severity)
    """
    limit    = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity', None)
    alerts   = alert_manager.get_alerts(limit=limit, severity=severity)
    return jsonify({"alerts": alerts, "stats": alert_manager.get_stats()})


@app.route('/api/stats')
def api_stats():
    """
    GET /api/stats
    Kembalikan statistik real-time dashboard (uptime, device count, attack counts).

    Returns JSON: hasil dari get_stats_data()

    ---
    GET /api/stats
    Return real-time dashboard statistics (uptime, device count, attack counts).

    Returns JSON: result of get_stats_data()
    """
    return jsonify(get_stats_data())


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Trigger manual network scan"""
    scanner.force_scan()
    return jsonify({"status": "scan_started", "message": "Network scan initiated"})


@app.route('/api/alerts/clear', methods=['POST'])
def api_clear_alerts():
    """
    POST /api/alerts/clear
    Hapus semua alert dari memori dan broadcast ke semua client.

    ---
    POST /api/alerts/clear
    Clear all alerts from memory and broadcast to all clients.
    """
    alert_manager.clear()
    socketio.emit('alerts_cleared')
    return jsonify({"status": "ok"})


@app.route('/api/alerts/read-all', methods=['POST'])
def api_read_all():
    """
    POST /api/alerts/read-all
    Tandai semua alert sebagai sudah dibaca (hapus badge notifikasi).

    ---
    POST /api/alerts/read-all
    Mark all alerts as read (clears notification badge).
    """
    alert_manager.mark_all_read()
    return jsonify({"status": "ok"})


@app.route('/api/mitigate/preview', methods=['POST'])
def api_mitigate_preview():
    """Return preview of commands that will be run for mitigation"""
    data = request.json or {}
    attack_type = data.get("attack_type", "")
    source_ip   = data.get("source_ip", "N/A")
    commands = get_mitigation_preview(attack_type, source_ip)
    return jsonify({"commands": commands, "attack_type": attack_type, "source_ip": source_ip})


@app.route('/api/mitigate/<int:alert_id>', methods=['POST'])
def api_mitigate(alert_id):
    """Run mitigation for a specific alert"""
    alert = alert_manager.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"status": "error", "message": f"Alert {alert_id} not found"}), 404

    if alert.get("mitigated"):
        return jsonify({
            "status": "already_mitigated",
            "message": "This alert has already been mitigated",
            "result": alert.get("mitigation_result")
        })

    result = run_mitigation(alert)
    alert_manager.mark_mitigated(alert_id, result)

    # Notify all clients about mitigation
    socketio.emit('alert_mitigated', {
        "alert_id": alert_id,
        "source_ip": alert.get("source_ip"),
        "result": result
    })

    return jsonify({"status": "ok", "alert_id": alert_id, "result": result})


# ─── ESP8266 Integration ──────────────────────────────────────────────────────

# Simpan status ESP yang terhubung: {esp_id: {last_seen, ip, data}}
esp_devices = {}

@app.route('/api/esp/report', methods=['POST'])
def api_esp_report():
    """
    Terima laporan dari ESP8266.
    ESP mengirim JSON berisi deteksi serangan dan hasil scan.
    """
    data = request.json or {}
    esp_id   = data.get("esp_id", "esp-unknown")
    esp_ip   = request.remote_addr
    now_str  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Update status ESP — simpan esp_ip (IP ESP itu sendiri) dan web port-nya
    esp_devices[esp_id] = {
        "esp_id":        esp_id,
        "ip":            esp_ip,                          # IP request masuk (dari Flask)
        "esp_ip":        data.get("esp_ip", esp_ip),     # IP ESP sendiri (dari payload)
        "esp_web_port":  data.get("esp_web_port", 80),
        "last_seen":     now_str,
        "firmware":      data.get("firmware", "unknown"),
        "uptime":        data.get("uptime", 0),
        "rssi":          data.get("rssi", 0),
        "connected_ssid": data.get("connected_ssid", ""),
    }

    processed = []

    # Proses deauth yang terdeteksi ESP
    for deauth in data.get("deauth_events", []):
        src_mac = deauth.get("src_mac", "unknown")
        count   = deauth.get("count", 0)
        channel = deauth.get("channel", 0)

        alert = alert_manager.add_alert({
            "type":        "DEAUTH_ATTACK",
            "severity":    "HIGH",
            "title":       "🚫 Deauth Attack (ESP8266 Sensor)",
            "message":     (
                f"ESP8266 [{esp_id}] mendeteksi {count} deauth frame dari "
                f"{src_mac} di channel {channel}."
            ),
            "source_mac":  src_mac,
            "source_ip":   "N/A",
            "channel":     channel,
            "frame_count": count,
            "sensor":      esp_id,
            "attack_type": "WiFi Deauth Attack",
        })
        if alert:
            processed.append({"type": "deauth", "alert_id": alert["id"]})

    # Proses ARP anomali yang dilaporkan ESP
    for arp in data.get("arp_events", []):
        ip      = arp.get("ip", "")
        old_mac = arp.get("old_mac", "")
        new_mac = arp.get("new_mac", "")

        if ip and old_mac and new_mac:
            alert = alert_manager.add_alert({
                "type":        "ARP_SPOOFING",
                "severity":    "CRITICAL",
                "title":       "⚠️ ARP Spoofing (ESP8266 Sensor)",
                "message":     (
                    f"ESP8266 [{esp_id}] mendeteksi perubahan MAC untuk IP {ip}: "
                    f"{old_mac} → {new_mac}. Kemungkinan MITM!"
                ),
                "source_ip":   ip,
                "source_mac":  new_mac,
                "old_mac":     old_mac,
                "sensor":      esp_id,
                "attack_type": "ARP Spoofing / MITM",
            })
            if alert:
                processed.append({"type": "arp", "alert_id": alert["id"]})

    # Proses hasil scan WiFi dari ESP (daftar SSID di sekitar)
    wifi_scan = data.get("wifi_scan", [])
    if wifi_scan:
        socketio.emit("esp_wifi_scan", {
            "esp_id":    esp_id,
            "networks":  wifi_scan,
            "timestamp": now_str,
        })

    socketio.emit("esp_status_update", {
        "devices": list(esp_devices.values())
    })

    return jsonify({
        "status":    "ok",
        "esp_id":    esp_id,
        "processed": len(processed),
        "alerts":    processed,
        "timestamp": now_str,
    })


@app.route('/api/esp/status', methods=['GET'])
def api_esp_status():
    """Kembalikan daftar ESP8266 yang pernah terhubung"""
    return jsonify({
        "devices": list(esp_devices.values()),
        "count":   len(esp_devices),
    })


@app.route('/api/esp/<esp_id>/scan', methods=['GET'])
def api_esp_scan(esp_id):
    """
    GET /api/esp/<esp_id>/scan
    Perintahkan ESP untuk scan WiFi di sekitarnya.
    Flask bertindak sebagai proxy — forward request ke web server di ESP.

    Returns JSON: daftar SSID yang ditemukan ESP
    """
    import requests as req_lib
    esp = esp_devices.get(esp_id)
    if not esp:
        return jsonify({"error": f"ESP '{esp_id}' tidak ditemukan atau belum terhubung"}), 404

    esp_ip   = esp.get("esp_ip") or esp.get("ip")
    esp_port = esp.get("esp_web_port", 80)

    try:
        r = req_lib.get(f"http://{esp_ip}:{esp_port}/scan", timeout=35)
        data = r.json()
        # Broadcast hasil scan ke semua client dashboard via WebSocket
        socketio.emit("esp_wifi_scan", {
            "esp_id":   esp_id,
            "networks": data.get("networks", []),
        })
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e), "esp_ip": esp_ip}), 502


@app.route('/api/esp/<esp_id>/connect', methods=['POST'])
def api_esp_connect(esp_id):
    """
    POST /api/esp/<esp_id>/connect
    Perintahkan ESP untuk konek ke WiFi tertentu.
    Body JSON: {"ssid": "NamaWiFi", "password": "password"}

    Flask forward request ke web server di ESP, lalu broadcast status ke dashboard.
    """
    import requests as req_lib
    esp = esp_devices.get(esp_id)
    if not esp:
        return jsonify({"error": f"ESP '{esp_id}' tidak ditemukan"}), 404

    data     = request.json or {}
    ssid     = data.get("ssid", "")
    password = data.get("password", "")

    if not ssid:
        return jsonify({"error": "ssid wajib diisi"}), 400

    esp_ip   = esp.get("esp_ip") or esp.get("ip")
    esp_port = esp.get("esp_web_port", 80)

    try:
        r = req_lib.post(
            f"http://{esp_ip}:{esp_port}/connect",
            data={"ssid": ssid, "password": password},
            timeout=10
        )
        result = r.json()
        # Broadcast status connecting ke semua client
        socketio.emit("esp_connecting", {
            "esp_id":  esp_id,
            "ssid":    ssid,
            "status":  "connecting",
        })
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route('/api/esp/<esp_id>/status', methods=['GET'])
def api_esp_device_status(esp_id):
    """
    GET /api/esp/<esp_id>/status
    Ambil status real-time ESP langsung dari web server-nya.
    """
    import requests as req_lib
    esp = esp_devices.get(esp_id)
    if not esp:
        return jsonify({"error": f"ESP '{esp_id}' tidak ditemukan"}), 404

    esp_ip   = esp.get("esp_ip") or esp.get("ip")
    esp_port = esp.get("esp_web_port", 80)

    try:
        r = req_lib.get(f"http://{esp_ip}:{esp_port}/status", timeout=5)
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e), "cached": esp}), 200


@app.route('/api/restore/<ip>', methods=['POST'])
def api_restore_internet(ip):
    """Restore internet access for a blocked IP (remove iptables rules)"""
    import subprocess, shutil

    steps = []
    is_root = False
    try:
        import os
        is_root = (os.geteuid() == 0)
    except Exception:
        pass

    def _run(cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return result.returncode == 0, (result.stdout + result.stderr).strip()
        except Exception as e:
            return False, str(e)

    if not is_root:
        return jsonify({
            "status": "error",
            "message": "Butuh root/sudo untuk restore internet. Jalankan: sudo python3 app.py"
        }), 403

    # Remove INPUT DROP rule for this IP
    ok1, out1 = _run(f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null || true")
    steps.append({"action": f"Remove INPUT block for {ip}", "success": True, "output": out1 or "Done"})

    # Remove OUTPUT DROP rule for this IP
    ok2, out2 = _run(f"iptables -D OUTPUT -d {ip} -j DROP 2>/dev/null || true")
    steps.append({"action": f"Remove OUTPUT block for {ip}", "success": True, "output": out2 or "Done"})

    # Remove rate-limit rule if any
    _run(f"iptables -D INPUT -s {ip} -p tcp --syn -m limit --limit 1/s -j ACCEPT 2>/dev/null || true")

    # Flush ARP cache so device can re-connect
    _run("ip neigh flush all 2>/dev/null || true")
    steps.append({"action": "Flush ARP cache", "success": True, "output": "ARP cache flushed"})

    # Notify all clients
    socketio.emit('device_restored', {"ip": ip})

    return jsonify({
        "status": "ok",
        "ip": ip,
        "steps": steps,
        "message": f"Internet access restored for {ip}"
    })


@app.route('/api/arp-spoof', methods=['POST'])
def api_arp_spoof():
    """Simulate ARP spoofing attack targeting a specific IP"""
    data = request.json or {}
    target_ip  = data.get('target_ip', '')
    attacker_ip = data.get('attacker_ip', '')
    target_mac = data.get('target_mac', 'N/A')

    if not target_ip:
        return jsonify({"status": "error", "message": "target_ip required"}), 400

    # Generate fake attacker IP if not provided
    if not attacker_ip:
        import random
        base = '.'.join(target_ip.split('.')[:3])
        attacker_ip = f"{base}.{random.randint(2, 254)}"

    # Generate fake MACs
    import random
    def rand_mac():
        return ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))

    old_mac = target_mac if target_mac and target_mac != 'N/A' else rand_mac()
    new_mac = rand_mac()

    alert = alert_manager.add_alert({
        "type": "ARP_SPOOFING",
        "severity": "CRITICAL",
        "title": "⚠️ ARP Spoofing Detected!",
        "message": (
            f"IP {target_ip} changed MAC from {old_mac} to {new_mac}. "
            f"Attacker: {attacker_ip} — Possible Man-in-the-Middle attack!"
        ),
        "source_ip": target_ip,
        "source_mac": new_mac,
        "old_mac": old_mac,
        "attacker_ip": attacker_ip,
        "attack_type": "ARP Spoofing / MITM"
    })

    return jsonify({
        "status": "ok",
        "target_ip": target_ip,
        "attacker_ip": attacker_ip,
        "old_mac": old_mac,
        "new_mac": new_mac,
        "alert_id": alert["id"] if alert else None
    })


@app.route('/api/simulate/<attack_type>', methods=['POST'])
def api_simulate(attack_type):
    """Simulate attacks for demo/testing"""
    src_ip = request.json.get('src_ip', '192.168.1.100') if request.json else '192.168.1.100'

    simulations = {
        "arp": lambda: alert_manager.add_alert({
            "type": "ARP_SPOOFING", "severity": "CRITICAL",
            "title": "⚠️ ARP Spoofing Detected!",
            "message": f"IP {src_ip} changed MAC from aa:bb:cc:11:22:33 to ff:ee:dd:cc:bb:aa. MITM attack!",
            "source_ip": src_ip, "attack_type": "ARP Spoofing / MITM"
        }),
        "deauth": lambda: deauth_monitor.simulate_attack(src_ip),
        "dns": lambda: alert_manager.add_alert({
            "type": "DNS_SPOOFING", "severity": "HIGH",
            "title": "🔴 DNS Spoofing Detected!",
            "message": f"google.com resolved to 10.0.0.1 by {src_ip} but trusted DNS says 142.250.80.46",
            "source_ip": src_ip, "attack_type": "DNS Cache Poisoning"
        }),
        "dhcp": lambda: alert_manager.add_alert({
            "type": "DHCP_STARVATION", "severity": "HIGH",
            "title": "💥 DHCP Starvation Attack!",
            "message": f"Device {src_ip} sent 50 DHCP requests in 30s. IP pool exhaustion!",
            "source_ip": src_ip, "attack_type": "DHCP Starvation"
        }),
        "portscan": lambda: alert_manager.add_alert({
            "type": "PORT_SCAN", "severity": "MEDIUM",
            "title": "🔍 Port Scan Detected!",
            "message": f"Device {src_ip} scanned 45 ports on 192.168.1.1 in 10s. Reconnaissance!",
            "source_ip": src_ip, "attack_type": "TCP SYN Scan"
        }),
        "synflood": lambda: alert_manager.add_alert({
            "type": "SYN_FLOOD", "severity": "HIGH",
            "title": "💥 SYN Flood Attack!",
            "message": f"Device {src_ip} sent 500 SYN packets in 10s. DoS attack!",
            "source_ip": src_ip, "attack_type": "SYN Flood / DoS"
        }),
    }

    if attack_type in simulations:
        simulations[attack_type]()
        return jsonify({"status": "ok", "simulated": attack_type})

    return jsonify({"status": "error", "message": "Unknown attack type"}), 400


# ─── SocketIO Events ──────────────────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    """
    Event: client WebSocket baru terhubung.
    Kirim data awal (devices, alerts, stats) agar dashboard langsung terisi.

    ---
    Event: new WebSocket client connected.
    Send initial data (devices, alerts, stats) so dashboard loads immediately.
    """
    print(f"[WS] Client connected: {request.sid}")
    emit('initial_data', {
        "devices":   scanner.get_devices(),
        "alerts":    alert_manager.get_alerts(limit=20),
        "stats":     get_stats_data(),
        "demo_mode": demo_mode
    })


@socketio.on('disconnect')
def on_disconnect():
    """
    Event: client WebSocket terputus.
    Hanya log, tidak ada aksi khusus.

    ---
    Event: WebSocket client disconnected.
    Log only, no special action needed.
    """
    print(f"[WS] Client disconnected: {request.sid}")


@socketio.on('request_scan')
def on_request_scan():
    """
    Event: client meminta scan jaringan manual.
    Jalankan force_scan() di background dan beri tahu client bahwa scan dimulai.

    ---
    Event: client requests a manual network scan.
    Runs force_scan() in background and notifies client that scan started.
    """
    scanner.force_scan()
    emit('scan_started', {"message": "Scanning network..."})


@socketio.on('request_stats')
def on_request_stats():
    """
    Event: client meminta update statistik terbaru.
    Kirim balik stats_update ke client yang meminta saja (bukan broadcast).

    ---
    Event: client requests latest statistics update.
    Sends stats_update back to requesting client only (not broadcast).
    """
    emit('stats_update', get_stats_data())


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 9002))
    host = os.environ.get("HOST", "0.0.0.0")

    print("""
╔══════════════════════════════════════════════════════╗
║         WiFi Cyber Attack Monitor v1.0               ║
║         Real-time Network Security Dashboard         ║
╚══════════════════════════════════════════════════════╝
    """)

    if demo_mode:
        print("[App] 🎮 DEMO MODE - Loading sample alerts...")
        alert_manager.add_demo_alerts()
    else:
        print("[App] 🔍 Starting network monitors (requires root/sudo)...")
        monitor_thread = threading.Thread(target=start_monitors, daemon=True)
        monitor_thread.start()

    # Start auto-scan broadcast thread (always active)
    auto_scan_thread = threading.Thread(target=auto_scan_loop, daemon=True)
    auto_scan_thread.start()
    print("[App] 🔄 Auto-scan broadcast started (every 5s)")

    print(f"[App] 🌐 Dashboard: http://{host}:{port}")
    print(f"[App] 📱 Mobile: http://<your-ip>:{port}")
    print("[App] Press Ctrl+C to stop\n")

    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
