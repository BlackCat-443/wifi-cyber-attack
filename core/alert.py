"""
Alert Manager — core/alert.py
==============================
Sistem manajemen alert terpusat untuk WiFi Monitor.

Fitur utama:
- Deduplication: alert yang sama tidak muncul berulang dalam waktu cooldown
- Severity levels: LOW, MEDIUM, HIGH, CRITICAL dengan warna berbeda
- Thread-safe: semua operasi pakai lock agar aman diakses dari banyak thread
- Callback: kirim alert ke WebSocket secara real-time via on_alert hook

Cara pakai:
    manager = AlertManager()
    manager.on_alert = lambda alert: socketio.emit('new_alert', alert)
    manager.add_alert({"type": "ARP_SPOOFING", "severity": "CRITICAL", ...})

---
Alert Manager — core/alert.py
==============================
Centralized alert management system for WiFi Monitor.

Features:
- Deduplication: same alert won't fire again within cooldown window
- Severity levels: LOW, MEDIUM, HIGH, CRITICAL with distinct colors
- Thread-safe: all operations use locks for multi-thread safety
- Callback: push alerts to WebSocket in real-time via on_alert hook
"""

import threading
import time
from datetime import datetime
from collections import deque


# Warna hex untuk setiap level severity — dipakai di frontend dashboard
# Hex color for each severity level — used in the frontend dashboard
SEVERITY_COLORS = {
    "LOW":      "#3b82f6",   # biru / blue
    "MEDIUM":   "#f59e0b",   # kuning / yellow
    "HIGH":     "#ef4444",   # merah / red
    "CRITICAL": "#7c3aed",   # ungu / purple
}

# Urutan numerik severity untuk sorting / perbandingan
# Numeric severity order for sorting / comparison
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Cooldown dalam detik per pasangan (tipe_alert, source_ip).
# Alert yang sama dari IP yang sama tidak akan muncul lagi sebelum cooldown habis.
# Cooldown in seconds per (alert_type, source_ip) pair.
# Same alert from same IP won't fire again until cooldown expires.
ALERT_COOLDOWN = {
    "ARP_SPOOFING":          60,
    "GRATUITOUS_ARP":        120,
    "DEAUTH_ATTACK":         30,
    "DNS_SPOOFING":          60,
    "DHCP_STARVATION":       45,
    "ROGUE_DHCP":            120,
    "PORT_SCAN":             20,
    "SYN_FLOOD":             15,
    "ICMP_SWEEP":            30,
    "DANGEROUS_PORT_ACCESS": 60,
    "DEFAULT":               30,
}


class AlertManager:
    """
    Manajemen alert terpusat dengan deduplication, severity tracking, dan callback real-time.

    Attributes:
        alerts      : deque berisi semua alert (max 500, terbaru di depan)
        on_alert    : callback function dipanggil setiap ada alert baru
        total_count : total alert yang pernah dibuat sejak server start
        severity_counts : dict hitungan per severity {LOW, MEDIUM, HIGH, CRITICAL}

    ---
    Centralized alert manager with deduplication, severity tracking, and real-time callback.

    Attributes:
        alerts      : deque of all alerts (max 500, newest first)
        on_alert    : callback function called on every new alert
        total_count : total alerts created since server start
        severity_counts : per-severity count dict {LOW, MEDIUM, HIGH, CRITICAL}
    """

    def __init__(self, max_alerts=500):
        """
        Inisialisasi AlertManager.

        Args:
            max_alerts: jumlah maksimum alert yang disimpan di memori (default 500).
                        Alert lama otomatis dihapus kalau sudah penuh.
        ---
        Initialize AlertManager.

        Args:
            max_alerts: max number of alerts kept in memory (default 500).
                        Oldest alerts are auto-removed when full.
        """
        self.alerts = deque(maxlen=max_alerts)
        self._lock = threading.Lock()
        self.on_alert = None
        self.total_count = 0
        self.severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        # Dedup tracker: {(alert_type, source_ip): unix_timestamp_terakhir}
        # Dedup tracker: {(alert_type, source_ip): last_unix_timestamp}
        self._last_seen = {}

    def _is_duplicate(self, alert_type, source_ip):
        """
        Cek apakah alert ini sudah pernah dikirim dalam window cooldown.

        Args:
            alert_type : tipe alert, misal "ARP_SPOOFING"
            source_ip  : IP sumber serangan

        Returns:
            True  → alert duplikat, jangan kirim lagi
            False → alert baru, boleh dikirim

        ---
        Check if this alert was already fired within the cooldown window.

        Args:
            alert_type : alert type, e.g. "ARP_SPOOFING"
            source_ip  : attacker source IP

        Returns:
            True  → duplicate alert, skip it
            False → new alert, allow it
        """
        key = (alert_type, source_ip or "N/A")
        cooldown = ALERT_COOLDOWN.get(alert_type, ALERT_COOLDOWN["DEFAULT"])
        now = time.time()
        last = self._last_seen.get(key, 0)
        if now - last < cooldown:
            return True
        self._last_seen[key] = now
        return False

    def add_alert(self, alert_data):
        """
        Tambahkan alert baru ke sistem. Otomatis skip kalau duplikat.

        Alert yang berhasil ditambahkan akan:
        1. Disimpan di self.alerts (thread-safe)
        2. Menambah counter severity
        3. Memanggil self.on_alert(alert) untuk push ke WebSocket

        Args:
            alert_data: dict berisi data alert. Field yang dikenali:
                - type        : tipe serangan, misal "ARP_SPOOFING" (wajib)
                - severity    : "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
                - title       : judul singkat alert
                - message     : deskripsi detail
                - source_ip   : IP penyerang
                - source_mac  : MAC penyerang
                - attack_type : nama serangan untuk tampilan UI
                - timestamp   : waktu kejadian (auto-generate kalau tidak ada)
                - (field lain akan disertakan apa adanya)

        Returns:
            dict alert yang dibuat, atau None kalau duplikat.

        ---
        Add a new alert to the system. Automatically skips duplicates.

        Successfully added alerts will:
        1. Be stored in self.alerts (thread-safe)
        2. Increment severity counter
        3. Call self.on_alert(alert) to push to WebSocket

        Args:
            alert_data: dict with alert data. Recognized fields:
                - type        : attack type, e.g. "ARP_SPOOFING" (required)
                - severity    : "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
                - title       : short alert title
                - message     : detailed description
                - source_ip   : attacker IP
                - source_mac  : attacker MAC
                - attack_type : attack name for UI display
                - timestamp   : event time (auto-generated if missing)
                - (other fields are passed through as-is)

        Returns:
            The created alert dict, or None if duplicate.
        """
        alert_type = alert_data.get("type", "UNKNOWN")
        source_ip  = alert_data.get("source_ip", "N/A")

        if self._is_duplicate(alert_type, source_ip):
            return None

        alert = {
            "id":               self.total_count + 1,
            "type":             alert_type,
            "severity":         alert_data.get("severity", "LOW"),
            "title":            alert_data.get("title", "Alert"),
            "message":          alert_data.get("message", ""),
            "timestamp":        alert_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "attack_type":      alert_data.get("attack_type", "Unknown"),
            "source_ip":        source_ip,
            "source_mac":       alert_data.get("source_mac", "N/A"),
            "color":            SEVERITY_COLORS.get(alert_data.get("severity", "LOW"), "#3b82f6"),
            "read":             False,
            "mitigated":        False,
            "mitigation_result": None,
            # Sertakan field tambahan dari alert_data yang tidak ada di atas
            # Include extra fields from alert_data not listed above
            **{k: v for k, v in alert_data.items()
               if k not in ["type", "severity", "title", "message", "timestamp",
                            "attack_type", "source_ip", "source_mac"]}
        }

        with self._lock:
            self.alerts.appendleft(alert)
            self.total_count += 1
            sev = alert["severity"]
            if sev in self.severity_counts:
                self.severity_counts[sev] += 1

        print(f"[Alert] [{alert['severity']}] {alert['title']} | {source_ip}")

        if self.on_alert:
            self.on_alert(alert)

        return alert

    def get_alert_by_id(self, alert_id):
        """
        Cari alert berdasarkan ID uniknya.

        Args:
            alert_id: integer ID alert

        Returns:
            dict alert kalau ditemukan, None kalau tidak ada.

        ---
        Find an alert by its unique ID.

        Args:
            alert_id: integer alert ID

        Returns:
            Alert dict if found, None otherwise.
        """
        with self._lock:
            for a in self.alerts:
                if a["id"] == alert_id:
                    return a
        return None

    def mark_mitigated(self, alert_id, result):
        """
        Tandai alert sebagai sudah dimitigasi dan simpan hasilnya.

        Args:
            alert_id : ID alert yang dimitigasi
            result   : dict hasil mitigasi dari mitigator.py

        Returns:
            True kalau berhasil, False kalau alert tidak ditemukan.

        ---
        Mark an alert as mitigated and store the result.

        Args:
            alert_id : ID of the mitigated alert
            result   : mitigation result dict from mitigator.py

        Returns:
            True if successful, False if alert not found.
        """
        with self._lock:
            for a in self.alerts:
                if a["id"] == alert_id:
                    a["mitigated"] = True
                    a["mitigation_result"] = result
                    return True
        return False

    def get_alerts(self, limit=50, severity=None):
        """
        Ambil daftar alert, opsional filter berdasarkan severity.

        Args:
            limit    : jumlah maksimum alert yang dikembalikan (default 50)
            severity : filter severity, misal "HIGH". None = semua severity.

        Returns:
            List dict alert, diurutkan dari terbaru ke terlama.

        ---
        Get list of alerts, optionally filtered by severity.

        Args:
            limit    : max number of alerts to return (default 50)
            severity : severity filter, e.g. "HIGH". None = all severities.

        Returns:
            List of alert dicts, newest first.
        """
        with self._lock:
            alerts = list(self.alerts)
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]
        return alerts[:limit]

    def get_stats(self):
        """
        Ambil statistik ringkasan semua alert.

        Returns:
            dict berisi:
                - total          : total alert sejak server start
                - severity_counts: hitungan per severity
                - recent_count   : jumlah alert di memori saat ini
                - unread         : jumlah alert yang belum dibaca

        ---
        Get summary statistics of all alerts.

        Returns:
            dict containing:
                - total          : total alerts since server start
                - severity_counts: count per severity level
                - recent_count   : number of alerts currently in memory
                - unread         : number of unread alerts
        """
        with self._lock:
            return {
                "total":          self.total_count,
                "severity_counts": dict(self.severity_counts),
                "recent_count":   len(self.alerts),
                "unread":         sum(1 for a in self.alerts if not a["read"])
            }

    def mark_read(self, alert_id):
        """
        Tandai satu alert sebagai sudah dibaca.

        Args:
            alert_id: ID alert yang mau ditandai.

        ---
        Mark a single alert as read.

        Args:
            alert_id: ID of the alert to mark.
        """
        with self._lock:
            for alert in self.alerts:
                if alert["id"] == alert_id:
                    alert["read"] = True
                    break

    def mark_all_read(self):
        """
        Tandai semua alert sebagai sudah dibaca sekaligus.
        Dipanggil saat user membuka tab Alerts di dashboard.

        ---
        Mark all alerts as read at once.
        Called when user opens the Alerts tab in the dashboard.
        """
        with self._lock:
            for alert in self.alerts:
                alert["read"] = True

    def clear(self):
        """
        Hapus semua alert dari memori dan reset semua counter.
        Operasi ini tidak bisa di-undo.

        ---
        Clear all alerts from memory and reset all counters.
        This operation cannot be undone.
        """
        with self._lock:
            self.alerts.clear()
            self.severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            self._last_seen.clear()

    def add_demo_alerts(self):
        """
        Tambahkan alert contoh untuk testing tampilan UI.
        Hanya dipakai saat DEMO_MODE=1, tidak untuk produksi.

        Alert yang ditambahkan mencakup semua tipe serangan yang didukung
        agar semua komponen UI bisa ditest sekaligus.

        ---
        Add sample alerts for UI testing purposes.
        Only used when DEMO_MODE=1, not for production.

        Added alerts cover all supported attack types so all
        UI components can be tested at once.
        """
        demos = [
            {
                "type": "ARP_SPOOFING",
                "severity": "CRITICAL",
                "title": "⚠️ ARP Spoofing Detected!",
                "message": "IP 192.168.1.5 changed MAC from aa:bb:cc:dd:ee:ff to 11:22:33:44:55:66. Possible MITM attack!",
                "source_ip": "192.168.1.5",
                "attack_type": "ARP Spoofing / MITM",
                "old_mac": "aa:bb:cc:dd:ee:ff",
                "source_mac": "11:22:33:44:55:66"
            },
            {
                "type": "DEAUTH_ATTACK",
                "severity": "HIGH",
                "title": "🚫 WiFi Deauth Attack!",
                "message": "Device 192.168.1.10 sending deauth frames. Multiple devices disconnected!",
                "source_ip": "192.168.1.10",
                "attack_type": "WiFi Deauth Attack",
                "source_mac": "de:ad:be:ef:00:10"
            },
            {
                "type": "PORT_SCAN",
                "severity": "MEDIUM",
                "title": "🔍 Port Scan Detected",
                "message": "Device 192.168.1.15 scanned 45 ports on 192.168.1.1 in 10s.",
                "source_ip": "192.168.1.15",
                "attack_type": "TCP SYN Scan"
            },
            {
                "type": "DNS_SPOOFING",
                "severity": "HIGH",
                "title": "🔴 DNS Spoofing Detected!",
                "message": "google.com resolved to 10.0.0.1 but trusted DNS says 142.250.80.46",
                "source_ip": "192.168.1.1",
                "attack_type": "DNS Cache Poisoning"
            },
            {
                "type": "DHCP_STARVATION",
                "severity": "HIGH",
                "title": "💥 DHCP Starvation Attack!",
                "message": "MAC de:ad:be:ef:00:01 sent 50 DHCP requests in 30s. IP pool exhaustion!",
                "source_ip": "192.168.1.20",
                "attack_type": "DHCP Starvation",
                "source_mac": "de:ad:be:ef:00:01"
            }
        ]
        for demo in demos:
            self.add_alert(demo)
            time.sleep(0.05)
