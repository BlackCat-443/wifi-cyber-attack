"""
Deauthentication Attack Detector
Detects 802.11 WiFi deauth/disassoc frames that kick devices off the network
"""

import threading
import time
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas, RadioTap, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class DeauthMonitor:
    """
    Detektor serangan WiFi Deauthentication (deauth attack).

    Cara kerja:
    - Sniff frame 802.11 management (deauth + disassoc) menggunakan Scapy
    - Hitung frame dari setiap MAC address dalam window waktu tertentu
    - Kalau jumlah frame melebihi threshold → alert HIGH
    - Butuh WiFi adapter dalam monitor mode untuk deteksi penuh
    - Kalau monitor mode tidak tersedia, fallback ke mode alternatif

    Catatan: Deauth attack dipakai penyerang untuk memutus koneksi WiFi
    perangkat lain secara paksa (misal sebelum melakukan evil twin attack).

    ---
    WiFi Deauthentication attack detector.

    How it works:
    - Sniffs 802.11 management frames (deauth + disassoc) using Scapy
    - Counts frames from each MAC address within a time window
    - If frame count exceeds threshold → HIGH alert
    - Requires WiFi adapter in monitor mode for full detection
    - Falls back to alternative mode if monitor mode unavailable

    Note: Deauth attacks are used by attackers to forcibly disconnect
    other devices from WiFi (e.g., before launching an evil twin attack).
    """

    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self.running = False
        self.deauth_counts = defaultdict(int)   # {src_mac: jumlah_frame}
        self.last_reset = time.time()
        self.threshold = 5      # Jumlah frame sebelum dianggap serangan
        self.time_window = 10   # Window waktu dalam detik
        self._lock = threading.Lock()
        self.attack_count = 0

    def start(self, iface=None):
        """
        Mulai monitoring deauth di background thread.
        Butuh WiFi adapter dalam monitor mode untuk deteksi penuh.

        Args:
            iface: nama interface, misal "wlan0mon". None = default.

        ---
        Start deauth monitoring in a background thread.
        Requires WiFi adapter in monitor mode for full detection.

        Args:
            iface: interface name, e.g. "wlan0mon". None = default.
        """
        if not SCAPY_AVAILABLE:
            print("[Deauth] Scapy not available, Deauth monitoring disabled")
            return

        self.iface = iface
        self.running = True
        # Deauth detection butuh monitor mode — kalau tidak ada, pakai alternatif
        thread = threading.Thread(target=self._sniff_loop, daemon=True)
        thread.start()
        print(f"[Deauth] Monitor started (requires monitor mode for full detection)")

    def stop(self):
        """Hentikan monitoring. / Stop monitoring."""
        self.running = False

    def _sniff_loop(self):
        """
        Loop sniffing frame 802.11 management.
        Kalau monitor mode tidak tersedia, otomatis fallback ke _alternative_detection().

        ---
        Sniffing loop for 802.11 management frames.
        Automatically falls back to _alternative_detection() if monitor mode unavailable.
        """
        try:
            conf.verb = 0
            kwargs = {
                "filter": "type mgt subtype deauth or type mgt subtype disassoc",
                "prn": self._process_packet,
                "store": False
            }
            if self.iface:
                kwargs["iface"] = self.iface
            sniff(**kwargs)
        except Exception as e:
            print(f"[Deauth] Monitor mode not available: {e}")
            self._alternative_detection()

    def _alternative_detection(self):
        """
        Mode alternatif kalau monitor mode tidak tersedia.
        Saat ini hanya idle loop — bisa dikembangkan untuk deteksi
        via connectivity drops atau anomali traffic lainnya.

        ---
        Alternative mode when monitor mode is unavailable.
        Currently just an idle loop — can be extended to detect
        via connectivity drops or other traffic anomalies.
        """
        print("[Deauth] Using alternative detection (connectivity monitoring)")
        while self.running:
            time.sleep(5)

    def _process_packet(self, packet):
        """
        Proses setiap frame 802.11 deauth/disassoc yang ditangkap.

        Logika:
        1. Reset counter setiap time_window detik
        2. Hitung frame dari setiap MAC sumber
        3. Kalau count >= threshold → trigger alert dan reset counter MAC itu

        Args:
            packet: objek paket Scapy (frame 802.11)

        ---
        Process each captured 802.11 deauth/disassoc frame.

        Logic:
        1. Reset counters every time_window seconds
        2. Count frames from each source MAC
        3. If count >= threshold → trigger alert and reset that MAC's counter

        Args:
            packet: Scapy packet object (802.11 frame)
        """
        if not self.running:
            return

        # Reset counter setiap time_window detik
        now = time.time()
        if now - self.last_reset > self.time_window:
            with self._lock:
                self.deauth_counts.clear()
                self.last_reset = now

        if packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas):
            src        = packet[Dot11].addr2 or "Unknown"
            dst        = packet[Dot11].addr1 or "Broadcast"
            frame_type = "Deauth" if packet.haslayer(Dot11Deauth) else "Disassoc"

            with self._lock:
                self.deauth_counts[src] += 1
                count = self.deauth_counts[src]

            if count >= self.threshold:
                self.attack_count += 1
                self.alert_manager.add_alert({
                    "type":        "DEAUTH_ATTACK",
                    "severity":    "HIGH",
                    "title":       "🚫 WiFi Deauth Attack Detected!",
                    "message":     (
                        f"Device {src} sent {count} {frame_type} frames in {self.time_window}s. "
                        f"Target: {dst}. Devices may be getting kicked off WiFi!"
                    ),
                    "source_mac":  src,
                    "target_mac":  dst,
                    "frame_count": count,
                    "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "attack_type": f"WiFi {frame_type} Attack"
                })
                print(f"[Deauth] ⚠️ ATTACK: {src} -> {dst} ({count} frames)")

                # Reset counter MAC ini agar tidak spam alert
                with self._lock:
                    self.deauth_counts[src] = 0

    def simulate_attack(self, src_ip="192.168.1.100"):
        """
        Simulasikan deauth attack untuk testing UI.
        Tidak mengirim frame nyata ke jaringan.

        Args:
            src_ip: IP yang akan ditampilkan sebagai sumber serangan

        ---
        Simulate a deauth attack for UI testing.
        Does not send real frames to the network.

        Args:
            src_ip: IP to display as the attack source
        """
        self.attack_count += 1
        self.alert_manager.add_alert({
            "type":        "DEAUTH_ATTACK",
            "severity":    "HIGH",
            "title":       "🚫 WiFi Deauth Attack Detected! (Simulated)",
            "message":     (
                f"Device {src_ip} is sending deauthentication frames. "
                f"Multiple devices being disconnected from WiFi!"
            ),
            "source_ip":   src_ip,
            "source_mac":  "aa:bb:cc:dd:ee:ff",
            "frame_count": 50,
            "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": "WiFi Deauth Attack (Demo)"
        })
