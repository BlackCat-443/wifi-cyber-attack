"""
ARP Spoofing / Poisoning Detector
Monitors ARP traffic and detects MAC address changes (ARP spoofing)
"""

import threading
import time
from datetime import datetime

try:
    from scapy.all import sniff, ARP, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


class ARPMonitor:
    """
    Monitor ARP spoofing / Man-in-the-Middle attack secara real-time.

    Cara kerja:
    - Sniff semua paket ARP di jaringan menggunakan Scapy
    - Simpan tabel IP→MAC yang dianggap "benar" (di-seed dari scan awal)
    - Kalau ada ARP Reply yang mengubah MAC untuk IP yang sudah dikenal → alert CRITICAL
    - Kalau ada Gratuitous ARP (broadcast ke 0.0.0.0) → alert MEDIUM

    Butuh: root/sudo + Scapy terinstall

    ---
    Real-time ARP spoofing / Man-in-the-Middle attack monitor.

    How it works:
    - Sniffs all ARP packets on the network using Scapy
    - Maintains a trusted IP→MAC table (seeded from initial scan)
    - If an ARP Reply changes MAC for a known IP → CRITICAL alert
    - If a Gratuitous ARP is seen (broadcast to 0.0.0.0) → MEDIUM alert

    Requires: root/sudo + Scapy installed
    """

    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self.arp_table = {}       # {ip: mac} — tabel MAC yang dianggap benar / trusted MAC table
        self.running = False
        self._lock = threading.Lock()
        self.attack_count = 0     # Jumlah serangan yang terdeteksi sejak start

    def start(self, iface=None):
        """
        Mulai sniffing ARP di background thread.

        Args:
            iface: nama interface jaringan, misal "wlan0". None = default interface.

        ---
        Start ARP sniffing in a background thread.

        Args:
            iface: network interface name, e.g. "wlan0". None = default interface.
        """
        if not SCAPY_AVAILABLE:
            print("[ARP] Scapy not available, ARP monitoring disabled")
            return
        self.iface = iface
        self.running = True
        thread = threading.Thread(target=self._sniff_loop, daemon=True)
        thread.start()
        print(f"[ARP] Monitor started on {iface or 'default'}")

    def stop(self):
        """Hentikan sniffing. / Stop sniffing."""
        self.running = False

    def _sniff_loop(self):
        """
        Loop sniffing yang berjalan di background thread.
        Filter hanya paket ARP untuk efisiensi.

        ---
        Sniffing loop running in background thread.
        Filters only ARP packets for efficiency.
        """
        try:
            conf.verb = 0
            kwargs = {"filter": "arp", "prn": self._process_packet, "store": False}
            if self.iface:
                kwargs["iface"] = self.iface
            sniff(**kwargs)
        except Exception as e:
            print(f"[ARP] Sniff error: {e}")

    def _process_packet(self, packet):
        """
        Proses setiap paket ARP yang ditangkap.

        Logika deteksi:
        1. ARP Reply (op=2): cek apakah MAC untuk IP ini berubah dari yang dikenal
           - Berubah → kemungkinan ARP spoofing → alert CRITICAL
           - Belum dikenal → tambahkan ke tabel sebagai entri baru
        2. Gratuitous ARP (reply ke 0.0.0.0): mencurigakan → alert MEDIUM

        Args:
            packet: objek paket Scapy yang ditangkap dari jaringan

        ---
        Process each captured ARP packet.

        Detection logic:
        1. ARP Reply (op=2): check if MAC for this IP changed from known value
           - Changed → possible ARP spoofing → CRITICAL alert
           - Unknown → add to table as new entry
        2. Gratuitous ARP (reply to 0.0.0.0): suspicious → MEDIUM alert

        Args:
            packet: Scapy packet object captured from the network
        """
        if not self.running:
            return

        if packet.haslayer(ARP):
            arp = packet[ARP]

            # Gratuitous ARP harus diperiksa lebih dulu karena juga merupakan
            # ARP reply (op=2). Pada paket gratuitous, sender IP == target IP
            # atau target IP dapat berupa 0.0.0.0/broadcast bergantung implementasi.
            is_gratuitous = (
                arp.op == 2
                and (
                    arp.psrc == arp.pdst
                    or arp.pdst == "0.0.0.0"
                    or arp.hwdst in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}
                )
            )

            if is_gratuitous:
                self.alert_manager.add_alert({
                    "type":        "GRATUITOUS_ARP",
                    "severity":    "MEDIUM",
                    "title":       "⚠️ Gratuitous ARP Detected",
                    "message":     f"Suspicious gratuitous ARP from {arp.psrc} ({arp.hwsrc})",
                    "source_ip":   arp.psrc,
                    "source_mac":  arp.hwsrc,
                    "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "attack_type": "Gratuitous ARP"
                })
                # Gratuitous ARP yang valid tidak otomatis berarti spoofing.
                # Tetap simpan mapping-nya agar tabel trusted tetap up to date.
                with self._lock:
                    if arp.psrc and arp.hwsrc:
                        self.arp_table.setdefault(arp.psrc, arp.hwsrc)

            # ARP Reply (op=2) — perangkat mengumumkan MAC-nya
            elif arp.op == 2:
                ip = arp.psrc
                mac = arp.hwsrc

                with self._lock:
                    if ip in self.arp_table:
                        known_mac = self.arp_table[ip]
                        if known_mac != mac:
                            # MAC berubah = kemungkinan ARP spoofing!
                            self.attack_count += 1
                            self.alert_manager.add_alert({
                                "type":        "ARP_SPOOFING",
                                "severity":    "CRITICAL",
                                "title":       "⚠️ ARP Spoofing Detected!",
                                "message":     (
                                    f"IP {ip} changed MAC from {known_mac} to {mac}. "
                                    f"Possible Man-in-the-Middle attack!"
                                ),
                                "source_ip":   ip,
                                "source_mac":  mac,
                                "old_mac":     known_mac,
                                "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "attack_type": "ARP Spoofing / MITM"
                            })
                            print(f"[ARP] ⚠️ SPOOFING: {ip} | {known_mac} -> {mac}")
                    else:
                        # Pertama kali lihat IP ini, simpan sebagai entri terpercaya
                        self.arp_table[ip] = mac

    def get_arp_table(self):
        """
        Ambil salinan tabel ARP yang dipercaya saat ini (thread-safe).

        Returns:
            dict {ip: mac} — snapshot tabel ARP saat ini

        ---
        Get a thread-safe copy of the current trusted ARP table.

        Returns:
            dict {ip: mac} — snapshot of current ARP table
        """
        with self._lock:
            return dict(self.arp_table)

    def seed_table(self, devices):
        """
        Isi tabel ARP awal dari hasil scan jaringan.
        Dipanggil sekali saat startup sebelum monitoring dimulai,
        agar MAC yang sudah dikenal tidak dianggap spoofing.

        Args:
            devices: list dict perangkat dari NetworkScanner.get_devices()

        ---
        Pre-populate the ARP table from network scan results.
        Called once at startup before monitoring begins,
        so known MACs are not flagged as spoofing.

        Args:
            devices: list of device dicts from NetworkScanner.get_devices()
        """
        with self._lock:
            for dev in devices:
                if dev.get("mac") and dev.get("mac") != "N/A":
                    self.arp_table[dev["ip"]] = dev["mac"]
        print(f"[ARP] Seeded table with {len(devices)} devices")
