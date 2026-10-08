"""
DHCP Starvation & Rogue DHCP Detector
Detects DHCP flooding attacks and unauthorized DHCP servers
"""

import threading
import time
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, DHCP, BOOTP, Ether, IP, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


class DHCPMonitor:
    """
    Detektor DHCP Starvation dan Rogue DHCP Server.

    Dua jenis serangan yang dideteksi:

    1. DHCP Starvation:
       Penyerang mengirim banyak DHCP DISCOVER/REQUEST dengan MAC palsu
       untuk menghabiskan semua IP yang tersedia di pool DHCP server.
       Akibatnya perangkat baru tidak bisa dapat IP → denial of service.

    2. Rogue DHCP Server:
       Penyerang menjalankan DHCP server palsu yang merespons request klien
       dengan konfigurasi berbahaya (gateway palsu, DNS palsu).
       Ini bisa dipakai untuk MITM atau redirect traffic.

    ---
    DHCP Starvation and Rogue DHCP Server detector.

    Two attack types detected:

    1. DHCP Starvation:
       Attacker sends many DHCP DISCOVER/REQUEST with fake MACs to exhaust
       all available IPs in the DHCP server's pool.
       Result: new devices can't get an IP → denial of service.

    2. Rogue DHCP Server:
       Attacker runs a fake DHCP server that responds to client requests
       with malicious config (fake gateway, fake DNS).
       Can be used for MITM or traffic redirection.
    """

    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self.running = False
        self.dhcp_requests = defaultdict(list)  # {mac: [unix_timestamps]}
        self.known_dhcp_servers = set()          # IP server DHCP yang sudah dikenal
        self.legitimate_server = None            # Server DHCP pertama yang terlihat = dianggap sah
        self._lock = threading.Lock()
        self.starvation_threshold = 10   # Request per window sebelum dianggap starvation
        self.time_window = 30            # Window waktu dalam detik
        self.attack_count = 0

    def start(self, iface=None):
        """
        Mulai monitoring DHCP di background thread.

        Args:
            iface: nama interface jaringan. None = default.

        ---
        Start DHCP monitoring in a background thread.

        Args:
            iface: network interface name. None = default.
        """
        if not SCAPY_AVAILABLE:
            print("[DHCP] Scapy not available, DHCP monitoring disabled")
            return
        self.iface = iface
        self.running = True
        thread = threading.Thread(target=self._sniff_loop, daemon=True)
        thread.start()
        print("[DHCP] Monitor started")

    def stop(self):
        """Hentikan monitoring. / Stop monitoring."""
        self.running = False

    def _sniff_loop(self):
        """
        Loop sniffing paket UDP port 67/68 (DHCP).
        Port 67 = server, port 68 = client.

        ---
        Sniffing loop for UDP port 67/68 (DHCP).
        Port 67 = server, port 68 = client.
        """
        try:
            conf.verb = 0
            kwargs = {
                "filter": "udp and (port 67 or port 68)",
                "prn": self._process_packet,
                "store": False
            }
            if self.iface:
                kwargs["iface"] = self.iface
            sniff(**kwargs)
        except Exception as e:
            print(f"[DHCP] Sniff error: {e}")

    def _process_packet(self, packet):
        """
        Routing paket DHCP ke handler yang sesuai berdasarkan message-type.

        DHCP message types:
        - 1 (DISCOVER) : klien mencari server DHCP → cek starvation
        - 2 (OFFER)    : server menawarkan IP → cek rogue server
        - 3 (REQUEST)  : klien meminta IP → cek starvation
        - 5 (ACK)      : server konfirmasi → cek rogue server

        Args:
            packet: paket Scapy yang ditangkap

        ---
        Route DHCP packets to the appropriate handler based on message-type.

        DHCP message types:
        - 1 (DISCOVER) : client looking for DHCP server → check starvation
        - 2 (OFFER)    : server offering IP → check rogue server
        - 3 (REQUEST)  : client requesting IP → check starvation
        - 5 (ACK)      : server confirming → check rogue server

        Args:
            packet: captured Scapy packet
        """
        if not self.running:
            return

        if not packet.haslayer(DHCP):
            return

        dhcp_options = dict(
            (opt[0], opt[1]) for opt in packet[DHCP].options
            if isinstance(opt, tuple) and len(opt) >= 2
        )
        msg_type = dhcp_options.get('message-type', 0)

        # Pesan dari klien (DISCOVER/REQUEST) → cek starvation
        if msg_type in [1, 3]:
            self._check_starvation(packet)

        # Pesan dari server (OFFER/ACK) → cek rogue server
        elif msg_type in [2, 5]:
            self._check_rogue_server(packet)

    def _check_starvation(self, packet):
        """Detect DHCP starvation (flood of DISCOVER/REQUEST)"""
        mac = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
        now = time.time()

        with self._lock:
            # Clean old timestamps
            self.dhcp_requests[mac] = [
                t for t in self.dhcp_requests[mac]
                if now - t < self.time_window
            ]
            self.dhcp_requests[mac].append(now)
            count = len(self.dhcp_requests[mac])

        if count >= self.starvation_threshold:
            self.attack_count += 1
            self.alert_manager.add_alert({
                "type": "DHCP_STARVATION",
                "severity": "HIGH",
                "title": "💥 DHCP Starvation Attack!",
                "message": (
                    f"MAC {mac} sent {count} DHCP requests in {self.time_window}s. "
                    f"Attacker may be exhausting IP pool to deny service!"
                ),
                "source_mac": mac,
                "request_count": count,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attack_type": "DHCP Starvation"
            })
            print(f"[DHCP] ⚠️ STARVATION: {mac} ({count} requests)")

            with self._lock:
                self.dhcp_requests[mac] = []  # Reset

    def _check_rogue_server(self, packet):
        """Detect unauthorized DHCP servers"""
        if not packet.haslayer(IP):
            return

        server_ip = packet[IP].src

        with self._lock:
            if self.legitimate_server is None:
                self.legitimate_server = server_ip
                self.known_dhcp_servers.add(server_ip)
                print(f"[DHCP] Legitimate server: {server_ip}")
                return

            if server_ip not in self.known_dhcp_servers:
                self.attack_count += 1
                self.known_dhcp_servers.add(server_ip)

        self.alert_manager.add_alert({
            "type": "ROGUE_DHCP",
            "severity": "CRITICAL",
            "title": "🚨 Rogue DHCP Server Detected!",
            "message": (
                f"Unknown DHCP server at {server_ip} is responding to clients. "
                f"Legitimate server: {self.legitimate_server}. "
                f"Attacker may redirect traffic!"
            ),
            "rogue_server": server_ip,
            "legitimate_server": self.legitimate_server,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": "Rogue DHCP Server"
        })
        print(f"[DHCP] ⚠️ ROGUE SERVER: {server_ip}")
