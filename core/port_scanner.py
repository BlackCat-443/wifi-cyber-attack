"""
Port Scan Detector
Detects port scanning activity from devices on the network
"""

import threading
import time
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# Common dangerous ports
DANGEROUS_PORTS = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 5900: "VNC", 21: "FTP", 20: "FTP-Data"
}


class PortScanMonitor:
    """
    Detektor port scanning, SYN flood, dan ICMP sweep.

    Tiga jenis aktivitas yang dideteksi:

    1. TCP SYN Scan (Nmap -sS):
       Penyerang mengirim SYN ke banyak port berbeda tanpa menyelesaikan
       handshake TCP. Dipakai untuk reconnaissance — cari port yang terbuka.
       Deteksi: >15 port unik dari satu IP dalam 10 detik.

    2. SYN Flood (DoS):
       Penyerang mengirim banjir SYN tanpa pernah ACK, menghabiskan
       resource server (half-open connections).
       Deteksi: >50 SYN packet dari satu IP dalam 10 detik.

    3. ICMP Ping Sweep:
       Penyerang ping banyak host sekaligus untuk peta jaringan.
       Deteksi: >20 host berbeda di-ping dari satu IP.

    ---
    Port scanning, SYN flood, and ICMP sweep detector.

    Three activity types detected:

    1. TCP SYN Scan (Nmap -sS):
       Attacker sends SYN to many different ports without completing
       TCP handshake. Used for reconnaissance — finding open ports.
       Detection: >15 unique ports from one IP within 10 seconds.

    2. SYN Flood (DoS):
       Attacker sends a flood of SYN packets without ever ACKing,
       exhausting server resources (half-open connections).
       Detection: >50 SYN packets from one IP within 10 seconds.

    3. ICMP Ping Sweep:
       Attacker pings many hosts at once to map the network.
       Detection: >20 different hosts pinged from one IP.
    """

    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self.running = False
        # {src_ip: {dst_ip: set(ports)}} — tracker port scan per pasangan IP
        self.scan_tracker = defaultdict(lambda: defaultdict(set))
        self.syn_tracker  = defaultdict(list)    # {src_ip: [unix_timestamps]}
        self._lock = threading.Lock()
        self.port_threshold = 15    # Port unik sebelum dianggap scan
        self.syn_threshold  = 50    # SYN packet sebelum dianggap flood
        self.time_window    = 10    # Window waktu dalam detik
        self.last_cleanup   = time.time()
        self.attack_count   = 0

    def start(self, iface=None):
        """
        Mulai monitoring port scan di background thread.

        Args:
            iface: nama interface jaringan. None = default.

        ---
        Start port scan monitoring in a background thread.

        Args:
            iface: network interface name. None = default.
        """
        if not SCAPY_AVAILABLE:
            print("[PortScan] Scapy not available, port scan monitoring disabled")
            return
        self.iface = iface
        self.running = True
        thread = threading.Thread(target=self._sniff_loop, daemon=True)
        thread.start()
        print("[PortScan] Monitor started")

    def stop(self):
        """Hentikan monitoring. / Stop monitoring."""
        self.running = False

    def _sniff_loop(self):
        """
        Loop sniffing paket TCP, UDP, dan ICMP.
        Filter luas agar semua jenis scan bisa terdeteksi.

        ---
        Sniffing loop for TCP, UDP, and ICMP packets.
        Broad filter to catch all scan types.
        """
        try:
            conf.verb = 0
            kwargs = {
                "filter": "tcp or udp or icmp",
                "prn": self._process_packet,
                "store": False
            }
            if self.iface:
                kwargs["iface"] = self.iface
            sniff(**kwargs)
        except Exception as e:
            print(f"[PortScan] Sniff error: {e}")

    def _process_packet(self, packet):
        """
        Routing paket ke handler deteksi yang sesuai.

        Logika per protokol:
        - TCP SYN (flags=0x02): cek port scan + SYN flood + akses port berbahaya
        - UDP: cek port scan via UDP
        - ICMP type 8 (echo request): cek ping sweep

        Cleanup data lama dijalankan setiap 30 detik untuk hemat memori.

        Args:
            packet: paket Scapy yang ditangkap

        ---
        Route packets to the appropriate detection handler.

        Per-protocol logic:
        - TCP SYN (flags=0x02): check port scan + SYN flood + dangerous port access
        - UDP: check UDP port scan
        - ICMP type 8 (echo request): check ping sweep

        Old data cleanup runs every 30 seconds to save memory.

        Args:
            packet: captured Scapy packet
        """
        if not self.running:
            return

        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        now    = time.time()

        # Bersihkan data lama secara berkala
        if now - self.last_cleanup > 30:
            self._cleanup()

        if packet.haslayer(TCP):
            tcp      = packet[TCP]
            dst_port = tcp.dport

            # SYN flag saja (0x02) = SYN scan, belum handshake penuh
            if tcp.flags == 0x02:
                with self._lock:
                    self.scan_tracker[src_ip][dst_ip].add(dst_port)
                    self.syn_tracker[src_ip].append(now)

                    port_count = len(self.scan_tracker[src_ip][dst_ip])
                    syn_count  = len([t for t in self.syn_tracker[src_ip]
                                      if now - t < self.time_window])

                if port_count >= self.port_threshold:
                    self._report_port_scan(src_ip, dst_ip, port_count, "TCP SYN Scan")

                if syn_count >= self.syn_threshold:
                    self._report_syn_flood(src_ip, dst_ip, syn_count)

            # Cek akses ke port berbahaya (hanya pada SYN = koneksi baru)
            if dst_port in DANGEROUS_PORTS and (tcp.flags & 0x02):
                self._check_dangerous_port(src_ip, dst_ip, dst_port, DANGEROUS_PORTS[dst_port])

        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            with self._lock:
                self.scan_tracker[src_ip][dst_ip].add(dst_port)
                port_count = len(self.scan_tracker[src_ip][dst_ip])

            if port_count >= self.port_threshold:
                self._report_port_scan(src_ip, dst_ip, port_count, "UDP Scan")

        elif packet.haslayer(ICMP):
            # Type 8 = echo request (ping)
            if packet[ICMP].type == 8:
                with self._lock:
                    self.scan_tracker[src_ip]["icmp"].add(dst_ip)
                    sweep_count = len(self.scan_tracker[src_ip]["icmp"])

                if sweep_count >= 20:
                    self._report_icmp_sweep(src_ip, sweep_count)

    def _report_port_scan(self, src_ip, dst_ip, port_count, scan_type):
        self.attack_count += 1
        self.alert_manager.add_alert({
            "type": "PORT_SCAN",
            "severity": "MEDIUM",
            "title": f"🔍 {scan_type} Detected!",
            "message": (
                f"Device {src_ip} scanned {port_count} ports on {dst_ip} "
                f"in {self.time_window}s. Possible reconnaissance!"
            ),
            "source_ip": src_ip,
            "target_ip": dst_ip,
            "port_count": port_count,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": scan_type
        })
        print(f"[PortScan] ⚠️ {scan_type}: {src_ip} -> {dst_ip} ({port_count} ports)")
        with self._lock:
            self.scan_tracker[src_ip][dst_ip].clear()

    def _report_syn_flood(self, src_ip, dst_ip, count):
        self.attack_count += 1
        self.alert_manager.add_alert({
            "type": "SYN_FLOOD",
            "severity": "HIGH",
            "title": "💥 SYN Flood Attack!",
            "message": (
                f"Device {src_ip} sent {count} SYN packets to {dst_ip} "
                f"in {self.time_window}s. Possible DoS attack!"
            ),
            "source_ip": src_ip,
            "target_ip": dst_ip,
            "syn_count": count,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": "SYN Flood / DoS"
        })
        print(f"[PortScan] ⚠️ SYN FLOOD: {src_ip} -> {dst_ip} ({count} SYNs)")
        with self._lock:
            self.syn_tracker[src_ip] = []

    def _report_icmp_sweep(self, src_ip, count):
        self.attack_count += 1
        self.alert_manager.add_alert({
            "type": "ICMP_SWEEP",
            "severity": "LOW",
            "title": "📡 ICMP Ping Sweep Detected",
            "message": (
                f"Device {src_ip} pinged {count} hosts. "
                f"Possible network reconnaissance!"
            ),
            "source_ip": src_ip,
            "host_count": count,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": "ICMP Ping Sweep"
        })
        with self._lock:
            self.scan_tracker[src_ip]["icmp"].clear()

    def _check_dangerous_port(self, src_ip, dst_ip, port, service):
        """Alert on access to sensitive services"""
        # Only alert if external IP accessing internal service
        if not src_ip.startswith(("192.168.", "10.", "172.")):
            self.alert_manager.add_alert({
                "type": "DANGEROUS_PORT_ACCESS",
                "severity": "MEDIUM",
                "title": f"⚠️ External Access to {service}",
                "message": (
                    f"External IP {src_ip} attempting to connect to "
                    f"{service} (port {port}) on {dst_ip}"
                ),
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "port": port,
                "service": service,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attack_type": f"Unauthorized {service} Access"
            })

    def _cleanup(self):
        """Clean old tracking data"""
        with self._lock:
            now = time.time()
            for ip in list(self.syn_tracker.keys()):
                self.syn_tracker[ip] = [
                    t for t in self.syn_tracker[ip]
                    if now - t < self.time_window
                ]
            self.last_cleanup = now
