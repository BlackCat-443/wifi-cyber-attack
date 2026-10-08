"""
DNS Spoofing Detector
Compares DNS responses against trusted DNS servers to detect poisoning
"""

import threading
import socket
import time
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, DNS, DNSRR, IP, UDP, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    import dns.resolver
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False


TRUSTED_DNS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def resolve_trusted(domain):
    """Resolve domain using trusted DNS servers"""
    results = set()
    for server in TRUSTED_DNS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            # Simple DNS query
            if DNSPYTHON_AVAILABLE:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server]
                answers = resolver.resolve(domain, 'A', lifetime=3)
                for rdata in answers:
                    results.add(str(rdata))
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return results


class DNSMonitor:
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self.running = False
        self.dns_cache = {}         # {domain: set(ips)} from trusted DNS
        self.query_log = defaultdict(list)
        self._lock = threading.Lock()
        self.attack_count = 0

    def start(self, iface=None):
        if not SCAPY_AVAILABLE:
            print("[DNS] Scapy not available, DNS monitoring disabled")
            return
        self.iface = iface
        self.running = True
        thread = threading.Thread(target=self._sniff_loop, daemon=True)
        thread.start()
        print("[DNS] Monitor started")

    def stop(self):
        self.running = False

    def _sniff_loop(self):
        try:
            conf.verb = 0
            kwargs = {
                "filter": "udp port 53",
                "prn": self._process_packet,
                "store": False
            }
            if self.iface:
                kwargs["iface"] = self.iface
            sniff(**kwargs)
        except Exception as e:
            print(f"[DNS] Sniff error: {e}")

    def _process_packet(self, packet):
        if not self.running:
            return

        if packet.haslayer(DNS) and packet.haslayer(DNSRR):
            dns_layer = packet[DNS]

            # Only process DNS responses (qr=1)
            if dns_layer.qr != 1:
                return

            src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"

            # Extract answers
            for i in range(dns_layer.ancount):
                try:
                    rr = dns_layer.an
                    for _ in range(i):
                        rr = rr.payload

                    if rr.type == 1:  # A record
                        domain = rr.rrname.decode().rstrip('.')
                        resolved_ip = rr.rdata

                        self._check_dns_spoofing(domain, str(resolved_ip), src_ip)
                except Exception:
                    pass

    def _check_dns_spoofing(self, domain, resolved_ip, src_ip):
        """Compare resolved IP against trusted DNS"""
        with self._lock:
            if domain not in self.dns_cache:
                # Fetch from trusted DNS in background
                thread = threading.Thread(
                    target=self._fetch_trusted,
                    args=(domain, resolved_ip, src_ip),
                    daemon=True
                )
                thread.start()
                self.dns_cache[domain] = {resolved_ip}  # Assume first is correct
                return

            trusted_ips = self.dns_cache[domain]

        if resolved_ip not in trusted_ips and len(trusted_ips) > 0:
            self.attack_count += 1
            self.alert_manager.add_alert({
                "type": "DNS_SPOOFING",
                "severity": "HIGH",
                "title": "🔴 DNS Spoofing Detected!",
                "message": (
                    f"Domain '{domain}' resolved to {resolved_ip} "
                    f"but trusted DNS says: {', '.join(trusted_ips)}. "
                    f"Response from: {src_ip}"
                ),
                "domain": domain,
                "spoofed_ip": resolved_ip,
                "trusted_ips": list(trusted_ips),
                "source_ip": src_ip,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attack_type": "DNS Spoofing / Cache Poisoning"
            })
            print(f"[DNS] ⚠️ SPOOFING: {domain} -> {resolved_ip} (trusted: {trusted_ips})")

    def _fetch_trusted(self, domain, local_ip, src_ip):
        """Fetch trusted DNS resolution and compare"""
        trusted = resolve_trusted(domain)
        if trusted:
            with self._lock:
                self.dns_cache[domain] = trusted

            if local_ip not in trusted:
                self.attack_count += 1
                self.alert_manager.add_alert({
                    "type": "DNS_SPOOFING",
                    "severity": "HIGH",
                    "title": "🔴 DNS Spoofing Detected!",
                    "message": (
                        f"Domain '{domain}' resolved to {local_ip} "
                        f"but trusted DNS says: {', '.join(trusted)}. "
                        f"Possible DNS cache poisoning!"
                    ),
                    "domain": domain,
                    "spoofed_ip": local_ip,
                    "trusted_ips": list(trusted),
                    "source_ip": src_ip,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "attack_type": "DNS Spoofing / Cache Poisoning"
                })
